/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! An example Matter device that acts as an OTA Software Update Requestor: it
//! hosts the OTA Requestor cluster and runs a driver that, once a Commissioner
//! has pointed it at an OTA Provider (via the `DefaultOTAProviders` attribute or
//! the `AnnounceOTAProvider` command), queries the provider, downloads a newer
//! image over BDX, and applies it.
//!
//! The image handling is stubbed out here by `DummyOtaTarget`, which just counts
//! the bytes it receives. A real device would write the image to a spare
//! firmware slot and reboot into it from `apply`.

use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::{select, select4};

use log::info;

use rand::RngCore;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::SharedNetworks;
use rs_matter::dm::clusters::ota_requestor::{
    ClusterHandler as _, OtaRequestor, OtaRequestorHandler, OtaState, OtaTarget,
};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_OTA_REQUESTOR;
use rs_matter::dm::endpoints;
use rs_matter::dm::events::NoEvents;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::subscriptions::Subscriptions;
use rs_matter::dm::IMBuffer;
use rs_matter::dm::{Async, DataModel, DataModelHandler, Dataver, Endpoint, EpClMatcher, Node};
use rs_matter::error::Error;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{DirKvBlobStore, SharedKvBlobStore};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

/// This device's vendor and product id (matched against `QueryImage`).
const VENDOR_ID: u16 = TEST_DEV_DET.vid;
const PRODUCT_ID: u16 = TEST_DEV_DET.pid;

/// The currently running software version of this device.
const SOFTWARE_VERSION: u32 = 1;

static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<PooledBuffers<10, IMBuffer>> = StaticCell::new();
static SUBSCRIPTIONS: StaticCell<Subscriptions> = StaticCell::new();
static KV_BUF: StaticCell<[u8; 4096]> = StaticCell::new();

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug"),
    );

    let matter = MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        MATTER_PORT,
    ));

    // Persistence
    let kv_buf = KV_BUF.uninit().init_zeroed().as_mut_slice();
    let mut kv = DirKvBlobStore::new_default();
    futures_lite::future::block_on(matter.load_persist(&mut kv, kv_buf))?;

    let buffers = BUFFERS.uninit().init_with(PooledBuffers::init(0));
    let subscriptions = SUBSCRIPTIONS.uninit().init_with(Subscriptions::init());

    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);
    // A second crypto instance owned by the OTA driver (it initiates its own
    // CASE exchanges to the provider).
    let ota_crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);

    let rand = crypto.rand()?;

    // The state shared between the OTA Requestor cluster handler and the driver.
    let ota_state = OtaState::new();

    let events = NoEvents::new();

    let dm = DataModel::new(
        matter,
        &crypto,
        buffers,
        subscriptions,
        &events,
        dm_handler(rand, &ota_state),
        SharedKvBlobStore::new(kv, kv_buf),
        SharedNetworks::new(EthNetwork::new_default()),
    );

    let responder = DefaultResponder::new(&dm);
    let mut respond = pin!(responder.run::<4, 4>());
    let mut dm_job = pin!(dm.run());

    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    let mut mdns = pin!(mdns::run_mdns(matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, &socket));

    // The OTA Requestor driver: polls the configured providers (and reacts to
    // `AnnounceOTAProvider`), downloads any newer image, and applies it.
    let mut ota = OtaRequestor::new(
        matter,
        &ota_state,
        ota_crypto,
        DummyOtaTarget::new(),
        VENDOR_ID,
        PRODUCT_ID,
    );
    let ota_job = pin!(ota.run());

    if !matter.is_commissioned() {
        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;
    }

    // Combine the Matter stack (transport, mDNS, responder, data model) with the
    // OTA driver into a single task.
    let matter_job = select4(&mut transport, &mut mdns, &mut respond, &mut dm_job).coalesce();
    let all = select(matter_job, ota_job).coalesce();

    futures_lite::future::block_on(all)
}

/// The Node meta-data: a root node plus an OTA Requestor endpoint.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_OTA_REQUESTOR),
            clusters!(desc::DescHandler::CLUSTER, OtaRequestorHandler::CLUSTER),
        ),
    ],
};

/// The Data Model handler: the root endpoint 0 handler plus the OTA Requestor
/// cluster (and its descriptor) on endpoint 1.
fn dm_handler<'a>(
    mut rand: impl RngCore + Copy,
    ota_state: &'a OtaState,
) -> impl DataModelHandler + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&SysNetifs)
            .build(rand)
            .chain(
                EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(OtaRequestorHandler::CLUSTER.id)),
                Async(OtaRequestorHandler::new(Dataver::new_rand(&mut rand), ota_state).adapt()),
            ),
    )
}

/// A stub [`OtaTarget`] that just counts the bytes of the downloaded image. A
/// real device would write them to a spare firmware slot and reboot from `apply`.
struct DummyOtaTarget {
    received: usize,
}

impl DummyOtaTarget {
    fn new() -> Self {
        Self { received: 0 }
    }
}

impl OtaTarget for DummyOtaTarget {
    fn current_version(&self) -> u32 {
        SOFTWARE_VERSION
    }

    async fn begin(&mut self, version: u32) -> Result<(), Error> {
        info!("OTA: starting download of version {version}");
        self.received = 0;
        Ok(())
    }

    async fn write(&mut self, _offset: u64, data: &[u8]) -> Result<(), Error> {
        self.received += data.len();
        Ok(())
    }

    async fn apply(&mut self) -> Result<(), Error> {
        info!("OTA: applying image ({} bytes received)", self.received);
        Ok(())
    }
}
