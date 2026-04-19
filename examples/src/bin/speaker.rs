/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

//! An example Matter device that implements a Speaker device over Ethernet.
//! Demonstrates how to make use of the `rs_matter::import` macro for `LevelControl`.

use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::select4;

use rand::RngCore;
use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::level_control::{
    self, test::TestLevelControlDeviceLogic, AttributeDefaults, LevelControlHandler,
    LevelControlHooks, OptionsBitmap,
};
use rs_matter::dm::clusters::net_comm::SharedNetworks;
use rs_matter::dm::clusters::on_off::{self, test::TestOnOffDeviceLogic, OnOffHandler, OnOffHooks};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_SMART_SPEAKER;
use rs_matter::dm::endpoints;
use rs_matter::dm::events::Events;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::subscriptions::Subscriptions;
use rs_matter::dm::{
    Async, AsyncHandler, AsyncMetadata, DataModel, Dataver, EmptyHandler, Endpoint, EpClMatcher,
    Node,
};
use rs_matter::error::Error;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{DirKvBlobStore, SharedKvBlobStore};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::Nullable;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

#[path = "../common/mdns.rs"]
mod mdns;

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Create the Matter object
    let mut matter = Matter::new_default(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Need to call this once
    matter.initialize_transport_buffers()?;

    // Create the event queue
    let mut events: Events = Events::new_default();

    // Persistence
    let mut kv_buf = [0; 4096];
    let mut kv = DirKvBlobStore::new_default();
    futures_lite::future::block_on(matter.load_persist(&mut kv, &mut kv_buf))?;
    futures_lite::future::block_on(events.load_persist(&mut kv, &mut kv_buf))?;

    // Create the transport buffers
    let buffers = PooledBuffers::<10, _>::new(0);

    // Create the subscriptions
    let subscriptions: Subscriptions = Subscriptions::new();

    // Create the crypto instance
    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // OnOff cluster setup
    let on_off_handler = on_off::OnOffHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(true),
    );

    // LevelControl cluster setup
    let level_control_handler = LevelControlHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        TestLevelControlDeviceLogic::new(),
        AttributeDefaults {
            on_level: Nullable::some(42),
            options: OptionsBitmap::from_bits(OptionsBitmap::EXECUTE_IF_OFF.bits()).unwrap(),
            on_off_transition_time: 0,
            on_transition_time: Nullable::none(),
            off_transition_time: Nullable::none(),
            default_move_rate: Nullable::none(),
        },
    );

    // Cluster wiring, validation and initialisation
    on_off_handler.init(Some(&level_control_handler));
    level_control_handler.init(Some(&on_off_handler));

    // Create the Data Model instance
    let dm = DataModel::new(
        &matter,
        &crypto,
        &buffers,
        &subscriptions,
        &events,
        dm_handler(rand, &on_off_handler, &level_control_handler),
        SharedKvBlobStore::new(kv, kv_buf.as_mut_slice()),
        SharedNetworks::new(EthNetwork::new_default()),
    );

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&dm);

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(responder.run::<4, 4>());

    // Run the background job of the data model
    let mut dm_job = pin!(dm.run());

    // Create the Matter UDP socket
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(&matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, &socket));

    if !matter.is_commissioned() {
        // If the device is not commissioned yet, print the QR text and code to the console
        // and enable basic commissioning

        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, dm.change_notify())?;
    }

    // Combine all async tasks in a single one
    let all = select4(&mut transport, &mut mdns, &mut respond, &mut dm_job).coalesce();

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all)
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_SMART_SPEAKER),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                TestLevelControlDeviceLogic::CLUSTER
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the Speaker handler.
fn dm_handler<'a, LH: LevelControlHooks, OH: OnOffHooks>(
    mut rand: impl RngCore + Copy,
    on_off: &'a OnOffHandler<'a, OH, LH>,
    level_control: &'a LevelControlHandler<'a, LH, OH>,
) -> impl AsyncMetadata + AsyncHandler + 'a {
    (
        NODE,
        endpoints::with_eth_sys(
            &false,
            &(),
            &UnixNetifs,
            rand,
            EmptyHandler
                .chain(
                    EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                    Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(TestLevelControlDeviceLogic::CLUSTER.id)),
                    level_control::HandlerAsyncAdaptor(level_control),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                    on_off::HandlerAsyncAdaptor(on_off),
                ),
        ),
    )
}
