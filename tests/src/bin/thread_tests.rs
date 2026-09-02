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

//! A driver for the `thread` integration test suite (`cargo xtask itest
//! --suite thread`): the Thread sibling of `wireless_tests`, with the crucial
//! difference that there is no mock — the Network Commissioning cluster is
//! wired via [`OtbrCtl`] to a real `otbr-agent` (stood up by xtask's
//! `OtbrEnv` on a private D-Bus bus, over a simulated or physical RCP radio).
//! `ScanNetworks` / `ConnectNetwork` genuinely scan and genuinely attach; the
//! Thread Network Diagnostics attributes carry live stack state.
//!
//! At startup the driver attaches to the operational dataset handed to it via
//! the `RS_MATTER_THREAD_DATASET` env var (hex TLVs), so the node presents as
//! already provisioned — the state the `TC_CNET_*` tests expect to find it in.

use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::select3;

use async_signal::{Signal, Signals};

use futures_lite::StreamExt;

use rand::RngCore;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::{
    NetCtl, NetCtlStatus, NetworkType, Networks, WirelessCreds,
};
use rs_matter::dm::clusters::thread_diag::{self, ThreadDiag};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE};
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::wireless::{NetCtlState, NetCtlWithStatusImpl, ThreadNetworks};
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, Cluster, DataModel, Dataver, Endpoint, EpClMatcher, Node};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::im::{InteractionModel, WirelessInteractionModelState};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{KvBlobStoreAccess, NETWORKS_KEY};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::transport::network::thread::otbr::OtbrCtl;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::zbus::Connection;
use rs_matter::{clusters, devices, Matter};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

#[path = "../common/args.rs"]
mod args;

#[path = "../common/logging.rs"]
mod logging;

/// The env var carrying the (hex TLV) operational dataset the driver attaches
/// to at startup. Set by `cargo xtask itest --suite thread`.
const DATASET_ENV: &str = "RS_MATTER_THREAD_DATASET";

/// How many provisioned networks the device can hold. As for
/// `wireless_tests`: the certification tests add a second network alongside
/// the provisioned one, so this has to be greater than one.
const MAX_NETWORKS: usize = 3;

static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static THREAD_STATE: StaticCell<WirelessInteractionModelState<ThreadNetworks<MAX_NETWORKS>>> =
    StaticCell::new();

fn main() -> Result<(), Error> {
    let thread = std::thread::Builder::new()
        .stack_size(550 * 1024)
        .spawn(run)
        .unwrap();
    thread.join().unwrap()
}

fn run() -> Result<(), Error> {
    logging::init();

    // Built before the Thread attach below so that `--pics-json` works
    // without an operational dataset or a running `otbr-agent`: the data
    // model does not depend on either.
    let matter = MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        args::comm_overrides(),
        &TEST_DEV_ATT,
        args::port_override(),
    ));

    // Dump the data model as JSON for `cargo xtask pics`, then exit.
    if args::dump_pics_json(matter, &NODE_THREAD)? {
        return Ok(());
    }

    let dataset = dataset_from_env()?;
    let ext_pan_id = dataset_ext_pan_id(&dataset)?;

    // The suite's `OtbrEnv` points `DBUS_SYSTEM_BUS_ADDRESS` at its private
    // bus. Connect to it with ANONYMOUS auth: the chip-tool YAML runner
    // spawns this binary inside `unshare --map-root-user`, where the
    // announced euid (0) does not match the peer credential the bus daemon
    // sees, so the default `EXTERNAL` mechanism is rejected. Without the env
    // var (manual runs against a real system bus), plain `system()` applies.
    let connection = futures_lite::future::block_on(async {
        match std::env::var("DBUS_SYSTEM_BUS_ADDRESS") {
            Ok(addr) => {
                rs_matter::utils::zbus::connection::Builder::address(addr.as_str())?
                    .auth_mechanism(rs_matter::utils::zbus::AuthMechanism::Anonymous)
                    .build()
                    .await
            }
            Err(_) => Connection::system().await,
        }
    })
    .map_err(|e| {
        log::error!("Failed to connect to the (otbr-agent) D-Bus bus: {e}");
        ErrorCode::NoNetworkInterface
    })?;

    let otbr_ctl = OtbrCtl::new(&connection);

    // Attach to the suite's network for real, so the stack state matches what
    // the seeded `Networks` store claims.
    futures_lite::future::block_on(otbr_ctl.connect(&WirelessCreds::Thread {
        dataset_tlv: &dataset,
    }))
    .map_err(|e| {
        log::error!("Failed to attach to the Thread network: {e:?}");
        ErrorCode::NoNetworkInterface
    })?;

    // As for `wireless_tests`: seed the provisioned Thread network, because
    // the harness commissions this node on-network and the tests expect to
    // find it already provisioned.
    let mut networks = ThreadNetworks::<MAX_NETWORKS>::new();
    Networks::add_or_update(
        &mut networks,
        &WirelessCreds::Thread {
            dataset_tlv: &dataset,
        },
    )
    .map_err(|_| ErrorCode::InvalidData)?;

    let seed = networks;
    let state = THREAD_STATE.init(WirelessInteractionModelState::new(ThreadNetworks::<
        MAX_NETWORKS,
    >::new()));

    let buffers = BUFFERS.uninit().init_with(MatterBuffers::init());
    let kv = matter.kv(args::file_kv_store());

    matter.startup(&kv)?;

    seed_networks(&kv, &seed)?;

    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);
    let mut rand = crypto.rand()?;

    let on_off = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(true),
    );

    let net_ctl_state = NetCtlState::new_with_mutex();
    let net_ctl = NetCtlWithStatusImpl::new(&net_ctl_state, &otbr_ctl);

    // ... and record it as the network we are connected to, so it reads back
    // as `Connected` in the `Networks` attribute.
    NetCtlState::update_with_mutex(
        &net_ctl_state,
        Some(&ext_pan_id),
        Ok::<_, rs_matter::dm::clusters::net_comm::NetCtlError>(()),
    )
    .map_err(|_| ErrorCode::InvalidState)?;

    let im = InteractionModel::new_with_net_ctl(
        matter,
        &crypto,
        buffers,
        data_model_thread(rand, &on_off, &net_ctl, &net_ctl),
        &kv,
        &net_ctl,
        state,
    );

    futures_lite::future::block_on(im.startup())?;

    let responder = DefaultResponder::new(&im);

    let mut respond = pin!(responder.run::<4, 4>());
    let mut im_job = pin!(im.run());

    let socket = async_io::Async::<UdpSocket>::bind(args::bind_addr())?;

    let mut mdns = pin!(mdns::run_mdns(matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, &socket));

    matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;

    if !matter.has_fabrics() {
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;
        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;
    }

    #[cfg(not(windows))]
    let mut term_signal = Signals::new([Signal::Term])?;
    #[cfg(windows)]
    let mut term_signal = Signals::new([Signal::Int])?;
    let mut term = pin!(async {
        term_signal.next().await;
        Ok(())
    });

    let all = select3(
        &mut transport,
        &mut mdns,
        select3(&mut respond, &mut im_job, &mut term).coalesce(),
    );

    futures_lite::future::block_on(all.coalesce())
}

/// The Thread Network Diagnostics cluster, widened past the handler's
/// `required`-only default metadata with the `MACCounts` feature and the MAC
/// counter attributes that the otbr backend serves off the live stack
/// (exercised by `Test_TC_DGTHREAD_2_2` / `_2_3`).
///
/// The two `TxDirect/IndirectMaxRetryExpiryCount` attributes stay out (and
/// unclaimed in the `.pics`): otbr's D-Bus marshaling of the MAC counters
/// omits them.

const THREAD_DIAG_CLUSTER: Cluster<'static> = thread_diag::FULL_CLUSTER
    .with_features(thread_diag::Feature::MAC_COUNTS.bits())
    .with_attrs(rs_matter::with!(
        required;
        thread_diag::AttributeId::TxTotalCount
            | thread_diag::AttributeId::TxUnicastCount
            | thread_diag::AttributeId::TxBroadcastCount
            | thread_diag::AttributeId::TxAckRequestedCount
            | thread_diag::AttributeId::TxAckedCount
            | thread_diag::AttributeId::TxNoAckRequestedCount
            | thread_diag::AttributeId::TxDataCount
            | thread_diag::AttributeId::TxDataPollCount
            | thread_diag::AttributeId::TxBeaconCount
            | thread_diag::AttributeId::TxBeaconRequestCount
            | thread_diag::AttributeId::TxOtherCount
            | thread_diag::AttributeId::TxRetryCount
            | thread_diag::AttributeId::TxErrCcaCount
            | thread_diag::AttributeId::TxErrAbortCount
            | thread_diag::AttributeId::TxErrBusyChannelCount
            | thread_diag::AttributeId::RxTotalCount
            | thread_diag::AttributeId::RxUnicastCount
            | thread_diag::AttributeId::RxBroadcastCount
            | thread_diag::AttributeId::RxDataCount
            | thread_diag::AttributeId::RxDataPollCount
            | thread_diag::AttributeId::RxBeaconCount
            | thread_diag::AttributeId::RxBeaconRequestCount
            | thread_diag::AttributeId::RxOtherCount
            | thread_diag::AttributeId::RxAddressFilteredCount
            | thread_diag::AttributeId::RxDestAddrFilteredCount
            | thread_diag::AttributeId::RxDuplicatedCount
            | thread_diag::AttributeId::RxErrNoFrameCount
            | thread_diag::AttributeId::RxErrUnknownNeighborCount
            | thread_diag::AttributeId::RxErrInvalidSrcAddrCount
            | thread_diag::AttributeId::RxErrSecCount
            | thread_diag::AttributeId::RxErrFcsCount
            | thread_diag::AttributeId::RxErrOtherCount
    ))
    .with_cmds(rs_matter::with!());

/// The Node meta-data: same composition as `wireless_tests`' Thread flavour,
/// except for the widened Thread diagnostics cluster - hence the root
/// endpoint is spelled out (`root_endpoint!(thread)` would pull in the
/// handler's default, `required`-only metadata).
const NODE_THREAD: Node<'static> = Node {
    endpoints: &[
        Endpoint {
            id: endpoints::ROOT_ENDPOINT_ID,
            device_types: devices!(DEV_TYPE_ROOT_NODE),
            clusters: clusters!(
                sys;
                NetworkType::Thread.cluster(),
                THREAD_DIAG_CLUSTER,
            ),
            client_clusters: &[],
            unique_id: None,
            semantic_tags: &[],
        },
        Endpoint::new(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER
            ),
        ),
    ],
};

fn data_model_thread<'a, OH: OnOffHooks, LH: LevelControlHooks, T>(
    mut rand: impl RngCore + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
    thread_diag: &'a dyn ThreadDiag,
    net_ctl: T,
) -> impl DataModel + 'a
where
    T: NetCtl + NetCtlStatus + 'a,
{
    (
        NODE_THREAD,
        endpoints::ThreadSysHandlerBuilder::new(net_ctl, thread_diag)
            .netif_diag(&SysNetifs)
            .build(rand)
            .chain(
                EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(groups::GroupsHandler::CLUSTER.id)),
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                on_off::HandlerAsyncAdaptor(on_off),
            ),
    )
}

/// Persist `networks` under [`NETWORKS_KEY`] so that
/// `InteractionModel::startup` restores it (`startup` resets the in-memory
/// store before loading, so the seed has to go through persistence).
fn seed_networks<K, N>(kv: &K, networks: &N) -> Result<(), Error>
where
    K: KvBlobStoreAccess,
    N: Networks,
{
    kv.access(|store, buf| {
        let mut blob = [0; 512];

        let Some(len) = networks.save(&mut blob)? else {
            return Ok(());
        };

        store.store(NETWORKS_KEY, &blob[..len], buf)
    })
}

/// Decode the operational dataset from [`DATASET_ENV`].
fn dataset_from_env() -> Result<Vec<u8>, Error> {
    let Some(hex) = std::env::var_os(DATASET_ENV) else {
        log::error!("`{DATASET_ENV}` is not set; it must carry the hex TLVs of the operational dataset to attach to");
        return Err(ErrorCode::InvalidData.into());
    };

    let hex = hex.to_string_lossy();
    let hex = hex.trim();

    if hex.len() % 2 != 0 || hex.is_empty() {
        log::error!("`{DATASET_ENV}` is not an even-length hex string");
        return Err(ErrorCode::InvalidData.into());
    }

    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair =
                core::str::from_utf8(pair).map_err(|_| Error::from(ErrorCode::InvalidData))?;
            u8::from_str_radix(pair, 16).map_err(|_| ErrorCode::InvalidData.into())
        })
        .collect()
}

/// Extract the Extended PAN ID octets out of a TLV-encoded operational
/// dataset — the value the Network Commissioning cluster uses as the
/// `NetworkID` for Thread networks.
fn dataset_ext_pan_id(dataset: &[u8]) -> Result<[u8; 8], Error> {
    const EXT_PAN_ID_TLV: u8 = 0x02;

    let mut offset = 0;
    while offset + 2 <= dataset.len() {
        let (tlv_type, len) = (dataset[offset], dataset[offset + 1] as usize);
        offset += 2;

        if offset + len > dataset.len() {
            break;
        }

        if tlv_type == EXT_PAN_ID_TLV && len == 8 {
            let mut ext_pan_id = [0; 8];
            ext_pan_id.copy_from_slice(&dataset[offset..offset + 8]);
            return Ok(ext_pan_id);
        }

        offset += len;
    }

    log::error!("`{DATASET_ENV}` does not contain an Extended PAN ID TLV");
    Err(ErrorCode::InvalidData.into())
}
