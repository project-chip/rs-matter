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

//! A Matter device advertising a *wireless* Network Commissioning cluster,
//! used to drive the `TC_CNET_4_*` itest suite.
//!
//! It claims the Wi-Fi (`CNET.S.F00`) or Thread (`CNET.S.F01`) feature and
//! serves `ScanNetworks` / `ConnectNetwork` from [`MockNetCtl`], so the whole
//! Network Commissioning surface can be exercised without a radio. Operational
//! traffic still runs over the ordinary UDP socket, exactly as for the Ethernet
//! `system_tests` device - only the cluster's view of the world is wireless.
//!
//! Pass `--thread` (or set `RS_MATTER_WIRELESS_THREAD`) for the Thread
//! flavour; the default is Wi-Fi.
#![allow(clippy::uninlined_format_args)]

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
use rs_matter::dm::clusters::thread_diag::ThreadDiag;
use rs_matter::dm::clusters::wifi_diag::WifiDiag;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::wireless::{
    NetCtlState, NetCtlWithStatusImpl, ThreadNetworks, WifiNetworks,
};
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, DataModel, Dataver, Endpoint, EpClMatcher, Node};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::im::{InteractionModel, WirelessInteractionModelState};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{KvBlobStoreAccess, NETWORKS_KEY};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::{clusters, devices, root_endpoint, Matter};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

#[path = "../common/args.rs"]
mod args;

#[path = "../common/mock_net_ctl.rs"]
mod mock_net_ctl;

use mock_net_ctl::MockNetCtl;

/// How many provisioned networks the device can hold. The certification tests
/// add a second network alongside the provisioned one and check the ordering,
/// so this has to be greater than one.
const MAX_NETWORKS: usize = 3;

static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static WIFI_STATE: StaticCell<WirelessInteractionModelState<WifiNetworks<MAX_NETWORKS>>> =
    StaticCell::new();
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
    env_logger::builder()
        .format(|buf, record| {
            use std::io::Write;
            writeln!(buf, "{}: {}", record.level(), record.args())
        })
        .target(env_logger::Target::Stdout)
        .filter_level(::log::LevelFilter::Debug)
        .init();

    // The Wi-Fi and Thread network stores are distinct types, so the node is
    // built out in one of two monomorphisations rather than switched at runtime.
    //
    // The environment variable is how the chip-tool YAML runner selects the
    // flavour: it spawns the device itself and passes it no arguments of ours.
    if args::arg_present("--thread") || std::env::var_os("RS_MATTER_WIRELESS_THREAD").is_some() {
        run_thread()
    } else {
        run_wifi()
    }
}

/// Bring up the Wi-Fi flavour of the node.
fn run_wifi() -> Result<(), Error> {
    // The harness commissions this node on-network, so nothing ever ran the
    // `AddOrUpdateWiFiNetwork` + `ConnectNetwork` pair that a real BLE-Wi-Fi
    // commissioning would. Seed the store so the node presents as already
    // provisioned onto the mock network, which is the state the Network
    // Commissioning tests expect to find it in.
    let mut networks = WifiNetworks::<MAX_NETWORKS>::new();
    Networks::add_or_update(
        &mut networks,
        &WirelessCreds::Wifi {
            ssid: mock_net_ctl::MOCK_WIFI_SSID,
            pass: mock_net_ctl::MOCK_WIFI_PASS,
        },
    )
    .map_err(|_| ErrorCode::InvalidData)?;

    let seed = networks;
    let state = WIFI_STATE.init(WirelessInteractionModelState::new(WifiNetworks::<
        MAX_NETWORKS,
    >::new()));

    let matter = MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        args::comm_overrides(),
        &TEST_DEV_ATT,
        args::port_override(),
    ));

    // Dump the data model as JSON for `cargo xtask pics`, then exit.
    if args::dump_pics_json(matter, &NODE_WIFI)? {
        return Ok(());
    }

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

    // The mock radio, wrapped so the cluster can report the status of the last
    // scan / connect through `LastNetworkingStatus` and friends.
    let net_ctl_state = NetCtlState::new_with_mutex();
    let net_ctl = NetCtlWithStatusImpl::new(&net_ctl_state, MockNetCtl::new(NetworkType::Wifi));

    // ... and record it as the network we are connected to, so it reads back as
    // `Connected` in the `Networks` attribute.
    NetCtlState::update_with_mutex(
        &net_ctl_state,
        Some(mock_net_ctl::MOCK_WIFI_SSID),
        Ok::<_, rs_matter::dm::clusters::net_comm::NetCtlError>(()),
    )
    .map_err(|_| ErrorCode::InvalidState)?;

    let im = InteractionModel::new_with_net_ctl(
        matter,
        &crypto,
        buffers,
        data_model_wifi(rand, &on_off, &net_ctl, &net_ctl),
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

/// Bring up the Thread flavour of the node.
fn run_thread() -> Result<(), Error> {
    // As for Wi-Fi above: seed the provisioned Thread network.
    let mut networks = ThreadNetworks::<MAX_NETWORKS>::new();
    Networks::add_or_update(
        &mut networks,
        &WirelessCreds::Thread {
            dataset_tlv: &mock_net_ctl::MOCK_THREAD_DATASET,
        },
    )
    .map_err(|_| ErrorCode::InvalidData)?;

    let seed = networks;
    let state = THREAD_STATE.init(WirelessInteractionModelState::new(ThreadNetworks::<
        MAX_NETWORKS,
    >::new()));

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
    let net_ctl = NetCtlWithStatusImpl::new(&net_ctl_state, MockNetCtl::new(NetworkType::Thread));

    NetCtlState::update_with_mutex(
        &net_ctl_state,
        Some(&mock_net_ctl::MOCK_THREAD_EXT_PAN_ID),
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

/// The Node meta-data for the Wi-Fi flavour.
const NODE_WIFI: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(wifi),
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

/// The Node meta-data for the Thread flavour.
const NODE_THREAD: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(thread),
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

fn data_model_wifi<'a, OH: OnOffHooks, LH: LevelControlHooks, T>(
    mut rand: impl RngCore + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
    wifi_diag: &'a dyn WifiDiag,
    net_ctl: T,
) -> impl DataModel + 'a
where
    T: NetCtl + NetCtlStatus + 'a,
{
    (
        NODE_WIFI,
        endpoints::WifiSysHandlerBuilder::new(net_ctl, wifi_diag)
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

/// Persist `networks` under [`NETWORKS_KEY`] so that `InteractionModel::startup`
/// restores it.
///
/// The harness commissions this node on-network, so nothing ever ran the
/// `AddOrUpdateWiFiNetwork` + `ConnectNetwork` pair that a real BLE-Wi-Fi or
/// BLE-Thread commissioning would, and the Network Commissioning tests expect
/// to find the node already provisioned. Seeding the in-memory store directly
/// would not survive: `startup` resets the store before loading, so the seed
/// has to go through persistence like any other provisioned network.
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
