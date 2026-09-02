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

//! A Matter device commissioned over **BLE**, used to drive the CHIP
//! `--commissioning-method ble-wifi` / `ble-thread` flows against `rs-matter`'s
//! own BTP and BlueZ GATT stack.
//!
//! This is the non-concurrent provisioning flow: the node advertises and serves
//! BTP over BlueZ, the commissioner establishes PASE over it and provisions a
//! network, and once [`NetCtlState`] reports the provisioning done the BTP
//! transport is torn down and the node comes back up on UDP.
//!
//! Two flavours:
//! - **Wi-Fi** (default, `ble-wifi`): the network is [`MockNetCtl`], exactly as
//!   for `wireless_tests` - no radio is involved on either side of the link.
//! - **Thread** (`--thread`, `ble-thread`): the network is a REAL Thread stack -
//!   [`OtbrCtl`] against an `otbr-agent` living on the same D-Bus bus as the
//!   (mock) BlueZ. The commissioner's `ConnectNetwork` arrives over BTP and is
//!   *deferred* per the non-concurrent contract ([`DeferredNetCtl`]); once BTP
//!   is torn down the driver replays it via [`InteractionModel::connect_once`],
//!   genuinely attaching to the provisioned PAN before coming up operationally.
//!
//! The Bluetooth adapter is real as far as `rs-matter` is concerned, but it can
//! equally be one published by `bluezoo`, which is what makes this runnable on a
//! machine with no Bluetooth hardware at all.
//!
//! Arguments:
//! - `--ble-controller <n>` - bind to `hci<n>`; defaults to the first suitable
//!   adapter. The CHIP harness passes this to keep the device and the
//!   commissioner on separate adapters.
//! - `--thread` - the Thread flavour described above.
//! - `--bluer` - drive the radio through the `bluer` crate instead of
//!   `rs-matter`'s own BlueZ (zbus) client. Only available when built with the
//!   `bluer` feature; both backends speak to the same `org.bluez`, so either can
//!   equally be pointed at real hardware or at `bluezoo`. Wi-Fi flavour only.
#![allow(clippy::uninlined_format_args)]

use core::pin::pin;
use core::sync::atomic::{AtomicBool, Ordering};

use std::net::UdpSocket;

use embassy_futures::select::{select, select3, select4};

use futures_lite::StreamExt;

use async_signal::{Signal, Signals};

use log::info;
use rand::RngCore;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetCtlStatus, NetworkScanInfo, NetworkType, WirelessCreds,
};
use rs_matter::dm::clusters::thread_diag::ThreadDiag;
use rs_matter::dm::clusters::wifi_diag::{WifiDiag, WirelessDiag};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::wireless::{
    NetCtlState, NetCtlWithStatusImpl, ThreadNetworks, WifiNetworks,
};
use rs_matter::dm::networks::{NetChangeNotif, SysNetifs};
use rs_matter::dm::{Async, DataModel, Dataver, Endpoint, EpClMatcher, Node};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::im::{InteractionModel, WirelessInteractionModelState};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::transport::network::btp::{bluez, AdvData, Btp};
use rs_matter::transport::network::thread::otbr::OtbrCtl;
use rs_matter::transport::network::NoNetwork;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::zbus::Connection;
use rs_matter::{clusters, devices, root_endpoint, Matter};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

#[path = "../common/args.rs"]
mod args;

#[path = "../common/logging.rs"]
mod logging;

#[path = "../common/mock_net_ctl.rs"]
#[allow(dead_code)]
mod mock_net_ctl;

use mock_net_ctl::MockNetCtl;

/// How many provisioned networks the device can hold.
const MAX_NETWORKS: usize = 3;

static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static STATE: StaticCell<WirelessInteractionModelState<WifiNetworks<MAX_NETWORKS>>> =
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
    logging::init();

    // `--ble-controller <n>` selects `hci<n>`, matching how the CHIP harness
    // keeps the device and the commissioner on separate adapters.
    let adapter = args::parse_arg_opt_override("--ble-controller", |s| format!("hci{}", s.trim()));

    // One connection serves the whole driver: the BlueZ GATT peripheral, and -
    // in the Thread flavour - the `otbr-agent` client too (the suite publishes
    // both `org.bluez` and `io.openthread.BorderRouter` on the same bus).
    let connection = futures_lite::future::block_on(Connection::system())
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // As for `wireless_tests`: the Wi-Fi and Thread network stores are distinct
    // types, so the node is built out in one of two monomorphisations.
    if args::arg_present("--thread") {
        run_thread(connection, adapter)
    } else {
        run_wifi(connection, adapter)
    }
}

/// Bring up the Wi-Fi flavour of the node ([`MockNetCtl`], `ble-wifi`).
fn run_wifi(connection: Connection, adapter: Option<String>) -> Result<(), Error> {
    let matter = MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        args::comm_overrides(),
        &TEST_DEV_ATT,
        args::port_override(),
    ));

    let buffers = BUFFERS.uninit().init_with(MatterBuffers::init());
    let kv = matter.kv(args::file_kv_store());

    matter.startup(&kv)?;

    // Unlike `wireless_tests`, nothing is seeded here: the commissioner is
    // expected to provision the network itself over BTP, which is the whole
    // point of this driver.
    let state = STATE.init(WirelessInteractionModelState::new(WifiNetworks::<
        MAX_NETWORKS,
    >::new()));

    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);
    let mut rand = crypto.rand()?;

    let on_off = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(true),
    );

    let net_ctl_state = NetCtlState::new_with_mutex();
    let net_ctl = NetCtlWithStatusImpl::new(&net_ctl_state, MockNetCtl::new(NetworkType::Wifi));

    let im = InteractionModel::new_with_net_ctl(
        matter,
        &crypto,
        buffers,
        data_model(rand, &on_off, &net_ctl, &net_ctl),
        &kv,
        &net_ctl,
        state,
    );

    futures_lite::future::block_on(im.startup())?;

    let responder = DefaultResponder::new(&im);

    let mut respond = pin!(responder.run::<4, 4>());
    let mut im_job = pin!(im.run());

    if !matter.has_fabrics() {
        matter.print_standard_qr_text(DiscoveryCapabilities::BLE)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::BLE)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;

        // Phase 1: serve BTP over BlueZ until the commissioner has provisioned
        // a network, then drop the transport.
        let btp = Btp::new();
        // BlueZ under-reports the GATT MTU, so accept a larger negotiated one.
        btp.set_relaxed_mtu_nego(true);

        let adv_data = AdvData::new(&TEST_DEV_DET, TEST_DEV_COMM.discriminator);

        // Both backends implement the same GATT peripheral against `org.bluez`;
        // which one is exercised is a runtime choice so that a single build can
        // cover both.
        #[cfg(feature = "bluer")]
        let bluer_backend = args::arg_present("--bluer");
        #[cfg(not(feature = "bluer"))]
        let bluer_backend = false;

        if bluer_backend {
            info!("Driving the BLE peripheral through `bluer`");
        } else {
            info!("Driving the BLE peripheral through the BlueZ (zbus) client");
        }

        #[cfg(feature = "bluer")]
        let mut bluetooth_bluer = pin!(async_compat::Compat::new(
            rs_matter::transport::network::btp::bluer::run_peripheral(
                adapter.as_deref(),
                "MT",
                &adv_data,
                &btp,
            )
        ));

        let mut bluetooth_bluez = pin!(bluez::run_peripheral(
            &connection,
            adapter.as_deref(),
            "MT",
            &adv_data,
            &btp,
        ));

        let mut bluetooth = pin!(async {
            #[cfg(feature = "bluer")]
            if bluer_backend {
                return bluetooth_bluer.as_mut().await;
            }

            bluetooth_bluez.as_mut().await
        });

        let mut transport = pin!(matter.run(&crypto, &btp, &btp, NoNetwork));
        let mut prov = pin!(async {
            NetCtlState::wait_prov_ready(&net_ctl_state, &btp).await;
            Ok(())
        });

        let all = select4(
            &mut transport,
            &mut bluetooth,
            &mut prov,
            select(&mut respond, &mut im_job).coalesce(),
        );

        futures_lite::future::block_on(all.coalesce())?;

        matter.reset_transport()?;
    }

    // Phase 2: operational, over UDP.
    let socket = async_io::Async::<UdpSocket>::bind(args::bind_addr())?;

    let mut mdns = pin!(mdns::run_mdns(matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, &socket));

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

/// Bring up the Thread flavour of the node ([`OtbrCtl`], `ble-thread`).
fn run_thread(connection: Connection, adapter: Option<String>) -> Result<(), Error> {
    let otbr_ctl = OtbrCtl::new(&connection);

    // Unlike `thread_tests`, there is no startup attach and no seeded network:
    // the commissioner provisions the (real) PAN itself over BTP, which is the
    // whole point of this flavour.
    let state = THREAD_STATE.init(WirelessInteractionModelState::new(ThreadNetworks::<
        MAX_NETWORKS,
    >::new()));

    let matter = MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        args::comm_overrides(),
        &TEST_DEV_ATT,
        args::port_override(),
    ));

    let buffers = BUFFERS.uninit().init_with(MatterBuffers::init());
    let kv = matter.kv(args::file_kv_store());

    matter.startup(&kv)?;

    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);
    let mut rand = crypto.rand()?;

    let on_off = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(true),
    );

    let net_ctl_state = NetCtlState::new_with_mutex();
    let deferred_ctl = DeferredNetCtl::new(&otbr_ctl);
    let net_ctl = NetCtlWithStatusImpl::new(&net_ctl_state, &deferred_ctl);

    let im = InteractionModel::new_with_net_ctl(
        matter,
        &crypto,
        buffers,
        data_model_thread(rand, &on_off, &otbr_ctl, &net_ctl),
        &kv,
        &net_ctl,
        state,
    );

    futures_lite::future::block_on(im.startup())?;

    let responder = DefaultResponder::new(&im);

    let mut respond = pin!(responder.run::<4, 4>());
    let mut im_job = pin!(im.run());

    if !matter.has_fabrics() {
        matter.print_standard_qr_text(DiscoveryCapabilities::BLE)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::BLE)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;

        // Phase 1: serve BTP over BlueZ until the commissioner has provisioned
        // a network, then drop the transport. The `ConnectNetwork` it sends is
        // answered without touching the radio (see `DeferredNetCtl`).
        let btp = Btp::new();
        // BlueZ under-reports the GATT MTU, so accept a larger negotiated one.
        btp.set_relaxed_mtu_nego(true);

        let adv_data = AdvData::new(&TEST_DEV_DET, TEST_DEV_COMM.discriminator);

        let mut bluetooth = pin!(bluez::run_peripheral(
            &connection,
            adapter.as_deref(),
            "MT",
            &adv_data,
            &btp,
        ));

        let mut transport = pin!(matter.run(&crypto, &btp, &btp, NoNetwork));
        let mut prov = pin!(async {
            NetCtlState::wait_prov_ready(&net_ctl_state, &btp).await;
            Ok(())
        });

        let all = select4(
            &mut transport,
            &mut bluetooth,
            &mut prov,
            select(&mut respond, &mut im_job).coalesce(),
        );

        futures_lite::future::block_on(all.coalesce())?;

        matter.reset_transport()?;

        // Replay the deferred `ConnectNetwork`: with BTP gone, the controller
        // goes live and the attach happens for real, off the credentials the
        // commissioner stored - and it must complete before the node comes up
        // operationally, because the commissioner's next step is establishing
        // CASE over the operational network.
        deferred_ctl.set_live();

        let network_id = net_ctl.last_network_id(|id| {
            id.map(|id| id.to_vec())
                .ok_or_else(|| Error::from(ErrorCode::InvalidState))
        })?;

        futures_lite::future::block_on(im.connect_once(&network_id))?;
    } else {
        // Operational restart: no BTP phase; the connection manager re-attaches
        // by itself, so all the controller needs is to be live.
        deferred_ctl.set_live();
    }

    // Phase 2: operational, over UDP.
    let socket = async_io::Async::<UdpSocket>::bind(args::bind_addr())?;

    let mut mdns = pin!(mdns::run_mdns(matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, &socket));

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

/// A [`NetCtl`] wrapper implementing the **non-concurrent** provisioning
/// contract over a real network controller.
///
/// While provisioning over BTP is in progress, `connect` succeeds *without*
/// touching the radio: the command's response has to reach the commissioner
/// over the BLE link, which on a radio-constrained device could not survive
/// the operational network coming up. The driver later flips the wrapper
/// [`live`](Self::set_live) once BTP is torn down and replays the attach via
/// [`InteractionModel::connect_once`], off the credentials the commissioner
/// stored; from that point every `connect` (including the connection
/// manager's reconnects) goes straight through.
struct DeferredNetCtl<'a> {
    ctl: &'a OtbrCtl<'a>,
    live: AtomicBool,
}

impl<'a> DeferredNetCtl<'a> {
    const fn new(ctl: &'a OtbrCtl<'a>) -> Self {
        Self {
            ctl,
            live: AtomicBool::new(false),
        }
    }

    /// Stop deferring: forward `connect` to the wrapped controller from now on.
    fn set_live(&self) {
        self.live.store(true, Ordering::Relaxed);
    }
}

impl NetCtl for DeferredNetCtl<'_> {
    fn net_type(&self) -> NetworkType {
        self.ctl.net_type()
    }

    fn connect_max_time_seconds(&self) -> u8 {
        self.ctl.connect_max_time_seconds()
    }

    fn scan_max_time_seconds(&self) -> u8 {
        self.ctl.scan_max_time_seconds()
    }

    fn supported_wifi_bands<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnMut(rs_matter::dm::clusters::net_comm::WiFiBandEnum) -> Result<(), Error>,
    {
        self.ctl.supported_wifi_bands(f)
    }

    fn supported_thread_features(
        &self,
    ) -> rs_matter::dm::clusters::decl::network_commissioning::ThreadCapabilitiesBitmap {
        self.ctl.supported_thread_features()
    }

    fn thread_version(&self) -> u16 {
        self.ctl.thread_version()
    }

    async fn scan<F>(&self, network: Option<&[u8]>, f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>,
    {
        self.ctl.scan(network, f).await
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        if self.live.load(Ordering::Relaxed) {
            self.ctl.connect(creds).await
        } else {
            // Deferred: report success so provisioning can conclude over BTP;
            // the credentials are in the network store, whence `connect_once`
            // replays them once the BLE phase is over.
            Ok(creds.check_match(self.net_type())?)
        }
    }
}

impl NetChangeNotif for DeferredNetCtl<'_> {
    async fn wait_changed(&self) {
        self.ctl.wait_changed().await
    }
}

impl rs_matter::utils::sync::DynBase for DeferredNetCtl<'_> {}

impl WirelessDiag for DeferredNetCtl<'_> {
    fn connected(&self) -> Result<bool, Error> {
        self.ctl.connected()
    }
}

/// The Node meta-data for the Wi-Fi flavour.
const NODE: Node<'static> = Node {
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

fn data_model<'a, OH: OnOffHooks, LH: LevelControlHooks, T>(
    mut rand: impl RngCore + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
    wifi_diag: &'a dyn WifiDiag,
    net_ctl: T,
) -> impl DataModel + 'a
where
    T: NetCtl + NetCtlStatus + 'a,
{
    (
        NODE,
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
