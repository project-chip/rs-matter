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

//! A dedicated Matter device for ConnectedHomeIP YAML integration tests.
//! Implements On/Off and Unit Testing clusters over Ethernet.

use core::pin::pin;

use std::net::UdpSocket;

use async_signal::{Signal, Signals};

use embassy_futures::select::{select3, select4};

use futures_lite::StreamExt;

use log::{info, warn};

use rand::RngCore;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::acl::{self, ClusterHandler as _};
use rs_matter::dm::clusters::adm_comm::{self, ClusterHandler as _};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::test::TestOnOffDeviceLogic;
use rs_matter::dm::clusters::app::on_off::{self, OnOffHandler, OnOffHooks};
use rs_matter::dm::clusters::basic_info::{
    AttributeId as BasicInfoAttributeId, BasicInfoConfig, ColorEnum, PairingHintFlags,
    ProductAppearance, ProductFinishEnum, FULL_CLUSTER as BASIC_INFO_FULL_CLUSTER,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::eth_diag::{self, ClusterHandler as _};
use rs_matter::dm::clusters::gen_comm::{self, ClusterHandler as _};
use rs_matter::dm::clusters::gen_diag::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::grp_key_mgmt::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::{self, SharedNetworks};
use rs_matter::dm::clusters::noc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::unit_testing::{
    ClusterHandler as _, UnitTestingHandler, UnitTestingHandlerData,
};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE};
use rs_matter::dm::endpoints::{self, ROOT_ENDPOINT_ID};
use rs_matter::dm::events::Events;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::subscriptions::Subscriptions;
use rs_matter::dm::{
    Async, AsyncHandler, AsyncMetadata, Cluster, DataModel, Dataver, EmptyHandler, Endpoint,
    EpClMatcher, Node,
};
use rs_matter::error::Error;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{FileKvBlobStore, SharedKvBlobStore};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::sc::pase::{Spake2pVerifierPassword, Spake2pVerifierPasswordRef};
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::BasicCommData;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

// Statically allocate in BSS the bigger objects
// `rs-matter` supports efficient initialization of BSS objects (with `init`)
// as well as just allocating the objects on-stack or on the heap.
static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<PooledBuffers<20, rs_matter::dm::IMBuffer>> = StaticCell::new();
static SUBSCRIPTIONS: StaticCell<Subscriptions> = StaticCell::new();
static EVENTS: StaticCell<Events> = StaticCell::new();
static KV_BUF: StaticCell<[u8; 4096]> = StaticCell::new();
static UNIT_TESTING_DATA: StaticCell<RefCell<UnitTestingHandlerData>> = StaticCell::new();

fn main() -> Result<(), Error> {
    // Enable detailed backtraces for debugging test failures
    // (Temporarily disabled to keep TC_SC_3_4 traces readable.)
    // std::env::set_var("RUST_BACKTRACE", "1");

    // Special logging configuration compatible with ConnectedHomeIP YAML tests
    // Log to stdout with simplified format at debug level as required by chip-tool tests
    env_logger::builder()
        .format(|buf, record| {
            use std::io::Write;
            writeln!(buf, "{}: {}", record.level(), record.args())
        })
        .target(env_logger::Target::Stdout)
        .filter_level(::log::LevelFilter::Debug)
        .init();

    info!(
        "Matter memory: Matter (BSS)={}B, IM Buffers (BSS)={}B, Subscriptions (BSS)={}B",
        core::mem::size_of::<Matter>(),
        core::mem::size_of::<PooledBuffers<20, rs_matter::dm::IMBuffer>>(),
        core::mem::size_of::<Subscriptions>()
    );

    // Optional `--discriminator <u16>` / `--passcode <u32>` overrides for the
    // hardcoded `TEST_DEV_COMM` defaults. Used by tests like TC-SC-7.1 that
    // assert the device is *not* using the spec-default `3840`/`20202021`.
    let comm_data = parse_comm_overrides();
    let passcode = u32::from_le_bytes(*comm_data.password.access());
    // Optional `--port <u16>` override for the default Matter UDP/TCP port.
    // Used by tests that spawn a *second* CHIP Matter app under the test
    // framework's control (e.g. TC-SC-3.5, where `chip-all-clusters-app`
    // takes the default 5540 as TH_SERVER and the rs-matter DUT must move
    // out of the way).
    let port = parse_port_override();
    info!(
        "Commissioning data: discriminator={}, passcode={}, port={}",
        comm_data.discriminator, passcode, port,
    );

    let matter = MATTER.uninit().init_with(Matter::init(
        &BASIC_INFO,
        comm_data,
        &TEST_DEV_ATT,
        rs_matter::utils::epoch::sys_epoch,
        port,
    ));

    // Create the event queue
    let events = EVENTS.uninit().init_with(Events::init_default());

    // Persistence
    let kv_buf = KV_BUF.uninit().init_zeroed().as_mut_slice();
    let mut kv = FileKvBlobStore::new_default();
    futures_lite::future::block_on(matter.load_persist(&mut kv, kv_buf))?;
    futures_lite::future::block_on(events.load_persist(&mut kv, kv_buf))?;

    // Create the transport buffers
    let buffers = BUFFERS.uninit().init_with(PooledBuffers::init(0));

    // Create the subscriptions
    let subscriptions = SUBSCRIPTIONS.uninit().init_with(Subscriptions::init());

    // Create the crypto instance
    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // Our on-off cluster
    let on_off_handler_1 = OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(false),
    );

    // On-off cluster for 2nd endpoint
    let on_off_handler_2 = OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        2,
        TestOnOffDeviceLogic::new(false),
    );

    // Our unit testing cluster data
    let unit_testing_data = UNIT_TESTING_DATA
        .uninit()
        .init_with(RefCell::init(UnitTestingHandlerData::init()));

    // `--app-pipe <path>` is only ever supplied by `TC_BINFO_3_2`. We use it
    // as the trigger to switch the device's BasicInformation cluster metadata
    // to the variant that exposes the provisional `ConfigurationVersion`
    // attribute, while leaving the default chip_tool_tests build (used by
    // `TestBasicInformation` and everything else) on the upstream-1.5
    // attribute set.
    let app_pipe = parse_app_pipe_override();
    let node: &'static Node<'static> = if app_pipe.is_some() {
        &NODE_BINFO_CV_EXPOSED
    } else {
        &NODE
    };

    // Create the Data Model instance
    let dm = DataModel::new(
        matter,
        &crypto,
        buffers,
        subscriptions,
        events,
        dm_handler(
            node,
            rand,
            unit_testing_data,
            &on_off_handler_1,
            &on_off_handler_2,
        ),
        SharedKvBlobStore::new(kv, kv_buf),
        SharedNetworks::new(EthNetwork::new_default()),
    );

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&dm);
    info!(
        "Responder memory: Responder (stack)={}B, Runner fut (stack)={}B",
        core::mem::size_of_val(&responder),
        core::mem::size_of_val(&responder.run::<16, 4>())
    );

    // Run the responder with up to 16 handlers (i.e. 16 exchanges can be handled simultaneously).
    // Clients trying to open more exchanges than the ones currently running will get
    // "I'm busy, please try again later" from the busy-responder pool (4 handlers).
    // 16 / 4 chosen to match `max-sessions-32`: TC_SC_3_6 establishes 15 subscriptions
    // back-to-back and the initial-report exchanges overlap with the next handshake,
    // overflowing the smaller pool with IM BUSY (status 0x9c).
    let mut respond = pin!(responder.run::<16, 4>());

    // Run the background job of the data model
    let mut dm_job = pin!(dm.run());

    // Bind the UDP socket. When `--port` is overridden we have to bind to
    // the same port instead of the default `MATTER_SOCKET_BIND_ADDR` (which
    // is hard-coded to 5540).
    let bind_addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        port,
        0,
        0,
    ));
    let udp_socket = async_io::Async::<UdpSocket>::bind(bind_addr)?;

    #[allow(unused_mut)]
    let (mut net_send, mut net_recv, mut net_multicast) = (&udp_socket, &udp_socket, &udp_socket);

    // Optionally bind a TCP listener as well
    #[cfg(feature = "test-tcp")]
    let tcp = {
        use rs_matter::transport::network::tcp::TcpNetwork;

        let tcp_socket = async_io::Async::<std::net::TcpListener>::bind(bind_addr)?;

        info!("TCP transport enabled, listening on {}", bind_addr);

        TcpNetwork::<8>::new(tcp_socket)
    };

    // Optionally create a chained UDP+TCP network
    #[cfg(feature = "test-tcp")]
    let (mut net_send, mut net_recv, mut net_multicast) = {
        use rs_matter::transport::network::{Address, ChainedNetwork};

        let net_send = ChainedNetwork::new(|addr: &Address| addr.is_tcp(), &tcp, net_send);
        let net_recv = ChainedNetwork::new(|addr: &Address| addr.is_tcp(), &tcp, net_recv);

        (net_send, net_recv, net_multicast)
    };

    info!(
        "Transport memory: Transport fut (stack)={}B, mDNS fut (stack)={}B",
        core::mem::size_of_val(&matter.run(
            &crypto,
            &mut net_send,
            &mut net_recv,
            &mut net_multicast
        )),
        core::mem::size_of_val(&mdns::run_mdns(matter, &crypto))
    );

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &mut net_send, &mut net_recv, &mut net_multicast));

    // We need to always print the QR text, because the test runner expects it to be printed
    // even if the device is already commissioned
    matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;

    if !matter.is_commissioned() {
        // If the device is not commissioned yet, print the QR code to the console
        // and enable basic commissioning

        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, dm.change_notify())?;
    }

    // Optional `--app-pipe <path>` CLI integration.
    //
    // The CHIP Python test framework (`MatterBaseTest::write_to_app_pipe`) sends out-of-band JSON
    // commands to the DUT through a named pipe at the given path.
    let mut app_pipe_actions = pin!(run_app_pipe_actions(app_pipe, |action| {
        if action.contains("SimulateConfigurationVersionChange") {
            dm.bump_configuration_version()?;

            Ok(true)
        } else {
            Ok(false)
        }
    }));

    // Listen to SIGTERM (or Ctrl-C on Windows, where SIGTERM is not
    // supported by `async-signal`) because at the end of the test we'll
    // receive it.
    #[cfg(not(windows))]
    let mut term_signal = Signals::new([Signal::Term])?;
    #[cfg(windows)]
    let mut term_signal = Signals::new([Signal::Int])?;
    let mut term = pin!(async {
        term_signal.next().await;
        Ok(())
    });

    // Combine all async tasks in a single one
    let all = select4(
        &mut transport,
        &mut mdns,
        &mut app_pipe_actions,
        select3(&mut respond, &mut dm_job, &mut term).coalesce(),
    );

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all.coalesce())
}

/// Overriden so that:
/// - We can set the product appearance to what the `TestBasicInformation` tests expect;
/// - We can set the device type and pairing hint to what the `TestDiscovery` tests expect.
/// - When the `test-tcp` feature is enabled, we advertise TCP support via mDNS (`T=1`).
/// - We advertise `MaxPathsPerInvoke = 1`. This is the spec minimum and keeps
///   `TC_IDM_1_4` on the short path (it skips steps 3+ for devices that report 1),
///   avoiding test-only requirements like `TestEventTriggers` on the General Diagnostics
///   cluster which we do not implement.
const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    product_appearance: ProductAppearance {
        finish: ProductFinishEnum::Satin,
        color: Some(ColorEnum::Purple),
    },
    device_type: Some(0x0101),
    pairing_hint: PairingHintFlags::PRESS_RESET_BUTTON,
    tcp_supported: cfg!(feature = "test-tcp"),
    max_paths_per_invoke: 1,
    ..TEST_DEV_DET
};

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(geth),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                UnitTestingHandler::CLUSTER
            ),
        },
        Endpoint {
            id: 2,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER
            ),
        },
    ],
};

/// `BasicInformation` cluster metadata that exposes the provisional
/// `ConfigurationVersion` attribute (only `Reachable` is excluded). Used by
/// `NODE_BINFO_CV_EXPOSED` when the test runner wires the device up for
/// `TC_BINFO_3_2` (signalled by the presence of `--app-pipe`).
const BASIC_INFO_CLUSTER_CV_EXPOSED: Cluster<'static> = BASIC_INFO_FULL_CLUSTER
    .with_attrs(rs_matter::except!(BasicInfoAttributeId::Reachable))
    .with_cmds(rs_matter::with!());

/// Alternate Node metadata used when the test framework signals it intends
/// to run `TC_BINFO_3_2` (via `--app-pipe`). It's identical to `NODE` except
/// that endpoint 0's cluster list substitutes
/// `BASIC_INFO_CLUSTER_CV_EXPOSED` for the standard `BasicInfoHandler::CLUSTER`,
/// putting `ConfigurationVersion` in `AttributeList` and accepting reads on
/// it. The runtime handler chain (`with_eth_sys`) is unchanged: the standard
/// `BasicInfoHandler` already implements `configuration_version()` against
/// `BasicInfoSettings`, so the read dispatches to it once the metadata
/// allows the attribute through.
///
/// We can't condition this at the rs-matter library level because `Cluster`'s
/// `WithAttrs` filter is a plain `fn`-pointer with no access to runtime
/// state, so we keep the choice in the test app and pick at startup. Other
/// chip_tool_tests-driven YAML/Python tests (notably `TestBasicInformation`,
/// which asserts an exact `AttributeList` from upstream's 1.5 dataset where
/// `ConfigurationVersion` was deliberately removed in
/// `connectedhomeip@faf4d09ad1`) keep using the default `NODE`.
const NODE_BINFO_CV_EXPOSED: Node<'static> = Node {
    endpoints: &[
        Endpoint {
            id: ROOT_ENDPOINT_ID,
            device_types: devices!(DEV_TYPE_ROOT_NODE),
            // Manually expanded `clusters!(geth;)` with `BasicInfoHandler::CLUSTER`
            // replaced by `BASIC_INFO_CLUSTER_CV_EXPOSED`. Keep this in sync
            // with `clusters!(geth;)` in `rs-matter/src/dm/types/cluster.rs`.
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                acl::AclHandler::CLUSTER,
                BASIC_INFO_CLUSTER_CV_EXPOSED,
                gen_comm::GenCommHandler::CLUSTER,
                gen_diag::GenDiagHandler::CLUSTER,
                adm_comm::AdminCommHandler::CLUSTER,
                noc::NocHandler::CLUSTER,
                grp_key_mgmt::GrpKeyMgmtHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                net_comm::NetworkType::Ethernet.cluster(),
                eth_diag::EthDiagHandler::CLUSTER,
            ),
        },
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                UnitTestingHandler::CLUSTER
            ),
        },
        Endpoint {
            id: 2,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off and unit testing handlers.
fn dm_handler<'a, OH: OnOffHooks, LH: LevelControlHooks>(
    node: &'static Node<'static>,
    mut rand: impl RngCore + Copy,
    unit_testing_data: &'a RefCell<UnitTestingHandlerData>,
    on_off_1: &'a OnOffHandler<'a, OH, LH>,
    on_off_2: &'a OnOffHandler<'a, OH, LH>,
) -> impl AsyncMetadata + AsyncHandler + 'a {
    (
        node,
        endpoints::with_eth_sys(
            &false,
            &(),
            &SysNetifs,
            rand,
            EmptyHandler
                // Clusters for Endpoint 1
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
                    on_off::HandlerAsyncAdaptor(on_off_1),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(UnitTestingHandler::CLUSTER.id)),
                    Async(
                        UnitTestingHandler::new(Dataver::new_rand(&mut rand), unit_testing_data)
                            .adapt(),
                    ),
                )
                // (mostly) Similar Clusters for Endpoint 2
                .chain(
                    EpClMatcher::new(Some(2), Some(desc::DescHandler::CLUSTER.id)),
                    Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                )
                .chain(
                    EpClMatcher::new(Some(2), Some(groups::GroupsHandler::CLUSTER.id)),
                    Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                )
                .chain(
                    EpClMatcher::new(Some(2), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                    on_off::HandlerAsyncAdaptor(on_off_2),
                ),
        ),
    )
}

/// Parse optional `--discriminator <u16>` / `--passcode <u32>` CLI overrides
/// and return a `BasicCommData` based on those (or the spec defaults when not
/// provided).
///
/// Used by tests such as TC-SC-7.1 that assert the device is *not* using the
/// spec-default discriminator (3840) and passcode (20202021).
fn parse_comm_overrides() -> BasicCommData {
    let mut data = TEST_DEV_COMM;

    if let Some(discriminator) =
        parse_arg_opt_override("--discriminator", |s| s.parse::<u16>().ok()).flatten()
    {
        data.discriminator = discriminator;
    }

    if let Some(passcode) =
        parse_arg_opt_override("--passcode", |s| s.parse::<u32>().ok()).flatten()
    {
        data.password = Spake2pVerifierPassword::new_from_ref(Spake2pVerifierPasswordRef::new(
            &passcode.to_le_bytes(),
        ));
    }

    data
}

/// Parse an optional `--port <u16>` CLI override and return the Matter UDP/TCP
/// port to bind on. Defaults to `MATTER_PORT` (5540) when not provided.
///
/// Used by tests like TC-SC-3.5 that spawn a *second* CHIP Matter app
/// (`chip-all-clusters-app`) under the test framework's control. That app
/// hard-codes 5540 as TH_SERVER, so the rs-matter DUT must move out of the
/// way to avoid a `bind: Address already in use`.
fn parse_port_override() -> u16 {
    parse_arg_opt_override("--port", |s| s.parse::<u16>().unwrap_or(MATTER_PORT))
        .unwrap_or(MATTER_PORT)
}

/// Parse an optional `--app-pipe <path>` CLI override. When present, the CHIP
/// Python test framework writes JSON command lines to that path; we spin up
/// an OS-thread reader to act on them.
fn parse_app_pipe_override() -> Option<String> {
    parse_arg_opt_override("--app-pipe", |s| s.to_string())
}

fn parse_arg_opt_override<T>(opt: &str, conv: impl FnOnce(&str) -> T) -> Option<T> {
    let args: Vec<String> = std::env::args().collect();

    let mut i = 1;
    while i < args.len() {
        if args[i] == opt && i + 1 < args.len() {
            return Some(conv(&args[i + 1]));
        }

        i += 1;
    }

    None
}

/// Read JSON command lines from the named pipe at `path` and dispatch them to
/// `bump` on the calling task — which is the main thread, so it's free to
/// touch `&Matter` / `&DataModel` directly (neither is `Sync`).
async fn run_app_pipe_actions(
    path: Option<String>,
    mut action: impl FnMut(String) -> Result<bool, Error>,
) -> Result<(), Error> {
    let Some(path) = path else {
        info!("No --app-pipe provided; out-of-band command channel disabled.");
        core::future::pending::<()>().await;
        unreachable!()
    };
    info!("App pipe enabled at {path}");

    use blocking::{unblock, Unblock};
    use futures_lite::io::{AsyncBufReadExt, BufReader};

    // Best-effort: create the FIFO if it doesn't already exist. Shell out to
    // `mkfifo` to avoid pulling in a `libc`/`nix` dep just for this. Errors
    // here are non-fatal: if the file already exists (or is a regular file
    // from a prior run) the reader open below will surface a useful error.
    let _ = std::process::Command::new("mkfifo").arg(&path).status();

    loop {
        let path_clone = path.clone();
        let file = match unblock(move || std::fs::File::open(&path_clone)).await {
            Ok(f) => f,
            Err(e) => {
                log::warn!("Failed to open app pipe {}: {}", path, e);
                embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
                continue;
            }
        };

        let mut reader = BufReader::new(Unblock::new(file));
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // writer closed; reopen
                Ok(_) => {
                    // Avoid a JSON dep: the framework sends one JSON dict per
                    // line and we only care about a single command name.

                    let line = line.trim_end();
                    info!("[app-pipe] received: {line}");

                    match action(line.to_string()) {
                        Ok(true) => info!("Processed"),
                        Ok(false) => info!("Skipped"),
                        Err(e) => warn!("Failed: {}", e),
                    }
                }
                Err(e) => {
                    log::warn!("Error reading from app pipe: {}", e);
                    break;
                }
            }
        }
    }
}
