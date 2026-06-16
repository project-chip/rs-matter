/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

#![recursion_limit = "256"]

use core::pin::pin;

use std::net::UdpSocket;

use async_signal::{Signal, Signals};

use embassy_futures::select::{select, select4};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;

use futures_lite::StreamExt;

use log::{info, warn};

use rand::RngCore;

use rs_matter::bdx::{Bdx, BdxDownloadInitiator, PROTO_ID_BDX};
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
use rs_matter::dm::clusters::binding::{self, BindingHandler, Bindings};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::diagnostic_logs::{
    self, DiagnosticLogsHandler, DiagnosticLogsProvider, IntentEnum,
};
use rs_matter::dm::clusters::eth_diag::{self, ClusterHandler as _};
use rs_matter::dm::clusters::fixed_label::{self, FixedLabelEntry, FixedLabelHandler};
use rs_matter::dm::clusters::gen_comm::{self, ClusterHandler as _};
use rs_matter::dm::clusters::gen_diag::{self, ClusterHandler as _, GenDiag};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::grp_key_mgmt::{self, ClusterHandler as _};
use rs_matter::dm::clusters::identify::{self, IdentifyHandler};
use rs_matter::dm::clusters::net_comm::{self, SharedNetworks};
use rs_matter::dm::clusters::noc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::ota_provider::{
    BdxBuffer, ClusterAsyncHandler, DownloadProtocolEnum, OtaBdxHandler, OtaImageMeta, OtaImages,
    OtaImagesRegistry, OtaProviderHandler, OtaQueryOutcome, StatusEnum,
};
use rs_matter::dm::clusters::ota_requestor::{
    parse_bdx_url, ClusterHandler as _, OtaRequestorHandler, OtaState, Provider, Providers,
};
use rs_matter::dm::clusters::sw_diag::SoftwareFault;
use rs_matter::dm::clusters::unit_testing::{
    ClusterHandler as _, UnitTestingHandler, UnitTestingHandlerData,
};
use rs_matter::dm::clusters::user_label::{self, UserLabelHandler, UserLabels};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE};
use rs_matter::dm::endpoints::{self, ROOT_ENDPOINT_ID};
use rs_matter::dm::events::Events;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::subscriptions::Subscriptions;
use rs_matter::dm::{
    Async, AttrChangeNotifier, Cluster, DataModel, DataModelHandler, Dataver, Endpoint,
    EpClMatcher, Node,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::im::PROTO_ID_INTERACTION_MODEL;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::SharedKvBlobStore;
use rs_matter::respond::{ChainedExchangeHandler, Responder};
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::sc::SecureChannel;
use rs_matter::transport::exchange::Exchange;
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::utils::sync::Notification;
use rs_matter::{clusters, devices, Matter};

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

#[path = "../common/args.rs"]
mod args;

// Statically allocate in BSS the bigger objects
// `rs-matter` supports efficient initialization of BSS objects (with `init`)
// as well as just allocating the objects on-stack or on the heap.
static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<PooledBuffers<20, rs_matter::dm::IMBuffer>> = StaticCell::new();
static SUBSCRIPTIONS: StaticCell<Subscriptions> = StaticCell::new();
static EVENTS: StaticCell<Events> = StaticCell::new();
static KV_BUF: StaticCell<[u8; 4096]> = StaticCell::new();
static UNIT_TESTING_DATA: StaticCell<RefCell<UnitTestingHandlerData>> = StaticCell::new();
static GEN_DIAG: StaticCell<TestEventTriggerDiag> = StaticCell::new();
// UserLabel registry — host endpoints and labels-per-endpoint counts
// match `dm_handler`'s `UserLabelHandler<'_, E, N>` parameterisation.
static USER_LABELS: StaticCell<UserLabels<1, 4>> = StaticCell::new();
// Binding registry. Capacity 16 — `TestBinding` writes a 17-entry
// table and expects `RESOURCE_EXHAUSTED`, so this bound is what makes
// that step pass. Two fabrics × ~8 entries per fabric is comfortably
// above what the YAML's per-fabric scenarios actually exercise.
static BINDINGS: StaticCell<Bindings<16>> = StaticCell::new();
// OTA Provider role (gated behind `--filepath`): the file-backed image source
// and a small pool of BDX block-staging buffers.
static OTA_IMAGES: StaticCell<OtaFileImages> = StaticCell::new();
static BDX_BUFFERS: StaticCell<PooledBuffers<2, BdxBuffer>> = StaticCell::new();

// Diagnostic Logs role (driven by `--end_user_support_log` / `--network_diagnostics_log`
// / `--crash_log`): the file-backed log source, plus a small pool of BDX staging
// buffers (one for an inline read, one for a concurrent BDX transfer).
static LOG_PROVIDER: StaticCell<LogFileProvider> = StaticCell::new();
static DLOG_BUFFERS: StaticCell<PooledBuffers<2, BdxBuffer>> = StaticCell::new();

static SW_FAULT_NOTIFY: Notification<CriticalSectionRawMutex> = Notification::new();

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
    let comm_data = args::comm_overrides();
    let passcode = u32::from_le_bytes(*comm_data.password.access());
    // Optional `--port <u16>` override for the default Matter UDP/TCP port.
    // Used by tests that spawn a *second* CHIP Matter app under the test
    // framework's control (e.g. TC-SC-3.5, where `chip-all-clusters-app`
    // takes the default 5540 as TH_SERVER and the rs-matter DUT must move
    // out of the way).
    let port = args::port_override();
    info!(
        "Commissioning data: discriminator={}, passcode={}, port={}",
        comm_data.discriminator, passcode, port,
    );

    let matter =
        MATTER
            .uninit()
            .init_with(Matter::init(&BASIC_INFO, comm_data, &TEST_DEV_ATT, port));

    // Create the event queue
    let events = EVENTS.uninit().init_with(Events::init());

    // Persistence
    let kv_buf = KV_BUF.uninit().init_zeroed().as_mut_slice();
    let mut kv = args::file_kv_store();
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

    // Shared UserLabel registry. We only host the UserLabel cluster on
    // the root endpoint here, so `E = 1` is enough (raise it if more
    // endpoints later acquire the cluster). Loaded from
    // KV *before* the data model accepts commissioner traffic so the
    // post-reboot `Verify User Label List after reboot` step of the
    // `TestUserLabelCluster` YAML test sees the labels the previous
    // boot wrote.
    let user_labels = USER_LABELS.uninit().init_with(UserLabels::init());
    futures_lite::future::block_on(user_labels.load_persist(&mut kv, kv_buf))?;

    let user_label_handler =
        UserLabelHandler::new(Dataver::new_rand(&mut rand), ROOT_ENDPOINT_ID, user_labels);

    // Binding registry — same `StaticCell` + in-place-init pattern as
    // UserLabels. Loaded from KV before the data model accepts traffic
    // so bindings written pre-reboot survive.
    let bindings = BINDINGS.uninit().init_with(Bindings::init());
    futures_lite::future::block_on(bindings.load_persist(&mut kv, kv_buf))?;

    let binding_handler_ep0 =
        BindingHandler::new(Dataver::new_rand(&mut rand), ROOT_ENDPOINT_ID, bindings);
    let binding_handler_ep1 = BindingHandler::new(Dataver::new_rand(&mut rand), 1, bindings);

    // Our unit testing cluster data
    let unit_testing_data = UNIT_TESTING_DATA
        .uninit()
        .init_with(RefCell::init(UnitTestingHandlerData::init()));

    // `--app-pipe <path>` is only ever supplied by `TC_BINFO_3_2`. We use it
    // as the trigger to switch the device's BasicInformation cluster metadata
    // to the variant that exposes the provisional `ConfigurationVersion`
    // attribute, while leaving the default system_tests build (used by
    // `TestBasicInformation` and everything else) on the upstream-1.5
    // attribute set.
    // OTA role inputs: the `OTA_SuccessfulTransfer` integration test starts the
    // provider with `--filepath <ota image>` and the requestor with
    // `--otaDownloadPath <dst>`. The OTA clusters are always present in `NODE`
    // now, so these only configure behavior (the image to serve / where to write
    // the download); they don't change the device composition.
    let ota_filepath = args::parse_arg_opt_override("--filepath", |s| s.to_string());
    let ota_download_path = args::parse_arg_opt_override("--otaDownloadPath", |s| s.to_string());
    let ota_images: &OtaFileImages = OTA_IMAGES.init(OtaFileImages::new(ota_filepath));
    let ota_providers = Providers::new();
    let ota_state = OtaState::new(ROOT_ENDPOINT_ID);

    // Diagnostic Logs role inputs: `TestDiagnosticLogs` (re)starts the DUT with a
    // log-file path per intent. Always wired (the cluster is always present); when
    // a path is absent or the file is missing, that intent reports `NoLogs`.
    let log_provider: &LogFileProvider = LOG_PROVIDER.init(LogFileProvider::new(
        args::parse_arg_opt_override("--end_user_support_log", |s| s.to_string()),
        args::parse_arg_opt_override("--network_diagnostics_log", |s| s.to_string()),
        args::parse_arg_opt_override("--crash_log", |s| s.to_string()),
    ));
    let dlog_buffers: &PooledBuffers<2, BdxBuffer> =
        DLOG_BUFFERS.uninit().init_with(PooledBuffers::init(0));

    let app_pipe = parse_app_pipe_override();
    let node: &'static Node<'static> = if app_pipe.is_some() {
        &NODE_BINFO_CV_EXPOSED
    } else {
        &NODE
    };

    // Optional `--enable-key <hex32>` plumbing for `TC_TestEventTrigger`.
    // When present, the device flips `GeneralDiagnostics::TestEventTriggersEnabled`
    // to true and validates the `TestEventTrigger` invoke key against the
    // supplied bytes. Without it, the default `()` `GenDiag` impl reports
    // disabled and rejects every trigger.
    let gen_diag: &'static dyn GenDiag = if let Some(key) = parse_enable_key_override() {
        info!("TestEventTrigger enabled with configured 16-byte key");
        GEN_DIAG.init(TestEventTriggerDiag { enable_key: key })
    } else {
        &()
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
            gen_diag,
            rand,
            unit_testing_data,
            &on_off_handler_1,
            &on_off_handler_2,
            &user_label_handler,
            &binding_handler_ep0,
            &binding_handler_ep1,
            ota_images,
            &ota_providers,
            &ota_state,
            dlog_buffers,
            log_provider,
        ),
        SharedKvBlobStore::new(kv, kv_buf),
        SharedNetworks::new(EthNetwork::new_default()),
    );

    // Responder = the default IM + Secure Channel handler chain, plus a BDX
    // protocol handler for the OTA Provider role. BDX is inert without OTA
    // traffic, so this is equivalent to `DefaultResponder` for every non-OTA
    // test. We can't use `DefaultResponder` directly because it builds its
    // handler chain internally with no way to inject BDX.
    let bdx_buffers: &PooledBuffers<2, BdxBuffer> =
        BDX_BUFFERS.uninit().init_with(PooledBuffers::init(0));
    let main_handler = ChainedExchangeHandler::new(
        PROTO_ID_INTERACTION_MODEL,
        &dm,
        SecureChannel::new(dm.crypto(), &dm),
    )
    .chain(
        PROTO_ID_BDX,
        Bdx::new(OtaBdxHandler::new(bdx_buffers, ota_images)),
    );
    let main_responder = Responder::new("Responder", main_handler, matter, 0);
    // Busy responder (matches `DefaultResponder`'s 500ms busy pool) so a flood of
    // exchanges gets "try again later" rather than being dropped. 16 / 4 chosen to
    // match `max-sessions-32`: TC_SC_3_6 establishes 15 subscriptions back-to-back
    // and the initial-report exchanges overlap with the next handshake, overflowing
    // a smaller pool with IM BUSY (status 0x9c).
    let busy_responder = Responder::new_busy(matter, 500);

    let mut respond = pin!(async {
        let mut actual = pin!(main_responder.run::<16>());
        let mut busy = pin!(busy_responder.run::<4>());

        select(&mut actual, &mut busy).coalesce().await
    });

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

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;
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

    let mut sw_fault_emitter = pin!(emit_software_fault_on_trigger(&dm));

    // OTA Requestor role loop (active only with `--otaDownloadPath`): reacts to
    // `AnnounceOTAProvider` by downloading the image from the announced provider.
    let mut ota_job = pin!(run_ota_requestor(
        matter,
        &crypto,
        &ota_providers,
        &ota_state,
        &dm,
        ota_download_path,
    ));

    // Combine all async tasks in a single one
    let all = select4(
        &mut transport,
        &mut mdns,
        &mut app_pipe_actions,
        select4(
            &mut respond,
            &mut dm_job,
            &mut sw_fault_emitter,
            select(&mut term, &mut ota_job).coalesce(),
        )
        .coalesce(),
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
///
/// EP0 uses `clusters!(eth;)` for the Root Node system cluster set
/// (Matter Core spec / Device Library: Root Node device
/// type 0x0016 does not list Groups). Groups is then *manually
/// re-added* at EP0 because the YAML test `TestGroupMessaging`
/// exercises group-addressed writes against root-endpoint attributes
/// like `BasicInformation::NodeLabel`, which require the device's
/// Root Node endpoint to be a member of a multicast group — and the
/// only way to achieve that is per-endpoint Groups membership (App
/// Cluster spec). The matching runtime handler binding for
/// Groups at `ROOT_ENDPOINT_ID` is wired in `with_eth_sys` below; the
/// library-level `with_*_sys` chain no longer adds it.
///
/// Spec note: Matter Core Spec says extra clusters MAY be present
/// on an endpoint and clients MAY ignore them — i.e. having Groups on
/// EP0 is permitted but does mean a strict device-type-conformance
/// run (`TC_DeviceConformance::test_TC_IDM_10_5`) would flag it as an
/// "extra cluster". That test is not on `system_tests`'s active
/// run list (see the `TC_DeviceConformance` skip comment in
/// `xtask/src/itest.rs`). The library-level `g*` macro variants and
/// the Groups EpClMatcher in `with_sys()` were dropped to keep
/// device-type-pure compositions the *default* — having Groups on
/// EP0 here is a deliberate per-fixture exception.
///
/// `UserLabel` (cluster ID 0x0041) is also wired onto EP0 even though
/// it isn't part of the Root Node device type — the
/// `TestUserLabelClusterConstraints` YAML test targets `endpoint: 0`
/// and exercises the `LabelList` length-constraint behaviour. Same
/// rationale as Groups: Matter Core Spec permits extras, our
/// device-type-conformance test is already on the skip list.
/// Static fixed-label data exposed by EP1's `FixedLabel` cluster.
/// `TC_FLABEL_2_1` step 2 asserts every entry's `label`/`value` is a
/// string ≤ 16 bytes (Matter Application Cluster Spec); both
/// pairs below satisfy that constraint.
const FIXED_LABELS_EP1: &[FixedLabelEntry<'static>] = &[
    FixedLabelEntry {
        label: "room",
        value: "test",
    },
    FixedLabelEntry {
        label: "orientation",
        value: "north",
    },
];

const NODE: Node<'static> = Node {
    endpoints: &[
        // `Binding` (cluster ID 0x001E) is wired on EP0 too because
        // `TestBinding` exercises writes against both endpoints
        // (see step "Write binding table (endpoint 0)" in the
        // YAML) and asserts per-endpoint isolation. Pairing
        // Binding-server with a client cluster declaration in
        // `client_clusters` is the rs-matter way to advertise
        // "this endpoint will initiate `OnOff` interactions" via
        // `Descriptor::ClientList`.
        Endpoint::new_with_clients(
            ROOT_ENDPOINT_ID,
            devices!(DEV_TYPE_ROOT_NODE),
            clusters!(
                eth,
                // Claim `TimeSynchronization.TIME_SYNC_CLIENT`
                // (Matter Core Spec) so the device advertises the
                // `TrustedTimeSource` attribute + `SetTrustedTimeSource`
                // command — exercised by `TC_TIMESYNC_2_13` and
                // consumed by [`time_sync::client::TimeSyncClient`].
                time_sync(time_sync_client);
                groups::GroupsHandler::CLUSTER,
                user_label::CLUSTER,
                binding::CLUSTER,
                // OTA Software Update Provider (0x0029) + Requestor (0x002A) for
                // the `OTA_*` itests. Always present (matter permits extra
                // clusters on an endpoint); inert unless the OTA harness drives
                // them via `--filepath` / `--otaDownloadPath`. The OTA test's
                // `AnnounceOTAProvider` targets endpoint 0, so they live here.
                OTA_PROVIDER_CLUSTER,
                OTA_REQUESTOR_CLUSTER,
                // Diagnostic Logs (0x0032) for the `TestDiagnosticLogs` itest.
                // Always present; serves logs only when started with the log-file
                // flags, otherwise answers `NoLogs`.
                DIAGNOSTIC_LOGS_CLUSTER
            ),
            &[on_off::FULL_CLUSTER.id],
        ),
        // `FixedLabel` (cluster ID 0x0040) is wired on EP1 because
        // `TC_FLABEL_2_1` runs with `--endpoint 1` and skips cleanly
        // via `has_attribute(FixedLabel.LabelList)` when the cluster
        // is absent; adding it here turns the skip into an actual
        // content + read-only-write check.
        //
        // `Binding` is wired on EP1 to satisfy `TestBinding`, which
        // writes/reads its primary table here. Paired with a
        // client-cluster declaration so `Descriptor::ClientList`
        // truthfully advertises the intent to control OnOff bulbs.
        Endpoint::new_with_clients(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                identify::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                fixed_label::CLUSTER,
                binding::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                UnitTestingHandler::CLUSTER
            ),
            &[on_off::FULL_CLUSTER.id],
        ),
        Endpoint::new(
            2,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                identify::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER
            ),
        ),
    ],
};

/// The OTA Software Update Provider cluster metadata, exactly as served by
/// [`OtaProviderHandler`] (so `NODE`'s declaration matches the handler).
const OTA_PROVIDER_CLUSTER: Cluster<'static> =
    <OtaProviderHandler<&OtaFileImages> as ClusterAsyncHandler>::CLUSTER;

/// The OTA Software Update Requestor cluster metadata, as served by
/// [`OtaRequestorHandler`].
const OTA_REQUESTOR_CLUSTER: Cluster<'static> = OtaRequestorHandler::CLUSTER;

/// The Diagnostic Logs cluster metadata, exactly as served by the
/// [`DiagnosticLogsHandler`] wired in `dm_handler` (so `NODE`'s declaration
/// matches the handler).
const DIAGNOSTIC_LOGS_CLUSTER: Cluster<'static> = <DiagnosticLogsHandler<
    &PooledBuffers<2, BdxBuffer>,
    &LogFileProvider,
> as diagnostic_logs::ClusterAsyncHandler>::CLUSTER;

/// Download protocols this requestor advertises (BDX only).
const OTA_PROTOCOLS: &[DownloadProtocolEnum] = &[DownloadProtocolEnum::BDXSynchronous];

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
/// system_tests-driven YAML/Python tests (notably `TestBasicInformation`,
/// which asserts an exact `AttributeList` from upstream's 1.5 dataset where
/// `ConfigurationVersion` was deliberately removed in
/// `connectedhomeip@faf4d09ad1`) keep using the default `NODE`.
const NODE_BINFO_CV_EXPOSED: Node<'static> = Node {
    endpoints: &[
        // Manually expanded `clusters!(eth;)` with `BasicInfoHandler::CLUSTER`
        // replaced by `BASIC_INFO_CLUSTER_CV_EXPOSED`. Keep this in sync
        // with `clusters!(eth;)` in `rs-matter/src/dm/types/cluster.rs`.
        // `GroupsHandler::CLUSTER` and `user_label::CLUSTER` are
        // included for the same `TestGroupMessaging` /
        // `TestUserLabelClusterConstraints` reasons documented on `NODE`.
        Endpoint::new_with_clients(
            ROOT_ENDPOINT_ID,
            devices!(DEV_TYPE_ROOT_NODE),
            clusters!(
                desc::DescHandler::CLUSTER,
                acl::AclHandler::CLUSTER,
                BASIC_INFO_CLUSTER_CV_EXPOSED,
                gen_comm::GenCommHandler::CLUSTER,
                gen_diag::GenDiagHandler::CLUSTER,
                adm_comm::AdminCommHandler::CLUSTER,
                noc::NocHandler::CLUSTER,
                grp_key_mgmt::GrpKeyMgmtHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                user_label::CLUSTER,
                binding::CLUSTER,
                net_comm::NetworkType::Ethernet.cluster(),
                eth_diag::EthDiagHandler::CLUSTER,
                // OTA clusters present on every variant (see `NODE`).
                OTA_PROVIDER_CLUSTER,
                OTA_REQUESTOR_CLUSTER,
                // Diagnostic Logs present on every variant (see `NODE`).
                DIAGNOSTIC_LOGS_CLUSTER,
            ),
            &[on_off::FULL_CLUSTER.id],
        ),
        // `FixedLabel` (cluster ID 0x0040) is wired on EP1 because
        // `TC_FLABEL_2_1` runs with `--endpoint 1` and skips cleanly
        // via `has_attribute(FixedLabel.LabelList)` when the cluster
        // is absent; adding it here turns the skip into an actual
        // content + read-only-write check.
        //
        // `Binding` is wired on EP1 to satisfy `TestBinding`, which
        // writes/reads its primary table here. Paired with a
        // client-cluster declaration so `Descriptor::ClientList`
        // truthfully advertises the intent to control OnOff bulbs.
        Endpoint::new_with_clients(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                identify::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                fixed_label::CLUSTER,
                binding::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                UnitTestingHandler::CLUSTER
            ),
            &[on_off::FULL_CLUSTER.id],
        ),
        Endpoint::new(
            2,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                identify::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER
            ),
        ),
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off and unit testing handlers.
// The test-fixture function is intentionally a wide top-level
// composition root — every additional cluster handler we wire grows
// the parameter list. Suppressing here is cleaner than abstracting.
#[allow(clippy::too_many_arguments)]
fn dm_handler<'a, OH: OnOffHooks, LH: LevelControlHooks>(
    node: &'static Node<'static>,
    gen_diag: &'a dyn GenDiag,
    mut rand: impl RngCore + Copy,
    unit_testing_data: &'a RefCell<UnitTestingHandlerData>,
    on_off_1: &'a OnOffHandler<'a, OH, LH>,
    on_off_2: &'a OnOffHandler<'a, OH, LH>,
    user_label_handler: &'a UserLabelHandler<'a, 1, 4>,
    binding_handler_ep0: &'a BindingHandler<'a, 16>,
    binding_handler_ep1: &'a BindingHandler<'a, 16>,
    ota_images: &'a OtaFileImages,
    ota_providers: &'a Providers,
    ota_state: &'a OtaState,
    dlog_buffers: &'a PooledBuffers<2, BdxBuffer>,
    log_provider: &'a LogFileProvider,
) -> impl DataModelHandler + 'a {
    (
        node,
        endpoints::EthSysHandlerBuilder::new()
            .gen_diag(gen_diag)
            .netif_diag(&SysNetifs)
            .build(rand)
            // Groups handler at the root endpoint. The library-level
            // `with_*_sys()` chain in `rs-matter/src/dm/endpoints.rs`
            // intentionally does *not* bind Groups at root anymore —
            // Groups is not part of the Root Node device type
            // (Matter Device Library). We re-add it here
            // because the `TestGroupMessaging` YAML test exercises
            // group-addressed writes against root-endpoint
            // attributes (e.g. `BasicInformation::NodeLabel`), which
            // requires this endpoint to be a member of the target
            // multicast group via per-endpoint Groups membership
            // (App Cluster Spec). The matching metadata entry
            // is in `NODE` and `NODE_BINFO_CV_EXPOSED` above.
            .chain(
                EpClMatcher::new(
                    Some(ROOT_ENDPOINT_ID),
                    Some(groups::GroupsHandler::CLUSTER.id),
                ),
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            // UserLabel handler at the root endpoint. Wired here for
            // the same per-fixture-exception reason as Groups above:
            // `TestUserLabelClusterConstraints` and the persistence-
            // focused `TestUserLabelCluster` write / read the cluster
            // at `endpoint: 0`. The handler is owned by `main` so we
            // can call `load_persist` *before* the data model is
            // exposed; we hand it in by reference here and wrap it
            // with `user_label::HandlerAdaptor` (rather than the
            // owning-`.adapt()`) so the chain doesn't take ownership.
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(user_label::CLUSTER.id)),
                Async(user_label::HandlerAdaptor(user_label_handler)),
            )
            // Binding handler at the root endpoint — owned by main
            // (so `load_persist` can run before commissioner
            // traffic), borrowed by reference into the chain.
            // `TestBinding` exercises writes against EP0.
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(binding::CLUSTER.id)),
                Async(binding::HandlerAdaptor(binding_handler_ep0)),
            )
            // Clusters for Endpoint 1
            .chain(
                EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(identify::CLUSTER.id)),
                Async(IdentifyHandler::new(Dataver::new_rand(&mut rand))),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(groups::GroupsHandler::CLUSTER.id)),
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(fixed_label::CLUSTER.id)),
                Async(
                    FixedLabelHandler::new(Dataver::new_rand(&mut rand), FIXED_LABELS_EP1).adapt(),
                ),
            )
            // Binding handler at EP1 — same registry as EP0,
            // separate facade so the per-cluster-instance Dataver
            // stays granular per Matter Core Spec.
            .chain(
                EpClMatcher::new(Some(1), Some(binding::CLUSTER.id)),
                Async(binding::HandlerAdaptor(binding_handler_ep1)),
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
                EpClMatcher::new(Some(2), Some(identify::CLUSTER.id)),
                Async(IdentifyHandler::new(Dataver::new_rand(&mut rand))),
            )
            .chain(
                EpClMatcher::new(Some(2), Some(groups::GroupsHandler::CLUSTER.id)),
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(2), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                on_off::HandlerAsyncAdaptor(on_off_2),
            )
            // OTA Software Update Provider on the root endpoint (OTA role). The
            // handler is always present but only matched when `NODE` declares
            // the cluster (gated behind `--filepath`), so it is inert otherwise.
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(OTA_PROVIDER_CLUSTER.id)),
                OtaProviderHandler::new(Dataver::new_rand(&mut rand), ota_images).adapt(),
            )
            // OTA Software Update Requestor on the root endpoint (OTA role).
            // Inert unless an and an
            // `AnnounceOTAProvider` arrives; the actual download is driven by
            // `run_ota_requestor` in `main`.
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(OTA_REQUESTOR_CLUSTER.id)),
                Async(
                    OtaRequestorHandler::new(
                        Dataver::new_rand(&mut rand),
                        ota_providers,
                        ota_state,
                    )
                    .adapt(),
                ),
            )
            // Diagnostic Logs on the root endpoint. The handler's `run` hook (BDX
            // streaming) is driven as part of this chain by `dm.run()`.
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(DIAGNOSTIC_LOGS_CLUSTER.id)),
                DiagnosticLogsHandler::new(
                    Dataver::new_rand(&mut rand),
                    dlog_buffers,
                    log_provider,
                )
                .adapt(),
            ),
    )
}

/// Parse an optional `--app-pipe <path>` CLI override. When present, the CHIP
/// Python test framework writes JSON command lines to that path; we spin up
/// an OS-thread reader to act on them.
fn parse_app_pipe_override() -> Option<String> {
    args::parse_arg_opt_override("--app-pipe", |s| s.to_string())
}

/// Parse an optional `--enable-key <hex>` CLI override. The argument is a
/// 32-character hex string (16 bytes) that the device will accept as the
/// `TestEventTrigger` enable-key. Used by `TC_TestEventTrigger`.
fn parse_enable_key_override() -> Option<[u8; 16]> {
    args::parse_arg_opt_override("--enable-key", |s| s.to_string()).and_then(|hex| {
        if hex.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(out)
    })
}

/// `GenDiag` implementation that ties `TestEventTriggersEnabled` and
/// `TestEventTrigger` to a configured 16-byte enable key. Uptime falls back
/// to the library default impl on `()`. Per Matter Core Spec, the
/// command must:
///
/// - reject an all-zero `enableKey` with `ConstraintError`,
/// - reject a key mismatch with `ConstraintError`,
/// - reject an unrecognised `eventTrigger` with `InvalidCommand`.
///
/// We accept the canonical CHIP test trigger `0xFFFF_FFFF_FFF1_0000` (mirrors
/// the Linux `SampleTestEventTriggerDelegate` so `TC_TestEventTrigger` step
/// `correct_key_valid_code` succeeds).
struct TestEventTriggerDiag {
    enable_key: [u8; 16],
}

impl rs_matter::utils::sync::DynBase for TestEventTriggerDiag {}

impl GenDiag for TestEventTriggerDiag {
    fn reboot_count(&self) -> Result<u16, Error> {
        ().reboot_count()
    }

    fn uptime_ms(&self) -> Result<u64, Error> {
        ().uptime_ms()
    }

    fn test_event_triggers_enabled(&self) -> Result<bool, Error> {
        Ok(true)
    }

    fn test_event_trigger(&self, key: &[u8], trigger: u64) -> Result<(), Error> {
        if key.iter().all(|&b| b == 0) || key != self.enable_key {
            return Err(rs_matter::error::ErrorCode::ConstraintError.into());
        }
        // Mirror CHIP's `SampleTestEventTriggerDelegate`: the canonical CHIP
        // test trigger code is accepted by `TC_TestEventTrigger`.
        const TC_TEST_EVENT_TRIGGER: u64 = 0xFFFF_FFFF_FFF1_0000;
        // SoftwareDiagnostics `SoftwareFault` test trigger (Matter Core Spec).
        // `TC_DGSW_2_2` invokes this trigger and then waits for a
        // `SoftwareFault` event. We signal `SW_FAULT_NOTIFY` so the
        // top-level async task can emit the event (the trait method
        // itself is sync and has no event-emitter context).
        const SW_FAULT_TRIGGER: u64 = 0x0034_0000_0000_0000;
        match trigger {
            TC_TEST_EVENT_TRIGGER => Ok(()),
            SW_FAULT_TRIGGER => {
                SW_FAULT_NOTIFY.notify();
                Ok(())
            }
            _ => Err(rs_matter::error::ErrorCode::InvalidCommand.into()),
        }
    }
}

/// Drains [`SW_FAULT_NOTIFY`] and emits a stub
/// `SoftwareDiagnostics::SoftwareFault` event each time it fires. Bridges
/// the sync `GenDiag::test_event_trigger` trait method (which can't carry
/// an event-emitter context) to the async event-emission path on
/// `DataModel`. The emitted event's fields (`id`, `name`,
/// `faultRecording`) are vendor-defined; we ship plausible stub values
/// that satisfy `TC_DGSW_2_2`'s `validate_soft_fault_event_data` shape
/// checks (uint64 / Utf8 / OctetStr).
async fn emit_software_fault_on_trigger<E>(emitter: &E) -> Result<(), Error>
where
    E: rs_matter::dm::EventEmitter,
{
    loop {
        SW_FAULT_NOTIFY.wait().await;

        let res = SoftwareFault::emit_for(emitter, ROOT_ENDPOINT_ID, |b| {
            b.id(1)?
                .name(Some("rs-matter system_tests"))?
                .fault_recording(Some(rs_matter::tlv::Octets::new(&[])))?
                .end()
        });

        match res {
            Ok(_) => info!("TestEventTrigger: emitted SoftwareDiagnostics::SoftwareFault event"),
            Err(e) => warn!(
                "TestEventTrigger: failed to emit SoftwareFault event: {:?}",
                e
            ),
        }
    }
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

/// The BDX file designator for the single OTA image we serve (also reused as the
/// `UpdateToken`, which it fits at 19 bytes within the spec's 8..=32 bound).
const OTA_FILE_DESIGNATOR: &[u8] = b"rs-matter-ota-image";

/// The software version we offer. Must match the `-vn 2` that the OTA test
/// harness passes to `ota_image_tool create`, so the CHIP requestor accepts the
/// offered image (its version must be strictly newer than the requestor's).
const OTA_OFFERED_VERSION: u32 = 2;

/// A file-backed [`OtaImagesRegistry`] + [`OtaImages`] for the OTA Provider role:
/// it offers, and serves over BDX, the single Matter OTA image file given via
/// `--filepath`. Active only when a path is supplied (the OTA gate); otherwise
/// `query`/`size` report nothing so the provider is inert.
struct OtaFileImages {
    path: Option<String>,
    size: u64,
}

impl OtaFileImages {
    fn new(path: Option<String>) -> Self {
        let size = path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0);

        Self { path, size }
    }
}

impl OtaImagesRegistry for OtaFileImages {
    async fn query<'b>(
        &self,
        _vendor_id: u16,
        _product_id: u16,
        _current_version: u32,
        _requestor_can_consent: bool,
        designator_buf: &'b mut [u8],
    ) -> OtaQueryOutcome<'b> {
        if self.path.is_none() {
            return OtaQueryOutcome::NotAvailable;
        }

        let Some(slot) = designator_buf.get_mut(..OTA_FILE_DESIGNATOR.len()) else {
            return OtaQueryOutcome::NotAvailable;
        };
        slot.copy_from_slice(OTA_FILE_DESIGNATOR);
        // `OTA_FILE_DESIGNATOR` is ASCII, so this is always valid UTF-8.
        let file_designator = core::str::from_utf8(slot).unwrap();

        OtaQueryOutcome::Available(OtaImageMeta {
            version: OTA_OFFERED_VERSION,
            file_designator,
            update_token: OTA_FILE_DESIGNATOR,
            size: Some(self.size),
            user_consent_needed: false,
        })
    }
}

impl OtaImages for OtaFileImages {
    async fn size(&self, file_designator: &[u8]) -> Option<u64> {
        (self.path.is_some() && file_designator == OTA_FILE_DESIGNATOR).then_some(self.size)
    }

    async fn read(
        &self,
        file_designator: &[u8],
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        use std::io::{Read, Seek, SeekFrom};

        if file_designator != OTA_FILE_DESIGNATOR {
            return Err(rs_matter::error::ErrorCode::NotFound.into());
        }
        let Some(path) = &self.path else {
            return Err(rs_matter::error::ErrorCode::NotFound.into());
        };

        let mut f = std::fs::File::open(path).map_err(|_| rs_matter::error::ErrorCode::NotFound)?;
        f.seek(SeekFrom::Start(offset))
            .map_err(|_| rs_matter::error::ErrorCode::Invalid)?;
        let n = f
            .read(buf)
            .map_err(|_| rs_matter::error::ErrorCode::Invalid)?;

        Ok(n)
    }
}

/// A file-backed [`DiagnosticLogsProvider`] for the `TestDiagnosticLogs` itest:
/// each [`IntentEnum`] maps to a log-file path (given via CLI), read fresh on
/// every request so the test can rewrite a file between queries and have the
/// next query observe the new size/content.
struct LogFileProvider {
    end_user_support: Option<String>,
    network_diagnostics: Option<String>,
    crash: Option<String>,
}

impl LogFileProvider {
    fn new(
        end_user_support: Option<String>,
        network_diagnostics: Option<String>,
        crash: Option<String>,
    ) -> Self {
        Self {
            end_user_support,
            network_diagnostics,
            crash,
        }
    }

    fn path(&self, intent: IntentEnum) -> Option<&str> {
        match intent {
            IntentEnum::EndUserSupport => self.end_user_support.as_deref(),
            IntentEnum::NetworkDiag => self.network_diagnostics.as_deref(),
            IntentEnum::CrashLogs => self.crash.as_deref(),
        }
    }
}

impl DiagnosticLogsProvider for LogFileProvider {
    async fn size(&self, intent: IntentEnum) -> Option<u64> {
        // Fresh `metadata` (not cached): the test rewrites files between queries.
        let path = self.path(intent)?;
        std::fs::metadata(path).ok().map(|m| m.len())
    }

    async fn read(&self, intent: IntentEnum, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        use std::io::{Read, Seek, SeekFrom};

        let path = self
            .path(intent)
            .ok_or(rs_matter::error::ErrorCode::NotFound)?;

        let mut f = std::fs::File::open(path).map_err(|_| rs_matter::error::ErrorCode::NotFound)?;
        f.seek(SeekFrom::Start(offset))
            .map_err(|_| rs_matter::error::ErrorCode::Invalid)?;
        let n = f
            .read(buf)
            .map_err(|_| rs_matter::error::ErrorCode::Invalid)?;

        Ok(n)
    }
}

/// OTA Requestor role (active only when `--otaDownloadPath` is given): on each
/// `AnnounceOTAProvider`, query the announced provider, download its image over
/// BDX, strip the Matter OTA header, write the raw payload to the download path,
/// and print "OTA image downloaded" (the line the test harness waits for).
async fn run_ota_requestor(
    matter: &Matter<'_>,
    crypto: impl Crypto,
    providers: &Providers,
    ota_state: &OtaState,
    notifier: &dyn AttrChangeNotifier,
    download_path: Option<String>,
) -> Result<(), Error> {
    let Some(download_path) = download_path else {
        // Not the requestor role — idle forever so the `select` never picks us.
        core::future::pending::<()>().await;
        unreachable!()
    };

    loop {
        // Wake on an `AnnounceOTAProvider` (or any provider-set change).
        providers.wait_changed().await;

        // Drain the announced set up front so a provider announced while a download
        // is in progress is processed on the next pass rather than lost to a clear.
        for provider in providers.take_announced() {
            if let Err(e) = download_image(
                matter,
                &crypto,
                &provider,
                ota_state,
                notifier,
                &download_path,
            )
            .await
            {
                warn!(
                    "OTA: download from 0x{:016x} failed: {:?}",
                    provider.node_id, e
                );
            }
        }
    }
}

/// Query `provider`, download the offered image over BDX, strip the OTA header,
/// and write the raw payload to `download_path`.
async fn download_image(
    matter: &Matter<'_>,
    crypto: &impl Crypto,
    provider: &Provider,
    ota_state: &OtaState,
    notifier: &dyn AttrChangeNotifier,
    download_path: &str,
) -> Result<(), Error> {
    let update = ota_state.initiate_update(notifier);
    update.querying();

    // Copy out the `bdx://` image URI before the response buffer is released.
    let mut uri_buf = [0u8; 256];
    let found = provider
        .query(matter, crypto, OTA_PROTOCOLS, None, false, |resp| {
            if resp.status()? != StatusEnum::UpdateAvailable {
                return Ok(None);
            }
            let uri = resp.image_uri()?.ok_or(ErrorCode::InvalidData)?.as_bytes();
            uri_buf
                .get_mut(..uri.len())
                .ok_or(ErrorCode::NoSpace)?
                .copy_from_slice(uri);

            Ok(Some(uri.len()))
        })
        .await?;

    let Some(uri_len) = found else {
        return Ok(());
    };
    let uri = core::str::from_utf8(&uri_buf[..uri_len]).map_err(|_| ErrorCode::InvalidData)?;
    let (node_id, fd) = parse_bdx_url(uri)?;

    update.downloading(Some(0));

    // Download the whole (small, test) OTA image over BDX into memory.
    let exchange = Exchange::initiate(matter, crypto, provider.fab_idx, node_id).await?;
    let mut reader = exchange.download(fd.as_bytes(), None).await?;
    let mut image: std::vec::Vec<u8> = std::vec::Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        image.extend_from_slice(&buf[..n]);
    }

    // Strip the Matter OTA header and write the raw payload; a real device would
    // instead stream blocks to a firmware slot and verify as it goes.
    let payload = strip_ota_header(&image)?;
    std::fs::write(download_path, payload).map_err(|_| ErrorCode::Invalid)?;

    update.applying();
    // The exact substring the harness's `WaitForMessage` blocks on.
    info!("OTA image downloaded");
    update.complete();

    Ok(())
}

/// Strip the Matter OTA image fixed header (`<u32 magic><u64 totalSize><u32
/// headerSize>` followed by `headerSize` TLV bytes), returning the raw payload.
fn strip_ota_header(image: &[u8]) -> Result<&[u8], Error> {
    const MAGIC: u32 = 0x1BEE_F11E;
    const FIXED: usize = 16; // u32 magic + u64 total size + u32 header size

    if image.len() < FIXED || u32::from_le_bytes(image[0..4].try_into().unwrap()) != MAGIC {
        return Err(ErrorCode::InvalidData.into());
    }
    let header_size = u32::from_le_bytes(image[12..16].try_into().unwrap()) as usize;

    image
        .get(FIXED + header_size..)
        .ok_or_else(|| ErrorCode::InvalidData.into())
}
