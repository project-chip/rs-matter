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

//! Full in-process commissioning integration test.
//!
//! Exercises the complete flow:
//! 1. Device (in-process) starts with a full InteractionModel + mDNS responder
//! 2. Controller discovers the device via mDNS
//! 3. PASE session established over UDP
//! 4. IM read on OnOff attribute (ep 1) — assert initial value is `false`
//! 5. IM invoke Toggle command
//! 6. IM read again — assert value flipped to `true`
//!
//! ## Platform support
//!
//! - **Linux** (no extra features): uses `BuiltinMdns` (responder + querier)
//!   on the device and controller sides.
//! - **macOS** (with `astro-dnssd` feature): uses `AstroMdns` (integrates with
//!   the OS Bonjour daemon, so no port-5353 conflict) on both sides; its
//!   `run()` services the resolve/browse rendezvous like the builtin one.

#![cfg(all(
    feature = "std",
    feature = "async-io",
    any(target_os = "linux", feature = "astro-dnssd")
))]

use core::pin::pin;
use std::net::{TcpListener, UdpSocket};

use embassy_futures::select::{select, select3, Either};
use embassy_time::{Duration, Timer};

use log::{debug, info, warn};

use rand_core::Rng;

use rs_matter::cert::gen::VALID_FOREVER;
use rs_matter::cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN};
use rs_matter::crypto::{
    test_only_crypto, CanonAeadKey, CanonPkcSecretKey, Crypto, SecretKey, SigningSecretKey,
};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::DummyNetworks;
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::{endpoints, Async, DataModel, Dataver, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::im::subscriptions::DEFAULT_MAX_SUBSCRIPTIONS;
use rs_matter::im::IMStatusCode;
use rs_matter::im::{InteractionModel, InteractionModelState};
use rs_matter::onboard::cac::{IcacGenerator, RcacGenerator};
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::onboard::{CommissionOptions, CommissionResult, Commissioner};
use rs_matter::persist::DummyKvBlobStore;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::transport::network::tcp::TcpNetwork;
use rs_matter::transport::network::{Address, NoNetwork, SocketAddr, SocketAddrV6};
use rs_matter::transport::session::{Session, SessionMode};
use rs_matter::transport::{TransportPreference, MATTER_SOCKET_BIND_ADDR};
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

use socket2::{Domain, Protocol, Socket, Type};

use static_cell::StaticCell;

use crate::common::mdns::stub_mdns_resolver_txt;
use crate::common::{init_env_logger, run_device_controller, run_with_transport};

#[allow(dead_code)]
mod common;

/// Passcode used by `TEST_DEV_COMM`
const TEST_PASSCODE: u32 = 20202021;

const IM_TIMEOUT_SECS: u64 = 10;

/// The device's data model state: a dummy (no-op) network store, default
/// subscription count, no events.
type DeviceDmState = InteractionModelState<DummyNetworks, DEFAULT_MAX_SUBSCRIPTIONS, 0>;

static DEVICE_MATTER: StaticCell<Matter> = StaticCell::new();
static DEVICE_BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static DEVICE_STATE: StaticCell<DeviceDmState> = StaticCell::new();
static CTRL_MATTER: StaticCell<Matter> = StaticCell::new();

// Separate statics for the TCP variant (StaticCell is one-shot)
static TCP_DEVICE_MATTER: StaticCell<Matter> = StaticCell::new();
static TCP_DEVICE_BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static TCP_DEVICE_STATE: StaticCell<DeviceDmState> = StaticCell::new();
static TCP_CTRL_MATTER: StaticCell<Matter> = StaticCell::new();

// ============================================================================
// Device data model — copied from examples/src/bin/onoff_light.rs
// ============================================================================

const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(desc::DescHandler::CLUSTER, TestOnOffDeviceLogic::CLUSTER),
        ),
    ],
};

fn data_model<'a, OH: OnOffHooks, LH: LevelControlHooks>(
    mut rand: impl Rng + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
) -> impl DataModel + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&UnixNetifs)
            .build(rand)
            .chain(
                |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == TestOnOffDeviceLogic::CLUSTER.id,
                on_off::HandlerAsyncAdaptor(on_off),
            ),
    )
}

/// Generates a commissioning test function for a given transport.
///
/// Each invocation produces its own async function and `#[test]` entry point,
/// so that the Rust compiler generates a **separate** future state-machine for
/// each transport type (keeping the future small enough for the default 2 MiB
/// thread stack).
macro_rules! commissioning_test {
    (
        test_name: $test_name:ident,
        run_name: $run_name:ident,
        device_matter: $dev_matter:expr,
        device_buffers: $dev_buffers:expr,
        device_subscriptions: $dev_subs:expr,
        ctrl_matter: $ctrl_matter:expr,
        use_tcp: $use_tcp:expr,
        device_transport: $dev_transport:expr,
        ctrl_transport: $ctrl_transport:expr $(,)?
    ) => {
        #[test]
        fn $test_name() {
            let thread = std::thread::spawn(|| {
                init_env_logger();
                futures_lite::future::block_on(async {
                    $run_name().await.unwrap();
                });
            });
            thread.join().unwrap();
        }

        async fn $run_name() -> Result<(), Error> {
            let device_matter = $dev_matter.uninit().init_with(Matter::init(
                &TEST_DEV_DET,
                TEST_DEV_COMM,
                &TEST_DEV_ATT,
                MATTER_PORT,
            ));

            let device_crypto = test_only_crypto();
            let mut rand = device_crypto.rand()?;

            let device_buffers = $dev_buffers.uninit().init_with(MatterBuffers::init());
            let device_state = $dev_subs.init(InteractionModelState::new(DummyNetworks));

            let on_off_handler = on_off::OnOffHandler::new_standalone(
                Dataver::new_rand(&mut rand),
                1,
                TestOnOffDeviceLogic::new(false),
            );

            let device_kv = device_matter.kv(DummyKvBlobStore);

            let dm = InteractionModel::new(
                device_matter,
                &device_crypto,
                device_buffers,
                data_model(rand, &on_off_handler),
                &device_kv,
                device_state,
            );

            // Open commissioning window before starting the mDNS responder so the
            // `wait_mdns` signal is already set when the broadcast loop first runs.
            device_matter.open_basic_comm_window(
                MAX_COMM_WINDOW_TIMEOUT_SECS,
                &device_crypto,
                &(),
            )?;

            let responder = DefaultResponder::new(&dm);

            let device_net = $dev_transport;
            let ctrl_net = $ctrl_transport;

            let ctrl_matter = $ctrl_matter.uninit().init_with(Matter::init(
                &TEST_DEV_DET,
                TEST_DEV_COMM,
                &TEST_DEV_ATT,
                0,
            ));
            let ctrl_crypto = test_only_crypto();

            let transport_label = if $use_tcp { "TCP" } else { "UDP" };
            info!(
                "Device and controller initialized ({transport_label}), \
                 starting commissioning test..."
            );

            // NOTE: the mDNS responder is intentionally NOT started here. mDNS
            // discovery is skipped in this in-process test (see
            // `discover_and_resolve_device`); device and controller share the
            // host's real :5353, which is unreliable for multicast loopback
            // (SO_REUSEPORT semantics + any system avahi-daemon). The mDNS
            // protocol code is covered by unit tests instead.
            let device_fut = async {
                select3(
                    device_matter.run(&device_crypto, &device_net, &device_net, NoNetwork),
                    responder.run::<4, 4>(),
                    dm.run(),
                )
                .coalesce()
                .await
            };

            let controller_fut = run_with_transport(
                ctrl_matter.run(&ctrl_crypto, &ctrl_net, &ctrl_net, NoNetwork),
                run_controller_flow(
                    ctrl_matter,
                    &ctrl_crypto,
                    device_matter,
                    &device_crypto,
                    $use_tcp,
                ),
            );

            run_device_controller(device_fut, controller_fut).await
        }
    };
}

commissioning_test! {
    test_name: test_commissioning_onoff_cluster,
    run_name: run_test_udp,
    device_matter: DEVICE_MATTER,
    device_buffers: DEVICE_BUFFERS,
    device_subscriptions: DEVICE_STATE,
    ctrl_matter: CTRL_MATTER,
    use_tcp: false,
    device_transport: async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?,
    ctrl_transport: create_dual_stack_socket()?,
}

commissioning_test! {
    test_name: test_commissioning_onoff_cluster_tcp,
    run_name: run_test_tcp,
    device_matter: TCP_DEVICE_MATTER,
    device_buffers: TCP_DEVICE_BUFFERS,
    device_subscriptions: TCP_DEVICE_STATE,
    ctrl_matter: TCP_CTRL_MATTER,
    use_tcp: true,
    device_transport: TcpNetwork::<8>::new(
        async_io::Async::<TcpListener>::bind(MATTER_SOCKET_BIND_ADDR)?,
    ),
    ctrl_transport: TcpNetwork::<8>::new(async_io::Async::<TcpListener>::bind(
        SocketAddr::V6(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    )?),
}

async fn run_controller_flow<C: Crypto, D: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    device_matter: &Matter<'_>,
    device_crypto: &D,
    use_tcp: bool,
) -> Result<(), Error> {
    info!("=== Phase 1: Resolve device endpoint (mDNS skipped) ===");
    let peer_addr = discover_and_resolve_device(use_tcp)?;

    info!("=== Phase 2: Commissioner — commission() (incl. PASE) + complete_via_case() ===");
    let (controller_fab_idx, device_node_id) =
        test_commission(matter, crypto, peer_addr, use_tcp).await?;

    // Cherry on top: after `CommissioningComplete` the device has
    // committed our fabric, torn down PASE, and the only authenticated
    // channel to it is the CASE session we just established. Open a
    // fresh CASE-secured exchange (via `Exchange::initiate(matter,
    // controller_fab_idx, device_node_id, secure=true)`) and exercise
    // OnOff over it — proving the whole pipe end-to-end.
    info!("=== Phase 4: IM Operations over the CASE session ===");
    test_onoff_cluster(matter, controller_fab_idx, device_node_id).await?;

    // Phase 5 - the device reboots and is commissioned again by the *same*
    // controller. A reboot wipes the device's session table, but the controller
    // still holds its half of the PASE session from the first run, and
    // `initiate_pase` reuses a PASE session by peer address alone. So the first
    // step of the second run lands on a session the device no longer has. The
    // device answers `SessionNotFound`, the controller drops its stale session,
    // and phase 1 must retry on a fresh one rather than fail - which is what
    // used to limit a controller to one commissioning per process.
    //
    // `test_commission` mints a fresh controller fabric, so the device simply
    // gains a second fabric (no `AddNOC` conflict with the first).
    info!("=== Phase 5: device reboots, then the same controller commissions it again ===");
    device_matter.remove_sessions(|_| true);
    device_matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, device_crypto, &())?;

    test_commission(matter, crypto, peer_addr, use_tcp).await?;

    info!("=== Phase 6: a stale CASE session to the node ID being assigned is dropped ===");
    test_stale_case_is_dropped(
        matter,
        crypto,
        device_matter,
        device_crypto,
        peer_addr,
        use_tcp,
    )
    .await?;

    info!("=== All commissioning test phases completed successfully! ===");
    Ok(())
}

const FABRIC_ID: u64 = 1;
// chip-tool's conventional admin NodeID; matches the
// CaseAdminSubject the device-side ACL is seeded with.
const CONTROLLER_NODE_ID: u64 = 112233;
// The single device this test commissions. Real callers pick
// these from whatever NodeID allocation scheme they prefer.
const DEVICE_NODE_ID: u64 = 112234;
const ADMIN_VENDOR_ID: u16 = 0xFFF1;

/// Drive both phases of the commissioner flow against the peer that
/// PASE was just negotiated with. Returns the
/// `(controller_local_fab_idx, device_node_id)` needed to open
/// post-commissioning CASE exchanges.
///
/// All of the "build a fabric for the controller" plumbing lives in
/// this test, not the `commissioner` crate: generate RCAC + ICAC,
/// drop the RCAC priv key (in production it'd be HSM-resident), mint
/// the controller's own operational keypair + NOC, generate an IPK,
/// install the fabric in `matter.state.fabrics`. Then build a
/// [`NocGenerator`] and hand it (plus the fab_idx) to the
/// [`Commissioner`].
async fn test_commission<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: Address,
    use_tcp: bool,
) -> Result<(core::num::NonZeroU8, u64), Error> {
    // ---- Offline CA chain: RCAC then ICAC; RCAC priv discarded ----

    let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut rcac_gen = RcacGenerator::new(&mut rcac_buf);
    let (rcac_priv, rcac) = rcac_gen.generate(crypto, FABRIC_ID, VALID_FOREVER)?;

    let mut icac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut icac_gen = IcacGenerator::new(&mut icac_buf);
    let (icac_priv, icac) =
        icac_gen.generate(crypto, rcac_priv.reference(), rcac, VALID_FOREVER)?;
    drop(rcac_priv);

    // ---- NocGenerator: signs the controller NOC now, then the
    //      device NOC during commissioning. The NOC serial is derived
    //      from the NodeID internally. ----

    let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut noc_generator = NocGenerator::create(icac_priv.reference(), rcac, icac, &mut noc_buf)?;

    let controller_fab_idx =
        install_controller_fabric(matter, crypto, &mut noc_generator, rcac, icac)?;

    // Scratch buffer for Commissioner — used to stage the fabric's
    // RCAC / ICAC bytes across the async on-wire calls. One
    // `MAX_CERT_TLV_LEN` slot is enough; see `Commissioner::new`.
    let mut commissioner_buf = [0u8; MAX_CERT_TLV_LEN];
    let mut commissioner = Commissioner::new(
        matter,
        crypto,
        controller_fab_idx,
        &mut noc_generator,
        &mut commissioner_buf,
    )
    .with_transport(transport(use_tcp));

    let result = run_commissioner(matter, &mut commissioner, peer_addr, use_tcp).await?;

    Ok((controller_fab_idx, result.device_node_id))
}

/// A CASE session to the node ID being assigned must not cost phase 2 an
/// attempt.
///
/// NodeIDs get reused, so the controller can still hold a CASE session to the
/// previous holder of the ID it is about to hand out. `Commissioner::commission`
/// drops it up front; otherwise phase 2 resumes it and only learns it is dead by
/// losing an attempt - fatal when given a single one, as here.
///
/// Two other things would clear that session first and let this pass without
/// the fix, so both are ruled out. The device is reset *locally*: a
/// `RemoveFabric` could close the session over the wire. And phase 1 starts on
/// a fresh PASE session: a stale one draws a `SessionNotFound`, which drops
/// every secure session to the device, the stale CASE session included.
///
/// Over UDP a third one can't be ruled out, so only the TCP variant exercises
/// the fix: the controller's trailing MRP ack for `CommissioningComplete` can
/// reach the device after its reset, and draws a `SessionNotFound` that clears
/// the session anyway. TCP has no MRP acks - nor does BTP, where commissioning
/// is typically given a single phase 2 attempt.
async fn test_stale_case_is_dropped<C: Crypto, D: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    device_matter: &Matter<'_>,
    device_crypto: &D,
    peer_addr: Address,
    use_tcp: bool,
) -> Result<(), Error> {
    // One controller fabric for both runs.
    let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut rcac_gen = RcacGenerator::new(&mut rcac_buf);
    let (rcac_priv, rcac) = rcac_gen.generate(crypto, FABRIC_ID, VALID_FOREVER)?;

    let mut icac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut icac_gen = IcacGenerator::new(&mut icac_buf);
    let (icac_priv, icac) =
        icac_gen.generate(crypto, rcac_priv.reference(), rcac, VALID_FOREVER)?;
    drop(rcac_priv);

    let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut noc_generator = NocGenerator::create(icac_priv.reference(), rcac, icac, &mut noc_buf)?;
    let controller_fab_idx =
        install_controller_fabric(matter, crypto, &mut noc_generator, rcac, icac)?;

    let device = peer_addr.canonical();
    let pase_to_device = move |sess: &Session| {
        matches!(sess.get_session_mode(), SessionMode::Pase { .. })
            && sess.get_peer_addr().canonical() == device
    };

    // Start both nodes clean.
    matter.remove_sessions(pase_to_device);
    device_matter.remove_sessions(|_| true);
    device_matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, device_crypto, &())?;

    // First run: leaves a CASE session to `(controller_fab_idx, DEVICE_NODE_ID)`.
    let mut commissioner_buf = [0u8; MAX_CERT_TLV_LEN];
    let mut commissioner = Commissioner::new(
        matter,
        crypto,
        controller_fab_idx,
        &mut noc_generator,
        &mut commissioner_buf,
    )
    .with_transport(transport(use_tcp));
    let first = run_commissioner(matter, &mut commissioner, peer_addr, use_tcp).await?;

    // Factory-reset the device without a word to the controller, whose CASE
    // session to it is now stale.
    device_matter.remove_sessions(|_| true);
    device_matter.with_state(|state| state.fabrics.remove(first.fabric_index))?;
    device_matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, device_crypto, &())?;

    // A fresh PASE session for phase 1, so nothing there clears the stale one.
    matter.remove_sessions(pase_to_device);

    // Second run: same fabric and node ID, a single phase 2 attempt.
    let mut commissioner_buf = [0u8; MAX_CERT_TLV_LEN];
    let mut commissioner = Commissioner::new(
        matter,
        crypto,
        controller_fab_idx,
        &mut noc_generator,
        &mut commissioner_buf,
    )
    .with_transport(transport(use_tcp))
    .with_case_attempts(1);
    run_commissioner(matter, &mut commissioner, peer_addr, use_tcp).await?;

    Ok(())
}

/// Mint the controller's own operational key and NOC (signed by
/// `noc_generator`) plus the fabric IPK, and install the controller fabric.
/// Returns its index.
fn install_controller_fabric<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    noc_generator: &mut NocGenerator<'_>,
    rcac: &[u8],
    icac: &[u8],
) -> Result<core::num::NonZeroU8, Error> {
    // ---- Controller operational keypair + CSR ----

    let controller_secret_key = crypto.generate_secret_key()?;
    let mut controller_csr_buf = [0u8; 256];
    let controller_csr = controller_secret_key.csr(&mut controller_csr_buf)?;
    let mut controller_secret_key_canon = CanonPkcSecretKey::new();
    controller_secret_key.write_canon(&mut controller_secret_key_canon)?;

    let controller_noc = noc_generator.generate(
        crypto,
        controller_csr,
        CONTROLLER_NODE_ID,
        &[],
        VALID_FOREVER,
    )?;

    // ---- Fabric IPK: 16 random bytes, shared across the fabric ----
    let mut ipk = CanonAeadKey::new();
    crypto.rand()?.fill_bytes(ipk.access_mut());

    // ---- Install the controller's fabric in matter.state.fabrics ----
    matter.with_state(|state| {
        state
            .fabrics
            .add(
                crypto,
                controller_secret_key_canon.reference(),
                rcac,
                controller_noc,
                icac,
                Some(ipk.reference()),
                ADMIN_VENDOR_ID,
                CONTROLLER_NODE_ID,
            )
            .map(|f| f.fab_idx())
    })
}

/// Phase 2 discovers the device and defaults to UDP, as the CHIP SDK's
/// commissioner does. This test's TCP device listens on TCP *only*, so it has
/// to ask for TCP explicitly - which also covers the `tcp_capable` veto path,
/// since the stub resolver has to advertise TCP support for this to be allowed.
fn transport(use_tcp: bool) -> TransportPreference {
    if use_tcp {
        TransportPreference::LargePayload
    } else {
        TransportPreference::Mrp
    }
}

/// Drive both phases of an already-built `Commissioner` against the device.
async fn run_commissioner<C: Crypto>(
    matter: &Matter<'_>,
    commissioner: &mut Commissioner<'_, '_, C>,
    peer_addr: Address,
    use_tcp: bool,
) -> Result<CommissionResult, Error> {
    let opts = CommissionOptions {
        // Test DAC — system_tests / TEST_DEV_ATT.
        allow_test_attestation: true,
        ..CommissionOptions::default()
    };

    // Phase 1 — establishes PASE (lazily on first step) then ArmFailSafe → ... → AddNOC.
    let result = commissioner
        .commission(
            peer_addr,
            TEST_PASSCODE,
            &opts,
            DEVICE_NODE_ID,
            VALID_FOREVER,
        )
        .await?;
    info!(
        "commission() phase 1 ok: device_fabric_index={}, device_node_id=0x{:016x}",
        result.fabric_index, result.device_node_id,
    );

    // Phase 2 — operational discovery, then CASE against the device's
    // operational identity, then CommissioningComplete on the new session.
    //
    // No mDNS backend runs in this test, so a stub answers the resolve request
    // with the device's known address. That covers the production path end to
    // end; it does not exercise the *failover* across several candidates, which
    // needs an address that times out rather than failing the send outright and
    // is therefore too environment-dependent to pin down here.
    let (Address::Udp(SocketAddr::V6(peer_sock)) | Address::Tcp(SocketAddr::V6(peer_sock))) =
        peer_addr
    else {
        panic!("expected an IPv6 device address");
    };

    let mdns_table = [(result.device_node_id, peer_sock)];
    // `T=6` = TCP client (bit 1) + TCP server (bit 2), which is what a
    // TCP-capable node advertises and what the commissioner's TCP request checks
    // against.
    let mdns = stub_mdns_resolver_txt(matter, &mdns_table, if use_tcp { "6" } else { "" });

    match select(pin!(commissioner.complete_via_case(&result)), pin!(mdns)).await {
        Either::First(r) => r?,
        Either::Second(_) => unreachable!("the stub resolver never returns"),
    }

    info!(
        "complete_via_case() ok: controller_fab_idx={}, discovery+CASE+CommissioningComplete done",
        commissioner.fab_idx(),
    );

    Ok(result)
}

// ============================================================================
// Phase 1: mDNS Discovery
// ============================================================================

/// Resolve the device's operational endpoint.
///
/// mDNS discovery is intentionally skipped in this in-process test: device and
/// controller share the host's real `:5353`, whose multicast loopback is
/// unreliable (`SO_REUSEPORT` delivery semantics plus any system avahi-daemon),
/// making discovery flaky and environment-dependent. The mDNS protocol code
/// (query building, response parsing, the resolve rendezvous) is covered by
/// unit tests instead. Here we use the device's known localhost address: it
/// binds `MATTER_SOCKET_BIND_ADDR` (`[::]:MATTER_PORT`), reachable via the
/// host's IPv4 address.
fn discover_and_resolve_device(use_tcp: bool) -> Result<Address, Error> {
    let (ipv4, _ipv6_available, _interface) = find_network_interface()?;

    let make_addr = if use_tcp { Address::Tcp } else { Address::Udp };
    let peer_addr = make_addr(SocketAddr::V6(SocketAddrV6::new(
        ipv4.to_ipv6_mapped(),
        MATTER_PORT,
        0,
        0,
    )));

    info!("Using device address (mDNS discovery skipped): {peer_addr}");

    Ok(peer_addr)
}

// ============================================================================
// Phase 3: Interaction Model Operations
// ============================================================================

async fn test_onoff_cluster(
    matter: &Matter<'_>,
    fab_idx: core::num::NonZeroU8,
    peer_node_id: u64,
) -> Result<(), Error> {
    info!("Step 3a: Reading initial OnOff attribute...");
    let initial_value = read_onoff_with_timeout(matter, fab_idx, peer_node_id).await?;
    info!("Initial OnOff value: {initial_value}");
    assert!(!initial_value, "Expected initial OnOff value to be false");

    info!("Step 3b: Invoking Toggle command...");
    let status = invoke_toggle_with_timeout(matter, fab_idx, peer_node_id).await?;
    info!("Toggle completed with status: {status:?}");

    info!("Step 3c: Verifying toggle effect...");
    let final_value = read_onoff_with_timeout(matter, fab_idx, peer_node_id).await?;
    info!("Final OnOff value: {final_value}");

    assert!(
        final_value,
        "Expected OnOff to be true after toggle, got {final_value}"
    );
    info!("Toggle verified: {initial_value} -> {final_value}");

    info!("Step 3d: Reading a string attribute (BasicInformation::VendorName)...");
    let vendor_name = read_vendor_name_with_timeout(matter, fab_idx, peer_node_id).await?;
    info!("VendorName: {vendor_name}");
    assert_eq!(
        vendor_name, TEST_DEV_DET.vendor_name,
        "Expected VendorName to match the served BasicInfoConfig"
    );

    Ok(())
}

async fn read_onoff_with_timeout(
    matter: &Matter<'_>,
    fab_idx: core::num::NonZeroU8,
    peer_node_id: u64,
) -> Result<bool, Error> {
    let exchange = Exchange::initiate(matter, test_only_crypto(), fab_idx, peer_node_id).await?;
    debug!("IM read exchange initiated: {}", exchange.id());

    let mut read_fut = pin!(read_onoff(exchange));
    let mut timeout = pin!(Timer::after(Duration::from_secs(IM_TIMEOUT_SECS)));

    match select(&mut read_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => {
            warn!("Read operation timed out");
            Err(rs_matter::error::ErrorCode::RxTimeout.into())
        }
    }
}

async fn read_onoff(exchange: Exchange<'_>) -> Result<bool, Error> {
    use rs_matter::dm::clusters::app::on_off::OnOffClient;

    // Single-shot: cluster ID, attribute ID, fabric_filtered=true,
    // retransmit loop, response parsing, status-to-error conversion,
    // and chunk drain (trailing StatusResponse) are all baked into
    // the codegen-emitted `on_off_on_off_read`.
    exchange.on_off().on_off_read(1).await
}

async fn read_vendor_name_with_timeout(
    matter: &Matter<'_>,
    fab_idx: core::num::NonZeroU8,
    peer_node_id: u64,
) -> Result<String, Error> {
    let exchange = Exchange::initiate(matter, test_only_crypto(), fab_idx, peer_node_id).await?;
    debug!("VendorName read exchange initiated: {}", exchange.id());

    let mut read_fut = pin!(read_vendor_name(exchange));
    let mut timeout = pin!(Timer::after(Duration::from_secs(IM_TIMEOUT_SECS)));

    match select(&mut read_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => {
            warn!("Read operation timed out");
            Err(rs_matter::error::ErrorCode::RxTimeout.into())
        }
    }
}

async fn read_vendor_name(exchange: Exchange<'_>) -> Result<String, Error> {
    use rs_matter::dm::clusters::decl::basic_information::BasicInformationClient;

    // `VendorName` is a *string* attribute, so its value (`Utf8Str<'_>`)
    // borrows the response buffer and can't be returned by value. The
    // codegen emits `<attr>_read_with(endpoint, f)` for non-scalar
    // attributes: it reads, hands the borrowed `Result<Utf8Str, Error>`
    // to `f` while the buffer is live, and returns the owned value `f`
    // produces — here, an owned `String`. (Scalar attributes like OnOff
    // use the by-value `<attr>_read` instead.)
    exchange
        .basic_information()
        .vendor_name_read_with(0, |v| v.map(String::from))
        .await?
}

async fn invoke_toggle_with_timeout(
    matter: &Matter<'_>,
    fab_idx: core::num::NonZeroU8,
    peer_node_id: u64,
) -> Result<IMStatusCode, Error> {
    let exchange = Exchange::initiate(matter, test_only_crypto(), fab_idx, peer_node_id).await?;
    debug!("Invoke exchange initiated: {}", exchange.id());

    let mut invoke_fut = pin!(invoke_toggle(exchange));
    let mut timeout = pin!(Timer::after(Duration::from_secs(IM_TIMEOUT_SECS)));

    match select(&mut invoke_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => {
            warn!("Invoke operation timed out");
            Err(rs_matter::error::ErrorCode::RxTimeout.into())
        }
    }
}

async fn invoke_toggle(exchange: Exchange<'_>) -> Result<IMStatusCode, Error> {
    use rs_matter::dm::clusters::app::on_off::OnOffClient;

    // `OnOff::Toggle` is an empty-request DefaultSuccess command —
    // `on_off_toggle` returns `Ok(())` on success and converts the
    // IM status to an `Error` otherwise. The remaining `IMStatusCode`
    // return type is preserved for the caller — on the happy path it
    // is always `Success`.
    exchange.on_off().toggle(1).await?;
    Ok(IMStatusCode::Success)
}

// ============================================================================
// Network Utilities
// ============================================================================

/// Create a dual-stack UDP socket for Matter communication (ephemeral port).
fn create_dual_stack_socket() -> Result<async_io::Async<UdpSocket>, Error> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_reuse_address(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_only_v6(false)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    let bind_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0);
    socket
        .bind(&bind_addr.into())
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    let socket: UdpSocket = socket.into();
    async_io::Async::new_nonblocking(socket)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface.into())
}

/// Find a suitable network interface for the device's localhost endpoint.
///
/// Returns `(ipv4_addr, ipv6_addr_opt, interface_index)`.
/// Falls back to IPv4-only when no dual-stack interface is available.
fn find_network_interface() -> Result<(std::net::Ipv4Addr, bool, u32), Error> {
    use nix::net::if_::InterfaceFlags;
    use nix::sys::socket::SockaddrIn6;

    let interfaces = || {
        nix::ifaddrs::getifaddrs().unwrap().filter(|ia| {
            ia.flags.contains(InterfaceFlags::IFF_UP)
                && ia
                    .flags
                    .intersects(InterfaceFlags::IFF_BROADCAST | InterfaceFlags::IFF_MULTICAST)
                && !ia
                    .flags
                    .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
        })
    };

    // Prefer interface with both IPv4 and IPv6
    let result = interfaces()
        .filter_map(|ia| {
            ia.address
                .and_then(|addr| addr.as_sockaddr_in6().map(SockaddrIn6::ip))
                .map(|_ipv6| ia.interface_name.clone())
        })
        .find_map(|iname| {
            interfaces()
                .filter(|ia2| ia2.interface_name == iname)
                .find_map(|ia2| {
                    ia2.address
                        .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip()))
                        .map(|ip: std::net::Ipv4Addr| (iname.clone(), ip, true))
                })
        });

    // Fallback to IPv4 only
    let (iname, ip, ipv6_available) = result
        .or_else(|| {
            interfaces().find_map(|ia| {
                ia.address
                    .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip()))
                    .map(|ip: std::net::Ipv4Addr| (ia.interface_name.clone(), ip, false))
            })
        })
        .ok_or_else(|| {
            warn!("Cannot find network interface suitable for mDNS");
            rs_matter::error::ErrorCode::NoNetworkInterface
        })?;

    let if_index = nix::net::if_::if_nametoindex::<str>(iname.as_str()).unwrap_or(0);

    info!("Using network interface {iname} (index {if_index}) with {ip} (IPv6: {ipv6_available})");

    Ok((ip, ipv6_available, if_index))
}
