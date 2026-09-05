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

#![recursion_limit = "256"]

//! In-process device-to-device binding integration test — the automated
//! equivalent of the certification test plan's (manual) TC-BIND-2.1
//! "DUT as controller" procedure.
//!
//! Three in-process Matter stacks over loopback UDP:
//! - Device A: an **On/Off Light Switch** (`0x0103`) — OnOff in its *client*
//!   list plus a Binding cluster (its address book);
//! - Device B: an On/Off **Light** — the OnOff server;
//! - A controller, which commissions both onto one fabric.
//!
//! The flow:
//! 1. Commission A and B (PASE → AddNOC → CASE → CommissioningComplete);
//! 2. Controller replaces B's ACL with `[admin(controller), operate(A)]` —
//!    granting A's *node identity* operate-access on B;
//! 3. Controller writes a Binding entry on A's switch endpoint pointing at
//!    B's light endpoint, scoped to the OnOff cluster;
//! 4. A "switch press" is simulated: A walks its binding registry and — like
//!    the `onoff_light_switch` example — opens CASE to the bound peer and
//!    invokes `OnOff::Toggle`;
//! 5. The controller reads B's OnOff attribute and asserts it flipped.
//!
//! mDNS is skipped like in `commissioning.rs` (shared host `:5353` is
//! unreliable for multicast loopback): the commissioner is given the two
//! devices' addresses directly, and A's switch press CASEs to the bound
//! node at its (test-known) address via `Exchange::initiate_plaintext` +
//! `CaseInitiator::perform` — the same building blocks
//! `Transport::initiate_new_case` composes after an mDNS resolve.

#![cfg(all(
    feature = "std",
    feature = "async-io",
    feature = "groups",
    target_os = "linux"
))]

use core::num::NonZeroU8;
use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::{select, select3, Either};
use embassy_time::{Duration, Timer};

use log::info;

use rand_core::RngCore;

use rs_matter::cert::gen::VALID_FOREVER;
use rs_matter::cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN};
use rs_matter::crypto::{
    test_only_crypto, CanonAeadKey, CanonPkcSecretKey, Crypto, SecretKey, SigningSecretKey,
};
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::clusters::binding::{self, BindingHandler, Bindings};
use rs_matter::dm::clusters::decl::access_control::{
    AccessControlEntryAuthModeEnum, AccessControlEntryPrivilegeEnum,
};
use rs_matter::dm::clusters::decl::group_key_management::{
    GroupKeyManagementAttrWrites as _, GroupKeyManagementClient as _, GroupKeySecurityPolicyEnum,
};
use rs_matter::dm::clusters::decl::groups::GroupsClient as _;
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _, GroupsHandler};
use rs_matter::dm::clusters::net_comm::DummyNetworks;
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ON_OFF_LIGHT_SWITCH};
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::{endpoints, Async, DataModel, Dataver, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::im::client::ImClient;
use rs_matter::im::subscriptions::DEFAULT_MAX_SUBSCRIPTIONS;
use rs_matter::im::{CmdDataTag, CmdPath, InteractionModel, InteractionModelState};
use rs_matter::onboard::cac::{IcacGenerator, RcacGenerator};
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::onboard::{CommissionOptions, Commissioner};
use rs_matter::persist::DummyKvBlobStore;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::case::CaseInitiator;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::{Nullable, OctetStr, TLVTag, TLVWrite};
use rs_matter::transport::exchange::{Exchange, MatterBuffers};
use rs_matter::transport::network::{Address, NoNetwork, SocketAddr, SocketAddrV6};
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

// IM-client extension traits: `.on_off()` on `Exchange`, and the
// `.access_control_write()` / `.binding_write()` views on the write-request
// entries array.
use rs_matter::dm::clusters::app::on_off::OnOffClient as _;
use rs_matter::dm::clusters::decl::access_control::AccessControlAttrWrites as _;
use rs_matter::dm::clusters::decl::binding::BindingAttrWrites as _;

use static_cell::StaticCell;

use crate::common::mdns::stub_mdns_resolver;
use crate::common::{init_env_logger, run_device_controller, run_with_transport};

#[allow(dead_code)]
mod common;

/// Passcode used by `TEST_DEV_COMM`
const TEST_PASSCODE: u32 = 20202021;

/// The switch's port — off `MATTER_PORT` so it never clashes with B.
const PORT_A: u16 = 5580;
/// The light's port MUST be `MATTER_PORT` (5540): group data messages are
/// multicast to the fixed Matter port. Safe against the `commissioning`
/// test binary (which also binds 5540): cargo runs test binaries
/// sequentially.
const PORT_B: u16 = MATTER_PORT;

/// The group the light joins and the switch multicasts to, with its
/// security material.
const GROUP_ID: u16 = 0x002A;
const GROUP_KEY_SET_ID: u16 = 0x01A3;
const GROUP_EPOCH_KEY: [u8; 16] = [
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];

/// Operational node ids the controller assigns during commissioning.
const NODE_ID_A: u64 = 0x11;
const NODE_ID_B: u64 = 0x22;
/// The controller's own node id (also the CaseAdminSubject seeded into each
/// device's ACL by AddNOC) — chip-tool's conventional admin node id.
const CONTROLLER_NODE_ID: u64 = 112233;

/// The endpoint hosting the switch role on device A.
const SWITCH_ENDPOINT: u16 = 1;
/// The endpoint hosting the light on device B.
const LIGHT_ENDPOINT: u16 = 1;

/// How many binding entries device A can hold.
const MAX_BINDINGS: usize = 4;

/// Timeout for the whole driven flow.
const FLOW_TIMEOUT_SECS: u64 = 60;

/// A device's data model state: a dummy (no-op) network store, default
/// subscription count, no events.
type DeviceDmState = InteractionModelState<DummyNetworks, DEFAULT_MAX_SUBSCRIPTIONS, 0>;

static A_MATTER: StaticCell<Matter> = StaticCell::new();
static A_BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static A_STATE: StaticCell<DeviceDmState> = StaticCell::new();
static B_MATTER: StaticCell<Matter> = StaticCell::new();
static B_BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static B_STATE: StaticCell<DeviceDmState> = StaticCell::new();
static CTRL_MATTER: StaticCell<Matter> = StaticCell::new();

// ============================================================================
// Device A: the switch — Binding server + OnOff client on `SWITCH_ENDPOINT`
// ============================================================================

const SWITCH_NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new_with_clients(
            SWITCH_ENDPOINT,
            devices!(DEV_TYPE_ON_OFF_LIGHT_SWITCH),
            clusters!(desc::DescHandler::CLUSTER, binding::CLUSTER),
            &[on_off::FULL_CLUSTER.id],
        ),
    ],
};

fn switch_data_model<'a>(
    mut rand: impl RngCore + Copy,
    bindings: &'a Bindings<MAX_BINDINGS>,
) -> impl DataModel + 'a {
    (
        SWITCH_NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&UnixNetifs)
            .build(rand)
            .chain(
                |e, c| e == SWITCH_ENDPOINT && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == SWITCH_ENDPOINT && c == binding::CLUSTER.id,
                Async(
                    BindingHandler::new(Dataver::new_rand(&mut rand), SWITCH_ENDPOINT, bindings)
                        .adapt(),
                ),
            ),
    )
}

// ============================================================================
// Device B: the light — OnOff server on `LIGHT_ENDPOINT`
// ============================================================================

const LIGHT_NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            LIGHT_ENDPOINT,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
            ),
        ),
    ],
};

fn light_data_model<'a, OH: OnOffHooks>(
    mut rand: impl RngCore + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, on_off::NoLevelControl>,
) -> impl DataModel + 'a {
    (
        LIGHT_NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&UnixNetifs)
            .build(rand)
            .chain(
                |e, c| e == LIGHT_ENDPOINT && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == LIGHT_ENDPOINT && c == groups::GroupsHandler::CLUSTER.id,
                Async(GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == LIGHT_ENDPOINT && c == TestOnOffDeviceLogic::CLUSTER.id,
                on_off::HandlerAsyncAdaptor(on_off),
            ),
    )
}

// ============================================================================
// The test
// ============================================================================

#[test]
fn test_switch_binding() {
    // Three in-process Matter stacks' worth of future state-machines don't
    // fit the default 2 MiB test-thread stack.
    let thread = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            init_env_logger();
            futures_lite::future::block_on(async {
                run_test().await.unwrap();
            });
        })
        .unwrap();
    thread.join().unwrap();
}

async fn run_test() -> Result<(), Error> {
    // ---- Device A (the switch) ----

    let a_matter = A_MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        PORT_A,
    ));
    let a_crypto = test_only_crypto();
    let a_rand = a_crypto.rand()?;
    let a_buffers = A_BUFFERS.uninit().init_with(MatterBuffers::init());
    let a_state = A_STATE.init(InteractionModelState::new(DummyNetworks));
    let a_kv = a_matter.kv(DummyKvBlobStore);

    let bindings = Bindings::<MAX_BINDINGS>::new();

    let a_dm = InteractionModel::new(
        a_matter,
        &a_crypto,
        a_buffers,
        switch_data_model(a_rand, &bindings),
        &a_kv,
        a_state,
    );

    a_matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &a_crypto, &())?;

    let a_responder = DefaultResponder::new(&a_dm);
    let a_net = async_io::Async::<UdpSocket>::bind(device_bind_addr(PORT_A))?;

    let a_fut = async {
        select3(
            a_matter.run(&a_crypto, &a_net, &a_net, NoNetwork),
            a_responder.run::<4, 4>(),
            a_dm.run(),
        )
        .coalesce()
        .await
    };

    // ---- Device B (the light) ----

    let b_matter = B_MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        PORT_B,
    ));
    let b_crypto = test_only_crypto();
    let mut b_rand = b_crypto.rand()?;
    let b_buffers = B_BUFFERS.uninit().init_with(MatterBuffers::init());
    let b_state = B_STATE.init(InteractionModelState::new(DummyNetworks));
    let b_kv = b_matter.kv(DummyKvBlobStore);

    let b_on_off = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut b_rand),
        LIGHT_ENDPOINT,
        TestOnOffDeviceLogic::new(false),
    );

    let b_dm = InteractionModel::new(
        b_matter,
        &b_crypto,
        b_buffers,
        light_data_model(b_rand, &b_on_off),
        &b_kv,
        b_state,
    );

    b_matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &b_crypto, &())?;

    let b_responder = DefaultResponder::new(&b_dm);
    let b_net = async_io::Async::<UdpSocket>::bind(device_bind_addr(PORT_B))?;

    let b_fut = async {
        select3(
            // B's own socket doubles as the multicast impl, so the transport
            // joins the group multicast address once B is added to the group.
            b_matter.run(&b_crypto, &b_net, &b_net, &b_net),
            b_responder.run::<4, 4>(),
            b_dm.run(),
        )
        .coalesce()
        .await
    };

    // ---- The controller ----

    let ctrl_matter = CTRL_MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        0,
    ));
    let ctrl_crypto = test_only_crypto();
    let ctrl_net = async_io::Async::<UdpSocket>::bind(SocketAddr::V6(SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))?;

    info!("Two devices and the controller initialized; starting the binding test...");

    let controller_fut = run_with_transport(
        ctrl_matter.run(&ctrl_crypto, &ctrl_net, &ctrl_net, NoNetwork),
        run_flow_with_timeout(ctrl_matter, &ctrl_crypto, a_matter, &a_crypto, &bindings),
    );

    let devices_fut = async {
        let mut a_fut = pin!(a_fut);
        let mut b_fut = pin!(b_fut);
        select(&mut a_fut, &mut b_fut).coalesce().await
    };

    run_device_controller(devices_fut, controller_fut).await
}

async fn run_flow_with_timeout<C: Crypto, AC: Crypto>(
    ctrl_matter: &Matter<'_>,
    ctrl_crypto: &C,
    a_matter: &Matter<'_>,
    a_crypto: &AC,
    bindings: &Bindings<MAX_BINDINGS>,
) -> Result<(), Error> {
    let mut flow = pin!(run_flow(
        ctrl_matter,
        ctrl_crypto,
        a_matter,
        a_crypto,
        bindings
    ));
    let mut timeout = pin!(Timer::after(Duration::from_secs(FLOW_TIMEOUT_SECS)));

    match select(&mut flow, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => panic!("binding test flow timed out after {FLOW_TIMEOUT_SECS}s"),
    }
}

async fn run_flow<C: Crypto, AC: Crypto>(
    ctrl_matter: &Matter<'_>,
    ctrl_crypto: &C,
    a_matter: &Matter<'_>,
    a_crypto: &AC,
    bindings: &Bindings<MAX_BINDINGS>,
) -> Result<(), Error> {
    let addr_a = device_addr(PORT_A)?;
    let addr_b = device_addr(PORT_B)?;

    info!("=== Phase 1: Commission both devices onto one fabric ===");
    let ctrl_fab_idx = commission_both(ctrl_matter, ctrl_crypto, addr_a, addr_b).await?;

    info!("=== Phase 2: Replace B's ACL with [admin(controller), operate(A)] ===");
    write_light_acl(ctrl_matter, ctrl_crypto, ctrl_fab_idx).await?;

    info!("=== Phase 3: Write the Binding entry on A's switch endpoint ===");
    write_switch_binding(ctrl_matter, ctrl_crypto, ctrl_fab_idx).await?;

    let initial = read_light_on_off(ctrl_matter, ctrl_crypto, ctrl_fab_idx).await?;
    assert!(!initial, "expected the light OFF before the switch press");

    info!("=== Phase 4: Simulate the switch press on A ===");
    press_switch(a_matter, a_crypto, bindings, addr_b).await?;

    info!("=== Phase 5: Verify the bound light toggled ===");
    let toggled = read_light_on_off(ctrl_matter, ctrl_crypto, ctrl_fab_idx).await?;
    assert!(toggled, "expected the light ON after the switch press");

    info!("=== Phase 6: Provision the group on both devices ===");
    // Key material on both ends: A encrypts with it, B decrypts with it.
    provision_group_keys(ctrl_matter, ctrl_crypto, ctrl_fab_idx, NODE_ID_A).await?;
    provision_group_keys(ctrl_matter, ctrl_crypto, ctrl_fab_idx, NODE_ID_B).await?;
    // B's light endpoint joins the group (and its transport joins the
    // group's multicast address).
    add_light_to_group(ctrl_matter, ctrl_crypto, ctrl_fab_idx).await?;

    info!("=== Phase 7: Re-bind A's switch to the group ===");
    write_switch_group_binding(ctrl_matter, ctrl_crypto, ctrl_fab_idx).await?;

    // Give B's transport a moment to complete the multicast join.
    Timer::after(Duration::from_millis(500)).await;

    info!("=== Phase 8: Simulate a switch press — now a groupcast Toggle ===");
    press_switch(a_matter, a_crypto, bindings, addr_b).await?;

    info!("=== Phase 9: Verify the light toggled via the group message ===");
    // The groupcast Toggle flips the (currently ON) light OFF. Poll: the
    // multicast delivery is asynchronous to the (fire-and-forget) send.
    let deadline = embassy_time::Instant::now() + Duration::from_secs(10);
    loop {
        if !read_light_on_off(ctrl_matter, ctrl_crypto, ctrl_fab_idx).await? {
            break;
        }

        if embassy_time::Instant::now() > deadline {
            panic!("light did not toggle OFF on the groupcast Toggle");
        }

        Timer::after(Duration::from_millis(250)).await;
    }

    info!("=== Binding test (unicast + groupcast) completed successfully! ===");
    Ok(())
}

/// Provision the group's security material on `node_id` via the
/// GroupKeyManagement cluster: `KeySetWrite` with the shared epoch key,
/// then a `GroupKeyMap` entry binding [`GROUP_ID`] to the key set.
async fn provision_group_keys<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    fab_idx: NonZeroU8,
    node_id: u64,
) -> Result<(), Error> {
    let exchange = Exchange::initiate(matter, crypto, fab_idx, node_id).await?;

    exchange
        .group_key_management()
        .key_set_write(0, |b| {
            b.group_key_set()?
                .group_key_set_id(GROUP_KEY_SET_ID)?
                .group_key_security_policy(GroupKeySecurityPolicyEnum::TrustFirst)?
                .epoch_key_0(Nullable::some(OctetStr::new(&GROUP_EPOCH_KEY)))?
                .epoch_start_time_0(Nullable::some(1))?
                .epoch_key_1(Nullable::none())?
                .epoch_start_time_1(Nullable::none())?
                .epoch_key_2(Nullable::none())?
                .epoch_start_time_2(Nullable::none())?
                .group_key_multicast_policy(
                    rs_matter::dm::clusters::decl::group_key_management::GroupKeyMulticastPolicyEnum::PerGroupID,
                )?
                .end()?
                .end()
        })
        .await?;

    let exchange = Exchange::initiate(matter, crypto, fab_idx, node_id).await?;

    let handle = exchange
        .write_with(None, |builder| {
            let entries = builder.write_requests()?;
            let map = entries.group_key_management_write().group_key_map(0)?;

            let map = map
                .push()?
                .group_id(GROUP_ID)?
                .group_key_set_id(GROUP_KEY_SET_ID)?
                .fabric_index(None)?
                .end()?;

            map.end()?.end()?.end()?.end()
        })
        .await?;

    let resp = handle.response()?;
    for status in resp.write_responses.iter() {
        let status = status?;
        assert_eq!(
            status.status.status,
            rs_matter::im::IMStatusCode::Success,
            "GroupKeyMap write failed"
        );
    }

    Ok(())
}

/// Add B's light endpoint to [`GROUP_ID`] via the Groups cluster.
async fn add_light_to_group<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    fab_idx: NonZeroU8,
) -> Result<(), Error> {
    let exchange = Exchange::initiate(matter, crypto, fab_idx, NODE_ID_B).await?;

    let handle = exchange
        .groups()
        .add_group(LIGHT_ENDPOINT, |b| {
            b.group_id(GROUP_ID)?.group_name("")?.end()
        })
        .await?;

    {
        let resp = handle.response()?;
        assert_eq!(resp.status()?, 0, "AddGroup on the light failed");
    }

    handle.complete().await
}

/// Replace A's binding list with a single *group* target — the switch now
/// multicasts to the group instead of CASE-ing to a node.
async fn write_switch_group_binding<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    fab_idx: NonZeroU8,
) -> Result<(), Error> {
    let exchange = Exchange::initiate(matter, crypto, fab_idx, NODE_ID_A).await?;

    let handle = exchange
        .write_with(None, |builder| {
            let entries = builder.write_requests()?;
            let bindings = entries.binding_write().binding(SWITCH_ENDPOINT)?;

            let bindings = bindings
                .push()?
                .node(None)?
                .group(Some(GROUP_ID))?
                .endpoint(None)?
                .cluster(Some(on_off::FULL_CLUSTER.id))?
                .fabric_index(None)?
                .end()?;

            bindings.end()?.end()?.end()?.end()
        })
        .await?;

    let resp = handle.response()?;
    for status in resp.write_responses.iter() {
        let status = status?;
        assert_eq!(
            status.status.status,
            rs_matter::im::IMStatusCode::Success,
            "Group binding write on the switch failed"
        );
    }

    Ok(())
}

/// Build the controller's fabric and commission device A, then device B,
/// onto it. Same offline-CA plumbing as `commissioning.rs`.
async fn commission_both<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    addr_a: Address,
    addr_b: Address,
) -> Result<NonZeroU8, Error> {
    const FABRIC_ID: u64 = 1;
    const ADMIN_VENDOR_ID: u16 = 0xFFF1;

    // ---- Offline CA chain: RCAC then ICAC; RCAC priv discarded ----

    let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut rcac_gen = RcacGenerator::new(&mut rcac_buf);
    let (rcac_priv, rcac) = rcac_gen.generate(crypto, FABRIC_ID, VALID_FOREVER)?;

    let mut icac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut icac_gen = IcacGenerator::new(&mut icac_buf);
    let (icac_priv, icac) =
        icac_gen.generate(crypto, rcac_priv.reference(), rcac, VALID_FOREVER)?;
    drop(rcac_priv);

    // ---- Controller operational keypair + NOC ----

    let controller_secret_key = crypto.generate_secret_key()?;
    let mut controller_csr_buf = [0u8; 256];
    let controller_csr = controller_secret_key.csr(&mut controller_csr_buf)?;
    let mut controller_secret_key_canon = CanonPkcSecretKey::new();
    controller_secret_key.write_canon(&mut controller_secret_key_canon)?;

    let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut noc_generator = NocGenerator::create(icac_priv.reference(), rcac, icac, &mut noc_buf)?;

    let controller_noc = noc_generator.generate(
        crypto,
        controller_csr,
        CONTROLLER_NODE_ID,
        &[],
        VALID_FOREVER,
    )?;

    // ---- Fabric IPK + install the controller's fabric ----

    let mut ipk = CanonAeadKey::new();
    crypto.rand()?.fill_bytes(ipk.access_mut());

    let ctrl_fab_idx = matter.with_state(|state| {
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
    })?;

    // ---- Commission the two devices, sequentially ----

    let mut commissioner_buf = [0u8; MAX_CERT_TLV_LEN];
    let mut commissioner = Commissioner::new(
        matter,
        crypto,
        ctrl_fab_idx,
        &mut noc_generator,
        &mut commissioner_buf,
    );

    let opts = CommissionOptions {
        // Test DAC — TEST_DEV_ATT.
        allow_test_attestation: true,
        ..CommissionOptions::default()
    };

    // Phase 2 goes through operational discovery rather than reusing the address
    // PASE was driven over, so a stub resolver stands in for the mDNS backend
    // this test does not run. It answers per node id, which is what lets both
    // devices be commissioned against the same stub.
    let sock_of = |addr: Address| match addr {
        Address::Udp(SocketAddr::V6(sock)) | Address::Tcp(SocketAddr::V6(sock)) => sock,
        _ => panic!("expected an IPv6 device address"),
    };

    let mdns_table = [(NODE_ID_A, sock_of(addr_a)), (NODE_ID_B, sock_of(addr_b))];
    let mdns = stub_mdns_resolver(matter, &mdns_table);

    let commission_both = async {
        for (addr, node_id, tag) in [
            (addr_a, NODE_ID_A, "switch-A"),
            (addr_b, NODE_ID_B, "light-B"),
        ] {
            let result = commissioner
                .commission(addr, TEST_PASSCODE, &opts, node_id, VALID_FOREVER)
                .await?;
            commissioner.complete_via_case(&result).await?;
            info!(
                "Commissioned {tag} as node 0x{:016x}",
                result.device_node_id
            );
        }

        Ok::<_, Error>(())
    };

    match select(pin!(commission_both), pin!(mdns)).await {
        Either::First(r) => r?,
        Either::Second(_) => unreachable!("the stub resolver never returns"),
    }

    Ok(ctrl_fab_idx)
}

/// Replace B's ACL with the admin entry (for the controller) plus an
/// operate entry for A's node identity — the grant that lets the switch
/// invoke `OnOff::Toggle` on the light.
async fn write_light_acl<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    fab_idx: NonZeroU8,
) -> Result<(), Error> {
    let exchange = Exchange::initiate(matter, crypto, fab_idx, NODE_ID_B).await?;

    let handle = exchange
        .write_with(None, |builder| {
            let entries = builder.write_requests()?;
            let acl = entries.access_control_write().acl(0)?;

            // Entry 1: the admin entry AddNOC seeded (CaseAdminSubject) —
            // a whole-list replace must carry it or the controller locks
            // itself out.
            let acl = acl
                .push()?
                .privilege(Some(AccessControlEntryPrivilegeEnum::Administer))?
                .auth_mode(Some(AccessControlEntryAuthModeEnum::CASE))?
                .subjects()?
                .some()?
                .non_null()?
                .push(&CONTROLLER_NODE_ID)?
                .end()?
                .targets()?
                .some()?
                .null()?
                .auxiliary_type(None)?
                .fabric_index(None)?
                .end()?;

            // Entry 2: operate for the switch's node identity.
            let acl = acl
                .push()?
                .privilege(Some(AccessControlEntryPrivilegeEnum::Operate))?
                .auth_mode(Some(AccessControlEntryAuthModeEnum::CASE))?
                .subjects()?
                .some()?
                .non_null()?
                .push(&NODE_ID_A)?
                .end()?
                .targets()?
                .some()?
                .null()?
                .auxiliary_type(None)?
                .fabric_index(None)?
                .end()?;

            // Entry 3: operate for groupcast invokes targeting GROUP_ID —
            // group messages authenticate via the group key, so their ACL
            // subject is the Group ID, not the sender's node identity.
            let acl = acl
                .push()?
                .privilege(Some(AccessControlEntryPrivilegeEnum::Operate))?
                .auth_mode(Some(AccessControlEntryAuthModeEnum::Group))?
                .subjects()?
                .some()?
                .non_null()?
                .push(&(GROUP_ID as u64))?
                .end()?
                .targets()?
                .some()?
                .null()?
                .auxiliary_type(None)?
                .fabric_index(None)?
                .end()?;

            acl.end()?.end()?.end()?.end()
        })
        .await?;

    let resp = handle.response()?;
    for status in resp.write_responses.iter() {
        let status = status?;
        assert_eq!(
            status.status.status,
            rs_matter::im::IMStatusCode::Success,
            "ACL write on the light failed"
        );
    }

    Ok(())
}

/// Write a single Binding entry on A's switch endpoint, pointing at B's
/// light endpoint and scoped to the OnOff cluster.
async fn write_switch_binding<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    fab_idx: NonZeroU8,
) -> Result<(), Error> {
    let exchange = Exchange::initiate(matter, crypto, fab_idx, NODE_ID_A).await?;

    let handle = exchange
        .write_with(None, |builder| {
            let entries = builder.write_requests()?;
            let bindings = entries.binding_write().binding(SWITCH_ENDPOINT)?;

            let bindings = bindings
                .push()?
                .node(Some(NODE_ID_B))?
                .group(None)?
                .endpoint(Some(LIGHT_ENDPOINT))?
                .cluster(Some(on_off::FULL_CLUSTER.id))?
                .fabric_index(None)?
                .end()?;

            bindings.end()?.end()?.end()?.end()
        })
        .await?;

    let resp = handle.response()?;
    for status in resp.write_responses.iter() {
        let status = status?;
        assert_eq!(
            status.status.status,
            rs_matter::im::IMStatusCode::Success,
            "Binding write on the switch failed"
        );
    }

    Ok(())
}

/// Simulate a switch press on device A: walk its binding registry and — for
/// each unicast OnOff target — establish CASE to the bound peer and invoke
/// `OnOff::Toggle`, exactly like the `onoff_light_switch` example's switch
/// loop. The bound peer's address comes from the test (mDNS is skipped);
/// `CaseInitiator::perform` + `Exchange::initiate` compose the same way
/// `Transport::initiate_new_case` does after an mDNS resolve.
async fn press_switch<C: Crypto>(
    a_matter: &Matter<'_>,
    a_crypto: &C,
    bindings: &Bindings<MAX_BINDINGS>,
    peer_addr: Address,
) -> Result<(), Error> {
    let mut toggled = 0;

    for i in 0..bindings.len() {
        let Some(binding) = bindings.get(i) else {
            break;
        };

        if binding.local_endpoint != SWITCH_ENDPOINT {
            continue;
        }

        if let Some(cluster) = binding.cluster {
            if cluster != on_off::FULL_CLUSTER.id {
                continue;
            }
        }

        if let Some(group_id) = binding.group {
            // Group target: multicast an encrypted, fire-and-forget Toggle
            // to the whole group, with an endpoint-less command path —
            // receivers apply it to their group-member endpoints.
            info!(
                "Switch: group-toggling fabric {}, group 0x{:04X}",
                binding.fab_idx, group_id
            );

            let exchange = Exchange::initiate_group(
                a_matter,
                a_crypto,
                a_matter.kv(DummyKvBlobStore),
                binding.fab_idx,
                group_id,
            )?;

            exchange
                .group_invoke_with(|b| {
                    b.push()?
                        .path_from(&CmdPath::new(
                            None,
                            Some(on_off::FULL_CLUSTER.id),
                            Some(on_off::CommandId::Toggle as u32),
                        ))?
                        .data(|w| {
                            w.start_struct(&TLVTag::Context(CmdDataTag::Data as u8))?;
                            w.end_container()
                        })?
                        .end()
                })
                .await?;

            toggled += 1;
            continue;
        }

        // Unicast OnOff targets (node + endpoint present).
        let (Some(node), Some(endpoint)) = (binding.node, binding.endpoint) else {
            continue;
        };

        info!(
            "Switch: toggling fabric {}, node 0x{:016X}, endpoint {}",
            binding.fab_idx, node, endpoint
        );

        // CASE to the bound peer at its known address (no mDNS in this test).
        let case_exchange = Exchange::initiate_plaintext(a_matter, a_crypto, peer_addr).await?;
        CaseInitiator::perform(case_exchange, a_crypto, binding.fab_idx, node).await?;

        // The CASE session is now in A's session table; `initiate` reuses it.
        let exchange = Exchange::initiate(a_matter, a_crypto, binding.fab_idx, node).await?;
        exchange.on_off().toggle(endpoint).await?;

        toggled += 1;
    }

    assert_eq!(toggled, 1, "expected exactly one bound light to toggle");

    Ok(())
}

/// Read B's OnOff attribute from the controller (over the CASE session kept
/// from commissioning).
async fn read_light_on_off<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    fab_idx: NonZeroU8,
) -> Result<bool, Error> {
    let exchange = Exchange::initiate(matter, crypto, fab_idx, NODE_ID_B).await?;

    exchange.on_off().on_off_read(LIGHT_ENDPOINT).await
}

/// The `[::]:<port>` address a device binds.
fn device_bind_addr(port: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        port,
        0,
        0,
    ))
}

/// The address peers use to reach a device (mDNS skipped): the host's
/// primary IPv4, v6-mapped — same approach as `commissioning.rs`.
fn device_addr(port: u16) -> Result<Address, Error> {
    let ipv4 = find_host_ipv4()?;

    Ok(Address::Udp(SocketAddr::V6(SocketAddrV6::new(
        ipv4.to_ipv6_mapped(),
        port,
        0,
        0,
    ))))
}

/// The host's primary (non-loopback, multicast-capable) IPv4 address.
fn find_host_ipv4() -> Result<std::net::Ipv4Addr, Error> {
    use nix::net::if_::InterfaceFlags;

    nix::ifaddrs::getifaddrs()
        .unwrap()
        .filter(|ia| {
            ia.flags.contains(InterfaceFlags::IFF_UP)
                && ia
                    .flags
                    .intersects(InterfaceFlags::IFF_BROADCAST | InterfaceFlags::IFF_MULTICAST)
                && !ia
                    .flags
                    .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
        })
        .find_map(|ia| {
            ia.address
                .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip()))
        })
        .ok_or_else(|| rs_matter::error::ErrorCode::NoNetworkInterface.into())
}
