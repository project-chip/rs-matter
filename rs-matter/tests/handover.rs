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

//! In-process commissioning handover test: phase 1 runs against device A,
//! A suspends into an envelope, device B resumes from it, and phase 2
//! (CASE + `CommissioningComplete`) completes against B, followed by an OnOff
//! toggle over CASE.

#![cfg(all(feature = "std", feature = "async-io", target_os = "linux"))]

use core::num::NonZeroU8;
use core::pin::pin;
use std::net::UdpSocket;

use embassy_futures::select::{select, select3, Either};
use embassy_time::{Duration, Timer};

use log::info;

use rand_core::Rng;

use rs_matter::cert::gen::VALID_FOREVER;
use rs_matter::cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN};
use rs_matter::crypto::{
    test_only_crypto, CanonAeadKey, CanonPkcSecretKey, Crypto, SecretKey, SigningSecretKey,
};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::{DummyNetworks, SharedNetworks};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::{endpoints, Async, DataModel, Dataver, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::handover::CommissioningHandover;
use rs_matter::im::subscriptions::DEFAULT_MAX_SUBSCRIPTIONS;
use rs_matter::im::{InteractionModel, InteractionModelState};
use rs_matter::onboard::cac::{IcacGenerator, RcacGenerator};
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::onboard::{CommissionOptions, Commissioner};
use rs_matter::persist::{KvBlobStoreAccess, FABRIC_KEYS_START};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::{FromTLV, TLVElement, TLVTag, ToTLV};
use rs_matter::transport::exchange::{Exchange, MatterBuffers};
use rs_matter::transport::network::{Address, NoNetwork, SocketAddr, SocketAddrV6};
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::WriteBuf;
use rs_matter::{clusters, devices, root_endpoint, Matter};

use static_cell::StaticCell;

use crate::common::mdns::stub_mdns_resolver_txt;
use crate::common::{init_env_logger, run_with_transport, MemKvBlobStore};

#[allow(dead_code)]
mod common;

/// Passcode used by `TEST_DEV_COMM`
const TEST_PASSCODE: u32 = 20202021;

/// Device ports, distinct from the other integration tests'.
const DEVICE_A_PORT: u16 = 5560;
const DEVICE_B_PORT: u16 = 5561;

const IM_TIMEOUT_SECS: u64 = 10;

type DeviceDmState = InteractionModelState<DummyNetworks, DEFAULT_MAX_SUBSCRIPTIONS, 0>;

static DEVICE_A_MATTER: StaticCell<Matter> = StaticCell::new();
static DEVICE_A_BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static DEVICE_A_STATE: StaticCell<DeviceDmState> = StaticCell::new();
static DEVICE_B_MATTER: StaticCell<Matter> = StaticCell::new();
static DEVICE_B_BUFFERS: StaticCell<MatterBuffers> = StaticCell::new();
static DEVICE_B_STATE: StaticCell<DeviceDmState> = StaticCell::new();
static CTRL_MATTER: StaticCell<Matter> = StaticCell::new();

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

/// What the controller flow needs from a device.
struct DeviceHandles<'a, K> {
    matter: &'a Matter<'a>,
    networks: &'a SharedNetworks<DummyNetworks>,
    kv: K,
    store: MemKvBlobStore,
}

#[test]
fn test_commissioning_handover() {
    // Two devices plus a controller in one future need more than the
    // default 2 MiB stack
    let thread = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            init_env_logger();
            futures_lite::future::block_on(async {
                run().await.unwrap();
            });
        })
        .unwrap();
    thread.join().unwrap();
}

async fn run() -> Result<(), Error> {
    let crypto = test_only_crypto();

    // ---- Device A: commissionable ----

    let device_a = DEVICE_A_MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        DEVICE_A_PORT,
    ));
    let buffers_a = DEVICE_A_BUFFERS.uninit().init_with(MatterBuffers::init());
    let state_a = DEVICE_A_STATE.init(InteractionModelState::new(DummyNetworks));
    let on_off_a = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut crypto.rand()?),
        1,
        TestOnOffDeviceLogic::new(false),
    );
    let store_a = MemKvBlobStore::default();
    let kv_a = device_a.kv(store_a.clone());
    let dm_a = InteractionModel::new(
        device_a,
        &crypto,
        buffers_a,
        data_model(crypto.rand()?, &on_off_a),
        &kv_a,
        state_a,
    );

    device_a.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;

    // ---- Device B: resumes from the envelope ----

    let device_b = DEVICE_B_MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        DEVICE_B_PORT,
    ));
    let buffers_b = DEVICE_B_BUFFERS.uninit().init_with(MatterBuffers::init());
    let state_b = DEVICE_B_STATE.init(InteractionModelState::new(DummyNetworks));
    let on_off_b = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut crypto.rand()?),
        1,
        TestOnOffDeviceLogic::new(false),
    );
    let store_b = MemKvBlobStore::default();
    let kv_b = device_b.kv(store_b.clone());
    let dm_b = InteractionModel::new(
        device_b,
        &crypto,
        buffers_b,
        data_model(crypto.rand()?, &on_off_b),
        &kv_b,
        state_b,
    );

    let responder_a = DefaultResponder::new(&dm_a);
    let responder_b = DefaultResponder::new(&dm_b);

    let net_a = bind_udp(DEVICE_A_PORT)?;
    let net_b = bind_udp(DEVICE_B_PORT)?;

    // ---- Controller ----

    let ctrl_matter = CTRL_MATTER.uninit().init_with(Matter::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        0,
    ));
    let ctrl_net = bind_udp(0)?;

    let device_a_fut = async {
        select3(
            device_a.run(&crypto, &net_a, &net_a, NoNetwork),
            responder_a.run::<4, 4>(),
            dm_a.run(),
        )
        .coalesce()
        .await
    };

    let device_b_fut = async {
        select3(
            device_b.run(&crypto, &net_b, &net_b, NoNetwork),
            responder_b.run::<4, 4>(),
            dm_b.run(),
        )
        .coalesce()
        .await
    };

    let controller_fut = run_with_transport(
        ctrl_matter.run(&crypto, &ctrl_net, &ctrl_net, NoNetwork),
        run_controller_flow(
            ctrl_matter,
            &crypto,
            DeviceHandles {
                matter: device_a,
                networks: state_a.networks(),
                kv: &kv_a,
                store: store_a.clone(),
            },
            DeviceHandles {
                matter: device_b,
                networks: state_b.networks(),
                kv: &kv_b,
                store: store_b.clone(),
            },
        ),
    );

    let mut devices_fut = pin!(async { select(device_a_fut, device_b_fut).coalesce().await });
    let mut controller_fut = pin!(controller_fut);

    match select(&mut devices_fut, &mut controller_fut).await {
        Either::First(r) => panic!("A device exited unexpectedly: {r:?}"),
        Either::Second(result) => result,
    }
}

async fn run_controller_flow<C: Crypto, K: KvBlobStoreAccess>(
    matter: &Matter<'_>,
    crypto: &C,
    device_a: DeviceHandles<'_, K>,
    device_b: DeviceHandles<'_, K>,
) -> Result<(), Error> {
    const FABRIC_ID: u64 = 1;
    const CONTROLLER_NODE_ID: u64 = 112233;
    const DEVICE_NODE_ID: u64 = 112234;
    const ADMIN_VENDOR_ID: u16 = 0xFFF1;

    let ipv4 = find_ipv4()?;
    let sock_of = |port| SocketAddrV6::new(ipv4.to_ipv6_mapped(), port, 0, 0);

    // ---- Controller fabric ----

    let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut rcac_gen = RcacGenerator::new(&mut rcac_buf);
    let (rcac_priv, rcac) = rcac_gen.generate(crypto, FABRIC_ID, VALID_FOREVER)?;

    let mut icac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut icac_gen = IcacGenerator::new(&mut icac_buf);
    let (icac_priv, icac) =
        icac_gen.generate(crypto, rcac_priv.reference(), rcac, VALID_FOREVER)?;
    drop(rcac_priv);

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

    let mut ipk = CanonAeadKey::new();
    crypto.rand()?.fill_bytes(ipk.access_mut());

    let controller_fab_idx = matter.with_state(|state| {
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

    let mut commissioner_buf = [0u8; MAX_CERT_TLV_LEN];
    let mut commissioner = Commissioner::new(
        matter,
        crypto,
        controller_fab_idx,
        &mut noc_generator,
        &mut commissioner_buf,
    );

    let opts = CommissionOptions {
        allow_test_attestation: true,
        ..CommissionOptions::default()
    };

    // ---- Phase 1 against A ----

    info!("=== Phase 1: commission() against device A ===");
    let result = commissioner
        .commission(
            Address::Udp(SocketAddr::V6(sock_of(DEVICE_A_PORT))),
            TEST_PASSCODE,
            &opts,
            DEVICE_NODE_ID,
            VALID_FOREVER,
        )
        .await?;

    assert!(
        device_a.matter.has_fabrics(),
        "A should hold the pending fabric"
    );
    assert!(
        !device_b.matter.has_fabrics(),
        "B should not have any fabric yet"
    );

    // ---- Suspend on A ----

    info!("=== Handover: suspend on A ===");

    let serialize = |handover: &CommissioningHandover<'_>| {
        let mut buf = vec![0u8; 2048];
        let mut wb = WriteBuf::new(&mut buf);
        handover.to_tlv(&TLVTag::Anonymous, &mut wb)?;
        let len = wb.get_tail();
        buf.truncate(len);

        Ok(buf)
    };

    // Nothing to export without a pending AddNOC
    assert!(device_b
        .matter
        .suspend_commissioning(device_b.networks, &device_b.kv, serialize)
        .is_err());

    // A failing closure leaves A untouched
    assert!(device_a
        .matter
        .suspend_commissioning(device_a.networks, &device_a.kv, |_| Err::<(), _>(
            rs_matter::error::ErrorCode::Invalid.into()
        ))
        .is_err());
    assert!(
        device_a.matter.has_fabrics(),
        "A should still hold the fabric"
    );

    let envelope =
        device_a
            .matter
            .suspend_commissioning(device_a.networks, &device_a.kv, serialize)?;

    assert!(
        !device_a.matter.has_fabrics(),
        "A should have rolled back to no fabrics"
    );
    assert!(
        !device_a.store.contains_key(FABRIC_KEYS_START + 1),
        "A should never have persisted the fabric"
    );

    // ---- Resume on B ----

    info!("=== Handover: resume on B ===");
    let handover = CommissioningHandover::from_tlv(&TLVElement::new(&envelope))?;
    handover.validate()?;
    assert_eq!(handover.admin_vendor_id, ADMIN_VENDOR_ID);
    assert!(handover.icac.is_some(), "the controller chain has an ICAC");
    assert!(handover.fail_safe_remaining_secs > 0);
    assert_eq!(
        handover.acl.iter()?.count(),
        1,
        "just the AddNOC admin entry"
    );

    let fab_idx =
        device_b
            .matter
            .resume_commissioning(crypto, device_b.networks, &device_b.kv, &handover)?;

    assert!(
        device_b.matter.has_fabrics(),
        "B should hold the resumed fabric"
    );
    assert!(
        device_b
            .matter
            .resume_commissioning(crypto, device_b.networks, &device_b.kv, &handover)
            .is_err(),
        "a second resume while the fail-safe is armed must fail"
    );
    assert!(
        !device_b
            .store
            .contains_key(FABRIC_KEYS_START + fab_idx.get() as u16),
        "nothing is persisted before CommissioningComplete"
    );

    // ---- Phase 2 against B ----

    info!("=== Phase 2: complete_via_case() against device B ===");
    let mdns_table = [(result.device_node_id, sock_of(DEVICE_B_PORT))];
    let mdns = stub_mdns_resolver_txt(matter, &mdns_table, "");

    match select(pin!(commissioner.complete_via_case(&result)), pin!(mdns)).await {
        Either::First(r) => r?,
        Either::Second(_) => unreachable!("the stub resolver never returns"),
    }

    assert!(
        device_b
            .store
            .contains_key(FABRIC_KEYS_START + fab_idx.get() as u16),
        "CommissioningComplete should have persisted the fabric on B"
    );

    // ---- OnOff over CASE against B ----

    info!("=== Phase 3: OnOff over CASE against device B ===");
    let initial =
        read_onoff_with_timeout(matter, controller_fab_idx, result.device_node_id).await?;
    assert!(!initial);

    invoke_toggle_with_timeout(matter, controller_fab_idx, result.device_node_id).await?;

    let toggled =
        read_onoff_with_timeout(matter, controller_fab_idx, result.device_node_id).await?;
    assert!(toggled, "OnOff should have toggled on B");

    info!("=== Handover test completed successfully ===");

    Ok(())
}

async fn read_onoff_with_timeout(
    matter: &Matter<'_>,
    fab_idx: NonZeroU8,
    peer_node_id: u64,
) -> Result<bool, Error> {
    use rs_matter::dm::clusters::app::on_off::OnOffClient;

    let exchange = Exchange::initiate(matter, test_only_crypto(), fab_idx, peer_node_id).await?;

    let mut read_fut = pin!(exchange.on_off().on_off_read(1));
    let mut timeout = pin!(Timer::after(Duration::from_secs(IM_TIMEOUT_SECS)));

    match select(&mut read_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => panic!("Read operation timed out"),
    }
}

async fn invoke_toggle_with_timeout(
    matter: &Matter<'_>,
    fab_idx: NonZeroU8,
    peer_node_id: u64,
) -> Result<(), Error> {
    use rs_matter::dm::clusters::app::on_off::OnOffClient;

    let exchange = Exchange::initiate(matter, test_only_crypto(), fab_idx, peer_node_id).await?;

    let mut invoke_fut = pin!(exchange.on_off().toggle(1));
    let mut timeout = pin!(Timer::after(Duration::from_secs(IM_TIMEOUT_SECS)));

    match select(&mut invoke_fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => panic!("Invoke operation timed out"),
    }
}

/// A dual-stack UDP socket bound to `port` (`0` = ephemeral).
fn bind_udp(port: u16) -> Result<async_io::Async<UdpSocket>, Error> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_reuse_address(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_only_v6(false)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    let bind_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, port, 0, 0);
    socket
        .bind(&bind_addr.into())
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    let socket: UdpSocket = socket.into();
    async_io::Async::new_nonblocking(socket)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface.into())
}

/// The host's non-loopback IPv4 address.
fn find_ipv4() -> Result<std::net::Ipv4Addr, Error> {
    use nix::net::if_::InterfaceFlags;

    let (iname, ip) = nix::ifaddrs::getifaddrs()
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
                .map(|ip: std::net::Ipv4Addr| (ia.interface_name.clone(), ip))
        })
        .ok_or(rs_matter::error::ErrorCode::NoNetworkInterface)?;

    info!("Using network interface {iname} with {ip}");

    Ok(ip)
}
