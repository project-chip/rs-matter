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

//! Fail-safe expiry tests over loopback UDP with the real `Commissioner`.
//!
//! Phase 1 of commissioning (PASE, `ArmFailSafe` with a short expiry, ...,
//! `AddNOC`) is driven against an in-process device and then deliberately
//! left incomplete: `CommissioningComplete` is never sent.
//!
//! What the tests prove:
//! - once the fail-safe timer expires, the device rolls back: the pending
//!   fabric is gone, nothing was ever persisted to the device's store, and
//!   the PASE session the commissioning ran over is closed (a further read
//!   on it fails);
//! - re-arming the fail-safe over a CASE session before it expires restarts
//!   the timer: the fabric survives the original deadline and is only rolled
//!   back once the new deadline passes.

#![cfg(all(feature = "std", feature = "async-io", target_os = "linux"))]

use core::cell::Cell;
use core::future::Future;
use core::pin::pin;
use std::net::UdpSocket;

use embassy_futures::select::{select, select3, Either};
use embassy_time::{Duration, Instant, Timer};

use log::info;

use rand_core::Rng;

use rs_matter::cert::gen::VALID_FOREVER;
use rs_matter::cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN};
use rs_matter::crypto::{
    test_only_crypto, CanonAeadKey, CanonPkcSecretKey, Crypto, SecretKey, SigningSecretKey,
};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{
    self, test::TestOnOffDeviceLogic, OnOffClient, OnOffHooks,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::gen_comm::{CommissioningErrorEnum, GeneralCommissioningClient};
use rs_matter::dm::clusters::net_comm::DummyNetworks;
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::{endpoints, Async, DataModel, Dataver, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::im::subscriptions::DEFAULT_MAX_SUBSCRIPTIONS;
use rs_matter::im::{InteractionModel, InteractionModelState};
use rs_matter::onboard::cac::{IcacGenerator, RcacGenerator};
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::onboard::{CommissionOptions, Commissioner};
use rs_matter::persist::FABRIC_KEYS_START;
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::{Exchange, MatterBuffers};
use rs_matter::transport::network::{Address, NetworkSend, NoNetwork, SocketAddr, SocketAddrV6};
use rs_matter::utils::select::Coalesce;
use rs_matter::{clusters, devices, root_endpoint, Matter};

use crate::common::mdns::stub_mdns_resolver_txt;
use crate::common::{
    create_localhost_socket_pair, init_env_logger, run_device_controller, run_with_transport,
    MemKvBlobStore,
};

#[allow(dead_code)]
mod common;

/// Passcode used by `TEST_DEV_COMM`
const TEST_PASSCODE: u32 = 20202021;

const FABRIC_ID: u64 = 1;
const CONTROLLER_NODE_ID: u64 = 112233;
const DEVICE_NODE_ID: u64 = 112234;
const ADMIN_VENDOR_ID: u16 = 0xFFF1;

/// `ExpiryLengthSeconds` the commissioner arms the fail-safe with.
const FAILSAFE_SECS: u16 = 3;
/// `ExpiryLengthSeconds` of the re-arm over CASE.
const REARM_SECS: u16 = 6;
/// How long the device may take to notice an expired fail-safe: its
/// Interaction Model polls the timer once a second.
const CHECK_LAG_SECS: u64 = 1;

const COMMISSION_TIMEOUT_SECS: u64 = 30;
const IM_TIMEOUT_SECS: u64 = 15;
const ROLLBACK_TIMEOUT_SECS: u64 = 20;

type DeviceDmState = InteractionModelState<DummyNetworks, DEFAULT_MAX_SUBSCRIPTIONS, 0>;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    /// Let the fail-safe expire.
    Expire,
    /// Re-arm the fail-safe over CASE before it expires, then let it expire.
    RearmViaCase,
}

/// A UDP sender which counts the packets the device puts on the wire.
struct CountingSend<'a> {
    socket: &'a async_io::Async<UdpSocket>,
    sent: &'a Cell<u32>,
}

impl NetworkSend for CountingSend<'_> {
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        self.sent.set(self.sent.get() + 1);

        let mut socket = self.socket;
        NetworkSend::send_to(&mut socket, data, addr).await
    }
}

/// The device as seen by the controller flow.
struct Device<'a> {
    matter: &'a Matter<'a>,
    store: &'a MemKvBlobStore,
    addr: SocketAddrV6,
    sent: &'a Cell<u32>,
}

/// A fail-safe armed for `FAILSAFE_SECS` and never completed is rolled
/// back once it expires.
#[test]
fn test_failsafe_expiry_rolls_back_pending_fabric() {
    run(Scenario::Expire);
}

/// Re-arming the fail-safe over CASE restarts its timer.
#[test]
fn test_failsafe_rearm_via_case_restarts_timer() {
    run(Scenario::RearmViaCase);
}

fn run(scenario: Scenario) {
    // A device plus a controller in one future need more than the default
    // 2 MiB stack.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            init_env_logger();
            futures_lite::future::block_on(async {
                run_scenario(scenario).await.unwrap();
            });
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn run_scenario(scenario: Scenario) -> Result<(), Error> {
    let crypto = test_only_crypto();

    // ---- Device ----

    let device_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
    let mut rand = crypto.rand()?;
    let buffers: MatterBuffers = MatterBuffers::new();
    let state: DeviceDmState = InteractionModelState::new(DummyNetworks);
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(false),
    );
    let store = MemKvBlobStore::default();
    let kv = device_matter.kv(store.clone());
    let dm = InteractionModel::new(
        &device_matter,
        &crypto,
        &buffers,
        data_model(rand, &on_off_handler),
        &kv,
        &state,
    );

    device_matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;

    let responder = DefaultResponder::new(&dm);

    let (device_socket, ctrl_socket) = create_localhost_socket_pair();
    let SocketAddr::V6(device_addr) = device_socket.get_ref().local_addr()? else {
        panic!("expected an IPv6 device socket");
    };

    let device_sent = Cell::new(0);

    let device_fut = async {
        select3(
            device_matter.run(
                &crypto,
                CountingSend {
                    socket: &device_socket,
                    sent: &device_sent,
                },
                &device_socket,
                NoNetwork,
            ),
            responder.run::<4, 4>(),
            dm.run(),
        )
        .coalesce()
        .await
    };

    // ---- Controller ----

    let ctrl_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);

    let ctrl_fut = run_with_transport(
        ctrl_matter.run(&crypto, &ctrl_socket, &ctrl_socket, NoNetwork),
        controller_flow(
            &ctrl_matter,
            &crypto,
            scenario,
            Device {
                matter: &device_matter,
                store: &store,
                addr: device_addr,
                sent: &device_sent,
            },
        ),
    );

    run_device_controller(device_fut, ctrl_fut).await
}

async fn controller_flow<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    scenario: Scenario,
    device: Device<'_>,
) -> Result<(), Error> {
    let peer_addr = Address::Udp(SocketAddr::V6(device.addr));

    // ---- Controller fabric: RCAC + ICAC chain, operational keypair, IPK ----

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
        fail_safe_secs: FAILSAFE_SECS,
        allow_test_attestation: true,
    };

    // ---- Phase 1: PASE, ArmFailSafe(FAILSAFE_SECS), ..., AddNOC ----

    info!("=== Phase 1: commission() with a {FAILSAFE_SECS}s fail-safe ===");

    // The fail-safe is armed at some point after this instant, so its
    // deadline is no earlier than `armed_after + FAILSAFE_SECS`.
    let armed_after = Instant::now();

    let result = with_timeout(
        commissioner.commission(
            peer_addr,
            TEST_PASSCODE,
            &opts,
            DEVICE_NODE_ID,
            VALID_FOREVER,
        ),
        COMMISSION_TIMEOUT_SECS,
        "commission()",
    )
    .await?;

    let fabric_key = FABRIC_KEYS_START + result.fabric_index.get() as u16;

    assert!(
        device.matter.has_fabrics(),
        "the device should hold the pending fabric"
    );
    assert!(
        !device.store.contains_key(fabric_key),
        "nothing is persisted before CommissioningComplete"
    );

    // The PASE session is alive: a read over it succeeds.
    let on = with_timeout(
        read_onoff_over_pase(matter, crypto, peer_addr),
        IM_TIMEOUT_SECS,
        "read over PASE",
    )
    .await?;
    assert!(!on);

    let rolled_back_after = match scenario {
        Scenario::Expire => armed_after,
        Scenario::RearmViaCase => {
            // ---- Re-arm over CASE ----

            info!("=== Re-arming the fail-safe over CASE for {REARM_SECS}s ===");

            let mdns_table = [(DEVICE_NODE_ID, device.addr)];
            let mdns = stub_mdns_resolver_txt(matter, &mdns_table, "");

            let exchange = with_timeout(
                async {
                    match select(
                        pin!(Exchange::initiate(
                            matter,
                            crypto,
                            controller_fab_idx,
                            DEVICE_NODE_ID
                        )),
                        pin!(mdns),
                    )
                    .await
                    {
                        Either::First(r) => r,
                        Either::Second(_) => unreachable!("the stub resolver never returns"),
                    }
                },
                IM_TIMEOUT_SECS,
                "CASE",
            )
            .await?;

            let rearmed_after = Instant::now();

            let handle = with_timeout(
                exchange
                    .general_commissioning()
                    .arm_fail_safe(ROOT_ENDPOINT_ID, |req| {
                        req.expiry_length_seconds(REARM_SECS)?.breadcrumb(0)?.end()
                    }),
                IM_TIMEOUT_SECS,
                "ArmFailSafe over CASE",
            )
            .await?;

            let code = handle.response()?.error_code()?;
            handle.complete().await?;
            assert_eq!(code, CommissioningErrorEnum::OK);

            // The original deadline (plus the device's polling lag) passes
            // without a rollback.
            Timer::at(armed_after + Duration::from_secs(FAILSAFE_SECS as u64 + CHECK_LAG_SECS + 1))
                .await;

            assert!(
                device.matter.has_fabrics(),
                "the re-armed fail-safe should have kept the fabric past the original deadline"
            );
            assert!(!device.store.contains_key(fabric_key));

            rearmed_after
        }
    };

    // ---- Expiry ----

    let expiry_secs = match scenario {
        Scenario::Expire => FAILSAFE_SECS,
        Scenario::RearmViaCase => REARM_SECS,
    } as u64;

    info!("=== Waiting for the fail-safe to expire ===");

    let rolled_back_at = wait_for_rollback(device.matter).await;
    let elapsed = rolled_back_at - rolled_back_after;

    info!("Fabric rolled back {}ms after arming", elapsed.as_millis());

    assert!(
        elapsed >= Duration::from_secs(expiry_secs),
        "the fail-safe expired early: {}ms",
        elapsed.as_millis()
    );
    assert!(
        elapsed <= Duration::from_secs(expiry_secs + CHECK_LAG_SECS + IM_TIMEOUT_SECS),
        "the fail-safe expired late: {}ms",
        elapsed.as_millis()
    );

    assert!(
        !device.store.contains_key(fabric_key),
        "the rolled-back fabric must not have been persisted"
    );

    // The PASE session the commissioning ran over is gone: the controller
    // still believes it is alive, but a read over it now fails.
    let sent_before = device.sent.get();

    let mut read = pin!(read_onoff_over_pase(matter, crypto, peer_addr));
    let mut timeout = pin!(Timer::after(Duration::from_secs(IM_TIMEOUT_SECS)));

    match select(&mut read, &mut timeout).await {
        Either::First(Ok(_)) => panic!("a read over the closed PASE session succeeded"),
        Either::First(Err(e)) => info!("Read over the closed PASE session failed: {e:?}"),
        Either::Second(_) => panic!("the read over the closed PASE session hung"),
    }

    info!(
        "The device sent {} packets while the stale-session read was failing",
        device.sent.get() - sent_before
    );

    Ok(())
}

/// Poll the device until its pending fabric is gone, returning when that
/// happened. Panics if it does not happen within `ROLLBACK_TIMEOUT_SECS`.
async fn wait_for_rollback(device: &Matter<'_>) -> Instant {
    let deadline = Instant::now() + Duration::from_secs(ROLLBACK_TIMEOUT_SECS);

    while device.has_fabrics() {
        assert!(
            Instant::now() < deadline,
            "the fail-safe did not expire within {ROLLBACK_TIMEOUT_SECS}s"
        );

        Timer::after(Duration::from_millis(100)).await;
    }

    Instant::now()
}

/// Read `OnOff` on endpoint 1 over the PASE session to `peer_addr`.
async fn read_onoff_over_pase<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: Address,
) -> Result<bool, Error> {
    let exchange = Exchange::initiate_pase(matter, crypto, peer_addr, TEST_PASSCODE).await?;

    exchange.on_off().on_off_read(1).await
}

async fn with_timeout<T, F>(fut: F, secs: u64, what: &str) -> Result<T, Error>
where
    F: Future<Output = Result<T, Error>>,
{
    let mut fut = pin!(fut);
    let mut timeout = pin!(Timer::after(Duration::from_secs(secs)));

    match select(&mut fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => panic!("{what} timed out after {secs}s"),
    }
}
