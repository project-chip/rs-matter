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

//! Message Reliability Protocol (MRP) tests over an in-memory, deliberately
//! unreliable link.
//!
//! Two `Matter` instances (a device running the e2e Interaction Model handler
//! and a client) are connected over two zero-copy channels, exactly like the
//! `E2eRunner`, except that the sending side of each channel is wrapped in a
//! `LossySend` that can drop or duplicate packets according to a policy and
//! keeps statistics about what the transport asked it to send.
//!
//! What the tests prove:
//! - a read, a write, an invoke and a subscribe all complete when every third
//!   packet is lost in both directions, and the loss is recovered through
//!   retransmissions (visible in the link statistics);
//! - when every packet is delivered twice, the duplicates are absorbed by the
//!   message-counter window: the device processes (and answers) each request
//!   exactly once, and the client sees exactly one response per request;
//! - a reliable message which the peer receives but never answers is still
//!   acknowledged with a standalone ack, so the sender stops retransmitting
//!   without ever receiving an application message;
//! - a reliable message that is never delivered fails at the sender with
//!   `TxTimeout` after the maximum number of transmissions, instead of hanging.
//!
//! Both nodes advertise a small session active interval so that
//! retransmissions happen within tens of milliseconds.

#![cfg(all(feature = "std", feature = "async-io"))]

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use core::num::NonZeroU8;
use core::pin::pin;

use embassy_futures::select::{select, select3, Either, Either3};
use embassy_sync::zerocopy_channel::{Channel, Receiver, Sender};
use embassy_time::{Duration, Timer};

use log::info;

use rs_matter::acl::{AclEntry, AuthMode};
use rs_matter::crypto::{test_only_crypto, CanonAeadKey, Crypto};
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic};
use rs_matter::dm::clusters::basic_info::BasicInfoConfig;
use rs_matter::dm::clusters::net_comm::DummyNetworks;
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::{Dataver, Privilege};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::im::{
    AttrPath, AttrStatus, GenericPath, IMStatusCode, InteractionModel, InteractionModelState,
    OpCode, StatusResp, SubscribeResp, PROTO_ID_INTERACTION_MODEL,
};
use rs_matter::persist::DummyKvBlobStore;
use rs_matter::respond::{ExchangeHandler, Responder};
use rs_matter::sc::{OpCode as ScOpCode, PROTO_ID_SECURE_CHANNEL};
use rs_matter::transport::exchange::{Exchange, MatterBuffers, MessageMeta};
use rs_matter::transport::network::{
    Address, NetworkReceive, NetworkSend, NoNetwork, MAX_RX_PACKET_SIZE, MAX_TX_PACKET_SIZE,
};
use rs_matter::transport::packet::PacketHdr;
use rs_matter::transport::session::{NocCatIds, ReservedSession, SessionMode};
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::ParseBuf;
use rs_matter::utils::sync::blocking::raw::MatterRawMutex;
use rs_matter::{Matter, MATTER_PORT};

use crate::common::e2e::im::attributes::TestAttrData;
use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::im::handler::E2eTestHandler;
use crate::common::e2e::im::{ReplyProcessor, TestReportDataMsg, TestSubscribeReq};
use crate::common::e2e::test::E2eTest;
use crate::common::e2e::tlv::TLVTest;
use crate::common::init_env_logger;

#[allow(dead_code)]
mod common;

/// Node ID of the device under test.
const DEVICE_NODE_ID: u64 = 123456;
/// Node ID of the client driving the tests.
const CLIENT_NODE_ID: u64 = 445566;

/// Session active interval advertised by both nodes, in milliseconds.
///
/// Drives the MRP retransmission back-off, so the tests recover from
/// packet loss in tens of milliseconds rather than seconds.
const FAST_SAI_MS: u32 = 50;

/// Upper bound for a whole test scenario.
const SCENARIO_TIMEOUT_SECS: u64 = 60;

/// Fake peer address recorded in the pre-installed sessions.
const SESSION_ADDR: Address =
    Address::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));

/// `TEST_DEV_DET` with fast MRP intervals.
const FAST_MRP_DEV_DET: BasicInfoConfig = BasicInfoConfig {
    sai: Some(FAST_SAI_MS),
    sii: Some(FAST_SAI_MS),
    ..TEST_DEV_DET
};

/// How a `LossySend` treats the packets the transport hands it.
#[derive(Debug, Clone, Copy)]
enum LossMode {
    /// Deliver everything.
    Reliable,
    /// Drop every `n`-th packet (the `n`-th, `2n`-th, ...).
    DropEveryNth(u32),
    /// Deliver every packet twice.
    DuplicateAll,
    /// Deliver nothing.
    DropAll,
}

/// What the transport asked one direction of the link to send.
struct LinkStats {
    /// Node ID of the node sending over this direction of the link; needed
    /// to decrypt the packet headers.
    sender_nodeid: u64,
    /// The loss policy currently applied to this direction of the link.
    mode: Cell<LossMode>,
    /// Packets handed to the link by the transport.
    offered: Cell<u32>,
    /// Packets actually pushed into the pipe, duplicates included.
    delivered: Cell<u32>,
    /// Packets the policy dropped.
    dropped: Cell<u32>,
    /// Offered packets whose message counter was seen before, i.e. MRP
    /// retransmissions.
    retransmissions: Cell<u32>,
    /// Offered packets which are MRP standalone acks.
    standalone_acks: Cell<u32>,
    /// Offered packets carrying an Interaction Model message.
    im_messages: Cell<u32>,
    /// Message counters seen so far.
    seen_ctrs: RefCell<Vec<u32>>,
}

impl LinkStats {
    fn new(sender_nodeid: u64) -> Self {
        Self {
            sender_nodeid,
            mode: Cell::new(LossMode::Reliable),
            offered: Cell::new(0),
            delivered: Cell::new(0),
            dropped: Cell::new(0),
            retransmissions: Cell::new(0),
            standalone_acks: Cell::new(0),
            im_messages: Cell::new(0),
            seen_ctrs: RefCell::new(Vec::new()),
        }
    }

    fn record(&self, data: &[u8]) {
        self.offered.set(self.offered.get() + 1);

        let Some((ctr, proto_id, opcode)) = decode_hdr(data, self.sender_nodeid) else {
            panic!("Undecodable packet on the link");
        };

        let mut seen = self.seen_ctrs.borrow_mut();
        if seen.contains(&ctr) {
            self.retransmissions.set(self.retransmissions.get() + 1);
        } else {
            seen.push(ctr);
        }

        if proto_id == PROTO_ID_SECURE_CHANNEL && opcode == ScOpCode::MRPStandAloneAck as u8 {
            self.standalone_acks.set(self.standalone_acks.get() + 1);
        }

        if proto_id == PROTO_ID_INTERACTION_MODEL {
            self.im_messages.set(self.im_messages.get() + 1);
        }
    }

    /// Number of distinct message counters that were offered.
    fn unique(&self) -> u32 {
        self.seen_ctrs.borrow().len() as u32
    }

    /// Zero the packet counters, keeping the message counters seen so far so
    /// that retransmissions of earlier packets are still recognised.
    fn reset_counts(&self) {
        self.offered.set(0);
        self.delivered.set(0);
        self.dropped.set(0);
        self.retransmissions.set(0);
        self.standalone_acks.set(0);
        self.im_messages.set(0);
    }
}

/// Decode the plain and protocol headers of a packet sent by `sender_nodeid`
/// over the test link: `(message counter, protocol ID, protocol opcode)`.
///
/// The pre-installed sessions carry no key material, so the packets are
/// encrypted with an all-zero key.
fn decode_hdr(data: &[u8], sender_nodeid: u64) -> Option<(u32, u16, u8)> {
    let mut data = data.to_vec();
    let mut pb = ParseBuf::new(data.as_mut_slice());
    let mut hdr = PacketHdr::new();

    let key = CanonAeadKey::new();

    hdr.decode_plain_hdr(&mut pb).ok()?;
    hdr.decode_remaining(
        test_only_crypto(),
        Some(key.reference()),
        sender_nodeid,
        &mut pb,
    )
    .ok()?;

    Some((hdr.plain.ctr, hdr.proto.proto_id, hdr.proto.proto_opcode))
}

type Pipe<'a, const N: usize> = Channel<'a, MatterRawMutex, heapless::Vec<u8, N>>;

/// The sending half of a pipe, with a loss policy in front of it.
struct LossySend<'a, const N: usize> {
    pipe: Sender<'a, MatterRawMutex, heapless::Vec<u8, N>>,
    stats: &'a LinkStats,
}

impl<const N: usize> LossySend<'_, N> {
    async fn deliver(&mut self, data: &[u8]) {
        let vec = self.pipe.send().await;

        vec.clear();
        vec.extend_from_slice(data).unwrap();

        self.pipe.send_done();

        self.stats.delivered.set(self.stats.delivered.get() + 1);
    }
}

impl<const N: usize> NetworkSend for LossySend<'_, N> {
    async fn send_to(&mut self, data: &[u8], _addr: Address) -> Result<(), Error> {
        self.stats.record(data);

        let mode = self.stats.mode.get();

        let drop = match mode {
            LossMode::Reliable | LossMode::DuplicateAll => false,
            LossMode::DropEveryNth(n) => self.stats.offered.get().is_multiple_of(n),
            LossMode::DropAll => true,
        };

        if drop {
            self.stats.dropped.set(self.stats.dropped.get() + 1);
            return Ok(());
        }

        self.deliver(data).await;

        if matches!(mode, LossMode::DuplicateAll) {
            self.deliver(data).await;
        }

        Ok(())
    }
}

/// The receiving half of a pipe.
struct PipeRecv<'a, const N: usize>(Receiver<'a, MatterRawMutex, heapless::Vec<u8, N>>);

impl<const N: usize> NetworkReceive for PipeRecv<'_, N> {
    async fn wait_available(&mut self) -> Result<(), Error> {
        self.0.receive().await;

        Ok(())
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        let vec = self.0.receive().await;

        buffer[..vec.len()].copy_from_slice(vec);
        let len = vec.len();

        self.0.receive_done();

        Ok((len, SESSION_ADDR))
    }
}

/// A `Matter` instance with a single fabric.
fn new_matter() -> Matter<'static> {
    let matter = Matter::new(&FAST_MRP_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    matter.with_state(|state| {
        state.fabrics.add_with_post_init(|_| Ok(())).unwrap();
    });

    matter
}

/// Pre-install a keyless CASE-shaped session towards `remote_nodeid`.
fn install_session(matter: &Matter<'_>, local_nodeid: u64, remote_nodeid: u64) {
    matter.reset_transport().unwrap();

    let mut session = ReservedSession::reserve_now(matter, test_only_crypto()).unwrap();

    session
        .update(
            local_nodeid,
            remote_nodeid,
            1,
            1,
            SESSION_ADDR,
            SessionMode::Case {
                fab_idx: NonZeroU8::new(1).unwrap(),
                cat_ids: NocCatIds::default(),
            },
            None,
            None,
            None,
            None,
        )
        .unwrap();

    session.complete();
}

/// Grant the client admin rights on the device.
fn add_admin_acl(matter: &Matter<'_>) {
    let mut acl = AclEntry::new(None, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(CLIENT_NODE_ID).unwrap();

    matter.with_state(|state| {
        state
            .fabrics
            .fabric_mut(NonZeroU8::new(1).unwrap())
            .unwrap()
            .acl_add(acl)
            .unwrap();
    });
}

/// Run both transports over the lossy link together with the device-side
/// `responder` future, until `client` completes.
///
/// Panics if a transport or the responder exits first, or if the scenario
/// does not complete within `SCENARIO_TIMEOUT_SECS`.
async fn run_link<R, F, T>(
    device: &Matter<'_>,
    client: &Matter<'_>,
    device_link: (LossMode, &LinkStats),
    client_link: (LossMode, &LinkStats),
    responder: R,
    client_flow: F,
) -> Result<T, Error>
where
    R: Future<Output = Result<(), Error>>,
    F: Future<Output = Result<T, Error>>,
{
    let crypto = test_only_crypto();

    device_link.1.mode.set(device_link.0);
    client_link.1.mode.set(client_link.0);

    let mut to_client_buf = [heapless::Vec::new(); 1];
    let mut to_device_buf = [heapless::Vec::new(); 1];

    let mut to_client = Pipe::<MAX_RX_PACKET_SIZE>::new(&mut to_client_buf);
    let mut to_device = Pipe::<MAX_TX_PACKET_SIZE>::new(&mut to_device_buf);

    let (device_send, client_recv) = to_client.split();
    let (client_send, device_recv) = to_device.split();

    let mut transports = pin!(select3(
        device.run(
            &crypto,
            LossySend {
                pipe: device_send,
                stats: device_link.1,
            },
            PipeRecv(device_recv),
            NoNetwork,
        ),
        client.run(
            &crypto,
            LossySend {
                pipe: client_send,
                stats: client_link.1,
            },
            PipeRecv(client_recv),
            NoNetwork,
        ),
        responder,
    )
    .coalesce());

    let mut client_flow = pin!(client_flow);
    let mut timeout = pin!(Timer::after(Duration::from_secs(SCENARIO_TIMEOUT_SECS)));

    match select3(&mut transports, &mut client_flow, &mut timeout).await {
        Either3::First(result) => panic!("Transport or responder exited prematurely: {result:?}"),
        Either3::Second(result) => result,
        Either3::Third(_) => panic!("Scenario timed out after {SCENARIO_TIMEOUT_SECS}s"),
    }
}

/// Open an exchange on the client's pre-installed session to the device.
async fn initiate_exchange<'a>(client: &'a Matter<'a>) -> Result<Exchange<'a>, Error> {
    Exchange::initiate(
        client,
        test_only_crypto(),
        NonZeroU8::new(1).unwrap(),
        DEVICE_NODE_ID,
    )
    .await
}

/// Send the test's input over `exchange` and validate the reply.
async fn run_im_test<T: E2eTest>(exchange: &mut Exchange<'_>, test: &T) -> Result<(), Error> {
    exchange
        .send_with(|_, wb| {
            let meta = test.fill_input(wb)?;

            Ok(Some(meta))
        })
        .await?;

    let rx = exchange.recv().await?;
    test.validate_result(rx.meta(), rx.payload())?;

    Ok(())
}

/// Number of Interaction Model requests `im_interactions` sends
/// (and the number of responses it expects).
const IM_INTERACTIONS: u32 = 5;

/// A read, a write, an invoke and a subscribe (which is a request plus
/// a status response), all on one exchange.
/// Read `Att1` of the echo cluster on endpoint 0 over `exchange` and check
/// the reported value.
async fn read_att1(exchange: &mut Exchange<'_>) -> Result<(), Error> {
    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );
    let read_input = [AttrPath::from_gp(&ep0_att1)];
    let read_expected = [attr_data_path!(ep0_att1, Some(&0x1234u16))];

    run_im_test(exchange, &TLVTest::read_attrs(&read_input, &read_expected)).await?;
    exchange.acknowledge().await
}

/// One lossless request/response before the loss policy is switched on.
///
/// The first message a session receives seeds its replay window with every
/// counter below it marked as already seen. The device stamps a response
/// with its counter when the response is encoded, but a standalone ack for
/// a duplicate of the request can be encoded later and still leave first;
/// on a window seeded by that ack the response would then be discarded as a
/// duplicate. A completed exchange leaves the window with real history, so
/// out-of-order counters are judged by the window bits from then on.
async fn warm_up(client: &Matter<'_>) -> Result<(), Error> {
    let mut exchange = initiate_exchange(client).await?;

    info!("=== Warm-up read ===");
    read_att1(&mut exchange).await
}

/// Run one Interaction Model transaction of each kind against the device.
///
/// Every transaction opens an exchange of its own, as Matter clients do: the
/// responder side of an exchange lingers until the ack of its last message
/// arrives, and if that ack is lost, a follow-up request reusing the exchange
/// ID would reach the device as a piggybacked ack for the old exchange rather
/// than as a new request.
async fn im_interactions(client: &Matter<'_>) -> Result<(), Error> {
    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );
    let read_input = [AttrPath::from_gp(&ep0_att1)];
    let read_expected = [attr_data_path!(ep0_att1, Some(&0x1234u16))];

    info!("=== Read ===");
    let mut exchange = initiate_exchange(client).await?;
    read_att1(&mut exchange).await?;

    // Write
    let ep0_att_write = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let write_value = 10u16;
    let write_input = [TestAttrData::new(
        None,
        AttrPath::from_gp(&ep0_att_write),
        &write_value as _,
    )];
    let write_expected = [AttrStatus::from_gp(
        &ep0_att_write,
        IMStatusCode::Success,
        None,
    )];

    info!("=== Write ===");
    let mut exchange = initiate_exchange(client).await?;
    run_im_test(
        &mut exchange,
        &TLVTest::write_attrs(&write_input, &write_expected),
    )
    .await?;
    exchange.acknowledge().await?;

    // Invoke
    let invoke_input = [echo_req!(0, 5).with_command_ref(0)];
    let invoke_expected = [echo_resp!(0, 10).with_command_ref(0)];

    info!("=== Invoke ===");
    let mut exchange = initiate_exchange(client).await?;
    run_im_test(
        &mut exchange,
        &TLVTest::inv_cmds(&invoke_input, &invoke_expected),
    )
    .await?;
    exchange.acknowledge().await?;

    // Subscribe: the primed report, then the status response that
    // completes the subscription.
    info!("=== Subscribe ===");
    let mut exchange = initiate_exchange(client).await?;
    run_im_test(
        &mut exchange,
        &TLVTest::subscribe(
            TestSubscribeReq {
                min_int_floor: 0,
                max_int_ceil: 1,
                ..TestSubscribeReq::reqs(&read_input)
            },
            TestReportDataMsg {
                subscription_id: Some(1),
                attr_reports: Some(&read_expected),
                ..Default::default()
            },
            ReplyProcessor::remove_attr_dataver,
        ),
    )
    .await?;
    exchange.acknowledge().await?;

    run_im_test(
        &mut exchange,
        &TLVTest::subscribe_final(
            StatusResp::default(),
            SubscribeResp::new(1, 40),
            ReplyProcessor::none,
        ),
    )
    .await?;
    exchange.acknowledge().await?;

    Ok(())
}

/// Run `im_interactions` against the e2e Interaction Model handler over a
/// link with the given loss policies. Returns the per-direction link
/// statistics and the Interaction Model message counters of the device
/// and the client, as `(device, client)` pairs.
fn run_im_scenario(
    device_mode: LossMode,
    client_mode: LossMode,
) -> (
    (LinkStats, LinkStats),
    (
        rs_matter::transport::MessageCounters,
        rs_matter::transport::MessageCounters,
    ),
) {
    let device = new_matter();
    let client = new_matter();

    install_session(&device, DEVICE_NODE_ID, CLIENT_NODE_ID);
    install_session(&client, CLIENT_NODE_ID, DEVICE_NODE_ID);
    add_admin_acl(&device);

    let crypto = test_only_crypto();
    let buffers: MatterBuffers = MatterBuffers::new();
    let state = InteractionModelState::<DummyNetworks, 3, 0>::new(DummyNetworks);

    let mut rand = crypto.rand().unwrap();
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(false),
    );
    let handler = E2eTestHandler::new(rand, on_off_handler);

    let kv = device.kv(DummyKvBlobStore);
    let dm = InteractionModel::new(&device, &crypto, &buffers, &handler, &kv, &state);
    let responder = Responder::new_default(&dm);

    let device_stats = LinkStats::new(DEVICE_NODE_ID);
    let client_stats = LinkStats::new(CLIENT_NODE_ID);

    let (device_before, client_before) = futures_lite::future::block_on(run_link(
        &device,
        &client,
        (LossMode::Reliable, &device_stats),
        (LossMode::Reliable, &client_stats),
        async { select(responder.run::<4>(), dm.run()).coalesce().await },
        async {
            warm_up(&client).await?;

            device_stats.reset_counts();
            client_stats.reset_counts();
            device_stats.mode.set(device_mode);
            client_stats.mode.set(client_mode);

            let before = (device.transport().counters(), client.transport().counters());

            im_interactions(&client).await?;

            // Let packets still in the pipe (a duplicate, a standalone ack)
            // reach the other side before the link is torn down.
            Timer::after(Duration::from_millis(300)).await;

            Ok(before)
        },
    ))
    .unwrap();

    let device_after = device.transport().counters();
    let client_after = client.transport().counters();

    let delta = |before: rs_matter::transport::MessageCounters,
                 after: rs_matter::transport::MessageCounters| {
        rs_matter::transport::MessageCounters {
            im_sent: after.im_sent - before.im_sent,
            im_received: after.im_received - before.im_received,
        }
    };

    (
        (device_stats, client_stats),
        (
            delta(device_before, device_after),
            delta(client_before, client_after),
        ),
    )
}

fn spawn_with_large_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

/// How long to let any Status Report ping-pong run before counting packets.
const LOOP_SETTLE_SECS: u64 = 3;

/// Packet budget for the scenario below. The legitimate traffic is one read
/// plus its MRP retransmissions and the device's answers - a couple of dozen
/// at most. A ping-pong loop runs at pipe speed and blows through this by
/// orders of magnitude within the settle window.
const LOOP_PACKET_BUDGET: u32 = 200;

/// A link half that only counts packets.
///
/// Unlike [`LossySend`] it does not decode headers: the scenario below
/// deliberately produces *unsecured* packets, which carry no session to decode
/// against, and a raw count is all the assertion needs.
struct CountingSend<'a, const N: usize> {
    pipe: Sender<'a, MatterRawMutex, heapless::Vec<u8, N>>,
    count: &'a Cell<u32>,
}

impl<const N: usize> NetworkSend for CountingSend<'_, N> {
    async fn send_to(&mut self, data: &[u8], _addr: Address) -> Result<(), Error> {
        self.count.set(self.count.get() + 1);

        let vec = self.pipe.send().await;
        vec.clear();
        vec.extend_from_slice(data).unwrap();
        self.pipe.send_done();

        Ok(())
    }
}

/// Two nodes where only one still believes a session exists.
///
/// The node that cannot match an incoming message answers with an unsecured
/// `SessionNotFound` Status Report. That answer is itself an unsecured Status
/// Report on no session - so if the peer also has nothing to match it against,
/// it answers the answer, and the two trade identical reports forever at line
/// rate. Nothing in the loop establishes a session, so it neither converges nor
/// decays; observed in the field at ~430 packets/s until a node was killed.
///
/// A Status Report must therefore never be answered with a Status Report: an
/// unmatched one is dropped, and traffic dies once MRP retries are spent.
#[test]
fn status_report_to_a_sessionless_peer_does_not_loop() {
    init_env_logger();

    spawn_with_large_stack(|| {
        let device = new_matter();
        let client = new_matter();

        // Only the client believes the session exists. The device's table is
        // empty - as after a reboot, a `RemoveFabric`, or a controller dropping
        // a device it could no longer reach.
        install_session(&client, CLIENT_NODE_ID, DEVICE_NODE_ID);

        let device_count = Cell::new(0u32);
        let client_count = Cell::new(0u32);

        let mut to_client_buf = [heapless::Vec::new(); 1];
        let mut to_device_buf = [heapless::Vec::new(); 1];

        let mut to_client = Pipe::<MAX_RX_PACKET_SIZE>::new(&mut to_client_buf);
        let mut to_device = Pipe::<MAX_TX_PACKET_SIZE>::new(&mut to_device_buf);

        let (device_send, client_recv) = to_client.split();
        let (client_send, device_recv) = to_device.split();

        let crypto = test_only_crypto();

        futures_lite::future::block_on(async {
            let mut transports = pin!(select(
                device.run(
                    &crypto,
                    CountingSend {
                        pipe: device_send,
                        count: &device_count,
                    },
                    PipeRecv(device_recv),
                    NoNetwork,
                ),
                client.run(
                    &crypto,
                    CountingSend {
                        pipe: client_send,
                        count: &client_count,
                    },
                    PipeRecv(client_recv),
                    NoNetwork,
                ),
            )
            .coalesce());

            let mut flow = pin!(async {
                // One message on the stale session is all it takes to start it.
                // The read itself is expected to fail - the device can decrypt
                // nothing - so only the traffic it provokes matters.
                if let Ok(mut exchange) = initiate_exchange(&client).await {
                    let _ = read_att1(&mut exchange).await;
                }

                // Let any loop run freely, then measure.
                Timer::after(Duration::from_secs(LOOP_SETTLE_SECS)).await;
            });

            match select(&mut transports, &mut flow).await {
                Either::First(r) => panic!("Transport exited prematurely: {r:?}"),
                Either::Second(()) => (),
            }
        });

        let total = device_count.get() + client_count.get();

        info!(
            "packets offered: device={} client={} total={}",
            device_count.get(),
            client_count.get(),
            total
        );

        assert!(
            total < LOOP_PACKET_BUDGET,
            "Status Report ping-pong: {total} packets in {LOOP_SETTLE_SECS}s \
             (budget {LOOP_PACKET_BUDGET}) - an unmatched Status Report is being \
             answered with another Status Report"
        );
    });
}

/// Every third packet is lost in both directions: all four interaction
/// types still complete, and the link statistics show that the loss was
/// recovered through retransmissions.
#[test]
fn test_drop_every_third_packet() {
    init_env_logger();

    spawn_with_large_stack(|| {
        let ((device, client), (device_ctrs, client_ctrs)) =
            run_im_scenario(LossMode::DropEveryNth(3), LossMode::DropEveryNth(3));

        info!(
            "Device link: offered={} dropped={} retrans={} acks={}; client link: offered={} dropped={} retrans={} acks={}",
            device.offered.get(),
            device.dropped.get(),
            device.retransmissions.get(),
            device.standalone_acks.get(),
            client.offered.get(),
            client.dropped.get(),
            client.retransmissions.get(),
            client.standalone_acks.get(),
        );

        assert!(
            device.dropped.get() >= 1,
            "no packet was dropped on the device side"
        );
        assert!(
            client.dropped.get() >= 1,
            "no packet was dropped on the client side"
        );
        assert!(
            device.retransmissions.get() + client.retransmissions.get() >= 1,
            "the loss should have been recovered through at least one retransmission"
        );

        // Every request was processed exactly once and answered exactly once,
        // no matter how many times it had to be sent.
        assert_eq!(device_ctrs.im_received, IM_INTERACTIONS);
        assert_eq!(device_ctrs.im_sent, IM_INTERACTIONS);
        assert_eq!(client_ctrs.im_received, IM_INTERACTIONS);
    });
}

/// Every packet is delivered twice in both directions: the duplicates are
/// absorbed by the message-counter window, so each request is processed
/// and answered exactly once, and the client sees exactly one response per
/// request.
#[test]
fn test_duplicate_every_packet() {
    init_env_logger();

    spawn_with_large_stack(|| {
        let ((device, client), (device_ctrs, client_ctrs)) =
            run_im_scenario(LossMode::DuplicateAll, LossMode::DuplicateAll);

        info!(
            "Device link: offered={} delivered={} unique={} im={}; client link: offered={} delivered={} unique={} im={}",
            device.offered.get(),
            device.delivered.get(),
            device.unique(),
            device.im_messages.get(),
            client.offered.get(),
            client.delivered.get(),
            client.unique(),
            client.im_messages.get(),
        );

        // The wrapper really did put every packet on the wire twice...
        assert_eq!(device.delivered.get(), 2 * device.offered.get());
        assert_eq!(client.delivered.get(), 2 * client.offered.get());
        assert!(client.im_messages.get() >= IM_INTERACTIONS);

        // ...yet the device processed each request once and answered it once...
        assert_eq!(device_ctrs.im_received, IM_INTERACTIONS);
        assert_eq!(device_ctrs.im_sent, IM_INTERACTIONS);

        // ...and the client received exactly one response per request.
        assert_eq!(client_ctrs.im_received, IM_INTERACTIONS);
    });
}

/// An exchange handler which reads the incoming message and then drops the
/// exchange without ever answering.
struct SilentHandler;

impl ExchangeHandler for SilentHandler {
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        exchange.recv().await?;

        Ok(())
    }
}

/// A reliable message with no application reply: the device transport
/// acknowledges it with a standalone ack. The client's send completes with
/// nothing pending, the only packet the device ever sent is that ack, and no
/// application message reaches the client.
#[test]
fn test_standalone_ack_for_unanswered_message() {
    init_env_logger();

    spawn_with_large_stack(|| {
        let device = new_matter();
        let client = new_matter();

        install_session(&device, DEVICE_NODE_ID, CLIENT_NODE_ID);
        install_session(&client, CLIENT_NODE_ID, DEVICE_NODE_ID);

        let responder = Responder::new("silent", SilentHandler, &device, 0);

        let device_stats = LinkStats::new(DEVICE_NODE_ID);
        let client_stats = LinkStats::new(CLIENT_NODE_ID);

        let client_before = client.transport().counters();

        futures_lite::future::block_on(run_link(
            &device,
            &client,
            (LossMode::Reliable, &device_stats),
            (LossMode::Reliable, &client_stats),
            responder.run::<4>(),
            async {
                let mut exchange = initiate_exchange(&client).await?;

                // `send` only completes once the peer acknowledged the message
                // (or the retransmissions ran out, which is an error).
                exchange
                    .send(
                        MessageMeta::new(
                            PROTO_ID_INTERACTION_MODEL,
                            OpCode::ReadRequest as u8,
                            true,
                        ),
                        &[0x15, 0x18], // An empty TLV structure
                    )
                    .await?;

                assert!(
                    !exchange.pending_retrans()?,
                    "the message must have been acknowledged"
                );

                // Nothing else arrives on the exchange.
                {
                    let mut recv = pin!(exchange.recv());
                    let mut timeout = pin!(Timer::after(Duration::from_millis(500)));

                    if let Either::First(rx) = select(&mut recv, &mut timeout).await {
                        panic!(
                            "Unexpected message on the exchange: {:?}",
                            rx.map(|rx| rx.meta())
                        );
                    }
                }

                Ok(())
            },
        ))
        .unwrap();

        let client_after = client.transport().counters();

        assert_eq!(
            device_stats.offered.get(),
            1,
            "the device should have sent exactly one packet"
        );
        assert_eq!(
            device_stats.standalone_acks.get(),
            1,
            "the device's only packet should be a standalone ack"
        );
        assert_eq!(
            client_stats.retransmissions.get(),
            0,
            "the ack should have arrived before the first retransmission"
        );
        assert_eq!(
            client_after.im_received - client_before.im_received,
            0,
            "no application message should have reached the client"
        );
    });
}

/// A reliable message that never reaches the peer fails at the sender with
/// `TxTimeout` once the maximum number of transmissions is exhausted.
#[test]
fn test_send_fails_after_max_transmissions() {
    init_env_logger();

    // The number of times the transport puts a reliable message on the wire
    // before giving up: the initial transmission plus the five retransmissions
    // of the MRP backoff ladder.
    const MAX_TRANSMISSIONS: u32 = 6;

    spawn_with_large_stack(|| {
        let device = new_matter();
        let client = new_matter();

        install_session(&device, DEVICE_NODE_ID, CLIENT_NODE_ID);
        install_session(&client, CLIENT_NODE_ID, DEVICE_NODE_ID);

        let responder = Responder::new("silent", SilentHandler, &device, 0);

        let device_stats = LinkStats::new(DEVICE_NODE_ID);
        let client_stats = LinkStats::new(CLIENT_NODE_ID);

        futures_lite::future::block_on(run_link(
            &device,
            &client,
            (LossMode::Reliable, &device_stats),
            (LossMode::DropAll, &client_stats),
            responder.run::<4>(),
            async {
                let mut exchange = initiate_exchange(&client).await?;

                let result = exchange
                    .send(
                        MessageMeta::new(
                            PROTO_ID_INTERACTION_MODEL,
                            OpCode::ReadRequest as u8,
                            true,
                        ),
                        &[0x15, 0x18], // An empty TLV structure
                    )
                    .await;

                let err = result.expect_err("sending into a black hole should fail");
                assert_eq!(err.code(), ErrorCode::TxTimeout);

                Ok(())
            },
        ))
        .unwrap();

        assert_eq!(client_stats.offered.get(), MAX_TRANSMISSIONS);
        assert_eq!(
            client_stats.unique(),
            1,
            "all transmissions carry the same message"
        );
        assert_eq!(client_stats.retransmissions.get(), MAX_TRANSMISSIONS - 1);
        assert_eq!(client_stats.dropped.get(), MAX_TRANSMISSIONS);
        assert_eq!(
            device_stats.offered.get(),
            0,
            "the device never saw the message, so it had nothing to send"
        );
    });
}
