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

//! The harness of the `node` and `clusters` targets, and of the generator of their seeds in
//! `fuzz/seedgen`, with the node of the `node` target. Each message of the input is sent to
//! the node, which then runs until it has nothing left to do.
//!
//! The node has a CASE session with an administrator and a PASE session, each with a fixed
//! key, and the harness encrypts the messages on them with those keys. It has a CASE
//! session over TCP with a second administrator, where it does not use MRP and allows
//! large messages, which some commands need. That administrator is another node, as the
//! node would send its own messages to the first one over TCP too. The node also has a
//! CASE session with the first administrator that it can resume.
//!
//! The clock of the node, in `../clock.rs`, starts at 0 at the start of each run, and moves
//! only when the input says so. A run then does the same each time, and the input decides
//! when the timers of the node fire, such as for MRP retransmissions, subscription reports
//! or the end of a fail-safe. When the clock moves on, the node runs at each time that one
//! of its timers waits for on the way, as on a device, up to a number of times that bounds
//! how long a run takes.
//!
//! Each message starts with a byte that selects its kind, modulo 6:
//! - 0: a message on the CASE session, built from the fields below;
//! - 1: an unencrypted message, as for PASE and CASE, built from the same fields;
//! - 2: a datagram as it is: its length (2 bytes), then its bytes;
//! - 3: a message on the PASE session, built from the same fields as 0 and 1;
//! - 4: a message on the CASE session over TCP, built from the same fields;
//! - 5: not a message, but time that passes: the clock moves on by the tenths of a second
//!   in the next 2 bytes.
//!
//! The fields are the protocol ID (1 byte), the opcode, the exchange ID (1 byte), the
//! flags, and the length of the payload (2 bytes) followed by the payload. The flags are:
//! - 0x01: the initiator flag;
//! - 0x02: an acknowledgement of the latest message of the node on the exchange;
//! - 0x04: the reliable flag;
//! - 0x10: a vendor ID in the protocol header;
//! - 0x20: the message is on the latest exchange that the node opened, as the other end of
//!   it, in place of the exchange ID and the initiator flag. This is how to answer the node
//!   on an exchange that it opened, such as for a subscription report or a BDX transfer.
//!
//! The harness decrypts what the node sends, so as to know the exchanges of its messages.
//! It also checks what the node sends, and panics on a UDP datagram that is too large, on a
//! message whose TLV is malformed, and on an IM response that does not decode.

use core::future::{poll_fn, Future};
use core::num::NonZeroU8;
use core::pin::{pin, Pin};
use core::task::{Context, Poll, Waker};
use std::collections::{HashMap, VecDeque};

use rs_matter::acl::{AclEntry, AuthMode};
use rs_matter::crypto::{
    test_only_crypto, CanonAeadKeyRef, CanonPkcSharedSecret, Crypto, CryptoSensitive,
};
use rs_matter::dm::clusters::app::on_off::{
    self, test::TestOnOffDeviceLogic, ClusterHandler as _, NoLevelControl, OnOffHandler,
    OnOffHooks as _,
};
use rs_matter::dm::clusters::desc::{ClusterHandler as _, DescHandler};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE};
use rs_matter::dm::endpoints::EthSysHandlerBuilder;
use rs_matter::dm::{Async, DataModel, Dataver, Endpoint, Node, Privilege};
use rs_matter::error::Error;
use rs_matter::im::{
    InteractionModel, InteractionModelState, InvokeResp, ReportDataResp, StatusResp, SubscribeResp,
    WriteResp,
};
use rs_matter::persist::{DummyKvBlobStore, VENDOR_KEYS_START};
use rs_matter::respond::Responder;
use rs_matter::sc::case::ResumableSession;
use rs_matter::tlv::{FromTLV, TLVArray, TLVElement, TLVSequence, TlvError};
use rs_matter::transport::network::{
    Address, NetworkReceive, NetworkSend, NoNetwork, MAX_RX_PACKET_SIZE, MAX_TX_PACKET_SIZE,
};
use rs_matter::transport::packet::PacketHdr;
use rs_matter::transport::session::{AttChallengeRef, NocCatIds, ReservedSession, SessionMode};
use rs_matter::transport::MatterBuffers;
use rs_matter::utils::cell::RefCell;
use rs_matter::utils::futures::{select3, Coalesce};
use rs_matter::utils::storage::{ParseBuf, WriteBuf};
use rs_matter::utils::sync::blocking::Mutex;
use rs_matter::{clusters, Matter, MATTER_PORT};

#[path = "../clock.rs"]
mod clock;

/// The node ID of the node.
const NODE_ID: u64 = 123456;
/// The node ID of the administrator on the other end of the CASE session.
const PEER_ID: u64 = 445566;
/// The node ID of the administrator on the other end of the CASE session over TCP.
const PEER_TCP_ID: u64 = 778899;
/// The ephemeral node ID of the peer for unencrypted messages.
const EPHEMERAL_ID: u64 = 0x1122_3344_5566_7788;
/// The key of the CASE session, in both directions.
const KEY: CanonAeadKeyRef = CanonAeadKeyRef::new(&[0x5a; 16]);
/// The key of the PASE session, in both directions.
const PASE_KEY: CanonAeadKeyRef = CanonAeadKeyRef::new(&[0x3c; 16]);
/// The attestation challenge of the CASE and PASE sessions, which `CSRRequest` and
/// `AttestationRequest` need.
const ATT_CHALLENGE: AttChallengeRef = AttChallengeRef::new(&[0xa5; 16]);
/// The resumption ID and the shared secret of the CASE session that the node can resume.
const RESUMPTION_ID: [u8; 16] = [0x7e; 16];
const SHARED_SECRET: [u8; 32] = [0x5e; 32];
/// The address of the peer.
const PEER_ADDR: Address = Address::Udp(core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
    core::net::Ipv4Addr::UNSPECIFIED,
    0,
)));
/// The address of the peer for the CASE session over TCP.
const PEER_TCP_ADDR: Address = Address::Tcp(core::net::SocketAddr::V4(
    core::net::SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0),
));

/// The sessions that a message can be on.
#[derive(Clone, Copy)]
enum Sess {
    Case,
    Pase,
    CaseTcp,
    Unsecured,
}

impl Sess {
    /// The session of a message from the harness, by its kind.
    fn of_kind(kind: u8) -> Self {
        match kind % KINDS {
            0 => Self::Case,
            3 => Self::Pase,
            4 => Self::CaseTcp,
            _ => Self::Unsecured,
        }
    }

    /// The session of a message from the node, by its session ID.
    fn of_id(sess_id: u16) -> Self {
        match sess_id {
            1 => Self::Case,
            2 => Self::Pase,
            3 => Self::CaseTcp,
            _ => Self::Unsecured,
        }
    }

    /// The session ID, which is the same on both ends.
    fn id(self) -> u16 {
        match self {
            Self::Case => 1,
            Self::Pase => 2,
            Self::CaseTcp => 3,
            Self::Unsecured => 0,
        }
    }

    /// The key, which is the same in both directions.
    fn key(self) -> Option<CanonAeadKeyRef<'static>> {
        match self {
            Self::Case | Self::CaseTcp => Some(KEY),
            Self::Pase => Some(PASE_KEY),
            Self::Unsecured => None,
        }
    }

    /// The address of the peer.
    fn peer_addr(self) -> Address {
        match self {
            Self::CaseTcp => PEER_TCP_ADDR,
            _ => PEER_ADDR,
        }
    }

    /// The node ID in the nonce of a message from the harness, or from the node.
    fn nonce_node_id(self, from_node: bool) -> u64 {
        match (self, from_node) {
            (Self::Case, false) => PEER_ID,
            (Self::CaseTcp, false) => PEER_TCP_ID,
            (Self::Case | Self::CaseTcp, true) => NODE_ID,
            _ => 0,
        }
    }
}

/// How many kinds of messages there are.
const KINDS: u8 = 6;

/// How many polls without anything happening mean that the node has nothing left to do.
const QUIET_POLLS: usize = 32;
/// The most polls for one message.
const MAX_POLLS: usize = 4096;

const NODE: Node<'static> = Node {
    endpoints: &[
        Endpoint::new(0, &[DEV_TYPE_ROOT_NODE], clusters!(eth;)),
        Endpoint::new(
            1,
            &[DEV_TYPE_ON_OFF_LIGHT],
            clusters!(
                DescHandler::CLUSTER,
                OnOffHandler::<'_, TestOnOffDeviceLogic, NoLevelControl>::CLUSTER,
            ),
        ),
    ],
};

/// The datagrams between the harness and the node.
#[derive(Default)]
struct Wire {
    /// The datagrams to the node that it has not received yet, with the address of the peer.
    to_node: VecDeque<(Vec<u8>, Address)>,
    /// The message counter of the latest message of the node.
    node_ctr: u32,
    /// The latest exchange that the node opened.
    node_exch: u16,
    /// The message counter of the latest message of the node on each exchange, by the
    /// session ID and the exchange ID.
    node_ctrs: HashMap<(u16, u16), u32>,
    /// How many datagrams the node has sent.
    sent: usize,
}

/// Sends the datagrams of the node to the harness, and shows the messages in them to an
/// observer, which gets the protocol ID, the opcode and the payload of each.
struct WireSend<'a, C, F>(&'a Mutex<RefCell<Wire>>, C, F);

impl<C: Crypto, F: FnMut(u16, u8, &[u8])> NetworkSend for WireSend<'_, C, F> {
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        assert!(
            addr.is_tcp() || data.len() <= MAX_TX_PACKET_SIZE,
            "The node sent a datagram of {} bytes",
            data.len()
        );

        let mut data = data.to_vec();
        let mut pb = ParseBuf::new(data.as_mut_slice());
        let mut hdr = PacketHdr::new();
        let decoded = hdr.decode_plain_hdr(&mut pb).and_then(|_| {
            let sess = Sess::of_id(hdr.plain.sess_id);
            hdr.decode_remaining(&self.1, sess.key(), sess.nonce_node_id(true), &mut pb)
        });

        self.0.lock(|wire| {
            let mut wire = wire.borrow_mut();

            if decoded.is_ok() {
                wire.node_ctr = hdr.plain.ctr;
                if hdr.proto.is_initiator() {
                    wire.node_exch = hdr.proto.exch_id;
                }
                wire.node_ctrs
                    .insert((hdr.plain.sess_id, hdr.proto.exch_id), hdr.plain.ctr);
            }

            wire.sent += 1;
        });

        if decoded.is_ok() {
            check_message(hdr.proto.proto_id, hdr.proto.proto_opcode, pb.as_slice());
            (self.2)(hdr.proto.proto_id, hdr.proto.proto_opcode, pb.as_slice());
        }

        Ok(())
    }
}

struct WireReceive<'a>(&'a Mutex<RefCell<Wire>>);

impl NetworkReceive for WireReceive<'_> {
    async fn wait_available(&mut self) -> Result<(), Error> {
        poll_fn(|_| {
            if self.0.lock(|wire| wire.borrow().to_node.is_empty()) {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        })
        .await
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        self.wait_available().await?;

        let datagram = self.0.lock(|wire| wire.borrow_mut().to_node.pop_front());
        let (datagram, addr) = datagram.unwrap_or((Vec::new(), PEER_ADDR));
        let len = datagram.len().min(buffer.len());
        buffer[..len].copy_from_slice(&datagram[..len]);

        Ok((len, addr))
    }
}

/// The message counters of the peer.
struct Counters {
    case: u32,
    pase: u32,
    case_tcp: u32,
    unencrypted: u32,
}

/// What the input does next.
enum Step {
    /// A datagram to the node, from the address of the peer.
    Datagram(Vec<u8>, Address),
    /// Time that passes, in milliseconds.
    Wait(u64),
}

/// Reads what the input does next.
fn next_step(
    input: &mut &[u8],
    ctrs: &mut Counters,
    wire: &Mutex<RefCell<Wire>>,
    crypto: impl Crypto,
) -> Option<Step> {
    let (&kind, rest) = input.split_first()?;
    *input = rest;

    if kind % KINDS == 2 {
        let (len, rest) = input.split_first_chunk::<2>()?;
        let len = (u16::from_le_bytes(*len) as usize).min(rest.len());
        let (datagram, rest) = rest.split_at(len);
        *input = rest;

        return Some(Step::Datagram(datagram.to_vec(), PEER_ADDR));
    }

    if kind % KINDS == 5 {
        let (tenths, rest) = input.split_first_chunk::<2>()?;
        *input = rest;

        return Some(Step::Wait(u64::from(u16::from_le_bytes(*tenths)) * 100));
    }

    let ([proto, opcode, exch_id, flags, len_lo, len_hi], rest) = input.split_first_chunk::<6>()?;
    let len = (u16::from_le_bytes([*len_lo, *len_hi]) as usize).min(rest.len());
    let (payload, rest) = rest.split_at(len);
    *input = rest;

    let mut hdr = PacketHdr::new();

    let sess = Sess::of_kind(kind);
    let ctr = match sess {
        Sess::Case => &mut ctrs.case,
        Sess::Pase => &mut ctrs.pase,
        Sess::CaseTcp => &mut ctrs.case_tcp,
        Sess::Unsecured => {
            hdr.plain.set_src_nodeid(Some(EPHEMERAL_ID));
            &mut ctrs.unencrypted
        }
    };

    hdr.plain.sess_id = sess.id();
    hdr.plain.ctr = *ctr;
    *ctr = ctr.wrapping_add(1);

    let (exch_id, initiator, ack) = wire.lock(|wire| {
        let wire = wire.borrow();

        let (exch_id, initiator) = if flags & 0x20 != 0 {
            (wire.node_exch, false)
        } else {
            (*exch_id as u16, flags & 0x01 != 0)
        };
        let ack = wire
            .node_ctrs
            .get(&(sess.id(), exch_id))
            .copied()
            .unwrap_or(wire.node_ctr);

        (exch_id, initiator, ack)
    });

    hdr.proto.exch_id = exch_id;
    hdr.proto.proto_id = *proto as u16;
    hdr.proto.proto_opcode = *opcode;
    if initiator {
        hdr.proto.set_initiator();
    } else {
        hdr.proto.unset_initiator();
    }
    if flags & 0x04 != 0 {
        hdr.proto.set_reliable();
    } else {
        hdr.proto.unset_reliable();
    }
    hdr.proto.set_ack((flags & 0x02 != 0).then_some(ack));
    hdr.proto.set_vendor((flags & 0x10 != 0).then_some(0));

    let mut buf = vec![0; MAX_RX_PACKET_SIZE + 2 * PacketHdr::HDR_RESERVE];
    let mut wb = WriteBuf::new_with(&mut buf, PacketHdr::HDR_RESERVE, PacketHdr::HDR_RESERVE);
    wb.append(
        &payload[..payload
            .len()
            .min(MAX_RX_PACKET_SIZE - PacketHdr::HDR_RESERVE)],
    )
    .ok()?;
    hdr.encode(crypto, sess.key(), sess.nonce_node_id(false), &mut wb)
        .ok()?;

    let mut datagram = wb.as_slice().to_vec();
    datagram.truncate(MAX_RX_PACKET_SIZE);

    Some(Step::Datagram(datagram, sess.peer_addr()))
}

/// Checks a message that the node sent, and panics if it is malformed.
fn check_message(proto_id: u16, opcode: u8, payload: &[u8]) {
    const PROTO_SC: u16 = 0;
    const PROTO_IM: u16 = 1;

    match (proto_id, opcode) {
        // Standalone acknowledgement
        (PROTO_SC, 0x10) => assert!(payload.is_empty(), "The node sent an ack with a payload"),
        // Status report: the general code, the protocol ID and the protocol code
        (PROTO_SC, 0x40) => assert!(payload.len() >= 8, "The node sent a short status report"),
        // PBKDFParamResponse, Pake2, Sigma2 and Sigma2Resume
        (PROTO_SC, 0x21 | 0x23 | 0x31 | 0x33) => {
            check_tlv(payload);
        }
        (PROTO_IM, _) => {
            let msg = check_tlv(payload);
            let check = |result: Result<(), TlvError>| {
                if let Err(err) = result {
                    panic!("The node sent an IM message (opcode {opcode:#x}) that does not decode: {err:?}");
                }
            };

            match opcode {
                0x01 => check(StatusResp::from_tlv(&msg).map(|_| ())),
                0x04 => check(SubscribeResp::from_tlv(&msg).map(|_| ())),
                0x05 => check(ReportDataResp::from_tlv(&msg).and_then(|resp| {
                    check_all(resp.attr_reports)?;
                    check_all(resp.event_reports)
                })),
                0x07 => check(
                    WriteResp::from_tlv(&msg)
                        .and_then(|resp| check_all(Some(resp.write_responses))),
                ),
                0x09 => check(
                    InvokeResp::from_tlv(&msg).and_then(|resp| check_all(resp.invoke_responses)),
                ),
                _ => (),
            }
        }
        _ => (),
    }
}

/// Decodes every item of an array.
fn check_all<'a, T: FromTLV<'a>>(array: Option<TLVArray<'a, T>>) -> Result<(), TlvError> {
    for item in array.iter().flatten() {
        item?;
    }

    Ok(())
}

/// Checks that a payload is one TLV structure, all of whose elements read, and returns it.
fn check_tlv(payload: &[u8]) -> TLVElement<'_> {
    fn walk(element: &TLVElement) -> Result<(), TlvError> {
        if element.is_container()? {
            for child in element.container()?.iter() {
                walk(&child?)?;
            }
        } else {
            element.value()?;
        }

        Ok(())
    }

    let mut elements = TLVSequence(payload).iter();
    let msg = elements
        .next()
        .and_then(Result::ok)
        .filter(|msg| msg.structure().is_ok())
        .unwrap_or_else(|| {
            panic!("The node sent a message that is not a TLV structure: {payload:02x?}")
        });

    assert!(
        elements.next().is_none(),
        "The node sent a message with more after its TLV structure: {payload:02x?}"
    );

    if let Err(err) = walk(&msg) {
        panic!("The node sent a message with malformed TLV ({err:?}): {payload:02x?}");
    }

    msg
}

/// Polls the node until it has nothing left to do. Returns `false` once the node is done.
fn run_until_idle<F: Future>(node: &mut Pin<&mut F>, wire: &Mutex<RefCell<Wire>>) -> bool {
    let mut cx = Context::from_waker(Waker::noop());
    let mut quiet = 0;
    let mut last = (usize::MAX, usize::MAX);

    for _ in 0..MAX_POLLS {
        if node.as_mut().poll(&mut cx).is_ready() {
            return false;
        }

        let now = wire.lock(|wire| {
            let wire = wire.borrow();
            (wire.to_node.len(), wire.sent)
        });

        if now == last && now.0 == 0 {
            quiet += 1;
            if quiet >= QUIET_POLLS {
                break;
            }
        } else {
            quiet = 0;
        }

        last = now;
    }

    true
}

/// Runs the node of the `node` target with the messages in `data`. `observe` gets the
/// protocol ID, the opcode and the payload of each message that the node sends.
pub fn run(data: &[u8], observe: impl FnMut(u16, u8, &[u8])) {
    let crypto = test_only_crypto();
    let mut rand = crypto.rand().unwrap();

    let matter = new_matter(&crypto);

    let on_off = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        VENDOR_KEYS_START + 0x10,
        TestOnOffDeviceLogic::new(false),
    );
    let handler = EthSysHandlerBuilder::new()
        .build(&matter, rand)
        .chain(
            |e, c| e == 1 && c == DescHandler::CLUSTER.id,
            Async(DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
        )
        .chain(
            |e, c| e == 1 && c == TestOnOffDeviceLogic::CLUSTER.id,
            Async(on_off::HandlerAdaptor(on_off)),
        );

    drive(&matter, &crypto, (NODE, handler), data, observe);
}

/// A node with the fabric of the administrators, the CASE session that it can resume, and
/// the CASE, PASE and TCP CASE sessions.
pub fn new_matter<C: Crypto>(crypto: C) -> Matter<'static> {
    // Each run starts at the same time
    clock::reset();

    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    let mut acl = AclEntry::new(None, Privilege::ADMIN, AuthMode::Case);
    acl.add_subject(PEER_ID).unwrap();
    acl.add_subject(PEER_TCP_ID).unwrap();
    matter.with_state(|state| {
        state.fabrics.add_with_post_init(|_| Ok(())).unwrap();
        state
            .fabrics
            .fabric_mut(NonZeroU8::new(1).unwrap())
            .unwrap()
            .acl_add(acl)
            .unwrap();

        let mut resumption_id = CryptoSensitive::new();
        resumption_id.load_from_array(&RESUMPTION_ID);
        let mut shared_secret = CanonPkcSharedSecret::new();
        shared_secret.load_from_array(&SHARED_SECRET);
        state.resumption.insert_or_update(ResumableSession {
            fab_idx: NonZeroU8::new(1).unwrap(),
            peer_nodeid: PEER_ID,
            peer_cat_ids: NocCatIds::default(),
            resumption_id,
            shared_secret,
        });
    });

    let mut session = ReservedSession::reserve_now(matter.transport(), &crypto).unwrap();
    session
        .update(
            NODE_ID,
            PEER_ID,
            1,
            1,
            PEER_ADDR,
            SessionMode::Case {
                fab_idx: NonZeroU8::new(1).unwrap(),
                cat_ids: NocCatIds::default(),
            },
            Some(KEY),
            Some(KEY),
            Some(ATT_CHALLENGE),
            None,
        )
        .unwrap();
    session.complete();

    let mut session = ReservedSession::reserve_now(matter.transport(), &crypto).unwrap();
    session
        .update(
            0,
            0,
            2,
            2,
            PEER_ADDR,
            SessionMode::Pase { fab_idx: 0 },
            Some(PASE_KEY),
            Some(PASE_KEY),
            Some(ATT_CHALLENGE),
            None,
        )
        .unwrap();
    session.complete();

    let mut session = ReservedSession::reserve_now(matter.transport(), &crypto).unwrap();
    session
        .update(
            NODE_ID,
            PEER_TCP_ID,
            3,
            3,
            PEER_TCP_ADDR,
            SessionMode::Case {
                fab_idx: NonZeroU8::new(1).unwrap(),
                cat_ids: NocCatIds::default(),
            },
            Some(KEY),
            Some(KEY),
            Some(ATT_CHALLENGE),
            None,
        )
        .unwrap();
    session.complete();

    matter
}

/// Runs a node with the data model `dm` and the messages in `data`. `observe` gets the
/// protocol ID, the opcode and the payload of each message that the node sends.
pub fn drive<C: Crypto, T: DataModel>(
    matter: &Matter,
    crypto: C,
    dm: T,
    data: &[u8],
    observe: impl FnMut(u16, u8, &[u8]),
) {
    let buffers: MatterBuffers = MatterBuffers::new();
    let state = InteractionModelState::<3, 1024>::new();
    let kv = matter.kv(DummyKvBlobStore);
    let dm = InteractionModel::new(matter, &crypto, &buffers, dm, &kv, &state);

    block_on(dm.startup()).unwrap();

    let responder = Responder::new_default(&dm);

    let wire = Mutex::new(RefCell::new(Wire::default()));

    let node = select3(
        matter.run(
            &crypto,
            WireSend(&wire, &crypto, observe),
            WireReceive(&wire),
            NoNetwork,
        ),
        responder.run::<4>(),
        dm.run(),
    )
    .coalesce();
    let mut node = pin!(node);

    let mut ctrs = Counters {
        case: 0x1000,
        pase: 0x3000,
        case_tcp: 0x4000,
        unencrypted: 0x2000,
    };
    let mut input = data;

    if !run_until_idle(&mut node, &wire) {
        return;
    }

    while let Some(step) = next_step(&mut input, &mut ctrs, &wire, &crypto) {
        match step {
            Step::Datagram(datagram, addr) => {
                wire.lock(|wire| wire.borrow_mut().to_node.push_back((datagram, addr)))
            }
            Step::Wait(ms) => {
                if !clock::advance(ms, || run_until_idle(&mut node, &wire)) {
                    break;
                }
            }
        }

        if !run_until_idle(&mut node, &wire) {
            break;
        }
    }
}

/// Polls a future that does not wait for anything until it is done.
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = pin!(fut);

    for _ in 0..MAX_POLLS {
        if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
            return output;
        }
    }

    panic!("A future that should not wait is still pending");
}
