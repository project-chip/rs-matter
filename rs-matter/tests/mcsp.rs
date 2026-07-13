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

//! End-to-end test for the MCSP responder.
//!
//! Wires an in-process device that runs a `SecureChannel` responder and
//! a hand-rolled UDP "peer" that composes a group-encrypted
//! `MsgCounterSyncReq` and verifies the reply. This exercises the RX
//! path's unicast-to-fabric branch (`get_or_create_for_group_rx` when
//! DSIZ=1) and the group-session TX path (`pre_send` GROUP_SESSION +
//! CONTROL_MSG framing, group op key encryption) in one shot.

#![cfg(all(feature = "std", feature = "async-io", feature = "groups"))]

#[allow(dead_code)]
mod common;

use core::num::NonZeroU8;
use core::pin::pin;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use log::info;

use rs_matter::cert::gen::VALID_FOREVER;
use rs_matter::cert::MAX_CERT_TLV_AND_ASN1_LEN;
use rs_matter::crypto::{
    test_only_crypto, CanonAeadKey, CanonPkcSecretKey, Crypto, RngCore, SecretKey,
    SigningSecretKey, AEAD_CANON_KEY_LEN, AEAD_KEY_ZEROED,
};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error;
use rs_matter::fabric::GroupKeyMapping;
use rs_matter::group_keys::{GroupEpochKeyEntry, GroupKeySet, KeySet};
use rs_matter::onboard::cac::RcacGenerator;
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::respond::Responder;
use rs_matter::sc::mcsp::{MsgCounterSyncReq, MsgCounterSyncRsp};
use rs_matter::sc::{OpCode, SecureChannel, PROTO_ID_SECURE_CHANNEL};
use rs_matter::transport::network::{Address, NoNetwork};
use rs_matter::transport::packet::PacketHdr;
use rs_matter::transport::session::derive_group_session_id;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::{ParseBuf, Vec, WriteBuf};
use rs_matter::Matter;

use crate::common::{create_localhost_socket_pair, init_env_logger, run_device_controller};

const TEST_FABRIC_ID: u64 = 1;
const CONTROLLER_NODE_ID: u64 = 100;
const DEVICE_NODE_ID: u64 = 200;
const TEST_GROUP_ID: u16 = 0x0101;
const TEST_GROUP_KEY_SET_ID: u16 = 42;
const TEST_EPOCH_KEY: [u8; AEAD_CANON_KEY_LEN] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

/// End-to-end MCSP responder test.
///
/// Provisions a fabric on the device with a single group key, then sends
/// a `MsgCounterSyncReq` from a bespoke UDP peer and asserts the device
/// replies with a valid `MsgCounterSyncRsp` that echoes the challenge
/// and carries a non-zero synchronized counter.
#[test]
fn test_mcsp_responder() {
    init_env_logger();

    futures_lite::future::block_on(async {
        let crypto = test_only_crypto();

        let device_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
        let device_fab_idx = provision_fabric_and_group(&device_matter, &crypto);

        // Derive the same operational key the device will derive
        // internally on RX, so we can encrypt requests and decrypt replies.
        let (op_key, group_sess_id) = {
            let compressed_fabric_id = device_matter.with_state(|state| {
                state
                    .fabrics
                    .fabric(device_fab_idx)
                    .unwrap()
                    .compressed_fabric_id()
            });
            derive_op_key_and_sess_id(&crypto, &TEST_EPOCH_KEY, &compressed_fabric_id)
        };

        let (device_socket, controller_socket) = create_localhost_socket_pair();
        let device_addr = Address::Udp(device_socket.get_ref().local_addr().unwrap());

        let sc = SecureChannel::new(&crypto, &());
        let responder = Responder::new("device", sc, &device_matter, 0);

        let device_fut = async {
            select(
                device_matter.run(&crypto, &device_socket, &device_socket, NoNetwork),
                responder.run::<4>(),
            )
            .coalesce()
            .await
        };

        let controller_fut = run_mcsp_peer(
            &controller_socket,
            device_addr,
            &op_key,
            group_sess_id,
            &crypto,
        );

        run_device_controller(device_fut, controller_fut)
            .await
            .unwrap();
    });
}

/// Provision a fabric on `matter` and install a single group key set
/// (`TEST_GROUP_KEY_SET_ID`) mapped to `TEST_GROUP_ID`, returning the
/// fabric index. The fabric's node id is [`DEVICE_NODE_ID`].
fn provision_fabric_and_group<C: Crypto>(matter: &Matter<'_>, crypto: &C) -> NonZeroU8 {
    let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut rcac_gen = RcacGenerator::new(&mut rcac_buf);
    let (rcac_privkey, rcac) = rcac_gen
        .generate(crypto, TEST_FABRIC_ID, VALID_FOREVER)
        .unwrap();

    let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut noc_generator =
        NocGenerator::create(rcac_privkey.reference(), rcac, &[], &mut noc_buf).unwrap();

    let mut ipk = CanonAeadKey::new();
    let mut ipk_bytes = [0u8; AEAD_CANON_KEY_LEN];
    crypto.rand().unwrap().fill_bytes(&mut ipk_bytes);
    ipk.load_from_array(&ipk_bytes);

    let device_sk = crypto.generate_secret_key().unwrap();
    let mut device_csr_buf = [0u8; 256];
    let device_csr = device_sk.csr(&mut device_csr_buf).unwrap();
    let mut device_sk_canon = CanonPkcSecretKey::new();
    device_sk.write_canon(&mut device_sk_canon).unwrap();

    let device_noc = noc_generator
        .generate(crypto, device_csr, DEVICE_NODE_ID, &[], VALID_FOREVER)
        .unwrap();

    matter.with_state(|state| {
        let fab_idx = state
            .fabrics
            .add(
                crypto,
                device_sk_canon.reference(),
                rcac,
                device_noc,
                &[],
                Some(ipk.reference()),
                0xFFF1,
                CONTROLLER_NODE_ID,
            )
            .unwrap()
            .fab_idx();

        let fabric = state.fabrics.fabric_mut(fab_idx).unwrap();

        let mut epoch_key = CanonAeadKey::new();
        epoch_key.load_from_array(&TEST_EPOCH_KEY);
        let mut epoch_keys = Vec::new();
        epoch_keys
            .push(GroupEpochKeyEntry {
                epoch_key,
                epoch_start_time: 0,
            })
            .unwrap();

        fabric
            .groups_mut()
            .key_set_add(GroupKeySet {
                group_key_set_id: TEST_GROUP_KEY_SET_ID,
                group_key_security_policy: 0, // TrustFirst
                epoch_keys,
            })
            .unwrap();

        fabric
            .groups_mut()
            .key_map_add(GroupKeyMapping {
                group_id: TEST_GROUP_ID,
                group_key_set_id: TEST_GROUP_KEY_SET_ID,
            })
            .unwrap();

        fab_idx
    })
}

/// Derive `(op_key, group_session_id)` from an epoch key + compressed
/// fabric id, matching what the RX path does internally.
fn derive_op_key_and_sess_id<C: Crypto>(
    crypto: &C,
    epoch_key_bytes: &[u8; AEAD_CANON_KEY_LEN],
    compressed_fabric_id: &u64,
) -> (CanonAeadKey, u16) {
    let mut epoch_key = CanonAeadKey::new();
    epoch_key.load_from_array(epoch_key_bytes);

    let mut ks = KeySet::new();
    ks.update(crypto, epoch_key.reference(), compressed_fabric_id)
        .unwrap();

    let group_sess_id = derive_group_session_id(crypto, ks.op_key()).unwrap();

    // Persist a copy of the op_key so it outlives `ks`.
    let mut op_key = AEAD_KEY_ZEROED;
    op_key.load(ks.op_key());

    (op_key, group_sess_id)
}

async fn run_mcsp_peer<C: Crypto>(
    socket: &async_io::Async<std::net::UdpSocket>,
    device_addr: Address,
    op_key: &CanonAeadKey,
    group_sess_id: u16,
    crypto: &C,
) -> Result<(), Error> {
    let mut rand = crypto.rand()?;

    let mut challenge = [0u8; 8];
    rand.fill_bytes(&mut challenge);

    let req_ctr = fresh_ctr(&mut rand);
    let req_exch_id = 0x1234;

    info!(
        "MCSP peer: sending MsgCounterSyncReq (challenge={:x?}, ctr={}, exch=0x{:04x})",
        challenge, req_ctr, req_exch_id
    );

    let mut tx_buf = [0u8; 256];
    let tx_slice = encode_mcsp_frame(
        crypto,
        op_key,
        &mut tx_buf,
        group_sess_id,
        req_ctr,
        req_exch_id,
        McspFrame::Req { challenge },
    )?;

    let device_sockaddr = match device_addr {
        Address::Udp(sa) => sa,
        _ => panic!("device addr must be UDP"),
    };
    socket
        .send_to(tx_slice, device_sockaddr)
        .await
        .expect("send_to");

    // Await the reply. A 5-second cap catches the "responder never
    // replied" failure mode instead of hanging the test suite.
    let mut rx_buf = [0u8; 1500];
    let (len, from) = {
        let mut recv = pin!(socket.recv_from(&mut rx_buf));
        let mut timeout = pin!(Timer::after(Duration::from_secs(5)));
        match select(&mut recv, &mut timeout).await {
            Either::First(r) => r.expect("recv_from"),
            Either::Second(_) => panic!("MCSP peer: no response within 5s"),
        }
    };
    info!("MCSP peer: got {} bytes from {}", len, from);

    let (rsp, rsp_ctr, rsp_exch_id) =
        decode_mcsp_rsp(crypto, op_key, &mut rx_buf[..len], group_sess_id)?;

    assert_eq!(
        rsp.response, challenge,
        "MsgCounterSyncRsp did not echo the challenge back"
    );
    assert_ne!(
        rsp.synchronized_counter, 0,
        "synchronized_counter must be non-zero"
    );
    info!(
        "MCSP peer: verified MsgCounterSyncRsp (sync_ctr={}, echo ok)",
        rsp.synchronized_counter
    );

    // Ack the reply so the device's MRP loop closes out cleanly and
    // doesn't scream about a stuck retransmission when the test tears
    // down.
    let ack_ctr = fresh_ctr(&mut rand);
    let mut ack_buf = [0u8; 128];
    let ack_slice = encode_mcsp_frame(
        crypto,
        op_key,
        &mut ack_buf,
        group_sess_id,
        ack_ctr,
        rsp_exch_id,
        McspFrame::Ack { ack_ctr: rsp_ctr },
    )?;
    socket
        .send_to(ack_slice, device_sockaddr)
        .await
        .expect("ack send_to");

    // Give the device transport a beat to consume the ACK before we
    // return and let it be dropped.
    Timer::after(Duration::from_millis(100)).await;

    Ok(())
}

/// A generic outgoing frame the MCSP peer emits.
enum McspFrame {
    Req { challenge: [u8; 8] },
    Ack { ack_ctr: u32 },
}

/// Compose a group-encrypted, control-flagged packet destined for the
/// device node, returning the slice of `buf` that holds the full wire
/// bytes ready for `send_to`.
fn encode_mcsp_frame<'a, C: Crypto>(
    crypto: &C,
    op_key: &CanonAeadKey,
    buf: &'a mut [u8],
    group_sess_id: u16,
    ctr: u32,
    exch_id: u16,
    frame: McspFrame,
) -> Result<&'a [u8], Error> {
    let mut wb = WriteBuf::new_with(buf, PacketHdr::HDR_RESERVE, PacketHdr::HDR_RESERVE);

    let mut hdr = PacketHdr::new();
    hdr.plain.sess_id = group_sess_id;
    hdr.plain.ctr = ctr;
    hdr.plain.set_group_session(true);
    hdr.plain.set_control_msg(true);
    hdr.plain.set_src_nodeid(Some(CONTROLLER_NODE_ID));
    hdr.plain.set_dst_unicast_nodeid(Some(DEVICE_NODE_ID));

    hdr.proto.proto_id = PROTO_ID_SECURE_CHANNEL;
    hdr.proto.exch_id = exch_id;
    match frame {
        McspFrame::Req { challenge } => {
            hdr.proto.proto_opcode = OpCode::MsgCounterSyncReq as u8;
            hdr.proto.set_initiator();
            hdr.proto.set_reliable();
            MsgCounterSyncReq { challenge }.write(&mut wb)?;
        }
        McspFrame::Ack { ack_ctr } => {
            hdr.proto.proto_opcode = OpCode::MRPStandAloneAck as u8;
            hdr.proto.set_initiator();
            hdr.proto.unset_reliable();
            hdr.proto.set_ack(Some(ack_ctr));
        }
    }

    hdr.encode(
        crypto,
        Some(op_key.reference()),
        CONTROLLER_NODE_ID,
        &mut wb,
    )?;

    let start = wb.get_start();
    let end = wb.get_tail();
    Ok(&buf[start..end])
}

/// Decode an incoming `MsgCounterSyncRsp` frame, verifying framing
/// invariants along the way, and return the payload plus counter/exch
/// id the ack needs to reference.
fn decode_mcsp_rsp<C: Crypto>(
    crypto: &C,
    op_key: &CanonAeadKey,
    buf: &mut [u8],
    expected_sess_id: u16,
) -> Result<(MsgCounterSyncRsp, u32, u16), Error> {
    let mut pb = ParseBuf::new(buf);
    let mut hdr = PacketHdr::new();
    hdr.decode_plain_hdr(&mut pb)?;

    assert_eq!(hdr.plain.sess_id, expected_sess_id, "reply session id");
    assert!(hdr.plain.is_group_session(), "reply must set GROUP_SESSION");
    assert!(hdr.plain.is_control_msg(), "reply must set CONTROL_MSG");
    assert_eq!(
        hdr.plain.get_src_nodeid(),
        Some(DEVICE_NODE_ID),
        "reply must carry device Source Node ID"
    );
    assert_eq!(
        hdr.plain.get_dst_unicast_nodeid(),
        Some(CONTROLLER_NODE_ID),
        "reply must be unicast to controller"
    );

    let rsp_ctr = hdr.plain.ctr;

    hdr.decode_remaining(crypto, Some(op_key.reference()), DEVICE_NODE_ID, &mut pb)?;

    assert_eq!(hdr.proto.proto_id, PROTO_ID_SECURE_CHANNEL);
    assert_eq!(
        hdr.proto.proto_opcode,
        OpCode::MsgCounterSyncResp as u8,
        "reply opcode"
    );

    let rsp = MsgCounterSyncRsp::read(pb.as_slice())?;
    Ok((rsp, rsp_ctr, hdr.proto.exch_id))
}

/// A fresh non-zero 28-bit message counter for the peer's outbound
/// frames. Kept in the 28-bit range to leave the top four bits clear
/// (matching how the transport itself allocates counters).
fn fresh_ctr(rand: &mut impl RngCore) -> u32 {
    loop {
        let v = rand.next_u32() & 0x0fff_ffff;
        if v != 0 {
            return v;
        }
    }
}
