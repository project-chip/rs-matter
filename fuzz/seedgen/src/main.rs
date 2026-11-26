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

//! Writes the seeds of the `node`, `clusters` and `tcp` fuzz targets to `fuzz/seeds/node`,
//! `fuzz/seeds/clusters` and `fuzz/seeds/tcp`, or to `node`, `clusters` and `tcp` in the
//! directory given as an argument:
//!
//! ```sh
//! cargo run --manifest-path fuzz/seedgen/Cargo.toml
//! ```
//!
//! The seeds follow the input format in `fuzz_targets/node/harness.rs`. The generator runs
//! the same harness, to take the CSR of the node from its answer to `CSRRequest`, to answer
//! each chunk of a report in the seeds of `clusters`, and to check each seed: it prints
//! how many messages the node sent for it. The seeds of `tcp`, in the input format in
//! `fuzz_targets/tcp.rs`, are written as they are.

// For the type of the node of the `clusters` target
#![recursion_limit = "256"]

use std::fs;
use std::path::{Path, PathBuf};

use rs_matter::cert::gen::VALID_FOREVER;
use rs_matter::cert::CertRef;
use rs_matter::crypto::group_keys::KeySet;
use rs_matter::crypto::{
    test_only_crypto, Aead, CanonAeadKey, CanonAeadKeyRef, CanonPkcPublicKeyRef, Crypto,
    CryptoSensitiveRef, Digest, Hash, Kdf,
};
use rs_matter::error::Error;
use rs_matter::fabric::Fabric;
use rs_matter::onboard::cac::RcacGenerator;
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::sc::pase::spake2p::{Spake2P, Spake2pVerifierPasswordRef, Spake2pVerifierStr};
use rs_matter::tlv::{TLVElement, TLVTag, TLVWrite};
use rs_matter::utils::storage::WriteBuf;

#[path = "../../fuzz_targets/clusters/all_clusters.rs"]
mod all_clusters;
mod clusters;
#[path = "../../fuzz_targets/node/harness.rs"]
mod harness;
mod tcp;

const A: TLVTag = TLVTag::Anonymous;

const fn c(tag: u8) -> TLVTag {
    TLVTag::Context(tag)
}

type R = Result<(), Error>;

// The flags of a message in the input
const I: u8 = 0x01;
const ACK: u8 = 0x02;
const REL: u8 = 0x04;
const NODE_EXCH: u8 = 0x20;

// Protocols
const SC: u8 = 0x00;
const IM: u8 = 0x01;
const BDX: u8 = 0x02;

// Secure Channel opcodes
const MCSP_REQ: u8 = 0x00;
const STANDALONE_ACK: u8 = 0x10;
const PBKDF_REQ: u8 = 0x20;
const PAKE1: u8 = 0x22;
const PAKE3: u8 = 0x24;
const SIGMA1: u8 = 0x30;
const SIGMA3: u8 = 0x32;
const STATUS_REPORT: u8 = 0x40;
const CHECK_IN: u8 = 0x50;

// IM opcodes
const STATUS_RESP: u8 = 0x01;
const READ: u8 = 0x02;
const SUBSCRIBE: u8 = 0x03;
const WRITE: u8 = 0x06;
const INVOKE: u8 = 0x08;
const INVOKE_RESP: u8 = 0x09;
const TIMED: u8 = 0x0a;

// BDX opcodes
const SEND_INIT: u8 = 0x01;
const RECEIVE_INIT: u8 = 0x04;

const IM_REV: u8 = 12;

/// The administrator on the other end of the CASE session, as in the harness
const PEER_ID: u64 = 445566;
/// The node ID of the node, as in the harness
const NODE_ID: u64 = 123456;
/// The resumption ID and the shared secret of the CASE session that the node can resume,
/// as in the harness
const RESUMPTION_ID: [u8; 16] = [0x7e; 16];
const SHARED_SECRET: [u8; 32] = [0x5e; 32];
/// The passcode of `TEST_DEV_COMM`
const PASSCODE: u32 = 20202021;

/// The node ID and the fabric ID in the NOC of `commission`
const NEW_NODE_ID: u64 = 0x1234;
const NEW_FABRIC_ID: u64 = 2;
/// The IPK of the fabric of `commission`
const IPK: [u8; 16] = [0x4a; 16];
/// The initiator random of Sigma1
const SIGMA1_RANDOM: [u8; 32] = [0x22; 32];

/// How many chunks the node sends for a read of every attribute, less the last one
const READ_ALL_CHUNKS: usize = 3;

/// The generator of P-256, a valid point for PASE and CASE
const P256_G: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];

fn main() {
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = env_logger::try_init();
    }

    let out = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../seeds"));

    let csr = node_csr(&commission_start());
    let pase_csr = node_csr(&commission_pase_start());

    write_seeds(
        &out.join("node"),
        seeds(&csr, &pase_csr),
        |data, observe| harness::run(data, observe),
    );
    write_seeds(&out.join("clusters"), clusters::seeds(), |data, observe| {
        all_clusters::run(data, observe)
    });

    let dir = out.join("tcp");
    fs::create_dir_all(&dir).unwrap();
    for (name, steps) in tcp::seeds() {
        fs::write(dir.join(name), &steps.0).unwrap();
        println!("{name}: {} bytes", steps.0.len());
    }
}

/// Runs the node of a target with an input, and shows each message of the node to an
/// observer
type Run = fn(&[u8], &mut dyn FnMut(u16, u8, &[u8]));

/// Writes the seeds of a target to `dir`, after a run of each through the node of the
/// target
fn write_seeds(dir: &Path, seeds: Vec<(&'static str, Seed)>, run: Run) {
    fs::create_dir_all(dir).unwrap();

    for (name, seed) in seeds {
        // The `-max_len` of the fuzz job in CI, which cuts longer inputs
        assert!(seed.0.len() <= 4096, "{name} is longer than 4096 bytes");

        fs::write(dir.join(name), &seed.0).unwrap();

        let mut sent = 0;
        run(&seed.0, &mut |_, _, _| sent += 1);

        println!(
            "{name}: {} bytes; messages from the node: {sent}",
            seed.0.len()
        );
    }
}

/// The CSR in the answer of the node to the `CSRRequest` at the end of `seed`
fn node_csr(seed: &Seed) -> Vec<u8> {
    let mut csr = None;

    harness::run(&seed.0, |proto, opcode, payload| {
        if proto == IM as u16 && opcode == INVOKE_RESP && csr.is_none() {
            csr = csr_of(payload);
        }
    });

    csr.expect("The node did not answer CSRRequest")
}

/// The CSR in an invoke response with a `CSRResponse`
fn csr_of(payload: &[u8]) -> Option<Vec<u8>> {
    let cmd = TLVElement::new(payload)
        .structure()
        .ok()?
        .find_ctx(1)
        .ok()?
        .array()
        .ok()?
        .iter()
        .next()?
        .ok()?
        .structure()
        .ok()?
        .find_ctx(0)
        .ok()?
        .structure()
        .ok()?;

    let path = cmd.find_ctx(0).ok()?.list().ok()?;
    if path.find_ctx(1).ok()?.u32().ok()? != 0x3e || path.find_ctx(2).ok()?.u32().ok()? != 0x05 {
        return None;
    }

    let elements = cmd
        .find_ctx(1)
        .ok()?
        .structure()
        .ok()?
        .find_ctx(0)
        .ok()?
        .str()
        .ok()?;

    let csr = TLVElement::new(elements)
        .structure()
        .ok()?
        .find_ctx(1)
        .ok()?
        .str()
        .ok()?;

    Some(csr.to_vec())
}

/// The start of `commission`: `ArmFailSafe` and `CSRRequest`
fn commission_start() -> Seed {
    let mut s = Seed::default();
    s.request(IM, INVOKE, 40, &arm_fail_safe(60, 1))
        .request(IM, INVOKE, 41, &csr_req(0x56, false));
    s
}

/// The start of `commission-pase`: `ArmFailSafe` and `CSRRequest`, on the PASE session
fn commission_pase_start() -> Seed {
    let mut s = Seed::default();
    s.pase_request(IM, INVOKE, 53, &arm_fail_safe(60, 1))
        .pase_request(IM, INVOKE, 54, &csr_req(0x58, false));
    s
}

fn seeds(csr: &[u8], pase_csr: &[u8]) -> Vec<(&'static str, Seed)> {
    let crypto = test_only_crypto();
    let mut seeds = Vec::new();

    // A read of every attribute, which the node sends in several chunks
    let mut s = Seed::default();
    s.case(
        IM,
        READ,
        1,
        I | REL,
        &read_req(&[(None, None, None)], &[], None, true),
    );
    for _ in 0..READ_ALL_CHUNKS {
        s.case(IM, STATUS_RESP, 1, I | REL | ACK, &status_ok());
    }
    s.ack(1);
    seeds.push(("read-all", s));

    // A read of the attributes of Basic Information with a data version filter, and of all events
    let mut s = Seed::default();
    s.request(
        IM,
        READ,
        2,
        &read_req(
            &[(Some(0), Some(0x28), None)],
            &[(None, None, None)],
            Some((0, 0x28, 0)),
            false,
        ),
    );
    seeds.push(("read-events", s));

    // A subscription, then changes to its attributes, and the answers to the reports
    let mut s = Seed::default();
    s.case(
        IM,
        SUBSCRIBE,
        3,
        I | REL,
        &subscribe_req(
            &[(Some(1), Some(6), Some(0)), (Some(0), Some(0x28), Some(5))],
            &[(Some(0), Some(0x28), None)],
            10,
        ),
    )
    .case(IM, STATUS_RESP, 3, I | REL | ACK, &status_ok())
    .ack(3)
    .request(IM, INVOKE, 4, &invoke1(false, 1, 6, 2, |_| Ok(())))
    .reply(IM, STATUS_RESP, &status_ok())
    .request(
        IM,
        WRITE,
        52,
        &write_req(false, |w| {
            attr_data(w, 0, 0x28, 5, false, |w, t| Ok(w.utf8(t, "subscribed")?))
        }),
    )
    .reply(IM, STATUS_RESP, &status_ok());
    seeds.push(("subscribe", s));

    // Several commands in one invoke request
    let mut s = Seed::default();
    s.request(
        IM,
        INVOKE,
        5,
        &invoke_req(false, |w| {
            cmd(w, 1, 6, 2, Some(1), |_| Ok(()))?;
            cmd(w, 0, 0x33, 1, Some(2), |_| Ok(()))?;
            cmd(w, 0, 0x30, 0, Some(3), |w| {
                w.u16(&c(0), 0)?;
                w.u64(&c(1), 5)?;
                Ok(())
            })
        }),
    );
    seeds.push(("invoke-batch", s));

    // Commands of the root endpoint
    let mut s = Seed::default();
    s.request(
        IM,
        INVOKE,
        6,
        &invoke1(false, 0, 0x33, 0, |w| {
            w.str(&c(0), &[0; 16])?;
            w.u64(&c(1), 0)?;
            Ok(())
        }),
    )
    .request(
        IM,
        INVOKE,
        7,
        &invoke1(false, 0, 0x38, 0, |w| {
            w.u64(&c(0), 800_000_000_000_000)?;
            w.u8(&c(1), 4)?;
            w.u8(&c(2), 1)?;
            Ok(())
        }),
    )
    .request(
        IM,
        INVOKE,
        8,
        &invoke1(false, 0, 0x3e, 0, |w| Ok(w.str(&c(0), &[0x55; 32])?)),
    )
    .request(
        IM,
        INVOKE,
        9,
        &invoke1(false, 0, 0x3e, 2, |w| Ok(w.u8(&c(0), 1)?)),
    )
    .request(
        IM,
        INVOKE,
        10,
        &invoke1(false, 0, 0x3e, 2, |w| Ok(w.u8(&c(0), 2)?)),
    )
    .request(
        IM,
        INVOKE,
        11,
        &invoke1(false, 0, 0x30, 2, |w| {
            w.u8(&c(0), 0)?;
            w.utf8(&c(1), "XX")?;
            w.u64(&c(2), 1)?;
            Ok(())
        }),
    );
    seeds.push(("invoke-root", s));

    // Writes to attributes of several clusters
    let mut s = Seed::default();
    s.request(
        IM,
        WRITE,
        12,
        &write_req(false, |w| {
            attr_data(w, 0, 0x28, 5, false, |w, t| Ok(w.utf8(t, "fuzz")?))?;
            attr_data(w, 0, 0x28, 6, false, |w, t| Ok(w.utf8(t, "XX")?))?;
            attr_data(w, 0, 0x30, 0, false, |w, t| Ok(w.u64(t, 7)?))?;
            attr_data(w, 1, 6, 0x4001, false, |w, t| Ok(w.u16(t, 10)?))?;
            attr_data(w, 1, 6, 0x4002, false, |w, t| Ok(w.u16(t, 5)?))?;
            attr_data(w, 1, 6, 0x4003, false, |w, t| Ok(w.null(t)?))
        }),
    );
    seeds.push(("write", s));

    // The same as a timed write
    let mut s = Seed::default();
    s.timed(
        WRITE,
        13,
        &write_req(true, |w| {
            attr_data(w, 0, 0x28, 5, false, |w, t| Ok(w.utf8(t, "timed")?))
        }),
    );
    seeds.push(("write-timed", s));

    // Writes to the access control list, then a read of it and of its events
    let mut s = Seed::default();
    s.request(
        IM,
        WRITE,
        14,
        &write_req(false, |w| {
            attr_data(w, 0, 0x1f, 0, false, |w, t| {
                w.start_array(t)?;
                acl_entry(w, &A, 5, 2, &[PEER_ID], &[])?;
                acl_entry(
                    w,
                    &A,
                    1,
                    2,
                    &[0xffff_fffd_0001_0001],
                    &[(Some(6), Some(1)), (None, Some(0))],
                )?;
                w.end_container()?;
                Ok(())
            })?;
            attr_data(w, 0, 0x1f, 0, true, |w, t| {
                acl_entry(w, t, 3, 3, &[0x0101], &[(Some(6), None)])
            })
        }),
    )
    .request(
        IM,
        READ,
        15,
        &read_req(
            &[(Some(0), Some(0x1f), None)],
            &[(Some(0), Some(0x1f), None)],
            None,
            true,
        ),
    );
    seeds.push(("write-acl", s));

    // Group keys: a key set, a group key map, then reads and the removal of the key set
    let mut s = Seed::default();
    s.request(
        IM,
        INVOKE,
        16,
        &invoke1(false, 0, 0x3f, 0, |w| {
            w.start_struct(&c(0))?;
            w.u16(&c(0), 1)?;
            w.u8(&c(1), 0)?;
            w.str(&c(2), &[0xd0; 16])?;
            w.u64(&c(3), 1)?;
            w.str(&c(4), &[0xd1; 16])?;
            w.u64(&c(5), 2)?;
            w.str(&c(6), &[0xd2; 16])?;
            w.u64(&c(7), 3)?;
            w.end_container()?;
            Ok(())
        }),
    )
    .request(
        IM,
        WRITE,
        17,
        &write_req(false, |w| {
            attr_data(w, 0, 0x3f, 0, false, |w, t| {
                w.start_array(t)?;
                w.start_struct(&A)?;
                w.u16(&c(1), 0x0101)?;
                w.u16(&c(2), 1)?;
                w.end_container()?;
                w.end_container()?;
                Ok(())
            })
        }),
    )
    .request(
        IM,
        READ,
        18,
        &read_req(&[(Some(0), Some(0x3f), None)], &[], None, true),
    )
    .request(
        IM,
        INVOKE,
        19,
        &invoke1(false, 0, 0x3f, 1, |w| Ok(w.u16(&c(0), 1)?)),
    )
    .request(IM, INVOKE, 20, &invoke1(false, 0, 0x3f, 4, |_| Ok(())))
    .request(
        IM,
        INVOKE,
        21,
        &invoke1(false, 0, 0x3f, 3, |w| Ok(w.u16(&c(0), 1)?)),
    );
    seeds.push(("group-keys", s));

    // An enhanced commissioning window, PASE with a wrong confirmation, `ArmFailSafe`
    // while the window is open, then the revocation of the window
    let salt = b"SPAKE2P Key Salt";
    let mut verifier = Spake2pVerifierStr::new();
    Spake2P::compute_verifier(
        &crypto,
        Spake2pVerifierPasswordRef::new(&PASSCODE.to_le_bytes()),
        1000,
        salt,
        &mut verifier,
    )
    .unwrap();

    let mut s = Seed::default();
    s.timed(
        INVOKE,
        22,
        &invoke1(true, 0, 0x3c, 0, |w| {
            w.u16(&c(0), 180)?;
            w.str(&c(1), verifier.access())?;
            w.u16(&c(2), 0xf00)?;
            w.u32(&c(3), 1000)?;
            w.str(&c(4), salt)?;
            Ok(())
        }),
    )
    .plain(SC, PBKDF_REQ, 23, I | REL, &pbkdf_param_req(0x1234, false))
    .plain(SC, PAKE1, 23, I | REL | ACK, &one_str(1, &P256_G))
    .plain(SC, PAKE3, 23, I | REL | ACK, &one_str(1, &[0x66; 32]))
    .plain_ack(23)
    .request(IM, INVOKE, 24, &arm_fail_safe(60, 1))
    .timed(INVOKE, 25, &invoke1(true, 0, 0x3c, 2, |_| Ok(())));
    seeds.push(("commissioning-window", s));

    // A basic commissioning window, then PASE with an invalid point
    let mut s = Seed::default();
    s.timed(
        INVOKE,
        26,
        &invoke1(true, 0, 0x3c, 1, |w| Ok(w.u16(&c(0), 180)?)),
    )
    .plain(SC, PBKDF_REQ, 27, I | REL, &pbkdf_param_req(0x1235, true))
    .plain(SC, PAKE1, 27, I | REL | ACK, &one_str(1, &[0x04; 65]))
    .plain_ack(27);
    seeds.push(("commissioning-window-basic", s));

    // CASE with a destination ID that matches no fabric, without and with resumption
    let mut s = Seed::default();
    s.plain(SC, SIGMA1, 28, I | REL, &sigma1(&[0x77; 32], None))
        .plain_ack(28)
        .plain(
            SC,
            SIGMA1,
            29,
            I | REL,
            &sigma1(&[0x77; 32], Some((&[0x33; 16], &[0x44; 16]))),
        )
        .plain_ack(29);
    seeds.push(("case", s));

    // The resumption of the CASE session of the administrator, the status report that
    // ends it, then a resumption with a wrong MIC, which falls back to a full CASE
    let mut s = Seed::default();
    s.plain(
        SC,
        SIGMA1,
        55,
        I | REL,
        &sigma1(&[0x77; 32], Some((&RESUMPTION_ID, &resume_mic(&crypto)))),
    )
    .plain(
        SC,
        STATUS_REPORT,
        55,
        I | REL | ACK,
        &sc_status_report(0, 0, 0),
    )
    .plain_ack(55)
    .plain(
        SC,
        SIGMA1,
        56,
        I | REL,
        &sigma1(&[0x77; 32], Some((&RESUMPTION_ID, &[0x44; 16]))),
    )
    .plain_ack(56);
    seeds.push(("case-resume", s));

    // BDX transfers that the node does not expect
    let mut s = Seed::default();
    s.request(
        BDX,
        SEND_INIT,
        30,
        &bdx_init(0x10, 0x00, 1024, None, b"test.log"),
    )
    .request(
        BDX,
        RECEIVE_INIT,
        31,
        &bdx_init(0x20, 0x01, 512, Some(4096), b"diag.log"),
    );
    seeds.push(("bdx", s));

    // Secure channel messages that the node does not expect, an IM request that is not
    // encrypted, and a datagram with a message extension, a destination node ID and a
    // vendor ID in the protocol header
    let mut raw = vec![0x05, 0x00, 0x00, 0x20, 0x00, 0x30, 0x00, 0x00];
    raw.extend_from_slice(&0x1122_3344_5566_7789u64.to_le_bytes());
    raw.extend_from_slice(&NODE_ID.to_le_bytes());
    raw.extend_from_slice(&[0x02, 0x00, 0xaa, 0xbb]);
    raw.extend_from_slice(&[0x15, STANDALONE_ACK, 0x24, 0x00, 0xf1, 0xff, 0x00, 0x00]);

    let mut s = Seed::default();
    s.request(SC, MCSP_REQ, 32, &[0x88; 8])
        .request(SC, STATUS_REPORT, 33, &sc_status_report(0, 0, 0))
        .request(SC, CHECK_IN, 34, &[0x99; 32])
        .plain(
            IM,
            READ,
            35,
            I | REL,
            &read_req(&[(Some(1), Some(6), Some(0))], &[], None, true),
        )
        .raw(&raw);
    seeds.push(("secure-channel", s));

    // The removal of a fabric that does not exist, a new label for the fabric of the
    // session, the removal of that fabric, then a read on the session
    let mut s = Seed::default();
    s.request(
        IM,
        INVOKE,
        36,
        &invoke1(false, 0, 0x3e, 0x0a, |w| Ok(w.u8(&c(0), 2)?)),
    )
    .request(
        IM,
        INVOKE,
        37,
        &invoke1(false, 0, 0x3e, 0x09, |w| Ok(w.utf8(&c(0), "fuzz")?)),
    )
    .request(
        IM,
        INVOKE,
        38,
        &invoke1(false, 0, 0x3e, 0x0a, |w| Ok(w.u8(&c(0), 1)?)),
    )
    .request(
        IM,
        READ,
        39,
        &read_req(&[(Some(1), Some(6), Some(0))], &[], None, true),
    );
    seeds.push(("remove-fabric", s));

    // A second fabric added over the CASE session, CASE up to Sigma3 with that fabric,
    // `CommissioningComplete`, then the fail-safe expired
    let (rcac, noc) = new_fabric(&crypto, csr);

    let mut s = commission_start();
    s.request(
        IM,
        INVOKE,
        42,
        &invoke1(false, 0, 0x3e, 0x0b, |w| Ok(w.str(&c(0), &rcac)?)),
    )
    .request(
        IM,
        INVOKE,
        43,
        &invoke1(false, 0, 0x3e, 6, |w| {
            w.str(&c(0), &noc)?;
            w.str(&c(2), &IPK)?;
            w.u64(&c(3), PEER_ID)?;
            w.u16(&c(4), 0xfff1)?;
            Ok(())
        }),
    )
    .request(
        IM,
        READ,
        44,
        &read_req(&[(Some(0), Some(0x3e), None)], &[], None, false),
    )
    .plain(
        SC,
        SIGMA1,
        45,
        I | REL,
        &sigma1(&dest_id(&crypto, &rcac), None),
    )
    .plain(SC, SIGMA3, 45, I | REL | ACK, &one_str(1, &[0x67; 120]))
    .plain_ack(45)
    .request(IM, INVOKE, 46, &invoke1(false, 0, 0x30, 4, |_| Ok(())))
    .request(IM, INVOKE, 47, &arm_fail_safe(0, 0));
    seeds.push(("commission", s));

    // `UpdateNOC` after a CSR for it, which fails, as the fabric of the session has no root
    let mut s = Seed::default();
    s.request(IM, INVOKE, 48, &arm_fail_safe(60, 1))
        .request(IM, INVOKE, 49, &csr_req(0x57, true))
        .request(
            IM,
            INVOKE,
            50,
            &invoke1(false, 0, 0x3e, 7, |w| Ok(w.str(&c(0), &noc)?)),
        )
        .request(IM, INVOKE, 51, &arm_fail_safe(0, 0));
    seeds.push(("update-noc", s));

    // The same as `commission`, on the PASE session, as a commissioner does it
    let (rcac, noc) = new_fabric(&crypto, pase_csr);

    let mut s = commission_pase_start();
    s.pase_request(
        IM,
        INVOKE,
        57,
        &invoke1(false, 0, 0x3e, 0x0b, |w| Ok(w.str(&c(0), &rcac)?)),
    )
    .pase_request(
        IM,
        INVOKE,
        58,
        &invoke1(false, 0, 0x3e, 6, |w| {
            w.str(&c(0), &noc)?;
            w.str(&c(2), &IPK)?;
            w.u64(&c(3), PEER_ID)?;
            w.u16(&c(4), 0xfff1)?;
            Ok(())
        }),
    )
    .pase_request(
        IM,
        READ,
        59,
        &read_req(&[(Some(0), Some(0x3e), None)], &[], None, false),
    )
    .pase_request(IM, INVOKE, 60, &invoke1(false, 0, 0x30, 4, |_| Ok(())))
    .pase_request(IM, INVOKE, 61, &arm_fail_safe(0, 0));
    seeds.push(("commission-pase", s));

    // A subscription: a keep-alive report, which the node sends half-way through the max
    // interval that it grants (40 s), and which is answered, then one that is not, which
    // the node sends again until it gives up
    let mut s = Seed::default();
    s.case(
        IM,
        SUBSCRIBE,
        60,
        I | REL,
        &subscribe_req(&[(Some(1), Some(6), Some(0))], &[], 5),
    )
    .case(IM, STATUS_RESP, 60, I | REL | ACK, &status_ok())
    .ack(60)
    .wait(210)
    .reply(IM, STATUS_RESP, &status_ok())
    .wait(210)
    .wait(10)
    .wait(20)
    .wait(40)
    .wait(80)
    .wait(160)
    .wait(600);
    seeds.push(("subscribe-timeout", s));

    // A response that is not acknowledged, which the node sends again until it gives up,
    // then a write after its timed request timed out
    let mut s = Seed::default();
    s.case(
        IM,
        READ,
        61,
        I | REL,
        &read_req(&[(Some(0), Some(0x28), Some(1))], &[], None, false),
    )
    .wait(10)
    .wait(20)
    .wait(40)
    .wait(80)
    .wait(160)
    .wait(320)
    .case(IM, TIMED, 62, I | REL, &timed_req(500))
    .wait(10)
    .case(
        IM,
        WRITE,
        62,
        I | REL | ACK,
        &write_req(true, |w| {
            attr_data(w, 0, 0x28, 5, false, |w, t| Ok(w.utf8(t, "late")?))
        }),
    )
    .ack(62);
    seeds.push(("timeouts", s));

    // A fail-safe of 5 s that expires after `CSRRequest`, then `CSRRequest` again, which
    // needs a fail-safe
    let mut s = Seed::default();
    s.request(IM, INVOKE, 63, &arm_fail_safe(5, 1))
        .request(IM, INVOKE, 64, &csr_req(0x5a, false))
        .wait(60)
        .request(IM, INVOKE, 65, &csr_req(0x5b, false));
    seeds.push(("fail-safe-timeout", s));

    // A basic commissioning window that closes after its 3 minutes, then PASE, which fails
    let mut s = Seed::default();
    s.timed(
        INVOKE,
        66,
        &invoke1(true, 0, 0x3c, 1, |w| Ok(w.u16(&c(0), 180)?)),
    )
    .wait(1810)
    .plain(SC, PBKDF_REQ, 67, I | REL, &pbkdf_param_req(0x1236, false));
    seeds.push(("commissioning-window-timeout", s));

    seeds
}

/// A root certificate for the fabric of `commission`, and a NOC for the key in `csr`
fn new_fabric<C: Crypto>(crypto: C, csr: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut rcac_buf = vec![0; 1024];
    let mut rcac_gen = RcacGenerator::new(&mut rcac_buf);
    let (rcac_key, rcac) = rcac_gen
        .generate(&crypto, NEW_FABRIC_ID, VALID_FOREVER)
        .unwrap();
    let rcac = rcac.to_vec();

    let mut noc_buf = vec![0; 1024];
    let noc = NocGenerator::create(rcac_key.reference(), &rcac, &[], &mut noc_buf)
        .unwrap()
        .generate(&crypto, csr, NEW_NODE_ID, &[], VALID_FOREVER)
        .unwrap()
        .to_vec();

    (rcac, noc)
}

/// The `InitiatorResumeMIC` of a Sigma1 that resumes the CASE session of the harness
fn resume_mic<C: Crypto>(crypto: C) -> [u8; 16] {
    let mut salt = SIGMA1_RANDOM.to_vec();
    salt.extend_from_slice(&RESUMPTION_ID);

    let mut s1rk = CanonAeadKey::new();
    crypto
        .kdf()
        .unwrap()
        .expand(
            &salt,
            CryptoSensitiveRef::new(&SHARED_SECRET),
            b"Sigma1_Resume",
            &mut s1rk,
        )
        .unwrap();

    let mut mic = [0; 16];
    let tag = crypto
        .aead()
        .unwrap()
        .encrypt_in_place(
            s1rk.reference(),
            CryptoSensitiveRef::new(b"NCASE_SigmaS1"),
            &[],
            &mut mic,
            0,
        )
        .unwrap()
        .to_vec();
    mic.copy_from_slice(&tag);

    mic
}

/// The destination ID of the node on the fabric of `commission`, for Sigma1
fn dest_id<C: Crypto>(crypto: C, rcac: &[u8]) -> Vec<u8> {
    let rcac = CertRef::new(TLVElement::new(rcac));
    let root_pubkey = rcac.pubkey().unwrap();
    let compressed_fabric_id = Fabric::compute_compressed_fabric_id(
        &crypto,
        CanonPkcPublicKeyRef::try_new(root_pubkey).unwrap(),
        NEW_FABRIC_ID,
    );

    let mut ipk = KeySet::new();
    ipk.update(&crypto, CanonAeadKeyRef::new(&IPK), &compressed_fabric_id)
        .unwrap();

    let mut mac = crypto.hmac(ipk.op_key()).unwrap();
    mac.update(&SIGMA1_RANDOM).unwrap();
    mac.update(root_pubkey).unwrap();
    mac.update(&NEW_FABRIC_ID.to_le_bytes()).unwrap();
    mac.update(&NEW_NODE_ID.to_le_bytes()).unwrap();

    let mut dest_id = Hash::new();
    mac.finish(&mut dest_id).unwrap();

    dest_id.access().to_vec()
}

/// A series of messages in the input format of the target
#[derive(Default)]
struct Seed(Vec<u8>);

impl Seed {
    fn msg(&mut self, kind: u8, proto: u8, opcode: u8, exch: u8, flags: u8, payload: &[u8]) {
        let len = u16::try_from(payload.len()).unwrap().to_le_bytes();
        self.0
            .extend_from_slice(&[kind, proto, opcode, exch, flags, len[0], len[1]]);
        self.0.extend_from_slice(payload);
    }

    /// A message on the CASE session
    fn case(&mut self, proto: u8, opcode: u8, exch: u8, flags: u8, payload: &[u8]) -> &mut Self {
        self.msg(0, proto, opcode, exch, flags, payload);
        self
    }

    /// A message on the PASE session
    fn pase(&mut self, proto: u8, opcode: u8, exch: u8, flags: u8, payload: &[u8]) -> &mut Self {
        self.msg(3, proto, opcode, exch, flags, payload);
        self
    }

    /// An unencrypted message
    fn plain(&mut self, proto: u8, opcode: u8, exch: u8, flags: u8, payload: &[u8]) -> &mut Self {
        self.msg(1, proto, opcode, exch, flags, payload);
        self
    }

    /// Time that passes, in tenths of a second
    fn wait(&mut self, tenths: u16) -> &mut Self {
        let tenths = tenths.to_le_bytes();
        self.0.extend_from_slice(&[5, tenths[0], tenths[1]]);
        self
    }

    /// A datagram as it is
    fn raw(&mut self, datagram: &[u8]) -> &mut Self {
        let len = u16::try_from(datagram.len()).unwrap().to_le_bytes();
        self.0.extend_from_slice(&[2, len[0], len[1]]);
        self.0.extend_from_slice(datagram);
        self
    }

    /// An acknowledgement of the latest message of the node on the exchange
    fn ack(&mut self, exch: u8) -> &mut Self {
        self.case(SC, STANDALONE_ACK, exch, I | ACK, &[])
    }

    /// The same as an unencrypted message
    fn plain_ack(&mut self, exch: u8) -> &mut Self {
        self.plain(SC, STANDALONE_ACK, exch, I | ACK, &[])
    }

    /// A request on a new exchange of the PASE session, and the acknowledgement of the response
    fn pase_request(&mut self, proto: u8, opcode: u8, exch: u8, payload: &[u8]) -> &mut Self {
        self.pase(proto, opcode, exch, I | REL, payload).pase(
            SC,
            STANDALONE_ACK,
            exch,
            I | ACK,
            &[],
        )
    }

    /// A request on a new exchange, and the acknowledgement of the response
    fn request(&mut self, proto: u8, opcode: u8, exch: u8, payload: &[u8]) -> &mut Self {
        self.case(proto, opcode, exch, I | REL, payload).ack(exch)
    }

    /// An answer to the latest message of the node, on its exchange
    fn reply(&mut self, proto: u8, opcode: u8, payload: &[u8]) -> &mut Self {
        self.case(proto, opcode, 0, NODE_EXCH | REL | ACK, payload)
    }

    /// A timed interaction: `TimedRequest`, then the request on the same exchange
    fn timed(&mut self, opcode: u8, exch: u8, payload: &[u8]) -> &mut Self {
        self.case(IM, TIMED, exch, I | REL, &timed_req(5000))
            .case(IM, opcode, exch, I | REL | ACK, payload)
            .ack(exch)
    }
}

fn tlv(f: impl FnOnce(&mut WriteBuf) -> R) -> Vec<u8> {
    let mut buf = vec![0; 4096];
    let mut wb = WriteBuf::new(&mut buf);
    f(&mut wb).unwrap();
    wb.as_slice().to_vec()
}

/// A path of an attribute or an event: the endpoint, the cluster, and the attribute or event
type Path3 = (Option<u16>, Option<u32>, Option<u32>);

/// An attribute path, with its tags from 2 (the endpoint) to 4 (the attribute)
fn attr_path(w: &mut WriteBuf, tag: &TLVTag, (ep, cl, at): Path3) -> R {
    w.start_list(tag)?;
    if let Some(ep) = ep {
        w.u16(&c(2), ep)?;
    }
    if let Some(cl) = cl {
        w.u32(&c(3), cl)?;
    }
    if let Some(at) = at {
        w.u32(&c(4), at)?;
    }
    w.end_container()?;
    Ok(())
}

/// An event path, with its tags from 1 (the endpoint) to 3 (the event)
fn event_path(w: &mut WriteBuf, (ep, cl, ev): Path3, urgent: bool) -> R {
    w.start_list(&A)?;
    if let Some(ep) = ep {
        w.u16(&c(1), ep)?;
    }
    if let Some(cl) = cl {
        w.u32(&c(2), cl)?;
    }
    if let Some(ev) = ev {
        w.u32(&c(3), ev)?;
    }
    if urgent {
        w.bool(&c(4), true)?;
    }
    w.end_container()?;
    Ok(())
}

fn read_req(
    attrs: &[Path3],
    events: &[Path3],
    dv_filter: Option<(u16, u32, u32)>,
    fabric_filtered: bool,
) -> Vec<u8> {
    tlv(|w| {
        w.start_struct(&A)?;
        if !attrs.is_empty() {
            w.start_array(&c(0))?;
            for path in attrs {
                attr_path(w, &A, *path)?;
            }
            w.end_container()?;
        }
        if !events.is_empty() {
            w.start_array(&c(1))?;
            for path in events {
                event_path(w, *path, false)?;
            }
            w.end_container()?;
            w.start_array(&c(2))?;
            w.start_struct(&A)?;
            w.u64(&c(1), 0)?;
            w.end_container()?;
            w.end_container()?;
        }
        w.bool(&c(3), fabric_filtered)?;
        if let Some((ep, cl, ver)) = dv_filter {
            w.start_array(&c(4))?;
            w.start_struct(&A)?;
            w.start_list(&c(0))?;
            w.u16(&c(1), ep)?;
            w.u32(&c(2), cl)?;
            w.end_container()?;
            w.u32(&c(1), ver)?;
            w.end_container()?;
            w.end_container()?;
        }
        w.u8(&c(0xff), IM_REV)?;
        w.end_container()?;
        Ok(())
    })
}

fn subscribe_req(attrs: &[Path3], events: &[Path3], max_interval: u16) -> Vec<u8> {
    tlv(|w| {
        w.start_struct(&A)?;
        w.bool(&c(0), false)?;
        w.u16(&c(1), 0)?;
        w.u16(&c(2), max_interval)?;
        w.start_array(&c(3))?;
        for path in attrs {
            attr_path(w, &A, *path)?;
        }
        w.end_container()?;
        if !events.is_empty() {
            w.start_array(&c(4))?;
            for path in events {
                event_path(w, *path, true)?;
            }
            w.end_container()?;
        }
        w.bool(&c(7), true)?;
        w.u8(&c(0xff), IM_REV)?;
        w.end_container()?;
        Ok(())
    })
}

fn status_ok() -> Vec<u8> {
    tlv(|w| {
        w.start_struct(&A)?;
        w.u8(&c(0), 0)?;
        w.u8(&c(0xff), IM_REV)?;
        w.end_container()?;
        Ok(())
    })
}

fn timed_req(timeout_ms: u16) -> Vec<u8> {
    tlv(|w| {
        w.start_struct(&A)?;
        w.u16(&c(0), timeout_ms)?;
        w.u8(&c(0xff), IM_REV)?;
        w.end_container()?;
        Ok(())
    })
}

/// One `CommandDataIB`
fn cmd(
    w: &mut WriteBuf,
    ep: u16,
    cl: u32,
    id: u32,
    cmd_ref: Option<u16>,
    fields: impl FnOnce(&mut WriteBuf) -> R,
) -> R {
    w.start_struct(&A)?;
    w.start_list(&c(0))?;
    w.u16(&c(0), ep)?;
    w.u32(&c(1), cl)?;
    w.u32(&c(2), id)?;
    w.end_container()?;
    w.start_struct(&c(1))?;
    fields(w)?;
    w.end_container()?;
    if let Some(cmd_ref) = cmd_ref {
        w.u16(&c(2), cmd_ref)?;
    }
    w.end_container()?;
    Ok(())
}

fn invoke_req(timed: bool, cmds: impl FnOnce(&mut WriteBuf) -> R) -> Vec<u8> {
    tlv(|w| {
        w.start_struct(&A)?;
        w.bool(&c(0), false)?;
        w.bool(&c(1), timed)?;
        w.start_array(&c(2))?;
        cmds(w)?;
        w.end_container()?;
        w.u8(&c(0xff), IM_REV)?;
        w.end_container()?;
        Ok(())
    })
}

/// An invoke request with one command
fn invoke1(
    timed: bool,
    ep: u16,
    cl: u32,
    id: u32,
    fields: impl FnOnce(&mut WriteBuf) -> R,
) -> Vec<u8> {
    invoke_req(timed, |w| cmd(w, ep, cl, id, None, fields))
}

fn arm_fail_safe(expiry_secs: u16, breadcrumb: u64) -> Vec<u8> {
    invoke1(false, 0, 0x30, 0, |w| {
        w.u16(&c(0), expiry_secs)?;
        w.u64(&c(1), breadcrumb)?;
        Ok(())
    })
}

fn csr_req(nonce: u8, for_update_noc: bool) -> Vec<u8> {
    invoke1(false, 0, 0x3e, 4, |w| {
        w.str(&c(0), &[nonce; 32])?;
        if for_update_noc {
            w.bool(&c(1), true)?;
        }
        Ok(())
    })
}

/// One `AttributeDataIB`; with `append`, the path adds an item to a list
fn attr_data(
    w: &mut WriteBuf,
    ep: u16,
    cl: u32,
    at: u32,
    append: bool,
    data: impl FnOnce(&mut WriteBuf, &TLVTag) -> R,
) -> R {
    w.start_struct(&A)?;
    w.start_list(&c(1))?;
    w.u16(&c(2), ep)?;
    w.u32(&c(3), cl)?;
    w.u32(&c(4), at)?;
    if append {
        w.null(&c(5))?;
    }
    w.end_container()?;
    data(w, &c(2))?;
    w.end_container()?;
    Ok(())
}

fn write_req(timed: bool, attrs: impl FnOnce(&mut WriteBuf) -> R) -> Vec<u8> {
    tlv(|w| {
        w.start_struct(&A)?;
        w.bool(&c(0), false)?;
        w.bool(&c(1), timed)?;
        w.start_array(&c(2))?;
        attrs(w)?;
        w.end_container()?;
        w.u8(&c(0xff), IM_REV)?;
        w.end_container()?;
        Ok(())
    })
}

/// An access control entry, with targets of a cluster and an endpoint
fn acl_entry(
    w: &mut WriteBuf,
    tag: &TLVTag,
    privilege: u8,
    auth_mode: u8,
    subjects: &[u64],
    targets: &[(Option<u32>, Option<u16>)],
) -> R {
    w.start_struct(tag)?;
    w.u8(&c(1), privilege)?;
    w.u8(&c(2), auth_mode)?;
    if subjects.is_empty() {
        w.null(&c(3))?;
    } else {
        w.start_array(&c(3))?;
        for subject in subjects {
            w.u64(&A, *subject)?;
        }
        w.end_container()?;
    }
    if targets.is_empty() {
        w.null(&c(4))?;
    } else {
        w.start_array(&c(4))?;
        for (cl, ep) in targets {
            w.start_struct(&A)?;
            match cl {
                Some(cl) => w.u32(&c(0), *cl)?,
                None => w.null(&c(0))?,
            }
            match ep {
                Some(ep) => w.u16(&c(1), *ep)?,
                None => w.null(&c(1))?,
            }
            w.null(&c(2))?;
            w.end_container()?;
        }
        w.end_container()?;
    }
    w.end_container()?;
    Ok(())
}

fn pbkdf_param_req(session_id: u16, with_session_params: bool) -> Vec<u8> {
    tlv(|w| {
        w.start_struct(&A)?;
        w.str(&c(1), &[0x11; 32])?;
        w.u16(&c(2), session_id)?;
        w.u16(&c(3), 0)?;
        w.bool(&c(4), false)?;
        if with_session_params {
            w.start_struct(&c(5))?;
            w.u32(&c(1), 500)?;
            w.u32(&c(2), 300)?;
            w.u16(&c(3), 4000)?;
            w.end_container()?;
        }
        w.end_container()?;
        Ok(())
    })
}

/// A structure with one octet string
fn one_str(tag: u8, data: &[u8]) -> Vec<u8> {
    tlv(|w| {
        w.start_struct(&A)?;
        w.str(&c(tag), data)?;
        w.end_container()?;
        Ok(())
    })
}

/// A Sigma1, with the resumption ID and the resumption MIC if `resumption` is there
fn sigma1(dest_id: &[u8], resumption: Option<(&[u8; 16], &[u8; 16])>) -> Vec<u8> {
    tlv(|w| {
        w.start_struct(&A)?;
        w.str(&c(1), &SIGMA1_RANDOM)?;
        w.u16(&c(2), 0x2345)?;
        w.str(&c(3), dest_id)?;
        w.str(&c(4), &P256_G)?;
        if let Some((resumption_id, mic)) = resumption {
            w.str(&c(6), resumption_id)?;
            w.str(&c(7), mic)?;
        }
        w.end_container()?;
        Ok(())
    })
}

fn sc_status_report(general_code: u16, proto_id: u32, proto_code: u16) -> Vec<u8> {
    let mut report = general_code.to_le_bytes().to_vec();
    report.extend_from_slice(&proto_id.to_le_bytes());
    report.extend_from_slice(&proto_code.to_le_bytes());
    report
}

fn bdx_init(
    transfer_ctl: u8,
    range_ctl: u8,
    max_block: u16,
    max_len: Option<u32>,
    file: &[u8],
) -> Vec<u8> {
    let mut init = vec![transfer_ctl, range_ctl];
    init.extend_from_slice(&max_block.to_le_bytes());
    if let Some(max_len) = max_len {
        init.extend_from_slice(&max_len.to_le_bytes());
    }
    init.extend_from_slice(&u16::try_from(file.len()).unwrap().to_le_bytes());
    init.extend_from_slice(file);
    init
}
