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

//! Arbitrary bytes as a series of BTP packets from BLE peers, through a BTP session,
//! and as a Matter BLE advertisement.
//!
//! The first three bytes are the settings: flags (bit 0: the central role, bit 1:
//! strict MTU negotiation, bit 2: a message of our own to send), then the GATT MTU
//! (0 for unknown). Each packet that follows starts with two bytes: which of the
//! two peers sends it, and its length.

#![no_main]

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use libfuzzer_sys::fuzz_target;

use rs_matter_transport::network::btp::{AdvData, Btp, RecoveryAdvData};
use rs_matter_transport::network::BtAddr;

// The clock of the targets, as BTP reads the time. It stays at 0 here.
#[allow(dead_code)]
#[path = "clock.rs"]
mod clock;

const PEERS: [BtAddr; 2] = [BtAddr([1, 2, 3, 4, 5, 6]), BtAddr([6, 5, 4, 3, 2, 1])];

/// How many packets BTP may send in reply to one packet, and how many messages
/// are read after it. Both are more than one packet can lead to.
const MAX_REPLIES: usize = 8;

/// Polls a future once, as BTP is driven here without an executor.
fn poll_once<F: Future>(fut: F) -> Option<F::Output> {
    match pin!(fut).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = AdvData::parse_adv(data);
    let _ = AdvData::parse_service_data(data);
    let _ = RecoveryAdvData::parse_adv(data);
    let _ = RecoveryAdvData::parse_service_data(data);

    let [flags, mtu_lo, mtu_hi, packets @ ..] = data else {
        return;
    };

    let mtu = u16::from_le_bytes([*mtu_lo, *mtu_hi]);
    let gatt_mtu = (mtu != 0).then_some(mtu);

    let btp = Btp::new();
    btp.set_initiator(flags & 0x01 != 0);
    btp.set_strict_mtu_nego(flags & 0x02 != 0);

    if flags & 0x04 != 0 {
        let _ = poll_once(btp.send(&[0x5a; 1000], PEERS[0]));
    }

    let mut buf = [0; 512];
    let mut msg = [0; 2048];
    let mut packets = packets;

    while let [peer, len, rest @ ..] = packets {
        let (packet, rest) = rest.split_at((*len as usize).min(rest.len()));
        packets = rest;

        let _ = btp.process_incoming(gatt_mtu, PEERS[(*peer & 1) as usize], packet);

        for _ in 0..MAX_REPLIES {
            if !matches!(btp.process_outgoing(gatt_mtu, &mut buf), Ok(len) if len > 0) {
                break;
            }
        }

        for _ in 0..MAX_REPLIES {
            if !matches!(poll_once(btp.recv(&mut msg)), Some(Ok(_))) {
                break;
            }
        }
    }
});
