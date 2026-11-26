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

//! Arbitrary message counters through the windows that detect duplicate messages,
//! checked against a plain model of them:
//! - a counter newer than every one before is always accepted;
//! - an encrypted message is never accepted twice;
//! - an encrypted unicast message is accepted exactly when it is newer than every
//!   one before, or not yet received and within the window.
//!
//! The first byte selects the kind of messages: encrypted unicast, unencrypted
//! unicast or group. The next four bytes are the first counter. Each counter after it
//! is one byte, its offset from the newest counter so far, or 0x80 followed by the
//! counter itself. For groups, each counter is preceded by one more byte, which selects
//! one of eight senders.

#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;

use rs_matter_transport::dedup::{GroupCtrStore, RxCtrState};

/// How many counters before the newest one the window holds.
const WINDOW: u32 = 32;

/// The counters of one sender as the window should see them.
///
/// Counters are kept as positions on a line without rollover, so that a group
/// counter that rolled over is not taken for one received before.
#[derive(Default)]
struct Model {
    /// The newest counter, and its position.
    newest: Option<(u32, u64)>,
    /// The positions of the accepted counters.
    accepted: BTreeSet<u64>,
}

impl Model {
    /// The position of the first group counter, far enough from 0 to go back from.
    const GROUP_START: u64 = 1 << 33;

    /// Reads the next counter from the input.
    fn next(&self, first: u32, input: &mut &[u8]) -> Option<u32> {
        let (&offset, rest) = input.split_first()?;
        *input = rest;

        if offset == 0x80 {
            let (ctr, rest) = input.split_first_chunk::<4>()?;
            *input = rest;

            Some(u32::from_le_bytes(*ctr))
        } else {
            let newest = self.newest.map(|(newest, _)| newest).unwrap_or(first);

            Some(newest.wrapping_add(offset as i8 as i32 as u32))
        }
    }

    fn is_newer(&self, ctr: u32, rollover: bool) -> bool {
        match self.newest {
            None => true,
            Some((newest, _)) if rollover => {
                (1..=i32::MAX as u32).contains(&ctr.wrapping_sub(newest))
            }
            Some((newest, _)) => ctr > newest,
        }
    }

    fn position(&self, ctr: u32, rollover: bool) -> u64 {
        match self.newest {
            Some((newest, pos)) if rollover => {
                if self.is_newer(ctr, true) {
                    pos + ctr.wrapping_sub(newest) as u64
                } else {
                    pos - newest.wrapping_sub(ctr) as u64
                }
            }
            None if rollover => Self::GROUP_START + ctr as u64,
            _ => ctr as u64,
        }
    }

    /// Whether an encrypted unicast message should be accepted.
    fn accepts_encrypted_unicast(&self, ctr: u32) -> bool {
        match self.newest {
            None => true,
            Some((newest, _)) => {
                ctr > newest || (newest - ctr <= WINDOW && !self.accepted.contains(&(ctr as u64)))
            }
        }
    }

    /// Checks what the window decided against the model, and records it.
    fn record(&mut self, ctr: u32, accepted: bool, encrypted: bool, rollover: bool) {
        let newer = self.is_newer(ctr, rollover);

        assert!(accepted || !newer, "newer counter {ctr} rejected");

        if !accepted {
            return;
        }

        let pos = self.position(ctr, rollover);

        if encrypted {
            assert!(self.accepted.insert(pos), "counter {ctr} accepted twice");
        }

        // Unencrypted, a counter far behind the newest one is taken as the counter
        // of a peer that rebooted
        let restarted = !encrypted
            && self
                .newest
                .is_some_and(|(newest, _)| newest.saturating_sub(ctr) > WINDOW);

        if newer || restarted {
            self.newest = Some((ctr, pos));
        }
    }
}

fn unicast(first: u32, mut input: &[u8], encrypted: bool) {
    let mut window = RxCtrState::new_unsynced();
    let mut model = Model::default();

    let mut ctr = Some(first);

    while let Some(c) = ctr {
        let accepted = window.post_recv(c, encrypted, false);

        if encrypted {
            assert_eq!(accepted, model.accepts_encrypted_unicast(c), "counter {c}");
        }

        model.record(c, accepted, encrypted, false);

        ctr = model.next(first, &mut input);
    }
}

fn group(first: u32, mut input: &[u8]) {
    let mut store = GroupCtrStore::new();
    let mut models: [Model; 8] = Default::default();

    while let Some((&sender, rest)) = input.split_first() {
        input = rest;

        let sender = (sender & 7) as usize;
        let model = &mut models[sender];

        let Some(ctr) = model.next(first, &mut input) else {
            break;
        };

        let accepted = store.post_recv(1, sender as u64, ctr);

        model.record(ctr, accepted, true, true);
    }
}

fuzz_target!(|data: &[u8]| {
    let [kind, c0, c1, c2, c3, steps @ ..] = data else {
        return;
    };

    let first = u32::from_le_bytes([*c0, *c1, *c2, *c3]);

    match kind % 3 {
        0 => unicast(first, steps, true),
        1 => unicast(first, steps, false),
        _ => group(first, steps),
    }
});
