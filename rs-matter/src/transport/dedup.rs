/*
 *
 *    Copyright (c) 2023-2026 Project CHIP Authors
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

const MSG_RX_STATE_BITMAP_LEN: u32 = 16;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RxCtrState {
    max_ctr: u32,
    ctr_bitmap: u16,
}

impl RxCtrState {
    pub const fn new(max_ctr: u32) -> Self {
        Self {
            max_ctr,
            ctr_bitmap: 0xffff,
        }
    }

    fn contains(&self, bit_number: u32) -> bool {
        (self.ctr_bitmap & (1 << bit_number)) != 0
    }

    fn insert(&mut self, bit_number: u32) {
        self.ctr_bitmap |= 1 << bit_number;
    }

    /// Receive a message and update RX state accordingly.
    ///
    /// The method will return `false` if the message is detected to be duplicate, and therefore,
    /// the RX state had not been updated.
    ///
    /// `with_rollover` selects how "forward" vs "behind" is computed:
    /// - `false` (unicast): plain numeric comparison —
    ///   the counter is monotonic and does not roll over within a session.
    /// - `true` (group): modular comparison — a counter is forward
    ///   iff `(msg_ctr - max_ctr) mod 2^32` falls in `[1, 2^31 - 1]`, otherwise behind.
    pub fn post_recv(&mut self, msg_ctr: u32, is_encrypted: bool, with_rollover: bool) -> bool {
        if msg_ctr == self.max_ctr {
            // Duplicate
            return false;
        }

        let (is_forward, udiff) = if with_rollover {
            let fwd = msg_ctr.wrapping_sub(self.max_ctr);
            if fwd <= i32::MAX as u32 {
                (true, fwd)
            } else {
                (false, self.max_ctr.wrapping_sub(msg_ctr))
            }
        } else {
            (msg_ctr > self.max_ctr, msg_ctr.abs_diff(self.max_ctr))
        };

        if !is_forward && udiff <= MSG_RX_STATE_BITMAP_LEN {
            // In Rx Bitmap
            let index = udiff - 1;
            if self.contains(index) {
                // Duplicate
                false
            } else {
                self.insert(index);
                true
            }
        }
        // Now the leftover cases are the new counter is outside of the bitmap as well as max_ctr
        // in either direction. Encrypted only allows in forward direction
        else if is_forward {
            self.max_ctr = msg_ctr;
            if udiff < MSG_RX_STATE_BITMAP_LEN {
                // The previous max_ctr is now the actual counter
                self.ctr_bitmap <<= udiff;
                self.insert(udiff - 1);
            } else {
                self.ctr_bitmap = 0xffff;
            }
            true
        } else if !is_encrypted {
            // This is the case where the peer possibly rebooted and chose a different
            // random counter
            self.max_ctr = msg_ctr;
            self.ctr_bitmap = 0xffff;
            true
        } else {
            false
        }
    }
}

/// Max number of unique group message senders tracked for replay protection.
pub const MAX_GROUP_CTR_ENTRIES: usize = 16;

/// A per-(fabric_idx, source_node_id) message counter entry for group messages.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct GroupCtrEntry {
    fab_idx: u8,
    src_nodeid: u64,
    rx_ctr: RxCtrState,
    /// Monotonic "clock" for LRU eviction (higher = more recently used).
    last_used: u32,
}

/// Fixed-size store for group message counters that persists across ephemeral
/// group session lifetimes, preventing replay attacks.
///
/// When the store is full, the least-recently-used entry is evicted.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GroupCtrStore {
    entries: heapless::Vec<GroupCtrEntry, MAX_GROUP_CTR_ENTRIES>,
    clock: u32,
}

impl GroupCtrStore {
    pub const fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
            clock: 0,
        }
    }

    /// Validate and record a group message counter.
    ///
    /// Returns `true` if the message is new (not a duplicate), `false` if duplicate.
    /// On first message from a new (fab_idx, src_nodeid), trust-first: accept and create entry.
    pub fn post_recv(&mut self, fab_idx: u8, src_nodeid: u64, msg_ctr: u32) -> bool {
        self.clock = self.clock.wrapping_add(1);

        // Look for existing entry
        for entry in &mut self.entries {
            if entry.fab_idx == fab_idx && entry.src_nodeid == src_nodeid {
                entry.last_used = self.clock;
                // Group messages are always encrypted and use a rollover counter
                return entry.rx_ctr.post_recv(msg_ctr, true, true);
            }
        }

        // New sender — trust-first: accept and create entry
        let new_entry = GroupCtrEntry {
            fab_idx,
            src_nodeid,
            rx_ctr: RxCtrState::new(msg_ctr),
            last_used: self.clock,
        };

        if self.entries.len() < MAX_GROUP_CTR_ENTRIES {
            // Safe: we checked len < capacity
            unwrap!(self.entries.push(new_entry));
        } else {
            // Evict LRU entry
            let lru_idx = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(i, _)| i)
                .unwrap(); // entries is non-empty since len == MAX
            self.entries[lru_idx] = new_entry;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::RxCtrState;

    const ENCRYPTED: bool = true;
    const NOT_ENCRYPTED: bool = false;

    fn assert_ndup(b: bool) {
        assert!(b);
    }

    fn assert_dup(b: bool) {
        assert!(!b);
    }

    #[test]
    fn new_msg_ctr() {
        let mut s = RxCtrState::new(101);

        assert_ndup(s.post_recv(103, ENCRYPTED, false));
        assert_ndup(s.post_recv(104, ENCRYPTED, false));
        assert_ndup(s.post_recv(106, ENCRYPTED, false));
        assert_eq!(s.max_ctr, 106);
        assert_eq!(s.ctr_bitmap, 0b1111_1111_1111_0110);

        assert_ndup(s.post_recv(118, NOT_ENCRYPTED, false));
        assert_eq!(s.ctr_bitmap, 0b0110_1000_0000_0000);
        assert_ndup(s.post_recv(119, NOT_ENCRYPTED, false));
        assert_ndup(s.post_recv(121, NOT_ENCRYPTED, false));
        assert_eq!(s.ctr_bitmap, 0b0100_0000_0000_0110);
    }

    #[test]
    fn dup_max_ctr() {
        let mut s = RxCtrState::new(101);

        assert_ndup(s.post_recv(103, ENCRYPTED, false));
        assert_dup(s.post_recv(103, ENCRYPTED, false));
        assert_dup(s.post_recv(103, NOT_ENCRYPTED, false));

        assert_eq!(s.max_ctr, 103);
        assert_eq!(s.ctr_bitmap, 0b1111_1111_1111_1110);
    }

    #[test]
    fn dup_in_rx_bitmap() {
        let mut ctr = 101;
        let mut s = RxCtrState::new(101);
        for _ in 1..8 {
            ctr += 2;
            assert_ndup(s.post_recv(ctr, ENCRYPTED, false));
        }
        assert_ndup(s.post_recv(116, ENCRYPTED, false));
        assert_ndup(s.post_recv(117, ENCRYPTED, false));
        assert_eq!(s.max_ctr, 117);
        assert_eq!(s.ctr_bitmap, 0b1010_1010_1010_1011);

        // duplicate on the left corner
        assert_dup(s.post_recv(101, ENCRYPTED, false));
        assert_dup(s.post_recv(101, NOT_ENCRYPTED, false));

        // duplicate on the right corner
        assert_dup(s.post_recv(116, ENCRYPTED, false));
        assert_dup(s.post_recv(116, NOT_ENCRYPTED, false));

        // valid insert
        assert_ndup(s.post_recv(102, ENCRYPTED, false));
        assert_dup(s.post_recv(102, ENCRYPTED, false));
        assert_eq!(s.ctr_bitmap, 0b1110_1010_1010_1011);
    }

    #[test]
    fn valid_corners_in_rx_bitmap() {
        let mut ctr = 102;
        let mut s = RxCtrState::new(101);
        for _ in 1..9 {
            ctr += 2;
            assert_ndup(s.post_recv(ctr, ENCRYPTED, false));
        }
        assert_eq!(s.max_ctr, 118);
        assert_eq!(s.ctr_bitmap, 0b0010_1010_1010_1010);

        // valid insert on the left corner
        assert_ndup(s.post_recv(102, ENCRYPTED, false));
        assert_eq!(s.ctr_bitmap, 0b1010_1010_1010_1010);

        // valid insert on the right corner
        assert_ndup(s.post_recv(117, ENCRYPTED, false));
        assert_eq!(s.ctr_bitmap, 0b1010_1010_1010_1011);
    }

    #[test]
    fn no_panic_on_large_diff() {
        // Regression: previously `(msg_ctr as i32) - (max as i32)` overflowed in
        // debug when one side was around `i32::MIN as u32`.
        let mut s = RxCtrState::new(1);
        assert_ndup(s.post_recv(0x8000_0000, ENCRYPTED, false));

        let mut s = RxCtrState::new(0x8000_0000);
        assert_dup(s.post_recv(1, ENCRYPTED, false));
    }

    #[test]
    fn encrypted_wraparound() {
        let mut s = RxCtrState::new(65534);

        assert_ndup(s.post_recv(65535, ENCRYPTED, false));
        assert_ndup(s.post_recv(65536, ENCRYPTED, false));
        assert_dup(s.post_recv(0, ENCRYPTED, false));
    }

    #[test]
    fn unencrypted_wraparound() {
        let mut s = RxCtrState::new(65534);

        assert_ndup(s.post_recv(65536, NOT_ENCRYPTED, false));
        assert_ndup(s.post_recv(0, NOT_ENCRYPTED, false));
    }

    #[test]
    fn unencrypted_device_reboot() {
        info!("Sub 65532 is {:?}", 1_u16.overflowing_sub(65532));
        info!("Sub 65535 is {:?}", 1_u16.overflowing_sub(65535));
        info!("Sub 11-13 is {:?}", 11_u32.wrapping_sub(13_u32) as i32);
        info!("Sub regular is {:?}", 2000_u16.overflowing_sub(1998));
        let mut s = RxCtrState::new(20010);

        assert_ndup(s.post_recv(20011, NOT_ENCRYPTED, false));
        assert_ndup(s.post_recv(0, NOT_ENCRYPTED, false));
    }

    mod group_ctr {
        use super::super::GroupCtrStore;

        #[test]
        fn trust_first_accepts_new_sender() {
            let mut store = GroupCtrStore::new();
            assert!(store.post_recv(1, 0x1111, 100));
        }

        #[test]
        fn rejects_duplicate_counter() {
            let mut store = GroupCtrStore::new();
            assert!(store.post_recv(1, 0x1111, 100));
            assert!(!store.post_recv(1, 0x1111, 100));
        }

        #[test]
        fn accepts_incrementing_counters() {
            let mut store = GroupCtrStore::new();
            assert!(store.post_recv(1, 0x1111, 100));
            assert!(store.post_recv(1, 0x1111, 101));
            assert!(store.post_recv(1, 0x1111, 102));
        }

        #[test]
        fn separate_tracking_per_sender() {
            let mut store = GroupCtrStore::new();
            assert!(store.post_recv(1, 0x1111, 100));
            assert!(store.post_recv(1, 0x2222, 100)); // different src_nodeid
            assert!(store.post_recv(2, 0x1111, 100)); // different fab_idx
        }

        #[test]
        fn rollover_accepts_counter_past_u32_max() {
            // Spec §4.6.5.2.2: forward iff (msg - max) mod 2^32 in [1, 2^31 - 1].
            // max near u32::MAX, msg just past zero is still forward.
            let mut store = GroupCtrStore::new();
            assert!(store.post_recv(1, 0x1111, u32::MAX - 1));
            assert!(store.post_recv(1, 0x1111, u32::MAX));
            assert!(store.post_recv(1, 0x1111, 0)); // rolls over
            assert!(store.post_recv(1, 0x1111, 5));
            assert!(!store.post_recv(1, 0x1111, 5)); // duplicate after rollover
        }

        #[test]
        fn rollover_rejects_behind_window_as_replay() {
            // After advancing past rollover, a counter that is "behind" in the
            // modular sense (e.g. the previous max) is a replay → reject.
            let mut store = GroupCtrStore::new();
            assert!(store.post_recv(1, 0x1111, u32::MAX - 10));
            assert!(store.post_recv(1, 0x1111, 100)); // forward by 111 across rollover
                                                      // u32::MAX - 10 is now behind by 111 (mod 2^32), outside bitmap → duplicate.
            assert!(!store.post_recv(1, 0x1111, u32::MAX - 10));
        }

        #[test]
        fn rollover_bitmap_window_across_boundary() {
            // Bitmap should still catch duplicates when the window straddles
            // the u32 rollover boundary.
            let mut store = GroupCtrStore::new();
            assert!(store.post_recv(1, 0x1111, u32::MAX - 5));
            assert!(store.post_recv(1, 0x1111, 2)); // max is now 2; old max is 8 behind (within bitmap)
                                                    // Counter u32::MAX - 5 is within the new bitmap (8 behind, mod 2^32) and seen → duplicate.
            assert!(!store.post_recv(1, 0x1111, u32::MAX - 5));
            // A neighbouring counter within window that was NOT seen → accepted.
            assert!(store.post_recv(1, 0x1111, u32::MAX - 4));
        }

        #[test]
        fn rollover_antipode_is_behind() {
            // Spec puts max + 2^31 exactly into the "behind" half-space.
            let mut store = GroupCtrStore::new();
            assert!(store.post_recv(1, 0x1111, 100));
            // 100 + 0x8000_0000 is at the antipode → behind by 2^31, far outside
            // the bitmap → duplicate.
            assert!(!store.post_recv(1, 0x1111, 100u32.wrapping_add(0x8000_0000)));
        }

        #[test]
        fn evicts_lru_when_full() {
            let mut store = GroupCtrStore::new();
            // Fill up all slots
            for i in 0..super::super::MAX_GROUP_CTR_ENTRIES {
                assert!(store.post_recv(1, i as u64, 100));
            }
            // One more should evict the LRU (slot 0 = src_nodeid 0)
            assert!(store.post_recv(1, 0xFFFF, 200));
            // The evicted sender is now unknown — trust-first accepts it again
            assert!(store.post_recv(1, 0, 100));
        }
    }
}
