/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

use embassy_time::Instant;

use crate::dm::clusters::basic_info::BasicInfoConfig;
use crate::error::{Error, ErrorCode};

use super::{plain_hdr::PlainHdr, proto_hdr::ProtoHdr};

/// Emit an MRP-diagnostic log message.
///
/// A number of log call sites in the transport layer fire in normal
/// operation on lossy channels — packet retransmissions, duplicate
/// packet drops, retrans / ACK mismatches, orphaned or late packets.
/// They are useful when investigating packet loss on Thread or Wi-Fi
/// but are noise otherwise.
///
/// This macro:
/// - expands to [`debug!`] by default — keeping this noise out of a
///   typical `info`-level log,
/// - expands to [`warn!`] when the `log-mrp` Cargo feature is
///   enabled — making these events visible under any reasonable log
///   filter (including the compile-time filters used by `defmt` and
///   `esp-println` in MCU firmwares).
///
/// Terminal / genuinely-erroneous conditions caused by noise (e.g.
/// "Too many retransmissions. Giving up") intentionally stay at
/// [`error!`] and are not routed through this macro.
macro_rules! mrp_log {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        #[cfg(feature = "log-mrp")]
        { warn!($s $(, $x)*); }
        #[cfg(not(feature = "log-mrp"))]
        { debug!($s $(, $x)*); }
    }};
}

pub(crate) use mrp_log;

//const MRP_STANDALONE_ACK_TIMEOUT_MS: u64 = 200;   // TODO: Use to pro-actively send ACKs
pub(crate) const MRP_BASE_RETRY_INTERVAL_MS: u32 = 300;
/// The length of the retransmission ladder: a reliable message goes out once
/// and is then retransmitted up to this many times, so it can be on the wire
/// `MRP_MAX_TRANSMISSIONS + 1` times in total. The Matter default of 5
/// counts total attempts, but the spec leaves the number to the sender.
const MRP_MAX_TRANSMISSIONS: u16 = 5;
const MRP_BACKOFF_THRESHOLD: u16 = 1;
const MRP_BACKOFF_BASE: (u64, u64) = (16, 10); // 1.6
const MRP_BACKOFF_JITTER: (u64, u64) = (25, 100); // 0.25
const MRP_BACKOFF_MARGIN: (u64, u64) = (11, 10); // 1.1
const MRP_JITTER_RAND_MAX: u8 = u8::MAX;

/// Allowance for the peer's upper layer to actually process a request, on top of
/// the time the message spends being retransmitted on the wire.
pub(crate) const MRP_EXPECTED_PROCESSING_MS: u64 = 30_000;

/// Fallback for `MRP_SESSION_IDLE_INTERVAL` when neither the peer nor our
/// own `BasicInfoConfig::sii` advertised a value. Matches the docstring
/// default on [`BasicInfoConfig::sii`].
const MRP_DEFAULT_IDLE_INTERVAL_MS: u32 = 5000;

/// Fallback for `MRP_SESSION_ACTIVE_THRESHOLD` when the peer didn't
/// advertise one. Matter Core spec default.
const MRP_DEFAULT_ACTIVE_THRESHOLD_MS: u16 = 4000;

/// Resolve the default peer-MRP timing for a freshly-created [`Session`]
/// from our own [`BasicInfoConfig`] (Matter Core spec): a peer
/// that never advertises `session_parameters` will be addressed using
/// our own SAI / SII as a reasonable approximation. Returns
/// `(active_interval_ms, idle_interval_ms, active_threshold_ms)`.
///
/// `Some(0)` is treated identically to `None` — an interval of zero
/// would collapse the MRP backoff to a tight retransmit loop and is
/// never a valid configuration, so the fallback constants are used
/// instead.
///
/// [`Session`]: crate::transport::session::Session
pub fn default_peer_mrp_params(dev_det: &BasicInfoConfig<'_>) -> (u32, u32, u16) {
    (
        dev_det
            .sai
            .filter(|&v| v > 0)
            .unwrap_or(MRP_BASE_RETRY_INTERVAL_MS),
        dev_det
            .sii
            .filter(|&v| v > 0)
            .unwrap_or(MRP_DEFAULT_IDLE_INTERVAL_MS),
        MRP_DEFAULT_ACTIVE_THRESHOLD_MS,
    )
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RetransEntry {
    /// The retransmission delay interval in milliseconds
    base_delay_interval_ms: u32,
    // The msg counter that we are waiting to be acknowledged
    msg_ctr: u32,
    // The retransmission counter
    counter: u16,
}

impl RetransEntry {
    pub fn new(base_delay_interval_ms: Option<u32>, msg_ctr: u32) -> Self {
        // Defence-in-depth: a future code path that bypasses the
        // peer-side / dev_det-side zero filters must never collapse the
        // backoff into a zero-delay retransmit loop. Treat `Some(0)`
        // identically to `None`.
        let base_delay_interval_ms = base_delay_interval_ms
            .filter(|&v| v > 0)
            .unwrap_or(MRP_BASE_RETRY_INTERVAL_MS);
        Self {
            base_delay_interval_ms,
            msg_ctr,
            counter: 0,
        }
    }

    pub fn get_msg_ctr(&self) -> u32 {
        self.msg_ctr
    }

    /// Return how much to delay before (re)transmitting the message
    /// based on the number of re-transmissions so far
    pub fn delay_ms(&self, jitter_rand: u8) -> u64 {
        self.delay_ms_counter(self.counter, jitter_rand)
    }

    /// Return how much to delay before (re)transmitting the message
    /// based on the provided number of re-transmissions so far
    pub fn delay_ms_counter(&self, counter: u16, jitter_rand: u8) -> u64 {
        Self::backoff_ms(self.base_delay_interval_ms, counter, jitter_rand)
    }

    pub fn pre_send(&mut self, ctr: u32) -> Result<(), Error> {
        if self.msg_ctr == ctr {
            if self.counter < MRP_MAX_TRANSMISSIONS {
                self.counter += 1;
                Ok(())
            } else {
                Err(ErrorCode::TxTimeout.into())
            }
        } else {
            // This indicates there was some existing entry for same sess-id/exch-id, which shouldn't happen
            panic!("Previous retrans entry for this exchange already exists");
        }
    }

    /// The delay before the `counter`-th (re)transmission of a message whose base
    /// retry interval is `base_interval_ms`, per the Matter Core Specification's
    /// backoff equation.
    fn backoff_ms(base_interval_ms: u32, counter: u16, jitter_rand: u8) -> u64 {
        let mut delay = base_interval_ms as u64 * MRP_BACKOFF_MARGIN.0 / MRP_BACKOFF_MARGIN.1;

        if counter > MRP_BACKOFF_THRESHOLD {
            for _ in 0..counter - MRP_BACKOFF_THRESHOLD {
                delay = delay * MRP_BACKOFF_BASE.0 / MRP_BACKOFF_BASE.1;
            }
        }

        delay + (delay * jitter_rand as u64 * MRP_BACKOFF_JITTER.0) / (255 * MRP_BACKOFF_JITTER.1)
    }

    /// How long a sender can keep retransmitting a message before it runs out of
    /// attempts - the *sum* of the whole backoff ladder with maximum jitter, not
    /// the length of its last step.
    pub fn retransmission_timeout_ms(
        active_interval_ms: u32,
        idle_interval_ms: u32,
        active_threshold_ms: u16,
        active_only: bool,
    ) -> u64 {
        let mut timeout = 0;

        for counter in 0..MRP_MAX_TRANSMISSIONS {
            let base_interval_ms = if active_only || timeout < active_threshold_ms as u64 {
                active_interval_ms
            } else {
                idle_interval_ms
            };

            timeout += Self::backoff_ms(base_interval_ms, counter, MRP_JITTER_RAND_MAX);
        }

        timeout
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AckEntry {
    // The msg counter that we should acknowledge
    pub(crate) msg_ctr: u32,
    // Whether the message was acknowledged at least once
    pub(crate) acknowledged: bool,
}

impl AckEntry {
    pub fn new(msg_ctr: u32) -> Result<Self, Error> {
        Ok(Self {
            msg_ctr,
            acknowledged: false,
        })
    }

    pub fn get_msg_ctr(&self) -> u32 {
        self.msg_ctr
    }
}

#[derive(Default, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReliableMessage {
    pub(crate) retrans: Option<RetransEntry>,
    pub(crate) ack: Option<AckEntry>,
    pub(crate) received_at: Option<Instant>,
}

impl ReliableMessage {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn is_retrans_pending(&self) -> bool {
        self.retrans.is_some()
    }

    pub fn is_ack_pending(&self) -> bool {
        self.ack
            .as_ref()
            .map(|ack| !ack.acknowledged)
            .unwrap_or(false)
    }

    pub fn has_rx_timed_out(&self, timeout_ms: u64) -> bool {
        self.received_at
            .map(|received_at| {
                let deadline =
                    received_at.saturating_add(embassy_time::Duration::from_millis(timeout_ms));
                Instant::now() >= deadline
            })
            .unwrap_or(false)
    }

    pub fn pre_send(
        &mut self,
        tx_plain: &PlainHdr,
        tx_proto: &mut ProtoHdr,
        session_active_interval_ms: Option<u32>,
        // TODO: Need to make use of it in future,
        // once we detect idle vs active devices
        _session_idle_interval_ms: Option<u32>,
    ) -> Result<(), Error> {
        // Check if any acknowledgements are pending for this exchange,
        if let Some(ack) = &mut self.ack {
            // if so, piggy back in the encoded header here
            tx_proto.set_ack(Some(ack.get_msg_ctr()));
            ack.acknowledged = true;
        }

        if tx_proto.is_reliable() {
            if let Some(retrans) = &mut self.retrans {
                if retrans.pre_send(tx_plain.ctr).is_err() {
                    // Too many retransmissions, give up
                    error!(
                        "Packet {}{}: Too many retransmissions. Giving up",
                        tx_plain, tx_proto
                    );

                    self.retrans = None;
                    self.ack = None;

                    // The error is propagated rather than swallowed: clearing
                    // `retrans` leaves no pending retransmission, which is exactly
                    // what a peer *acknowledging* the message also looks like.
                    Err(ErrorCode::TxTimeout)?;
                }
            } else {
                self.retrans = Some(RetransEntry::new(session_active_interval_ms, tx_plain.ctr));
            }
        }

        self.received_at = None;

        Ok(())
    }

    /// This method will update the state of the rentransmission and ACK tables
    /// with the data from the incoming packet.
    ///
    /// The method will return `Ok` if the message needs to be processed by the
    /// exchange layer, and an error if it needs to be dropped.
    ///
    /// A note about Message ACKs, it is a bit asymmetric in the sense that:
    /// - there can be only one pending ACK per exchange (so this is per-exchange)
    /// - there can be only one pending retransmission per exchange (so this is per-exchange)
    /// - duplicate detection should happen per session (obviously), so that part is per-session
    pub fn post_recv(&mut self, rx_plain: &PlainHdr, rx_proto: &ProtoHdr) -> Result<(), Error> {
        if let Some(ack_msg_ctr) = rx_proto.get_ack() {
            // Handle received Acks
            if let Some(entry) = &self.retrans {
                if entry.get_msg_ctr() != ack_msg_ctr {
                    mrp_log!("Mismatch in retrans-table's msg counter and received msg counter: received {:x}, expected {:x}.", ack_msg_ctr, entry.msg_ctr);

                    // This can actually happen on a noisy channel, where we've just sent a reply to a message
                    // - yet - the other side is still retransmitting the original message and thus acknowledging
                    // an earlier counter we've sent.

                    // In this case, we should ignore the ACK and not process this message any further, as it is
                    // a duplicate.
                    Err(ErrorCode::Duplicate)?;
                }

                self.retrans = None;
                self.ack = None;
            }
        }

        if rx_proto.is_reliable() {
            if let Some(ack) = &self.ack {
                // This indicates there was some existing entry for same sess-id/exch-id, which shouldnt happen
                // TODO: As per the spec if this happens, we need to send out the previous ACK and note this new ACK
                error!(
                    "Previous ACK entry {:x} for this exchange already exists",
                    ack.get_msg_ctr()
                );
            }

            self.ack = Some(AckEntry::new(rx_plain.ctr)?);
        }

        self.received_at = Some(Instant::now());

        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A sender gets exactly `MRP_MAX_TRANSMISSIONS` attempts, and the one after
    /// that fails with `TxTimeout` rather than silently succeeding.
    ///
    /// The give-up used to be swallowed, which is indistinguishable from the peer
    /// having acknowledged: the caller was told the message went out and then
    /// waited a whole receive timeout for an answer that could never come.
    #[test]
    fn retrans_entry_gives_up_after_max_transmissions() {
        const CTR: u32 = 42;

        let mut entry = RetransEntry::new(Some(300), CTR);

        for attempt in 0..MRP_MAX_TRANSMISSIONS {
            assert!(
                entry.pre_send(CTR).is_ok(),
                "transmission {attempt} should be allowed"
            );
        }

        let err = unwrap!(entry.pre_send(CTR).err());
        assert_eq!(err.code(), ErrorCode::TxTimeout);

        // ... and it keeps failing rather than resetting.
        assert_eq!(
            unwrap!(entry.pre_send(CTR).err()).code(),
            ErrorCode::TxTimeout
        );
    }

    /// The backoff grows: linear up to `MRP_BACKOFF_THRESHOLD`, exponential after.
    #[test]
    fn backoff_is_linear_then_exponential() {
        let step = |counter| RetransEntry::backoff_ms(300, counter, MRP_JITTER_RAND_MAX);

        // Up to the threshold the interval does not grow.
        assert_eq!(step(0), step(MRP_BACKOFF_THRESHOLD));

        // Beyond it, each step grows by the backoff base.
        for counter in MRP_BACKOFF_THRESHOLD + 1..MRP_MAX_TRANSMISSIONS {
            assert!(
                step(counter) > step(counter - 1),
                "step {counter} should exceed step {}",
                counter - 1
            );
        }
    }

    /// The retransmission timeout is the *sum* of the ladder, not the length of
    /// its last step - the distinction the receive timeout is built on.
    #[test]
    fn retransmission_timeout_sums_the_whole_ladder() {
        let expected: u64 = (0..MRP_MAX_TRANSMISSIONS)
            .map(|counter| RetransEntry::backoff_ms(300, counter, MRP_JITTER_RAND_MAX))
            .sum();

        let actual = RetransEntry::retransmission_timeout_ms(300, 300, 0, true);
        assert_eq!(actual, expected);

        // Strictly greater than any single step, which is what a "single step"
        // regression would collapse it to.
        let longest = RetransEntry::backoff_ms(300, MRP_MAX_TRANSMISSIONS - 1, MRP_JITTER_RAND_MAX);
        assert!(actual > longest);
    }

    /// A sender that may be talking to a sleeping peer paces the ladder by the
    /// idle interval once the accumulated wait leaves the active threshold, so it
    /// is more patient than an always-active one.
    #[test]
    fn retransmission_timeout_falls_back_to_the_idle_interval() {
        let active_only = RetransEntry::retransmission_timeout_ms(300, 5000, 4000, true);

        // With a threshold of zero, every step is paced by the idle interval.
        let idle = RetransEntry::retransmission_timeout_ms(300, 5000, 0, false);
        assert!(idle > active_only);

        // With a threshold beyond the whole ladder, none of them are.
        let active = RetransEntry::retransmission_timeout_ms(300, 5000, u16::MAX, false);
        assert_eq!(active, active_only);
    }

    /// A plain header carrying the given message counter.
    fn plain(ctr: u32) -> PlainHdr {
        let mut hdr = PlainHdr::new();
        hdr.ctr = ctr;
        hdr
    }

    /// A proto header with the R flag set (or not).
    fn proto(reliable: bool) -> ProtoHdr {
        let mut hdr = ProtoHdr::new();
        if reliable {
            hdr.set_reliable();
        }
        hdr
    }

    /// Sending a reliable message records a retransmission entry for its
    /// counter; sending an unreliable one records nothing.
    #[test]
    fn pre_send_arms_retrans_only_for_reliable_messages() {
        let mut mrp = ReliableMessage::new();

        let mut tx_proto = proto(false);
        unwrap!(mrp.pre_send(&plain(10), &mut tx_proto, Some(300), None));
        assert!(!mrp.is_retrans_pending());
        assert!(tx_proto.get_ack().is_none());

        let mut tx_proto = proto(true);
        unwrap!(mrp.pre_send(&plain(11), &mut tx_proto, Some(300), None));
        assert!(mrp.is_retrans_pending());
        assert_eq!(unwrap!(mrp.retrans.as_ref()).get_msg_ctr(), 11);
        assert!(tx_proto.is_reliable());
    }

    /// A pending ACK is piggybacked onto the next outgoing message: the A flag
    /// carries the counter, and the ACK is no longer reported as pending. The
    /// entry itself is only dropped by `post_recv`, so every later send keeps
    /// piggybacking the same counter.
    #[test]
    fn pre_send_piggybacks_pending_ack() {
        let mut mrp = ReliableMessage::new();
        unwrap!(mrp.post_recv(&plain(7), &proto(true)));
        assert!(mrp.is_ack_pending());

        let mut tx_proto = proto(false);
        unwrap!(mrp.pre_send(&plain(1), &mut tx_proto, Some(300), None));
        assert_eq!(tx_proto.get_ack(), Some(7));
        assert!(!mrp.is_ack_pending());

        let mut tx_proto = proto(false);
        unwrap!(mrp.pre_send(&plain(2), &mut tx_proto, Some(300), None));
        assert_eq!(tx_proto.get_ack(), Some(7));
        assert!(!mrp.is_ack_pending());
    }

    /// Re-sending the same counter while a retransmission is pending is a
    /// retransmission: the entry is kept and its attempt counter advances, and
    /// once the attempts run out the send fails and both tables are cleared.
    #[test]
    fn pre_send_same_counter_is_a_retransmission_until_attempts_run_out() {
        let mut mrp = ReliableMessage::new();
        unwrap!(mrp.post_recv(&plain(3), &proto(true)));

        let tx_plain = plain(20);

        // The first send arms the entry; each further one is a retransmission.
        unwrap!(mrp.pre_send(&tx_plain, &mut proto(true), Some(300), None));
        for _ in 0..MRP_MAX_TRANSMISSIONS {
            unwrap!(mrp.pre_send(&tx_plain, &mut proto(true), Some(300), None));
            assert!(mrp.is_retrans_pending());
        }
        assert_eq!(unwrap!(mrp.retrans.as_ref()).counter, MRP_MAX_TRANSMISSIONS);

        let err = unwrap!(mrp
            .pre_send(&tx_plain, &mut proto(true), Some(300), None)
            .err());
        assert_eq!(err.code(), ErrorCode::TxTimeout);
        assert!(!mrp.is_retrans_pending());
        assert!(mrp.ack.is_none());
    }

    /// A reliable send with a *different* counter while a retransmission is
    /// still pending is a caller bug and panics rather than silently replacing
    /// the pending entry.
    #[test]
    #[should_panic(expected = "Previous retrans entry")]
    fn pre_send_different_counter_while_retrans_pending_panics() {
        let mut mrp = ReliableMessage::new();
        unwrap!(mrp.pre_send(&plain(20), &mut proto(true), Some(300), None));
        let _ = mrp.pre_send(&plain(21), &mut proto(true), Some(300), None);
    }

    /// An incoming ACK for the pending counter clears the retransmission (and
    /// any piggyback ACK entry); one for another counter is a late duplicate
    /// that leaves the retransmission pending.
    #[test]
    fn post_recv_ack_must_match_pending_retrans() {
        let mut mrp = ReliableMessage::new();
        unwrap!(mrp.pre_send(&plain(20), &mut proto(true), Some(300), None));

        let mut rx_proto = proto(false);
        rx_proto.set_ack(Some(19));
        let err = unwrap!(mrp.post_recv(&plain(5), &rx_proto).err());
        assert_eq!(err.code(), ErrorCode::Duplicate);
        assert!(mrp.is_retrans_pending());

        rx_proto.set_ack(Some(20));
        unwrap!(mrp.post_recv(&plain(6), &rx_proto));
        assert!(!mrp.is_retrans_pending());
        assert!(mrp.ack.is_none());
    }

    /// An ACK arriving when nothing is being retransmitted is simply ignored.
    #[test]
    fn post_recv_ack_without_pending_retrans_is_ignored() {
        let mut mrp = ReliableMessage::new();

        let mut rx_proto = proto(false);
        rx_proto.set_ack(Some(99));
        unwrap!(mrp.post_recv(&plain(5), &rx_proto));
        assert!(!mrp.is_retrans_pending());
        assert!(!mrp.is_ack_pending());
    }

    /// A reliable incoming message arms an ACK for its counter and stamps the
    /// receive time; an unreliable one does neither.
    #[test]
    fn post_recv_reliable_message_arms_ack() {
        let mut mrp = ReliableMessage::new();

        unwrap!(mrp.post_recv(&plain(5), &proto(false)));
        assert!(!mrp.is_ack_pending());
        assert!(mrp.received_at.is_some());

        unwrap!(mrp.post_recv(&plain(6), &proto(true)));
        assert!(mrp.is_ack_pending());
        assert_eq!(unwrap!(mrp.ack.as_ref()).get_msg_ctr(), 6);
    }

    /// A retransmitted (or newer) reliable message re-arms the ACK, even after
    /// the previous one was already piggybacked out.
    #[test]
    fn post_recv_duplicate_reliable_message_rearms_ack() {
        let mut mrp = ReliableMessage::new();

        unwrap!(mrp.post_recv(&plain(6), &proto(true)));
        unwrap!(mrp.pre_send(&plain(1), &mut proto(false), Some(300), None));
        assert!(!mrp.is_ack_pending());

        unwrap!(mrp.post_recv(&plain(6), &proto(true)));
        assert!(mrp.is_ack_pending());
        assert_eq!(unwrap!(mrp.ack.as_ref()).get_msg_ctr(), 6);

        unwrap!(mrp.post_recv(&plain(7), &proto(true)));
        assert!(mrp.is_ack_pending());
        assert_eq!(unwrap!(mrp.ack.as_ref()).get_msg_ctr(), 7);
    }

    /// The receive timeout is measured from the last receive: nothing received
    /// means no timeout, a zero timeout expires at once, and a send clears the
    /// stamp again.
    #[test]
    fn has_rx_timed_out_boundaries() {
        let mut mrp = ReliableMessage::new();
        assert!(!mrp.has_rx_timed_out(0));

        mrp.received_at = Some(Instant::from_ticks(0));
        assert!(mrp.has_rx_timed_out(0));

        // A deadline that saturates at the end of time never arrives.
        mrp.received_at = Some(Instant::MAX);
        assert!(!mrp.has_rx_timed_out(0));
        mrp.received_at = Some(Instant::from_ticks(0));
        assert!(!mrp.has_rx_timed_out(1 << 40));

        unwrap!(mrp.pre_send(&plain(1), &mut proto(false), Some(300), None));
        assert!(mrp.received_at.is_none());
        assert!(!mrp.has_rx_timed_out(0));
    }

    /// The jitter adds between 0 (`jitter_rand == 0`) and a quarter
    /// (`jitter_rand == 255`) of the base delay, and grows with the random.
    #[test]
    fn delay_ms_jitter_stays_within_band() {
        let entry = RetransEntry::new(Some(300), 1);

        let no_jitter = entry.delay_ms(0);
        let max_jitter = entry.delay_ms(255);

        // First transmission: only the margin applies.
        assert_eq!(no_jitter, 300 * MRP_BACKOFF_MARGIN.0 / MRP_BACKOFF_MARGIN.1);
        assert_eq!(
            max_jitter,
            no_jitter + no_jitter * MRP_BACKOFF_JITTER.0 / MRP_BACKOFF_JITTER.1
        );

        let mid_jitter = entry.delay_ms(128);
        assert!(no_jitter < mid_jitter && mid_jitter < max_jitter);
    }

    /// `None` and `Some(0)` both fall back to the default base interval, so a
    /// zero interval can never collapse the ladder into a tight loop.
    #[test]
    fn retrans_entry_zero_interval_falls_back_to_default() {
        let default = RetransEntry::new(None, 1).delay_ms(0);

        assert_eq!(RetransEntry::new(Some(0), 1).delay_ms(0), default);
        assert_eq!(
            RetransEntry::new(Some(MRP_BASE_RETRY_INTERVAL_MS), 1).delay_ms(0),
            default
        );
        assert!(RetransEntry::new(Some(1000), 1).delay_ms(0) > default);
    }

    /// The peer-MRP defaults for a fresh session come from our own SAI / SII,
    /// with zero and absent values replaced by the built-in fallbacks.
    #[test]
    fn default_peer_mrp_params_derive_from_dev_det() {
        use crate::dm::devices::test::TEST_DEV_DET;

        // The test device advertises neither.
        assert_eq!(
            default_peer_mrp_params(&TEST_DEV_DET),
            (
                MRP_BASE_RETRY_INTERVAL_MS,
                MRP_DEFAULT_IDLE_INTERVAL_MS,
                MRP_DEFAULT_ACTIVE_THRESHOLD_MS
            )
        );

        let dev_det = BasicInfoConfig {
            sai: Some(500),
            sii: Some(0),
            ..TEST_DEV_DET
        };
        assert_eq!(
            default_peer_mrp_params(&dev_det),
            (
                500,
                MRP_DEFAULT_IDLE_INTERVAL_MS,
                MRP_DEFAULT_ACTIVE_THRESHOLD_MS
            )
        );

        let dev_det = BasicInfoConfig {
            sai: None,
            sii: Some(7000),
            ..TEST_DEV_DET
        };
        assert_eq!(
            default_peer_mrp_params(&dev_det),
            (
                MRP_BASE_RETRY_INTERVAL_MS,
                7000,
                MRP_DEFAULT_ACTIVE_THRESHOLD_MS
            )
        );
    }

    /// Any counter can be acknowledged, and a fresh entry is not yet
    /// acknowledged.
    #[test]
    fn ack_entry_accepts_any_counter() {
        for ctr in [0, 1, u32::MAX] {
            let entry = unwrap!(AckEntry::new(ctr));
            assert_eq!(entry.get_msg_ctr(), ctr);
            assert!(!entry.acknowledged);
        }
    }
}
