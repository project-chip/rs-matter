/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

use core::cmp::min;
use core::num::Wrapping;

use embassy_time::{Duration, Instant};

use log::{info, warn};

use crate::error::{Error, ErrorCode};
use crate::transport::network::btp::session::packet::{HandshakeReq, HandshakeResp};
use crate::transport::network::btp::{GATT_HEADER_SIZE, MAX_MTU, MIN_MTU};
use crate::transport::network::{BtAddr, MAX_RX_PACKET_SIZE};
use crate::utils::init::{init, Init};
use crate::utils::storage::{RingBuf, WriteBuf};

use self::packet::BtpHdr;

mod packet;

/// Matter Core spec constant:
/// The maximum amount of time after receipt of a segment before a stand-alone ACK must be sent.
pub(crate) const BTP_ACK_TIMEOUT_SECS: u16 = BTP_CONN_IDLE_TIMEOUT_SECS / 2;
/// Matter Core spec constant:
/// The maximum amount of time no unique data has been sent over a BTP session before the
/// Central Device must close the BTP session.
pub(crate) const BTP_CONN_IDLE_TIMEOUT_SECS: u16 = 30;

/// Represents the three possible states of each BTP session
#[derive(Debug)]
enum SessionState {
    /// The session was just created as a result of a remote peer writing a BTP Handshake Request SDU
    /// to characteristic `C1`.
    New,
    /// After sending the BTP Handshake SDU, the remote peer now also subscribed to characteristic `C2`.
    Subscribed,
    /// The session is fully established and data can be exchanged, as we have sent (a.k.a. indicated)
    /// to the remote peer a BTP Handshake Response SDU, via characteristic `C2`.
    Running,
}

/// Represents the sending window of a BTP session, as per the Matter Core spec.
#[derive(Debug)]
struct SendWindow {
    /// The negotiated window size
    window_size: u8,
    /// The current level of the window. 0 means the window is completely full
    level: u8,
    /// The last sequence number sent
    last_sent_seq_num: u8,
    /// The instant when the last BTP segment was sent. `Instant::MAX` means no segment was received yet.
    sent_at: Instant,
    /// Whether the session is currently locked for sending
    sending: bool,
}

impl SendWindow {
    /// Initialize a new sending window with the provided window size
    const fn new(window_size: u8) -> Self {
        Self {
            window_size,
            level: window_size,
            last_sent_seq_num: 255,
            sent_at: Instant::MAX,
            sending: false,
        }
    }

    /// Update the sending window level when a new BTP segment had arrived,
    /// based on the ACK seq num in the incoming packet (if any).
    fn accept_incoming(&mut self, hdr: &BtpHdr) {
        let Some(ack_seq_num) = hdr.get_ack() else {
            return;
        };

        if self.last_sent_seq_num == ack_seq_num {
            self.level = self.window_size;
            self.sent_at = Instant::MAX;
        } else {
            // Two examples just to clarify the logic of computing `unacknowledged`:
            //
            // Example 1:
            // We got an ACK for a seq num which is smaller than the last one we have sent
            // - if we have sent i.e. sequence numbers [3, 4, 5, 6, 7]
            // - i.e. our `last_sent_seq_num` would be = 7
            // - ... and we got ACK = 5
            // ... the unacknowledged packets are [6, 7] = 2 of these
            // which is computed as 7 - 5 = 2
            // ... and `(Wrapping(last_sent_seq_num) - Wrapping(ack_seq_num)).0` obviously gives 2
            //
            // Example 2:
            // We got an ACK for a seq num which is bigger than the last one we have sent.
            // This might happen if the sequence number has wrapped around (which might well
            // happen, as it is only one byte).
            //
            // In this case, the the number of packets we have sent and which remain un-acknowledged
            // has to account for the wrapping of the sequence number.
            // I.e.
            // - if we have sent i.e. sequence numbers [254, 255, 0, 1, 2]
            // - i.e. our `last_sent_seq_num` would be = 2
            // - ... and we got ACK = 254
            // ... the unacknowledged packets are [255, 0, 2, 1] = 4 of these
            // which is computed as 255 - 254 + 2 + 1 = 4
            // ... and `(Wrapping(last_sent_seq_num) - Wrapping(ack_seq_num)).0` (non-)obviously gives 4 as well!

            let unacknowledged = (Wrapping(self.last_sent_seq_num) - Wrapping(ack_seq_num)).0;

            // Adjust our "fullness" level with the number of packets that have been acknowledged
            self.level = self.window_size - unacknowledged;
            self.sent_at = Instant::now();
        }
    }

    /// Return true if the sending window is full.
    ///
    /// A reference to the receiving window is necessary, because - as per the Matter Core spec -
    /// the window is considered also full at level = 1 if the receiving window does not have
    /// a pending ACK.
    fn is_full(&self, recv_window: &RecvWindow) -> bool {
        self.level == 0 || self.level == 1 && recv_window.ack_level == 0
    }

    /// Return the next sequence to be used when sending a BTP segment.
    fn next_seq_num(&self) -> u8 {
        self.last_sent_seq_num.wrapping_add(1)
    }

    /// Update the state of the window after sending a BTP segment.
    /// Basically decreases the window level, updates the next sequence num and
    /// records the current instant as the time when the last BTP segment was sent.
    fn post_send(&mut self) {
        self.level -= 1;
        self.last_sent_seq_num = self.last_sent_seq_num.wrapping_add(1);
        self.sent_at = Instant::now();
    }
}

/// Enough room for one full Matter message + one extra
const MAX_MESSAGE_SIZE: usize = MAX_RX_PACKET_SIZE * 2;

/// Represents the receiving window of a BTP session, as per the Matter Core spec.
#[derive(Debug)]
struct RecvWindow {
    /// A ring-buffer holding all received BTP segment' payloads, including not been fully processed yet
    buf: RingBuf<MAX_MESSAGE_SIZE>,
    /// The number of complete Matter messages (i.e. BTP SDU payloads) currently in the buffer
    buf_messages_ct: u8,
    /// The current level of the window. 0 means the window is completely full
    level: u8,
    /// The level of the window that would be re-gained when sending ACK for the sequence kept in `ack_seq`
    ack_level: u8,
    /// The sequence that should be ACKed. If `ack_level` is 0, this is not used.
    ack_seq: u8,
    /// The instant when the last BTP segment was received. `Instant::MAX` means no packet was received yet.
    received_at: Instant,
    /// The remaining length of the current SDU being received. Used for packet validity checking only.
    rem_msg_len: u16,
}

impl RecvWindow {
    /// Create an in-place initializer for a receiving window with the provided window size.
    pub fn init(window_size: u8) -> impl Init<Self> {
        init!(Self {
            buf <- RingBuf::init(),
            buf_messages_ct: 0,
            level: window_size,
            ack_level: 0,
            ack_seq: 255,
            received_at: Instant::MAX,
            rem_msg_len: 0,
        })
    }

    /// Process an incoming BTP segment, updating the state of the window accordingly.
    fn accept_incoming(&mut self, hdr: &BtpHdr, payload: &[u8], mtu: u16) -> Result<(), Error> {
        // Check received packet integrity, as per the Matter Core spec
        self.check_data_integrity(hdr, payload, mtu)?;

        if let Some(msg_len) = hdr.get_msg_len() {
            if msg_len <= mtu && !hdr.is_final() {
                warn!("RX data integrity failure: An SDU that fits in a single BTP segment must be final");
                Err(ErrorCode::InvalidData)?;
            }

            self.rem_msg_len = msg_len;

            if msg_len > 0 {
                if self.buf.free() >= core::mem::size_of::<u16>() {
                    // New SDU; skip 0-length ones as they do not contain Matter messages
                    self.buf.push(&u16::to_le_bytes(msg_len));
                } else {
                    warn!("RX data integrity failure: got more data when the ring-buffer is full. Is the other party overflowing our recv window?");
                    Err(ErrorCode::InvalidData)?;
                }
            }
        }

        if self.rem_msg_len < payload.len() as u16 {
            warn!("RX data integrity failure: Packet contains more data than the message length");
            Err(ErrorCode::InvalidData)?;
        }

        self.rem_msg_len -= payload.len() as u16;
        if hdr.is_final() && self.rem_msg_len > 0 {
            warn!(
                "RX data integrity failure: Packet is final but the message length is not reached"
            );
            Err(ErrorCode::InvalidData)?;
        }

        if self.buf.free() < payload.len() {
            warn!("RX data integrity failure: got more data when the ring-buffer is full. Is the other party overflowing our recv window?");
            Err(ErrorCode::InvalidData)?;
        }

        self.buf.push(payload);
        self.level -= 1;
        // Unwrap is safe because we are only processing BTP data segments here and they always have a sequence number
        self.ack_seq = hdr.get_seq().unwrap();
        self.ack_level += 1;
        self.received_at = Instant::now();

        if hdr.is_final() && !payload.is_empty() {
            self.buf_messages_ct += 1;
        }

        Ok(())
    }

    fn check_data_integrity(&self, hdr: &BtpHdr, payload: &[u8], mtu: u16) -> Result<(), Error> {
        if hdr.is_handshake() {
            warn!("RX data integrity failure: Handshake packets are not allowed here");
            return Err(ErrorCode::InvalidData.into());
        }

        if hdr.get_opcode().is_some() {
            warn!("RX data integrity failure: Data and standalone ACK packets must not have an opcode");
            return Err(ErrorCode::InvalidData.into());
        }

        if hdr.is_standalone_ack() {
            if !payload.is_empty() {
                warn!("RX data integrity failure: Standalone ACKs don't have a payload");
                return Err(ErrorCode::InvalidData.into());
            }
        } else {
            if hdr.get_msg_len().is_none() && !hdr.is_continue() && !hdr.is_final() {
                warn!("RX data integrity failure: Should have at least one of BEGINNING_SEGMENT/CONTINUE/ENDING_SEGMENT raised");
                return Err(ErrorCode::InvalidData.into());
            }

            if hdr.get_msg_len().is_some() && hdr.is_continue() {
                warn!("RX data integrity failure: Cannot have both BEGINNING_SEGMENT and CONTINUE raised");
                return Err(ErrorCode::InvalidData.into());
            }

            if !hdr.is_final() && payload.len() + hdr.len() != mtu as _ {
                warn!("RX data integrity failure: Non-final packets should have a size equal to the MTU size");
                return Err(ErrorCode::InvalidData.into());
            }
        }

        if hdr
            .get_seq()
            .map(|seq| self.ack_seq.wrapping_add(1) != seq)
            .unwrap_or(true)
        {
            warn!(
                "RX data integrity failure: Data packets must have a sequence number which is equal to the last one received + 1; expected={}, actual={:?}", 
                self.ack_seq.wrapping_add(1),
                hdr.get_seq());
            return Err(ErrorCode::InvalidData.into());
        }

        Ok(())
    }

    fn check_handshake_integrity(hdr: &BtpHdr) -> Result<(), Error> {
        if !hdr.is_handshake() // Data packets are not allowed here
            || !hdr.is_final() // Handshake packets must be final
            || !matches!(hdr.get_opcode(), Some(0x6c)) // Handshake packets must have (the only existing) opcode 0x6c
            || hdr.get_msg_len().is_some() // Handshake packets must not have a message length
            || hdr.is_continue() // Handshake packets must not be continue packets
            || hdr.get_seq().is_some() // Handshake packets must not have a sequence number
            || hdr.get_ack().is_some()
        // Handshake packets must not have an ACK
        {
            warn!("RX handshake integrity failure: {hdr}");
            return Err(ErrorCode::InvalidData.into());
        }

        Ok(())
    }

    /// Return the sequence number that should be ACKed, if any.
    fn pending_ack(&self) -> Option<u8> {
        if self.ack_level > 0 && self.buf_messages_ct == 0 {
            // Do not send ACKs when there is one complete message in the buffer, or else we risk overflowing the buffer
            Some(self.ack_seq)
        } else {
            None
        }
    }

    /// Update the state of the window after sending a BTP segment.
    /// Basically increases the window level, based on the last ACKed sequence num.
    fn post_send(&mut self) {
        if self.pending_ack().is_some() {
            self.level += self.ack_level;
            self.ack_level = 0;
        }
    }

    /// Pops and fetches one SDU payload (a.k.a. a Matter message) from the front of the buffer.
    /// Returns the size of the fetched SDU payload, or the buffer size if the SDU is larger.
    ///
    /// If there are no complete SDUs inside the buffer, the method will return 0.
    fn fetch_message(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.buf_messages_ct == 0 {
            return Ok(0);
        }

        let len = u16::from_le_bytes([
            self.buf.pop_byte().ok_or(ErrorCode::Invalid)?,
            self.buf.pop_byte().ok_or(ErrorCode::Invalid)?,
        ]) as usize;

        let pop_len = min(len, buf.len());

        if self.buf.pop(&mut buf[..pop_len]) != pop_len {
            Err(ErrorCode::Invalid)?;
        }

        if pop_len < len {
            warn!("Truncating packet");

            for _ in pop_len..len {
                if self.buf.pop_byte().is_none() {
                    Err(ErrorCode::Invalid)?;
                }
            }
        }

        self.buf_messages_ct -= 1;

        Ok(pop_len)
    }
}

/// Represents a BTP Session, as per the MAtter Core spec.
#[derive(Debug)]
pub struct Session {
    address: BtAddr,
    state: SessionState,
    version: u8,
    mtu: u16,
    window_size: u8,
    recv_window: RecvWindow,
    send_window: SendWindow,
}

impl Session {
    /// Return an in-place initializer for a new BTP session with the provided address, version,
    /// MTU and window size.
    ///
    /// Initializing a session is done based on the data that had arrived in the Handshake Request message,
    /// written by a remote peer on the `C1` characteristic.
    fn init(address: BtAddr, version: u8, mtu: u16, window_size: u8) -> impl Init<Self> {
        init!(Self {
            address,
            state: SessionState::New,
            version,
            mtu,
            window_size,
            recv_window <- RecvWindow::init(window_size),
            send_window: SendWindow::new(window_size),
        })
    }

    /// Return the address of the remote peer.
    pub fn address(&self) -> BtAddr {
        self.address
    }

    /// Return true if this session is in a state where we need to send a BTP Handshake Response message
    /// to the remote peer (i.e. the remote peer did subscribe to characteristic `C2`).
    pub fn is_handshake_resp_due(&self) -> bool {
        matches!(self.state, SessionState::Subscribed)
    }

    /// Return true if this session is in a state where an ACK is available and needs to be sent immediately.
    /// I.e. the inactivity timeout had expired, or the window is full.
    pub fn is_ack_due(&self, now: Instant, ack_timeout_secs: u16) -> bool {
        matches!(self.state, SessionState::Running)
            && self.recv_window.pending_ack().is_some()
            && (self.recv_window.level <= 1
                || self
                    .recv_window
                    .received_at
                    .checked_add(Duration::from_secs(ack_timeout_secs as _))
                    .map(|expires| expires <= now)
                    .unwrap_or(false))
    }

    /// Return true if this session needs to be removed due to inactivity.
    /// (I.e. the remote peer did not sent an ACK in due time.)
    pub fn is_timed_out(&self, now: Instant, conn_idle_timeout_secs: u16) -> bool {
        self.send_window
            .sent_at
            .checked_add(Duration::from_secs(conn_idle_timeout_secs as _))
            .map(|expires| expires < now)
            .unwrap_or(false)
    }

    /// Set the session in subscribed state.
    /// This method should be called when the remote peer subscribes to the `C2` characteristic.
    ///
    /// Will return false if the current state of the session is not `New`.
    pub fn set_subscribed(&mut self) -> bool {
        if matches!(self.state, SessionState::New) {
            self.state = SessionState::Subscribed;
            true
        } else {
            false
        }
    }

    /// Set the session in running state.
    /// This method should be called after we had sent the BTP Handshake Response message to the remote peer.
    /// Calling this method on an already running session has no effect.
    ///
    /// Will return false if the current state of the session is not `Subscribed` or `Running`.
    pub fn set_running(&mut self) -> bool {
        if matches!(self.state, SessionState::Running | SessionState::Subscribed) {
            self.state = SessionState::Running;
            true
        } else {
            false
        }
    }

    /// Lock the session for sending.
    /// (As per the Matter Core spec, at any moment in time, a session
    /// can send the BTP segments of a single BTP SDU, hence the need for locking.)
    ///
    /// Will return `false` if sending is true and the session is already locked for sending.
    pub fn set_sending(&mut self, sending: bool) -> bool {
        if sending && self.send_window.sending {
            return false; // already in sending mode, cannot set twice
        }
        self.send_window.sending = sending;
        true
    }

    /// Return `true` if the session buffer contains at least one complete DSDU, for consumption by the
    /// Matter transport stack.
    pub fn message_available(&self) -> bool {
        matches!(self.state, SessionState::Running) && self.recv_window.buf_messages_ct > 0
    }

    /// Fetches the data of the first DSDU available in the buffer of the session.
    /// Returns the size of the fetched data.
    ///
    /// If there is no DSDU available, the method will return 0.
    pub fn fetch_message(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.recv_window.fetch_message(buf)
    }

    /// A utility method to check if the provided BTP segment represents a Handshake Request message.
    ///
    /// Alleviates the need to expose the `BtpHdr` struct to the outside world.
    pub fn is_handshake(data: &[u8]) -> Result<bool, Error> {
        let hdr = BtpHdr::from(data.iter().copied())?;

        Ok(hdr.is_handshake())
    }

    /// Process an incoming BTP segment of type Handshake Request, updating the state of the session accordingly.
    pub fn process_rx_handshake(
        address: BtAddr,
        data: &[u8],
        gatt_mtu: Option<u16>,
    ) -> Result<impl Init<Self>, Error> {
        let mut iter = data.iter();

        let hdr = BtpHdr::from((&mut iter).copied())?;
        let payload = iter.as_slice();

        // Check received packet integrity, as per the Matter Core spec
        RecvWindow::check_handshake_integrity(&hdr)?;

        let req = HandshakeReq::from(payload.iter().copied())?;

        let version = req.versions().min().unwrap_or(4);

        let mtu = if gatt_mtu.map(|gatt_mtu| gatt_mtu != req.mtu).unwrap_or(true) {
            if let Some(gatt_mtu) = gatt_mtu {
                warn!(
                    "MTU mismatch: GATT MTU: {gatt_mtu}, BTP MTU: {}, will use MTU: {MIN_MTU}",
                    req.mtu
                );
            }

            // We don't know our MTU or what we know is not what the other peer reports
            // => use the minimum MTU
            MIN_MTU
        } else {
            // Used MTU should not be bigger than the maximum allowed
            min(req.mtu, MAX_MTU)
        };

        // Remove the header as we need to report back the payload MTU
        // and we'll use the payload MTU anyway for all operations
        let mtu = mtu - GATT_HEADER_SIZE as u16;

        // Make sure we are using a window size that would allow us to receive at least one full BTP SDU
        // TODO: Revisit the mtu and window_size computations
        let window_size = min(
            req.window_size,
            min(MAX_MESSAGE_SIZE as u16 / mtu / 2, 255) as u8,
        );

        info!("\n>>>>> (BTP IO) {address} [{hdr}]\nHANDSHAKE REQ {req:?}\nSelected version: {version}, MTU: {mtu}, window size: {window_size}");

        Ok(Self::init(address, version, mtu, window_size))
    }

    /// Process an incoming BTP segment of a regular data or ACK type, updating the state of the session accordingly.
    pub fn process_rx_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut iter = data.iter();

        let hdr = BtpHdr::from((&mut iter).copied())?;
        let payload = iter.as_slice();

        info!(
            "\n>>>>> (BTP IO) {} [{hdr}]\nREAD {}B",
            self.address,
            payload.len()
        );

        self.recv_window.accept_incoming(&hdr, payload, self.mtu)?;
        self.send_window.accept_incoming(&hdr);

        Ok(())
    }

    /// Prepare a BTP segment to be sent as a response to a Handshake Request message.
    pub fn prep_tx_handshake<'s>(&mut self, buf: &'s mut [u8]) -> Result<&'s [u8], Error> {
        let resp = HandshakeResp {
            version: self.version,
            mtu: self.mtu,
            window_size: self.window_size,
        };

        let mut wb = WriteBuf::new(buf);

        let mut hdr = BtpHdr::new();
        hdr.set_handshake();
        hdr.set_opcode(Some(0x6c));

        info!(
            "\n<<<<< (BTP IO) {} [{hdr}]\nHANDSHAKE RESP {resp:?}",
            self.address
        );

        hdr.encode(&mut wb)?;
        resp.encode(&mut wb)?;

        self.send_window.post_send();

        let len = wb.get_tail();
        let slice = &buf[..len];

        Ok(slice)
    }

    /// Prepare a BTP segment to be sent as a regular data or a standalone ACK message.
    /// The data to be sent will be "chopped off" from the provided `data` slice, starting from offset `offset`.
    ///
    /// When the `data` slice is empty, the method will prepare a standalone ACK message.
    ///
    /// The method will return `None` if the session is not in a state where it can send data (i.e. send window full).
    /// In case the session is in a state where it can send data, the method will return the slice of the input `buf`
    /// filled with the binary BTP segment, and the new offset.
    pub fn prep_tx_data<'s>(
        &mut self,
        data: &[u8],
        offset: usize,
        buf: &'s mut [u8],
    ) -> Result<Option<(&'s [u8], usize)>, Error> {
        if self.send_window.is_full(&self.recv_window) {
            return Ok(None);
        }

        let mut hdr = BtpHdr::new();

        hdr.set_seq(Some(self.send_window.next_seq_num()));
        hdr.set_ack(self.recv_window.pending_ack());

        let segment_data = if !data.is_empty() {
            // Enhance to a data packet

            if offset == 0 {
                hdr.set_msg_len(Some(data.len() as u16));
            } else {
                hdr.set_continue();
            }

            let remaining_data = &data[offset..];

            let max_payload_len = self.mtu as usize - hdr.len();

            let chunk_end = min(remaining_data.len(), max_payload_len);

            if chunk_end == remaining_data.len() {
                hdr.set_final();
            }

            &remaining_data[..chunk_end]
        } else {
            // ACK packet

            &[]
        };

        let mut wb = WriteBuf::new(buf);

        hdr.encode(&mut wb)?;
        wb.append(segment_data)?;

        info!(
            "\n<<<<< (BTP IO) {} [{hdr}]\nWRITE {}B",
            self.address,
            segment_data.len()
        );

        self.send_window.post_send();
        self.recv_window.post_send();

        let len = wb.get_tail();
        let slice = &buf[..len];

        Ok(Some((slice, offset + segment_data.len())))
    }
}
