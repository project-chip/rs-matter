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

//! Matter TCP transport message framing.
//!
//! Per Matter Core Specification section 4.3.4 (Transport Framing), all Matter
//! messages transmitted over TCP are preceded by a 4-octet length field encoded
//! in little-endian format, indicating the length of the Matter message in octets.
//! The length does not include the 4-octet header itself. The minimum length
//! of a Matter message is greater than zero.

use crate::error::{Error, ErrorCode};
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec as StorageVec;

/// Size of the TCP framing header (4-byte little-endian message length prefix).
pub const FRAME_HDR_LEN: usize = 4;

/// Encode a 4-byte little-endian Matter TCP frame length header for the given payload length.
pub fn encode_frame_header(payload_len: usize) -> Result<[u8; FRAME_HDR_LEN], Error> {
    if payload_len > u32::MAX as usize {
        return Err(ErrorCode::BufferTooSmall.into());
    }
    Ok((payload_len as u32).to_le_bytes())
}

/// Parse and validate a 4-byte little-endian Matter TCP frame length header.
///
/// Per Matter Core Specification section 4.3.4, the message length must not
/// exceed `max_payload_len`.
pub fn parse_frame_header(
    hdr: &[u8; FRAME_HDR_LEN],
    max_payload_len: usize,
) -> Result<usize, Error> {
    let len = u32::from_le_bytes(*hdr) as usize;
    if len > max_payload_len {
        return Err(ErrorCode::InvalidData.into());
    }
    Ok(len)
}

/// Check if a buffer slice contains a complete framed message.
///
/// Returns:
/// - `Ok(Some(msg_len))` if a valid header and the full payload are present in `buf`.
/// - `Ok(None)` if more data is needed (partial header or partial payload).
/// - `Err(...)` if the frame header is present but invalid (exceeds `max_payload_len`).
pub fn check_frame_slice(buf: &[u8], max_payload_len: usize) -> Result<Option<usize>, Error> {
    if buf.len() < FRAME_HDR_LEN {
        return Ok(None);
    }

    let hdr: &[u8; FRAME_HDR_LEN] = buf[..FRAME_HDR_LEN]
        .try_into()
        .map_err(|_| ErrorCode::InvalidData)?;
    let msg_len = parse_frame_header(hdr, max_payload_len)?;

    if buf.len().saturating_sub(FRAME_HDR_LEN) >= msg_len {
        Ok(Some(msg_len))
    } else {
        Ok(None)
    }
}

/// A fixed-capacity streaming frame accumulator for zero-allocation Matter TCP parsing.
pub struct Frame<const N: usize> {
    header: [u8; FRAME_HDR_LEN],
    header_len: usize,
    payload: StorageVec<u8, N>,
    payload_read: usize,
    length: usize,
}

impl<const N: usize> Frame<N> {
    /// Create a new, empty frame accumulator.
    pub const fn new() -> Self {
        Self {
            header: [0; FRAME_HDR_LEN],
            header_len: 0,
            payload: StorageVec::new(),
            payload_read: 0,
            length: 0,
        }
    }

    /// Create an in-place initializer for a new, empty frame accumulator.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            header: [0; FRAME_HDR_LEN],
            header_len: 0,
            payload <- StorageVec::init(),
            payload_read: 0,
            length: 0,
        })
    }

    /// Return the mutable slice to read the next chunk of header or payload bytes directly into.
    ///
    /// Returns an empty slice once a complete frame has been accumulated.
    pub fn next_read_buf_mut(&mut self) -> &mut [u8] {
        if self.header_len < FRAME_HDR_LEN {
            &mut self.header[self.header_len..]
        } else {
            &mut self.payload[self.payload_read..self.length]
        }
    }

    /// Advance the accumulator by `count` bytes previously written into [`Self::next_read_buf_mut`].
    ///
    /// Returns `Err(ErrorCode::InvalidData)` if `count` exceeds the remaining capacity of
    /// the current header or payload phase, or if the completed 4-byte header announces
    /// a payload larger than `N`.
    pub fn advance(&mut self, count: usize) -> Result<(), Error> {
        if self.header_len < FRAME_HDR_LEN {
            if count > FRAME_HDR_LEN - self.header_len {
                return Err(ErrorCode::InvalidData.into());
            }
            self.header_len += count;
            if self.header_len == FRAME_HDR_LEN {
                self.length = parse_frame_header(&self.header, N)?;
                self.payload
                    .resize_default(self.length)
                    .map_err(|_| ErrorCode::BufferTooSmall)?;
                self.payload_read = 0;
            }
        } else {
            if count > self.length - self.payload_read {
                return Err(ErrorCode::InvalidData.into());
            }
            self.payload_read += count;
        }
        Ok(())
    }

    fn feed_segment<'a>(&mut self, input: &'a [u8]) -> Result<&'a [u8], Error> {
        let dst = self.next_read_buf_mut();
        let count = input.len().min(dst.len());
        dst[..count].copy_from_slice(&input[..count]);
        self.advance(count)?;
        Ok(&input[count..])
    }

    /// Feed incoming stream bytes into the frame accumulator.
    ///
    /// Returns the number of bytes consumed from `input`.
    pub fn feed(&mut self, mut input: &[u8]) -> Result<usize, Error> {
        let original_len = input.len();
        if self.header_len < FRAME_HDR_LEN {
            input = self.feed_segment(input)?;
        }
        if self.header_len == FRAME_HDR_LEN {
            input = self.feed_segment(input)?;
        }
        Ok(original_len - input.len())
    }

    /// Return `true` if a complete frame (header + full payload) has been accumulated.
    pub fn is_complete(&self) -> bool {
        self.header_len == FRAME_HDR_LEN && self.payload_read == self.length
    }

    /// Return the assembled message payload if complete.
    pub fn message(&self) -> Option<&[u8]> {
        self.is_complete().then(|| &self.payload[..self.length])
    }

    /// Return the number of bytes still needed to complete the current phase
    /// (either header or payload).
    pub fn remaining(&self) -> usize {
        if self.header_len < FRAME_HDR_LEN {
            FRAME_HDR_LEN - self.header_len
        } else {
            self.length - self.payload_read
        }
    }

    /// Reset the frame accumulator for reading the next message.
    pub fn reset(&mut self) {
        self.header_len = 0;
        self.payload.clear();
        self.payload_read = 0;
        self.length = 0;
    }
}

impl<const N: usize> Default for Frame<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn header_encode_decode_roundtrip() {
        let hdr = encode_frame_header(100).unwrap();
        assert_eq!(hdr, 100u32.to_le_bytes());
        assert_eq!(parse_frame_header(&hdr, 1500).unwrap(), 100);
    }

    #[test]
    fn header_allows_zero_length() {
        let zero_hdr = 0u32.to_le_bytes();
        assert_eq!(parse_frame_header(&zero_hdr, 1500).unwrap(), 0);
    }

    #[test]
    fn header_rejects_oversized() {
        let large_hdr = 2000u32.to_le_bytes();
        assert_eq!(
            parse_frame_header(&large_hdr, 1500).unwrap_err().code(),
            ErrorCode::InvalidData
        );
    }

    #[test]
    fn check_frame_slice_states() {
        // Less than header length
        assert_eq!(check_frame_slice(&[1, 2], 1500).unwrap(), None);

        // Header present but payload incomplete
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(&[1, 2, 3]);
        assert_eq!(check_frame_slice(&buf, 1500).unwrap(), None);

        // Header and exact payload present
        buf.extend_from_slice(&[4, 5]);
        assert_eq!(check_frame_slice(&buf, 1500).unwrap(), Some(5));

        // Header and payload present with trailing bytes
        buf.extend_from_slice(&[99, 98]);
        assert_eq!(check_frame_slice(&buf, 1500).unwrap(), Some(5));

        // Zero-length header in slice is accepted
        let zero_slice = 0u32.to_le_bytes();
        assert_eq!(check_frame_slice(&zero_slice, 1500).unwrap(), Some(0));
    }

    #[test]
    fn frame_reassembles_fragmented_little_endian_header_and_payload() {
        let mut frame = Frame::<64>::new();
        assert_eq!(frame.feed(&[5, 0]).unwrap(), 2);
        assert_eq!(frame.message(), None);
        assert_eq!(frame.remaining(), 2);

        assert_eq!(frame.feed(&[0, 0, b'h', b'e']).unwrap(), 4);
        assert_eq!(frame.message(), None);
        assert_eq!(frame.remaining(), 3);

        assert_eq!(frame.feed(b"llo").unwrap(), 3);
        assert_eq!(frame.message(), Some(&b"hello"[..]));
        assert_eq!(frame.remaining(), 0);
    }

    #[test]
    fn frame_leaves_back_to_back_message_for_the_next_read() {
        let mut frame = Frame::<64>::new();
        let mut stream = Vec::new();
        stream.extend_from_slice(&3u32.to_le_bytes());
        stream.extend_from_slice(b"one");
        stream.extend_from_slice(&3u32.to_le_bytes());
        stream.extend_from_slice(b"two");

        let consumed = frame.feed(&stream).unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(frame.message(), Some(&b"one"[..]));

        frame.reset();
        let consumed2 = frame.feed(&stream[consumed..]).unwrap();
        assert_eq!(consumed2, 7);
        assert_eq!(frame.message(), Some(&b"two"[..]));
    }

    #[test]
    fn frame_handles_empty_and_rejects_oversized_payloads() {
        let mut frame = Frame::<8>::new();
        let zero = 0u32.to_le_bytes();
        assert_eq!(frame.feed(&zero).unwrap(), 4);
        assert_eq!(frame.message(), Some(&b""[..]));

        let mut frame = Frame::<8>::new();
        let large = 9u32.to_le_bytes();
        assert_eq!(
            frame.feed(&large).unwrap_err().code(),
            ErrorCode::InvalidData
        );
    }

    #[test]
    fn frame_init_and_direct_read() {
        use crate::utils::init::InitMaybeUninit;
        use core::mem::MaybeUninit;

        let mut slot = MaybeUninit::<Frame<64>>::uninit();
        let frame = slot.init_with(Frame::init());

        // Read header directly in two chunks
        let buf = frame.next_read_buf_mut();
        assert_eq!(buf.len(), FRAME_HDR_LEN);
        buf[..2].copy_from_slice(&[5, 0]);
        frame.advance(2).unwrap();

        let buf = frame.next_read_buf_mut();
        assert_eq!(buf.len(), 2);
        buf.copy_from_slice(&[0, 0]);
        frame.advance(2).unwrap();

        // Read payload directly
        let buf = frame.next_read_buf_mut();
        assert_eq!(buf.len(), 5);
        buf.copy_from_slice(b"hello");
        frame.advance(5).unwrap();

        assert!(frame.is_complete());
        assert_eq!(frame.message(), Some(&b"hello"[..]));

        // SAFETY: `slot` was initialized by `init_with` above.
        unsafe { slot.assume_init_drop() };
    }

    #[test]
    fn frame_advance_rejects_out_of_bounds_counts() {
        let mut frame = Frame::<16>::new();
        assert_eq!(
            frame.advance(FRAME_HDR_LEN + 1).unwrap_err().code(),
            ErrorCode::InvalidData
        );

        let buf = frame.next_read_buf_mut();
        buf.copy_from_slice(&4u32.to_le_bytes());
        frame.advance(FRAME_HDR_LEN).unwrap();

        assert_eq!(frame.advance(5).unwrap_err().code(), ErrorCode::InvalidData);
        frame.advance(2).unwrap();
        assert_eq!(frame.advance(3).unwrap_err().code(), ErrorCode::InvalidData);
    }
}
