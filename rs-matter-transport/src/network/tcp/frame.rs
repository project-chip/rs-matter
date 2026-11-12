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
/// - `Err(...)` if the frame header is present but invalid (0 length or exceeds `max_payload_len`).
pub fn check_frame_slice(buf: &[u8], max_payload_len: usize) -> Result<Option<usize>, Error> {
    if buf.len() < FRAME_HDR_LEN {
        return Ok(None);
    }

    let hdr: &[u8; FRAME_HDR_LEN] = buf[..FRAME_HDR_LEN]
        .try_into()
        .map_err(|_| ErrorCode::InvalidData)?;
    let msg_len = parse_frame_header(hdr, max_payload_len)?;

    if buf.len() >= FRAME_HDR_LEN + msg_len {
        Ok(Some(msg_len))
    } else {
        Ok(None)
    }
}

/// A fixed-capacity streaming frame accumulator for zero-allocation Matter TCP parsing.
pub struct Frame<const N: usize> {
    header: [u8; FRAME_HDR_LEN],
    header_len: usize,
    payload: [u8; N],
    payload_len: usize,
    length: usize,
}

impl<const N: usize> Frame<N> {
    /// Create a new, empty frame accumulator.
    pub const fn new() -> Self {
        Self {
            header: [0; FRAME_HDR_LEN],
            header_len: 0,
            payload: [0; N],
            payload_len: 0,
            length: 0,
        }
    }

    /// Feed incoming stream bytes into the frame accumulator.
    ///
    /// Returns the number of bytes consumed from `input`.
    pub fn feed(&mut self, mut input: &[u8]) -> Result<usize, Error> {
        let original_len = input.len();
        if self.header_len < FRAME_HDR_LEN {
            let count = input.len().min(FRAME_HDR_LEN - self.header_len);
            self.header[self.header_len..self.header_len + count].copy_from_slice(&input[..count]);
            self.header_len += count;
            input = &input[count..];
            if self.header_len == FRAME_HDR_LEN {
                self.length = parse_frame_header(&self.header, N)?;
            }
        }
        if self.header_len == FRAME_HDR_LEN {
            let count = input.len().min(self.length - self.payload_len);
            self.payload[self.payload_len..self.payload_len + count]
                .copy_from_slice(&input[..count]);
            self.payload_len += count;
            input = &input[count..];
        }
        Ok(original_len - input.len())
    }

    /// Return the assembled message payload if complete.
    pub fn message(&self) -> Option<&[u8]> {
        (self.header_len == FRAME_HDR_LEN && self.payload_len == self.length)
            .then(|| &self.payload[..self.length])
    }

    /// Return the number of bytes still needed to complete the current phase
    /// (either header or payload).
    pub fn remaining(&self) -> usize {
        if self.header_len < FRAME_HDR_LEN {
            FRAME_HDR_LEN - self.header_len
        } else {
            self.length - self.payload_len
        }
    }

    /// Reset the frame accumulator for reading the next message.
    pub fn reset(&mut self) {
        self.header_len = 0;
        self.payload_len = 0;
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
}
