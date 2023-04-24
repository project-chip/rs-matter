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

use super::{CertConsumer, MAX_DEPTH};
use crate::error::Error;
use chrono::{Datelike, TimeZone, Utc}; // TODO
use core::fmt::Write;
use log::warn;

#[derive(Debug)]
pub struct ASN1Writer<'a> {
    buf: &'a mut [u8],
    // The current write offset in the buffer
    offset: usize,
    // If multiple 'composite' structures are being written, their starts are
    // captured in this
    depth: [usize; MAX_DEPTH],
    // The current depth of operation within the depth stack
    current_depth: usize,
}

const RESERVE_LEN_BYTES: usize = 3;
impl<'a> ASN1Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            offset: 0,
            depth: [0; MAX_DEPTH],
            current_depth: 0,
        }
    }

    pub fn append_with<F>(&mut self, size: usize, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Self),
    {
        if self.offset + size <= self.buf.len() {
            f(self);
            self.offset += size;
            return Ok(());
        }
        Err(Error::NoSpace)
    }

    pub fn append_tlv<F>(&mut self, tag: u8, len: usize, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Self),
    {
        let total_len = 1 + ASN1Writer::bytes_to_encode_len(len)? + len;
        if self.offset + total_len <= self.buf.len() {
            self.buf[self.offset] = tag;
            self.offset += 1;
            self.offset = self.encode_len(self.offset, len)?;
            f(self);
            self.offset += len;
            return Ok(());
        }
        Err(Error::NoSpace)
    }

    fn add_compound(&mut self, val: u8) -> Result<(), Error> {
        // We reserve 3 bytes for encoding the length
        // If a shorter length is actually required, we will move everything back
        self.append_with(1 + RESERVE_LEN_BYTES, |t| t.buf[t.offset] = val)?;
        self.depth[self.current_depth] = self.offset;
        self.current_depth += 1;
        if self.current_depth >= MAX_DEPTH {
            Err(Error::NoSpace)
        } else {
            Ok(())
        }
    }

    fn encode_len(&mut self, mut at_offset: usize, len: usize) -> Result<usize, Error> {
        let mut bytes_of_len = ASN1Writer::bytes_to_encode_len(len)?;
        if bytes_of_len > 1 {
            self.buf[at_offset] = (0x80 | (bytes_of_len - 1)) as u8;
            at_offset += 1;
            bytes_of_len -= 1;
        }

        // At this point bytes_of_len is the actual number of bytes for the length encoding
        // after the 0x80 (if it was present)
        let mut octet_number = bytes_of_len - 1;
        // We start encoding the highest octest first
        loop {
            self.buf[at_offset] = ((len >> (octet_number * 8)) & 0xff) as u8;

            at_offset += 1;
            if octet_number == 0 {
                break;
            }
            octet_number -= 1;
        }

        Ok(at_offset)
    }

    fn end_compound(&mut self) -> Result<(), Error> {
        if self.current_depth == 0 {
            return Err(Error::Invalid);
        }
        let seq_len = self.get_compound_len();
        let write_offset = self.get_length_encoding_offset();

        let mut write_offset = self.encode_len(write_offset, seq_len)?;

        // Shift everything by as much
        let shift_len = self.depth[self.current_depth - 1] - write_offset;
        if shift_len > 0 {
            for _i in 0..seq_len {
                self.buf[write_offset] = self.buf[write_offset + shift_len];
                write_offset += 1;
            }
        }
        self.current_depth -= 1;
        self.offset -= shift_len;
        Ok(())
    }

    fn get_compound_len(&self) -> usize {
        self.offset - self.depth[self.current_depth - 1]
    }

    fn bytes_to_encode_len(len: usize) -> Result<usize, Error> {
        let len = if len < 128 {
            // This is directly encoded
            1
        } else if len < 256 {
            // This is done with an 0xA1 followed by actual len
            2
        } else if len < 65536 {
            // This is done with an 0xA2 followed by 2 bytes of actual len
            3
        } else {
            return Err(Error::NoSpace);
        };
        Ok(len)
    }

    fn get_length_encoding_offset(&self) -> usize {
        self.depth[self.current_depth - 1] - RESERVE_LEN_BYTES
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.offset]
    }

    fn write_str(&mut self, vtype: u8, s: &[u8]) -> Result<(), Error> {
        self.append_tlv(vtype, s.len(), |t| {
            let end_offset = t.offset + s.len();
            t.buf[t.offset..end_offset].copy_from_slice(s);
        })
    }
}

impl<'a> CertConsumer for ASN1Writer<'a> {
    fn start_seq(&mut self, _tag: &str) -> Result<(), Error> {
        self.add_compound(0x30)
    }

    fn end_seq(&mut self) -> Result<(), Error> {
        self.end_compound()
    }

    fn integer(&mut self, _tag: &str, i: &[u8]) -> Result<(), Error> {
        self.write_str(0x02, i)
    }

    fn printstr(&mut self, _tag: &str, s: &str) -> Result<(), Error> {
        // Note: ASN1 has multiple strings, this is PrintableString
        self.write_str(0x13, s.as_bytes())
    }

    fn utf8str(&mut self, _tag: &str, s: &str) -> Result<(), Error> {
        // Note: ASN1 has multiple strings, this is UTF8String
        self.write_str(0x0c, s.as_bytes())
    }

    fn bitstr(&mut self, _tag: &str, truncate: bool, s: &[u8]) -> Result<(), Error> {
        // Note: ASN1 has multiple strings, this is BIT String

        // Strip off the end zeroes
        let mut last_byte = s.len() - 1;
        let mut num_of_zero = 0;
        if truncate {
            while s[last_byte] == 0 {
                last_byte -= 1;
            }
            // For the last valid byte, identifying the number of last bits
            // that are 0s
            num_of_zero = s[last_byte].trailing_zeros() as u8;
        }
        let s = &s[..(last_byte + 1)];
        self.append_tlv(0x03, s.len() + 1, |t| {
            t.buf[t.offset] = num_of_zero;
            let end_offset = t.offset + 1 + s.len();
            t.buf[(t.offset + 1)..end_offset].copy_from_slice(s);
        })
    }

    fn ostr(&mut self, _tag: &str, s: &[u8]) -> Result<(), Error> {
        // Note: ASN1 has multiple strings, this is Octet String
        self.write_str(0x04, s)
    }

    fn start_compound_ostr(&mut self, _tag: &str) -> Result<(), Error> {
        // Note: ASN1 has 3 string, this is compound Octet String
        self.add_compound(0x04)
    }

    fn end_compound_ostr(&mut self) -> Result<(), Error> {
        self.end_compound()
    }

    fn bool(&mut self, _tag: &str, b: bool) -> Result<(), Error> {
        self.append_tlv(0x01, 1, |t| {
            if b {
                t.buf[t.offset] = 0xFF;
            } else {
                t.buf[t.offset] = 0x00;
            }
        })
    }

    fn start_set(&mut self, _tag: &str) -> Result<(), Error> {
        self.add_compound(0x31)
    }

    fn end_set(&mut self) -> Result<(), Error> {
        self.end_compound()
    }

    fn ctx(&mut self, _tag: &str, id: u8, val: &[u8]) -> Result<(), Error> {
        self.write_str(0x80 | id, val)
    }

    fn start_ctx(&mut self, _tag: &str, val: u8) -> Result<(), Error> {
        self.add_compound(0xA0 | val)
    }

    fn end_ctx(&mut self) -> Result<(), Error> {
        self.end_compound()
    }

    fn oid(&mut self, _tag: &str, oid: &[u8]) -> Result<(), Error> {
        self.write_str(0x06, oid)
    }

    fn utctime(&mut self, _tag: &str, epoch: u32) -> Result<(), Error> {
        let mut matter_epoch = Utc
            .with_ymd_and_hms(2000, 1, 1, 0, 0, 0)
            .unwrap()
            .timestamp();

        matter_epoch += epoch as i64;

        let dt = match Utc.timestamp_opt(matter_epoch, 0) {
            chrono::LocalResult::None => return Err(Error::InvalidTime),
            chrono::LocalResult::Single(s) => s,
            chrono::LocalResult::Ambiguous(_, a) => {
                warn!("Ambiguous time for epoch {epoch}; returning latest timestamp: {a}");
                a
            }
        };

        if dt.year() >= 2050 {
            // If year is >= 2050, ASN.1 requires it to be Generalised Time
            let mut time_str = heapless::String::<32>::new();
            write!(&mut time_str, "{}Z", dt.format("%Y%m%d%H%M%S")).unwrap();
            self.write_str(0x18, time_str.as_bytes())
        } else {
            let mut time_str = heapless::String::<32>::new();
            write!(&mut time_str, "{}Z", dt.format("%y%m%d%H%M%S")).unwrap();
            self.write_str(0x17, time_str.as_bytes())
        }
    }
}
