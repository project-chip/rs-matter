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

use crate::utils::init::{init, Init};

/// A ring buffer of a fixed capacity `N` using owned storage.
#[derive(Debug)]
pub struct RingBuf<const N: usize> {
    buf: crate::utils::storage::Vec<u8, N>,
    start: usize,
    end: usize,
    non_empty: bool,
}

impl<const N: usize> Default for RingBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RingBuf<N> {
    /// Create a new ring buffer.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            buf: crate::utils::storage::Vec::new(),
            start: 0,
            end: 0,
            non_empty: false,
        }
    }

    /// Create an in-place initializer for the ring buffer.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            buf <- crate::utils::storage::Vec::init(),
            start: 0,
            end: 0,
            non_empty: false,
        })
    }

    /// Push new data to the end of the buffer.
    /// If the data does not fit in the buffer, the oldest data is dropped to make room for the new one.
    ///
    /// Return the new length of data in the buffer.
    #[inline(always)]
    pub fn push(&mut self, data: &[u8]) -> usize {
        // Unwrap is safe because the max size of the buffer is N
        self.buf.resize_default(N).unwrap();

        let mut offset = 0;

        while offset < data.len() {
            let len = min(self.buf.len() - self.end, data.len() - offset);

            self.buf[self.end..self.end + len].copy_from_slice(&data[offset..offset + len]);

            offset += len;

            if self.non_empty && self.start >= self.end && self.start < self.end + len {
                // Dropping oldest data
                self.start = self.end + len;
            }

            self.end += len;

            self.wrap();

            self.non_empty = true;
        }

        self.len()
    }

    /// Push a single byte to the end of the buffer.
    /// If the buffer is full, the oldest byte is dropped to make room for the new one.
    ///
    /// Return the new length of data in the buffer.
    #[inline(always)]
    pub fn push_byte(&mut self, data: u8) -> usize {
        // Unwrap is safe because the max size of the buffer is N
        self.buf.resize_default(N).unwrap();

        self.buf[self.end] = data;

        if self.non_empty && self.start == self.end {
            // Dropping oldest data
            self.start = self.end + 1;
        }

        self.end += 1;

        self.wrap();

        self.non_empty = true;

        self.len()
    }

    /// Pop one byte from the start of the buffer.
    /// If the bufer is empty, return `None`.
    #[inline(always)]
    pub fn pop_byte(&mut self) -> Option<u8> {
        let mut buf = [0; 1];

        if self.pop(&mut buf) == 1 {
            Some(buf[0])
        } else {
            None
        }
    }

    /// Pop data from the start of the buffer.
    /// Return the number of bytes copied to the output buffer.
    #[inline(always)]
    pub fn pop(&mut self, out_buf: &mut [u8]) -> usize {
        let mut offset = 0;

        while offset < out_buf.len() && self.non_empty {
            let len = min(
                if self.start < self.end {
                    self.end
                } else {
                    self.buf.len()
                } - self.start,
                out_buf.len() - offset,
            );

            out_buf[offset..offset + len].copy_from_slice(&self.buf[self.start..self.start + len]);

            self.start += len;

            self.wrap();

            if self.start == self.end {
                self.non_empty = false
            }

            offset += len;
        }

        offset
    }

    /// Return `true` when the buffer is full.
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.start == self.end && self.non_empty
    }

    /// Return `true` when the buffer is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        !self.non_empty
    }

    /// Return the current size of the data in the buffer.
    #[inline(always)]
    #[allow(unused)]
    pub fn len(&self) -> usize {
        if !self.non_empty {
            0
        } else if self.start < self.end {
            self.end - self.start
        } else {
            self.buf.len() + self.end - self.start
        }
    }

    /// Return the free space in the buffer.
    #[inline(always)]
    #[allow(unused)]
    pub fn free(&self) -> usize {
        N - self.len()
    }

    /// Clear the buffer.
    #[inline(always)]
    pub fn clear(&mut self) {
        self.start = 0;
        self.end = 0;
        self.non_empty = false;
    }

    #[inline(always)]
    fn wrap(&mut self) {
        if self.start == self.buf.len() {
            self.start = 0;
        }

        if self.end == self.buf.len() {
            self.end = 0;
        }
    }
}

impl<const N: usize> Iterator for RingBuf<N> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.pop_byte()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop() {
        let mut rb = RingBuf::<4>::new();
        assert!(rb.is_empty());

        rb.push(&[0, 1, 2]);
        assert_eq!(3, rb.len());
        assert!(!rb.is_empty());
        assert!(!rb.is_full());

        rb.push(&[3]);
        assert_eq!(4, rb.len());
        assert!(!rb.is_empty());
        assert!(rb.is_full());

        let mut buf = [0; 256];

        let len = rb.pop(&mut buf);
        assert_eq!(4, len);
        assert_eq!(&buf[0..4], &[0, 1, 2, 3]);
        assert!(rb.is_empty());

        rb.push(&[0, 1, 2, 3, 4, 5]);
        assert_eq!(4, rb.len());
        assert!(!rb.is_empty());
        assert!(rb.is_full());

        let len = rb.pop(&mut buf[..3]);
        assert_eq!(3, len);
        assert_eq!(&buf[0..len], &[2, 3, 4]);
        assert!(!rb.is_empty());
        assert!(!rb.is_full());

        let len = rb.pop(&mut buf);
        assert_eq!(1, len);
        assert_eq!(&buf[0..len], &[5]);
        assert!(rb.is_empty());
        assert!(!rb.is_full());

        let len = rb.pop(&mut buf);
        assert_eq!(0, len);
        assert!(rb.is_empty());
        assert!(!rb.is_full());
    }
}
