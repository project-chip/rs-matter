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

//! Arbitrary bytes as a TLV element: every accessor, a walk over all nested
//! elements, and `Display` / `Debug`. What reads from the input must write out as
//! the same bytes.

#![no_main]

use core::fmt::Write;

use libfuzzer_sys::fuzz_target;

use rs_matter_tlv::{TLVElement, TLVSequence, TLVWrite};
use rs_matter_utils::storage::WriteBuf;

/// How deep the walk goes, to bound the stack of the walk itself.
const MAX_DEPTH: usize = 32;

fn walk(element: &TLVElement, depth: usize) {
    let _ = element.control();
    let _ = element.tag();
    let _ = element.ctx();
    let _ = element.u64();
    let _ = element.i64();
    let _ = element.f32();
    let _ = element.f64();
    let _ = element.bool();
    let _ = element.null();
    let _ = element.utf8();
    let _ = element.octets();

    if depth < MAX_DEPTH {
        if let Ok(seq) = element.container() {
            for child in seq.iter().flatten() {
                walk(&child, depth + 1);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let element = TLVElement::new(data);

    walk(&element, 0);

    // Formatting fails only when the formatter does, and a `String` never does
    let mut text = String::new();
    write!(text, "{element}").unwrap();
    write!(text, "{element:?}").unwrap();

    // What reads from the input writes out as the same bytes, up to where the reading stops
    let mut buf = vec![0; data.len()];
    let mut wb = WriteBuf::new(&mut buf);
    for tlv in TLVSequence(data).tlv_iter() {
        let Ok(tlv) = tlv else {
            break;
        };

        wb.tlv(&tlv.tag, &tlv.value)
            .expect("A TLV that was read does not fit in as many bytes when written");
    }
    assert!(
        data.starts_with(wb.as_slice()),
        "TLV written back differs from what was read: {:02x?}",
        wb.as_slice()
    );
});
