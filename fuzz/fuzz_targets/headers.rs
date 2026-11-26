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

//! Arbitrary bytes as the two headers of a Matter message: the message header,
//! then the protocol header, as for an unencrypted message.

#![no_main]

use core::fmt::Write;

use libfuzzer_sys::fuzz_target;

use rs_matter_crypto::test_only_crypto;
use rs_matter_transport::packet::PacketHdr;
use rs_matter_utils::storage::ParseBuf;

fuzz_target!(|data: &[u8]| {
    let mut msg = data.to_vec();
    let mut pb = ParseBuf::new(&mut msg);

    let mut hdr = PacketHdr::new();
    if hdr.decode_plain_hdr(&mut pb).is_ok() {
        let _ = hdr.decode_remaining(test_only_crypto(), None, 0, &mut pb);
    }

    // Formatting fails only when the formatter does, and a `String` never does
    write!(String::new(), "{} {}", hdr.plain, hdr.proto).unwrap();
});
