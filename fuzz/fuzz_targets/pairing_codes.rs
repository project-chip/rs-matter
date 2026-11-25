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

//! Arbitrary text as an onboarding payload: a QR code and a manual pairing code.
//! What parses must encode back to the same values: the same digits for a manual
//! pairing code, and a QR code that parses to the same fields.

#![no_main]

use libfuzzer_sys::fuzz_target;

use rs_matter_pairing::qr::{no_optional_data, QrPayload};
use rs_matter_pairing::BasicCommData;

/// Encodes the fixed fields of a parsed QR code, and checks that they parse back the same.
fn check_qr(payload: &QrPayload<'_, &[u8]>) {
    let fields = |payload: &QrPayload<'_, &[u8]>| {
        (
            payload.discovery_capabilities(),
            payload.comm_flow(),
            payload.discriminator(),
            payload.passcode(),
            payload.vid(),
            payload.pid(),
        )
    };

    let rebuilt = QrPayload::new(
        payload.discovery_capabilities(),
        payload.comm_flow(),
        BasicCommData {
            password: payload.passcode().to_le_bytes().into(),
            discriminator: payload.discriminator(),
        },
        payload.vid(),
        payload.pid(),
        "",
        no_optional_data,
    );

    // The encoder refuses some values that the parser accepts, such as invalid passcodes
    let mut text_buf = [0; 256];
    let Ok((text, _)) = rebuilt.as_str(&mut text_buf) else {
        return;
    };

    let mut buf = [0; 256];
    let reparsed = QrPayload::parse(text, &mut buf).expect("An encoded QR code does not parse");
    assert_eq!(fields(&reparsed), fields(payload), "{text}");
}

/// Encodes a parsed manual pairing code, and checks that it is the same digits.
fn check_pairing_code(code: &str, payload: &QrPayload<'_, ()>) {
    let comm_data = BasicCommData {
        password: payload.passcode().to_le_bytes().into(),
        // The code carries the upper 4 bits of the 12-bit discriminator
        discriminator: (payload.short_discriminator() as u16) << 8,
    };

    let encoded = match payload.vid_pid() {
        Some((vid, pid)) => comm_data.compute_pairing_code_long(vid, pid).to_string(),
        None => comm_data.compute_pairing_code().to_string(),
    };
    let digits: String = code.chars().filter(|ch| !matches!(ch, '-' | ' ')).collect();

    assert_eq!(encoded, digits);
}

fuzz_target!(|data: &[u8]| {
    let Ok(code) = core::str::from_utf8(data) else {
        return;
    };

    // Larger than any payload decoded from the input
    let mut buf = vec![0; code.len() + 64];

    if let Ok(payload) = QrPayload::parse(code, &mut buf) {
        check_qr(&payload);
    }
    if let Ok(payload) = QrPayload::parse(&format!("MT:{code}"), &mut buf) {
        check_qr(&payload);
    }
    if let Ok(payload) = QrPayload::parse_pairing_code(code) {
        check_pairing_code(code, &payload);
    }
});
