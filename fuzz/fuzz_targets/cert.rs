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

//! Arbitrary bytes as a Matter (TLV) certificate, as the peer's certificates
//! arrive during CASE: the conversion to X.509, the accessors and `Display`. When
//! the conversion succeeds, its output must be well-formed DER.

#![no_main]

use core::fmt::Write;

use libfuzzer_sys::fuzz_target;

use rs_matter_cert::{CertRef, MAX_CERT_ASN1_LEN};
use rs_matter_tlv::TLVElement;

/// How deep the DER checks go, to bound their stack.
const MAX_DEPTH: usize = 16;

/// The OIDs of the extensions that the conversion encodes, from the fields of the
/// certificate: basic constraints, key usage, extended key usage, subject key ID and
/// authority key ID.
const ENCODED_EXTENSIONS: [&[u8]; 5] = [
    &[0x55, 0x1d, 0x13],
    &[0x55, 0x1d, 0x0f],
    &[0x55, 0x1d, 0x25],
    &[0x55, 0x1d, 0x0e],
    &[0x55, 0x1d, 0x23],
];

/// Reads one DER element: its tag, its content and what follows it. `None` unless the
/// tag is one byte and the length is in its shortest form and within the data.
fn der_element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;

    if tag & 0x1f == 0x1f {
        return None;
    }

    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let size = (first & 0x7f) as usize;
        // A size of 0 is the indefinite length of BER, which DER does not allow
        if size == 0 || size > 4 || rest.len() < size {
            return None;
        }

        let (len, rest) = rest.split_at(size);
        let len = len.iter().fold(0, |len, byte| (len << 8) | *byte as usize);
        if len < 0x80 || len >> ((size - 1) * 8) == 0 {
            return None;
        }

        (len, rest)
    };

    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// Checks that `der` is a series of DER elements, and so are the contents of the
/// constructed ones. Bit strings must say how many bits of their last byte are
/// unused, and these bits must be 0.
fn check_der(der: &[u8], depth: usize) {
    let mut rest = der;

    while !rest.is_empty() {
        let Some((tag, content, next)) = der_element(rest) else {
            panic!("Malformed DER in the X.509 conversion: {rest:02x?}");
        };

        if tag == 0x03 {
            let unused = content.first().copied().unwrap_or(8);
            let last = content
                .get(1..)
                .and_then(<[u8]>::last)
                .copied()
                .unwrap_or(0);
            assert!(
                unused < 8 && (content.len() > 1 || unused == 0) && last & ((1 << unused) - 1) == 0,
                "Malformed bit string in the X.509 conversion: {content:02x?}"
            );
        }

        if tag & 0x20 != 0 && depth < MAX_DEPTH {
            check_der(content, depth + 1);
        }

        rest = next;
    }
}

/// Checks the X.509 conversion of a certificate, which is its `TBSCertificate`: one
/// sequence, with the value of each extension that the conversion encodes DER as well.
/// The value of a future extension comes from the certificate as it is.
fn check_x509(tbs: &[u8]) {
    let Some((0x30, content, [])) = der_element(tbs) else {
        panic!("The X.509 conversion is not one sequence: {tbs:02x?}");
    };

    check_der(content, 0);

    // The extensions are the element with the context tag 3, a sequence of sequences
    // whose last element is an octet string with the value of the extension
    let mut rest = content;
    while let Some((tag, element, next)) = der_element(rest) {
        if tag == 0xa3 {
            let mut exts = der_element(element).map_or(&[][..], |(_, exts, _)| exts);
            while let Some((_, ext, next)) = der_element(exts) {
                let mut fields = ext;
                let mut oid = None;
                let mut value = None;
                while let Some((tag, field, next)) = der_element(fields) {
                    if tag == 0x06 {
                        oid = Some(field);
                    }
                    value = (tag == 0x04).then_some(field);
                    fields = next;
                }

                if let (Some(oid), Some(value)) = (oid, value) {
                    if ENCODED_EXTENSIONS.contains(&oid) {
                        check_der(value, 0);
                    }
                }

                exts = next;
            }
        }

        rest = next;
    }
}

fuzz_target!(|data: &[u8]| {
    let cert = CertRef::new(TLVElement::new(data));

    let mut asn1 = [0; MAX_CERT_ASN1_LEN];
    if let Ok(len) = cert.as_asn1(&mut asn1) {
        check_x509(&asn1[..len]);
    }

    let _ = cert.pubkey();
    let _ = cert.get_node_id();
    let _ = cert.get_fabric_id();
    let _ = cert.get_ca_id();
    let mut cat_ids = [0; 3];
    let _ = cert.get_cat_ids(&mut cat_ids);
    let _ = cert.is_self_signed();
    let _ = cert.basic_constraints_path_len();

    // Formatting fails only when the formatter does, and a `String` never does
    let mut text = String::new();
    write!(text, "{cert}").unwrap();
});
