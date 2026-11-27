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

//! The Certificate Signing Request (CSR) of a P-256 key, as a node sends it in
//! the `CSRResponse` command.
//!
//! The request is fixed except for the public key and the signature, so it is
//! written from a template, for all backends.

use crate::error::{Error, ErrorCode};
use crate::{
    CryptoSensitive, PublicKey, SigningSecretKey, PKC_CANON_PUBLIC_KEY_LEN, PKC_SIGNATURE_LEN,
};

/// The longest CSR that `SigningSecretKey::csr` writes, and the smallest buffer
/// it accepts.
///
/// The length of a CSR depends on its signature, so a buffer of this size always fits it.
pub const CSR_MAX_LEN: usize = 3
    + INFO_HEAD.len()
    + PKC_CANON_PUBLIC_KEY_LEN
    + INFO_TAIL.len()
    + SIG_ALG.len()
    + 3
    + MAX_DER_SIGNATURE_LEN;

/// The start of the request info, up to the public key.
///
/// The subject is `O=CSR` and the key an uncompressed P-256 point.
const INFO_HEAD: &[u8] = &[
    0x30, 0x70, // CertificationRequestInfo, 112 bytes
    0x02, 0x01, 0x00, // version v1
    0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, // subject: one RDN with one attribute
    0x06, 0x03, 0x55, 0x04, 0x0a, // organizationName (2.5.4.10)
    0x0c, 0x03, b'C', b'S', b'R', // UTF8String "CSR"
    0x30, 0x59, // subjectPKInfo
    0x30, 0x13, // algorithm
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey (1.2.840.10045.2.1)
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
    0x03, 0x42, 0x00, // subjectPublicKey: BIT STRING, no unused bits
];

/// The end of the request info: no attributes.
const INFO_TAIL: &[u8] = &[0xa0, 0x00];

/// The signature algorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
const SIG_ALG: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

/// The longest DER `ECDSA-Sig-Value` of a P-256 signature.
const MAX_DER_SIGNATURE_LEN: usize = 72;

/// Write the CSR of `key` into `buf`, signed with it.
pub(crate) fn write<'a, 's, const PUB_KEY_LEN: usize, const SIGNATURE_LEN: usize, K>(
    key: &K,
    buf: &'s mut [u8],
) -> Result<&'s [u8], Error>
where
    K: SigningSecretKey<'a, PUB_KEY_LEN, SIGNATURE_LEN> + ?Sized + 'a,
{
    // The template is for P-256
    const {
        ::core::assert!(
            PUB_KEY_LEN == PKC_CANON_PUBLIC_KEY_LEN && SIGNATURE_LEN == PKC_SIGNATURE_LEN
        )
    };

    // Checked before anything is written or signed, so that the outcome does not
    // depend on the length of the signature
    if buf.len() < CSR_MAX_LEN {
        Err(ErrorCode::BufferTooSmall)?;
    }

    let info_len = INFO_HEAD.len() + PUB_KEY_LEN + INFO_TAIL.len();

    // The request info goes after the 3-byte header of the request and is signed in place
    let mut signature = CryptoSensitive::<SIGNATURE_LEN>::new();

    {
        let info = &mut buf[3..3 + info_len];

        let (head, rest) = info.split_at_mut(INFO_HEAD.len());
        let (pub_key, tail) = rest.split_at_mut(PUB_KEY_LEN);

        let mut canon = CryptoSensitive::<PUB_KEY_LEN>::new();
        key.pub_key()?.write_canon(&mut canon)?;

        head.copy_from_slice(INFO_HEAD);
        pub_key.copy_from_slice(canon.access());
        tail.copy_from_slice(INFO_TAIL);

        key.sign(info, &mut signature)?;
    }

    let mut der = [0; MAX_DER_SIGNATURE_LEN];
    let der = der_signature(signature.access(), &mut der);

    let content_len = info_len + SIG_ALG.len() + 3 + der.len();
    let csr = &mut buf[..3 + content_len];

    // The content is 137 to 201 bytes, so its length takes one byte
    csr[..3].copy_from_slice(&[0x30, 0x81, content_len as u8]);

    let (sig_alg, rest) = csr[3 + info_len..].split_at_mut(SIG_ALG.len());
    sig_alg.copy_from_slice(SIG_ALG);
    rest[..3].copy_from_slice(&[0x03, der.len() as u8 + 1, 0x00]);
    rest[3..].copy_from_slice(der);

    Ok(csr)
}

/// Encode a raw `r || s` P-256 signature as a DER `ECDSA-Sig-Value`.
fn der_signature<'d>(raw: &[u8], der: &'d mut [u8; MAX_DER_SIGNATURE_LEN]) -> &'d [u8] {
    let mut len = 2;

    for int in raw.chunks(raw.len() / 2) {
        // A DER INTEGER has no leading zero bytes, but a positive one whose top bit
        // is set starts with a zero byte
        let zeros = int.iter().take_while(|byte| **byte == 0).count();
        let int = &int[zeros.min(int.len() - 1)..];
        let pad = (int[0] >> 7) as usize;

        der[len] = 0x02;
        der[len + 1] = (pad + int.len()) as u8;
        der[len + 2] = 0;
        der[len + 2 + pad..len + 2 + pad + int.len()].copy_from_slice(int);

        len += 2 + pad + int.len();
    }

    der[0] = 0x30;
    der[1] = (len - 2) as u8;

    &der[..len]
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{der_signature, CSR_MAX_LEN, MAX_DER_SIGNATURE_LEN};

    #[test]
    fn csr_max_len() {
        assert_eq!(CSR_MAX_LEN, 204);
    }

    #[test]
    fn der_signature_is_minimal() {
        let mut der = [0; MAX_DER_SIGNATURE_LEN];

        // `r` with its top bit set gets a leading zero; `s` with leading zeros loses them
        let mut raw = [0; 64];
        raw[0] = 0x80;
        raw[31] = 0x01;
        raw[62] = 0x7f;
        raw[63] = 0xff;

        let mut expected = std::vec![0x30, 0x27, 0x02, 0x21, 0x00, 0x80];
        expected.extend_from_slice(&[0; 30]);
        expected.extend_from_slice(&[0x01, 0x02, 0x02, 0x7f, 0xff]);
        assert_eq!(der_signature(&raw, &mut der), expected.as_slice());

        // Zero is a single zero byte
        let raw = [0; 64];
        assert_eq!(
            der_signature(&raw, &mut der),
            &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]
        );

        // The longest one
        let raw = [0xff; 64];
        assert_eq!(der_signature(&raw, &mut der).len(), MAX_DER_SIGNATURE_LEN);
    }
}
