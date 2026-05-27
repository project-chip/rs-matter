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

//! Matter TLV-encoded certificate generator (RCAC / ICAC / NOC).
//!
//! [`CertGenerator`] is the one-shot, caller-buffer cert generator
//! underlying [`crate::onboard::cac::RcacGenerator`],
//! [`crate::onboard::cac::IcacGenerator`] and
//! [`crate::onboard::noc::NocGenerator`]. It's parametric over
//! [`CertType`], with subject/issuer/validity/keys plumbed in by the
//! caller. (Matter Specification 6.5 "Operational Certificate Encoding")

use crate::attest::trust_store::{compute_key_id, KeyId};
use crate::cert::CertRef;
use crate::crypto::{CanonPkcPublicKeyRef, CanonPkcSignature, Crypto, PKC_CANON_PUBLIC_KEY_LEN};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVElement, TLVTag, TLVWrite};
use crate::utils::storage::WriteBuf;

use super::{x509::key_usage_tlv, CertTag, DNTag};

/// Certificate kind passed to [`CertGenerator::generate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertType {
    /// Root CA Certificate (self-signed, is_ca=true, no path_len).
    Rcac,
    /// Intermediate CA Certificate (signed by RCAC, is_ca=true, path_len=0).
    Icac,
    /// Node Operational Certificate (end entity, is_ca=false).
    Noc,
}

pub struct IssuerDN {
    pub(crate) ca_id: Option<u64>,
    pub(crate) fabric_id: Option<u64>,
    pub(crate) is_rcac: bool,
}

#[derive(Clone, Copy)]
pub struct SubjectDN<'a> {
    pub(crate) node_id: Option<u64>,
    pub(crate) fabric_id: Option<u64>,
    pub(crate) cat_ids: &'a [u32],
    pub(crate) ca_id: Option<u64>,
}

/// Validity period for certificates, represented as seconds since the Matter epoch (2000-01-01T00:00:00Z).
#[derive(Clone, Copy)]
pub struct Validity {
    /// NotBefore time (seconds since Matter epoch)
    ///
    /// This must not be 0 (the Matter epoch start) to avoid collision with CHIP's epoch=0 sentinel in ASN.1 time encoding.
    pub not_before: u32,
    /// NotAfter time (seconds since Matter epoch, 0 = no expiry)
    pub not_after: u32,
}

// NotBefore MUST NOT be 0 (Matter epoch start, 2000-01-01).
// CHIP's ChipEpochToASN1Time treats epoch=0 as the "no
// well-defined expiration date" sentinel and re-emits it as
// GeneralizedTime "99991231235959Z" regardless of which field
// it appears in (see CHIPCert.cpp:1076-1106 and the
// explanatory comment about CHIP epoch 0 NotBefore producing
// an invalid TBS signature on round-trip).
//
// We sign over UTCTime "000101000000Z" (Matter epoch); CHIP
// would reconstruct GeneralizedTime "99991231235959Z" and the
// hash would mismatch.  Using 1 second past the Matter epoch
// avoids the sentinel collision while keeping the cert
// effectively unbounded on the lower end.
pub const VALID_FOREVER: Validity = Validity {
    not_before: 1, // 2000-01-01 00:00:01 — past CHIP's epoch=0 sentinel
    not_after: 0,  // no expiry (NotAfter sentinel is legitimate)
};

/// One-shot Matter-TLV certificate generator writing into a
/// caller-supplied buffer.
///
/// Typical callers are the three issuers in [`crate::onboard::cac`]
/// (RCAC, ICAC) and [`crate::onboard::noc`] (NOC); each one
/// constructs a `CertGenerator` over its scratch buffer, calls
/// [`Self::generate`] once and discards the generator. Subject /
/// issuer / pubkey / signing-key consistency is the caller's
/// responsibility — `generate` only checks invariants generic across
/// cert types (serial number well-formedness).
pub struct CertGenerator<'a> {
    buf: &'a mut [u8],
}

impl<'a> CertGenerator<'a> {
    /// Create a new generator over the given output buffer.
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }

    /// Generate a Matter-TLV certificate of the given kind, sign it,
    /// and return the length written to the buffer.
    ///
    /// `issuer_pubkey` must be `None` for [`CertType::Rcac`]
    /// (self-signed: AKID = SKID) and `Some(_)` for `Icac` / `Noc`.
    /// `signing_key` is the issuer's private key — the RCAC's own key
    /// for RCAC and ICAC; the ICAC's (or RCAC's) for NOC.
    #[allow(clippy::too_many_arguments)]
    pub fn generate<C: Crypto>(
        &mut self,
        crypto: C,
        cert_type: CertType,
        serial_number: &[u8],
        validity: Validity,
        subject: SubjectDN,
        issuer: IssuerDN,
        subject_pubkey: CanonPkcPublicKeyRef<'_>,
        issuer_pubkey: Option<CanonPkcPublicKeyRef<'_>>,
        signing_key: &C::SecretKey<'_>,
    ) -> Result<usize, Error> {
        Self::validate_serial_number(serial_number)?;

        let subject_key_id = compute_key_id(&crypto, subject_pubkey)?;

        let authority_key_id = if let Some(issuer_pk) = issuer_pubkey {
            compute_key_id(&crypto, issuer_pk)?
        } else {
            // Self-signed: AKID = SKID
            subject_key_id
        };

        // Build the TBS (To-Be-Signed) certificate
        let tbs_len = self.write_tbs_certificate(
            serial_number,
            validity,
            subject_pubkey.access(),
            &subject_key_id,
            &authority_key_id,
            cert_type,
            subject,
            issuer,
        )?;

        // Convert TBS to ASN1 format for signing
        // According to the Matter Spec 6.5.2. "Matter certificate", the signature is over the
        // "corresponding X.509 certificate, not a signature of the preceding Matter TLV data."
        let (tlv_buf, asn1_buf) = self.buf.split_at_mut(tbs_len);
        let tbs_cert_ref = CertRef::new(TLVElement::new(tlv_buf));
        let asn1_len = tbs_cert_ref.as_asn1(asn1_buf)?;

        // Sign the ASN1-encoded TBS certificate
        let signature = Self::sign_tbs::<C>(&asn1_buf[..asn1_len], signing_key)?;

        // Append signature to complete the certificate
        self.append_signature(&signature, tbs_len)
    }

    /// Write the TBS (To-Be-Signed) certificate structure.
    ///
    /// This creates the certificate without the signature.
    #[allow(clippy::too_many_arguments)]
    fn write_tbs_certificate(
        &mut self,
        serial_number: &[u8],
        validity: Validity,
        pubkey: &[u8; PKC_CANON_PUBLIC_KEY_LEN],
        subject_key_id: &KeyId,
        authority_key_id: &KeyId,
        cert_type: CertType,
        subject: SubjectDN,
        issuer: IssuerDN,
    ) -> Result<usize, Error> {
        let mut tw = WriteBuf::new(self.buf);

        tw.start_struct(&TLVTag::Anonymous)?;

        // 1. Serial Number
        tw.str(&TLVTag::Context(CertTag::SerialNum as _), serial_number)?;

        // 2. Signature Algorithm (1 = ECDSA-SHA256)
        tw.u8(&TLVTag::Context(CertTag::SignAlgo as _), 1)?;

        // 3. Issuer
        tw.start_list(&TLVTag::Context(CertTag::Issuer as _))?;
        match cert_type {
            CertType::Rcac => {
                // Self-signed: issuer = subject
                if let Some(id) = subject.ca_id {
                    tw.u64(&TLVTag::Context(DNTag::RootCaId as u8), id)?;
                }
                if let Some(fid) = subject.fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?; // Fabric ID
                }
            }
            CertType::Icac | CertType::Noc => {
                // Use provided issuer information
                if let Some(id) = issuer.ca_id {
                    let tag = if issuer.is_rcac {
                        DNTag::RootCaId as u8
                    } else {
                        DNTag::IcaId as u8
                    };
                    tw.u64(&TLVTag::Context(tag), id)?;
                }
                if let Some(fid) = issuer.fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?;
                }
            }
        }
        tw.end_container()?;

        // 4. Not Before
        tw.u32(
            &TLVTag::Context(CertTag::NotBefore as u8),
            validity.not_before,
        )?;

        // 5. Not After (0 = no expiry)
        tw.u32(
            &TLVTag::Context(CertTag::NotAfter as u8),
            validity.not_after,
        )?;

        // 6. Subject
        tw.start_list(&TLVTag::Context(CertTag::Subject as u8))?;
        match cert_type {
            CertType::Noc => {
                // NOC Subject: NodeId, FabricId, optional CAT IDs
                if let Some(nid) = subject.node_id {
                    tw.u64(&TLVTag::Context(DNTag::NodeId as u8), nid)?;
                }
                if let Some(fid) = subject.fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?
                }
                for cat_id in subject.cat_ids {
                    tw.u64(&TLVTag::Context(DNTag::NocCat as u8), *cat_id as u64)?;
                }
            }
            CertType::Icac => {
                // ICAC Subject: ICAC ID, FabricId
                if let Some(id) = subject.ca_id {
                    tw.u64(&TLVTag::Context(DNTag::IcaId as u8), id)?;
                }
                if let Some(fid) = subject.fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?;
                }
            }
            CertType::Rcac => {
                // RCAC Subject: RCAC ID, FabricId
                if let Some(id) = subject.ca_id {
                    tw.u64(&TLVTag::Context(DNTag::RootCaId as u8), id)?;
                }
                if let Some(fid) = subject.fabric_id {
                    tw.u64(&TLVTag::Context(DNTag::FabricId as u8), fid)?;
                }
            }
        }
        tw.end_container()?;

        // 7. Public Key Algorithm (1 = EC Public Key)
        tw.u8(&TLVTag::Context(CertTag::PubKeyAlgo as u8), 1)?;

        // 8. EC Curve ID (1 = prime256v1)
        tw.u8(&TLVTag::Context(CertTag::EcCurveId as u8), 1)?;

        // 9. EC Public Key
        tw.str(&TLVTag::Context(CertTag::EcPubKey as u8), pubkey)?;

        // 10. Extensions
        tw.start_list(&TLVTag::Context(CertTag::Extensions as u8))?;
        Self::write_extensions(&mut tw, cert_type, subject_key_id, authority_key_id)?;
        tw.end_container()?;

        tw.end_container()?;

        Ok(tw.get_tail())
    }

    /// Write certificate extensions.
    fn write_extensions(
        tw: &mut impl TLVWrite,
        cert_type: CertType,
        subject_key_id: &KeyId,
        authority_key_id: &KeyId,
    ) -> Result<(), Error> {
        // 1. Basic Constraints — per Matter Spec:
        //   RCAC: cA = TRUE,  pathLenConstraint shall NOT be present
        //   ICAC: cA = TRUE,  pathLenConstraint = 0
        //   NOC:  cA = FALSE, pathLenConstraint shall NOT be present
        tw.start_struct(&TLVTag::Context(1))?;
        match cert_type {
            CertType::Rcac => {
                tw.bool(&TLVTag::Context(1), true)?;
            }
            CertType::Icac => {
                tw.bool(&TLVTag::Context(1), true)?;
                tw.u8(&TLVTag::Context(2), 0)?; // path_len = 0
            }
            CertType::Noc => {
                tw.bool(&TLVTag::Context(1), false)?;
            }
        }
        tw.end_container()?;

        // 2. Key Usage
        let key_usage = match cert_type {
            CertType::Rcac | CertType::Icac => {
                key_usage_tlv::KEY_CERT_SIGN | key_usage_tlv::CRL_SIGN
            }
            CertType::Noc => key_usage_tlv::DIGITAL_SIGNATURE,
        };
        tw.u16(&TLVTag::Context(2), key_usage)?;

        // 3. Extended Key Usage - for NOC only
        if cert_type == CertType::Noc {
            tw.start_array(&TLVTag::Context(3))?;
            tw.u8(&TLVTag::Anonymous, 1)?; // ServerAuth
            tw.u8(&TLVTag::Anonymous, 2)?; // ClientAuth
            tw.end_container()?;
        }

        // 4. Subject Key Identifier
        tw.str(&TLVTag::Context(4), subject_key_id)?;

        // 5. Authority Key Identifier (not present for self-signed RCAC in some cases,
        //    but Matter spec recommends including it)
        tw.str(&TLVTag::Context(5), authority_key_id)?;

        Ok(())
    }

    /// Sign the TBS certificate data.
    fn sign_tbs<C: Crypto>(
        tbs_data: &[u8],
        signing_key: &C::SecretKey<'_>,
    ) -> Result<CanonPkcSignature, Error> {
        use crate::crypto::SigningSecretKey;

        let mut signature = CanonPkcSignature::new();
        signing_key.sign(tbs_data, &mut signature)?;
        Ok(signature)
    }

    /// Append the signature to complete the certificate.
    ///
    /// This reads the TBS data, parses out the structure, and re-writes it
    /// with the signature field added.
    fn append_signature(
        &mut self,
        signature: &CanonPkcSignature,
        tbs_len: usize,
    ) -> Result<usize, Error> {
        if tbs_len == 0 || self.buf[tbs_len - 1] != 0x18 {
            return Err(ErrorCode::InvalidData.into());
        }

        let insert_pos = tbs_len - 1;

        // Use proper TLV encoding via WriteBuf
        let mut tw = WriteBuf::new(&mut self.buf[insert_pos..]);
        tw.str(
            &TLVTag::Context(CertTag::Signature as u8),
            signature.access(),
        )?;
        tw.end_container()?;

        Ok(insert_pos + tw.get_tail())
    }

    /// Validate serial number format.
    fn validate_serial_number(serial: &[u8]) -> Result<(), Error> {
        if serial.is_empty() {
            return Err(ErrorCode::InvalidData.into());
        }
        // Check for unnecessary leading zeros (except one needed for positive sign)
        if serial.len() > 1 && serial[0] == 0 && (serial[1] & 0x80) == 0 {
            return Err(ErrorCode::InvalidData.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cert::{MAX_CERT_TLV_AND_ASN1_LEN, MAX_CERT_TLV_LEN},
        crypto::{test_only_crypto, CanonPkcPublicKey, PublicKey, SigningSecretKey},
        dm::clusters::time_sync::UtcTime,
    };

    use super::*;

    /// IssuerDN slot for self-signed certs (RCAC). `generate` ignores
    /// `issuer` entirely when `cert_type == Rcac`, but the call site
    /// still has to pass *some* value.
    const RCAC_ISSUER_DN_UNUSED: IssuerDN = IssuerDN {
        ca_id: None,
        fabric_id: None,
        is_rcac: false,
    };

    #[test]
    fn test_validate_serial_number_valid() {
        assert!(CertGenerator::validate_serial_number(&[0x01]).is_ok());
        assert!(CertGenerator::validate_serial_number(&[0x00, 0x80]).is_ok()); // Leading zero needed for positive
        assert!(CertGenerator::validate_serial_number(&[0x7F]).is_ok());
    }

    #[test]
    fn test_validate_serial_number_invalid() {
        assert!(CertGenerator::validate_serial_number(&[]).is_err()); // Empty
        assert!(CertGenerator::validate_serial_number(&[0x00, 0x01]).is_err());
        // Unnecessary leading zero
    }

    /// Test building a self-signed RCAC
    #[test]
    fn test_build_rcac() {
        let crypto = test_only_crypto();

        let rcac_secret_key = unwrap!(crypto.generate_secret_key());
        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();

        let mut rcac_pubkey_canon = CanonPkcPublicKey::new();
        rcac_pubkey.write_canon(&mut rcac_pubkey_canon).unwrap();

        let serial_number = &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let rcac_id = 0x1234567890u64;
        let fabric_id = 0x0000000000000001u64;
        let not_before = 0u32; // Matter epoch start
        let not_after = 0u32; // No expiry

        let subject = SubjectDN {
            node_id: None,
            fabric_id: Some(fabric_id),
            cat_ids: &[],
            ca_id: Some(rcac_id),
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let len = unwrap!(CertGenerator::new(&mut cert_buf).generate(
            &crypto,
            CertType::Rcac,
            serial_number,
            validity,
            subject,
            RCAC_ISSUER_DN_UNUSED,
            rcac_pubkey_canon.reference(),
            None,
            &rcac_secret_key,
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    #[test]
    fn test_rcac_self_verify() {
        let crypto = test_only_crypto();

        let rcac_secret_key = unwrap!(crypto.generate_secret_key());
        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();

        let mut rcac_pubkey_canon = CanonPkcPublicKey::new();
        rcac_pubkey.write_canon(&mut rcac_pubkey_canon).unwrap();

        let subject = SubjectDN {
            node_id: None,
            fabric_id: Some(0x0000_0000_0000_0001),
            cat_ids: &[],
            ca_id: Some(0x1122_3344_5566_7788),
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let len = unwrap!(CertGenerator::new(&mut cert_buf).generate(
            &crypto,
            CertType::Rcac,
            &[0x01],
            VALID_FOREVER,
            subject,
            RCAC_ISSUER_DN_UNUSED,
            rcac_pubkey_canon.reference(),
            None,
            &rcac_secret_key,
        ));

        // Re-parse the just-built RCAC and self-verify.
        let cert = CertRef::new(crate::tlv::TLVElement::new(&cert_buf[..len]));
        let mut scratch = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let res = cert
            .verify_chain_start(
                &crypto,
                UtcTime::Reliable(VALID_FOREVER.not_before as u64 * 1_000_000),
            )
            .finalise(&mut scratch);
        assert!(
            res.is_ok(),
            "RCAC built by CertGenerator failed self-verification: {res:?}"
        );
    }

    /// Test building an ICAC signed by RCAC
    #[test]
    fn test_build_icac() {
        let crypto = test_only_crypto();

        let rcac_secret_key = unwrap!(crypto.generate_secret_key());

        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();
        let mut rcac_pubkey_canon = CanonPkcPublicKey::new();
        rcac_pubkey.write_canon(&mut rcac_pubkey_canon).unwrap();

        let icac_secret_key = unwrap!(crypto.generate_secret_key());

        let icac_pubkey = icac_secret_key.pub_key().unwrap();
        let mut icac_pubkey_canon = CanonPkcPublicKey::new();
        icac_pubkey.write_canon(&mut icac_pubkey_canon).unwrap();

        let serial_number = &[0x01, 0x02, 0x03, 0x04];
        let icac_id = 0x1234u64;
        let rcac_id = 0x5678u64;
        let fabric_id = 0x0000000000000001u64;

        let subject = SubjectDN {
            node_id: None,
            fabric_id: Some(fabric_id),
            cat_ids: &[],
            ca_id: Some(icac_id),
        };

        let issuer = IssuerDN {
            ca_id: Some(rcac_id),
            fabric_id: Some(fabric_id),
            is_rcac: true,
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let len = unwrap!(CertGenerator::new(&mut cert_buf).generate(
            &crypto,
            CertType::Icac,
            serial_number,
            VALID_FOREVER,
            subject,
            issuer,
            icac_pubkey_canon.reference(),
            Some(rcac_pubkey_canon.reference()),
            &rcac_secret_key,
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    /// Test building a NOC signed by RCAC
    #[test]
    fn test_build_noc_signed_by_rcac() {
        let crypto = test_only_crypto();

        let rcac_secret_key = unwrap!(crypto.generate_secret_key());

        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();
        let mut rcac_pubkey_canon = CanonPkcPublicKey::new();
        rcac_pubkey.write_canon(&mut rcac_pubkey_canon).unwrap();

        let noc_secret_key = unwrap!(crypto.generate_secret_key());

        let noc_pubkey = noc_secret_key.pub_key().unwrap();
        let mut noc_pubkey_canon = CanonPkcPublicKey::new();
        noc_pubkey.write_canon(&mut noc_pubkey_canon).unwrap();

        let serial_number = &[0xAA, 0xBB, 0xCC];
        let node_id = 0x1122334455667788u64;
        let fabric_id = 0x0000000000000001u64;
        let rcac_id = 0x9999u64;
        let not_before = 0u32;
        let not_after = 0u32;

        let subject = SubjectDN {
            node_id: Some(node_id),
            fabric_id: Some(fabric_id),
            cat_ids: &[], // No CAT IDs
            ca_id: None,
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let issuer = IssuerDN {
            ca_id: Some(rcac_id),
            fabric_id: Some(fabric_id),
            is_rcac: true, // Issuer is RCAC
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let len = unwrap!(CertGenerator::new(&mut cert_buf).generate(
            &crypto,
            CertType::Noc,
            serial_number,
            validity,
            subject,
            issuer,
            noc_pubkey_canon.reference(),
            Some(rcac_pubkey_canon.reference()),
            &rcac_secret_key,
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    /// Test building a NOC with CAT IDs
    #[test]
    fn test_build_noc_with_cat_ids() {
        let crypto = test_only_crypto();

        let rcac_secret_key = unwrap!(crypto.generate_secret_key());

        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();
        let mut rcac_pubkey_canon = CanonPkcPublicKey::new();
        rcac_pubkey.write_canon(&mut rcac_pubkey_canon).unwrap();

        let noc_secret_key = unwrap!(crypto.generate_secret_key());

        let noc_pubkey = noc_secret_key.pub_key().unwrap();
        let mut noc_pubkey_canon = CanonPkcPublicKey::new();
        noc_pubkey.write_canon(&mut noc_pubkey_canon).unwrap();

        let serial_number = &[0x01];
        let node_id = 0x0000000000000001u64;
        let fabric_id = 0x0000000000000001u64;
        let rcac_id = 0x1000u64;
        let cat_ids = &[0x00011111u32, 0x00022222u32, 0x00033333u32]; // Valid CAT IDs (version != 0)
        let not_before = 0u32;
        let not_after = 0u32;

        let subject = SubjectDN {
            node_id: Some(node_id),
            fabric_id: Some(fabric_id),
            cat_ids,
            ca_id: None,
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let issuer = IssuerDN {
            ca_id: Some(rcac_id),
            fabric_id: Some(fabric_id),
            is_rcac: true,
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let len = unwrap!(CertGenerator::new(&mut cert_buf).generate(
            &crypto,
            CertType::Noc,
            serial_number,
            validity,
            subject,
            issuer,
            noc_pubkey_canon.reference(),
            Some(rcac_pubkey_canon.reference()),
            &rcac_secret_key,
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    /// Test building a NOC signed by ICAC (3-cert chain)
    #[test]
    fn test_build_noc_signed_by_icac() {
        let crypto = test_only_crypto();

        let icac_secret_key = unwrap!(crypto.generate_secret_key());

        let icac_pubkey = icac_secret_key.pub_key().unwrap();
        let mut icac_pubkey_canon = CanonPkcPublicKey::new();
        icac_pubkey.write_canon(&mut icac_pubkey_canon).unwrap();

        let noc_secret_key = unwrap!(crypto.generate_secret_key());

        let noc_pubkey = noc_secret_key.pub_key().unwrap();
        let mut noc_pubkey_canon = CanonPkcPublicKey::new();
        noc_pubkey.write_canon(&mut noc_pubkey_canon).unwrap();

        let serial_number = &[0xFF];
        let node_id = 0xDEADBEEFu64;
        let fabric_id = 0x0000000000000001u64;
        let icac_id = 0x2468u64;
        let not_before = 0u32;
        let not_after = 0u32;

        let subject = SubjectDN {
            node_id: Some(node_id),
            fabric_id: Some(fabric_id),
            cat_ids: &[], // No CAT IDs
            ca_id: None,
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let issuer = IssuerDN {
            ca_id: Some(icac_id),
            fabric_id: Some(fabric_id),
            is_rcac: false, // Issuer is ICAC, not RCAC
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let len = unwrap!(CertGenerator::new(&mut cert_buf).generate(
            &crypto,
            CertType::Noc,
            serial_number,
            validity,
            subject,
            issuer,
            noc_pubkey_canon.reference(),
            Some(icac_pubkey_canon.reference()),
            &icac_secret_key,
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    /// Test complete certificate chain (RCAC -> ICAC -> NOC)
    #[test]
    fn test_build_complete_cert_chain() {
        let crypto = test_only_crypto();

        let fabric_id = 0x0000000000000001u64;
        let rcac_id = 0x1111111111u64;
        let icac_id = 0x2222u64;
        let node_id = 0x3333333333333333u64;
        let not_before = 0u32;
        let not_after = 0u32;

        let rcac_secret_key = unwrap!(crypto.generate_secret_key());

        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();
        let mut rcac_pubkey_canon = CanonPkcPublicKey::new();
        rcac_pubkey.write_canon(&mut rcac_pubkey_canon).unwrap();

        let rcac_subject = SubjectDN {
            node_id: None,
            fabric_id: Some(fabric_id),
            cat_ids: &[],
            ca_id: Some(rcac_id),
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let rcac_len = unwrap!(CertGenerator::new(&mut rcac_buf).generate(
            &crypto,
            CertType::Rcac,
            &[0x01],
            validity,
            rcac_subject,
            RCAC_ISSUER_DN_UNUSED,
            rcac_pubkey_canon.reference(),
            None,
            &rcac_secret_key,
        ));
        assert!(rcac_len > 0);

        let icac_secret_key = unwrap!(crypto.generate_secret_key());

        let icac_pubkey = icac_secret_key.pub_key().unwrap();
        let mut icac_pubkey_canon = CanonPkcPublicKey::new();
        icac_pubkey.write_canon(&mut icac_pubkey_canon).unwrap();

        let icac_subject = SubjectDN {
            node_id: None,
            fabric_id: Some(fabric_id),
            cat_ids: &[],
            ca_id: Some(icac_id),
        };

        let icac_issuer = IssuerDN {
            ca_id: Some(rcac_id),
            fabric_id: Some(fabric_id),
            is_rcac: true,
        };

        let mut icac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let icac_len = unwrap!(CertGenerator::new(&mut icac_buf).generate(
            &crypto,
            CertType::Icac,
            &[0x02],
            validity,
            icac_subject,
            icac_issuer,
            icac_pubkey_canon.reference(),
            Some(rcac_pubkey_canon.reference()),
            &rcac_secret_key,
        ));
        assert!(icac_len > 0);

        let noc_secret_key = unwrap!(crypto.generate_secret_key());

        let noc_pubkey = noc_secret_key.pub_key().unwrap();
        let mut noc_pubkey_canon = CanonPkcPublicKey::new();
        noc_pubkey.write_canon(&mut noc_pubkey_canon).unwrap();

        let noc_subject = SubjectDN {
            node_id: Some(node_id),
            fabric_id: Some(fabric_id),
            cat_ids: &[],
            ca_id: None,
        };

        let noc_issuer = IssuerDN {
            ca_id: Some(icac_id),
            fabric_id: Some(fabric_id),
            is_rcac: false, // Issuer is ICAC
        };

        let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let noc_len = unwrap!(CertGenerator::new(&mut noc_buf).generate(
            &crypto,
            CertType::Noc,
            &[0x03],
            validity,
            noc_subject,
            noc_issuer,
            noc_pubkey_canon.reference(),
            Some(icac_pubkey_canon.reference()),
            &icac_secret_key,
        ));
        assert!(noc_len > 0);

        // All certificates should be valid sizes
        assert!(rcac_len > 100 && rcac_len < MAX_CERT_TLV_LEN);
        assert!(icac_len > 100 && icac_len < MAX_CERT_TLV_LEN);
        assert!(noc_len > 100 && noc_len < MAX_CERT_TLV_LEN);
    }

    /// Test certificate with validity period
    #[test]
    fn test_build_cert_with_validity() {
        let crypto = test_only_crypto();

        let rcac_secret_key = unwrap!(crypto.generate_secret_key());

        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();
        let mut rcac_pubkey_canon = CanonPkcPublicKey::new();
        rcac_pubkey.write_canon(&mut rcac_pubkey_canon).unwrap();

        // Matter epoch: seconds since 2000-01-01 00:00:00 UTC
        // Year 2021: approximately 662688000 seconds
        let not_before = 662688000u32;
        // 10 years later
        let not_after = not_before + (10 * 365 * 24 * 60 * 60);

        let subject = SubjectDN {
            node_id: None,
            fabric_id: Some(0x0000000000000001u64),
            cat_ids: &[],
            ca_id: Some(0x1234567890u64),
        };

        let validity = Validity {
            not_before,
            not_after,
        };

        let mut cert_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let len = unwrap!(CertGenerator::new(&mut cert_buf).generate(
            &crypto,
            CertType::Rcac,
            &[0x01],
            validity,
            subject,
            RCAC_ISSUER_DN_UNUSED,
            rcac_pubkey_canon.reference(),
            None,
            &rcac_secret_key,
        ));

        assert!(len > 100);
        assert!(len < MAX_CERT_TLV_LEN);
    }

    /// Test key identifier computation
    #[test]
    fn test_compute_key_id() {
        let crypto = test_only_crypto();

        let secret_key = unwrap!(crypto.generate_secret_key());

        let mut pubkey = CanonPkcPublicKey::new();
        unwrap!(secret_key.pub_key().unwrap().write_canon(&mut pubkey));

        let key_id = unwrap!(compute_key_id(&crypto, pubkey.reference()));

        // Key ID should be deterministic for the same public key
        let key_id2 = unwrap!(compute_key_id(&crypto, pubkey.reference()));
        assert_eq!(key_id, key_id2);
    }

    /// Test that different public keys produce different key IDs
    #[test]
    fn test_different_keys_different_ids() {
        let crypto = test_only_crypto();

        let secret_key1 = unwrap!(crypto.generate_secret_key());
        let mut pubkey1 = CanonPkcPublicKey::new();
        unwrap!(secret_key1.pub_key().unwrap().write_canon(&mut pubkey1));

        let secret_key2 = unwrap!(crypto.generate_secret_key());
        let mut pubkey2 = CanonPkcPublicKey::new();
        unwrap!(secret_key2.pub_key().unwrap().write_canon(&mut pubkey2));

        let key_id1 = unwrap!(compute_key_id(&crypto, pubkey1.reference()));
        let key_id2 = unwrap!(compute_key_id(&crypto, pubkey2.reference()));

        // Different keys should produce different IDs
        assert_ne!(key_id1, key_id2);
    }
}
