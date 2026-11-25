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

//! Arbitrary bytes as the DER data a device sends during attestation: its
//! X.509 certificates, its CSR and the certification declaration.

#![no_main]

use libfuzzer_sys::fuzz_target;

use rs_matter_cert::attest::cd::{CertificationElements, CmsSignedData};
use rs_matter_cert::x509::cert::{CertType, DacExtensions, PaaExtensions, PaiExtensions, X509Cert};
use rs_matter_cert::x509::csr::CsrRef;

fn x509<'a, E: CertType<'a>>(data: &'a [u8]) {
    if let Ok(cert) = X509Cert::<E>::new(data) {
        let _ = cert.subject_key_id();
        let _ = cert.authority_key_id();
        let _ = cert.public_key();
        let _ = cert.vendor_id();
        let _ = cert.product_id();
        let _ = cert.not_before_unix();
        let _ = cert.not_after_unix();
        let _ = cert.is_valid_at(1_800_000_000);
    }
}

fuzz_target!(|data: &[u8]| {
    x509::<DacExtensions>(data);
    x509::<PaiExtensions>(data);
    x509::<PaaExtensions>(data);

    if let Ok(csr) = CsrRef::new(data) {
        let _ = csr.pubkey();
    }

    if let Ok(cms) = CmsSignedData::parse(data) {
        let _ = CertificationElements::decode(cms.cd_content);
    }
    let _ = CertificationElements::decode(data);
});
