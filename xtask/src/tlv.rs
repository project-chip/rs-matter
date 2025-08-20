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

use log::warn;

use rs_matter::cert::CertRef;
use rs_matter::tlv::TLVElement;

/// Decode the provided TLVs
///
/// # Arguments
/// - `tlv_str`: A string containing hex or decimal TLV octets, separated by comma
/// - `dec`: If true, the input is interpreted as decimal; otherwise, it is interpreted as hexadecimal
/// - `cert`: If true, the function will attempt to parse the TLV as a certificate
/// - `as_asn1`: If true, the function will convert the certificate to ASN.1 format and print it
pub fn decode(tlv_str: &str, dec: bool, cert: bool, as_asn1: bool) -> anyhow::Result<()> {
    warn!("Decoding TLV octets: '{tlv_str}'");

    let base = if dec { InputBase::Dec } else { InputBase::Hex };
    let tlv = base.parse_list(tlv_str, ',');

    let tlv = TLVElement::new(tlv.as_slice());

    warn!("Output:\n{}", tlv.clone());

    if cert {
        let cert = CertRef::new(tlv.clone());

        warn!("Certificate:\n{cert}");
    }

    if as_asn1 {
        let cert = CertRef::new(tlv);

        let mut buf = [0_u8; 1024];

        let len = cert.as_asn1(&mut buf)?;

        warn!("Certificate:\n{cert}");

        warn!("ASN1-Encoded:\n{:02x?}", &buf[..len]);
    }

    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum InputBase {
    Hex,
    Dec,
}

#[derive(Clone, Debug, PartialEq)]
struct ParseError {
    pub input: String,
    pub error: std::num::ParseIntError,
}

impl InputBase {
    /// Parses a single input
    ///
    /// # Examples
    ///
    /// ```
    /// use parser::InputBase;
    ///
    /// assert_eq!(InputBase::Hex.try_parse("12"), Ok(0x12));
    /// assert_eq!(InputBase::Dec.try_parse("12"), Ok(12));
    /// assert_eq!(InputBase::Hex.try_parse("0x12"), Ok(0x12));
    /// assert_eq!(InputBase::Dec.try_parse("0x12"), Ok(0x12)); // always hex if prefix
    /// ```
    pub fn try_parse(self, s: impl AsRef<str>) -> Result<u8, ParseError> {
        let s = s.as_ref();

        let error_map = |error: std::num::ParseIntError| ParseError {
            input: s.into(),
            error,
        };

        if let Some(suffix) = s.strip_prefix("0x") {
            // this is always hex
            return u8::from_str_radix(suffix, 16).map_err(error_map);
        }

        match self {
            InputBase::Hex => u8::from_str_radix(s, 16),
            InputBase::Dec => s.parse::<u8>(),
        }
        .map_err(error_map)
    }

    /// Parses a separated list of bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use parser::InputBase;
    ///
    /// assert_eq!(InputBase::Hex.parse_list("1, 2, 10, 20", ','), vec![1, 2, 0x10, 0x20]);
    /// assert_eq!(InputBase::Dec.parse_list("1, 2, 10, 20", ','), vec![1, 2, 10, 20]);
    /// assert_eq!(InputBase::Dec.parse_list("1:2:3:123", ':'), vec![1, 2, 3, 123]);
    ///
    /// // Parsing is lenient (ignores/skips errors)
    /// assert_eq!(InputBase::Dec.parse_list("1, 2, foo, 10, bar, 20", ','), vec![1, 2, 10, 20]);
    /// ```
    pub fn parse_list(self, list: &str, separator: char) -> Vec<u8> {
        list.split(separator)
            .map(|b| self.try_parse(b.trim()))
            .filter_map(|r| {
                if let Err(ref err) = r {
                    eprintln!("NOTE: error parsing '{}': {:?}", err.input, err.error);
                }
                r.ok()
            })
            .collect()
    }
}
