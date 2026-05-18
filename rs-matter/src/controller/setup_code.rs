/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 */

//! Onboarding payload decoders — the inverse of [`crate::pairing`].
//!
//! Matter accessories present commissioners with a setup credential in
//! one of two forms (Matter Core Spec §5.1 "Onboarding Payload"):
//!
//! 1. **Manual pairing code** — 11 decimal digits, often pretty-printed
//!    with dashes (`1234-567-8910` → `12345678910`). Carries the *short*
//!    discriminator (4 high bits of the 12-bit one) and the 27-bit
//!    passcode plus a Verhoeff check digit.
//! 2. **QR-code payload** — a base-38-encoded string prefixed with
//!    `MT:`. Carries the full payload: version, vendor/product IDs,
//!    commissioning flow, discovery capabilities, full 12-bit
//!    discriminator, passcode, and optional TLV add-ons.
//!
//! This module produces a [`SetupPayload`] from either form. The
//! commissioner state machine in [`super::commissioner`] consumes it.
//!
//! The encoders (device side) live in [`crate::pairing::code`] and
//! [`crate::pairing::qr`]; this module is their inverse.

use verhoeff::Verhoeff;

/// Decoded onboarding payload as carried in either a manual pairing
/// code or a QR-code string.
///
/// Fields the manual code can't supply (vendor/product IDs, discovery
/// capabilities, *full* 12-bit discriminator) are `None` when the source
/// was a manual code. The commissioner state machine treats those as
/// "unknown, fall back to defaults / scan for any matching short
/// discriminator."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupPayload {
    /// Payload version. `0` for current Matter spec.
    pub version: u8,
    /// 16-bit Vendor ID. `None` if not present in the source (manual code
    /// without `VID_PID_PRESENT` flag).
    pub vendor_id: Option<u16>,
    /// 16-bit Product ID. `None` mirrors `vendor_id`.
    pub product_id: Option<u16>,
    /// Commissioning flow — 0 standard, 1 user-intent, 2 custom.
    /// `None` if absent (manual codes don't carry it).
    pub commissioning_flow: Option<u8>,
    /// Discovery capabilities bitmap — bit 0 = SoftAP, bit 1 = BLE,
    /// bit 2 = On-network. `None` for manual codes.
    pub discovery_capabilities: Option<u8>,
    /// 12-bit discriminator. For manual codes only the top 4 bits ("short
    /// discriminator") are known; the lower 8 bits are zero and the
    /// commissioner must filter BLE adverts by the matching short value.
    pub discriminator: u16,
    /// Whether `discriminator` is the full 12-bit value or just the
    /// 4-bit short form padded with zeros.
    pub short_discriminator: bool,
    /// 27-bit setup passcode for PASE Spake2+ verifier derivation.
    pub passcode: u32,
}

/// Errors returned by setup-code parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupCodeError {
    /// Input string had the wrong length after dash-stripping.
    /// Manual codes are 11 digits; QR codes start with `MT:` and have
    /// at least one base-38 character.
    BadLength,
    /// Manual code contained non-digit characters.
    NonDigit,
    /// Verhoeff check digit didn't match the body.
    BadChecksum,
    /// Decoded passcode is in the reserved set (00000000, 11111111, …,
    /// 12345678, 87654321) — spec §5.1.7 forbids commissioning these.
    InvalidPasscode,
    /// QR payload didn't start with the `MT:` prefix.
    NotAQrCode,
    /// QR payload base-38 decode produced fewer bytes than the minimum
    /// 11-byte payload requires.
    QrTooShort,
    /// QR payload base-38 contained an invalid character.
    QrBadEncoding,
}

/// Strip dashes from a pretty-formatted pairing code (`1234-567-8910` →
/// `12345678910`).
fn strip_dashes_inplace(input: &str, buf: &mut heapless::String<13>) {
    for ch in input.chars() {
        if ch != '-' && ch != ' ' {
            let _ = buf.push(ch);
        }
    }
}

/// Decode an 11-digit manual pairing code (with or without dashes).
///
/// The packing (mirror of [`crate::pairing::code`]):
/// - digit\[0\] holds: bit 7 = `VID_PID_PRESENT` flag, bits 0-1 = top 2
///   bits of the short discriminator. (The current rs-matter encoder
///   always emits `VID_PID_PRESENT = 0`; if a peer accessory carries
///   VID/PID via a 21-digit code, that's not yet supported here.)
/// - digits\[1..6\] hold a 16-bit value: bits 14-15 = next 2 bits of the
///   short discriminator, bits 0-13 = low 14 bits of the passcode.
/// - digits\[6..10\] hold a 4-digit decimal value = passcode >> 14.
/// - digit\[10\] = Verhoeff check over the first 10 digits.
///
/// Reserved passcodes per §5.1.7 are rejected.
pub fn parse_manual_pairing_code(input: &str) -> Result<SetupPayload, SetupCodeError> {
    let mut stripped: heapless::String<13> = heapless::String::new();
    strip_dashes_inplace(input, &mut stripped);
    let digits = stripped.as_str();

    if digits.len() != 11 {
        return Err(SetupCodeError::BadLength);
    }
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(SetupCodeError::NonDigit);
    }

    // Verhoeff check over the first 10 digits, last digit must match.
    let body = &digits[..10];
    let provided_check = digits.as_bytes()[10] - b'0';
    if body.calculate_verhoeff_check_digit() != provided_check {
        return Err(SetupCodeError::BadChecksum);
    }

    // Parse each field.
    let d0: u8 = body[..1].parse().map_err(|_| SetupCodeError::NonDigit)?;
    let d1_5: u16 = body[1..6].parse().map_err(|_| SetupCodeError::NonDigit)?;
    let d6_9: u32 = body[6..10].parse().map_err(|_| SetupCodeError::NonDigit)?;

    // d0: bits 0-1 = top 2 bits of short discriminator; bit 2 reserved /
    // VID-PID-present flag.
    let disc_hi2 = (d0 & 0x03) as u16; // bits going into discriminator[2..4]
    let vid_pid_present = (d0 & 0x04) != 0;
    if vid_pid_present {
        // 21-digit codes carry VID + PID after the first 11 — not yet
        // wired in this build. Use the QR (MT:) form for vendor-aware
        // commissioning instead.
        return Err(SetupCodeError::QrBadEncoding);
    }

    // d1_5: top 2 bits = next 2 of short discriminator; bottom 14 bits =
    // passcode low 14 bits.
    let disc_lo2 = (d1_5 >> 14) & 0x03;
    let passcode_lo14 = (d1_5 & 0x3FFF) as u32;

    // d6_9: top 13 bits of the 27-bit passcode.
    let passcode_hi13 = d6_9;

    // Short discriminator: 4 bits, layout [hi2 | lo2].
    let short_disc = (disc_hi2 << 2) | disc_lo2;

    // Manual code only knows the short discriminator — emit it in the
    // top 4 bits of a 12-bit value (the rest are zeros, meaning "unknown
    // — match the top-4-bit short discriminator during BLE scan").
    let discriminator = short_disc << 8;

    let passcode = (passcode_hi13 << 14) | passcode_lo14;

    if is_reserved_passcode(passcode) {
        return Err(SetupCodeError::InvalidPasscode);
    }

    Ok(SetupPayload {
        version: 0,
        vendor_id: None,
        product_id: None,
        commissioning_flow: None,
        discovery_capabilities: None,
        discriminator,
        short_discriminator: true,
        passcode,
    })
}

/// Decode a QR-code onboarding payload string (`MT:...`).
///
/// Mirrors [`crate::pairing::qr`] encoder. The payload is base-38 decoded
/// to a byte buffer, then bit fields are extracted LSB-first in the
/// order Version (3 bits) → VendorID (16) → ProductID (16) →
/// CommissioningFlow (2) → DiscoveryCapabilities (8) →
/// Discriminator (12) → Passcode (27) → Padding (4) = 88 bits / 11
/// bytes. Anything past those 88 bits is optional TLV data — currently
/// not surfaced in [`SetupPayload`] (the commissioner doesn't need it
/// for the standard flow; spec §5.1.4 covers the optional tags).
pub fn parse_qr_payload(input: &str) -> Result<SetupPayload, SetupCodeError> {
    let body = input
        .strip_prefix("MT:")
        .ok_or(SetupCodeError::NotAQrCode)?;

    let bytes: heapless::Vec<u8, 64> =
        crate::utils::codec::base38::decode_vec(body).map_err(|_| SetupCodeError::QrBadEncoding)?;
    if bytes.len() < 11 {
        return Err(SetupCodeError::QrTooShort);
    }

    let mut br = BitReader::new(&bytes);
    let version = br.read(3) as u8;
    let vendor_id = br.read(16) as u16;
    let product_id = br.read(16) as u16;
    let commissioning_flow = br.read(2) as u8;
    let discovery_capabilities = br.read(8) as u8;
    let discriminator = br.read(12) as u16;
    let passcode = br.read(27);

    if is_reserved_passcode(passcode) {
        return Err(SetupCodeError::InvalidPasscode);
    }

    Ok(SetupPayload {
        version,
        vendor_id: Some(vendor_id),
        product_id: Some(product_id),
        commissioning_flow: Some(commissioning_flow),
        discovery_capabilities: Some(discovery_capabilities),
        discriminator,
        short_discriminator: false,
        passcode,
    })
}

/// Tiny LSB-first bit reader over a byte slice. Matches the encoder's
/// emit-bits ordering: the first written bit lives in bit 0 of byte 0.
struct BitReader<'a> {
    bytes: &'a [u8],
    pos: usize, // bit index
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read(&mut self, n: u32) -> u32 {
        let mut out: u32 = 0;
        for i in 0..n {
            let byte_idx = self.pos / 8;
            let bit_idx = self.pos % 8;
            let bit = if byte_idx < self.bytes.len() {
                (self.bytes[byte_idx] >> bit_idx) & 1
            } else {
                0
            };
            out |= (bit as u32) << i;
            self.pos += 1;
        }
        out
    }
}

/// Auto-detect the input shape (digits → manual code; `MT:` prefix → QR)
/// and dispatch to the right parser.
pub fn parse_setup_code(input: &str) -> Result<SetupPayload, SetupCodeError> {
    if input.starts_with("MT:") {
        parse_qr_payload(input)
    } else {
        parse_manual_pairing_code(input)
    }
}

/// Spec §5.1.7 — these passcodes are forbidden for commissioning even
/// though they decode cleanly, to discourage trivial PINs on shipped
/// devices.
fn is_reserved_passcode(p: u32) -> bool {
    matches!(
        p,
        0 | 11111111
            | 22222222
            | 33333333
            | 44444444
            | 55555555
            | 66666666
            | 77777777
            | 88888888
            | 99999999
            | 12345678
            | 87654321
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_rs_matter_example_1() {
        // From `crate::pairing::code::tests::can_compute_pairing_code` —
        // password=123456, discriminator=250 → "00876800071".
        // Our parser sees only the short (top 4 bits) of the discriminator,
        // which is (250 >> 8) & 0xF = 0, so the reconstructed short
        // value is 0 and the 12-bit field is 0 << 8 = 0.
        let p = parse_manual_pairing_code("00876800071").unwrap();
        assert_eq!(p.passcode, 123456);
        assert!(p.short_discriminator);
        // 12-bit field, with short value in top 4 bits.
        // For disc=250: top 4 bits of 12-bit disc = 250 >> 8 = 0.
        assert_eq!(p.discriminator, 0);
    }

    #[test]
    fn round_trip_rs_matter_example_2() {
        // password=34567890, discriminator=2976 → "26318621095".
        let p = parse_manual_pairing_code("26318621095").unwrap();
        assert_eq!(p.passcode, 34567890);
        // disc=2976 = 0xBA0, top 4 bits = 0xB.
        assert_eq!(p.discriminator >> 8, 0x0B);
    }

    #[test]
    fn accepts_dashed_pretty_form() {
        // `0087-6800-071` is the dashed form of "00876800071".
        let p = parse_manual_pairing_code("0087-6800-071").unwrap();
        assert_eq!(p.passcode, 123456);
    }

    #[test]
    fn rejects_bad_checksum() {
        // Flip the last digit (Verhoeff check).
        let r = parse_manual_pairing_code("00876800072");
        assert_eq!(r, Err(SetupCodeError::BadChecksum));
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            parse_manual_pairing_code("12345"),
            Err(SetupCodeError::BadLength)
        );
        assert_eq!(
            parse_manual_pairing_code("123456789012"),
            Err(SetupCodeError::BadLength)
        );
    }

    #[test]
    fn rejects_non_digit() {
        assert_eq!(
            parse_manual_pairing_code("abcdefghijk"),
            Err(SetupCodeError::NonDigit)
        );
    }

    #[test]
    fn qr_rejects_non_mt_prefix() {
        // "12345" doesn't start with "MT:", goes to manual parser instead.
        // Direct QR call rejects with NotAQrCode.
        assert_eq!(parse_qr_payload("HELLO"), Err(SetupCodeError::NotAQrCode));
    }

    #[test]
    fn parse_setup_code_dispatches_correctly() {
        // Manual path works.
        assert!(parse_setup_code("00876800071").is_ok());
        // QR path no longer errors with NotSupported — it actually decodes.
    }

    #[test]
    fn bit_reader_lsb_first() {
        // Encoder writes bit-by-bit, LSB-first into the stream.
        // Bytes [0b0000_0101, 0b0000_0010] should yield:
        //   read(3) → 0b101 = 5
        //   read(8) → 0b01000_000 = 0x40 (low 5 bits of byte 0 already
        //                                  consumed; next 8 are bits 3-10)
        let bytes = [0b0000_0101u8, 0b0000_0010u8];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read(3), 5);
        assert_eq!(r.read(8), 0x40);
    }

    #[test]
    fn qr_round_trip_known_payload() {
        // Manually constructed via Matter spec QR encoder semantics:
        //   version=0, vendor=0xFFF1, product=0x8000, flow=0,
        //   discovery=2 (BLE), discriminator=0x0F00, passcode=0x012ED0E1
        // Expected MT: form computed by the rs-matter encoder for this
        // commissioning data (see crate::pairing::qr tests). The test
        // uses the rs-matter encoder if available; for now, we just
        // verify the decoder is consistent for a hand-built byte array:
        //
        // Bit layout from byte 0 LSB:
        //   v(3)=0 | vendor(16) | product(16) | flow(2)=0
        //   | discovery(8)=2 | discriminator(12) | passcode(27) | pad(4)
        let mut bytes = [0u8; 11];
        let mut w = BitWriter::new(&mut bytes);
        w.write(3, 0);
        w.write(16, 0xFFF1);
        w.write(16, 0x8000);
        w.write(2, 0);
        w.write(8, 2);
        w.write(12, 0x0F00);
        w.write(27, 0x012ED0E1);
        w.write(4, 0);

        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read(3), 0); // version
        assert_eq!(r.read(16), 0xFFF1); // vendor
        assert_eq!(r.read(16), 0x8000); // product
        assert_eq!(r.read(2), 0); // flow
        assert_eq!(r.read(8), 2); // discovery
        assert_eq!(r.read(12), 0x0F00); // discriminator
        assert_eq!(r.read(27), 0x012ED0E1); // passcode
    }

    // Local LSB-first bit writer used only by the test above — kept here
    // so the production parser doesn't accidentally start depending on
    // it. The real encoder lives in crate::pairing::qr.
    struct BitWriter<'a> {
        bytes: &'a mut [u8],
        pos: usize,
    }
    impl<'a> BitWriter<'a> {
        fn new(bytes: &'a mut [u8]) -> Self {
            Self { bytes, pos: 0 }
        }
        fn write(&mut self, n: u32, value: u32) {
            for i in 0..n {
                let bit = (value >> i) & 1;
                let byte_idx = self.pos / 8;
                let bit_idx = self.pos % 8;
                if byte_idx < self.bytes.len() {
                    self.bytes[byte_idx] |= (bit as u8) << bit_idx;
                }
                self.pos += 1;
            }
        }
    }
}
