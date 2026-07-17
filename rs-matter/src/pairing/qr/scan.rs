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

//! Recognizing a Matter onboarding QR code *in an image*.
//!
//! These functions take **8-bit greyscale (luma) pixels plus the image dimensions**,
//! and nothing else - deliberately the narrowest useful currency. It is what QR
//! recognition actually needs, every source produces it cheaply (a camera's YUV
//! frame already *has* luma as its Y plane), and it keeps image-format decoding -
//! and the dependencies that come with it - out of `rs-matter`. Loading a file, or
//! pulling a frame off a camera, is the caller's job.
//!
//! # Example
//!
//! ```ignore
//! // `img` is whatever the caller already has - here, via the `image` crate.
//! let luma = image::open("qr.png")?.to_luma8();
//!
//! let text = scan_luma(luma.width() as _, luma.height() as _, &luma)?;
//!
//! let mut buf = [0; 128];
//! let payload = QrPayload::parse(&text, &mut buf)?;
//! ```

use crate::error::{Error, ErrorCode};

use rqrr::{MetaData, PreparedImage};

use super::QR_PREFIX;

use alloc::string::String;

extern crate alloc;

/// Scan an 8-bit greyscale image for a Matter onboarding QR code, returning its
/// `MT:...` text.
///
/// `luma` is the row-major pixel buffer (`0` = black, `255` = white) and must hold
/// at least `width * height` bytes; any trailing bytes are ignored, so a buffer
/// with padding is fine as long as its rows are not strided (for strided sources,
/// use [`scan_luma_with`]).
///
/// # Errors
/// - [`ErrorCode::InvalidData`] if `luma` is too small for `width * height`.
/// - [`ErrorCode::NotFound`] if the image contains no readable Matter QR code.
pub fn scan_luma(width: usize, height: usize, luma: &[u8]) -> Result<String, Error> {
    let pixels = width.checked_mul(height).ok_or(ErrorCode::InvalidData)?;

    if luma.len() < pixels {
        return Err(ErrorCode::InvalidData.into());
    }

    scan_luma_with(width, height, |x, y| luma[y * width + x])
}

/// Scan an 8-bit greyscale image for a Matter onboarding QR code, sampling the
/// pixels through `fill` rather than from a buffer.
///
/// `fill(x, y)` returns the luminance at that pixel (`0` = black, `255` = white).
/// This is the zero-copy entry point: it lets a caller convert RGBA to luma on the
/// fly, or read a camera frame's Y plane through its row stride, without building
/// an intermediate greyscale image.
///
/// # Errors
/// [`ErrorCode::NotFound`] if the image contains no readable Matter QR code.
pub fn scan_luma_with<F>(width: usize, height: usize, fill: F) -> Result<String, Error>
where
    F: FnMut(usize, usize) -> u8,
{
    let mut img = PreparedImage::prepare_from_greyscale(width, height, fill);
    let grids = img.detect_grids();

    first_matter_qr(grids.into_iter().map(|grid| grid.decode()))
}

/// Scan a black-and-white bitmap for a Matter onboarding QR code.
///
/// `fill(x, y)` returns `true` where the pixel is *black*. This suits sources that
/// are already binary - a rendered symbol, or an image a caller has thresholded
/// itself. For photographs prefer [`scan_luma`] / [`scan_luma_with`], which let the
/// recognizer do its own (much better) binarisation.
///
/// # Errors
/// [`ErrorCode::NotFound`] if the image contains no readable Matter QR code.
pub fn scan_bitmap<F>(width: usize, height: usize, fill: F) -> Result<String, Error>
where
    F: FnMut(usize, usize) -> bool,
{
    // Note: unlike the greyscale path, this skips `rqrr`'s binarisation pass - the
    // input is already black-and-white.
    let mut img = PreparedImage::prepare_from_bitmap(width, height, fill);
    let grids = img.detect_grids();

    first_matter_qr(grids.into_iter().map(|grid| grid.decode()))
}

/// Pick the first Matter QR code out of everything recognized in an image.
///
/// An image may legitimately contain several QR codes (a Wi-Fi code, a URL, a
/// vCard...), so codes that do not carry a Matter payload are skipped rather than
/// returned or treated as an error. Codes that fail to decode at all (partially
/// occluded, too blurry) are likewise skipped, so one bad symbol does not mask a
/// good one elsewhere in the frame.
///
/// Generic over the decode error `E` so that this - the only part worth sharing
/// between the entry points above - does not have to name `rqrr`'s image-buffer
/// types, which it does not re-export.
fn first_matter_qr<E>(
    decoded: impl Iterator<Item = Result<(MetaData, String), E>>,
) -> Result<String, Error> {
    for res in decoded {
        let Ok((_meta, content)) = res else {
            continue;
        };

        if content.starts_with(QR_PREFIX) {
            return Ok(content);
        }
    }

    Err(ErrorCode::NotFound.into())
}

#[cfg(test)]
mod tests {
    use crate::dm::devices::test::TEST_DEV_DET;
    use crate::pairing::qr::{CommFlowType, Qr, QrPayload};
    use crate::pairing::DiscoveryCapabilities;
    use crate::BasicCommData;

    use super::*;

    /// Render a QR code to a bitmap and read it back, exercising the whole chain:
    /// payload -> `MT:` text -> QR symbol -> recognition -> text -> parsed payload.
    ///
    /// Each module is drawn as `SCALE` pixels, surrounded by the 4-module quiet zone
    /// the recognizer needs to lock onto the symbol.
    #[test]
    fn scan_round_trips_a_rendered_qr() {
        const SCALE: usize = 4;
        const QUIET: usize = 4;

        let comm_data = BasicCommData {
            password: 20202021_u32.to_le_bytes().into(),
            discriminator: 3840,
        };

        let payload = QrPayload::new_from_basic_info(
            DiscoveryCapabilities::BLE,
            CommFlowType::Standard,
            comm_data,
            &TEST_DEV_DET,
            super::super::no_optional_data,
        );

        let mut str_buf = [0; 256];
        let text = unwrap!(payload.as_str(&mut str_buf), "Failed to encode").0;

        // Render the text as an actual QR symbol.
        let mut tmp_buf = [0; 2048];
        let mut out_buf = [0; 2048];
        let qr = unwrap!(
            Qr::compute(text, &mut tmp_buf, &mut out_buf),
            "Failed to render"
        );

        let modules = qr.size() as usize;
        let side = (modules + 2 * QUIET) * SCALE;

        // ... and recognize it back. `true` == black == a set module.
        let scanned = unwrap!(
            scan_bitmap(side, side, |x, y| {
                let mx = (x / SCALE) as i32 - QUIET as i32;
                let my = (y / SCALE) as i32 - QUIET as i32;

                qr.get_module(mx, my)
            }),
            "Failed to scan"
        );

        assert_eq!(scanned, text);

        // And the recognized text parses back to what we started from.
        let mut parse_buf = [0; 128];
        let parsed = unwrap!(
            QrPayload::parse(&scanned, &mut parse_buf),
            "Failed to parse"
        );

        assert_eq!(parsed.discriminator(), 3840);
        assert_eq!(parsed.passcode(), 20202021);
        assert_eq!(parsed.vid(), TEST_DEV_DET.vid);
        assert_eq!(parsed.pid(), TEST_DEV_DET.pid);
    }

    #[test]
    fn scan_finds_nothing_in_a_blank_image() {
        assert!(scan_luma(64, 64, &[255; 64 * 64]).is_err());
    }

    #[test]
    fn scan_luma_rejects_a_short_buffer() {
        assert!(scan_luma(64, 64, &[255; 16]).is_err());
    }
}
