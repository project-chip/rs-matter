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
//! The image is a [`QrLuma`]: **8-bit greyscale pixels and the image's width**, and
//! nothing else - deliberately the narrowest useful currency. It is what QR
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
//! let text = QrLuma::new(&luma, luma.width() as _).scan()?;
//!
//! let mut buf = [0; 128];
//! let payload = QrPayload::parse(&text, &mut buf)?;
//! ```

use crate::error::{Error, ErrorCode};

use rqrr::{BitGrid, Grid, MetaData, Point, PreparedImage, SimpleGrid};

use super::QR_PREFIX;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

extern crate alloc;

/// The radius of the square a pixel is averaged over against noise, before the
/// image is binarised here.
const DENOISE_RADIUS: usize = 2;

/// The side of the square around a pixel that its threshold is the mean of, as a
/// share of the image's longer side: several modules of any code that fits.
const THRESHOLD_SHARE: usize = 16;

/// How much darker than that mean a black pixel is.
const THRESHOLD_OFFSET: u8 = 1;

/// How far, in modules, a code's bottom-right corner is looked for around where
/// it is estimated to be, in turn, while the code read there does not decode.
const CORNER_STEPS: [f64; 5] = [0.0, -0.5, 0.5, -1.0, 1.0];

/// Where a module is read across, in modules off its centre, either way: nine
/// points in all.
const MODULE_SPREAD: [f64; 3] = [-0.25, 0.0, 0.25];

/// An 8-bit greyscale image, to look for a Matter onboarding QR code in.
#[derive(Clone, Copy)]
pub struct QrLuma<'a> {
    pixels: &'a [u8],
    width: usize,
}

impl<'a> QrLuma<'a> {
    /// The image of `pixels`, row-major (`0` = black, `255` = white), in rows of
    /// `width` pixels. Bytes past its last whole row are not part of it; rows with
    /// a stride have to be copied out of it first.
    pub const fn new(pixels: &'a [u8], width: usize) -> Self {
        Self { pixels, width }
    }

    /// The width of the image, in pixels.
    pub const fn width(&self) -> usize {
        self.width
    }

    /// The height of the image, in pixels: its whole rows.
    pub const fn height(&self) -> usize {
        match self.pixels.len().checked_div(self.width) {
            Some(height) => height,
            None => 0,
        }
    }

    /// Look for a Matter onboarding QR code in the image, returning its `MT:...`
    /// text.
    ///
    /// A code found nowhere is looked for again in the image binarised here:
    /// noise evened out, each pixel against the mean of a square around it. A dim,
    /// grainy frame (a code of little contrast, under noise as strong) defeats the
    /// recognizer's own threshold, a running mean along each row; each threshold
    /// finds codes the other misses.
    ///
    /// A code found that does not decode is read again from the image, each
    /// module across rather than at one pixel, with its bottom-right corner moved:
    /// the recognizer estimates that one, and a module off garbles that quarter of
    /// the code.
    ///
    /// # Errors
    /// [`ErrorCode::NotFound`] if the image contains no readable Matter QR code.
    pub fn scan(&self) -> Result<String, Error> {
        if self.height() == 0 {
            return Err(ErrorCode::NotFound.into());
        }

        self.scan_once().or_else(|_| self.scan_binarised())
    }

    /// Scan the image once, binarised by the recognizer.
    fn scan_once(&self) -> Result<String, Error> {
        let mut img =
            PreparedImage::prepare_from_greyscale(self.width, self.height(), |x, y| self.at(x, y));

        self.first_matter_qr(img.detect_grids())
    }

    /// Scan the image once, binarised here: averaged over [`DENOISE_RADIUS`], then
    /// each pixel black where darker than the mean around it (see
    /// [`THRESHOLD_SHARE`]). In sums, not means: a code of a dozen levels of
    /// contrast reads or not by a fraction of one.
    fn scan_binarised(&self) -> Result<String, Error> {
        let (width, height) = (self.width, self.height());

        let mut smooth = vec![0u32; width * height];
        box_sums(self.pixels, width, height, DENOISE_RADIUS, |at, sum| {
            smooth[at] = sum as u32
        });

        let smooth_area = square(DENOISE_RADIUS);
        let radius = (width.max(height) / THRESHOLD_SHARE / 2).max(1);
        let area = square(radius);

        let mut black = vec![false; width * height];
        box_sums(&smooth, width, height, radius, |at, sum| {
            let offset = u64::from(THRESHOLD_OFFSET) * smooth_area;
            black[at] = (u64::from(smooth[at]) + offset) * area < sum;
        });
        drop(smooth);

        let mut img =
            PreparedImage::prepare_from_bitmap(width, height, |x, y| black[y * width + x]);

        self.first_matter_qr(img.detect_grids())
    }

    /// Pick the first Matter QR code out of the codes found in the image.
    ///
    /// An image may legitimately contain several QR codes (a Wi-Fi code, a URL, a
    /// vCard...), so codes that do not carry a Matter payload are skipped rather
    /// than returned or treated as an error. A code that does not decode is read
    /// again (see [`Self::refit`]), and else skipped likewise (partially occluded,
    /// too blurry), so one bad symbol does not mask a good one elsewhere in the
    /// frame.
    fn first_matter_qr<G>(&self, grids: Vec<Grid<G>>) -> Result<String, Error>
    where
        G: BitGrid,
    {
        for grid in grids {
            let decoded = grid
                .decode()
                .ok()
                .or_else(|| self.refit(&grid.bounds, grid.grid.size()));
            let Some((_meta, content)) = decoded else {
                continue;
            };

            if content.starts_with(QR_PREFIX) {
                return Ok(content);
            }
        }

        Err(ErrorCode::NotFound.into())
    }

    /// Read a code of `size` modules found at `bounds` (top-left, top-right,
    /// bottom-right, bottom-left; a module wider than the code, as the recognizer
    /// has them), which did not decode, again.
    ///
    /// The recognizer estimates the bottom-right corner, where there is no finder
    /// pattern (nor, in a version 1 code, an alignment pattern), and a corner a
    /// module off garbles that quarter of the code. Corners around its estimate,
    /// and around the parallelogram's of the other three, are tried in turn (see
    /// [`CORNER_STEPS`]), until the code read there decodes.
    fn refit(&self, bounds: &[Point; 4], size: usize) -> Option<(MetaData, String)> {
        let [top_left, top_right, bottom_right, bottom_left] =
            bounds.map(|p| (f64::from(p.x), f64::from(p.y)));

        let module = (top_right.0 - top_left.0).hypot(top_right.1 - top_left.1) / (size + 1) as f64;
        let parallelogram = (
            top_right.0 + bottom_left.0 - top_left.0,
            top_right.1 + bottom_left.1 - top_left.1,
        );

        for estimate in [bottom_right, parallelogram] {
            for dy in CORNER_STEPS {
                for dx in CORNER_STEPS {
                    let corner = (estimate.0 + dx * module, estimate.1 + dy * module);
                    let modules =
                        self.read_modules([top_left, top_right, corner, bottom_left], size);

                    if let Ok(decoded) = modules.decode() {
                        return Some(decoded);
                    }
                }
            }
        }

        None
    }

    /// The modules of a code of `size` modules at `corners` (as
    /// [`Self::refit`]'s bounds): each the mean of nine points across it (see
    /// [`MODULE_SPREAD`]), black up to the code's threshold (see [`otsu`]).
    fn read_modules(&self, corners: [(f64, f64); 4], size: usize) -> Grid<SimpleGrid> {
        let map = square_to(corners);
        let span = (size + 1) as f64;

        let sums: Vec<u32> = (0..size * size)
            .map(|at| {
                let (x, y) = ((at % size) as f64 + 0.5, (at / size) as f64 + 0.5);

                MODULE_SPREAD
                    .iter()
                    .flat_map(|dy| MODULE_SPREAD.iter().map(move |dx| (*dx, *dy)))
                    .map(|(dx, dy)| {
                        let (px, py) = map((x + dx) / span, (y + dy) / span);
                        u32::from(self.at_point(px, py))
                    })
                    .sum()
            })
            .collect();
        let threshold = otsu(&sums);

        Grid::new(SimpleGrid::from_func(size, |x, y| {
            sums[y * size + x] <= threshold
        }))
    }

    fn at(&self, x: usize, y: usize) -> u8 {
        self.pixels[y * self.width + x]
    }

    /// The pixel at point `(x, y)`, or the nearest edge one off the image.
    fn at_point(&self, x: f64, y: f64) -> u8 {
        let x = (x as isize).clamp(0, self.width as isize - 1) as usize;
        let y = (y as isize).clamp(0, self.height() as isize - 1) as usize;

        self.at(x, y)
    }
}

/// The number of pixels in the square of `radius` around a pixel.
fn square(radius: usize) -> u64 {
    let side = 2 * radius as u64 + 1;

    side * side
}

/// Call `each` with every pixel of `image` (its index; `width` x `height`) and
/// the sum of the square of `radius` around it, where its edge pixels stand in
/// for those beyond it.
fn box_sums<T>(
    image: &[T],
    width: usize,
    height: usize,
    radius: usize,
    mut each: impl FnMut(usize, u64),
) where
    T: Copy + Into<u32>,
{
    let r = radius as isize;

    // Sums along rows, then of those along columns: a running sum each.
    let mut rows = vec![0u32; width * height];
    for y in 0..height {
        let row = &image[y * width..][..width];
        let at = |x: isize| row[x.clamp(0, width as isize - 1) as usize].into();

        let mut sum: u32 = (-r..=r).map(at).sum();
        for x in 0..width as isize {
            rows[y * width + x as usize] = sum;
            sum = sum + at(x + r + 1) - at(x - r);
        }
    }

    for x in 0..width {
        let at = |y: isize| u64::from(rows[y.clamp(0, height as isize - 1) as usize * width + x]);

        let mut sum: u64 = (-r..=r).map(at).sum();
        for y in 0..height as isize {
            each(y as usize * width + x, sum);
            sum = sum + at(y + r + 1) - at(y - r);
        }
    }
}

/// The projective map of the unit square onto `corners` (top-left, top-right,
/// bottom-right, bottom-left).
fn square_to(corners: [(f64, f64); 4]) -> impl Fn(f64, f64) -> (f64, f64) {
    let [(x0, y0), (x1, y1), (x2, y2), (x3, y3)] = corners;

    let (sx, sy) = (x0 - x1 + x2 - x3, y0 - y1 + y2 - y3);
    let (dx1, dy1, dx2, dy2) = (x1 - x2, y1 - y2, x3 - x2, y3 - y2);
    let det = dx1 * dy2 - dx2 * dy1;
    let (g, h) = if det == 0.0 {
        (0.0, 0.0)
    } else {
        ((sx * dy2 - dx2 * sy) / det, (dx1 * sy - sx * dy1) / det)
    };

    let (a, b, c) = (x1 - x0 + g * x1, x3 - x0 + h * x3, x0);
    let (d, e, f) = (y1 - y0 + g * y1, y3 - y0 + h * y3, y0);

    move |u, v| {
        let w = g * u + h * v + 1.0;
        ((a * u + b * v + c) / w, (d * u + e * v + f) / w)
    }
}

/// The value that splits `values` into the two most distinct classes (Otsu's
/// threshold): the greatest of the lower one.
fn otsu(values: &[u32]) -> u32 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();

    let total: u64 = sorted.iter().map(|value| u64::from(*value)).sum();
    let count = sorted.len();

    let (mut below, mut best, mut threshold) = (0u64, 0f64, sorted.first().copied().unwrap_or(0));
    for (i, pair) in sorted.windows(2).enumerate() {
        below += u64::from(pair[0]);
        if pair[0] == pair[1] {
            continue;
        }

        let (lower, upper) = ((i + 1) as f64, (count - i - 1) as f64);
        let gap = below as f64 / lower - (total - below) as f64 / upper;
        let between = lower * upper * gap * gap;
        if between > best {
            (best, threshold) = (between, pair[0]);
        }
    }

    threshold
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::dm::devices::test::TEST_DEV_DET;
    use crate::pairing::qr::{CommFlowType, Qr, QrPayload};
    use crate::pairing::DiscoveryCapabilities;
    use crate::BasicCommData;

    use super::*;

    /// The quiet zone around a rendered code, in modules.
    const QUIET: usize = 4;

    /// The test device's `MT:` text, and its QR symbol drawn `scale` pixels a
    /// module inside the 4-module quiet zone the recognizer needs: `side` pixels
    /// square, row-major, `true` for black.
    fn rendered(scale: usize) -> (String, usize, Vec<bool>) {
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

        let mut tmp_buf = [0; 2048];
        let mut out_buf = [0; 2048];
        let qr = unwrap!(
            Qr::compute(text, &mut tmp_buf, &mut out_buf),
            "Failed to render"
        );

        let side = (qr.size() as usize + 2 * QUIET) * scale;
        let bitmap = (0..side * side)
            .map(|i| {
                let mx = ((i % side) / scale) as i32 - QUIET as i32;
                let my = ((i / side) / scale) as i32 - QUIET as i32;

                qr.get_module(mx, my)
            })
            .collect();

        (text.into(), side, bitmap)
    }

    /// Render a QR code to a bitmap and read it back, exercising the whole chain:
    /// payload -> `MT:` text -> QR symbol -> recognition -> text -> parsed payload.
    #[test]
    fn scan_round_trips_a_rendered_qr() {
        let (text, side, bitmap) = rendered(4);

        let luma: Vec<u8> = bitmap
            .iter()
            .map(|black| if *black { 0 } else { 255 })
            .collect();

        let scanned = unwrap!(QrLuma::new(&luma, side).scan(), "Failed to scan");

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

    /// A small, soft code - 3 pixels a module, blurred over 3 x 3 pixels, as a
    /// camera sees a printed label - is found, but garbled as the recognizer
    /// reads it, a pixel a module; read across each module, it decodes.
    #[test]
    fn scan_rereads_a_small_soft_code() {
        let (text, side, bitmap) = rendered(3);

        let luma: Vec<u8> = (0..side * side)
            .map(|i| {
                let (x, y) = (i % side, i / side);
                let (mut sum, mut count) = (0u32, 0u32);
                for ny in y.saturating_sub(1)..=(y + 1).min(side - 1) {
                    for nx in x.saturating_sub(1)..=(x + 1).min(side - 1) {
                        sum += if bitmap[ny * side + nx] { 0 } else { 255 };
                        count += 1;
                    }
                }

                (sum / count) as u8
            })
            .collect();

        let mut img = PreparedImage::prepare_from_greyscale(side, side, |x, y| luma[y * side + x]);
        let grids = img.detect_grids();
        assert_eq!(grids.len(), 1);
        assert!(grids[0].decode().is_err());

        assert_eq!(
            unwrap!(QrLuma::new(&luma, side).scan(), "Failed to scan"),
            text
        );
    }

    /// A dim, grainy code - 16 levels of contrast under noise of as many, as a
    /// phone's camera sees a label in lamplight - eludes the recognizer's own
    /// threshold, and reads binarised here.
    #[test]
    fn scan_reads_a_dim_grainy_code() {
        const SCALE: usize = 8;
        const BLACK: i32 = 37;
        const WHITE: i32 = 53;
        const NOISE: u32 = 16;

        let (text, side, bitmap) = rendered(SCALE);

        let mut seed = 0x2545_f491_u32;
        let luma: Vec<u8> = bitmap
            .iter()
            .map(|black| {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let noise = ((seed >> 16) % (NOISE + 1)) as i32 - NOISE as i32 / 2;

                (if *black { BLACK } else { WHITE } + noise) as u8
            })
            .collect();

        let image = QrLuma::new(&luma, side);
        assert!(image.scan_once().is_err());
        assert_eq!(unwrap!(image.scan_binarised(), "Failed to scan"), text);
    }

    /// A code found with its bottom-right corner off, as the recognizer can
    /// estimate it, reads with the corner moved back.
    #[test]
    fn refit_moves_a_misplaced_corner() {
        const SCALE: usize = 6;

        let (text, side, bitmap) = rendered(SCALE);
        let luma: Vec<u8> = bitmap
            .iter()
            .map(|black| if *black { 0 } else { 255 })
            .collect();
        let size = side / SCALE - 2 * QUIET;

        // A module wider than the code, as the recognizer has them; the
        // bottom-right corner two modules in.
        let near = (QUIET * SCALE) as i32;
        let far = ((QUIET + size + 1) * SCALE) as i32;
        let off = far - 2 * SCALE as i32;
        let bounds = [
            Point { x: near, y: near },
            Point { x: far, y: near },
            Point { x: off, y: off },
            Point { x: near, y: far },
        ];

        let image = QrLuma::new(&luma, side);
        let corners = bounds.map(|p| (f64::from(p.x), f64::from(p.y)));
        assert!(image.read_modules(corners, size).decode().is_err());

        let refitted = unwrap!(
            image.refit(&bounds, size).ok_or(ErrorCode::NotFound),
            "Failed to refit"
        );
        assert_eq!(refitted.1, text);
    }

    #[test]
    fn scan_finds_nothing_in_a_blank_image() {
        assert!(QrLuma::new(&[255; 64 * 64], 64).scan().is_err());
    }

    /// The image is the whole rows of its pixels; with none, there is nothing to
    /// scan.
    #[test]
    fn height_counts_whole_rows() {
        assert_eq!(QrLuma::new(&[255; 64 * 3 + 16], 64).height(), 3);
        assert_eq!(QrLuma::new(&[255; 16], 64).height(), 0);
        assert_eq!(QrLuma::new(&[255; 16], 0).height(), 0);
        assert!(QrLuma::new(&[255; 16], 64).scan().is_err());
    }
}
