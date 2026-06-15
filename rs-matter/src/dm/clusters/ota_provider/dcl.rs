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

//! An [`OtaImagesRegistry`] + [`OtaImages`] implementation backed by the
//! CSA-IOT Distributed Compliance Ledger (DCL) and a firmware hosted via HTTP/HTTPS.
//!
//! HTTP/HTTPS itself is left to the application via the [`OtaHttp`] trait, so this stays
//! `no_std` and transport-agnostic (plug in `edge-http` + mbedtls, or anything
//! else). JSON is parsed with `serde-json-core`.
//!
//! All sizable working memory is caller-injected: [`DclImages::new`] takes a
//! scratch slice (used for the request URL and the JSON response - a couple of KiB
//! is plenty), so nothing large lives on the stack per call.
//!
//! The DCL REST shapes used here (see <https://docs.dcl.csa-iot.org>):
//! - `GET {base}/dcl/model/versions/{vid}/{pid}` -> `{ modelVersions: { softwareVersions: [..] } }`
//! - `GET {base}/dcl/model/versions/{vid}/{pid}/{version}` -> `{ modelVersion: { otaUrl, otaFileSize, .. } }`

use core::fmt::Write as _;

use heapless::String;

use serde::Deserialize;

use crate::error::{Error, ErrorCode};
use crate::utils::storage::WriteBuf;
use crate::utils::sync::IfMutex;

use super::{OtaImageMeta, OtaImages, OtaImagesRegistry, MAX_FILE_DESIGNATOR};

/// The CSA-IOT production DCL REST endpoint.
pub const DCL_MAINNET: &str = "https://on.dcl.csa-iot.org";
/// The CSA-IOT test-net DCL REST endpoint.
pub const DCL_TESTNET: &str = "https://on.test-net.dcl.csa-iot.org";

/// The maximum number of offered software versions parsed from a DCL version
/// list (a sample bound; a longer list fails to parse).
const MAX_VERSIONS: usize = 16;
/// The portion of the scratch buffer reserved for building a request/firmware URL;
/// the remainder holds the JSON response.
const MAX_URL: usize = 256;

/// A minimal pluggable HTTP/HTTPS client used to talk to the DCL and the firmware
/// host.
///
/// An implementation performs a `GET` of `url` and writes the response body into
/// `buf`, returning the number of bytes written. When `range` is
/// `Some((start, len))` it must request only `len` bytes starting at `start`
/// (i.e. send `Range: bytes=start-start+len-1`); a server returning fewer bytes
/// (e.g. the tail of the file) is fine, and `0` marks end-of-file.
pub trait OtaHttp {
    /// Perform the GET. See the trait docs for `range`/return semantics.
    async fn get(
        &self,
        url: &str,
        range: Option<(u64, usize)>,
        buf: &mut [u8],
    ) -> Result<usize, Error>;
}

impl<T> OtaHttp for &T
where
    T: OtaHttp,
{
    async fn get(
        &self,
        url: &str,
        range: Option<(u64, usize)>,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        T::get(self, url, range, buf).await
    }
}

/// A DCL-backed OTA image source, over a pluggable [`OtaHttp`] client.
///
/// Implements both [`OtaImagesRegistry`] (for an [`OtaProviderHandler`]) and
/// [`OtaImages`] (for an [`OtaBdxHandler`]). All large working buffers are
/// caller-injected via [`new`](Self::new).
///
/// [`OtaProviderHandler`]: super::OtaProviderHandler
/// [`OtaBdxHandler`]: super::OtaBdxHandler
pub struct DclImages<'a, H> {
    http: H,
    base_url: &'a str,
    /// The caller-injected scratch (for URL building + JSON parsing) and the
    /// resolution cache, behind one async mutex. A single scratch buffer means
    /// concurrent transfers must serialize; [`IfMutex`] makes a contending caller
    /// *wait* for its turn (rather than fail) while another holds it across its
    /// HTTP round-trips - which also serializes the (typically single-connection)
    /// HTTP client.
    locked: IfMutex<Locked<'a>>,
}

/// The mutex-guarded working state.
struct Locked<'a> {
    /// Caller-injected scratch for URL building + JSON parsing.
    scratch: &'a mut [u8],
    /// The image resolved by the most recent `query`/`read`, so a subsequent BDX
    /// download (`size`/`read`) need not re-query the DCL on every block. Held
    /// in-place (an empty `designator` means "no entry").
    cache: Cached,
}

struct Cached {
    designator: String<MAX_FILE_DESIGNATOR>,
    ota_url: String<MAX_URL>,
    size: u64,
}

impl<'a, H> DclImages<'a, H> {
    /// Create a source talking to the given DCL REST `base_url` (e.g.
    /// [`DCL_MAINNET`]). `scratch` is the working buffer for URL building and JSON
    /// parsing; a couple of KiB is recommended (it must be larger than
    /// [`MAX_URL`]).
    pub const fn new(http: H, base_url: &'a str, scratch: &'a mut [u8]) -> Self {
        Self {
            http,
            base_url,
            locked: IfMutex::new(Locked {
                scratch,
                cache: Cached {
                    designator: String::new(),
                    ota_url: String::new(),
                    size: 0,
                },
            }),
        }
    }

    /// Create a source talking to the production DCL ([`DCL_MAINNET`]).
    pub const fn mainnet(http: H, scratch: &'a mut [u8]) -> Self {
        Self::new(http, DCL_MAINNET, scratch)
    }

    /// Create a source talking to the test-net DCL ([`DCL_TESTNET`]).
    pub const fn testnet(http: H, scratch: &'a mut [u8]) -> Self {
        Self::new(http, DCL_TESTNET, scratch)
    }
}

impl<H: OtaHttp> DclImages<'_, H> {
    /// Fetch (if not already cached) the firmware URL + size for the image
    /// identified by file designator `fd`, leaving the result in `locked.cache`.
    /// The caller must hold the lock (`locked`).
    async fn resolve_into(&self, locked: &mut Locked<'_>, fd: &[u8]) -> Option<()> {
        if !fd.is_empty() && locked.cache.designator.as_bytes() == fd {
            return Some(());
        }

        let (vid, pid, version) = parse_designator(fd)?;
        let (url_buf, json_buf) = carve(locked.scratch)?;

        let url = build_detail_url(url_buf, self.base_url, vid, pid, version)?;
        let n = self.http.get(url, None, json_buf).await.ok()?;
        let (resp, _) = serde_json_core::from_slice::<DetailResponse>(&json_buf[..n]).ok()?;
        let mv = resp.model_version;

        let fd = core::str::from_utf8(fd).ok()?;
        store(&mut locked.cache, fd, mv.ota_url, mv.ota_file_size)
    }
}

/// Replace the cache entry in-place (no large stack temporary).
fn store(cache: &mut Cached, designator: &str, ota_url: &str, size: u64) -> Option<()> {
    cache.designator.clear();
    cache.designator.push_str(designator).ok()?;
    cache.ota_url.clear();
    cache.ota_url.push_str(ota_url).ok()?;
    cache.size = size;

    Some(())
}

impl<H: OtaHttp> OtaImagesRegistry for DclImages<'_, H> {
    async fn query<'b>(
        &self,
        vendor_id: u16,
        product_id: u16,
        current_version: u32,
        designator_buf: &'b mut [u8],
    ) -> Option<OtaImageMeta<'b>> {
        let mut guard = self.locked.lock().await;
        let locked = &mut *guard;
        let (url_buf, json_buf) = carve(locked.scratch)?;

        // 1. The version list -> the best candidate strictly newer than the requestor.
        let candidate = {
            let url = build_list_url(&mut *url_buf, self.base_url, vendor_id, product_id)?;
            let n = self.http.get(url, None, &mut *json_buf).await.ok()?;
            let (resp, _) = serde_json_core::from_slice::<VersionsResponse>(&json_buf[..n]).ok()?;

            select_version(&resp.model_versions.software_versions, current_version)?
        };

        // 2. The candidate's detail -> validity, applicability, firmware URL and size.
        let url = build_detail_url(
            &mut *url_buf,
            self.base_url,
            vendor_id,
            product_id,
            candidate,
        )?;
        let n = self.http.get(url, None, &mut *json_buf).await.ok()?;
        let (resp, _) = serde_json_core::from_slice::<DetailResponse>(&json_buf[..n]).ok()?;
        let mv = resp.model_version;

        if !applicable(
            mv.valid,
            mv.min_applicable,
            mv.max_applicable,
            current_version,
        ) {
            return None;
        }

        // 3. Mint the designator and cache the resolution for the imminent download.
        let designator =
            write_designator(designator_buf, vendor_id, product_id, mv.software_version)?;
        store(&mut locked.cache, designator, mv.ota_url, mv.ota_file_size)?;

        Some(OtaImageMeta {
            version: mv.software_version,
            file_designator: designator,
            size: Some(mv.ota_file_size),
        })
    }
}

impl<H: OtaHttp> OtaImages for DclImages<'_, H> {
    async fn size(&self, file_designator: &[u8]) -> Option<u64> {
        let mut guard = self.locked.lock().await;
        let locked = &mut *guard;

        self.resolve_into(locked, file_designator).await?;

        (locked.cache.designator.as_bytes() == file_designator).then_some(locked.cache.size)
    }

    async fn read(
        &self,
        file_designator: &[u8],
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        // Resolve under the lock (a cache miss does a DCL round-trip through the
        // shared scratch) and copy the firmware URL out - then release the lock.
        // The (large) firmware GET below needs neither the scratch nor the cache,
        // so holding the mutex across it would needlessly serialize concurrent
        // downloads (and block any other DCL query for the whole transfer).
        let mut url = String::<MAX_URL>::new();
        {
            let mut guard = self.locked.lock().await;
            let locked = &mut *guard;

            self.resolve_into(locked, file_designator)
                .await
                .ok_or(ErrorCode::InvalidData)?;
            if locked.cache.designator.as_bytes() != file_designator {
                return Err(ErrorCode::InvalidData.into());
            }

            url.push_str(&locked.cache.ota_url)
                .map_err(|_| ErrorCode::NoSpace)?;
        }

        self.http.get(&url, Some((offset, buf.len())), buf).await
    }
}

/// Split the scratch into a (URL, JSON) pair; `None` if it cannot hold a URL.
fn carve(scratch: &mut [u8]) -> Option<(&mut [u8], &mut [u8])> {
    (scratch.len() > MAX_URL).then(|| scratch.split_at_mut(MAX_URL))
}

fn build_list_url<'u>(url_buf: &'u mut [u8], base: &str, vid: u16, pid: u16) -> Option<&'u str> {
    let len = {
        let mut wb = WriteBuf::new(&mut *url_buf);
        write!(wb, "{base}/dcl/model/versions/{vid}/{pid}").ok()?;
        wb.as_slice().len()
    };

    core::str::from_utf8(&url_buf[..len]).ok()
}

fn build_detail_url<'u>(
    url_buf: &'u mut [u8],
    base: &str,
    vid: u16,
    pid: u16,
    version: u32,
) -> Option<&'u str> {
    let len = {
        let mut wb = WriteBuf::new(&mut *url_buf);
        write!(wb, "{base}/dcl/model/versions/{vid}/{pid}/{version}").ok()?;
        wb.as_slice().len()
    };

    core::str::from_utf8(&url_buf[..len]).ok()
}

// --- DCL REST response shapes (only the fields we need; others are ignored) ---

#[derive(Deserialize)]
struct VersionsResponse {
    #[serde(rename = "modelVersions")]
    model_versions: VersionList,
}

#[derive(Deserialize)]
struct VersionList {
    #[serde(rename = "softwareVersions")]
    software_versions: heapless::Vec<u32, MAX_VERSIONS>,
}

#[derive(Deserialize)]
struct DetailResponse<'a> {
    #[serde(borrow, rename = "modelVersion")]
    model_version: ModelVersion<'a>,
}

#[derive(Deserialize)]
struct ModelVersion<'a> {
    #[serde(rename = "softwareVersion")]
    software_version: u32,
    #[serde(rename = "softwareVersionValid")]
    valid: bool,
    #[serde(borrow, rename = "otaUrl")]
    ota_url: &'a str,
    #[serde(rename = "otaFileSize")]
    ota_file_size: u64,
    #[serde(rename = "minApplicableSoftwareVersion")]
    min_applicable: u32,
    #[serde(rename = "maxApplicableSoftwareVersion")]
    max_applicable: u32,
}

// --- Pure helpers (unit-tested without networking) ---

/// The best candidate: the highest offered version strictly newer than `current`.
fn select_version(versions: &[u32], current: u32) -> Option<u32> {
    versions.iter().copied().filter(|v| *v > current).max()
}

/// Whether `current` is within the image's applicable range and the image is valid.
fn applicable(valid: bool, min: u32, max: u32, current: u32) -> bool {
    valid && current >= min && current <= max
}

/// Encode `(vid, pid, version)` into `buf` as the file designator
/// `"<VID>-<PID>-<VERSION>"` (hex vid/pid), returning the borrowed string.
fn write_designator(buf: &mut [u8], vid: u16, pid: u16, version: u32) -> Option<&str> {
    let len = {
        let mut wb = WriteBuf::new(&mut *buf);
        write!(wb, "{vid:04X}-{pid:04X}-{version}").ok()?;
        wb.as_slice().len()
    };

    core::str::from_utf8(&buf[..len]).ok()
}

/// Parse a `"<VID>-<PID>-<VERSION>"` designator back into its triple.
fn parse_designator(fd: &[u8]) -> Option<(u16, u16, u32)> {
    let s = core::str::from_utf8(fd).ok()?;
    let mut parts = s.split('-');

    let vid = u16::from_str_radix(parts.next()?, 16).ok()?;
    let pid = u16::from_str_radix(parts.next()?, 16).ok()?;
    let version = parts.next()?.parse::<u32>().ok()?;

    if parts.next().is_some() {
        return None;
    }

    Some((vid, pid, version))
}

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use super::*;

    const VERSIONS_JSON: &[u8] =
        br#"{"modelVersions":{"vid":4660,"pid":22136,"softwareVersions":[1,2,10]}}"#;

    // A realistic detail payload, including fields we do *not* model (to exercise
    // unknown-field skipping).
    const DETAIL_JSON: &[u8] = br#"{"modelVersion":{"vid":4660,"pid":22136,"softwareVersion":10,
        "softwareVersionString":"1.0.10","cdVersionNumber":1,"firmwareInformation":"",
        "softwareVersionValid":true,"otaUrl":"https://fw.example.com/fw/10.ota",
        "otaFileSize":2500,"otaChecksum":"abcd","otaChecksumType":1,
        "minApplicableSoftwareVersion":1,"maxApplicableSoftwareVersion":9,
        "releaseNotesUrl":"","creator":"cosmos1xyz"}}"#;

    #[test]
    fn select_version_picks_highest_newer() {
        assert_eq!(select_version(&[1, 2, 10], 1), Some(10));
        assert_eq!(select_version(&[1, 2, 10], 9), Some(10));
        assert_eq!(select_version(&[1, 2, 10], 10), None);
        assert_eq!(select_version(&[], 0), None);
    }

    #[test]
    fn applicable_checks_validity_and_range() {
        assert!(applicable(true, 1, 9, 1));
        assert!(applicable(true, 1, 9, 9));
        assert!(!applicable(false, 1, 9, 5));
        assert!(!applicable(true, 5, 9, 1));
        assert!(!applicable(true, 1, 9, 10));
    }

    #[test]
    fn designator_round_trips() {
        let mut buf = [0u8; 64];
        let fd = write_designator(&mut buf, 0x1234, 0x5678, 10).unwrap();
        assert_eq!(fd, "1234-5678-10");
        assert_eq!(parse_designator(fd.as_bytes()), Some((0x1234, 0x5678, 10)));

        assert_eq!(parse_designator(b"nonsense"), None);
        assert_eq!(parse_designator(b"1234-5678-10-extra"), None);
    }

    #[test]
    fn parses_dcl_responses() {
        let (versions, _) = serde_json_core::from_slice::<VersionsResponse>(VERSIONS_JSON).unwrap();
        assert_eq!(versions.model_versions.software_versions, &[1, 2, 10]);

        let (detail, _) = serde_json_core::from_slice::<DetailResponse>(DETAIL_JSON).unwrap();
        let mv = detail.model_version;
        assert_eq!(mv.software_version, 10);
        assert!(mv.valid);
        assert_eq!(mv.ota_url, "https://fw.example.com/fw/10.ota");
        assert_eq!(mv.ota_file_size, 2500);
        assert_eq!((mv.min_applicable, mv.max_applicable), (1, 9));
    }

    /// A canned [`OtaHttp`] that answers the two DCL endpoints and the firmware
    /// URL from in-memory data, so the whole `query`/`size`/`read` flow can be
    /// exercised without networking.
    struct MockHttp {
        firmware: heapless::Vec<u8, 4096>,
    }

    impl OtaHttp for MockHttp {
        async fn get(
            &self,
            url: &str,
            range: Option<(u64, usize)>,
            buf: &mut [u8],
        ) -> Result<usize, Error> {
            let body: &[u8] = if url.contains("fw.example.com") {
                &self.firmware
            } else {
                // `.../versions/{vid}/{pid}` (list) vs `.../{vid}/{pid}/{version}` (detail).
                let tail = url.split("/versions/").nth(1).unwrap_or("");
                if tail.split('/').count() >= 3 {
                    DETAIL_JSON
                } else {
                    VERSIONS_JSON
                }
            };

            let (start, len) = range.unwrap_or((0, buf.len()));
            let start = start as usize;
            if start >= body.len() {
                return Ok(0);
            }

            let end = (start + len).min(body.len());
            let n = end - start;
            buf[..n].copy_from_slice(&body[start..end]);

            Ok(n)
        }
    }

    fn block_on<F: Future>(fut: F) -> F::Output {
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        fn noop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);

        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = core::pin::pin!(fut);

        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn end_to_end_query_then_download() {
        let firmware: heapless::Vec<u8, 4096> = (0..2500).map(|i| (i % 251) as u8).collect();
        let mut scratch = [0u8; 2048];
        let dcl = DclImages::new(
            MockHttp {
                firmware: firmware.clone(),
            },
            "https://on.dcl.csa-iot.org",
            &mut scratch,
        );

        block_on(async {
            // Registry: a v1 requestor is offered v10.
            let mut fd_buf = [0u8; 64];
            let meta = dcl.query(0x1234, 0x5678, 1, &mut fd_buf).await.unwrap();
            assert_eq!(meta.version, 10);
            assert_eq!(meta.file_designator, "1234-5678-10");
            assert_eq!(meta.size, Some(2500));

            // Data: the BDX server resolves that designator and streams the bytes.
            let fd = b"1234-5678-10";
            assert_eq!(dcl.size(fd).await, Some(2500));

            let mut out: heapless::Vec<u8, 4096> = heapless::Vec::new();
            let mut rbuf = [0u8; 300];
            let mut offset = 0u64;
            loop {
                let n = dcl.read(fd, offset, &mut rbuf).await.unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&rbuf[..n]).unwrap();
                offset += n as u64;
            }
            assert_eq!(out, firmware);

            // An up-to-date requestor (already at v10) is offered nothing.
            let mut fd_buf = [0u8; 64];
            assert!(dcl.query(0x1234, 0x5678, 10, &mut fd_buf).await.is_none());
        });
    }
}
