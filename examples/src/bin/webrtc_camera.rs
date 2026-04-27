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

//! An example Matter Camera device that bridges a real `str0m` WebRTC peer
//! into the Matter `WebRTCTransportProvider` (0x0553) cluster.
//!
//! # Scope
//!
//! * Matter cluster fully wired (commissioning, command dispatch, outbound
//!   trickle + End push through `WebRTCTransportRequestor`).
//! * A real `str0m::Rtc` is created per controller-initiated session, seeded
//!   with a local host candidate, and produces a proper SDP Answer.
//! * Per-session ICE/DTLS pump is driven from a **single-threaded async**
//!   executor (`async_executor::LocalExecutor`) joined into the main
//!   `select` alongside Matter's transport, mDNS, responder and DM jobs.
//!
//! # Architecture (all on one thread)
//!
//! ```text
//!   ┌────────────────────────── run() / block_on ────────────────────────────┐
//!   │                                                                        │
//!   │   matter.run  ──┐                                                      │
//!   │   mdns        ──┤                                                      │
//!   │   responder   ──┼── select5 ──► futures_lite::future::block_on         │
//!   │   dm.run      ──┤                                                      │
//!   │   drive       ──┘                                                      │
//!   │     │                                                                  │
//!   │     ▼     LocalExecutor                                                │
//!   │   new_session_rx ─► spawn(session_loop)  ─► poll_output /              │
//!   │                                             handle_input via           │
//!   │                                             async_io::Async<UdpSocket> │
//!   └────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! `Str0mHooks` methods (`on_offer`, `on_ice_candidates`, `on_end_session`,
//! …) run inline on the Matter command-dispatch task; they only mutate a
//! shared `RefCell<Str0mInner>` and post messages on `async_channel` queues
//! — never hold a borrow across an `.await`.
//!
//! ```sh
//! # Produce a suitable loop file from any MP4:
//! ffmpeg -i loop.mp4 \
//!   -c:v libx264 -preset veryfast -tune zerolatency \
//!   -profile:v baseline -level 3.1 \
//!   -pix_fmt yuv420p \
//!   -b:v 1500k -maxrate 1500k -bufsize 3000k \
//!   -g 60 -keyint_min 60 -sc_threshold 0 \
//!   -bsf:v h264_mp4toannexb \
//!   -an -f h264 loop_ok.h264
//!
//! # Run the example:
//! WEBRTC_CAMERA_H264=$PWD/loop.h264 WEBRTC_CAMERA_FPS=30 \
//!   cargo run -p rs-matter-examples --bin webrtc_camera --features webrtc
//! ```

use core::cell::RefCell;
use core::pin::pin;

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_channel::{Receiver, Sender};
use async_executor::LocalExecutor;
use async_io::Async;
use embassy_futures::select::{select, select4};

use log::{info, warn};

use rand::RngCore;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::cam_av_settings::{
    CamAvSettingsConfig, CamAvSettingsError, CamAvSettingsHandler, CamAvSettingsHooks, DptzView,
    Mptz, CLUSTER_DPTZ_ONLY,
};
use rs_matter::dm::clusters::app::cam_av_stream::{
    CamAvError, CameraAvStreamConfig, CameraAvStreamHandler, CameraAvStreamHooks,
    RateDistortionPoint, StreamUsageEnum, VideoCodecEnum, VideoSensorParams, VideoStream,
};
use rs_matter::dm::clusters::app::webrtc_prov::{
    AnswerOutcome, HandlerAsyncAdaptor as WebRtcAdaptor, OfferParams, OutboundWork, SolicitOutcome,
    WebRtcError, WebRtcHooks, WebRtcProvHandler,
};
use rs_matter::dm::clusters::app::zone_mgmt::{
    HandlerAsyncAdaptor as ZoneMgmtAdaptor, ZoneMgmtConfig, ZoneMgmtHandler, ZoneMgmtHooks,
};
use rs_matter::dm::clusters::basic_info::BasicInfoConfig;
use rs_matter::dm::clusters::decl::globals::{ICECandidateStruct, WebRTCEndReasonEnum};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::SharedNetworks;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::endpoints;
use rs_matter::dm::events::NoEvents;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::subscriptions::Subscriptions;
use rs_matter::dm::DeviceType;
use rs_matter::dm::IMBuffer;
use rs_matter::dm::{
    AsyncHandler, AsyncMetadata, DataModel, Dataver, EmptyHandler, Endpoint, EpClMatcher, Node,
};
use rs_matter::error::Error;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{DirKvBlobStore, SharedKvBlobStore};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::{Nullable, TLVArray, TLVBuilderParent};
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

use static_cell::StaticCell;

use str0m::change::SdpOffer;
use str0m::format::Codec;
use str0m::media::{MediaKind, MediaTime, Mid, Pt};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};

// The generated TLV builder for an `ICECandidateStruct` array element.
use rs_matter::dm::clusters::decl::globals::ICECandidateStructArrayBuilder;

#[path = "../common/mdns.rs"]
mod mdns;

// ---------------------------------------------------------------------------
// Device type / handler sizing
// ---------------------------------------------------------------------------

/// Matter 1.5 "Camera" device type (0x0142, rev 1). Not exposed from
/// `rs-matter`'s `devices` module yet, so defined inline.
///
/// Note: `0x0042` (which looks similar) is the Water Valve device type —
/// using that ID makes controllers like SmartThings commission the node
/// as a water valve.
const DEV_TYPE_MATTER_CAMERA: DeviceType = DeviceType {
    dtype: 0x0142,
    drev: 1,
};

const N_SESSIONS: usize = 4;
const SDP_LEN: usize = 8 * 1024;
// Must be large enough to hold an outbound `Answer(sdp)` invoke payload,
// i.e. the full SDP plus TLV framing overhead.
const OUT_LEN: usize = SDP_LEN + 1024;

type WebRtc = WebRtcProvHandler<Str0mHooks, N_SESSIONS, SDP_LEN, OUT_LEN>;

/// Stream usages advertised by the `CameraAVStreamManagement` cluster, in
/// priority order (highest priority first). `LiveView` is the only usage
/// currently relevant to WebRTC signaling with SmartThings / Google Home.
const CAM_AV_STREAM_USAGES: &[StreamUsageEnum] = &[StreamUsageEnum::LiveView];

/// One advertised `RateDistortionTradeOffPoints` operating point: H.264
/// at 640x360 minimum, 500 kbps minimum bitrate. SmartThings inspects
/// this list before issuing a `VideoStreamAllocate`.
const CAM_AV_RATE_DISTORTION: &[RateDistortionPoint] = &[RateDistortionPoint {
    codec: VideoCodecEnum::H264,
    min_resolution: (640, 360),
    min_bit_rate: 500_000,
}];

/// Maximum number of concurrently allocated video streams. The demo
/// pre-seeds one at boot and accepts at most one more dynamic
/// allocation from the controller.
const CAM_AV_NV: usize = 2;

/// Hooks impl for the str0m-based example. The actual encoder is the
/// pre-loaded H.264 file and is started/stopped by the WebRTC session
/// lifecycle, not by `CameraAVStreamManagement` commands. So all hooks
/// are no-ops — they merely log so an operator can see the cluster
/// being driven.
struct Str0mCamHooks;

impl CameraAvStreamHooks for Str0mCamHooks {
    async fn allocate_video(&self, stream: &VideoStream) -> Result<(), CamAvError> {
        info!(
            "cam-av: allocate video #{} {}x{}@{}fps",
            stream.video_stream_id, stream.max_width, stream.max_height, stream.max_frame_rate
        );
        Ok(())
    }

    async fn modify_video(
        &self,
        id: u16,
        watermark: Option<bool>,
        osd: Option<bool>,
    ) -> Result<(), CamAvError> {
        info!(
            "cam-av: modify video #{} watermark={:?} osd={:?}",
            id, watermark, osd
        );
        Ok(())
    }

    async fn deallocate_video(&self, id: u16) -> Result<(), CamAvError> {
        info!("cam-av: deallocate video #{}", id);
        Ok(())
    }
}

/// Number of detection zones the demo can hold (manufacturer + user).
const ZONE_NZ: usize = 4;
/// Maximum vertices per zone polygon.
const ZONE_NV: usize = 8;
/// Maximum number of triggers (one per zone is plenty for the demo).
const ZONE_NT: usize = 4;

/// Hooks for the Zone Management cluster. The demo has no real motion
/// detector — hooks just log so an operator can see the cluster being
/// driven by a controller.
struct DemoZoneHooks;

impl ZoneMgmtHooks<ZONE_NV> for DemoZoneHooks {
    async fn zone_created(
        &self,
        zone: &rs_matter::dm::clusters::app::zone_mgmt::Zone<ZONE_NV>,
    ) -> Result<(), rs_matter::dm::clusters::app::zone_mgmt::ZoneError> {
        info!(
            "zone-mgmt: zone #{} created ({} vertices)",
            zone.zone_id,
            zone.vertices.len()
        );
        Ok(())
    }

    async fn zone_removed(
        &self,
        id: u16,
    ) -> Result<(), rs_matter::dm::clusters::app::zone_mgmt::ZoneError> {
        info!("zone-mgmt: zone #{} removed", id);
        Ok(())
    }

    async fn trigger_set(
        &self,
        t: &rs_matter::dm::clusters::app::zone_mgmt::Trigger,
    ) -> Result<(), rs_matter::dm::clusters::app::zone_mgmt::ZoneError> {
        info!(
            "zone-mgmt: trigger set zone=#{} initial={}s max={}s blind={}s",
            t.zone_id, t.initial_duration, t.max_duration, t.blind_duration
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// H.264 Annex-B media source
// ---------------------------------------------------------------------------

/// One H.264 access unit, stored as Annex-B (NAL units prefixed by
/// `00 00 00 01`). Fed verbatim to `str0m`'s `Writer::write`, which
/// parses the start codes and emits STAP-A / FU-A as needed.
#[derive(Clone)]
struct H264Frame {
    data: Vec<u8>,
    is_keyframe: bool,
}

/// Parse an Annex-B H.264 file into access units.
///
/// Grouping rule: a new AU begins at the first non-VCL NAL that follows a
/// VCL NAL. VCL NALs are types 1 (non-IDR slice) and 5 (IDR). All other
/// NALs that appear before the next VCL are attached to the current AU.
/// This matches how zero-latency encoders (e.g. `ffmpeg -tune zerolatency`)
/// lay out `[SPS][PPS][IDR]` and `[P]` access units.
fn parse_annex_b(data: &[u8]) -> Vec<H264Frame> {
    // Yield NAL-unit byte slices (without the start code).
    fn iter_nals(data: &[u8]) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut i = 0usize;
        let mut cur_start: Option<usize> = None;
        while i < data.len() {
            let sc_len = if i + 2 < data.len() && data[i] == 0 && data[i + 1] == 0 {
                if data[i + 2] == 1 {
                    3
                } else if i + 3 < data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                    4
                } else {
                    0
                }
            } else {
                0
            };
            if sc_len > 0 {
                if let Some(s) = cur_start.take() {
                    out.push((s, i));
                }
                cur_start = Some(i + sc_len);
                i += sc_len;
            } else {
                i += 1;
            }
        }
        if let Some(s) = cur_start {
            out.push((s, data.len()));
        }
        out
    }

    let mut frames = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut cur_is_key = false;
    let mut cur_has_vcl = false;

    for (s, e) in iter_nals(data) {
        if s >= e {
            continue;
        }
        let nal = &data[s..e];
        let nal_type = nal[0] & 0x1F;
        let is_vcl = matches!(nal_type, 1 | 5);

        // Determine whether this VCL NAL starts a new picture. The first
        // syntax element of slice_header() is `first_mb_in_slice` (ue(v)).
        // In Exp-Golomb, value 0 is encoded as a single `1` bit, so a
        // slice that begins a picture has its first RBSP bit set. Any
        // other leading bit pattern means this is a continuation slice
        // belonging to the same picture as the previous VCL — typical of
        // multi-slice encodings (e.g. baseline with ASO/FMO or simply
        // `-slices N`).
        let starts_new_picture = is_vcl && nal.len() > 1 && (nal[1] & 0x80) != 0;

        // Flush the in-progress AU when:
        //   - a non-VCL NAL appears AFTER a VCL (classic boundary, e.g.
        //     AUD/SEI/SPS/PPS preceding the next picture), OR
        //   - a VCL NAL starts a new picture while the current AU
        //     already has a VCL.
        let flush = cur_has_vcl && !cur.is_empty() && (!is_vcl || starts_new_picture);
        if flush {
            frames.push(H264Frame {
                data: core::mem::take(&mut cur),
                is_keyframe: cur_is_key,
            });
            cur_is_key = false;
            cur_has_vcl = false;
        }

        cur.extend_from_slice(&[0, 0, 0, 1]);
        cur.extend_from_slice(nal);
        if nal_type == 5 {
            cur_is_key = true;
        }
        if is_vcl {
            cur_has_vcl = true;
        }
    }
    if !cur.is_empty() {
        frames.push(H264Frame {
            data: cur,
            is_keyframe: cur_is_key,
        });
    }
    frames
}

// ---------------------------------------------------------------------------
// Shared state between hooks (Matter-side) and driver (str0m-side)
// ---------------------------------------------------------------------------

/// A new session handed from `on_offer` over to the driver task.
struct NewSession {
    id: u16,
    rtc: Rtc,
    socket: Async<UdpSocket>,
    local_addr: SocketAddr,
    remote_cand_rx: Receiver<Candidate>,
    shutdown_rx: Receiver<()>,
    trickle_buf: Rc<RefCell<Vec<String>>>,
    outbound_tx: Sender<OutboundWork>,
    frames: Arc<Vec<H264Frame>>,
    fps: u32,
}

/// Hook-side handle to a live session.
struct SessionCtrl {
    remote_cand_tx: Sender<Candidate>,
    shutdown_tx: Sender<()>,
    /// Locally-gathered candidates awaiting transmission via
    /// `fill_ice_candidates`. Populated by the driver, drained by the hook.
    trickle_buf: Rc<RefCell<Vec<String>>>,
    /// SDP Answer produced by `on_offer`, awaiting transmission via
    /// `take_answer_sdp`. `None` once the Answer has been pushed.
    answer_sdp: RefCell<Option<String>>,
}

struct Str0mInner {
    sessions: AllocMap<u16, SessionCtrl>,
}

/// Lives in a `StaticCell`; both the hooks (embedded in `WebRtcProvHandler`)
/// and the driver future hold a `&'static` borrow.
struct Str0mShared {
    inner: RefCell<Str0mInner>,
    new_session_tx: Sender<NewSession>,
    new_session_rx: Receiver<NewSession>,
    outbound_tx: Sender<OutboundWork>,
    outbound_rx: Receiver<OutboundWork>,
    frames: Arc<Vec<H264Frame>>,
    fps: u32,
}

impl Str0mShared {
    fn new(frames: Arc<Vec<H264Frame>>, fps: u32) -> Self {
        let (new_session_tx, new_session_rx) = async_channel::unbounded();
        let (outbound_tx, outbound_rx) = async_channel::unbounded();
        Self {
            inner: RefCell::new(Str0mInner {
                sessions: AllocMap::new(),
            }),
            new_session_tx,
            new_session_rx,
            outbound_tx,
            outbound_rx,
            frames,
            fps,
        }
    }

    /// Main async driver future. Joined into the top-level `select` and
    /// runs a `LocalExecutor` that owns one task per active session.
    async fn drive(&'static self) -> Result<(), Error> {
        let ex: LocalExecutor<'static> = LocalExecutor::new();
        let accept = async {
            while let Ok(new) = self.new_session_rx.recv().await {
                let sid = new.id;
                info!("webrtc_camera: spawning session driver for {sid}");
                ex.spawn(session_loop(new)).detach();
            }
        };
        ex.run(accept).await;
        Ok(())
    }
}

/// The `WebRtcHooks` implementation; just a thin borrow of the shared state.
#[derive(Copy, Clone)]
struct Str0mHooks {
    shared: &'static Str0mShared,
}

// ---------------------------------------------------------------------------
// Minimal alloc-backed map (keeps us off `std::collections::HashMap`)
// ---------------------------------------------------------------------------

struct AllocMap<K, V> {
    entries: Vec<(K, V)>,
}

impl<K: Eq, V> AllocMap<K, V> {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn insert(&mut self, k: K, v: V) {
        self.entries.retain(|e| e.0 != k);
        self.entries.push((k, v));
    }

    fn remove(&mut self, k: &K) -> Option<V> {
        let pos = self.entries.iter().position(|e| &e.0 == k)?;
        Some(self.entries.swap_remove(pos).1)
    }

    fn get(&self, k: &K) -> Option<&V> {
        self.entries.iter().find(|e| &e.0 == k).map(|e| &e.1)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// Per-session driver task
// ---------------------------------------------------------------------------

/// Drive a single `Rtc` + its UDP socket to completion. Owns the `Rtc`,
/// the `Async<UdpSocket>`, and the control receivers. Runs until
/// `IceConnectionState::Disconnected` is observed, a shutdown is signalled
/// via `EndSession`, or a fatal I/O / str0m error occurs.
async fn session_loop(session: NewSession) {
    let NewSession {
        id,
        mut rtc,
        socket,
        local_addr,
        remote_cand_rx,
        shutdown_rx,
        trickle_buf: _trickle_buf,
        outbound_tx,
        frames,
        fps,
    } = session;

    let mut buf = vec![0u8; 2048];
    let mut end_reason = WebRTCEndReasonEnum::ICEFailed;

    // Media bookkeeping.
    let frame_interval = if fps > 0 {
        Duration::from_nanos(1_000_000_000 / fps as u64)
    } else {
        Duration::from_millis(33)
    };
    // RTP timestamp step at 90 kHz for the chosen fps (video clock rate).
    let rtp_step: u64 = if fps > 0 { 90_000 / fps as u64 } else { 3_000 };
    let has_media = !frames.is_empty();
    let mut video_mid: Option<Mid> = None;
    let mut video_pt: Option<Pt> = None;
    let mut connected = false;
    let mut next_frame_at: Option<Instant> = None;
    let mut next_frame_idx: usize = 0;
    let mut rtp_ts: u64 = 0;

    'outer: loop {
        // Non-blocking drain of control messages.
        while let Ok(c) = remote_cand_rx.try_recv() {
            log::debug!("webrtc_camera[{id}]: remote candidate {c:?}");
            rtc.add_remote_candidate(c);
        }
        if shutdown_rx.try_recv().is_ok() {
            end_reason = WebRTCEndReasonEnum::UserHangup;
            break 'outer;
        }

        // If a frame is due and we can send, send it before the next poll.
        // IMPORTANT: after `writer.write` we must let the loop fall through
        // to `poll_output` — str0m requires `poll_output` to be called
        // between consecutive `write()`s. Falling through (no `continue`)
        // guarantees that invariant even when we are behind schedule.
        if has_media && connected {
            if let (Some(mid), Some(pt), Some(at)) = (video_mid, video_pt, next_frame_at) {
                let now = Instant::now();
                if at <= now {
                    let frame = &frames[next_frame_idx];
                    if let Some(writer) = rtc.writer(mid) {
                        let wallclock = now;
                        let mtime = MediaTime::from_90khz(rtp_ts);
                        if let Err(e) = writer.write(pt, wallclock, mtime, frame.data.clone()) {
                            warn!("webrtc_camera[{id}]: Writer::write failed: {e}");
                        }
                    } else {
                        warn!("webrtc_camera[{id}]: no writer for mid {mid:?}");
                    }
                    next_frame_idx = (next_frame_idx + 1) % frames.len();
                    rtp_ts = rtp_ts.wrapping_add(rtp_step);
                    // Cap catch-up: if we are more than one frame_interval
                    // behind, snap next_frame_at to `now + frame_interval`
                    // so we do not burst the backlog at the decoder. This
                    // keeps wallclock pacing real-time even if we briefly
                    // lagged. Without this, repeated fall-through would
                    // emit several frames in a tight loop.
                    let next = at + frame_interval;
                    next_frame_at = Some(if next + frame_interval < now {
                        now + frame_interval
                    } else {
                        next
                    });
                    // Fall through to poll_output (do NOT `continue`).
                }
            }
        }

        let out = match rtc.poll_output() {
            Ok(o) => o,
            Err(e) => {
                warn!("webrtc_camera[{id}]: poll_output failed: {e}");
                break 'outer;
            }
        };

        match out {
            Output::Transmit(t) => {
                let n = t.contents.len();
                let k = packet_kind(&t.contents);
                log::debug!(
                    "webrtc_camera[{id}]: TX -> {} {} bytes ({k})",
                    t.destination,
                    n
                );
                if let Err(e) = socket.send_to(&t.contents, t.destination).await {
                    warn!("webrtc_camera[{id}]: send_to {} failed: {e}", t.destination);
                }
            }
            Output::Timeout(at) => {
                let now = Instant::now();
                // Tighten the wait to whichever comes first: str0m deadline
                // or the next frame emission.
                let deadline = match next_frame_at {
                    Some(f) if connected && has_media => at.min(f),
                    _ => at,
                };
                if deadline <= now {
                    // If the str0m deadline is past, feed it a Timeout.
                    if at <= now {
                        if let Err(e) = rtc.handle_input(Input::Timeout(now)) {
                            warn!("webrtc_camera[{id}]: handle_input(Timeout) failed: {e}");
                            break 'outer;
                        }
                    }
                    continue;
                }
                // Race: UDP recv | deadline timer | new remote candidate | shutdown.
                let ev =
                    race_next_event(&socket, &mut buf, deadline, &remote_cand_rx, &shutdown_rx)
                        .await;
                match ev {
                    DriverEvent::Recv(Ok((n, from))) => {
                        let k = packet_kind(&buf[..n]);
                        log::debug!("webrtc_camera[{id}]: RX <- {from} {n} bytes ({k})");
                        match Receive::new(Protocol::Udp, from, local_addr, &buf[..n]) {
                            Ok(r) => {
                                if let Err(e) = rtc.handle_input(Input::Receive(Instant::now(), r))
                                {
                                    warn!("webrtc_camera[{id}]: handle_input(Receive) failed: {e}");
                                }
                            }
                            Err(e) => {
                                // Non-WebRTC packet — ignore.
                                log::debug!("webrtc_camera[{id}]: dropped non-webrtc packet ({e})");
                            }
                        }
                    }
                    DriverEvent::Recv(Err(e)) => {
                        warn!("webrtc_camera[{id}]: recv_from failed: {e}");
                        break 'outer;
                    }
                    DriverEvent::Timeout => {
                        // Could be either the str0m deadline or the frame
                        // deadline. Only feed Timeout if str0m's time has
                        // elapsed; the frame check at the top of the loop
                        // will handle the media side.
                        let now = Instant::now();
                        if at <= now {
                            if let Err(e) = rtc.handle_input(Input::Timeout(now)) {
                                warn!("webrtc_camera[{id}]: handle_input(Timeout) failed: {e}");
                                break 'outer;
                            }
                        }
                    }
                    DriverEvent::NewRemote(c) => {
                        log::debug!("webrtc_camera[{id}]: remote candidate {c:?}");
                        rtc.add_remote_candidate(c);
                    }
                    DriverEvent::Shutdown => {
                        end_reason = WebRTCEndReasonEnum::UserHangup;
                        break 'outer;
                    }
                }
            }
            Output::Event(ev) => match ev {
                Event::Connected => {
                    info!("webrtc_camera[{id}]: ICE+DTLS connected");
                    connected = true;
                    if has_media && video_pt.is_some() {
                        next_frame_at = Some(Instant::now());
                    }
                }
                Event::IceConnectionStateChange(s) => {
                    info!("webrtc_camera[{id}]: ICE state -> {s:?}");
                    if matches!(s, IceConnectionState::Disconnected) {
                        end_reason = WebRTCEndReasonEnum::ICEFailed;
                        break 'outer;
                    }
                }
                Event::MediaAdded(m) => {
                    info!(
                        "webrtc_camera[{id}]: MediaAdded mid={:?} kind={:?} dir={:?}",
                        m.mid, m.kind, m.direction
                    );
                    if has_media && m.kind == MediaKind::Video && video_mid.is_none() {
                        video_mid = Some(m.mid);
                        // Resolve an H.264 payload type for this mid.
                        if let Some(writer) = rtc.writer(m.mid) {
                            let pt = writer
                                .payload_params()
                                .find(|p| p.spec().codec == Codec::H264)
                                .map(|p| p.pt());
                            if let Some(pt) = pt {
                                info!(
                                    "webrtc_camera[{id}]: H264 PT={pt:?} bound to mid {:?}",
                                    m.mid
                                );
                                video_pt = Some(pt);
                                if connected {
                                    next_frame_at = Some(Instant::now());
                                }
                            } else {
                                warn!(
                                    "webrtc_camera[{id}]: no H264 payload type negotiated for mid {:?}",
                                    m.mid
                                );
                            }
                        }
                    }
                }
                other => {
                    log::debug!("webrtc_camera[{id}]: str0m event {other:?}");
                }
            },
        }
    }

    // Notify the controller that we are tearing down.
    if let Err(e) = outbound_tx
        .send(OutboundWork::End {
            session_id: id,
            reason: end_reason,
        })
        .await
    {
        warn!("webrtc_camera[{id}]: outbound End enqueue failed: {e}");
    }
    info!("webrtc_camera[{id}]: session driver exited ({end_reason:?})");
}

enum DriverEvent {
    Recv(std::io::Result<(usize, SocketAddr)>),
    Timeout,
    NewRemote(Candidate),
    Shutdown,
}

/// Classify a UDP payload for logging:
/// - STUN/TURN: first byte 0x00..=0x03 (RFC 5389); also decode STUN message class.
/// - DTLS: first byte 20..=63 (RFC 5764)
/// - RTP/RTCP: first byte 128..=191 (RFC 5764)
fn packet_kind(b: &[u8]) -> String {
    match b.first().copied() {
        Some(0x00..=0x03) => {
            // STUN message-type is first 2 bytes, method in low 12 bits,
            // class in bits 4 & 8 of that 16-bit value.
            if b.len() < 2 {
                return "STUN(short)".into();
            }
            let mt = u16::from_be_bytes([b[0], b[1]]);
            let method = mt & 0x0FFF;
            let class = ((mt >> 4) & 1) | ((mt >> 7) & 2);
            let class_str = match class {
                0 => "Request",
                1 => "Indication",
                2 => "Success",
                3 => "Error",
                _ => "?",
            };
            let method_str = match method {
                0x001 => "Binding",
                0x003 => "Allocate",
                0x004 => "Refresh",
                0x006 => "Send",
                0x007 => "Data",
                0x008 => "CreatePermission",
                0x009 => "ChannelBind",
                _ => "Unknown",
            };
            format!("STUN {method_str}/{class_str}")
        }
        Some(20..=63) => "DTLS".into(),
        Some(128..=191) => "RTP/RTCP".into(),
        _ => "other".into(),
    }
}

async fn race_next_event(
    socket: &Async<UdpSocket>,
    buf: &mut [u8],
    deadline: Instant,
    remote_cand_rx: &Receiver<Candidate>,
    shutdown_rx: &Receiver<()>,
) -> DriverEvent {
    use futures_lite::future::or;

    let recv_fut = async { DriverEvent::Recv(socket.recv_from(buf).await) };
    let timer_fut = async {
        async_io::Timer::at(deadline).await;
        DriverEvent::Timeout
    };
    let remote_fut = async {
        match remote_cand_rx.recv().await {
            Ok(c) => DriverEvent::NewRemote(c),
            Err(_) => DriverEvent::Shutdown,
        }
    };
    let shutdown_fut = async {
        let _ = shutdown_rx.recv().await;
        DriverEvent::Shutdown
    };

    or(or(recv_fut, timer_fut), or(remote_fut, shutdown_fut)).await
}

// ---------------------------------------------------------------------------
// WebRtcHooks impl
// ---------------------------------------------------------------------------

impl WebRtcHooks for Str0mHooks {
    async fn on_solicit_offer(
        &self,
        session_id: u16,
        _params: &OfferParams,
    ) -> Result<SolicitOutcome, WebRtcError> {
        warn!(
            "webrtc_camera: SolicitOffer (session {session_id}) rejected — \
             camera-initiated flow not implemented in this example"
        );
        Err(WebRtcError::Failure)
    }

    async fn on_offer(
        &self,
        session_id: u16,
        sdp: &str,
        _params: &OfferParams,
    ) -> Result<AnswerOutcome, WebRtcError> {
        info!(
            "webrtc_camera: ProvideOffer session {session_id}, offer len {} B",
            sdp.len()
        );

        let offer = SdpOffer::from_sdp_string(sdp).map_err(|e| {
            warn!("webrtc_camera: SDP offer parse failed: {e}");
            WebRtcError::DynamicConstraint
        })?;

        let bind_addr: SocketAddr = ([0u8, 0, 0, 0], 0u16).into();
        let socket = Async::<UdpSocket>::bind(bind_addr).map_err(|e| {
            warn!("webrtc_camera: udp bind failed: {e}");
            WebRtcError::Failure
        })?;
        let local_addr = socket.as_ref().local_addr().map_err(|e| {
            warn!("webrtc_camera: local_addr failed: {e}");
            WebRtcError::Failure
        })?;

        // The socket is bound to 0.0.0.0 so it can receive from any interface,
        // but ICE requires a concrete routable IP in the host candidate. Probe
        // the kernel's routing table by UDP-connecting to a dummy public address
        // (TEST-NET-2, no packets actually sent) to discover the preferred
        // outbound IPv4.
        let host_ip = UdpSocket::bind(SocketAddr::from(([0u8, 0, 0, 0], 0u16)))
            .and_then(|s| {
                s.connect(SocketAddr::from(([198u8, 51, 100, 1], 80)))?;
                s.local_addr()
            })
            .ok()
            .map(|a| a.ip())
            .filter(|ip| !ip.is_unspecified())
            .ok_or_else(|| {
                warn!("webrtc_camera: could not determine local routable IP");
                WebRtcError::Failure
            })?;
        let host_addr = SocketAddr::new(host_ip, local_addr.port());

        let mut rtc = Rtc::new(Instant::now());
        let cand = Candidate::host(host_addr, "udp").map_err(|e| {
            warn!("webrtc_camera: Candidate::host failed: {e}");
            WebRtcError::Failure
        })?;
        let local_cand_sdp = cand.to_sdp_string();
        rtc.add_local_candidate(cand);

        let answer = rtc.sdp_api().accept_offer(offer).map_err(|e| {
            warn!("webrtc_camera: accept_offer failed: {e}");
            WebRtcError::DynamicConstraint
        })?;
        let answer_sdp = answer.to_sdp_string();

        // Plumb the session over to the driver task.
        let (remote_cand_tx, remote_cand_rx) = async_channel::unbounded();
        let (shutdown_tx, shutdown_rx) = async_channel::bounded(1);
        let trickle_buf = Rc::new(RefCell::new(vec![local_cand_sdp]));

        {
            let mut inner = self.shared.inner.borrow_mut();
            inner.sessions.insert(
                session_id,
                SessionCtrl {
                    remote_cand_tx,
                    shutdown_tx,
                    trickle_buf: trickle_buf.clone(),
                    answer_sdp: RefCell::new(Some(answer_sdp)),
                },
            );
            info!(
                "webrtc_camera: session {session_id} established, bind = {local_addr}, \
                 host candidate = {host_addr}, active sessions = {}",
                inner.sessions.len()
            );
        }

        // Send the session to the driver. If this fails, the driver task
        // is gone — bail.
        self.shared
            .new_session_tx
            .send(NewSession {
                id: session_id,
                rtc,
                socket,
                // Use the routable host address (not the 0.0.0.0 bind
                // address), because str0m's ICE agent matches incoming
                // packets' `destination` against the local candidate list,
                // which contains the host address.
                local_addr: host_addr,
                remote_cand_rx,
                shutdown_rx,
                trickle_buf,
                outbound_tx: self.shared.outbound_tx.clone(),
                frames: self.shared.frames.clone(),
                fps: self.shared.fps,
            })
            .await
            .map_err(|e| {
                warn!("webrtc_camera: new_session enqueue failed: {e}");
                WebRtcError::Failure
            })?;

        // Push the SDP Answer to the controller's WebRTCTransportRequestor.
        if let Err(e) = self
            .shared
            .outbound_tx
            .send(OutboundWork::Answer { session_id })
            .await
        {
            warn!("webrtc_camera: outbound Answer enqueue failed: {e}");
        }

        // Request the outbound-trickle pump to flush our host candidate.
        if let Err(e) = self
            .shared
            .outbound_tx
            .send(OutboundWork::IceCandidates { session_id })
            .await
        {
            warn!("webrtc_camera: outbound IceCandidates enqueue failed: {e}");
        }

        Ok(AnswerOutcome {
            video_stream_id: None,
            audio_stream_id: None,
        })
    }

    async fn on_answer(&self, session_id: u16, _sdp: &str) -> Result<(), WebRtcError> {
        warn!("webrtc_camera: unexpected ProvideAnswer for session {session_id}");
        Err(WebRtcError::InvalidInState)
    }

    async fn on_ice_candidates(
        &self,
        session_id: u16,
        candidates: &TLVArray<'_, ICECandidateStruct<'_>>,
    ) -> Result<(), WebRtcError> {
        // Collect parsed candidates without holding the inner borrow.
        let mut parsed: Vec<Candidate> = Vec::new();
        for cand in candidates.iter() {
            let cand = match cand {
                Ok(c) => c,
                Err(e) => {
                    warn!("webrtc_camera: malformed ICE candidate in batch: {e}");
                    continue;
                }
            };
            let sdp_line = match cand.candidate() {
                Ok(s) => s,
                Err(e) => {
                    warn!("webrtc_camera: ICE candidate TLV missing SDP string: {e}");
                    continue;
                }
            };
            let trimmed = sdp_line.trim_start_matches("a=");
            match Candidate::from_sdp_string(trimmed) {
                Ok(c) => parsed.push(c),
                Err(e) => warn!("webrtc_camera: Candidate::from_sdp_string failed: {e}"),
            }
        }

        let sender = {
            let inner = self.shared.inner.borrow();
            let Some(s) = inner.sessions.get(&session_id) else {
                warn!("webrtc_camera: remote ICE for unknown session {session_id}");
                return Err(WebRtcError::InvalidInState);
            };
            s.remote_cand_tx.clone()
        };

        let added = parsed.len();
        for c in parsed {
            let _ = sender.send(c).await;
        }
        info!("webrtc_camera: session {session_id} trickle-ICE +{added} remote candidates");
        Ok(())
    }

    async fn on_end_session(
        &self,
        session_id: u16,
        reason: WebRTCEndReasonEnum,
    ) -> Result<(), WebRtcError> {
        let ctrl = self.shared.inner.borrow_mut().sessions.remove(&session_id);
        if let Some(ctrl) = ctrl {
            let _ = ctrl.shutdown_tx.try_send(());
            info!(
                "webrtc_camera: session {session_id} ended ({reason:?}), active = {}",
                self.shared.inner.borrow().sessions.len()
            );
        } else {
            warn!("webrtc_camera: EndSession for unknown session {session_id}");
        }
        Ok(())
    }

    async fn next_outbound(&self) -> OutboundWork {
        // Park until the driver (or `on_offer`) posts something.
        // If the sender half ever dropped, await forever — no-op.
        match self.shared.outbound_rx.recv().await {
            Ok(w) => w,
            Err(_) => core::future::pending().await,
        }
    }

    async fn fill_ice_candidates<P: TLVBuilderParent>(
        &self,
        session_id: u16,
        mut candidates: ICECandidateStructArrayBuilder<P>,
    ) -> Result<P, Error> {
        // Drain the per-session trickle buffer.
        let drained: Vec<String> = {
            let inner = self.shared.inner.borrow();
            if let Some(s) = inner.sessions.get(&session_id) {
                s.trickle_buf.borrow_mut().drain(..).collect()
            } else {
                Vec::new()
            }
        };

        for cand in &drained {
            candidates = candidates
                .push()?
                .candidate(cand.as_str())?
                .sdp_mid(Nullable::none())?
                .sdpm_line_index(Nullable::none())?
                .end()?;
        }

        candidates.end()
    }

    async fn take_answer_sdp(
        &self,
        session_id: u16,
        sdp_out: &mut [u8],
    ) -> Result<usize, WebRtcError> {
        let sdp = {
            let inner = self.shared.inner.borrow();
            let Some(s) = inner.sessions.get(&session_id) else {
                warn!("webrtc_camera: take_answer_sdp for unknown session {session_id}");
                return Err(WebRtcError::InvalidInState);
            };
            let taken = s.answer_sdp.borrow_mut().take();
            taken.ok_or_else(|| {
                warn!("webrtc_camera: take_answer_sdp: no Answer queued for session {session_id}");
                WebRtcError::InvalidInState
            })?
        };
        if sdp.len() > sdp_out.len() {
            warn!(
                "webrtc_camera: answer SDP ({} B) exceeds buffer ({} B)",
                sdp.len(),
                sdp_out.len()
            );
            return Err(WebRtcError::ResourceExhausted);
        }
        sdp_out[..sdp.len()].copy_from_slice(sdp.as_bytes());
        Ok(sdp.len())
    }
}

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

static MATTER: StaticCell<Matter> = StaticCell::new();
static BUFFERS: StaticCell<PooledBuffers<10, IMBuffer>> = StaticCell::new();
static SUBSCRIPTIONS: StaticCell<Subscriptions> = StaticCell::new();
static KV_BUF: StaticCell<[u8; 4096]> = StaticCell::new();
static WEBRTC: StaticCell<WebRtc> = StaticCell::new();
static CAM_AV: StaticCell<CameraAvStreamHandler<'static, Str0mCamHooks, CAM_AV_NV>> =
    StaticCell::new();
static ZONE_MGMT: StaticCell<ZoneMgmtHandler<DemoZoneHooks, ZONE_NZ, ZONE_NV, ZONE_NT>> =
    StaticCell::new();
/// DPTZ-only demo: 1 video stream, 1 viewport entry, 0 presets.
const CAM_AV_SETTINGS_NP: usize = 0;
const CAM_AV_SETTINGS_NS: usize = 2;

/// Hooks for `CameraAVSettingsUserLevelManagement`. The str0m demo
/// has a fixed lens and a fixed encoded resolution, so all hooks just
/// log: the actual viewport translation would be the
/// application's responsibility (e.g. GPU crop) in a real product.
struct DemoCamAvSettingsHooks;

impl CamAvSettingsHooks for DemoCamAvSettingsHooks {
    async fn dptz_apply(&self, view: &DptzView) -> Result<(), CamAvSettingsError> {
        info!(
            "cam-av-settings: dptz stream=#{} viewport=({},{})-({},{})",
            view.video_stream_id, view.x1, view.y1, view.x2, view.y2
        );
        Ok(())
    }
}

static CAM_AV_SETTINGS: StaticCell<
    CamAvSettingsHandler<DemoCamAvSettingsHooks, CAM_AV_SETTINGS_NP, CAM_AV_SETTINGS_NS>,
> = StaticCell::new();
static SHARED: StaticCell<Str0mShared> = StaticCell::new();

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Error> {
    // Use `tracing-subscriber` so we see both the rs-matter `log::*` events
    // (bridged via the `tracing-log` feature of `tracing-subscriber`) AND
    // `str0m`'s `tracing::*` events in the same output. Default filter:
    // `debug` for our crates, `trace` for str0m unless `RUST_LOG` overrides.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("info,webrtc_camera=info,str0m=info")
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(false)
        .init();

    info!(
        "Matter memory: Matter (BSS)={}B, IM Buffers (BSS)={}B, Subscriptions (BSS)={}B, WebRtc (BSS)={}B",
        core::mem::size_of::<Matter>(),
        core::mem::size_of::<PooledBuffers<10, IMBuffer>>(),
        core::mem::size_of::<Subscriptions>(),
        core::mem::size_of::<WebRtc>(),
    );

    let matter = MATTER.uninit().init_with(Matter::init(
        &BASIC_INFO,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        rs_matter::utils::epoch::sys_epoch,
        MATTER_PORT,
    ));

    let kv_buf = KV_BUF.uninit().init_zeroed().as_mut_slice();
    let mut kv = DirKvBlobStore::new_default();
    futures_lite::future::block_on(matter.load_persist(&mut kv, kv_buf))?;

    let buffers = BUFFERS.uninit().init_with(PooledBuffers::init(0));
    let subscriptions = SUBSCRIPTIONS.uninit().init_with(Subscriptions::init());

    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);
    let mut rand = crypto.rand()?;

    // Optional H.264 Annex-B media source. Set `WEBRTC_CAMERA_H264` to a
    // path to enable; with no source the example negotiates ICE+DTLS but
    // sends no media. FPS defaults to 30; override via `WEBRTC_CAMERA_FPS`.
    let fps: u32 = std::env::var("WEBRTC_CAMERA_FPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&v: &u32| v > 0 && v <= 120)
        .unwrap_or(30);
    let frames: Arc<Vec<H264Frame>> = match std::env::var("WEBRTC_CAMERA_H264").ok() {
        Some(path) if !path.is_empty() => match std::fs::read(&path) {
            Ok(bytes) => {
                let frames = parse_annex_b(&bytes);
                let keyframes = frames.iter().filter(|f| f.is_keyframe).count();
                info!(
                    "webrtc_camera: loaded {} ({} bytes) → {} access units ({} keyframes) @ {fps} fps",
                    path,
                    bytes.len(),
                    frames.len(),
                    keyframes
                );
                if frames.is_empty() {
                    warn!("webrtc_camera: no NAL units found in {path}; media plane disabled");
                }
                Arc::new(frames)
            }
            Err(e) => {
                warn!("webrtc_camera: failed to read {path}: {e}; media plane disabled");
                Arc::new(Vec::new())
            }
        },
        _ => {
            info!(
                "webrtc_camera: WEBRTC_CAMERA_H264 not set; media plane disabled \
                 (ICE+DTLS only — no video will be sent)"
            );
            Arc::new(Vec::new())
        }
    };

    let shared: &'static Str0mShared = SHARED.init(Str0mShared::new(frames, fps));
    let webrtc = WEBRTC.init(WebRtcProvHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        Str0mHooks { shared },
    ));
    let cam_av_config = CameraAvStreamConfig {
        max_concurrent_encoders: 1,
        max_encoded_pixel_rate: 1920 * 1080 * 30,
        sensor: VideoSensorParams {
            sensor_width: 1920,
            sensor_height: 1080,
            max_fps: 30,
            max_hdrfps: None,
        },
        min_viewport: (640, 360),
        max_content_buffer_size: 1_048_576,
        max_network_bandwidth: 10_000,
        supported_stream_usages: CAM_AV_STREAM_USAGES,
        default_stream_usage_priorities: CAM_AV_STREAM_USAGES,
        rate_distortion_points: CAM_AV_RATE_DISTORTION,
        mic_capabilities: None,
    };
    let cam_av = CAM_AV.init(CameraAvStreamHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        cam_av_config,
        rs_matter::dm::clusters::app::cam_av_stream::Feature::VIDEO.bits(),
        Str0mCamHooks,
    ));
    // Pre-seed one H.264 1080p30 stream so AllocatedVideoStreams is
    // non-empty at boot, mirroring the prior demo behaviour.
    let _ = cam_av.add_preallocated_video(VideoStream {
        video_stream_id: 0, // overwritten by handler
        stream_usage: StreamUsageEnum::LiveView,
        video_codec: VideoCodecEnum::H264,
        min_frame_rate: 1,
        max_frame_rate: 30,
        min_width: 640,
        min_height: 360,
        max_width: 1920,
        max_height: 1080,
        min_bit_rate: 500_000,
        max_bit_rate: 4_000_000,
        key_frame_interval: 2000,
        watermark_enabled: None,
        osd_enabled: None,
        reference_count: 0,
    });
    let cam_av_settings = CAM_AV_SETTINGS.init(CamAvSettingsHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        CLUSTER_DPTZ_ONLY,
        CamAvSettingsConfig {
            pan_range: (0, 0),
            tilt_range: (0, 0),
            zoom_max: 1,
            default_position: Mptz {
                pan: None,
                tilt: None,
                zoom: None,
            },
            max_presets: 0,
        },
        DemoCamAvSettingsHooks,
    ));

    let zone_mgmt = ZONE_MGMT.init(ZoneMgmtHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        ZoneMgmtConfig {
            max_zones: ZONE_NZ as u8,
            max_user_defined_zones: ZONE_NZ as u8,
            sensitivity_max: 0,
            default_sensitivity: 0,
            two_d_cartesian_max: (1920, 1080),
        },
        rs_matter::dm::clusters::app::zone_mgmt::Feature::TWO_DIMENSIONAL_CARTESIAN_ZONE.bits()
            | rs_matter::dm::clusters::app::zone_mgmt::Feature::USER_DEFINED.bits(),
        DemoZoneHooks,
    ));

    let events = NoEvents::new_default();
    let dm = DataModel::new(
        matter,
        &crypto,
        buffers,
        subscriptions,
        &events,
        dm_handler(rand, webrtc, cam_av, cam_av_settings, zone_mgmt),
        SharedKvBlobStore::new(kv, kv_buf),
        SharedNetworks::new(EthNetwork::new_default()),
    );

    let responder = DefaultResponder::new(&dm);
    let mut respond = pin!(responder.run::<4, 4>());
    let mut dm_job = pin!(dm.run());

    let udp_socket = Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // WebRTC ICE / STUN / DTLS messages routed over Matter can easily
    // exceed Matter's UDP MRU (~1200 B post-PASE); attach a TCP transport
    // so the controller can fall back to TCP for large payloads. The
    // `tcp_supported: true` flag in `BASIC_INFO` advertises this via
    // mDNS (`T=1`).
    let tcp_socket = Async::<TcpListener>::bind(MATTER_SOCKET_BIND_ADDR)?;
    let tcp = rs_matter::transport::network::tcp::TcpNetwork::<8>::new(tcp_socket);
    info!(
        "TCP transport enabled, listening on {}",
        MATTER_SOCKET_BIND_ADDR
    );

    let (mut net_send, mut net_recv, mut net_multicast) = {
        use rs_matter::transport::network::{Address, ChainedNetwork};

        let net_send = ChainedNetwork::new(|addr: &Address| addr.is_tcp(), &tcp, &udp_socket);
        let net_recv = ChainedNetwork::new(|addr: &Address| addr.is_tcp(), &tcp, &udp_socket);
        (net_send, net_recv, &udp_socket)
    };

    let mut mdns = pin!(mdns::run_mdns(matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &mut net_send, &mut net_recv, &mut net_multicast));
    let mut driver = pin!(shared.drive());

    if !matter.is_commissioned() {
        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;
        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, dm.change_notify())?;
    }

    let matter_core = select4(&mut transport, &mut mdns, &mut respond, &mut dm_job).coalesce();
    let all = select(matter_core, &mut driver).coalesce();
    futures_lite::future::block_on(all)
}

// ---------------------------------------------------------------------------
// Node + handler wiring
// ---------------------------------------------------------------------------

/// Basic-info override: same as `TEST_DEV_DET` but advertises TCP support
/// (`T=1` in the mDNS TXT record). Required because some WebRTC payloads
/// (large ICE / STUN / DTLS messages) exceed Matter's UDP MRU and need to
/// fall back to TCP.
const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    tcp_supported: true,
    ..TEST_DEV_DET
};

const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(geth),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_MATTER_CAMERA),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                CameraAvStreamHandler::<Str0mCamHooks, CAM_AV_NV>::CLUSTER,
                rs_matter::dm::clusters::app::cam_av_settings::CLUSTER_DPTZ_ONLY,
                ZoneMgmtHandler::<DemoZoneHooks, ZONE_NZ, ZONE_NV, ZONE_NT>::CLUSTER,
                WebRtc::CLUSTER
            ),
        },
    ],
};

fn dm_handler<'a>(
    mut rand: impl RngCore + Copy,
    webrtc: &'a WebRtc,
    cam_av: &'a CameraAvStreamHandler<'static, Str0mCamHooks, CAM_AV_NV>,
    cam_av_settings: &'a CamAvSettingsHandler<
        DemoCamAvSettingsHooks,
        CAM_AV_SETTINGS_NP,
        CAM_AV_SETTINGS_NS,
    >,
    zone_mgmt: &'a ZoneMgmtHandler<DemoZoneHooks, ZONE_NZ, ZONE_NV, ZONE_NT>,
) -> impl AsyncMetadata + AsyncHandler + 'a {
    (
        NODE,
        endpoints::with_eth_sys(
            &false,
            &(),
            &UnixNetifs,
            rand,
            EmptyHandler
                .chain(
                    EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                    rs_matter::dm::Async(
                        desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt(),
                    ),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(groups::GroupsHandler::CLUSTER.id)),
                    rs_matter::dm::Async(
                        groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt(),
                    ),
                )
                .chain(
                    EpClMatcher::new(
                        Some(1),
                        Some(CameraAvStreamHandler::<Str0mCamHooks, CAM_AV_NV>::CLUSTER.id),
                    ),
                    rs_matter::dm::clusters::app::cam_av_stream::HandlerAsyncAdaptor(cam_av),
                )
                .chain(
                    EpClMatcher::new(
                        Some(1),
                        Some(rs_matter::dm::clusters::app::cam_av_settings::CLUSTER_DPTZ_ONLY.id),
                    ),
                    rs_matter::dm::clusters::app::cam_av_settings::HandlerAsyncAdaptor(
                        cam_av_settings,
                    ),
                )
                .chain(
                    EpClMatcher::new(
                        Some(1),
                        Some(
                            ZoneMgmtHandler::<DemoZoneHooks, ZONE_NZ, ZONE_NV, ZONE_NT>::CLUSTER.id,
                        ),
                    ),
                    ZoneMgmtAdaptor(zone_mgmt),
                )
                .chain(
                    EpClMatcher::new(Some(1), Some(WebRtc::CLUSTER.id)),
                    WebRtcAdaptor(webrtc),
                ),
        ),
    )
}
