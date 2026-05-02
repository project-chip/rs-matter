/*
 *
 *    Copyright (c) 2020-2026 Project CHIP Authors
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

//! The WebRTC Transport Provider cluster (0x0553).
//!
//! Implements the server side of the Matter WebRTC signalling used by Matter
//! cameras to expose audio/video streams to Matter controllers via the standard
//! WebRTC Offer/Answer flow and trickle-ICE exchange.
//!
//! # Architecture (Pattern B1 — "Hooks")
//!
//! [`WebRtcProvHandler`] implements the spec-defined session table and
//! command state machine. All media-specific work (SDP generation, ICE
//! gathering, media-source lifecycle) is delegated to a user-supplied
//! [`WebRtcHooks`] implementation.
//!
//! ```text
//! ┌───────────────────┐   ClusterAsyncHandler    ┌────────────────┐
//! │                   │◀── inbound commands ─────│   rs-matter IM │
//! │  WebRtcProvHandler│                          │    dispatcher  │
//! └───────┬───────────┘                          └────────────────┘
//!         │ delegates SDP/ICE work
//!         ▼
//! ┌───────────────────┐
//! │    WebRtcHooks    │  user-supplied (e.g. str0m-based for std)
//! └───────────────────┘
//! ```
//!
//! # Const generics
//!
//! Every static allocation is explicit at the call-site:
//!
//! * `N_SESSIONS` — maximum concurrent WebRTC sessions held in the table.
//!   The Matter spec mandates MinLimit = 3; typical values are 3..=8.
//! * `SDP_LEN` — maximum SDP blob size, in bytes. Full WebRTC SDPs range
//!   2–8 KiB depending on codec support.
//! * `OUT_LEN` — scratch-buffer size, in bytes, for the outbound invoke
//!   payload produced by [`WebRtcProvHandler::run`]. Must be large enough
//!   for a trickle-ICE batch; typical value 1 KiB.
//!
//! On `no_std` / embedded targets, [`WebRtcProvHandler::run`] holds an
//! `[u8; OUT_LEN]` plus, on the `Offer`/`Answer` paths, an `[u8; SDP_LEN]`
//! in its async-future state. Pick `SDP_LEN` to fit the smallest SDP your
//! deployment will negotiate (e.g. 2 KiB for a single H.264 + Opus track)
//! to keep the future small enough for the executor's task slot.
//!
//! # Scope
//!
//! * Inbound command state machine: fully implemented for
//!   `SolicitOffer` / `ProvideOffer` / `ProvideAnswer` /
//!   `ProvideICECandidates` / `EndSession`.
//! * Fabric-scoped `CurrentSessions` attribute.
//! * `WebRtcHooks` trait with `async` hooks for the media-plane work.
//! * Outbound push to `WebRTCTransportRequestor`:
//!   [`OutboundWork::Offer`] (deferred-offer flow — camera-initiated
//!   SDP Offer following an earlier `SolicitOffer`),
//!   [`OutboundWork::Answer`] (SDP Answer for `ProvideOffer`),
//!   [`OutboundWork::IceCandidates`] (trickle ICE to traverse NAT) and
//!   [`OutboundWork::End`] (camera-initiated teardown) are driven from
//!   [`WebRtcProvHandler::run`] via [`WebRtcHooks::next_outbound`].

#[allow(unused_imports)]
pub use crate::dm::clusters::decl::web_rtc_transport_provider::*;

use core::cell::{Cell, RefCell};

use crate::dm::clusters::decl::globals::{
    ICECandidateStruct, ICECandidateStructArrayBuilder, StreamUsageEnum, WebRTCEndReasonEnum,
    WebRTCSessionStructArrayBuilder, WebRTCSessionStructBuilder,
};
use crate::dm::{
    ArrayAttributeRead, Cluster, Dataver, EndptId, HandlerContext, InvokeContext, ReadContext,
};
use crate::error::{Error, ErrorCode};
use crate::im::client::ImClient;
use crate::tlv::{Nullable, TLVArray, TLVBuilderParent, TLVElement, TLVTag, TLVWriteParent};
use crate::transport::exchange::Exchange;
use crate::utils::storage::{Vec, WriteBuf};
use crate::utils::sync::blocking::Mutex;
use crate::with;

use super::super::decl::web_rtc_transport_provider as decl;
use super::super::decl::web_rtc_transport_requestor as req_decl;

/// Cluster ID of `WebRTCTransportRequestor` (spec 1.5, §1.16), the peer
/// cluster we invoke for outbound trickle-ICE and session-end pushes.
const REQUESTOR_CLUSTER_ID: u32 = 0x0554;

/// Errors surfaced by [`WebRtcHooks`] implementations. These map to
/// Matter cluster-status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum WebRtcError {
    /// `INVALID_IN_STATE` — the command cannot be processed in the current
    /// session state (e.g. `ProvideAnswer` before an Offer was sent).
    InvalidInState,
    /// `INVALID_COMMAND` — the command parameters are structurally invalid
    /// (e.g. `SolicitOffer` with no stream IDs at all).
    InvalidCommand,
    /// `DYNAMIC_CONSTRAINT_ERROR` — the request refers to stream IDs,
    /// codecs or capabilities the hooks cannot satisfy.
    DynamicConstraint,
    /// `RESOURCE_EXHAUSTED` — the media source cannot accept a new session.
    ResourceExhausted,
    /// `FAILURE` — any other hooks-level failure.
    Failure,
}

impl From<WebRtcError> for Error {
    fn from(e: WebRtcError) -> Self {
        match e {
            WebRtcError::InvalidInState => ErrorCode::InvalidAction.into(),
            WebRtcError::InvalidCommand => ErrorCode::InvalidCommand.into(),
            WebRtcError::DynamicConstraint => ErrorCode::DynamicConstraintError.into(),
            WebRtcError::ResourceExhausted => ErrorCode::ResourceExhausted.into(),
            WebRtcError::Failure => ErrorCode::Failure.into(),
        }
    }
}

/// Owned parameters of a `SolicitOffer` / `ProvideOffer` request.
///
/// Owned (not TLV-borrowed) so it can cross `.await` points when passed
/// to async hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OfferParams {
    /// The stream usage requested by the peer.
    pub stream_usage: StreamUsageEnum,
    /// Originating endpoint of the controller hosting the
    /// `WebRTCTransportRequestor`.
    pub originating_endpoint_id: EndptId,
    /// Requested video-stream ID.
    /// - `None`           → field absent from request
    /// - `Some(None)`     → explicit NULL
    /// - `Some(Some(id))` → concrete ID
    pub video_stream_id: Option<Option<u16>>,
    /// Requested audio-stream ID, same encoding as `video_stream_id`.
    pub audio_stream_id: Option<Option<u16>>,
    /// Whether the peer opted in to metadata delivery.
    pub metadata_enabled: bool,
}

/// Outcome of [`WebRtcHooks::on_solicit_offer`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SolicitOutcome {
    /// If `false`, the `SolicitOfferResponse` has `deferredOffer = false`
    /// and the hooks are expected to enqueue [`OutboundWork::Offer`]
    /// shortly so the Offer can be pushed via
    /// `WebRTCTransportRequestor::Offer`. If `true`, the media source was
    /// not ready; the hooks must enqueue the Offer when it becomes
    /// available.
    pub deferred: bool,
    /// Resolved video-stream ID (absent = omit field in response).
    pub video_stream_id: Option<u16>,
    /// Resolved audio-stream ID (absent = omit field in response).
    pub audio_stream_id: Option<u16>,
}

/// Outcome of [`WebRtcHooks::on_offer`].
///
/// The SDP Answer itself is buffered by the hooks implementation and
/// pushed asynchronously via [`OutboundWork::Answer`] /
/// [`WebRtcHooks::fill_answer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AnswerOutcome {
    /// Resolved video-stream ID, or NULL (= session has no video).
    pub video_stream_id: Option<u16>,
    /// Resolved audio-stream ID, or NULL (= session has no audio).
    pub audio_stream_id: Option<u16>,
}

/// A descriptor of an outbound invocation, returned by
/// [`WebRtcHooks::next_outbound`] and dispatched by
/// [`WebRtcProvHandler::run`].
///
/// The payload itself is NOT carried here: for [`OutboundWork::IceCandidates`]
/// the handler calls [`WebRtcHooks::fill_ice_candidates`] with a TLV
/// array builder and the hook streams queued candidates into it directly,
/// avoiding any owned intermediate buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OutboundWork {
    /// `WebRTCTransportRequestor::Offer` — deferred-offer flow:
    /// the controller previously called `SolicitOffer` and the device
    /// returned `deferredOffer = true`; once the local media source
    /// produces an SDP Offer, the hooks enqueue this work item so the
    /// handler pushes it to the controller. The handler invokes
    /// [`WebRtcHooks::take_offer_sdp`] to obtain the SDP bytes.
    Offer {
        /// Target session.
        session_id: u16,
    },
    /// `WebRTCTransportRequestor::Answer` — push the SDP Answer for a
    /// session whose Offer arrived via `ProvideOffer`. The handler
    /// invokes [`WebRtcHooks::fill_answer`] to obtain the SDP bytes.
    Answer {
        /// Target session.
        session_id: u16,
    },
    /// `WebRTCTransportRequestor::ICECandidates` — trickle a batch of
    /// locally-gathered ICE candidates to the peer (needed for NAT
    /// traversal).
    IceCandidates {
        /// Target session.
        session_id: u16,
    },
    /// `WebRTCTransportRequestor::End` — notify the peer that we are
    /// tearing down the session (e.g. camera power-down, media source
    /// lost).
    End {
        /// Target session.
        session_id: u16,
        /// Reason for termination.
        reason: WebRTCEndReasonEnum,
    },
}

/// The device-side WebRTC media-plane plumbing. Cluster state (session
/// table, dataver, attribute/command dispatch) is owned by
/// [`WebRtcProvHandler`]; this trait captures every side-effect the
/// spec commands have on the actual WebRTC peer.
///
/// All methods are `async` and invoked inline from the handler's command
/// dispatch. Implementations MUST NOT perform blocking I/O.
pub trait WebRtcHooks {
    /// Handle an inbound `SolicitOffer` command. The session ID has been
    /// allocated; the hook decides whether to respond with `deferred = false`
    /// (in which case it MUST shortly enqueue an [`OutboundWork::Offer`] so
    /// the handler can push the SDP Offer via
    /// `WebRTCTransportRequestor::Offer`) or `deferred = true` (Offer
    /// pushed when the media source becomes ready).
    ///
    /// `SolicitOfferResponse` itself does NOT carry an SDP — see Matter 1.5
    /// §1.16 — so this hook never returns Offer bytes inline.
    async fn on_solicit_offer(
        &self,
        session_id: u16,
        params: &OfferParams,
    ) -> Result<SolicitOutcome, WebRtcError>;

    /// Handle an inbound `ProvideOffer` command. The SDP Offer has been
    /// validated as UTF-8; the hooks buffers the SDP Answer internally
    /// and enqueues an [`OutboundWork::Answer`] so the handler can push
    /// it to the peer's `WebRTCTransportRequestor::Answer` command.
    async fn on_offer(
        &self,
        session_id: u16,
        sdp: &str,
        params: &OfferParams,
    ) -> Result<AnswerOutcome, WebRtcError>;

    /// Handle an inbound `ProvideAnswer` for a session whose Offer THIS
    /// node originally sent (deferred-offer flow).
    async fn on_answer(&self, session_id: u16, sdp: &str) -> Result<(), WebRtcError>;

    /// Handle an inbound batch of remote ICE candidates.
    async fn on_ice_candidates(
        &self,
        session_id: u16,
        candidates: &TLVArray<'_, ICECandidateStruct<'_>>,
    ) -> Result<(), WebRtcError>;

    /// Handle an inbound `EndSession`. The session entry is removed from
    /// the table immediately after this call returns.
    async fn on_end_session(
        &self,
        session_id: u16,
        reason: WebRTCEndReasonEnum,
    ) -> Result<(), WebRtcError>;

    /// Await the next outbound invocation the camera wants to push to the
    /// controller. Called in a tight loop from [`WebRtcProvHandler::run`]:
    /// when the hook has nothing to send it MUST `.await` a future that
    /// never completes (e.g. [`core::future::pending`]) or parks on an
    /// internal signal.
    ///
    /// A default implementation is provided that parks forever, i.e.
    /// opts the implementor out of outbound support. Override to enable
    /// trickle-ICE and camera-initiated session end.
    async fn next_outbound(&self) -> OutboundWork {
        core::future::pending().await
    }

    /// Fill the `ICECandidates` array of an outbound `ICECandidates`
    /// request. Called by the handler immediately after
    /// [`Self::next_outbound`] returns [`OutboundWork::IceCandidates`].
    /// Implementations MUST push every candidate queued for `session_id`
    /// and then `end()` the array builder.
    ///
    /// Default: errors out — override when overriding [`Self::next_outbound`]
    /// to emit [`OutboundWork::IceCandidates`].
    async fn fill_ice_candidates<P: TLVBuilderParent>(
        &self,
        _session_id: u16,
        _candidates: ICECandidateStructArrayBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::Invalid.into())
    }

    /// Write the SDP Answer bytes for `session_id` into the supplied
    /// buffer, returning the number of bytes written. Called by the
    /// handler immediately after [`Self::next_outbound`] returns
    /// [`OutboundWork::Answer`].
    ///
    /// If the buffer is too small the hooks SHOULD return
    /// [`WebRtcError::ResourceExhausted`]; if no Answer is queued for
    /// `session_id` return [`WebRtcError::InvalidInState`].
    ///
    /// Default: errors out — override when overriding [`Self::on_offer`].
    async fn take_answer_sdp(
        &self,
        _session_id: u16,
        _sdp_out: &mut [u8],
    ) -> Result<usize, WebRtcError> {
        Err(WebRtcError::InvalidInState)
    }

    /// Write the SDP Offer bytes for `session_id` into the supplied
    /// buffer, returning the number of bytes written. Called by the
    /// handler immediately after [`Self::next_outbound`] returns
    /// [`OutboundWork::Offer`].
    ///
    /// If the buffer is too small the hooks SHOULD return
    /// [`WebRtcError::ResourceExhausted`]; if no Offer is queued for
    /// `session_id` return [`WebRtcError::InvalidInState`].
    ///
    /// Default: errors out — override to enable the deferred-offer
    /// flow ([`SolicitOutcome::deferred = true`](SolicitOutcome) on a
    /// `SolicitOffer` response, followed by an [`OutboundWork::Offer`]
    /// from [`Self::next_outbound`]).
    async fn take_offer_sdp(
        &self,
        _session_id: u16,
        _sdp_out: &mut [u8],
    ) -> Result<usize, WebRtcError> {
        Err(WebRtcError::InvalidInState)
    }
}

/// Internal session-state tracked by the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum SessionState {
    /// Created via `SolicitOffer` with a deferred Offer; awaiting the
    /// hooks to enqueue [`OutboundWork::Offer`].
    AwaitingDeferredOffer,
    /// Offer was sent (immediately via SolicitOfferResponse or later via
    /// the deferred flow). Awaiting `ProvideAnswer`.
    AwaitingAnswer,
    /// `ProvideOffer` arrived peer-initiated and was answered inline, OR
    /// `ProvideAnswer` arrived for an already-sent Offer. Signalling
    /// done; ICE candidates may still flow.
    Established,
}

/// Owned session-table row. Kept small + `Copy` so snapshotting for
/// iteration is cheap.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct SessionEntry {
    id: u16,
    fab_idx: u8,
    peer_node_id: u64,
    peer_endpoint_id: EndptId,
    stream_usage: StreamUsageEnum,
    /// `None` = NULL in spec; `Some(x)` = concrete stream ID.
    video_stream_id: Option<u16>,
    /// `None` = NULL in spec; `Some(x)` = concrete stream ID.
    audio_stream_id: Option<u16>,
    metadata_enabled: bool,
    state: SessionState,
}

/// The WebRTC Transport Provider cluster handler.
///
/// See the [module documentation](self) for the architecture and usage.
pub struct WebRtcProvHandler<
    H: WebRtcHooks,
    const N_SESSIONS: usize,
    const SDP_LEN: usize,
    const OUT_LEN: usize,
> {
    dataver: Dataver,
    endpoint_id: EndptId,
    hooks: H,
    sessions: Mutex<RefCell<Vec<SessionEntry, N_SESSIONS>>>,
    next_id: Mutex<Cell<u16>>,
}

impl<H: WebRtcHooks, const N_SESSIONS: usize, const SDP_LEN: usize, const OUT_LEN: usize>
    WebRtcProvHandler<H, N_SESSIONS, SDP_LEN, OUT_LEN>
{
    /// Cluster metadata exposed to the data-model dispatcher.
    pub const CLUSTER: Cluster<'static> = decl::FULL_CLUSTER
        .with_revision(2)
        .with_attrs(with!(required))
        .with_cmds(with!(
            decl::CommandId::SolicitOffer
                | decl::CommandId::ProvideOffer
                | decl::CommandId::ProvideAnswer
                | decl::CommandId::ProvideICECandidates
                | decl::CommandId::EndSession
        ));

    /// Construct a new handler.
    pub const fn new(dataver: Dataver, endpoint_id: EndptId, hooks: H) -> Self {
        Self {
            dataver,
            endpoint_id,
            hooks,
            sessions: Mutex::new(RefCell::new(Vec::new())),
            next_id: Mutex::new(Cell::new(1)),
        }
    }

    /// Wrap in the generic async adaptor for registration with a
    /// `rs-matter` `Node`.
    pub const fn adapt(self) -> decl::HandlerAsyncAdaptor<Self> {
        decl::HandlerAsyncAdaptor(self)
    }

    /// Remove every session owned by the given fabric index. Callers MUST
    /// invoke this when a fabric is removed (spec §"Fabric-scoped data"
    /// for fabric removal). Hooks are NOT notified.
    pub fn remove_fabric_sessions(&self, fab_idx: u8) {
        let changed = self.sessions.lock(|cell| {
            let mut sessions = cell.borrow_mut();
            let before = sessions.len();
            sessions.retain(|s| s.fab_idx != fab_idx);
            before != sessions.len()
        });
        if changed {
            self.dataver.changed();
        }
    }

    /// Get the endpoint this handler is mounted on.
    pub const fn endpoint_id(&self) -> EndptId {
        self.endpoint_id
    }

    fn allocate_id(&self) -> u16 {
        self.sessions.lock(|cell| {
            let sessions = cell.borrow();
            self.next_id.lock(|n| loop {
                let candidate = n.get();
                // Wrap and skip zero (spec: session ID MUST be non-zero).
                let next = if candidate == u16::MAX {
                    1
                } else {
                    candidate + 1
                };
                n.set(next);
                if candidate != 0 && !sessions.iter().any(|s| s.id == candidate) {
                    return candidate;
                }
            })
        })
    }

    fn session_copy(&self, id: u16) -> Option<SessionEntry> {
        self.sessions
            .lock(|cell| cell.borrow().iter().find(|s| s.id == id).copied())
    }

    fn upsert_session(&self, entry: SessionEntry) -> Result<(), Error> {
        self.sessions.lock(|cell| {
            let mut sessions = cell.borrow_mut();
            if let Some(existing) = sessions.iter_mut().find(|s| s.id == entry.id) {
                *existing = entry;
                Ok(())
            } else {
                sessions
                    .push(entry)
                    .map_err(|_| Error::from(ErrorCode::ResourceExhausted))
            }
        })
    }

    fn remove_session(&self, id: u16) {
        self.sessions.lock(|cell| {
            let mut sessions = cell.borrow_mut();
            sessions.retain(|s| s.id != id);
        });
    }

    fn set_state(&self, id: u16, state: SessionState) {
        self.sessions.lock(|cell| {
            if let Some(s) = cell.borrow_mut().iter_mut().find(|s| s.id == id) {
                s.state = state;
            }
        });
    }

    fn check_peer(&self, s: &SessionEntry, fab_idx: u8, peer: u64) -> Result<(), Error> {
        // Spec: NOT_FOUND if the session does not belong to the accessing
        // fabric. Peer-node mismatch within the same fabric is also
        // NOT_FOUND to avoid leaking existence.
        if s.fab_idx != fab_idx || s.peer_node_id != peer {
            Err(ErrorCode::NotFound.into())
        } else {
            Ok(())
        }
    }

    /// Encode and send a single [`OutboundWork`] item.
    ///
    /// Opens a new initiator exchange to the session's peer via
    /// [`Exchange::initiate`] (which in turn uses the CASE session cache
    /// and mDNS if needed), encodes the request payload into a fixed-size
    /// scratch buffer, and invokes the paired `WebRTCTransportRequestor`
    /// cluster on the peer's originating endpoint.
    ///
    /// Returns `Ok(())` without doing anything if the session has been
    /// removed meanwhile (e.g. peer sent `EndSession` in the race window).
    async fn push_outbound(
        &self,
        ctx: &impl HandlerContext,
        work: OutboundWork,
    ) -> Result<(), Error> {
        let session_id = match work {
            OutboundWork::Offer { session_id } => session_id,
            OutboundWork::Answer { session_id } => session_id,
            OutboundWork::IceCandidates { session_id } => session_id,
            OutboundWork::End { session_id, .. } => session_id,
        };
        let Some(session) = self.session_copy(session_id) else {
            // Session dropped concurrently — not an error, just a race.
            return Ok(());
        };

        let mut buf = [0u8; OUT_LEN];
        let mut wb = WriteBuf::new(&mut buf);
        let cmd_id = match work {
            OutboundWork::Offer { .. } => req_decl::CommandId::Offer as u32,
            OutboundWork::Answer { .. } => req_decl::CommandId::Answer as u32,
            OutboundWork::IceCandidates { .. } => req_decl::CommandId::ICECandidates as u32,
            OutboundWork::End { .. } => req_decl::CommandId::End as u32,
        };

        match work {
            OutboundWork::Offer { session_id } => {
                let mut sdp_buf = [0u8; SDP_LEN];
                let sdp_len = self
                    .hooks
                    .take_offer_sdp(session_id, &mut sdp_buf)
                    .await
                    .map_err(Error::from)?;
                let sdp = core::str::from_utf8(&sdp_buf[..sdp_len])
                    .map_err(|_| Error::from(ErrorCode::Invalid))?;
                let parent = TLVWriteParent::new((), &mut wb);
                let _ = req_decl::OfferRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .web_rtc_session_id(session_id)?
                    .sdp(sdp)?
                    .ice_servers()?
                    .none()
                    .ice_transport_policy(None)?
                    .end()?;
                // Now that the Offer is on the wire, transition the
                // session to AwaitingAnswer so a subsequent
                // ProvideAnswer is accepted.
                self.set_state(session_id, SessionState::AwaitingAnswer);
            }
            OutboundWork::Answer { session_id } => {
                let mut sdp_buf = [0u8; SDP_LEN];
                let sdp_len = self
                    .hooks
                    .take_answer_sdp(session_id, &mut sdp_buf)
                    .await
                    .map_err(Error::from)?;
                let sdp = core::str::from_utf8(&sdp_buf[..sdp_len])
                    .map_err(|_| Error::from(ErrorCode::Invalid))?;
                let parent = TLVWriteParent::new((), &mut wb);
                let _ = req_decl::AnswerRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .web_rtc_session_id(session_id)?
                    .sdp(sdp)?
                    .end()?;
            }
            OutboundWork::IceCandidates { session_id } => {
                let parent = TLVWriteParent::new((), &mut wb);
                let req = req_decl::ICECandidatesRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .web_rtc_session_id(session_id)?;
                let arr = req.ice_candidates()?;
                let req = self.hooks.fill_ice_candidates(session_id, arr).await?;
                let _ = req.end()?;
            }
            OutboundWork::End { session_id, reason } => {
                let parent = TLVWriteParent::new((), &mut wb);
                let _ = req_decl::EndRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .web_rtc_session_id(session_id)?
                    .reason(reason)?
                    .end()?;
            }
        }

        let element = TLVElement::new(wb.as_slice());

        let mut exchange =
            Exchange::initiate(ctx.matter(), session.fab_idx, session.peer_node_id, true).await?;

        let _resp = ImClient::invoke_single_cmd(
            &mut exchange,
            session.peer_endpoint_id,
            REQUESTOR_CLUSTER_ID,
            cmd_id,
            element,
            None,
        )
        .await?;

        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────
// ClusterAsyncHandler
// ──────────────────────────────────────────────────────────────────────

impl<H: WebRtcHooks, const N_SESSIONS: usize, const SDP_LEN: usize, const OUT_LEN: usize>
    decl::ClusterAsyncHandler for WebRtcProvHandler<H, N_SESSIONS, SDP_LEN, OUT_LEN>
{
    const CLUSTER: Cluster<'static> = Self::CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        // Drain loop: the hook parks in `next_outbound().await` until it
        // has something to say, then we push it to the paired
        // `WebRTCTransportRequestor` on the remote. Errors are logged
        // (when a `log`/`defmt` feature is enabled) and the loop
        // continues — a single failed push must not take down the whole
        // cluster.
        loop {
            let work = self.hooks.next_outbound().await;
            if let Err(err) = self.push_outbound(&ctx, work).await {
                warn!("webrtc_prov: outbound push failed: {}", err);
            }
        }
    }

    async fn current_sessions<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            WebRTCSessionStructArrayBuilder<P>,
            WebRTCSessionStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        let attr = ctx.attr();

        // Snapshot the filtered list so we don't hold the Mutex across
        // any `?` bail-outs inside the builder chain.
        let mut snapshot: Vec<SessionEntry, N_SESSIONS> = Vec::new();
        self.sessions.lock(|cell| {
            for s in cell.borrow().iter() {
                if !attr.fab_filter || s.fab_idx == attr.fab_idx {
                    // `push` cannot fail: the snapshot is the same size
                    // as the source.
                    let _ = snapshot.push(*s);
                }
            }
        });

        match builder {
            ArrayAttributeRead::ReadAll(mut arr) => {
                for s in &snapshot {
                    arr = encode_session_struct(arr.push()?, s)?;
                }
                arr.end()
            }
            ArrayAttributeRead::ReadOne(index, b) => {
                let s = snapshot
                    .get(index as usize)
                    .ok_or(Error::from(ErrorCode::ConstraintError))?;
                encode_session_struct(b, s)
            }
            ArrayAttributeRead::ReadNone(b) => b.end(),
        }
    }

    async fn handle_solicit_offer<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: decl::SolicitOfferRequest<'_>,
        response: decl::SolicitOfferResponseBuilder<P>,
    ) -> Result<P, Error> {
        let cmd = ctx.cmd();
        let fab_idx = cmd.fab_idx;
        let peer_node_id = exchange_peer_node_id(ctx.exchange())?;

        let params = OfferParams {
            stream_usage: request.stream_usage()?,
            originating_endpoint_id: request.originating_endpoint_id()?,
            video_stream_id: request.video_stream_id()?.map(|n| n.into_option()),
            audio_stream_id: request.audio_stream_id()?.map(|n| n.into_option()),
            metadata_enabled: request.metadata_enabled()?.unwrap_or(false),
        };

        let session_id = self.allocate_id();

        let outcome = self
            .hooks
            .on_solicit_offer(session_id, &params)
            .await
            .map_err(Error::from)?;
        let state = if outcome.deferred {
            SessionState::AwaitingDeferredOffer
        } else {
            SessionState::AwaitingAnswer
        };

        self.upsert_session(SessionEntry {
            id: session_id,
            fab_idx,
            peer_node_id,
            peer_endpoint_id: params.originating_endpoint_id,
            stream_usage: params.stream_usage,
            video_stream_id: outcome.video_stream_id,
            audio_stream_id: outcome.audio_stream_id,
            metadata_enabled: params.metadata_enabled,
            state,
        })?;
        ctx.notify_own_attr_changed(AttributeId::CurrentSessions as _);

        response
            .web_rtc_session_id(session_id)?
            .deferred_offer(outcome.deferred)?
            .video_stream_id(wrap_opt_u16_nullable(outcome.video_stream_id))?
            .audio_stream_id(wrap_opt_u16_nullable(outcome.audio_stream_id))?
            .end()
    }

    async fn handle_provide_offer<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: decl::ProvideOfferRequest<'_>,
        response: decl::ProvideOfferResponseBuilder<P>,
    ) -> Result<P, Error> {
        let cmd = ctx.cmd();
        let fab_idx = cmd.fab_idx;
        let peer_node_id = exchange_peer_node_id(ctx.exchange())?;

        let sdp = request.sdp()?;
        if sdp.len() > SDP_LEN {
            return Err(ErrorCode::ConstraintError.into());
        }

        let params = OfferParams {
            stream_usage: request.stream_usage()?,
            originating_endpoint_id: request.originating_endpoint_id()?,
            video_stream_id: request.video_stream_id()?.map(|n| n.into_option()),
            audio_stream_id: request.audio_stream_id()?.map(|n| n.into_option()),
            metadata_enabled: request.metadata_enabled()?.unwrap_or(false),
        };

        // Spec: NULL session ID = allocate new; non-null = existing session.
        let session_id = match request.web_rtc_session_id()?.into_option() {
            None => self.allocate_id(),
            Some(id) => {
                let s = self
                    .session_copy(id)
                    .ok_or(Error::from(ErrorCode::NotFound))?;
                self.check_peer(&s, fab_idx, peer_node_id)?;
                id
            }
        };

        let outcome = self
            .hooks
            .on_offer(session_id, sdp, &params)
            .await
            .map_err(Error::from)?;

        self.upsert_session(SessionEntry {
            id: session_id,
            fab_idx,
            peer_node_id,
            peer_endpoint_id: params.originating_endpoint_id,
            stream_usage: params.stream_usage,
            video_stream_id: outcome.video_stream_id,
            audio_stream_id: outcome.audio_stream_id,
            metadata_enabled: params.metadata_enabled,
            state: SessionState::Established,
        })?;
        ctx.notify_own_attr_changed(AttributeId::CurrentSessions as _);

        response
            .web_rtc_session_id(session_id)?
            .video_stream_id(wrap_opt_u16_nullable(outcome.video_stream_id))?
            .audio_stream_id(wrap_opt_u16_nullable(outcome.audio_stream_id))?
            .end()
    }

    async fn handle_provide_answer(
        &self,
        ctx: impl InvokeContext,
        request: decl::ProvideAnswerRequest<'_>,
    ) -> Result<(), Error> {
        let cmd = ctx.cmd();
        let fab_idx = cmd.fab_idx;
        let peer_node_id = exchange_peer_node_id(ctx.exchange())?;

        let session_id = request.web_rtc_session_id()?;
        let sdp = request.sdp()?;
        if sdp.len() > SDP_LEN {
            return Err(ErrorCode::ConstraintError.into());
        }

        let session = self
            .session_copy(session_id)
            .ok_or(Error::from(ErrorCode::NotFound))?;
        self.check_peer(&session, fab_idx, peer_node_id)?;

        // Spec: ProvideAnswer is only valid when we sent the Offer.
        match session.state {
            SessionState::AwaitingAnswer | SessionState::AwaitingDeferredOffer => {}
            SessionState::Established => return Err(ErrorCode::InvalidAction.into()),
        }

        self.hooks
            .on_answer(session_id, sdp)
            .await
            .map_err(Error::from)?;
        self.set_state(session_id, SessionState::Established);
        Ok(())
    }

    async fn handle_provide_ice_candidates(
        &self,
        ctx: impl InvokeContext,
        request: decl::ProvideICECandidatesRequest<'_>,
    ) -> Result<(), Error> {
        let cmd = ctx.cmd();
        let fab_idx = cmd.fab_idx;
        let peer_node_id = exchange_peer_node_id(ctx.exchange())?;

        let session_id = request.web_rtc_session_id()?;
        let session = self
            .session_copy(session_id)
            .ok_or(Error::from(ErrorCode::NotFound))?;
        self.check_peer(&session, fab_idx, peer_node_id)?;

        let candidates = request.ice_candidates()?;
        self.hooks
            .on_ice_candidates(session_id, &candidates)
            .await
            .map_err(Error::from)
    }

    async fn handle_end_session(
        &self,
        ctx: impl InvokeContext,
        request: decl::EndSessionRequest<'_>,
    ) -> Result<(), Error> {
        let cmd = ctx.cmd();
        let fab_idx = cmd.fab_idx;
        let peer_node_id = exchange_peer_node_id(ctx.exchange())?;

        let session_id = request.web_rtc_session_id()?;
        let reason = request.reason()?;

        let session = self
            .session_copy(session_id)
            .ok_or(Error::from(ErrorCode::NotFound))?;
        self.check_peer(&session, fab_idx, peer_node_id)?;

        // Best-effort notify the hooks; even if they fail we drop the row.
        let _ = self.hooks.on_end_session(session_id, reason).await;
        self.remove_session(session_id);
        ctx.notify_own_attr_changed(AttributeId::CurrentSessions as _);
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

/// Extract the peer node ID from an incoming exchange's session state.
fn exchange_peer_node_id(exchange: &Exchange<'_>) -> Result<u64, Error> {
    exchange.with_state(|state| {
        let sess = exchange.id().session(&mut state.sessions);
        sess.get_peer_node_id().ok_or(ErrorCode::Invalid.into())
    })
}

/// Convert `Option<u16>` (internal storage) into `Option<Nullable<u16>>`
/// suitable for response builders that treat the field as BOTH optional
/// and nullable. We always emit the field (`Some(_)`); `None` stream ID
/// is represented as `Nullable::none()`.
fn wrap_opt_u16_nullable(v: Option<u16>) -> Option<Nullable<u16>> {
    Some(match v {
        Some(x) => Nullable::some(x),
        None => Nullable::none(),
    })
}

/// Emit a single `WebRTCSessionStruct` into the TLV stream.
fn encode_session_struct<P: TLVBuilderParent>(
    b: WebRTCSessionStructBuilder<P>,
    s: &SessionEntry,
) -> Result<P, Error> {
    let video = match s.video_stream_id {
        Some(x) => Nullable::some(x),
        None => Nullable::none(),
    };
    let audio = match s.audio_stream_id {
        Some(x) => Nullable::some(x),
        None => Nullable::none(),
    };
    b.id(s.id)?
        .peer_node_id(s.peer_node_id)?
        .peer_endpoint_id(s.peer_endpoint_id)?
        .stream_usage(s.stream_usage)?
        .video_stream_id(video)?
        .audio_stream_id(audio)?
        .metadata_enabled(s.metadata_enabled)?
        .video_streams()?
        .none()
        .audio_streams()?
        .none()
        .fabric_index(Some(s.fab_idx))?
        .end()
}
