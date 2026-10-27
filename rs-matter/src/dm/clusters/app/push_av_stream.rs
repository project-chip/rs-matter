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

//! Implementation of the Matter Push AV Stream Transport cluster (0x0555).
//!
//! Lets a camera push audio/video streams to an external endpoint (e.g.
//! a cloud recorder or NVR) using CMAF/DASH over TLS, as an alternative
//! to the pull-style WebRTC transport.
//!
//! # Architecture (Pattern B1 — "Hooks")
//!
//! [`PushAvStreamHandler`] owns the spec-defined state — the
//! `CurrentConnections` table, stable connection IDs, the
//! `SupportedFormats` catalogue — and performs all spec validation
//! before delegating the side-effecting bits (open / modify / close
//! the actual outgoing TLS push) to a user-supplied
//! [`PushAvStreamHooks`] implementation.
//!
//! # Storage
//!
//! `TransportOptionsStruct` is large (11 fields including 2 nested
//! structs and 2 nullable arrays). Rather than mirror every leaf in
//! a dedicated owned type, the handler captures the request's TLV
//! bytes verbatim into a per-connection
//! [`Vec<u8, MAX_TRANSPORT_OPTIONS_BYTES>`] and replays them on
//! attribute reads / `FindTransport`. This keeps the in-memory
//! footprint predictable and faithful to whatever the controller
//! sent without round-tripping through Rust types we'd have to keep
//! in sync with codegen.
//!
//! # Const generics
//!
//! * `NC` — maximum number of concurrently allocated push connections.
//!   Spec MinLimit is 1 for any device advertising the cluster;
//!   typical values 2..=8.
//!
//! # Scope of v1
//!
//! * Full validation, allocation, modification, deallocation,
//!   set-status, manually-trigger, find of push transport
//!   connections.
//! * `SupportedFormats` advertises the `(ContainerFormat, IngestMethod)`
//!   pairs the device can produce.
//! * Round-trip of `TransportOptionsStruct` is byte-for-byte (raw
//!   TLV pass-through) on `CurrentConnections` reads and
//!   `FindTransport` responses.
//! * The `PushTransportBegin` / `PushTransportEnd` events the commands
//!   call for: on `ManuallyTriggerTransport`, and on `SetTransportStatus`
//!   to `Inactive`. The application reports the others - a recording
//!   starting or finishing its upload, a transmission starting on
//!   `SetTransportStatus` to `Active`, a manually triggered one ending -
//!   with [`PushAvStreamHandler::transport_started`] and
//!   [`PushAvStreamHandler::transport_stopped`].
//! * NOT in scope (left to the application via hooks):
//!   `PerZoneSensitivity` / `Metadata` features beyond echoing the
//!   client-supplied bits in stored options. The cluster declares
//!   neither feature in [`Self::CLUSTER`]; build a custom `Cluster`
//!   value if you need them.

use core::cell::{Cell, RefCell};

use crate::dm::FabricIndex;
use crate::dm::{
    ArrayAttributeRead, Cluster, Dataver, EndptId, EventEmitter, HandlerContext, InvokeContext,
    LifecycleOp, ReadContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{TLVBuilderParent, TLVElement, TLVTag, ToTLV};
use crate::utils::storage::{Vec, WriteBuf};
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::{MaybeSend, MaybeSendSync, Notification};
use crate::with;

#[allow(unused_imports)]
pub use crate::dm::clusters::decl::push_av_stream_transport::*;

use super::super::decl::push_av_stream_transport as decl;

/// Maximum size, in bytes, of a single connection's serialized
/// `TransportOptionsStruct`. Sized to fit the worst-case CMAF-with-CENC
/// shape (URL up to 256 chars, two CENC keys, motion zones). Increase
/// at the call site by re-sizing the [`Vec`] type if your deployment
/// pushes the limit.
pub const MAX_TRANSPORT_OPTIONS_BYTES: usize = 768;

/// Errors a [`PushAvStreamHooks`] implementation can surface back to
/// the cluster. Each maps to a Matter cluster-status code (most via
/// the generic `ErrorCode` set; cluster-specific codes are emitted
/// directly by the handler from [`Self::CLUSTER`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PushAvError {
    /// `FAILURE` — generic hooks-level failure.
    Failure,
    /// `NOT_FOUND` — referenced connection ID does not exist.
    NotFound,
    /// `RESOURCE_EXHAUSTED` — application cannot accept another
    /// concurrent push.
    ResourceExhausted,
    /// `CONSTRAINT_ERROR` — combination of params is unsupported at
    /// runtime (e.g. URL host unreachable, codec unavailable on the
    /// requested stream).
    DynamicConstraint,
    /// `INVALID_IN_STATE` — cluster-specific (e.g. trigger before
    /// allocate).
    InvalidInState,
}

impl From<PushAvError> for Error {
    fn from(e: PushAvError) -> Self {
        match e {
            PushAvError::Failure => ErrorCode::Failure.into(),
            PushAvError::NotFound => ErrorCode::NotFound.into(),
            PushAvError::ResourceExhausted => ErrorCode::ResourceExhausted.into(),
            PushAvError::DynamicConstraint => ErrorCode::ConstraintError.into(),
            PushAvError::InvalidInState => ErrorCode::InvalidInState.into(),
        }
    }
}

/// One row in the `SupportedFormats` attribute.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SupportedFormat {
    pub container_format: ContainerFormatEnum,
    pub ingest_method: IngestMethodsEnum,
}

/// One row in the `CurrentConnections` attribute. Stored verbatim by
/// [`PushAvStreamHandler`].
#[derive(Debug, Clone)]
pub struct PushConnection {
    /// Stable, server-assigned ID handed back in
    /// `AllocatePushTransportResponse`.
    pub connection_id: u16,
    /// Fabric the connection belongs to (taken from the invoking
    /// command's accessing fabric — fabric-scoped per spec).
    pub fabric_index: FabricIndex,
    /// Mutable status flipped by `SetTransportStatus` /
    /// `ManuallyTriggerTransport`.
    pub status: TransportStatusEnum,
    /// Raw TLV bytes of the `TransportOptionsStruct` as received in
    /// the original `AllocatePushTransport` (or, after a successful
    /// `ModifyPushTransport`, the new options). Replayed on
    /// attribute reads.
    pub transport_options: Vec<u8, MAX_TRANSPORT_OPTIONS_BYTES>,
}

/// Static configuration for a [`PushAvStreamHandler`]. Currently just
/// the supported-formats catalogue; expand here when you need
/// per-deployment knobs.
#[derive(Debug, Clone, Copy)]
pub struct PushAvStreamConfig<'a> {
    pub supported_formats: &'a [SupportedFormat],
}

/// Application hooks. All spec validation (URL non-empty, stream
/// reference checks if you wire them up via the cam-av-stream
/// reference-counting helpers, capacity, fabric scoping) is done by
/// [`PushAvStreamHandler`] before any of these methods run.
///
/// Implementors only need to interact with their actual upload
/// pipeline (open the TLS connection, push CMAF segments, etc.).
pub trait PushAvStreamHooks: MaybeSendSync {
    /// Called when a new push connection has been validated and
    /// assigned a stable ID. The implementation should provision the
    /// upload pipeline; returning `Err` aborts the allocation (the
    /// connection is NOT added to `CurrentConnections` and no ID is
    /// returned to the controller).
    fn on_allocate(
        &self,
        connection_id: u16,
        fabric_index: FabricIndex,
        request: &AllocatePushTransportRequest<'_>,
    ) -> impl core::future::Future<Output = Result<(), PushAvError>> + MaybeSend;

    /// Called when a controller requests `DeallocatePushTransport`
    /// AND the handler has confirmed the connection exists and is
    /// owned by the accessing fabric. On `Err` the row is left in
    /// place.
    fn on_deallocate(
        &self,
        _connection_id: u16,
    ) -> impl core::future::Future<Output = Result<(), PushAvError>> + MaybeSend {
        async { Ok(()) }
    }

    /// Called on `ModifyPushTransport`. The handler has already
    /// confirmed existence and fabric scoping; on success the stored
    /// raw options are replaced.
    fn on_modify(
        &self,
        _connection_id: u16,
        _request: &ModifyPushTransportRequest<'_>,
    ) -> impl core::future::Future<Output = Result<(), PushAvError>> + MaybeSend {
        async { Ok(()) }
    }

    /// Called on `SetTransportStatus`. `connection_id == None` means
    /// "all connections of the accessing fabric" per spec. Status is
    /// applied to the cluster table on `Ok`. The handler emits
    /// `PushTransportEnd` for the connections made `Inactive`; report the
    /// transmissions that begin on `Active` with
    /// [`PushAvStreamHandler::transport_started`].
    fn on_set_status(
        &self,
        _connection_id: Option<u16>,
        _status: TransportStatusEnum,
    ) -> impl core::future::Future<Output = Result<(), PushAvError>> + MaybeSend {
        async { Ok(()) }
    }

    /// Called on `ManuallyTriggerTransport` — request the upload
    /// pipeline to begin (or extend) a push. `time_control` carries
    /// the optional motion-trigger envelope; `user_defined` carries
    /// the optional opaque blob from the spec's `userDefined` field.
    /// On `Ok` the handler emits `PushTransportBegin`; report the push
    /// ending with [`PushAvStreamHandler::transport_stopped`].
    fn on_manually_trigger(
        &self,
        _connection_id: u16,
        _activation_reason: TriggerActivationReasonEnum,
        _time_control: Option<TransportMotionTriggerTimeControlStruct<'_>>,
        _user_defined: Option<&[u8]>,
    ) -> impl core::future::Future<Output = Result<(), PushAvError>> + MaybeSend {
        async { Ok(()) }
    }

    /// The number of the CMAF session connection `connection_id` uploads,
    /// for its `PushTransportBegin` / `PushTransportEnd` events.
    fn cmaf_session_number(&self, _connection_id: u16) -> Option<u64> {
        None
    }
}

impl<T> PushAvStreamHooks for &T
where
    T: PushAvStreamHooks,
{
    fn on_allocate(
        &self,
        connection_id: u16,
        fabric_index: FabricIndex,
        request: &AllocatePushTransportRequest<'_>,
    ) -> impl core::future::Future<Output = Result<(), PushAvError>> {
        (*self).on_allocate(connection_id, fabric_index, request)
    }

    fn on_deallocate(
        &self,
        connection_id: u16,
    ) -> impl core::future::Future<Output = Result<(), PushAvError>> {
        (*self).on_deallocate(connection_id)
    }

    fn on_modify(
        &self,
        connection_id: u16,
        request: &ModifyPushTransportRequest<'_>,
    ) -> impl core::future::Future<Output = Result<(), PushAvError>> {
        (*self).on_modify(connection_id, request)
    }

    fn on_set_status(
        &self,
        connection_id: Option<u16>,
        status: TransportStatusEnum,
    ) -> impl core::future::Future<Output = Result<(), PushAvError>> {
        (*self).on_set_status(connection_id, status)
    }

    fn on_manually_trigger(
        &self,
        connection_id: u16,
        activation_reason: TriggerActivationReasonEnum,
        time_control: Option<TransportMotionTriggerTimeControlStruct<'_>>,
        user_defined: Option<&[u8]>,
    ) -> impl core::future::Future<Output = Result<(), PushAvError>> {
        (*self).on_manually_trigger(connection_id, activation_reason, time_control, user_defined)
    }

    fn cmaf_session_number(&self, connection_id: u16) -> Option<u64> {
        (*self).cmaf_session_number(connection_id)
    }
}

struct State<const NC: usize> {
    connections: Vec<PushConnection, NC>,
    /// IDs of connections dropped because their fabric was removed, for which
    /// [`PushAvStreamHooks::on_deallocate`] is still to be called.
    removed: Vec<u16, NC>,
}

impl<const NC: usize> State<NC> {
    const fn new() -> Self {
        Self {
            connections: Vec::new(),
            removed: Vec::new(),
        }
    }
}

/// Handler for the Push AV Stream Transport cluster (0x0555).
pub struct PushAvStreamHandler<'a, H, const NC: usize>
where
    H: PushAvStreamHooks,
{
    dataver: Dataver,
    endpoint_id: EndptId,
    config: PushAvStreamConfig<'a>,
    hooks: H,
    state: Mutex<RefCell<State<NC>>>,
    next_id: Mutex<Cell<u16>>,
    removed_signal: Notification,
}

impl<'a, H, const NC: usize> PushAvStreamHandler<'a, H, NC>
where
    H: PushAvStreamHooks,
{
    /// Cluster metadata advertising the mandatory attribute / command
    /// set without optional features. Build a custom [`Cluster`]
    /// value via `decl::FULL_CLUSTER.with_features(...)` for
    /// `PER_ZONE_SENSITIVITY` / `METADATA`.
    pub const CLUSTER: Cluster<'static> = decl::FULL_CLUSTER
        .with_revision(2)
        .with_attrs(with!(
            required;
            AttributeId::SupportedFormats | AttributeId::CurrentConnections
        ))
        .with_cmds(with!(
            decl::CommandId::AllocatePushTransport
                | decl::CommandId::DeallocatePushTransport
                | decl::CommandId::ModifyPushTransport
                | decl::CommandId::SetTransportStatus
                | decl::CommandId::ManuallyTriggerTransport
                | decl::CommandId::FindTransport
        ));

    /// Construct a new handler.
    pub const fn new(
        dataver: Dataver,
        endpoint_id: EndptId,
        config: PushAvStreamConfig<'a>,
        hooks: H,
    ) -> Self {
        Self {
            dataver,
            endpoint_id,
            config,
            hooks,
            state: Mutex::new(RefCell::new(State::new())),
            next_id: Mutex::new(Cell::new(1)),
            removed_signal: Notification::new(),
        }
    }

    /// Wrap in the generic async adaptor for registration with a
    /// `rs-matter` `Node`.
    pub const fn adapt(self) -> decl::HandlerAsyncAdaptor<Self> {
        decl::HandlerAsyncAdaptor(self)
    }

    /// Endpoint this handler is mounted on.
    pub const fn endpoint_id(&self) -> EndptId {
        self.endpoint_id
    }

    /// Snapshot the current connections. Useful for diagnostics.
    pub fn connections(&self) -> Vec<PushConnection, NC> {
        self.state.lock(|cell| cell.borrow().connections.clone())
    }

    /// Report that connection `connection_id` began pushing a recording or
    /// a transmission, as triggered by `trigger_type` (`activation_reason`:
    /// why, if by `Command`): the `PushTransportBegin` event, through
    /// `emitter` (typically the `InteractionModel`). `cmaf_session_number`
    /// is that of the CMAF session uploaded.
    pub fn transport_started(
        &self,
        emitter: impl EventEmitter,
        connection_id: u16,
        trigger_type: TransportTriggerTypeEnum,
        activation_reason: Option<TriggerActivationReasonEnum>,
        cmaf_session_number: Option<u64>,
    ) -> Result<(), Error> {
        let container = self.container_type(connection_id)?;

        PushTransportBegin::emit_for(emitter, self.endpoint_id, |event| {
            event
                .connection_id(connection_id)?
                .trigger_type(trigger_type)?
                .activation_reason(activation_reason)?
                .container_type(Some(container))?
                .cmaf_session_number(cmaf_session_number)?
                .end()
        })?;

        Ok(())
    }

    /// Report that connection `connection_id` finished pushing a recording
    /// or a transmission: the `PushTransportEnd` event, through `emitter`
    /// (typically the `InteractionModel`). `cmaf_session_number` is that of
    /// the CMAF session uploaded.
    pub fn transport_stopped(
        &self,
        emitter: impl EventEmitter,
        connection_id: u16,
        cmaf_session_number: Option<u64>,
    ) -> Result<(), Error> {
        let container = self.container_type(connection_id)?;

        PushTransportEnd::emit_for(emitter, self.endpoint_id, |event| {
            event
                .connection_id(connection_id)?
                .container_type(Some(container))?
                .cmaf_session_number(cmaf_session_number)?
                .end()
        })?;

        Ok(())
    }

    /// The container connection `connection_id` pushes, as its transport
    /// options say.
    fn container_type(&self, connection_id: u16) -> Result<ContainerFormatEnum, Error> {
        self.state.lock(|cell| {
            let state = cell.borrow();
            let connection = state
                .connections
                .iter()
                .find(|c| c.connection_id == connection_id)
                .ok_or(ErrorCode::NotFound)?;

            TransportOptionsStruct::new(TLVElement::new(&connection.transport_options))
                .container_options()?
                .container_type()
        })
    }

    /// Drop the connections owned by `fab_idx` and queue them for
    /// [`PushAvStreamHooks::on_deallocate`], which is called from the
    /// handler's `run` task. Returns `true` if any connection was dropped.
    fn remove_fabric_connections(&self, fab_idx: FabricIndex) -> bool {
        let removed = self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            let state = &mut *state;

            let before = state.connections.len();

            for c in state
                .connections
                .iter()
                .filter(|c| c.fabric_index == fab_idx)
            {
                if state.removed.push(c.connection_id).is_err() {
                    warn!(
                        "push_av_stream: no room to queue the deallocation of connection {}",
                        c.connection_id
                    );
                }
            }

            state.connections.retain(|c| c.fabric_index != fab_idx);

            before != state.connections.len()
        });

        if removed {
            self.removed_signal.notify();
        }

        removed
    }

    /// Set the status of the `fab_idx` connections - all, or the one with
    /// `connection_id`; the ones it changed.
    fn set_status(
        &self,
        fab_idx: FabricIndex,
        connection_id: Option<u16>,
        status: TransportStatusEnum,
    ) -> Vec<u16, NC> {
        self.state.lock(|cell| {
            let mut changed = Vec::new();

            for c in cell.borrow_mut().connections.iter_mut().filter(|c| {
                c.fabric_index == fab_idx
                    && connection_id.is_none_or(|id| id == c.connection_id)
                    && c.status != status
            }) {
                c.status = status;
                let _ = changed.push(c.connection_id);
            }

            changed
        })
    }

    /// Call [`PushAvStreamHooks::on_deallocate`] for the connections dropped
    /// on fabric removal.
    async fn deallocate_removed_connections(&self) {
        while let Some(connection_id) = self.state.lock(|cell| cell.borrow_mut().removed.pop()) {
            if let Err(err) = self.hooks.on_deallocate(connection_id).await {
                warn!(
                    "push_av_stream: on_deallocate({}) failed after fabric removal: {:?}",
                    connection_id, err
                );
            }
        }
    }

    /// Allocate the next free `connection_id` (wraps to 1 on `u16`
    /// overflow).
    fn alloc_id(&self) -> u16 {
        self.next_id.lock(|cell| {
            let mut id = cell.get();
            if id == 0 {
                id = 1;
            }
            cell.set(id.wrapping_add(1).max(1));
            id
        })
    }

    /// Capture `options` (a request-side `TransportOptionsStruct`)
    /// into a fresh raw-TLV buffer.
    fn capture_options(
        &self,
        options: &TransportOptionsStruct<'_>,
    ) -> Result<Vec<u8, MAX_TRANSPORT_OPTIONS_BYTES>, Error> {
        let mut buf = [0u8; MAX_TRANSPORT_OPTIONS_BYTES];
        let mut wb = WriteBuf::new(&mut buf);
        options.to_tlv(&TLVTag::Anonymous, &mut wb)?;
        let bytes = wb.as_slice();
        let mut stored: Vec<u8, MAX_TRANSPORT_OPTIONS_BYTES> = Vec::new();
        stored
            .extend_from_slice(bytes)
            .map_err(|_| Error::from(ErrorCode::ResourceExhausted))?;
        Ok(stored)
    }
}

impl<'a, H, const NC: usize> ClusterAsyncHandler for PushAvStreamHandler<'a, H, NC>
where
    H: PushAvStreamHooks,
{
    const CLUSTER: Cluster<'static> = Self::CLUSTER;

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        if let LifecycleOp::FabricRemoval { fab_idx } = op {
            if self.remove_fabric_connections(fab_idx.get()) {
                ctx.notify_attr_changed(
                    self.endpoint_id,
                    Self::CLUSTER.id,
                    AttributeId::CurrentConnections as _,
                );
            }
        }

        Ok(())
    }

    async fn run(&self, _ctx: impl HandlerContext) -> Result<(), Error> {
        // Tell the hooks about the connections dropped on fabric removal. This
        // is done here because `lifecycle` is synchronous and the hooks are not.
        loop {
            self.removed_signal.wait().await;
            self.deallocate_removed_connections().await;
        }
    }

    // ----- Attributes -----

    async fn supported_formats<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            SupportedFormatStructArrayBuilder<P>,
            SupportedFormatStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(mut b) => {
                for f in self.config.supported_formats {
                    b = write_supported_format(b.push()?, f)?;
                }
                b.end()
            }
            ArrayAttributeRead::ReadOne(idx, b) => {
                let Some(f) = self.config.supported_formats.get(idx as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                write_supported_format(b, f)
            }
            ArrayAttributeRead::ReadNone(b) => b.end(),
        }
    }

    async fn current_connections<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            TransportConfigurationStructArrayBuilder<P>,
            TransportConfigurationStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        let attr = ctx.attr();
        let mut snapshot: Vec<PushConnection, NC> = Vec::new();
        self.state.lock(|cell| {
            for c in cell.borrow().connections.iter() {
                if !attr.fab_filter || c.fabric_index == attr.fab_idx {
                    let _ = snapshot.push(c.clone());
                }
            }
        });

        match builder {
            ArrayAttributeRead::ReadAll(mut b) => {
                for c in snapshot.iter() {
                    b = write_connection(b.push()?, c)?;
                }
                b.end()
            }
            ArrayAttributeRead::ReadOne(idx, b) => {
                let Some(c) = snapshot.get(idx as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                write_connection(b, c)
            }
            ArrayAttributeRead::ReadNone(b) => b.end(),
        }
    }

    // ----- Commands -----

    async fn handle_allocate_push_transport<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: AllocatePushTransportRequest<'_>,
        response: AllocatePushTransportResponseBuilder<P>,
    ) -> Result<P, Error> {
        let cmd = ctx.cmd();
        let fab_idx = cmd.fab_idx;

        let options = request.transport_options()?;

        // Spec: URL must be non-empty.
        let url = options.url()?;
        if url.is_empty() {
            return Err(ErrorCode::ConstraintError.into());
        }

        // Capacity.
        let full = self
            .state
            .lock(|cell| cell.borrow().connections.len() >= NC);
        if full {
            return Err(ErrorCode::ResourceExhausted.into());
        }

        // Capture raw options before crossing the await boundary so
        // we don't re-borrow the request after the hook returns.
        let stored_options = self.capture_options(&options)?;

        let connection_id = self.alloc_id();
        self.hooks
            .on_allocate(connection_id, fab_idx, &request)
            .await?;

        let pushed = self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state
                .connections
                .push(PushConnection {
                    connection_id,
                    fabric_index: fab_idx,
                    status: TransportStatusEnum::Inactive,
                    transport_options: stored_options,
                })
                .is_ok()
        });
        if !pushed {
            let _ = self.hooks.on_deallocate(connection_id).await;
            return Err(ErrorCode::ResourceExhausted.into());
        }
        ctx.notify_own_attr_changed(AttributeId::CurrentConnections as _);

        // Build the response: echo the just-stored connection.
        let snapshot = self
            .state
            .lock(|cell| cell.borrow().connections.last().cloned())
            .ok_or(Error::from(ErrorCode::Failure))?;
        let cfg = response.transport_configuration()?;
        write_connection(cfg, &snapshot)?.end()
    }

    async fn handle_deallocate_push_transport(
        &self,
        ctx: impl InvokeContext,
        request: DeallocatePushTransportRequest<'_>,
    ) -> Result<(), Error> {
        let cmd = ctx.cmd();
        let fab_idx = cmd.fab_idx;
        let connection_id = request.connection_id()?;

        let exists = self.state.lock(|cell| {
            cell.borrow()
                .connections
                .iter()
                .any(|c| c.connection_id == connection_id && c.fabric_index == fab_idx)
        });
        if !exists {
            return Err(ErrorCode::NotFound.into());
        }

        self.hooks.on_deallocate(connection_id).await?;

        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state
                .connections
                .retain(|c| !(c.connection_id == connection_id && c.fabric_index == fab_idx));
        });
        ctx.notify_own_attr_changed(AttributeId::CurrentConnections as _);
        Ok(())
    }

    async fn handle_modify_push_transport(
        &self,
        ctx: impl InvokeContext,
        request: ModifyPushTransportRequest<'_>,
    ) -> Result<(), Error> {
        let cmd = ctx.cmd();
        let fab_idx = cmd.fab_idx;
        let connection_id = request.connection_id()?;
        let options = request.transport_options()?;

        let url = options.url()?;
        if url.is_empty() {
            return Err(ErrorCode::ConstraintError.into());
        }

        let exists = self.state.lock(|cell| {
            cell.borrow()
                .connections
                .iter()
                .any(|c| c.connection_id == connection_id && c.fabric_index == fab_idx)
        });
        if !exists {
            return Err(ErrorCode::NotFound.into());
        }

        let stored_options = self.capture_options(&options)?;

        self.hooks.on_modify(connection_id, &request).await?;

        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if let Some(row) = state
                .connections
                .iter_mut()
                .find(|c| c.connection_id == connection_id && c.fabric_index == fab_idx)
            {
                row.transport_options = stored_options;
            }
        });
        ctx.notify_own_attr_changed(AttributeId::CurrentConnections as _);
        Ok(())
    }

    async fn handle_set_transport_status(
        &self,
        ctx: impl InvokeContext,
        request: SetTransportStatusRequest<'_>,
    ) -> Result<(), Error> {
        let cmd = ctx.cmd();
        let fab_idx = cmd.fab_idx;
        let connection_id = request.connection_id()?.into_option();
        let status = request.transport_status()?;

        // If a specific connection is targeted, validate existence + ownership.
        if let Some(id) = connection_id {
            let owned = self.state.lock(|cell| {
                cell.borrow()
                    .connections
                    .iter()
                    .any(|c| c.connection_id == id && c.fabric_index == fab_idx)
            });
            if !owned {
                return Err(ErrorCode::NotFound.into());
            }
        }

        self.hooks.on_set_status(connection_id, status).await?;

        let changed = self.set_status(fab_idx, connection_id, status);
        ctx.notify_own_attr_changed(AttributeId::CurrentConnections as _);

        // Made inactive, their pushes end.
        if status == TransportStatusEnum::Inactive {
            for id in changed {
                let cmaf_session = self.hooks.cmaf_session_number(id);
                if let Err(e) = self.transport_stopped(&ctx, id, cmaf_session) {
                    warn!("Failed to emit PushTransportEnd: {:?}", e);
                }
            }
        }

        Ok(())
    }

    async fn handle_manually_trigger_transport(
        &self,
        ctx: impl InvokeContext,
        request: ManuallyTriggerTransportRequest<'_>,
    ) -> Result<(), Error> {
        let cmd = ctx.cmd();
        let fab_idx = cmd.fab_idx;
        let connection_id = request.connection_id()?;
        let reason = request.activation_reason()?;
        let time_control = request.time_control()?;
        let user_defined = request.user_defined()?;

        let owned = self.state.lock(|cell| {
            cell.borrow()
                .connections
                .iter()
                .any(|c| c.connection_id == connection_id && c.fabric_index == fab_idx)
        });
        if !owned {
            return Err(ErrorCode::NotFound.into());
        }

        self.hooks
            .on_manually_trigger(
                connection_id,
                reason,
                time_control,
                user_defined.map(|s| s.0),
            )
            .await?;

        let cmaf_session = self.hooks.cmaf_session_number(connection_id);
        let started = self.transport_started(
            &ctx,
            connection_id,
            TransportTriggerTypeEnum::Command,
            Some(reason),
            cmaf_session,
        );
        if let Err(e) = started {
            warn!("Failed to emit PushTransportBegin: {:?}", e);
        }

        Ok(())
    }

    async fn handle_find_transport<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: FindTransportRequest<'_>,
        response: FindTransportResponseBuilder<P>,
    ) -> Result<P, Error> {
        let cmd = ctx.cmd();
        let fab_idx = cmd.fab_idx;
        let connection_id = request.connection_id()?.into_option();

        // Snapshot matching rows.
        let mut snapshot: Vec<PushConnection, NC> = Vec::new();
        self.state.lock(|cell| {
            for c in cell.borrow().connections.iter() {
                if c.fabric_index != fab_idx {
                    continue;
                }
                if let Some(id) = connection_id {
                    if c.connection_id != id {
                        continue;
                    }
                }
                let _ = snapshot.push(c.clone());
            }
        });

        // Spec: NOT_FOUND if no matching transport.
        if snapshot.is_empty() {
            return Err(ErrorCode::NotFound.into());
        }

        let mut arr = response.transport_configurations()?;
        for c in snapshot.iter() {
            arr = write_connection(arr.push()?, c)?;
        }
        arr.end()?.end()
    }
}

fn write_supported_format<P: TLVBuilderParent>(
    builder: SupportedFormatStructBuilder<P>,
    f: &SupportedFormat,
) -> Result<P, Error> {
    builder
        .container_format(f.container_format)?
        .ingest_method(f.ingest_method)?
        .end()
}

/// Replay a stored [`PushConnection`] into a
/// `TransportConfigurationStructBuilder<P>`.
///
/// Slot 0 (`connection_id`) and slot 1 (`transport_status`) are
/// written via the typed builder; slot 2 (`transport_options`,
/// optional) is sidestepped via `OptionalBuilder::none()` and
/// the stored raw TLV bytes are spliced in directly under
/// `Context(2)` — this lets us round-trip arbitrarily complex
/// `TransportOptionsStruct` values without reconstructing every
/// nested struct field-by-field.
fn write_connection<P: TLVBuilderParent>(
    builder: TransportConfigurationStructBuilder<P>,
    c: &PushConnection,
) -> Result<P, Error> {
    let b = builder
        .connection_id(c.connection_id)?
        .transport_status(c.status)?;
    // Skip the typed builder for slot 2 and write the raw stored TLV
    // directly under Context(2). The const-generic state advances to
    // 254 either way, preserving slot ordering for `fabric_index`.
    let mut b = b.transport_options()?.none();
    if !c.transport_options.is_empty() {
        let element = TLVElement::new(c.transport_options.as_slice());
        element.to_tlv(&TLVTag::Context(2), b.writer())?;
    }
    b.fabric_index(Some(c.fabric_index))?.end()
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use super::*;

    /// Records the connections the handler deallocates.
    struct RecordingHooks {
        deallocated: RefCell<Vec<u16, 4>>,
    }

    impl PushAvStreamHooks for RecordingHooks {
        async fn on_allocate(
            &self,
            _connection_id: u16,
            _fabric_index: FabricIndex,
            _request: &AllocatePushTransportRequest<'_>,
        ) -> Result<(), PushAvError> {
            Ok(())
        }

        async fn on_deallocate(&self, connection_id: u16) -> Result<(), PushAvError> {
            unwrap!(self.deallocated.borrow_mut().push(connection_id));
            Ok(())
        }
    }

    fn connection(connection_id: u16, fabric_index: FabricIndex) -> PushConnection {
        PushConnection {
            connection_id,
            fabric_index,
            status: TransportStatusEnum::Active,
            transport_options: Vec::new(),
        }
    }

    #[test]
    fn fabric_removal_drops_and_deallocates_its_connections() {
        let handler = PushAvStreamHandler::<_, 4>::new(
            Dataver::new(1),
            1,
            PushAvStreamConfig {
                supported_formats: &[],
            },
            RecordingHooks {
                deallocated: RefCell::new(Vec::new()),
            },
        );

        handler.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            for c in [connection(1, 1), connection(2, 2), connection(3, 1)] {
                unwrap!(state.connections.push(c));
            }
        });

        assert!(handler.remove_fabric_connections(1));
        assert!(!handler.remove_fabric_connections(1));

        let remaining: std::vec::Vec<_> = handler
            .connections()
            .iter()
            .map(|c| c.connection_id)
            .collect();
        assert_eq!(remaining, [2]);

        futures_lite::future::block_on(handler.deallocate_removed_connections());

        let mut deallocated = handler.hooks.deallocated.borrow().clone();
        deallocated.sort_unstable();
        assert_eq!(deallocated.as_slice(), [1, 3]);
    }

    #[test]
    fn only_status_changes_are_reported() {
        let handler = PushAvStreamHandler::<_, 4>::new(
            Dataver::new(1),
            1,
            PushAvStreamConfig {
                supported_formats: &[],
            },
            RecordingHooks {
                deallocated: RefCell::new(Vec::new()),
            },
        );

        handler.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            for c in [connection(1, 1), connection(2, 2), connection(3, 1)] {
                unwrap!(state.connections.push(c));
            }
        });

        let inactive = TransportStatusEnum::Inactive;
        assert_eq!(handler.set_status(1, Some(3), inactive).as_slice(), [3]);
        // Already inactive: not again.
        assert_eq!(handler.set_status(1, None, inactive).as_slice(), [1]);
        assert!(handler.set_status(1, None, inactive).is_empty());
        assert_eq!(
            handler
                .set_status(1, Some(1), TransportStatusEnum::Active)
                .as_slice(),
            [1]
        );
    }

    #[test]
    fn reported_pushes_are_events_of_their_container() {
        use crate::dm::clusters::app::test_util::RecordingEvents;
        use crate::tlv::TLVWrite;

        let handler = PushAvStreamHandler::<_, 4>::new(
            Dataver::new(1),
            1,
            PushAvStreamConfig {
                supported_formats: &[],
            },
            RecordingHooks {
                deallocated: RefCell::new(Vec::new()),
            },
        );

        // Transport options with a CMAF container.
        let mut buf = [0; 16];
        let mut wb = WriteBuf::new(&mut buf);
        unwrap!(wb.start_struct(&TLVTag::Anonymous));
        unwrap!(wb.start_struct(&TLVTag::Context(7)));
        unwrap!(wb.u8(&TLVTag::Context(0), ContainerFormatEnum::CMAF as u8));
        unwrap!(wb.end_container());
        unwrap!(wb.end_container());
        let mut c = connection(1, 1);
        unwrap!(c.transport_options.extend_from_slice(wb.as_slice()));
        handler
            .state
            .lock(|cell| unwrap!(cell.borrow_mut().connections.push(c)));

        let events = RecordingEvents::default();
        unwrap!(handler.transport_started(
            &events,
            1,
            TransportTriggerTypeEnum::Motion,
            None,
            Some(42)
        ));
        unwrap!(handler.transport_stopped(&events, 1, Some(42)));
        assert!(handler.transport_stopped(&events, 2, None).is_err());

        events.with_events(|emitted| {
            assert_eq!(emitted.len(), 2);

            let begin = unwrap!(emitted[0].data.structure());
            assert_eq!(
                emitted[0].path.event,
                Some(EventId::PushTransportBegin as u32)
            );
            assert_eq!(unwrap!(unwrap!(begin.ctx(0)).u16()), 1);
            assert_eq!(
                unwrap!(unwrap!(begin.ctx(1)).u8()),
                TransportTriggerTypeEnum::Motion as u8
            );
            assert!(begin.ctx(2).is_err());
            assert_eq!(
                unwrap!(unwrap!(begin.ctx(3)).u8()),
                ContainerFormatEnum::CMAF as u8
            );
            assert_eq!(unwrap!(unwrap!(begin.ctx(4)).u64()), 42);

            let end = unwrap!(emitted[1].data.structure());
            assert_eq!(
                emitted[1].path.event,
                Some(EventId::PushTransportEnd as u32)
            );
            assert_eq!(unwrap!(unwrap!(end.ctx(0)).u16()), 1);
            assert_eq!(unwrap!(unwrap!(end.ctx(2)).u64()), 42);
        });
    }
}
