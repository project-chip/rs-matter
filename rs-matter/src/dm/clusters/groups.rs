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

//! This module contains the implementation of the Groups cluster and its handler.

use core::num::NonZeroU8;

use crate::dm::clusters::acl::notify_auxiliary_access_updated;
use crate::dm::clusters::identify::IdentifyStatus;
use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::fabric::FabricPersist;
use crate::im::encoding::IMStatusCode;
use crate::tlv::{Nullable, TLVBuilderParent};
use crate::{with, MatterState};

pub use crate::dm::clusters::decl::groups::*;

/// The handler for the Groups Matter cluster.
///
/// This handler manages per-endpoint group membership in the node-wide Group Table.
#[derive(Clone)]
pub struct GroupsHandler<'a> {
    dataver: Dataver,
    /// Identification state of the endpoint this instance serves.
    /// `AddGroupIfIdentifying` is a successful no-op when absent — an
    /// endpoint without an Identify coupling is never identifying.
    identify: Option<&'a dyn IdentifyStatus>,
}

impl<'a> GroupsHandler<'a> {
    /// Creates a new instance of the `GroupsHandler`.
    ///
    /// # Arguments
    /// * `dataver` - The data version tracker
    pub const fn new(dataver: Dataver) -> Self {
        Self {
            dataver,
            identify: None,
        }
    }

    /// Creates a new instance of the `GroupsHandler` coupled to the
    /// Identify cluster handler serving the same endpoint, so that
    /// `AddGroupIfIdentifying` can take effect while the endpoint is
    /// identifying.
    ///
    /// # Arguments
    /// * `dataver` - The data version tracker
    /// * `identify` - The Identify handler (or any [`IdentifyStatus`] impl)
    ///   of the endpoint this `GroupsHandler` instance is matched to
    pub const fn new_with_identify(dataver: Dataver, identify: &'a dyn IdentifyStatus) -> Self {
        Self {
            dataver,
            identify: Some(identify),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    /// Check if the fabric has security material (a group key map entry) for the given group ID.
    fn has_group_material(
        state: &mut MatterState,
        fab_idx: NonZeroU8,
        group_id: u16,
    ) -> Result<bool, Error> {
        let fabric = state.fabrics.fabric(fab_idx)?;

        let result = fabric
            .groups()
            .key_map_iter()
            .any(|entry| entry.group_id == group_id);

        Ok(result)
    }
}

impl GroupsHandler<'_> {
    /// Whether the given (aux-flagged) group's auxiliary ACL coverage of
    /// `endpoint_id` would change by adding/removing that endpoint - i.e.
    /// whether an `AuxiliaryAccessUpdated` notification is due.
    ///
    /// `group_id` of `None` means "any group" (the `RemoveAllGroups` case).
    fn aux_coverage_touched(
        state: &crate::MatterState,
        fab_idx: core::num::NonZeroU8,
        endpoint_id: u16,
        group_id: Option<u16>,
        member: bool,
    ) -> bool {
        let Some(fabric) = state.fabrics.get(fab_idx) else {
            return false;
        };

        fabric.groups().iter().any(|entry| {
            group_id.is_none_or(|id| id == entry.group_id)
                && entry.has_aux_acl()
                && entry.endpoints.contains(&endpoint_id) == member
        })
    }

    /// The node ID of the invoking peer (for the `AuxiliaryAccessUpdated`
    /// event's `AdminNodeID` field).
    fn peer_node_id(ctx: &impl InvokeContext) -> Option<u64> {
        ctx.exchange()
            .with_state(|state| {
                Ok::<_, Error>(
                    ctx.exchange()
                        .id()
                        .session(&mut state.sessions)
                        .get_peer_node_id(),
                )
            })
            .unwrap_or(None)
    }

    /// Emit the auxiliary-ACL change notification, best-effort (the group
    /// mutation has already been committed).
    fn notify_aux(ctx: &impl InvokeContext, fab_idx: core::num::NonZeroU8) {
        let peer_node_id = Self::peer_node_id(ctx);

        if let Err(e) = notify_auxiliary_access_updated(ctx, peer_node_id, fab_idx) {
            warn!("Failed to notify the auxiliary ACL change: {:?}", e);
        }
    }

    /// Add the invoked endpoint to `group_id` for the invoking fabric —
    /// the shared core of `AddGroup` and `AddGroupIfIdentifying` (which
    /// differ only in how the outcome is reported back).
    ///
    /// Returns the IM status of the operation: `UnsupportedAccess` when
    /// the fabric has no group key material for the group,
    /// `ResourceExhausted` when the group table is full, `Success`
    /// otherwise. Emits the auxiliary-ACL change notification when due.
    fn add_group(
        &self,
        ctx: &impl InvokeContext,
        fab_idx: NonZeroU8,
        group_id: u16,
        group_name: &str,
    ) -> Result<IMStatusCode, Error> {
        let mut persist = FabricPersist::new(ctx.kv());

        let status = ctx.exchange().with_state(|state| {
            // Check if group security material is available
            if !Self::has_group_material(state, fab_idx, group_id)? {
                return Ok((IMStatusCode::UnsupportedAccess, false));
            }

            // Add or update group membership
            let endpoint_id = ctx.cmd().endpoint_id;

            // Joining an endpoint to a group with auxiliary ACL generation
            // enabled (via the Groupcast cluster) extends the synthesized
            // `AuxiliaryACL` coverage - which must be notified
            let aux_touched =
                Self::aux_coverage_touched(state, fab_idx, endpoint_id, Some(group_id), false);

            let fabric = state.fabrics.fabric_mut(fab_idx)?;

            match fabric.groups_mut().add(endpoint_id, group_id, group_name) {
                Ok(_) => {
                    // NOTE: Not sure this is a spec-compliant behavor:
                    // If the failsafe is armed for our fabric, we'll NOT persist the group changes until commissioning is complete.
                    // And we'll LOSE those changes if the failsafe times out before commissioning completes.
                    if !state.failsafe.is_armed_for(fab_idx.get()) {
                        persist.store(fabric)?;
                    }

                    ctx.exchange().matter().transport().notify_groups_changed();

                    Ok((IMStatusCode::Success, aux_touched))
                }
                Err(e) if e.code() == ErrorCode::ResourceExhausted => {
                    Ok((IMStatusCode::ResourceExhausted, false))
                }
                Err(e) => Err(e)?,
            }
        })?;

        persist.run()?;

        let (status, aux_touched) = status;
        if aux_touched && matches!(status, IMStatusCode::Success) {
            Self::notify_aux(ctx, fab_idx);
        }

        Ok(status)
    }
}

impl ClusterHandler for GroupsHandler<'_> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_features(Feature::GROUP_NAMES.bits())
        .with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn name_support(&self, _ctx: impl ReadContext) -> Result<NameSupportBitmap, Error> {
        // Bit 7 (GroupNames) = 1 when GN feature is supported
        Ok(NameSupportBitmap::GROUP_NAMES)
    }

    fn handle_add_group<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: AddGroupRequest<'_>,
        response: AddGroupResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = ctx.accessor()?.fab_idx()?;
        let group_id = request.group_id()?;
        let group_name: &str = request.group_name()?;

        // Validate constraints
        if (group_id == 0) || (group_name.len() > 16) {
            return response
                .status(IMStatusCode::ConstraintError as u8)?
                .group_id(group_id)?
                .end();
        }

        let status = self.add_group(&ctx, fab_idx, group_id, group_name)?;

        response.status(status as u8)?.group_id(group_id)?.end()
    }

    fn handle_view_group<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: ViewGroupRequest<'_>,
        response: ViewGroupResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = ctx.accessor()?.fab_idx()?;
        let group_id = request.group_id()?;

        // Validate constraints
        if group_id == 0 {
            return response
                .status(IMStatusCode::ConstraintError as u8)?
                .group_id(group_id)?
                .group_name("")?
                .end();
        }

        ctx.exchange().with_state(|state| {
            // Check membership for group_id
            let fabric = state.fabrics.fabric(fab_idx)?;

            let endpoint_id = ctx.cmd().endpoint_id;
            if let Some(entry) = fabric.groups().get(group_id) {
                if entry.endpoints.contains(&endpoint_id) {
                    return response
                        .status(IMStatusCode::Success as u8)?
                        .group_id(group_id)?
                        .group_name(entry.group_name.as_str())?
                        .end();
                }
            }

            response
                .status(IMStatusCode::NotFound as u8)?
                .group_id(group_id)?
                .group_name("")?
                .end()
        })
    }

    fn handle_get_group_membership<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: GetGroupMembershipRequest<'_>,
        response: GetGroupMembershipResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = ctx.accessor()?.fab_idx()?;
        let request_group_list = request.group_list()?;

        ctx.exchange().with_state(|state| {
            let fabric = state.fabrics.fabric(fab_idx)?;

            // Capacity is nullable - return null to indicate unknown capacity
            let capacity = Nullable::<u8>::none();

            let endpoint_id = ctx.cmd().endpoint_id;
            let mut group_list = response.capacity(capacity)?.group_list()?;

            if request_group_list.iter().count() == 0 {
                // Return all groups this endpoint is a member of
                for entry in fabric.groups().iter() {
                    if entry.endpoints.contains(&endpoint_id) {
                        group_list = group_list.push(&entry.group_id)?;
                    }
                }
            } else {
                // Return intersection: only requested groups that this endpoint is a member of
                for gid in request_group_list.into_iter().flatten() {
                    if let Some(entry) = fabric.groups().get(gid) {
                        if entry.endpoints.contains(&endpoint_id) {
                            group_list = group_list.push(&gid)?;
                        }
                    }
                }
            }

            group_list.end()?.end()
        })
    }

    fn handle_remove_group<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: RemoveGroupRequest<'_>,
        response: RemoveGroupResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = ctx.accessor()?.fab_idx()?;
        let group_id = request.group_id()?;
        let endpoint_id = ctx.cmd().endpoint_id;

        let mut persist = FabricPersist::new(ctx.kv());

        let status = ctx.exchange().with_state(|state| {
            // Step 1: Validate constraints
            if group_id == 0 {
                return Ok((IMStatusCode::ConstraintError, false));
            }

            // Removing an endpoint from a group with auxiliary ACL
            // generation enabled shrinks the synthesized `AuxiliaryACL`
            // coverage - which must be notified
            let aux_touched =
                Self::aux_coverage_touched(state, fab_idx, endpoint_id, Some(group_id), true);

            let fabric = state.fabrics.fabric_mut(fab_idx)?;

            // Steps 2-3: Remove membership
            if fabric.groups_mut().remove(endpoint_id, Some(group_id)) {
                // NOTE: Not sure this is a spec-compliant behavor:
                // If the failsafe is armed for our fabric, we'll NOT persist the group changes until commissioning is complete.
                // And we'll LOSE those changes if the failsafe times out before commissioning completes.
                if !state.failsafe.is_armed_for(fab_idx.get()) {
                    persist.store(fabric)?;
                }

                ctx.exchange().matter().transport().notify_groups_changed();

                Ok((IMStatusCode::Success, aux_touched))
            } else {
                Ok((IMStatusCode::NotFound, false))
            }
        })?;

        persist.run()?;

        let (status, aux_touched) = status;
        if aux_touched && matches!(status, IMStatusCode::Success) {
            Self::notify_aux(&ctx, fab_idx);
        }

        response.status(status as u8)?.group_id(group_id)?.end()
    }

    fn handle_remove_all_groups(&self, ctx: impl InvokeContext) -> Result<(), Error> {
        let fab_idx = ctx.accessor()?.fab_idx()?;
        let endpoint_id = ctx.cmd().endpoint_id;

        let mut persist = FabricPersist::new(ctx.kv());

        let aux_touched = ctx.exchange().with_state(|state| {
            let aux_touched = Self::aux_coverage_touched(state, fab_idx, endpoint_id, None, true);

            let fabric = state.fabrics.fabric_mut(fab_idx)?;

            fabric.groups_mut().remove(endpoint_id, None);

            // NOTE: Not sure this is a spec-compliant behavor:
            // If the failsafe is armed for our fabric, we'll NOT persist the group changes until commissioning is complete.
            // And we'll LOSE those changes if the failsafe times out before commissioning completes.
            if !state.failsafe.is_armed_for(fab_idx.get()) {
                persist.store(fabric)?;
            }

            ctx.exchange().matter().transport().notify_groups_changed();

            Ok(aux_touched)
        })?;

        persist.run()?;

        if aux_touched {
            Self::notify_aux(&ctx, fab_idx);
        }

        Ok(())
    }

    fn handle_add_group_if_identifying(
        &self,
        ctx: impl InvokeContext,
        request: AddGroupIfIdentifyingRequest<'_>,
    ) -> Result<(), Error> {
        // Per App Cluster spec, the command is accepted (SUCCESS) but has
        // no effect unless the endpoint is currently identifying
        if !self
            .identify
            .is_some_and(|identify| identify.is_identifying())
        {
            return Ok(());
        }

        let fab_idx = ctx.accessor()?.fab_idx()?;
        let group_id = request.group_id()?;
        let group_name: &str = request.group_name()?;

        // Validate constraints
        if (group_id == 0) || (group_name.len() > 16) {
            return Err(ErrorCode::ConstraintError.into());
        }

        // Unlike `AddGroup`, this command responds with a plain status
        // rather than an `AddGroupResponse` - so a non-success outcome
        // is reported by erroring out
        let status = self.add_group(&ctx, fab_idx, group_id, group_name)?;
        if let Some(code) = status.to_error_code() {
            return Err(code.into());
        }

        Ok(())
    }
}
