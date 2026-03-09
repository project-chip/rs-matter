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

use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::group_keys::GroupMembershipStore;
use crate::im::IMStatusCode;
use crate::tlv::{Nullable, TLVBuilderParent};
use crate::with;

pub use crate::dm::clusters::decl::groups::*;

/// The handler for the Groups Matter cluster.
///
/// This handler manages per-endpoint group membership in the node-wide Group Table.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GroupsHandler<'a> {
    dataver: Dataver,
    group_store: &'a dyn GroupMembershipStore,
}

impl<'a> GroupsHandler<'a> {
    /// Creates a new instance of the `GroupsHandler`.
    ///
    /// # Arguments
    /// * `dataver` - The data version tracker
    /// * `group_store` - Reference to the group membership store implementation
    pub const fn new(dataver: Dataver, group_store: &'a dyn GroupMembershipStore) -> Self {
        Self {
            dataver,
            group_store,
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    /// Check if the fabric has security material (a group key map entry) for the given group ID.
    fn has_group_material(&self, fab_idx: NonZeroU8, group_id: u16) -> bool {
        self.group_store.has_group_key_map_entry(fab_idx, group_id)
    }
}

impl<'a> ClusterHandler for GroupsHandler<'a> {
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
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor(None)?.fab_idx).ok_or(ErrorCode::Invalid)?;

        let group_id = request.group_id()?;
        let group_name: &str = request.group_name()?;

        // Validate constraints
        if (group_id == 0) || (group_name.len() > 16) {
            return response
                .status(IMStatusCode::ConstraintError as u8)?
                .group_id(group_id)?
                .end();
        }

        // Check if group security material is available
        if !self.has_group_material(fab_idx, group_id) {
            return response
                .status(IMStatusCode::UnsupportedAccess as u8)?
                .group_id(group_id)?
                .end();
        }

        // Add or update group membership
        let endpoint_id = ctx.cmd().endpoint_id;
        match self
            .group_store
            .group_add(fab_idx, group_id, endpoint_id, group_name)
        {
            Ok(_) => {
                ctx.exchange().matter().notify_groups_changed();
                response
                    .status(IMStatusCode::Success as u8)?
                    .group_id(group_id)?
                    .end()
            }
            Err(e) if e.code() == ErrorCode::ResourceExhausted => response
                .status(IMStatusCode::ResourceExhausted as u8)?
                .group_id(group_id)?
                .end(),
            Err(e) => Err(e),
        }
    }

    fn handle_view_group<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: ViewGroupRequest<'_>,
        response: ViewGroupResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor(None)?.fab_idx).ok_or(ErrorCode::Invalid)?;

        let group_id = request.group_id()?;

        // Validate constraints
        if group_id == 0 {
            return response
                .status(IMStatusCode::ConstraintError as u8)?
                .group_id(group_id)?
                .group_name("")?
                .end();
        }

        // Check membership for group_id
        let endpoint_id = ctx.cmd().endpoint_id;
        if self.group_store.has_group(fab_idx, group_id, endpoint_id) {
            let name = self
                .group_store
                .group_name(fab_idx, group_id)?
                .unwrap_or_default();
            response
                .status(IMStatusCode::Success as u8)?
                .group_id(group_id)?
                .group_name(name.as_str())?
                .end()
        } else {
            response
                .status(IMStatusCode::NotFound as u8)?
                .group_id(group_id)?
                .group_name("")?
                .end()
        }
    }

    fn handle_get_group_membership<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: GetGroupMembershipRequest<'_>,
        response: GetGroupMembershipResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor(None)?.fab_idx).ok_or(ErrorCode::Invalid)?;

        let request_group_list = request.group_list()?;

        // Capacity is nullable - return null to indicate unknown capacity
        let capacity = Nullable::<u8>::none();

        let endpoint_id = ctx.cmd().endpoint_id;
        let mut group_list = response.capacity(capacity)?.group_list()?;

        if request_group_list.iter().count() == 0 {
            // Return all groups this endpoint is a member of
            // Collect group IDs for this endpoint
            let mut group_ids: heapless::Vec<u16, 24> = heapless::Vec::new();
            self.group_store
                .for_each_group(Some(fab_idx), &mut |_fab_idx, entry| {
                    if entry.endpoint_id == endpoint_id {
                        let _ = group_ids.push(entry.group_id);
                    }
                });
            for gid in &group_ids {
                group_list = group_list.push(gid)?;
            }
        } else {
            // Return intersection: only requested groups that this endpoint is a member of
            for gid in request_group_list.into_iter().flatten() {
                if self.group_store.has_group(fab_idx, gid, endpoint_id) {
                    group_list = group_list.push(&gid)?;
                }
            }
        }

        group_list.end()?.end()
    }

    fn handle_remove_group<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: RemoveGroupRequest<'_>,
        response: RemoveGroupResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor(None)?.fab_idx).ok_or(ErrorCode::Invalid)?;

        let group_id = request.group_id()?;

        // Step 1: Validate constraints
        if group_id == 0 {
            return response
                .status(IMStatusCode::ConstraintError as u8)?
                .group_id(group_id)?
                .end();
        }

        // Steps 2-3: Remove membership
        let endpoint_id = ctx.cmd().endpoint_id;
        let removed = self
            .group_store
            .group_remove(fab_idx, group_id, endpoint_id)?;

        if removed {
            ctx.exchange().matter().notify_groups_changed();
            response
                .status(IMStatusCode::Success as u8)?
                .group_id(group_id)?
                .end()
        } else {
            response
                .status(IMStatusCode::NotFound as u8)?
                .group_id(group_id)?
                .end()
        }
    }

    fn handle_remove_all_groups(&self, ctx: impl InvokeContext) -> Result<(), Error> {
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor(None)?.fab_idx).ok_or(ErrorCode::Invalid)?;

        let endpoint_id = ctx.cmd().endpoint_id;
        self.group_store
            .group_remove_all_for_endpoint(fab_idx, endpoint_id)?;

        ctx.exchange().matter().notify_groups_changed();

        Ok(())
    }

    fn handle_add_group_if_identifying(
        &self,
        _ctx: impl InvokeContext,
        _request: AddGroupIfIdentifyingRequest<'_>,
    ) -> Result<(), Error> {
        // TODO: implement with Identity Cluster
        todo!()
    }
}
