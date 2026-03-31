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

use core::future::{ready, Future};
use core::num::NonZeroU8;

use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::fabric::FabricPersist;
use crate::im::IMStatusCode;
use crate::tlv::{Nullable, TLVBuilderParent};
use crate::utils::future::delayed_ready;
use crate::{with, MatterState};

pub use crate::dm::clusters::decl::groups::*;

/// The handler for the Groups Matter cluster.
///
/// This handler manages per-endpoint group membership in the node-wide Group Table.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GroupsHandler {
    dataver: Dataver,
}

impl GroupsHandler {
    /// Creates a new instance of the `GroupsHandler`.
    ///
    /// # Arguments
    /// * `dataver` - The data version tracker
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `AsyncHandler` trait
    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }

    /// Check if the fabric has security material (a group key map entry) for the given group ID.
    fn has_group_material(
        state: &mut MatterState,
        fab_idx: NonZeroU8,
        group_id: u16,
    ) -> Result<bool, Error> {
        let fabric = state.fabrics.get(fab_idx).ok_or(ErrorCode::NotFound)?;

        let result = fabric
            .groups()
            .key_map_iter()
            .any(|entry| entry.group_id == group_id);

        Ok(result)
    }
}

impl ClusterAsyncHandler for GroupsHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_features(Feature::GROUP_NAMES.bits())
        .with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn name_support(
        &self,
        _ctx: impl ReadContext,
    ) -> impl Future<Output = Result<NameSupportBitmap, Error>> {
        // Bit 7 (GroupNames) = 1 when GN feature is supported
        ready(Ok(NameSupportBitmap::GROUP_NAMES))
    }

    async fn handle_add_group<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: AddGroupRequest<'_>,
        response: AddGroupResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor()?.fab_idx).ok_or(ErrorCode::Invalid)?;

        let group_id = request.group_id()?;
        let group_name: &str = request.group_name()?;

        // Validate constraints
        if (group_id == 0) || (group_name.len() > 16) {
            return response
                .status(IMStatusCode::ConstraintError as u8)?
                .group_id(group_id)?
                .end();
        }

        let mut persist = FabricPersist::new(ctx.kv().await);

        let status = ctx.exchange().with_state(|state| {
            // Check if group security material is available
            if !Self::has_group_material(state, fab_idx, group_id)? {
                return Ok(IMStatusCode::UnsupportedAccess);
            }

            // Add or update group membership
            let endpoint_id = ctx.cmd().endpoint_id;
            let fabric = state.fabrics.fabric_mut(fab_idx)?;

            match fabric.groups_mut().add(endpoint_id, group_id, group_name) {
                Ok(_) => {
                    persist.store(fabric)?;
                    ctx.exchange().matter().notify_groups_changed();

                    Ok(IMStatusCode::Success)
                }
                Err(e) if e.code() == ErrorCode::ResourceExhausted => {
                    Ok(IMStatusCode::ResourceExhausted)
                }
                Err(e) => Err(e)?,
            }
        })?;

        persist.run().await?;

        response.status(status as u8)?.group_id(group_id)?.end()
    }

    fn handle_view_group<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: ViewGroupRequest<'_>,
        response: ViewGroupResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        delayed_ready(move || {
            let fab_idx =
                NonZeroU8::new(ctx.exchange().accessor()?.fab_idx).ok_or(ErrorCode::Invalid)?;

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
                let fabric = state.fabrics.get(fab_idx).ok_or(ErrorCode::NotFound)?;

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
        })
    }

    fn handle_get_group_membership<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: GetGroupMembershipRequest<'_>,
        response: GetGroupMembershipResponseBuilder<P>,
    ) -> impl Future<Output = Result<P, Error>> {
        delayed_ready(move || {
            let fab_idx =
                NonZeroU8::new(ctx.exchange().accessor()?.fab_idx).ok_or(ErrorCode::Invalid)?;

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
        })
    }

    async fn handle_remove_group<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: RemoveGroupRequest<'_>,
        response: RemoveGroupResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor()?.fab_idx).ok_or(ErrorCode::Invalid)?;
        let group_id = request.group_id()?;
        let endpoint_id = ctx.cmd().endpoint_id;

        let mut persist = FabricPersist::new(ctx.kv().await);

        let status = ctx.exchange().with_state(|state| {
            // Step 1: Validate constraints
            if group_id == 0 {
                return Ok(IMStatusCode::ConstraintError);
            }

            let fabric = state.fabrics.fabric_mut(fab_idx)?;

            // Steps 2-3: Remove membership
            if fabric.groups_mut().remove(endpoint_id, Some(group_id)) {
                persist.store(fabric)?;
                ctx.exchange().matter().notify_groups_changed();

                Ok(IMStatusCode::Success)
            } else {
                Ok(IMStatusCode::NotFound)
            }
        })?;

        persist.run().await?;

        response.status(status as u8)?.group_id(group_id)?.end()
    }

    async fn handle_remove_all_groups(&self, ctx: impl InvokeContext) -> Result<(), Error> {
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor()?.fab_idx).ok_or(ErrorCode::Invalid)?;
        let endpoint_id = ctx.cmd().endpoint_id;

        let mut persist = FabricPersist::new(ctx.kv().await);

        ctx.exchange().with_state(|state| {
            let fabric = state.fabrics.fabric_mut(fab_idx)?;

            fabric.groups_mut().remove(endpoint_id, None);

            persist.store(fabric)?;
            ctx.exchange().matter().notify_groups_changed();

            Ok(())
        })?;

        persist.run().await?;

        Ok(())
    }

    fn handle_add_group_if_identifying(
        &self,
        _ctx: impl InvokeContext,
        _request: AddGroupIfIdentifyingRequest<'_>,
    ) -> impl Future<Output = Result<(), Error>> {
        // TODO: implement with Identity Cluster
        delayed_ready(move || todo!())
    }
}
