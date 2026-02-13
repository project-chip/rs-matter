/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
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

//! This module contains the implementation of the Group Key Management cluster and its handler.

use core::num::NonZeroU8;

use crate::dm::{
    ArrayAttributeRead, ArrayAttributeWrite, Cluster, Dataver, InvokeContext, ReadContext,
    WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::fabric::GrpKeyMapEntry;
use crate::group_keys::GrpKeySetEntry;
use crate::tlv::{Nullable, Octets, TLVArray, TLVBuilderParent};
use crate::with;

pub use crate::dm::clusters::decl::group_key_management::*;

/// The system implementation of a handler for the Group Key Management Matter cluster.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GrpKeyMgmtHandler {
    dataver: Dataver,
}

impl GrpKeyMgmtHandler {
    /// Creates a new instance of the `GrpKeyMgmtHandler` with the given `Dataver`.
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for GrpKeyMgmtHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn group_key_map<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<GroupKeyMapStructArrayBuilder<P>, GroupKeyMapStructBuilder<P>>,
    ) -> Result<P, Error> {
        let fabric_mgr = ctx.exchange().matter().fabric_mgr.borrow();
        let attr = ctx.attr();

        let mut entries = fabric_mgr
            .iter()
            .filter(|fabric| !attr.fab_filter || fabric.fab_idx().get() == attr.fab_idx)
            .flat_map(|fabric| {
                fabric
                    .group_key_map_iter()
                    .map(move |entry| (fabric.fab_idx(), entry))
            });

        match builder {
            ArrayAttributeRead::ReadAll(mut builder) => {
                for (fab_idx, entry) in entries {
                    builder = builder
                        .push()?
                        .group_id(entry.group_id)?
                        .group_key_set_id(entry.group_key_set_id)?
                        .fabric_index(Some(fab_idx.get()))?
                        .end()?;
                }
                builder.end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let Some((fab_idx, entry)) = entries.nth(index as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                builder
                    .group_id(entry.group_id)?
                    .group_key_set_id(entry.group_key_set_id)?
                    .fabric_index(Some(fab_idx.get()))?
                    .end()
            }
            ArrayAttributeRead::ReadNone(builder) => builder.end(),
        }
    }

    fn group_table<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            GroupInfoMapStructArrayBuilder<P>,
            GroupInfoMapStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        let fabric_mgr = ctx.exchange().matter().fabric_mgr.borrow();
        let attr = ctx.attr();

        // Build a deduplicated list of (fab_idx, group_id) -> (endpoints, group_name)
        // by iterating over all group entries across all fabrics
        struct GroupInfo {
            group_id: u16,
            fab_idx: u8,
            endpoints: heapless::Vec<u16, 8>,
            group_name: heapless::String<16>,
        }

        let mut groups: heapless::Vec<GroupInfo, 24> = heapless::Vec::new();

        for fabric in fabric_mgr.iter() {
            if attr.fab_filter && fabric.fab_idx().get() != attr.fab_idx {
                continue;
            }
            for entry in fabric.group_iter() {
                // Try to find an existing group with the same (fab_idx, group_id)
                if let Some(existing) = groups
                    .iter_mut()
                    .find(|g| g.fab_idx == fabric.fab_idx().get() && g.group_id == entry.group_id)
                {
                    let _ = existing.endpoints.push(entry.endpoint_id);
                } else {
                    let mut info = GroupInfo {
                        group_id: entry.group_id,
                        fab_idx: fabric.fab_idx().get(),
                        endpoints: heapless::Vec::new(),
                        group_name: heapless::String::new(),
                    };
                    let _ = info.endpoints.push(entry.endpoint_id);
                    let _ = info.group_name.push_str(&entry.group_name);
                    let _ = groups.push(info);
                }
            }
        }

        match builder {
            ArrayAttributeRead::ReadAll(mut builder) => {
                for info in &groups {
                    let mut endpoints_builder =
                        builder.push()?.group_id(info.group_id)?.endpoints()?;
                    for &ep in &info.endpoints {
                        endpoints_builder = endpoints_builder.push(&ep)?;
                    }
                    builder = endpoints_builder
                        .end()?
                        .group_name(Some(info.group_name.as_str()))?
                        .fabric_index(Some(info.fab_idx))?
                        .end()?;
                }
                builder.end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let Some(info) = groups.get(index as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                let mut endpoints_builder = builder.group_id(info.group_id)?.endpoints()?;
                for &ep in &info.endpoints {
                    endpoints_builder = endpoints_builder.push(&ep)?;
                }
                endpoints_builder
                    .end()?
                    .group_name(Some(info.group_name.as_str()))?
                    .fabric_index(Some(info.fab_idx))?
                    .end()
            }
            ArrayAttributeRead::ReadNone(builder) => builder.end(),
        }
    }

    fn max_groups_per_fabric(&self, ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(ctx
            .exchange()
            .matter()
            .fabric_mgr
            .borrow()
            .max_groups_per_fabric())
    }

    fn max_group_keys_per_fabric(&self, ctx: impl ReadContext) -> Result<u16, Error> {
        // +1 for IPK (key set 0)
        Ok(ctx
            .exchange()
            .matter()
            .fabric_mgr
            .borrow()
            .max_group_keys_per_fabric()
            + 1)
    }

    fn set_group_key_map(
        &self,
        ctx: impl WriteContext,
        value: ArrayAttributeWrite<TLVArray<'_, GroupKeyMapStruct<'_>>, GroupKeyMapStruct<'_>>,
    ) -> Result<(), Error> {
        let fab_idx = NonZeroU8::new(ctx.attr().fab_idx).ok_or(ErrorCode::Invalid)?;

        let mut fabric_mgr = ctx.exchange().matter().fabric_mgr.borrow_mut();

        match value {
            ArrayAttributeWrite::Replace(list) => {
                // First validate all entries
                let mut count: usize = 0;
                for entry in &list {
                    count += 1;
                    if count > fabric_mgr.max_groups_per_fabric().into() {
                        return Err(ErrorCode::Failure.into());
                    }
                    let entry = entry?;
                    // GroupKeySetID must not be 0
                    if entry.group_key_set_id()? == 0 {
                        return Err(ErrorCode::ConstraintError.into());
                    }
                }

                // Now replace all entries
                let entries = list.into_iter().filter_map(|entry| {
                    let entry = entry.ok()?;
                    Some(GrpKeyMapEntry {
                        group_id: entry.group_id().ok()?,
                        group_key_set_id: entry.group_key_set_id().ok()?,
                    })
                });

                fabric_mgr.group_key_map_replace(fab_idx, entries)?;
            }
            ArrayAttributeWrite::Add(entry) => {
                // GroupKeySetID must not be 0
                if entry.group_key_set_id()? == 0 {
                    return Err(ErrorCode::ConstraintError.into());
                }

                let new_entry = GrpKeyMapEntry {
                    group_id: entry.group_id()?,
                    group_key_set_id: entry.group_key_set_id()?,
                };

                fabric_mgr.group_key_map_add(fab_idx, new_entry)?;
            }
            _ => {
                return Err(ErrorCode::InvalidAction.into());
            }
        }

        Ok(())
    }

    fn handle_key_set_write(
        &self,
        ctx: impl InvokeContext,
        request: KeySetWriteRequest<'_>,
    ) -> Result<(), Error> {
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor()?.fab_idx).ok_or(ErrorCode::Invalid)?;

        let key_set = request.group_key_set()?;

        let group_key_set_id = key_set.group_key_set_id()?;
        let group_key_security_policy = key_set.group_key_security_policy()?;

        // GroupKeySetID 0 is reserved for IPK
        if group_key_set_id == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        // Parse nullable epoch keys and start times
        let epoch_key_0 = key_set.epoch_key_0()?;
        let epoch_start_time_0 = key_set.epoch_start_time_0()?;
        let epoch_key_1 = key_set.epoch_key_1()?;
        let epoch_start_time_1 = key_set.epoch_start_time_1()?;
        let epoch_key_2 = key_set.epoch_key_2()?;
        let epoch_start_time_2 = key_set.epoch_start_time_2()?;

        // Validate EpochKey0 must not be null
        let Some(epoch_key_0_val) = epoch_key_0.as_opt_ref() else {
            return Err(ErrorCode::InvalidCommand.into());
        };

        // Validate EpochStartTime0 must not be null
        let Some(&epoch_start_time_0_val) = epoch_start_time_0.as_opt_ref() else {
            return Err(ErrorCode::InvalidCommand.into());
        };

        // Validate EpochStartTime0 must not be 0
        if epoch_start_time_0_val == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        // Validate EpochKey0 length must be 16
        if epoch_key_0_val.0.len() != 16 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let has_epoch_key_1 = epoch_key_1.as_opt_ref().is_some();
        let has_epoch_start_time_1 = epoch_start_time_1.as_opt_ref().is_some();

        // If one of key1/time1 is present, both must be present
        if has_epoch_key_1 != has_epoch_start_time_1 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        let mut entry = GrpKeySetEntry {
            group_key_set_id,
            group_key_security_policy: group_key_security_policy as u8,
            epoch_start_time0: epoch_start_time_0_val,
            ..Default::default()
        };

        // Copy epoch key 0
        entry
            .epoch_key0
            .vec
            .extend_from_slice(epoch_key_0_val.0)
            .map_err(|_| ErrorCode::ConstraintError)?;

        if has_epoch_key_1 {
            let epoch_key_1_val = epoch_key_1.as_opt_ref().unwrap();
            let &epoch_start_time_1_val = epoch_start_time_1.as_opt_ref().unwrap();

            // Validate key length
            if epoch_key_1_val.0.len() != 16 {
                return Err(ErrorCode::ConstraintError.into());
            }

            // Validate time1 > time0
            if epoch_start_time_1_val <= epoch_start_time_0_val {
                return Err(ErrorCode::InvalidCommand.into());
            }

            entry.has_epoch_key1 = true;
            entry
                .epoch_key1
                .vec
                .extend_from_slice(epoch_key_1_val.0)
                .map_err(|_| ErrorCode::ConstraintError)?;
            entry.epoch_start_time1 = epoch_start_time_1_val;

            // Check epoch key 2
            let has_epoch_key_2 = epoch_key_2.as_opt_ref().is_some();
            let has_epoch_start_time_2 = epoch_start_time_2.as_opt_ref().is_some();

            if has_epoch_key_2 != has_epoch_start_time_2 {
                return Err(ErrorCode::InvalidCommand.into());
            }

            if has_epoch_key_2 {
                let epoch_key_2_val = epoch_key_2.as_opt_ref().unwrap();
                let &epoch_start_time_2_val = epoch_start_time_2.as_opt_ref().unwrap();

                // Validate key length
                if epoch_key_2_val.0.len() != 16 {
                    return Err(ErrorCode::ConstraintError.into());
                }

                // Validate time2 > time1
                if epoch_start_time_2_val <= epoch_start_time_1_val {
                    return Err(ErrorCode::InvalidCommand.into());
                }

                entry.has_epoch_key2 = true;
                entry
                    .epoch_key2
                    .vec
                    .extend_from_slice(epoch_key_2_val.0)
                    .map_err(|_| ErrorCode::ConstraintError)?;
                entry.epoch_start_time2 = epoch_start_time_2_val;
            }
        } else {
            // If key1 not present, key2 must not be present either
            let has_epoch_key_2 = epoch_key_2.as_opt_ref().is_some();
            let has_epoch_start_time_2 = epoch_start_time_2.as_opt_ref().is_some();

            if has_epoch_key_2 || has_epoch_start_time_2 {
                return Err(ErrorCode::InvalidCommand.into());
            }
        }

        ctx.exchange()
            .matter()
            .fabric_mgr
            .borrow_mut()
            .group_key_set_add(fab_idx, entry)?;

        Ok(())
    }

    fn handle_key_set_read<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: KeySetReadRequest<'_>,
        response: KeySetReadResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor()?.fab_idx).ok_or(ErrorCode::Invalid)?;

        let group_key_set_id = request.group_key_set_id()?;

        let fabric_mgr = ctx.exchange().matter().fabric_mgr.borrow();
        let fabric = fabric_mgr.get(fab_idx).ok_or(ErrorCode::NotFound)?;
        let entry = fabric
            .group_key_set_get(group_key_set_id)
            .ok_or(ErrorCode::NotFound)?;

        // Build response: epoch keys are always null, start times are preserved
        response
            .group_key_set()?
            .group_key_set_id(group_key_set_id)?
            .group_key_security_policy(
                // SAFETY: group_key_security_policy is validated at write time
                // and the enum is #[repr(u8)]
                unsafe {
                    core::mem::transmute::<u8, GroupKeySecurityPolicyEnum>(
                        entry.group_key_security_policy,
                    )
                },
            )?
            .epoch_key_0(Nullable::<Octets<'_>>::none())?
            .epoch_start_time_0(Nullable::some(entry.epoch_start_time0))?
            .epoch_key_1(Nullable::<Octets<'_>>::none())?
            .epoch_start_time_1(if entry.has_epoch_key1 {
                Nullable::some(entry.epoch_start_time1)
            } else {
                Nullable::none()
            })?
            .epoch_key_2(Nullable::<Octets<'_>>::none())?
            .epoch_start_time_2(if entry.has_epoch_key2 {
                Nullable::some(entry.epoch_start_time2)
            } else {
                Nullable::none()
            })?
            .end()?
            .end()
    }

    fn handle_key_set_remove(
        &self,
        ctx: impl InvokeContext,
        request: KeySetRemoveRequest<'_>,
    ) -> Result<(), Error> {
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor()?.fab_idx).ok_or(ErrorCode::Invalid)?;

        let group_key_set_id = request.group_key_set_id()?;

        // KeySetRemove of ID 0 (IPK) is not allowed
        if group_key_set_id == 0 {
            return Err(ErrorCode::InvalidCommand.into());
        }

        ctx.exchange()
            .matter()
            .fabric_mgr
            .borrow_mut()
            .group_key_set_remove(fab_idx, group_key_set_id)?;

        Ok(())
    }

    fn handle_key_set_read_all_indices<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        response: KeySetReadAllIndicesResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx =
            NonZeroU8::new(ctx.exchange().accessor()?.fab_idx).ok_or(ErrorCode::Invalid)?;

        let fabric_mgr = ctx.exchange().matter().fabric_mgr.borrow();
        let fabric = fabric_mgr.get(fab_idx).ok_or(ErrorCode::NotFound)?;

        // Always include IPK (0) plus all stored key set IDs
        let mut ids = response.group_key_set_i_ds()?;
        ids = ids.push(&0u16)?;
        for entry in fabric.group_key_set_iter() {
            ids = ids.push(&entry.group_key_set_id)?;
        }
        ids.end()?.end()
    }
}
