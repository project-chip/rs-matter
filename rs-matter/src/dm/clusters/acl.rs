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

//! This module contains the implementation of the Access Control cluster and its handler.

use core::num::NonZeroU8;

use crate::acl::{self, AclEntry, AuthMode, MAX_ACL_ENTRIES_PER_FABRIC};
use crate::dm::{
    ArrayAttributeRead, ArrayAttributeWrite, AttrDetails, Cluster, Dataver, InvokeContext,
    ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::fabric::{Fabric, FabricPersist, Fabrics};
use crate::tlv::{Nullable, TLVArray, TLVBuilderParent};
use crate::utils::init::stack_try_pin_init;
use crate::with;

pub use crate::dm::clusters::decl::access_control::*;

/// The system implementation of a handler for the Access Control Matter cluster.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AclHandler {
    dataver: Dataver,
}

impl AclHandler {
    /// Create a new instance of `AclHandler` with the given `dataver`
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    /// For unit-testing
    /// Read the ACL entries from the fabrics and write them into the builder
    fn acl<P: TLVBuilderParent>(
        &self,
        fabrics: &Fabrics,
        attr: &AttrDetails<'_>,
        builder: ArrayAttributeRead<
            AccessControlEntryStructArrayBuilder<P>,
            AccessControlEntryStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        let mut acls = fabrics
            .iter()
            .filter(|fabric| !attr.fab_filter || fabric.fab_idx().get() == attr.fab_idx)
            .flat_map(|fabric| fabric.acl_iter().map(|entry| (fabric.fab_idx(), entry)));

        match builder {
            ArrayAttributeRead::ReadAll(mut builder) => {
                for (fab_idx, entry) in acls {
                    builder =
                        entry.read_into(attr.fab_idx, Some(fab_idx.get()), builder.push()?)?;
                }

                builder.end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let Some((fab_idx, entry)) = acls.nth(index as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };

                entry.read_into(attr.fab_idx, Some(fab_idx.get()), builder)
            }
            ArrayAttributeRead::ReadNone(builder) => builder.end(),
        }
    }

    /// For unit-testing
    /// Set the ACL entries in the fabrics
    fn set_acl(
        &self,
        fabric: &mut Fabric,
        value: ArrayAttributeWrite<
            TLVArray<'_, AccessControlEntryStruct<'_>>,
            AccessControlEntryStruct<'_>,
        >,
    ) -> Result<(), Error> {
        match value {
            ArrayAttributeWrite::Replace(list) => {
                // Check the well-formedness of the list first & init to check validity
                let mut count: usize = 0;
                for entry in &list {
                    count += 1;
                    if count > MAX_ACL_ENTRIES_PER_FABRIC {
                        return Err(ErrorCode::ResourceExhausted)?;
                    }
                    let entry = entry?;
                    // Init a dummy to propagate failures for bad inputs
                    stack_try_pin_init!(let _processed =? AclEntry::init_with(fabric.fab_idx(), &entry));
                }

                // Now add everything once we know all are valid
                fabric.acl_remove_all();
                for entry in &list {
                    // unwrap! calls below can't fail because we already checked that the entry is well-formed
                    // and the length of the list is within the limit
                    let entry = unwrap!(entry);
                    unwrap!(fabric.acl_add_init(AclEntry::init_with(fabric.fab_idx(), &entry)));
                }
            }
            ArrayAttributeWrite::Add(entry) => {
                fabric.acl_add_init(AclEntry::init_with(fabric.fab_idx(), &entry))?;
            }
            ArrayAttributeWrite::Update(index, entry) => {
                fabric
                    .acl_update_init(index as _, AclEntry::init_with(fabric.fab_idx(), &entry))?;
            }
            ArrayAttributeWrite::Remove(index) => {
                fabric.acl_remove(index as _)?;
            }
        }

        Ok(())
    }
}

impl ClusterHandler for AclHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required)).with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn acl<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            AccessControlEntryStructArrayBuilder<P>,
            AccessControlEntryStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        ctx.exchange()
            .with_state(|state| self.acl(&state.fabrics, ctx.attr(), builder))
    }

    fn subjects_per_access_control_entry(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(acl::MAX_SUBJECTS_PER_ACL_ENTRY as _)
    }

    fn targets_per_access_control_entry(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(acl::MAX_TARGETS_PER_ACL_ENTRY as _)
    }

    fn access_control_entries_per_fabric(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(acl::MAX_ACL_ENTRIES_PER_FABRIC as _)
    }

    fn set_acl(
        &self,
        ctx: impl WriteContext,
        value: ArrayAttributeWrite<
            TLVArray<'_, AccessControlEntryStruct<'_>>,
            AccessControlEntryStruct<'_>,
        >,
    ) -> Result<(), Error> {
        let mut persist = FabricPersist::new(ctx.kv());

        let accessor = ctx.exchange().accessor()?;
        let admin_node_id: Nullable<u64> = match accessor.peer_node_id() {
            Some(id) => Nullable::some(id),
            None => Nullable::none(),
        };
        let admin_passcode_id: Nullable<u16> =
            if matches!(accessor.auth_mode(), Some(AuthMode::Pase)) {
                Nullable::some(0u16)
            } else {
                Nullable::none()
            };

        let fab_idx = NonZeroU8::new(ctx.attr().fab_idx).ok_or(ErrorCode::UnsupportedAccess)?;

        // We emit `AccessControlEntryChanged` events while still holding the
        // matter state lock so that we can compare the *old* and *new* ACL
        // contents and produce one event per entry change. `Events::push` (used
        // by the emit path) takes its own independent lock, so this is safe.
        ctx.exchange().with_state(|state| {
            let fabric = state.fabrics.fabric_mut(fab_idx)?;

            match value {
                ArrayAttributeWrite::Replace(list) => {
                    // Snapshot old entries so we can diff against the new list per index
                    // (Matter Core spec section 9.10.7 mandates one event per entry change,
                    // with `LatestValue` populated). `MAX_ACL_ENTRIES_PER_FABRIC` is small
                    // (default 4), so a stack-allocated snapshot is cheap.
                    let mut old_entries: heapless::Vec<AclEntry, MAX_ACL_ENTRIES_PER_FABRIC> =
                        heapless::Vec::new();
                    for e in fabric.acl_iter() {
                        let _ = old_entries.push(e.clone());
                    }

                    self.set_acl(fabric, ArrayAttributeWrite::Replace(list))?;

                    let new_count = fabric.acl_iter().count();
                    let old_count = old_entries.len();

                    // Per-index Changed (overlap) and Added (new tail) events.
                    for (i, entry) in fabric.acl_iter().enumerate() {
                        let change = if i < old_count {
                            ChangeTypeEnum::Changed
                        } else {
                            ChangeTypeEnum::Added
                        };
                        emit_acl_entry_changed(
                            &ctx,
                            admin_node_id.clone(),
                            admin_passcode_id.clone(),
                            change,
                            entry,
                            fab_idx.get(),
                        )?;
                    }

                    // Removed events for entries that fell off the end of the list.
                    // `LatestValue` for a removal is the entry's contents just before removal.
                    for old_entry in old_entries.iter().skip(new_count) {
                        emit_acl_entry_changed(
                            &ctx,
                            admin_node_id.clone(),
                            admin_passcode_id.clone(),
                            ChangeTypeEnum::Removed,
                            old_entry,
                            fab_idx.get(),
                        )?;
                    }
                }
                ArrayAttributeWrite::Add(entry) => {
                    let old_count = fabric.acl_iter().count();
                    self.set_acl(fabric, ArrayAttributeWrite::Add(entry))?;
                    if let Some(new_entry) = fabric.acl_iter().nth(old_count) {
                        emit_acl_entry_changed(
                            &ctx,
                            admin_node_id.clone(),
                            admin_passcode_id.clone(),
                            ChangeTypeEnum::Added,
                            new_entry,
                            fab_idx.get(),
                        )?;
                    }
                }
                ArrayAttributeWrite::Update(index, entry) => {
                    let idx = index as usize;
                    self.set_acl(fabric, ArrayAttributeWrite::Update(index, entry))?;
                    if let Some(new_entry) = fabric.acl_iter().nth(idx) {
                        emit_acl_entry_changed(
                            &ctx,
                            admin_node_id.clone(),
                            admin_passcode_id.clone(),
                            ChangeTypeEnum::Changed,
                            new_entry,
                            fab_idx.get(),
                        )?;
                    }
                }
                ArrayAttributeWrite::Remove(index) => {
                    let idx = index as usize;
                    let removed = fabric.acl_iter().nth(idx).cloned();
                    self.set_acl(fabric, ArrayAttributeWrite::Remove(index))?;
                    if let Some(old_entry) = removed {
                        emit_acl_entry_changed(
                            &ctx,
                            admin_node_id.clone(),
                            admin_passcode_id.clone(),
                            ChangeTypeEnum::Removed,
                            &old_entry,
                            fab_idx.get(),
                        )?;
                    }
                }
            }

            // NOTE: Not sure this is a spec-compliant behavor:
            // If the failsafe is armed for our fabric, we'll NOT persist the groups changes until commissioning is complete.
            // And we'll LOSE those changes if the failsafe times out before commissioning completes.
            if !state.failsafe.is_armed_for(fab_idx.get()) {
                persist.store(fabric)?;
            }

            Ok(())
        })?;

        persist.run()
    }

    fn handle_review_fabric_restrictions<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: ReviewFabricRestrictionsRequest<'_>,
        _response: ReviewFabricRestrictionsResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Only necessary with MNGD feature (ManagedDevice)
        unimplemented!()
    }
}

/// Emit one `AccessControlEntryChanged` event with the given change type and
/// the entry's contents serialized into `LatestValue`.
///
/// Callers pass in the `admin_node_id` / `admin_passcode_id` derived from the
/// requesting accessor (CASE → node id, PASE → passcode id 0). For changes
/// originating from internal flows that do not have a requester (e.g. the
/// auto-created admin entry on AddNOC, which runs over PASE), pass null/0.
///
/// The event is emitted on endpoint 0 (the AccessControl cluster always lives
/// there), via `emit_for` so the helper can be used from cluster handlers
/// other than ACL itself (e.g. from the OperationalCredentials handler when
/// AddNOC seeds the initial admin entry).
pub(crate) fn emit_acl_entry_changed<E>(
    emitter: E,
    admin_node_id: Nullable<u64>,
    admin_passcode_id: Nullable<u16>,
    change_type: ChangeTypeEnum,
    entry: &AclEntry,
    fab_idx: u8,
) -> Result<(), Error>
where
    E: crate::dm::EventEmitter,
{
    AccessControlEntryChanged::emit_for(emitter, 0, |tw| {
        let inner = tw
            .admin_node_id(admin_node_id)?
            .admin_passcode_id(admin_passcode_id)?
            .change_type(change_type)?
            .latest_value()?
            .non_null()?;

        // `read_into` populates the full `AccessControlEntryStruct` for the
        // requested fabric. We pass `fab_idx == fab_idx` so that all
        // fabric-sensitive fields are included in the event payload.
        let parent = entry.read_into(fab_idx, Some(fab_idx), inner)?;

        parent.fabric_index(Some(fab_idx))?.end()
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::num::NonZeroU8;

    use crate::acl::{AclEntry, AuthMode};
    use crate::dm::clusters::acl::{
        AccessControlEntryStruct, AccessControlEntryStructArrayBuilder, Dataver,
    };
    use crate::dm::{
        ArrayAttributeRead, ArrayAttributeWrite, AttrDetails, AttrReadReplyInstance, Node,
        Privilege, ReadReply, ReadReplyInstance, Reply,
    };
    use crate::fabric::Fabrics;
    use crate::tlv::{get_root_node_struct, TLVElement, TLVTag, TLVWriteParent, ToTLV};
    use crate::utils::storage::WriteBuf;

    use super::AclHandler;

    use crate::acl::tests::{FAB_1, FAB_2};

    #[test]
    /// Add an ACL entry
    fn acl_cluster_add() {
        let mut buf: [u8; 100] = [0; 100];
        let mut tw = WriteBuf::new(&mut buf);

        let mut fabrics = Fabrics::new();

        // Add fabric with ID 1
        unwrap!(fabrics.add_with_post_init(|_| Ok(())));

        let acl = AclHandler::new(Dataver::new(0));

        let new = AclEntry::new(Some(FAB_2), Privilege::VIEW, AuthMode::Case);

        unwrap!(new.to_tlv(&TLVTag::Anonymous, &mut tw));
        let data = unwrap!(get_root_node_struct(tw.as_slice()));

        // Test, ACL has fabric index 2, but the accessing fabric is 1
        //    the fabric index in the TLV should be ignored and the ACL should be created with entry 1
        acl_add(&acl, &mut fabrics, &data, FAB_1);

        let verifier = AclEntry::new(Some(FAB_1), Privilege::VIEW, AuthMode::Case);
        for fabric in fabrics.iter() {
            for a in fabric.acl_iter() {
                assert_eq!(*a, verifier);
            }
        }
    }

    #[test]
    /// - The listindex used for edit should be relative to the current fabric
    fn acl_cluster_edit() {
        let mut buf: [u8; 100] = [0; 100];
        let mut tw = WriteBuf::new(&mut buf);

        let mut fabrics = Fabrics::new();

        // Add fabric with ID 1
        fabrics.add_with_post_init(|_| Ok(())).unwrap();

        // Add fabric with ID 2
        fabrics.add_with_post_init(|_| Ok(())).unwrap();

        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let mut verifier = [
            AclEntry::new(Some(FAB_2), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_1), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_2), Privilege::ADMIN, AuthMode::Case),
        ];
        for i in &verifier {
            fabrics
                .fabric_mut(i.fab_idx.unwrap())
                .unwrap()
                .acl_add(i.clone())
                .unwrap();
        }
        let acl = AclHandler::new(Dataver::new(0));

        let new = AclEntry::new(Some(FAB_2), Privilege::VIEW, AuthMode::Case);
        new.to_tlv(&TLVTag::Anonymous, &mut tw).unwrap();
        let data = get_root_node_struct(tw.as_slice()).unwrap();

        // Test, Edit Fabric 2's index 1 - with accessing fabric as 2 - allow
        acl_edit(&acl, &mut fabrics, 1, &data, FAB_2);
        // Fabric 2's index 1, is actually our index 2, update the verifier
        verifier[2] = new;

        // Also validate in the fabrics that the entries are in the right order
        assert_eq!(fabrics.get(FAB_1).unwrap().acl_iter().count(), 1);
        assert_eq!(
            fabrics.get(FAB_1).unwrap().acl_iter().next().unwrap(),
            &verifier[1]
        );
        assert_eq!(fabrics.get(FAB_2).unwrap().acl_iter().count(), 2);
        assert_eq!(
            fabrics.get(FAB_2).unwrap().acl_iter().next().unwrap(),
            &verifier[0]
        );
        assert_eq!(
            fabrics.get(FAB_2).unwrap().acl_iter().nth(1).unwrap(),
            &verifier[2]
        );
    }

    #[test]
    /// - The listindex used for delete should be relative to the current fabric
    fn acl_cluster_delete() {
        let mut fabrics = Fabrics::new();

        // Add fabric with ID 1
        fabrics.add_with_post_init(|_| Ok(())).unwrap();

        // Add fabric with ID 2
        fabrics.add_with_post_init(|_| Ok(())).unwrap();

        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let input = [
            AclEntry::new(Some(FAB_2), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_1), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_2), Privilege::ADMIN, AuthMode::Case),
        ];
        for i in &input {
            fabrics
                .fabric_mut(i.fab_idx.unwrap())
                .unwrap()
                .acl_add(i.clone())
                .unwrap();
        }
        let acl = AclHandler::new(Dataver::new(0));

        // Test: delete Fabric 1's index 0
        acl_remove(&acl, &mut fabrics, 0, FAB_1);

        let verifier = [input[0].clone(), input[2].clone()];
        // Also validate in the fabrics that the entries are in the right order
        let mut index = 0;
        for fabric in fabrics.iter() {
            for a in fabric.acl_iter() {
                assert_eq!(*a, verifier[index]);
                index += 1;
            }
        }
    }

    #[test]
    /// - acl read with and without fabric filtering
    fn acl_cluster_read() {
        let mut buf: [u8; 100] = [0; 100];
        let mut writebuf = WriteBuf::new(&mut buf);

        let mut fabrics = Fabrics::new();

        // Add fabric with ID 1
        fabrics.add_with_post_init(|_| Ok(())).unwrap();

        // Add fabric with ID 2
        fabrics.add_with_post_init(|_| Ok(())).unwrap();

        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let input = [
            AclEntry::new(Some(FAB_2), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_1), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_2), Privilege::ADMIN, AuthMode::Case),
        ];
        for i in input {
            fabrics
                .fabric_mut(i.fab_idx.unwrap())
                .unwrap()
                .acl_add(i)
                .unwrap();
        }
        let acl = AclHandler::new(Dataver::new(0));

        // Test 1, all 3 entries are read in the response without fabric filtering
        {
            let attr = AttrDetails {
                node: &Node { endpoints: &[] },
                endpoint_id: 0,
                cluster_id: 0,
                attr_id: 0,
                list_index: None,
                list_chunked: false,
                fab_idx: 1,
                fab_filter: false,
                dataver: None,
                wildcard: false,
                cluster_status: Cell::new(0),
            };

            acl_read(&acl, &fabrics, &attr, &mut writebuf);
            assert_eq!(
                &[
                    21, 53, 1, 36, 0, 0, 55, 1, 36, 2, 0, 36, 3, 0, 36, 4, 0, 24, 54, 2, 21, 36, 1,
                    1, 36, 2, 2, 52, 3, 52, 4, 36, 254, 1, 24, 21, 36, 254, 2, 24, 21, 36, 254, 2,
                    24, 24, 24, 24
                ],
                writebuf.as_slice()
            );
        }
        writebuf.reset();

        // Test 2, only single entry is read in the response with fabric filtering and fabric idx 1
        {
            let attr = AttrDetails {
                node: &Node { endpoints: &[] },
                endpoint_id: 0,
                cluster_id: 0,
                attr_id: 0,
                list_index: None,
                list_chunked: false,
                fab_idx: 1,
                fab_filter: true,
                dataver: None,
                wildcard: false,
                cluster_status: Cell::new(0),
            };

            acl_read(&acl, &fabrics, &attr, &mut writebuf);
            assert_eq!(
                &[
                    21, 53, 1, 36, 0, 0, 55, 1, 36, 2, 0, 36, 3, 0, 36, 4, 0, 24, 54, 2, 21, 36, 1,
                    1, 36, 2, 2, 52, 3, 52, 4, 36, 254, 1, 24, 24, 24, 24
                ],
                writebuf.as_slice()
            );
        }
        writebuf.reset();

        // Test 3, only single entry is read in the response with fabric filtering and fabric idx 2
        {
            let attr = AttrDetails {
                node: &Node { endpoints: &[] },
                endpoint_id: 0,
                cluster_id: 0,
                attr_id: 0,
                list_index: None,
                list_chunked: false,
                fab_idx: 2,
                fab_filter: true,
                dataver: None,
                wildcard: false,
                cluster_status: Cell::new(0),
            };

            acl_read(&acl, &fabrics, &attr, &mut writebuf);
            assert_eq!(
                &[
                    21, 53, 1, 36, 0, 0, 55, 1, 36, 2, 0, 36, 3, 0, 36, 4, 0, 24, 54, 2, 21, 36, 1,
                    1, 36, 2, 2, 52, 3, 52, 4, 36, 254, 2, 24, 21, 36, 1, 5, 36, 2, 2, 52, 3, 52,
                    4, 36, 254, 2, 24, 24, 24, 24
                ],
                writebuf.as_slice()
            );
        }
    }

    fn acl_read(
        acl: &AclHandler,
        fabrics: &Fabrics,
        attr: &AttrDetails<'_>,
        tw: &mut WriteBuf<'_>,
    ) {
        let encoder = ReadReplyInstance::new(attr, &mut *tw);
        let mut writer = unwrap!(unwrap!(encoder.with_dataver(acl.dataver.get())));
        let build_root = TLVWriteParent::new((), writer.writer());
        unwrap!(acl.acl(
            fabrics,
            attr,
            ArrayAttributeRead::ReadAll(unwrap!(AccessControlEntryStructArrayBuilder::new(
                build_root,
                &AttrReadReplyInstance::<WriteBuf>::TAG
            )))
        ));

        unwrap!(writer.complete());
    }

    fn acl_add(acl: &AclHandler, fabrics: &mut Fabrics, data: &TLVElement<'_>, fab_idx: NonZeroU8) {
        unwrap!(acl.set_acl(
            fabrics.fabric_mut(fab_idx).unwrap(),
            ArrayAttributeWrite::Add(AccessControlEntryStruct::new(data.clone())),
        ));
    }

    fn acl_edit(
        acl: &AclHandler,
        fabrics: &mut Fabrics,
        index: u16,
        data: &TLVElement<'_>,
        fab_idx: NonZeroU8,
    ) {
        unwrap!(acl.set_acl(
            fabrics.fabric_mut(fab_idx).unwrap(),
            ArrayAttributeWrite::Update(index, AccessControlEntryStruct::new(data.clone())),
        ));
    }

    fn acl_remove(acl: &AclHandler, fabrics: &mut Fabrics, index: u16, fab_idx: NonZeroU8) {
        unwrap!(acl.set_acl(
            fabrics.fabric_mut(fab_idx).unwrap(),
            ArrayAttributeWrite::Remove(index)
        ));
    }
}
