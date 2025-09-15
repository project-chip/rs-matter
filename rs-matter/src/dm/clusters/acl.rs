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

use crate::acl::{self, AclEntry};
use crate::dm::{
    ArrayAttributeRead, ArrayAttributeWrite, AttrDetails, Cluster, Dataver, ReadContext,
    WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::fabric::FabricMgr;
use crate::tlv::{TLVArray, TLVBuilderParent};
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
    /// Read the ACL entries from the fabric manager and write them into the builder
    fn acl<P: TLVBuilderParent>(
        &self,
        fabric_mgr: &FabricMgr,
        attr: &AttrDetails<'_>,
        builder: ArrayAttributeRead<
            AccessControlEntryStructArrayBuilder<P>,
            AccessControlEntryStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        let mut acls = fabric_mgr
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
    /// Set the ACL entries in the fabric manager
    fn set_acl(
        &self,
        fabric_mgr: &mut FabricMgr,
        fab_idx: NonZeroU8,
        value: ArrayAttributeWrite<
            TLVArray<'_, AccessControlEntryStruct<'_>>,
            AccessControlEntryStruct<'_>,
        >,
    ) -> Result<(), Error> {
        match value {
            ArrayAttributeWrite::Replace(list) => {
                // Check the well-formedness of the list first
                for entry in &list {
                    let entry = entry?;
                    entry.check()?;
                }
                if list.iter().count() > acl::MAX_ACL_ENTRIES_PER_FABRIC {
                    Err(ErrorCode::ConstraintError)?;
                }

                // Now add everything
                fabric_mgr.acl_remove_all(fab_idx)?;
                for entry in list {
                    // unwrap! calls below can't fail because we already checked that the entry is well-formed
                    // and the length of the list is within the limit
                    let entry = unwrap!(entry);
                    unwrap!(fabric_mgr.acl_add_init(fab_idx, AclEntry::init_with(fab_idx, &entry)));
                }
            }
            ArrayAttributeWrite::Add(entry) => {
                fabric_mgr.acl_add_init(fab_idx, AclEntry::init_with(fab_idx, &entry))?;
            }
            ArrayAttributeWrite::Update(index, entry) => {
                fabric_mgr.acl_update_init(
                    fab_idx,
                    index as _,
                    AclEntry::init_with(fab_idx, &entry),
                )?;
            }
            ArrayAttributeWrite::Remove(index) => {
                fabric_mgr.acl_remove(fab_idx, index as _)?;
            }
        }

        Ok(())
    }
}

impl ClusterHandler for AclHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_revision(1)
        .with_attrs(with!(required))
        .with_cmds(with!());

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
        self.acl(
            &ctx.exchange().matter().fabric_mgr.borrow(),
            ctx.attr(),
            builder,
        )
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
        let fab_idx = NonZeroU8::new(ctx.attr().fab_idx).ok_or(ErrorCode::Invalid)?;
        self.set_acl(
            &mut ctx.exchange().matter().fabric_mgr.borrow_mut(),
            fab_idx,
            value,
        )
    }
}

impl AccessControlEntryStruct<'_> {
    /// Checks the well-formedness of the TLV value
    // TODO: This should be auto-generated by the `import!` macro
    pub(crate) fn check(&self) -> Result<(), Error> {
        self.auth_mode()?;
        self.privilege()?;
        self.subjects()?;
        self.targets()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU8;

    use crate::acl::{AclEntry, AuthMode};
    use crate::crypto::KeyPair;
    use crate::dm::clusters::acl::{
        AccessControlEntryStruct, AccessControlEntryStructArrayBuilder, Dataver,
    };
    use crate::dm::{
        ArrayAttributeRead, ArrayAttributeWrite, AttrDetails, AttrReadReplyInstance, Node,
        Privilege, ReadReply, ReadReplyInstance, Reply,
    };
    use crate::fabric::FabricMgr;
    use crate::tlv::{get_root_node_struct, TLVElement, TLVTag, TLVWriteParent, ToTLV};
    use crate::utils::rand::dummy_rand;
    use crate::utils::storage::WriteBuf;

    use super::AclHandler;

    use crate::acl::tests::{FAB_1, FAB_2};

    #[test]
    /// Add an ACL entry
    fn acl_cluster_add() {
        let mut buf: [u8; 100] = [0; 100];
        let mut tw = WriteBuf::new(&mut buf);

        let mut fab_mgr = FabricMgr::new();

        // Add fabric with ID 1
        unwrap!(fab_mgr.add_with_post_init(unwrap!(KeyPair::new(dummy_rand)), |_| Ok(())));

        let acl = AclHandler::new(Dataver::new(0));

        let new = AclEntry::new(Some(FAB_2), Privilege::VIEW, AuthMode::Case);

        unwrap!(new.to_tlv(&TLVTag::Anonymous, &mut tw));
        let data = unwrap!(get_root_node_struct(tw.as_slice()));

        // Test, ACL has fabric index 2, but the accessing fabric is 1
        //    the fabric index in the TLV should be ignored and the ACL should be created with entry 1
        acl_add(&acl, &mut fab_mgr, &data, FAB_1);

        let verifier = AclEntry::new(Some(FAB_1), Privilege::VIEW, AuthMode::Case);
        for fabric in fab_mgr.iter() {
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

        let mut fab_mgr = FabricMgr::new();

        // Add fabric with ID 1
        fab_mgr
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Add fabric with ID 2
        fab_mgr
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let mut verifier = [
            AclEntry::new(Some(FAB_2), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_1), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_2), Privilege::ADMIN, AuthMode::Case),
        ];
        for i in &verifier {
            fab_mgr.acl_add(i.fab_idx.unwrap(), i.clone()).unwrap();
        }
        let acl = AclHandler::new(Dataver::new(0));

        let new = AclEntry::new(Some(FAB_2), Privilege::VIEW, AuthMode::Case);
        new.to_tlv(&TLVTag::Anonymous, &mut tw).unwrap();
        let data = get_root_node_struct(tw.as_slice()).unwrap();

        // Test, Edit Fabric 2's index 1 - with accessing fabric as 2 - allow
        acl_edit(&acl, &mut fab_mgr, 1, &data, FAB_2);
        // Fabric 2's index 1, is actually our index 2, update the verifier
        verifier[2] = new;

        // Also validate in the fab_mgr that the entries are in the right order
        assert_eq!(fab_mgr.get(FAB_1).unwrap().acl_iter().count(), 1);
        assert_eq!(
            fab_mgr.get(FAB_1).unwrap().acl_iter().next().unwrap(),
            &verifier[1]
        );
        assert_eq!(fab_mgr.get(FAB_2).unwrap().acl_iter().count(), 2);
        assert_eq!(
            fab_mgr.get(FAB_2).unwrap().acl_iter().next().unwrap(),
            &verifier[0]
        );
        assert_eq!(
            fab_mgr.get(FAB_2).unwrap().acl_iter().nth(1).unwrap(),
            &verifier[2]
        );
    }

    #[test]
    /// - The listindex used for delete should be relative to the current fabric
    fn acl_cluster_delete() {
        let mut fab_mgr = FabricMgr::new();

        // Add fabric with ID 1
        fab_mgr
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Add fabric with ID 2
        fab_mgr
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let input = [
            AclEntry::new(Some(FAB_2), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_1), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_2), Privilege::ADMIN, AuthMode::Case),
        ];
        for i in &input {
            fab_mgr.acl_add(i.fab_idx.unwrap(), i.clone()).unwrap();
        }
        let acl = AclHandler::new(Dataver::new(0));

        // Test: delete Fabric 1's index 0
        acl_remove(&acl, &mut fab_mgr, 0, FAB_1);

        let verifier = [input[0].clone(), input[2].clone()];
        // Also validate in the fab_mgr that the entries are in the right order
        let mut index = 0;
        for fabric in fab_mgr.iter() {
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

        let mut fab_mgr = FabricMgr::new();

        // Add fabric with ID 1
        fab_mgr
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Add fabric with ID 2
        fab_mgr
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let input = [
            AclEntry::new(Some(FAB_2), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_1), Privilege::VIEW, AuthMode::Case),
            AclEntry::new(Some(FAB_2), Privilege::ADMIN, AuthMode::Case),
        ];
        for i in input {
            fab_mgr.acl_add(i.fab_idx.unwrap(), i).unwrap();
        }
        let acl = AclHandler::new(Dataver::new(0));

        // Test 1, all 3 entries are read in the response without fabric filtering
        {
            let attr = AttrDetails {
                node: &Node {
                    id: 0,
                    endpoints: &[],
                },
                endpoint_id: 0,
                cluster_id: 0,
                attr_id: 0,
                list_index: None,
                list_chunked: false,
                fab_idx: 1,
                fab_filter: false,
                dataver: None,
                wildcard: false,
            };

            acl_read(&acl, &fab_mgr, &attr, &mut writebuf);
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
                node: &Node {
                    id: 0,
                    endpoints: &[],
                },
                endpoint_id: 0,
                cluster_id: 0,
                attr_id: 0,
                list_index: None,
                list_chunked: false,
                fab_idx: 1,
                fab_filter: true,
                dataver: None,
                wildcard: false,
            };

            acl_read(&acl, &fab_mgr, &attr, &mut writebuf);
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
                node: &Node {
                    id: 0,
                    endpoints: &[],
                },
                endpoint_id: 0,
                cluster_id: 0,
                attr_id: 0,
                list_index: None,
                list_chunked: false,
                fab_idx: 2,
                fab_filter: true,
                dataver: None,
                wildcard: false,
            };

            acl_read(&acl, &fab_mgr, &attr, &mut writebuf);
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
        fab_mgr: &FabricMgr,
        attr: &AttrDetails<'_>,
        tw: &mut WriteBuf<'_>,
    ) {
        let encoder = ReadReplyInstance::new(attr, &mut *tw);
        let mut writer = unwrap!(unwrap!(encoder.with_dataver(acl.dataver.get())));
        let build_root = TLVWriteParent::new((), writer.writer());
        unwrap!(acl.acl(
            fab_mgr,
            attr,
            ArrayAttributeRead::ReadAll(unwrap!(AccessControlEntryStructArrayBuilder::new(
                build_root,
                &AttrReadReplyInstance::<WriteBuf>::TAG
            )))
        ));

        unwrap!(writer.complete());
    }

    fn acl_add(
        acl: &AclHandler,
        fab_mgr: &mut FabricMgr,
        data: &TLVElement<'_>,
        fab_idx: NonZeroU8,
    ) {
        unwrap!(acl.set_acl(
            fab_mgr,
            fab_idx,
            ArrayAttributeWrite::Add(AccessControlEntryStruct::new(data.clone())),
        ));
    }

    fn acl_edit(
        acl: &AclHandler,
        fab_mgr: &mut FabricMgr,
        index: u16,
        data: &TLVElement<'_>,
        fab_idx: NonZeroU8,
    ) {
        unwrap!(acl.set_acl(
            fab_mgr,
            fab_idx,
            ArrayAttributeWrite::Update(index, AccessControlEntryStruct::new(data.clone())),
        ));
    }

    fn acl_remove(acl: &AclHandler, fab_mgr: &mut FabricMgr, index: u16, fab_idx: NonZeroU8) {
        unwrap!(acl.set_acl(fab_mgr, fab_idx, ArrayAttributeWrite::Remove(index)));
    }
}
