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

use core::cell::RefCell;
use core::convert::TryInto;

use strum::{EnumDiscriminants, FromRepr};

use crate::acl::{self, AclEntry, AclMgr};
use crate::data_model::objects::*;
use crate::interaction_model::messages::ib::{attr_list_write, ListOperation};
use crate::tlv::{FromTLV, TLVElement, TagType, ToTLV};
use crate::utils::rand::Rand;
use crate::{attribute_enum, error::*};
use log::{error, info};

pub const ID: u32 = 0x001F;

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u16)]
pub enum Attributes {
    Acl(()) = 0,
    Extension(()) = 1,
    SubjectsPerEntry(AttrType<u16>) = 2,
    TargetsPerEntry(AttrType<u16>) = 3,
    EntriesPerFabric(AttrType<u16>) = 4,
}

attribute_enum!(Attributes);

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID,
    feature_map: 0,
    attributes: &[
        FEATURE_MAP,
        ATTRIBUTE_LIST,
        Attribute::new(
            AttributesDiscriminants::Acl as u16,
            Access::RWFA,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::Extension as u16,
            Access::RWFA,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::SubjectsPerEntry as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::TargetsPerEntry as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::EntriesPerFabric as u16,
            Access::RV,
            Quality::FIXED,
        ),
    ],
    commands: &[],
};

pub struct AccessControlCluster<'a> {
    data_ver: Dataver,
    acl_mgr: &'a RefCell<AclMgr>,
}

impl<'a> AccessControlCluster<'a> {
    pub fn new(acl_mgr: &'a RefCell<AclMgr>, rand: Rand) -> Self {
        Self {
            data_ver: Dataver::new(rand),
            acl_mgr,
        }
    }

    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::Acl(_) => {
                        writer.start_array(AttrDataWriter::TAG)?;
                        self.acl_mgr.borrow().for_each_acl(|entry| {
                            if !attr.fab_filter || Some(attr.fab_idx) == entry.fab_idx {
                                entry.to_tlv(&mut writer, TagType::Anonymous)?;
                            }

                            Ok(())
                        })?;
                        writer.end_container()?;

                        writer.complete()
                    }
                    Attributes::Extension(_) => {
                        // Empty for now
                        writer.start_array(AttrDataWriter::TAG)?;
                        writer.end_container()?;

                        writer.complete()
                    }
                    Attributes::SubjectsPerEntry(codec) => {
                        codec.encode(writer, acl::SUBJECTS_PER_ENTRY as u16)
                    }
                    Attributes::TargetsPerEntry(codec) => {
                        codec.encode(writer, acl::TARGETS_PER_ENTRY as u16)
                    }
                    Attributes::EntriesPerFabric(codec) => {
                        codec.encode(writer, acl::ENTRIES_PER_FABRIC as u16)
                    }
                }
            }
        } else {
            Ok(())
        }
    }

    pub fn write(&mut self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        match attr.attr_id.try_into()? {
            Attributes::Acl(_) => {
                attr_list_write(attr, data.with_dataver(self.data_ver.get())?, |op, data| {
                    self.write_acl_attr(&op, data, attr.fab_idx)
                })
            }
            _ => {
                error!("Attribute not yet supported: this shouldn't happen");
                Err(ErrorCode::AttributeNotFound.into())
            }
        }
    }

    /// Write the ACL Attribute
    ///
    /// This takes care of 4 things, add item, edit item, delete item, delete list.
    /// Care about fabric-scoped behaviour is taken
    fn write_acl_attr(
        &mut self,
        op: &ListOperation,
        data: &TLVElement,
        fab_idx: u8,
    ) -> Result<(), Error> {
        info!("Performing ACL operation {:?}", op);
        match op {
            ListOperation::AddItem | ListOperation::EditItem(_) => {
                let mut acl_entry = AclEntry::from_tlv(data)?;
                info!("ACL  {:?}", acl_entry);
                // Overwrite the fabric index with our accessing fabric index
                acl_entry.fab_idx = Some(fab_idx);

                if let ListOperation::EditItem(index) = op {
                    self.acl_mgr
                        .borrow_mut()
                        .edit(*index as u8, fab_idx, acl_entry)
                } else {
                    self.acl_mgr.borrow_mut().add(acl_entry)
                }
            }
            ListOperation::DeleteItem(index) => {
                self.acl_mgr.borrow_mut().delete(*index as u8, fab_idx)
            }
            ListOperation::DeleteList => self.acl_mgr.borrow_mut().delete_for_fabric(fab_idx),
        }
    }
}

impl<'a> Handler for AccessControlCluster<'a> {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        AccessControlCluster::read(self, attr, encoder)
    }

    fn write(&mut self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        AccessControlCluster::write(self, attr, data)
    }
}

impl<'a> NonBlockingHandler for AccessControlCluster<'a> {}

impl<'a> ChangeNotifier<()> for AccessControlCluster<'a> {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use crate::{
        acl::{AclEntry, AclMgr, AuthMode},
        data_model::objects::{AttrDataEncoder, AttrDetails, Node, Privilege},
        interaction_model::messages::ib::ListOperation,
        tlv::{get_root_node_struct, ElementType, TLVElement, TLVWriter, TagType, ToTLV},
        utils::{rand::dummy_rand, writebuf::WriteBuf},
    };

    use super::AccessControlCluster;

    #[test]
    /// Add an ACL entry
    fn acl_cluster_add() {
        let mut buf: [u8; 100] = [0; 100];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWriter::new(&mut writebuf);

        let acl_mgr = RefCell::new(AclMgr::new());
        let mut acl = AccessControlCluster::new(&acl_mgr, dummy_rand);

        let new = AclEntry::new(2, Privilege::VIEW, AuthMode::Case);
        new.to_tlv(&mut tw, TagType::Anonymous).unwrap();
        let data = get_root_node_struct(writebuf.as_slice()).unwrap();

        // Test, ACL has fabric index 2, but the accessing fabric is 1
        //    the fabric index in the TLV should be ignored and the ACL should be created with entry 1
        let result = acl.write_acl_attr(&ListOperation::AddItem, &data, 1);
        assert!(result.is_ok());

        let verifier = AclEntry::new(1, Privilege::VIEW, AuthMode::Case);
        acl_mgr
            .borrow()
            .for_each_acl(|a| {
                assert_eq!(*a, verifier);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    /// - The listindex used for edit should be relative to the current fabric
    fn acl_cluster_edit() {
        let mut buf: [u8; 100] = [0; 100];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWriter::new(&mut writebuf);

        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let acl_mgr = RefCell::new(AclMgr::new());
        let mut verifier = [
            AclEntry::new(2, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(1, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(2, Privilege::ADMIN, AuthMode::Case),
        ];
        for i in verifier {
            acl_mgr.borrow_mut().add(i).unwrap();
        }
        let mut acl = AccessControlCluster::new(&acl_mgr, dummy_rand);

        let new = AclEntry::new(2, Privilege::VIEW, AuthMode::Case);
        new.to_tlv(&mut tw, TagType::Anonymous).unwrap();
        let data = get_root_node_struct(writebuf.as_slice()).unwrap();

        // Test, Edit Fabric 2's index 1 - with accessing fabring as 2 - allow
        let result = acl.write_acl_attr(&ListOperation::EditItem(1), &data, 2);
        // Fabric 2's index 1, is actually our index 2, update the verifier
        verifier[2] = new;
        assert!(result.is_ok());

        // Also validate in the acl_mgr that the entries are in the right order
        let mut index = 0;
        acl_mgr
            .borrow()
            .for_each_acl(|a| {
                assert_eq!(*a, verifier[index]);
                index += 1;
                Ok(())
            })
            .unwrap();
    }

    #[test]
    /// - The listindex used for delete should be relative to the current fabric
    fn acl_cluster_delete() {
        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let acl_mgr = RefCell::new(AclMgr::new());
        let input = [
            AclEntry::new(2, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(1, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(2, Privilege::ADMIN, AuthMode::Case),
        ];
        for i in input {
            acl_mgr.borrow_mut().add(i).unwrap();
        }
        let mut acl = AccessControlCluster::new(&acl_mgr, dummy_rand);
        // data is don't-care actually
        let data = TLVElement::new(TagType::Anonymous, ElementType::True);

        // Test , Delete Fabric 1's index 0
        let result = acl.write_acl_attr(&ListOperation::DeleteItem(0), &data, 1);
        assert!(result.is_ok());

        let verifier = [input[0], input[2]];
        // Also validate in the acl_mgr that the entries are in the right order
        let mut index = 0;
        acl_mgr
            .borrow()
            .for_each_acl(|a| {
                assert_eq!(*a, verifier[index]);
                index += 1;
                Ok(())
            })
            .unwrap();
    }

    #[test]
    /// - acl read with and without fabric filtering
    fn acl_cluster_read() {
        let mut buf: [u8; 100] = [0; 100];
        let mut writebuf = WriteBuf::new(&mut buf);

        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let acl_mgr = RefCell::new(AclMgr::new());
        let input = [
            AclEntry::new(2, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(1, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(2, Privilege::ADMIN, AuthMode::Case),
        ];
        for i in input {
            acl_mgr.borrow_mut().add(i).unwrap();
        }
        let acl = AccessControlCluster::new(&acl_mgr, dummy_rand);
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
                fab_idx: 1,
                fab_filter: false,
                dataver: None,
                wildcard: false,
            };

            let mut tw = TLVWriter::new(&mut writebuf);
            let encoder = AttrDataEncoder::new(&attr, &mut tw);

            acl.read(&attr, encoder).unwrap();
            assert_eq!(
                // &[
                //     21, 53, 1, 36, 0, 0, 55, 1, 24, 54, 2, 21, 36, 1, 1, 36, 2, 2, 54, 3, 24, 54,
                //     4, 24, 36, 254, 2, 24, 21, 36, 1, 1, 36, 2, 2, 54, 3, 24, 54, 4, 24, 36, 254,
                //     1, 24, 21, 36, 1, 5, 36, 2, 2, 54, 3, 24, 54, 4, 24, 36, 254, 2, 24, 24, 24,
                //     24
                // ],
                &[
                    21, 53, 1, 36, 0, 0, 55, 1, 36, 2, 0, 36, 3, 0, 36, 4, 0, 24, 54, 2, 21, 36, 1,
                    1, 36, 2, 2, 54, 3, 24, 54, 4, 24, 36, 254, 2, 24, 21, 36, 1, 1, 36, 2, 2, 54,
                    3, 24, 54, 4, 24, 36, 254, 1, 24, 21, 36, 1, 5, 36, 2, 2, 54, 3, 24, 54, 4, 24,
                    36, 254, 2, 24, 24, 24, 24
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
                fab_idx: 1,
                fab_filter: true,
                dataver: None,
                wildcard: false,
            };

            let mut tw = TLVWriter::new(&mut writebuf);
            let encoder = AttrDataEncoder::new(&attr, &mut tw);

            acl.read(&attr, encoder).unwrap();
            assert_eq!(
                // &[
                //     21, 53, 1, 36, 0, 0, 55, 1, 24, 54, 2, 21, 36, 1, 1, 36, 2, 2, 54, 3, 24, 54,
                //     4, 24, 36, 254, 1, 24, 24, 24, 24
                // ],
                &[
                    21, 53, 1, 36, 0, 0, 55, 1, 36, 2, 0, 36, 3, 0, 36, 4, 0, 24, 54, 2, 21, 36, 1,
                    1, 36, 2, 2, 54, 3, 24, 54, 4, 24, 36, 254, 1, 24, 24, 24, 24
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
                fab_idx: 2,
                fab_filter: true,
                dataver: None,
                wildcard: false,
            };

            let mut tw = TLVWriter::new(&mut writebuf);
            let encoder = AttrDataEncoder::new(&attr, &mut tw);

            acl.read(&attr, encoder).unwrap();
            assert_eq!(
                // &[
                //     21, 53, 1, 36, 0, 0, 55, 1, 24, 54, 2, 21, 36, 1, 1, 36, 2, 2, 54, 3, 24, 54,
                //     4, 24, 36, 254, 2, 24, 21, 36, 1, 5, 36, 2, 2, 54, 3, 24, 54, 4, 24, 36, 254,
                //     2, 24, 24, 24, 24
                // ],
                &[
                    21, 53, 1, 36, 0, 0, 55, 1, 36, 2, 0, 36, 3, 0, 36, 4, 0, 24, 54, 2, 21, 36, 1,
                    1, 36, 2, 2, 54, 3, 24, 54, 4, 24, 36, 254, 2, 24, 21, 36, 1, 5, 36, 2, 2, 54,
                    3, 24, 54, 4, 24, 36, 254, 2, 24, 24, 24, 24
                ],
                writebuf.as_slice()
            );
        }
    }
}
