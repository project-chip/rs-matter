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

use std::sync::Arc;

use num_derive::FromPrimitive;

use crate::acl::{self, AclEntry, AclMgr};
use crate::data_model::objects::*;
use crate::error::*;
use crate::interaction_model::core::IMStatusCode;
use crate::interaction_model::messages::ib::{attr_list_write, ListOperation};
use crate::tlv::{FromTLV, TLVElement, TagType, ToTLV};
use log::{error, info};

pub const ID: u32 = 0x001F;

#[derive(FromPrimitive)]
pub enum Attributes {
    Acl = 0,
    Extension = 1,
    SubjectsPerEntry = 2,
    TargetsPerEntry = 3,
    EntriesPerFabric = 4,
}

pub struct AccessControlCluster {
    base: Cluster,
    acl_mgr: Arc<AclMgr>,
}

impl AccessControlCluster {
    pub fn new(acl_mgr: Arc<AclMgr>) -> Result<Box<Self>, Error> {
        let mut c = Box::new(AccessControlCluster {
            base: Cluster::new(ID)?,
            acl_mgr,
        });
        c.base.add_attribute(attr_acl_new()?)?;
        c.base.add_attribute(attr_extension_new()?)?;
        c.base.add_attribute(attr_subjects_per_entry_new()?)?;
        c.base.add_attribute(attr_targets_per_entry_new()?)?;
        c.base.add_attribute(attr_entries_per_fabric_new()?)?;
        Ok(c)
    }

    /// Write the ACL Attribute
    ///
    /// This takes care of 4 things, add item, edit item, delete item, delete list.
    /// Care about fabric-scoped behaviour is taken
    fn write_acl_attr(
        &mut self,
        op: ListOperation,
        data: &TLVElement,
        fab_idx: u8,
    ) -> Result<(), IMStatusCode> {
        info!("Performing ACL operation {:?}", op);
        let result = match op {
            ListOperation::AddItem | ListOperation::EditItem(_) => {
                let mut acl_entry =
                    AclEntry::from_tlv(data).map_err(|_| IMStatusCode::ConstraintError)?;
                info!("ACL  {:?}", acl_entry);
                // Overwrite the fabric index with our accessing fabric index
                acl_entry.fab_idx = Some(fab_idx);

                if let ListOperation::EditItem(index) = op {
                    self.acl_mgr.edit(index as u8, fab_idx, acl_entry)
                } else {
                    self.acl_mgr.add(acl_entry)
                }
            }
            ListOperation::DeleteItem(index) => self.acl_mgr.delete(index as u8, fab_idx),
            ListOperation::DeleteList => self.acl_mgr.delete_for_fabric(fab_idx),
        };
        match result {
            Ok(_) => Ok(()),
            Err(Error::NoSpace) => Err(IMStatusCode::ResourceExhausted),
            _ => Err(IMStatusCode::ConstraintError),
        }
    }
}

impl ClusterType for AccessControlCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }

    fn read_custom_attribute(&self, encoder: &mut dyn Encoder, attr: &AttrDetails) {
        match num::FromPrimitive::from_u16(attr.attr_id) {
            Some(Attributes::Acl) => encoder.encode(EncodeValue::Closure(&|tag, tw| {
                let _ = tw.start_array(tag);
                let _ = self.acl_mgr.for_each_acl(|entry| {
                    if !attr.fab_filter || Some(attr.fab_idx) == entry.fab_idx {
                        let _ = entry.to_tlv(tw, TagType::Anonymous);
                    }
                });
                let _ = tw.end_container();
            })),
            Some(Attributes::Extension) => encoder.encode(EncodeValue::Closure(&|tag, tw| {
                // Empty for now
                let _ = tw.start_array(tag);
                let _ = tw.end_container();
            })),
            _ => {
                error!("Attribute not yet supported: this shouldn't happen");
            }
        }
    }

    fn write_attribute(
        &mut self,
        attr: &AttrDetails,
        data: &TLVElement,
    ) -> Result<(), IMStatusCode> {
        let result = match num::FromPrimitive::from_u16(attr.attr_id) {
            Some(Attributes::Acl) => attr_list_write(attr, data, |op, data| {
                self.write_acl_attr(op, data, attr.fab_idx)
            }),
            _ => {
                error!("Attribute not yet supported: this shouldn't happen");
                Err(IMStatusCode::NotFound)
            }
        };
        if result.is_ok() {
            self.base.cluster_changed();
        }
        result
    }
}

fn attr_acl_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::Acl as u16,
        AttrValue::Custom,
        Access::RWFA,
        Quality::NONE,
    )
}

fn attr_extension_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::Extension as u16,
        AttrValue::Custom,
        Access::RWFA,
        Quality::NONE,
    )
}

fn attr_subjects_per_entry_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::SubjectsPerEntry as u16,
        AttrValue::Uint16(acl::SUBJECTS_PER_ENTRY as u16),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_targets_per_entry_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::TargetsPerEntry as u16,
        AttrValue::Uint16(acl::TARGETS_PER_ENTRY as u16),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_entries_per_fabric_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::EntriesPerFabric as u16,
        AttrValue::Uint16(acl::ENTRIES_PER_FABRIC as u16),
        Access::RV,
        Quality::FIXED,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        acl::{AclEntry, AclMgr, AuthMode},
        data_model::{
            core::AttrReadEncoder,
            objects::{AttrDetails, ClusterType, Privilege},
        },
        interaction_model::messages::ib::ListOperation,
        tlv::{get_root_node_struct, ElementType, TLVElement, TLVWriter, TagType, ToTLV},
        utils::writebuf::WriteBuf,
    };

    use super::AccessControlCluster;

    #[test]
    /// Add an ACL entry
    fn acl_cluster_add() {
        let mut buf: [u8; 100] = [0; 100];
        let buf_len = buf.len();
        let mut writebuf = WriteBuf::new(&mut buf, buf_len);
        let mut tw = TLVWriter::new(&mut writebuf);

        let acl_mgr = Arc::new(AclMgr::new_with(false).unwrap());
        let mut acl = AccessControlCluster::new(acl_mgr.clone()).unwrap();

        let new = AclEntry::new(2, Privilege::VIEW, AuthMode::Case);
        new.to_tlv(&mut tw, TagType::Anonymous).unwrap();
        let data = get_root_node_struct(writebuf.as_borrow_slice()).unwrap();

        // Test, ACL has fabric index 2, but the accessing fabric is 1
        //    the fabric index in the TLV should be ignored and the ACL should be created with entry 1
        let result = acl.write_acl_attr(ListOperation::AddItem, &data, 1);
        assert_eq!(result, Ok(()));

        let verifier = AclEntry::new(1, Privilege::VIEW, AuthMode::Case);
        acl_mgr
            .for_each_acl(|a| {
                assert_eq!(*a, verifier);
            })
            .unwrap();
    }

    #[test]
    /// - The listindex used for edit should be relative to the current fabric
    fn acl_cluster_edit() {
        let mut buf: [u8; 100] = [0; 100];
        let buf_len = buf.len();
        let mut writebuf = WriteBuf::new(&mut buf, buf_len);
        let mut tw = TLVWriter::new(&mut writebuf);

        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let acl_mgr = Arc::new(AclMgr::new_with(false).unwrap());
        let mut verifier = [
            AclEntry::new(2, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(1, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(2, Privilege::ADMIN, AuthMode::Case),
        ];
        for i in verifier {
            acl_mgr.add(i).unwrap();
        }
        let mut acl = AccessControlCluster::new(acl_mgr.clone()).unwrap();

        let new = AclEntry::new(2, Privilege::VIEW, AuthMode::Case);
        new.to_tlv(&mut tw, TagType::Anonymous).unwrap();
        let data = get_root_node_struct(writebuf.as_borrow_slice()).unwrap();

        // Test, Edit Fabric 2's index 1 - with accessing fabring as 2 - allow
        let result = acl.write_acl_attr(ListOperation::EditItem(1), &data, 2);
        // Fabric 2's index 1, is actually our index 2, update the verifier
        verifier[2] = new;
        assert_eq!(result, Ok(()));

        // Also validate in the acl_mgr that the entries are in the right order
        let mut index = 0;
        acl_mgr
            .for_each_acl(|a| {
                assert_eq!(*a, verifier[index]);
                index += 1;
            })
            .unwrap();
    }

    #[test]
    /// - The listindex used for delete should be relative to the current fabric
    fn acl_cluster_delete() {
        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let acl_mgr = Arc::new(AclMgr::new_with(false).unwrap());
        let input = [
            AclEntry::new(2, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(1, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(2, Privilege::ADMIN, AuthMode::Case),
        ];
        for i in input {
            acl_mgr.add(i).unwrap();
        }
        let mut acl = AccessControlCluster::new(acl_mgr.clone()).unwrap();
        // data is don't-care actually
        let data = TLVElement::new(TagType::Anonymous, ElementType::True);

        // Test , Delete Fabric 1's index 0
        let result = acl.write_acl_attr(ListOperation::DeleteItem(0), &data, 1);
        assert_eq!(result, Ok(()));

        let verifier = [input[0], input[2]];
        // Also validate in the acl_mgr that the entries are in the right order
        let mut index = 0;
        acl_mgr
            .for_each_acl(|a| {
                assert_eq!(*a, verifier[index]);
                index += 1;
            })
            .unwrap();
    }

    #[test]
    /// - acl read with and without fabric filtering
    fn acl_cluster_read() {
        let mut buf: [u8; 100] = [0; 100];
        let buf_len = buf.len();
        let mut writebuf = WriteBuf::new(&mut buf, buf_len);

        // Add 3 ACLs, belonging to fabric index 2, 1 and 2, in that order
        let acl_mgr = Arc::new(AclMgr::new_with(false).unwrap());
        let input = [
            AclEntry::new(2, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(1, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(2, Privilege::ADMIN, AuthMode::Case),
        ];
        for i in input {
            acl_mgr.add(i).unwrap();
        }
        let acl = AccessControlCluster::new(acl_mgr.clone()).unwrap();
        // Test 1, all 3 entries are read in the response without fabric filtering
        {
            let mut tw = TLVWriter::new(&mut writebuf);
            let mut encoder = AttrReadEncoder::new(&mut tw);
            let attr_details = AttrDetails {
                attr_id: 0,
                list_index: None,
                fab_idx: 1,
                fab_filter: false,
            };
            acl.read_custom_attribute(&mut encoder, &attr_details);
            assert_eq!(
                &[
                    21, 53, 1, 36, 0, 0, 55, 1, 24, 54, 2, 21, 36, 1, 1, 36, 2, 2, 54, 3, 24, 54,
                    4, 24, 36, 254, 2, 24, 21, 36, 1, 1, 36, 2, 2, 54, 3, 24, 54, 4, 24, 36, 254,
                    1, 24, 21, 36, 1, 5, 36, 2, 2, 54, 3, 24, 54, 4, 24, 36, 254, 2, 24, 24, 24,
                    24
                ],
                writebuf.as_borrow_slice()
            );
        }
        writebuf.reset(0);

        // Test 2, only single entry is read in the response with fabric filtering and fabric idx 1
        {
            let mut tw = TLVWriter::new(&mut writebuf);
            let mut encoder = AttrReadEncoder::new(&mut tw);

            let attr_details = AttrDetails {
                attr_id: 0,
                list_index: None,
                fab_idx: 1,
                fab_filter: true,
            };
            acl.read_custom_attribute(&mut encoder, &attr_details);
            assert_eq!(
                &[
                    21, 53, 1, 36, 0, 0, 55, 1, 24, 54, 2, 21, 36, 1, 1, 36, 2, 2, 54, 3, 24, 54,
                    4, 24, 36, 254, 1, 24, 24, 24, 24
                ],
                writebuf.as_borrow_slice()
            );
        }
        writebuf.reset(0);

        // Test 3, only single entry is read in the response with fabric filtering and fabric idx 2
        {
            let mut tw = TLVWriter::new(&mut writebuf);
            let mut encoder = AttrReadEncoder::new(&mut tw);

            let attr_details = AttrDetails {
                attr_id: 0,
                list_index: None,
                fab_idx: 2,
                fab_filter: true,
            };
            acl.read_custom_attribute(&mut encoder, &attr_details);
            assert_eq!(
                &[
                    21, 53, 1, 36, 0, 0, 55, 1, 24, 54, 2, 21, 36, 1, 1, 36, 2, 2, 54, 3, 24, 54,
                    4, 24, 36, 254, 2, 24, 21, 36, 1, 5, 36, 2, 2, 54, 3, 24, 54, 4, 24, 36, 254,
                    2, 24, 24, 24, 24
                ],
                writebuf.as_borrow_slice()
            );
        }
    }
}
