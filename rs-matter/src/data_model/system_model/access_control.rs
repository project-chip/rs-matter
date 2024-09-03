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

use core::num::NonZeroU8;

use strum::{EnumDiscriminants, FromRepr};

use log::{error, info};

use crate::acl::{self, AclEntry, AclMgr};
use crate::data_model::objects::*;
use crate::interaction_model::messages::ib::{attr_list_write, ListOperation};
use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV};
use crate::transport::exchange::Exchange;
use crate::{attribute_enum, error::*};

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

#[derive(Debug, Clone)]
pub struct AccessControlCluster {
    data_ver: Dataver,
}

impl AccessControlCluster {
    pub const fn new(data_ver: Dataver) -> Self {
        Self { data_ver }
    }

    pub fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        self.read_acl_attr(&exchange.matter().acl_mgr.borrow(), attr, encoder)
    }

    pub fn write(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        data: AttrData,
    ) -> Result<(), Error> {
        match attr.attr_id.try_into()? {
            Attributes::Acl(_) => {
                attr_list_write(attr, data.with_dataver(self.data_ver.get())?, |op, data| {
                    self.write_acl_attr(
                        &mut exchange.matter().acl_mgr.borrow_mut(),
                        &op,
                        data,
                        NonZeroU8::new(attr.fab_idx).ok_or(ErrorCode::Invalid)?,
                    )
                })
            }
            _ => {
                error!("Attribute not yet supported: this shouldn't happen");
                Err(ErrorCode::AttributeNotFound.into())
            }
        }
    }

    fn read_acl_attr(
        &self,
        acl_mgr: &AclMgr,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::Acl(_) => {
                        writer.start_array(&AttrDataWriter::TAG)?;
                        acl_mgr.for_each_acl(|entry| {
                            if !attr.fab_filter
                                || entry
                                    .fab_idx
                                    .map(|fi| fi.get() == attr.fab_idx)
                                    .unwrap_or(false)
                            {
                                entry.to_tlv(&TLVTag::Anonymous, &mut *writer)?;
                            }

                            Ok(())
                        })?;
                        writer.end_container()?;

                        writer.complete()
                    }
                    Attributes::Extension(_) => {
                        // Empty for now
                        writer.start_array(&AttrDataWriter::TAG)?;
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

    /// Write the ACL Attribute
    ///
    /// This takes care of 4 things, add item, edit item, delete item, delete list.
    /// Care about fabric-scoped behaviour is taken
    fn write_acl_attr(
        &self,
        acl_mgr: &mut AclMgr,
        op: &ListOperation,
        data: &TLVElement,
        fab_idx: NonZeroU8,
    ) -> Result<(), Error> {
        info!("Performing ACL operation {:?}", op);
        match op {
            ListOperation::AddItem | ListOperation::EditItem(_) => {
                let mut acl_entry = AclEntry::from_tlv(data)?;
                info!("ACL  {:?}", acl_entry);
                // Overwrite the fabric index with our accessing fabric index
                acl_entry.fab_idx = Some(fab_idx);

                if let ListOperation::EditItem(index) = op {
                    acl_mgr.edit(*index as u8, fab_idx, acl_entry)?;
                } else {
                    acl_mgr.add(acl_entry)?;
                }

                Ok(())
            }
            ListOperation::DeleteItem(index) => acl_mgr.delete(*index as u8, fab_idx),
            ListOperation::DeleteList => acl_mgr.delete_for_fabric(fab_idx),
        }
    }
}

impl Handler for AccessControlCluster {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        AccessControlCluster::read(self, exchange, attr, encoder)
    }

    fn write(&self, exchange: &Exchange, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        AccessControlCluster::write(self, exchange, attr, data)
    }
}

impl NonBlockingHandler for AccessControlCluster {}

impl ChangeNotifier<()> for AccessControlCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}

#[cfg(test)]
mod tests {
    use crate::acl::{AclEntry, AclMgr, AuthMode};
    use crate::data_model::objects::{AttrDataEncoder, AttrDetails, Node, Privilege};
    use crate::data_model::system_model::access_control::Dataver;
    use crate::interaction_model::messages::ib::ListOperation;
    use crate::tlv::{
        get_root_node_struct, TLVControl, TLVElement, TLVTag, TLVTagType, TLVValueType, TLVWriter,
        ToTLV,
    };
    use crate::utils::storage::WriteBuf;

    use super::AccessControlCluster;

    use crate::acl::tests::{FAB_1, FAB_2};

    #[test]
    /// Add an ACL entry
    fn acl_cluster_add() {
        let mut buf: [u8; 100] = [0; 100];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWriter::new(&mut writebuf);

        let mut acl_mgr = AclMgr::new();
        let acl = AccessControlCluster::new(Dataver::new(0));

        let new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.to_tlv(&TLVTag::Anonymous, &mut tw).unwrap();
        let data = get_root_node_struct(writebuf.as_slice()).unwrap();

        // Test, ACL has fabric index 2, but the accessing fabric is 1
        //    the fabric index in the TLV should be ignored and the ACL should be created with entry 1
        let result = acl.write_acl_attr(&mut acl_mgr, &ListOperation::AddItem, &data, FAB_1);
        assert!(result.is_ok());

        let verifier = AclEntry::new(FAB_1, Privilege::VIEW, AuthMode::Case);
        acl_mgr
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
        let mut acl_mgr = AclMgr::new();
        let mut verifier = [
            AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(FAB_1, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(FAB_2, Privilege::ADMIN, AuthMode::Case),
        ];
        for i in &verifier {
            acl_mgr.add(i.clone()).unwrap();
        }
        let acl = AccessControlCluster::new(Dataver::new(0));

        let new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.to_tlv(&TLVTag::Anonymous, &mut tw).unwrap();
        let data = get_root_node_struct(writebuf.as_slice()).unwrap();

        // Test, Edit Fabric 2's index 1 - with accessing fabring as 2 - allow
        let result = acl.write_acl_attr(&mut acl_mgr, &ListOperation::EditItem(1), &data, FAB_2);
        // Fabric 2's index 1, is actually our index 2, update the verifier
        verifier[2] = new;
        assert!(result.is_ok());

        // Also validate in the acl_mgr that the entries are in the right order
        let mut index = 0;
        acl_mgr
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
        let mut acl_mgr = AclMgr::new();
        let input = [
            AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(FAB_1, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(FAB_2, Privilege::ADMIN, AuthMode::Case),
        ];
        for i in &input {
            acl_mgr.add(i.clone()).unwrap();
        }
        let acl = AccessControlCluster::new(Dataver::new(0));
        // data is don't-care actually
        let data = &[TLVControl::new(TLVTagType::Anonymous, TLVValueType::Null).as_raw()];
        let data = TLVElement::new(data.as_slice());

        // Test , Delete Fabric 1's index 0
        let result = acl.write_acl_attr(&mut acl_mgr, &ListOperation::DeleteItem(0), &data, FAB_1);
        assert!(result.is_ok());

        let verifier = [input[0].clone(), input[2].clone()];
        // Also validate in the acl_mgr that the entries are in the right order
        let mut index = 0;
        acl_mgr
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
        let mut acl_mgr = AclMgr::new();
        let input = [
            AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(FAB_1, Privilege::VIEW, AuthMode::Case),
            AclEntry::new(FAB_2, Privilege::ADMIN, AuthMode::Case),
        ];
        for i in input {
            acl_mgr.add(i).unwrap();
        }
        let acl = AccessControlCluster::new(Dataver::new(0));
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

            acl.read_acl_attr(&acl_mgr, &attr, encoder).unwrap();
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

            acl.read_acl_attr(&acl_mgr, &attr, encoder).unwrap();
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

            acl.read_acl_attr(&acl_mgr, &attr, encoder).unwrap();
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
