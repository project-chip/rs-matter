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

use crate::{
    acl::AccessReq,
    data_model::objects::{Access, AttrValue, Attribute, EncodeValue, Quality},
    error::*,
    interaction_model::{command::CommandReq, core::IMStatusCode},
    // TODO: This layer shouldn't really depend on the TLV layer, should create an abstraction layer
    tlv::{Nullable, TLVElement, TLVWriter, TagType},
};
use log::error;
use num_derive::FromPrimitive;
use rand::Rng;
use std::fmt::{self, Debug};

use super::Encoder;

pub const ATTRS_PER_CLUSTER: usize = 10;
pub const CMDS_PER_CLUSTER: usize = 8;

#[derive(FromPrimitive, Debug)]
pub enum GlobalElements {
    _ClusterRevision = 0xFFFD,
    FeatureMap = 0xFFFC,
    AttributeList = 0xFFFB,
    _EventList = 0xFFFA,
    _ClientGenCmd = 0xFFF9,
    ServerGenCmd = 0xFFF8,
    FabricIndex = 0xFE,
}

// TODO: What if we instead of creating this, we just pass the AttrData/AttrPath to the read/write
// methods?
/// The Attribute Details structure records the details about the attribute under consideration.
/// Typically this structure is progressively built as we proceed through the request processing.
pub struct AttrDetails {
    /// Fabric Filtering Activated
    pub fab_filter: bool,
    /// The current Fabric Index
    pub fab_idx: u8,
    /// List Index, if any
    pub list_index: Option<Nullable<u16>>,
    /// The actual attribute ID
    pub attr_id: u16,
}

impl AttrDetails {
    pub fn new(fab_idx: u8, fab_filter: bool) -> Self {
        Self {
            fab_filter,
            fab_idx,
            list_index: None,
            attr_id: 0,
        }
    }
}

pub trait ClusterType {
    // TODO: 5 methods is going to be quite expensive for vtables of all the clusters
    fn base(&self) -> &Cluster;
    fn base_mut(&mut self) -> &mut Cluster;
    fn read_custom_attribute(&self, _encoder: &mut dyn Encoder, _attr: &AttrDetails) {}

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req.cmd.path.leaf.map(|a| a as u16);
        println!("Received command: {:?}", cmd);

        Err(IMStatusCode::UnsupportedCommand)
    }

    /// Write an attribute
    ///
    /// Note that if this method is defined, you must handle the write for all the attributes. Even those
    /// that are not 'custom'. This is different from how you handle the read_custom_attribute() method.
    /// The reason for this being, you may want to handle an attribute write request even though it is a
    /// standard attribute like u16, u32 etc.
    ///
    /// If you wish to update the standard attribute in the data model database, you must call the
    /// write_attribute_from_tlv() method from the base cluster, as is shown here in the default case
    fn write_attribute(
        &mut self,
        attr: &AttrDetails,
        data: &TLVElement,
    ) -> Result<(), IMStatusCode> {
        self.base_mut().write_attribute_from_tlv(attr.attr_id, data)
    }
}

pub struct Cluster {
    pub(super) id: u32,
    attributes: Vec<Attribute>,
    data_ver: u32,
}

impl Cluster {
    pub fn new(id: u32) -> Result<Cluster, Error> {
        let mut c = Cluster {
            id,
            attributes: Vec::with_capacity(ATTRS_PER_CLUSTER),
            data_ver: rand::thread_rng().gen_range(0..0xFFFFFFFF),
        };
        c.add_default_attributes()?;
        Ok(c)
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn get_dataver(&self) -> u32 {
        self.data_ver
    }

    pub fn set_feature_map(&mut self, map: u32) -> Result<(), Error> {
        self.write_attribute_raw(GlobalElements::FeatureMap as u16, AttrValue::Uint32(map))
            .map_err(|_| Error::Invalid)?;
        Ok(())
    }

    fn add_default_attributes(&mut self) -> Result<(), Error> {
        // Default feature map is 0
        self.add_attribute(Attribute::new(
            GlobalElements::FeatureMap as u16,
            AttrValue::Uint32(0),
            Access::RV,
            Quality::NONE,
        )?)?;

        self.add_attribute(Attribute::new(
            GlobalElements::AttributeList as u16,
            AttrValue::Custom,
            Access::RV,
            Quality::NONE,
        )?)
    }

    pub fn add_attributes(&mut self, attrs: &[Attribute]) -> Result<(), Error> {
        if self.attributes.len() + attrs.len() <= self.attributes.capacity() {
            self.attributes.extend_from_slice(attrs);
            Ok(())
        } else {
            Err(Error::NoSpace)
        }
    }

    pub fn add_attribute(&mut self, attr: Attribute) -> Result<(), Error> {
        if self.attributes.len() < self.attributes.capacity() {
            self.attributes.push(attr);
            Ok(())
        } else {
            Err(Error::NoSpace)
        }
    }

    fn get_attribute_index(&self, attr_id: u16) -> Option<usize> {
        self.attributes.iter().position(|c| c.id == attr_id)
    }

    fn get_attribute(&self, attr_id: u16) -> Result<&Attribute, Error> {
        let index = self
            .get_attribute_index(attr_id)
            .ok_or(Error::AttributeNotFound)?;
        Ok(&self.attributes[index])
    }

    fn get_attribute_mut(&mut self, attr_id: u16) -> Result<&mut Attribute, Error> {
        let index = self
            .get_attribute_index(attr_id)
            .ok_or(Error::AttributeNotFound)?;
        Ok(&mut self.attributes[index])
    }

    // Returns a slice of attribute, with either a single attribute or all (wildcard)
    pub fn get_wildcard_attribute(
        &self,
        attribute: Option<u16>,
    ) -> Result<(&[Attribute], bool), IMStatusCode> {
        if let Some(a) = attribute {
            if let Some(i) = self.get_attribute_index(a) {
                Ok((&self.attributes[i..i + 1], false))
            } else {
                Err(IMStatusCode::UnsupportedAttribute)
            }
        } else {
            Ok((&self.attributes[..], true))
        }
    }

    pub fn read_attribute(
        c: &dyn ClusterType,
        access_req: &mut AccessReq,
        encoder: &mut dyn Encoder,
        attr: &AttrDetails,
    ) {
        let mut error = IMStatusCode::Sucess;
        let base = c.base();
        let a = if let Ok(a) = base.get_attribute(attr.attr_id) {
            a
        } else {
            encoder.encode_status(IMStatusCode::UnsupportedAttribute, 0);
            return;
        };

        if !a.access.contains(Access::READ) {
            error = IMStatusCode::UnsupportedRead;
        }

        access_req.set_target_perms(a.access);
        if !access_req.allow() {
            error = IMStatusCode::UnsupportedAccess;
        }

        if error != IMStatusCode::Sucess {
            encoder.encode_status(error, 0);
        } else if Attribute::is_system_attr(attr.attr_id) {
            c.base().read_system_attribute(encoder, a)
        } else if a.value != AttrValue::Custom {
            encoder.encode(EncodeValue::Value(&a.value))
        } else {
            c.read_custom_attribute(encoder, attr)
        }
    }

    fn encode_attribute_ids(&self, tag: TagType, tw: &mut TLVWriter) {
        let _ = tw.start_array(tag);
        for a in &self.attributes {
            let _ = tw.u16(TagType::Anonymous, a.id);
        }
        let _ = tw.end_container();
    }

    fn read_system_attribute(&self, encoder: &mut dyn Encoder, attr: &Attribute) {
        let global_attr: Option<GlobalElements> = num::FromPrimitive::from_u16(attr.id);
        if let Some(global_attr) = global_attr {
            match global_attr {
                GlobalElements::AttributeList => {
                    encoder.encode(EncodeValue::Closure(&|tag, tw| {
                        self.encode_attribute_ids(tag, tw)
                    }));
                    return;
                }
                GlobalElements::FeatureMap => {
                    encoder.encode(EncodeValue::Value(&attr.value));
                    return;
                }
                _ => {
                    error!("This attribute not yet handled {:?}", global_attr);
                }
            }
        }
        encoder.encode_status(IMStatusCode::UnsupportedAttribute, 0)
    }

    pub fn read_attribute_raw(&self, attr_id: u16) -> Result<&AttrValue, IMStatusCode> {
        let a = self
            .get_attribute(attr_id)
            .map_err(|_| IMStatusCode::UnsupportedAttribute)?;
        Ok(&a.value)
    }

    pub fn write_attribute(
        c: &mut dyn ClusterType,
        access_req: &mut AccessReq,
        data: &TLVElement,
        attr: &AttrDetails,
    ) -> Result<(), IMStatusCode> {
        let base = c.base_mut();
        let a = if let Ok(a) = base.get_attribute_mut(attr.attr_id) {
            a
        } else {
            return Err(IMStatusCode::UnsupportedAttribute);
        };

        if !a.access.contains(Access::WRITE) {
            return Err(IMStatusCode::UnsupportedWrite);
        }

        access_req.set_target_perms(a.access);
        if !access_req.allow() {
            return Err(IMStatusCode::UnsupportedAccess);
        }

        c.write_attribute(attr, data)
    }

    pub fn write_attribute_from_tlv(
        &mut self,
        attr_id: u16,
        data: &TLVElement,
    ) -> Result<(), IMStatusCode> {
        let a = self.get_attribute_mut(attr_id)?;
        if a.value != AttrValue::Custom {
            let mut value = a.value.clone();
            value
                .update_from_tlv(data)
                .map_err(|_| IMStatusCode::Failure)?;
            a.set_value(value)
                .map(|_| {
                    self.cluster_changed();
                })
                .map_err(|_| IMStatusCode::UnsupportedWrite)
        } else {
            Err(IMStatusCode::UnsupportedAttribute)
        }
    }

    pub fn write_attribute_raw(&mut self, attr_id: u16, value: AttrValue) -> Result<(), Error> {
        let a = self.get_attribute_mut(attr_id)?;
        a.set_value(value).map(|_| {
            self.cluster_changed();
        })
    }

    /// This method must be called for any changes to the data model
    ///     Currently this only increments the data version, but we can reuse the same
    ///     for raising events too
    pub fn cluster_changed(&mut self) {
        self.data_ver = self.data_ver.wrapping_add(1);
    }
}

impl std::fmt::Display for Cluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id:{}, ", self.id)?;
        write!(f, "attrs[")?;
        let mut comma = "";
        for element in self.attributes.iter() {
            write!(f, "{} {}", comma, element)?;
            comma = ",";
        }
        write!(f, " ], ")
    }
}
