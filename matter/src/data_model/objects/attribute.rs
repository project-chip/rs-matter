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

use super::{GlobalElements, Privilege};
use crate::{
    error::*,
    // TODO: This layer shouldn't really depend on the TLV layer, should create an abstraction layer
    tlv::{TLVElement, TLVWriter, TagType, ToTLV},
};
use bitflags::bitflags;
use log::error;
use std::fmt::{self, Debug, Formatter};

bitflags! {
    #[derive(Default)]
    pub struct Access: u16 {
        // These must match the bits in the Privilege object :-|
        const NEED_VIEW = 0x00001;
        const NEED_OPERATE = 0x0002;
        const NEED_MANAGE = 0x0004;
        const NEED_ADMIN = 0x0008;

        const READ = 0x0010;
        const WRITE = 0x0020;
        const FAB_SCOPED = 0x0040;
        const FAB_SENSITIVE = 0x0080;
        const TIMED_ONLY = 0x0100;

        const READ_PRIVILEGE_MASK = Self::NEED_VIEW.bits | Self::NEED_MANAGE.bits | Self::NEED_OPERATE.bits | Self::NEED_ADMIN.bits;
        const WRITE_PRIVILEGE_MASK = Self::NEED_MANAGE.bits | Self::NEED_OPERATE.bits | Self::NEED_ADMIN.bits;
        const RV = Self::READ.bits | Self::NEED_VIEW.bits;
        const RWVA = Self::READ.bits | Self::WRITE.bits | Self::NEED_VIEW.bits | Self::NEED_ADMIN.bits;
        const RWFA = Self::READ.bits | Self::WRITE.bits | Self::FAB_SCOPED.bits | Self::NEED_ADMIN.bits;
        const RWVM = Self::READ.bits | Self::WRITE.bits | Self::NEED_VIEW.bits | Self::NEED_MANAGE.bits;
    }
}

impl Access {
    pub fn is_ok(&self, operation: Access, privilege: Privilege) -> bool {
        let required = if operation.contains(Access::READ) {
            *self & Access::READ_PRIVILEGE_MASK
        } else if operation.contains(Access::WRITE) {
            *self & Access::WRITE_PRIVILEGE_MASK
        } else {
            return false;
        };

        if required.is_empty() {
            // There must be some required privilege for any object
            return false;
        }

        if ((privilege.bits() as u16) & required.bits()) == 0 {
            return false;
        }

        self.contains(operation)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct Quality: u8 {
        const NONE = 0x00;
        const SCENE = 0x01;
        const PERSISTENT = 0x02;
        const FIXED = 0x03;
        const NULLABLE = 0x04;
    }
}

/* This file needs some major revamp.
 * - instead of allocating all over the heap, we should use some kind of slab/block allocator
 * - instead of arrays, can use linked-lists to conserve space and avoid the internal fragmentation
 */

#[derive(PartialEq, Clone)]
pub enum AttrValue {
    Int64(i64),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Bool(bool),
    Utf8(String),
    Custom,
}

impl Debug for AttrValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &self {
            AttrValue::Int64(v) => write!(f, "{:?}", *v),
            AttrValue::Uint8(v) => write!(f, "{:?}", *v),
            AttrValue::Uint16(v) => write!(f, "{:?}", *v),
            AttrValue::Uint32(v) => write!(f, "{:?}", *v),
            AttrValue::Uint64(v) => write!(f, "{:?}", *v),
            AttrValue::Bool(v) => write!(f, "{:?}", *v),
            AttrValue::Utf8(v) => write!(f, "{:?}", *v),
            AttrValue::Custom => write!(f, "custom-attribute"),
        }?;
        Ok(())
    }
}

impl ToTLV for AttrValue {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        // What is the time complexity of such long match statements?
        match self {
            AttrValue::Bool(v) => tw.bool(tag_type, *v),
            AttrValue::Uint8(v) => tw.u8(tag_type, *v),
            AttrValue::Uint16(v) => tw.u16(tag_type, *v),
            AttrValue::Uint32(v) => tw.u32(tag_type, *v),
            AttrValue::Uint64(v) => tw.u64(tag_type, *v),
            AttrValue::Utf8(v) => tw.utf8(tag_type, v.as_bytes()),
            _ => {
                error!("Attribute type not yet supported");
                Err(Error::AttributeNotFound)
            }
        }
    }
}

impl AttrValue {
    pub fn update_from_tlv(&mut self, tr: &TLVElement) -> Result<(), Error> {
        match self {
            AttrValue::Bool(v) => *v = tr.bool()?,
            AttrValue::Uint8(v) => *v = tr.u8()?,
            AttrValue::Uint16(v) => *v = tr.u16()?,
            AttrValue::Uint32(v) => *v = tr.u32()?,
            AttrValue::Uint64(v) => *v = tr.u64()?,
            _ => {
                error!("Attribute type not yet supported");
                return Err(Error::AttributeNotFound);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub(super) id: u16,
    pub(super) value: AttrValue,
    pub(super) quality: Quality,
    pub(super) access: Access,
}

impl Default for Attribute {
    fn default() -> Attribute {
        Attribute {
            id: 0,
            value: AttrValue::Bool(true),
            quality: Default::default(),
            access: Default::default(),
        }
    }
}

impl Attribute {
    pub fn new(
        id: u16,
        value: AttrValue,
        access: Access,
        quality: Quality,
    ) -> Result<Attribute, Error> {
        Ok(Attribute {
            id,
            value,
            access,
            quality,
        })
    }

    pub fn set_value(&mut self, value: AttrValue) -> Result<(), Error> {
        if !self.quality.contains(Quality::FIXED) {
            self.value = value;
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }

    pub fn is_system_attr(attr_id: u16) -> bool {
        attr_id >= (GlobalElements::ServerGenCmd as u16)
    }
}

impl std::fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.id, self.value)
    }
}

#[cfg(test)]
#[allow(clippy::bool_assert_comparison)]
mod tests {
    use super::Access;
    use crate::data_model::objects::Privilege;

    #[test]
    fn test_read() {
        let c = Access::READ;
        // Read without NEED_VIEW, implies No Read is possible
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), false);

        let c = Access::WRITE | Access::NEED_VIEW;
        // Read without Read, implies No Read is possible
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), false);

        let c = Access::RV;
        // Read with View or Admin privilege
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::ADMIN), true);

        let c = Access::READ | Access::NEED_ADMIN;
        // Read without Admin privilege
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), false);
        assert_eq!(c.is_ok(Access::READ, Privilege::OPERATE), false);
        assert_eq!(c.is_ok(Access::READ, Privilege::MANAGE), false);
        assert_eq!(c.is_ok(Access::READ, Privilege::ADMIN), true);

        let c = Access::READ | Access::NEED_OPERATE;
        // Read without Operate privilege
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), false);
        assert_eq!(c.is_ok(Access::READ, Privilege::OPERATE), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::MANAGE), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::ADMIN), true);
    }

    #[test]
    fn test_write() {
        let c = Access::WRITE;
        // Write NEED_*, implies No Write is possible
        assert_eq!(c.is_ok(Access::WRITE, Privilege::VIEW), false);

        let c = Access::READ | Access::NEED_MANAGE;
        // Write without Write, implies No Write is possible
        assert_eq!(c.is_ok(Access::WRITE, Privilege::MANAGE), false);

        let c = Access::RWVA;
        // Write with View and Admin privilege
        assert_eq!(c.is_ok(Access::WRITE, Privilege::VIEW), false);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::ADMIN), true);

        let c = Access::RWVA;
        // WRITE without Admin privilege
        assert_eq!(c.is_ok(Access::WRITE, Privilege::VIEW), false);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::OPERATE), false);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::MANAGE), false);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::ADMIN), true);
        // Read with View Privilege
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::OPERATE), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::MANAGE), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::ADMIN), true);

        let c = Access::WRITE | Access::NEED_OPERATE;
        // WRITE without Operate privilege
        assert_eq!(c.is_ok(Access::WRITE, Privilege::VIEW), false);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::OPERATE), true);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::MANAGE), true);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::ADMIN), true);
    }
}
