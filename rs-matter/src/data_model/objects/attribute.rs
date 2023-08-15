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
#![allow(clippy::bad_bit_mask)]

use crate::data_model::objects::GlobalElements;

use super::{AttrId, Privilege};
use bitflags::bitflags;
use core::fmt::{self, Debug};

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
        const RF = Self::READ.bits | Self::FAB_SCOPED.bits;
        const RA = Self::READ.bits | Self::NEED_ADMIN.bits;
        const RWVA = Self::READ.bits | Self::WRITE.bits | Self::NEED_VIEW.bits | Self::NEED_ADMIN.bits;
        const RWFA = Self::READ.bits | Self::WRITE.bits | Self::FAB_SCOPED.bits | Self::NEED_ADMIN.bits;
        const RWVM = Self::READ.bits | Self::WRITE.bits | Self::NEED_VIEW.bits | Self::NEED_MANAGE.bits;
        const RWFVM = Self::READ.bits | Self::WRITE.bits | Self::FAB_SCOPED.bits |Self::NEED_VIEW.bits | Self::NEED_MANAGE.bits;
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
        const SCENE = 0x01;      // Short: S
        const PERSISTENT = 0x02; // Short: N
        const FIXED = 0x04;      // Short: F
        const NULLABLE = 0x08;   // Short: X
        /// if best effort reporting is supported then the attribute supports a reporting configuration
        const REPORTABLE = 0x16; // Short: P 

        const SN = Self::SCENE.bits | Self::PERSISTENT.bits;
        const XN = Self::X.bits | Self::N.bits;
        const S = Self::SCENE.bits;
        const N = Self::PERSISTENT.bits;
        const F = Self::FIXED.bits;
        const X = Self::NULLABLE.bits;
        const P = Self::REPORTABLE.bits;
    }
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub id: AttrId,
    pub quality: Quality,
    pub access: Access,
}

impl Attribute {
    pub const fn new(id: AttrId, access: Access, quality: Quality) -> Self {
        Self {
            id,
            access,
            quality,
        }
    }

    pub fn is_system(&self) -> bool {
        Self::is_system_attr(self.id)
    }

    pub fn is_system_attr(attr_id: AttrId) -> bool {
        attr_id >= (GlobalElements::ServerGenCmd as AttrId)
    }
}

impl core::fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
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
