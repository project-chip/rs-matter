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

use crate::dm::clusters::acl::AccessControlEntryPrivilegeEnum;
use crate::error::Error;
use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};
use crate::utils::bitflags::bitflags;

bitflags! {
    #[repr(transparent)]
    #[derive(Default)]
    #[cfg_attr(not(feature = "defmt"), derive(Debug, Copy, Clone, Eq, PartialEq, Hash))]
    pub struct Privilege: u8 {
        const V = 0x01;
        const O = 0x02;
        const M = 0x04;
        const A = 0x08;

        const VIEW = Self::V.bits();
        const OPERATE = Self::V.bits() | Self::O.bits();
        const MANAGE = Self::V.bits() | Self::O.bits() | Self::M.bits();
        const ADMIN = Self::V.bits() | Self::O.bits() | Self::M.bits() | Self::A.bits();
    }
}

impl FromTLV<'_> for Privilege {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(AccessControlEntryPrivilegeEnum::from_tlv(t)?.into())
    }
}

impl ToTLV for Privilege {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        AccessControlEntryPrivilegeEnum::from(*self).to_tlv(tag, tw)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        TLV::u8(tag, AccessControlEntryPrivilegeEnum::from(*self) as _).into_tlv_iter()
    }
}

impl From<Privilege> for AccessControlEntryPrivilegeEnum {
    fn from(value: Privilege) -> Self {
        if value.contains(Privilege::A) {
            AccessControlEntryPrivilegeEnum::Administer
        } else if value.contains(Privilege::M) {
            AccessControlEntryPrivilegeEnum::Manage
        } else if value.contains(Privilege::O) {
            AccessControlEntryPrivilegeEnum::Operate
        } else if value.contains(Privilege::V) {
            AccessControlEntryPrivilegeEnum::View
        } else {
            unreachable!()
        }
    }
}

impl From<AccessControlEntryPrivilegeEnum> for Privilege {
    fn from(value: AccessControlEntryPrivilegeEnum) -> Self {
        match value {
            AccessControlEntryPrivilegeEnum::View => Privilege::VIEW,
            AccessControlEntryPrivilegeEnum::Manage => Privilege::MANAGE,
            AccessControlEntryPrivilegeEnum::Operate => Privilege::OPERATE,
            AccessControlEntryPrivilegeEnum::Administer => Privilege::ADMIN,
            _ => Privilege::empty(),
        }
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Default)]
    #[cfg_attr(not(feature = "defmt"), derive(Debug, Copy, Clone, Eq, PartialEq, Hash))]
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

        const READ_PRIVILEGE_MASK = Self::NEED_VIEW.bits() | Self::NEED_MANAGE.bits() | Self::NEED_OPERATE.bits() | Self::NEED_ADMIN.bits();
        const WRITE_PRIVILEGE_MASK = Self::NEED_MANAGE.bits() | Self::NEED_OPERATE.bits() | Self::NEED_ADMIN.bits();
        const RV = Self::READ.bits() | Self::NEED_VIEW.bits();
        const RF = Self::READ.bits() | Self::FAB_SCOPED.bits();
        const RA = Self::READ.bits() | Self::NEED_ADMIN.bits();
        const RWVA = Self::READ.bits() | Self::WRITE.bits() | Self::NEED_VIEW.bits() | Self::NEED_ADMIN.bits();
        const RWFA = Self::READ.bits() | Self::WRITE.bits() | Self::FAB_SCOPED.bits() | Self::NEED_ADMIN.bits();
        const RWVM = Self::READ.bits() | Self::WRITE.bits() | Self::NEED_VIEW.bits() | Self::NEED_MANAGE.bits();
        const RWFVM = Self::READ.bits() | Self::WRITE.bits() | Self::FAB_SCOPED.bits() |Self::NEED_VIEW.bits() | Self::NEED_MANAGE.bits();

        const WO = Self::WRITE.bits() | Self::NEED_OPERATE.bits() | Self::NEED_MANAGE.bits() | Self::NEED_ADMIN.bits();
        const WM = Self::WRITE.bits() | Self::NEED_MANAGE.bits() | Self::NEED_ADMIN.bits();
        const WA = Self::WRITE.bits() | Self::NEED_ADMIN.bits();
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
    #[repr(transparent)]
    #[derive(Default)]
    #[cfg_attr(not(feature = "defmt"), derive(Debug, Copy, Clone, Eq, PartialEq, Hash))]
    pub struct Quality: u8 {
        const NONE = 0x00;
        const SCENE = 0x01;      // Short: S
        const PERSISTENT = 0x02; // Short: N
        const FIXED = 0x04;      // Short: F
        const NULLABLE = 0x08;   // Short: X
        const OPTIONAL = 0x10;   // Short: O

        const SN = Self::SCENE.bits() | Self::PERSISTENT.bits();
        const S = Self::SCENE.bits();
        const N = Self::PERSISTENT.bits();
        const F = Self::FIXED.bits();
        const X = Self::NULLABLE.bits();
        const O = Self::OPTIONAL.bits();
    }
}
