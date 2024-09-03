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

use core::{fmt::Display, num::NonZeroU8};

use log::error;

use num_derive::FromPrimitive;

use crate::data_model::objects::{Access, ClusterId, EndptId, Privilege};
use crate::error::{Error, ErrorCode};
use crate::fabric;
use crate::interaction_model::messages::GenericPath;
use crate::tlv::{self, FromTLV, Nullable, TLVElement, TLVList, TLVWriter, TagType, ToTLV};
use crate::transport::session::{Session, SessionMode, MAX_CAT_IDS_PER_NOC};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::WriteBuf;

// Matter Minimum Requirements
pub const SUBJECTS_PER_ENTRY: usize = 4;
pub const TARGETS_PER_ENTRY: usize = 3;
pub const ENTRIES_PER_FABRIC: usize = 3;

// TODO: Check if this and the SessionMode can be combined into some generic data structure
#[derive(FromPrimitive, Copy, Clone, PartialEq, Debug)]
pub enum AuthMode {
    Pase = 1,
    Case = 2,
    Group = 3,
    Invalid = 4,
}

impl FromTLV<'_> for AuthMode {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error>
    where
        Self: Sized,
    {
        num::FromPrimitive::from_u32(t.u32()?)
            .filter(|a| *a != AuthMode::Invalid)
            .ok_or_else(|| ErrorCode::Invalid.into())
    }
}

impl ToTLV for AuthMode {
    fn to_tlv(
        &self,
        tw: &mut crate::tlv::TLVWriter,
        tag: crate::tlv::TagType,
    ) -> Result<(), Error> {
        match self {
            AuthMode::Invalid => Ok(()),
            _ => tw.u8(tag, *self as u8),
        }
    }
}

/// An accessor can have as many identities: one node id and Upto MAX_CAT_IDS_PER_NOC
const MAX_ACCESSOR_SUBJECTS: usize = 1 + MAX_CAT_IDS_PER_NOC;
/// The CAT Prefix used in Subjects
pub const NOC_CAT_SUBJECT_PREFIX: u64 = 0xFFFF_FFFD_0000_0000;
const NOC_CAT_ID_MASK: u64 = 0xFFFF_0000;
const NOC_CAT_VERSION_MASK: u64 = 0xFFFF;

/// Is this identifier a NOC CAT
fn is_noc_cat(id: u64) -> bool {
    (id & NOC_CAT_SUBJECT_PREFIX) == NOC_CAT_SUBJECT_PREFIX
}

/// Get the 16-bit NOC CAT id from the identifier
fn get_noc_cat_id(id: u64) -> u64 {
    (id & NOC_CAT_ID_MASK) >> 16
}

/// Get the 16-bit NOC CAT version from the identifier
fn get_noc_cat_version(id: u64) -> u64 {
    id & NOC_CAT_VERSION_MASK
}

/// Generate CAT that is embeddedable in the NoC
/// This only generates the 32-bit CAT ID
pub fn gen_noc_cat(id: u16, version: u16) -> u32 {
    ((id as u32) << 16) | version as u32
}

/// The Subjects that identify the Accessor
pub struct AccessorSubjects([u64; MAX_ACCESSOR_SUBJECTS]);

impl AccessorSubjects {
    pub fn new(id: u64) -> Self {
        let mut a = Self(Default::default());
        a.0[0] = id;
        a
    }

    pub fn add_catid(&mut self, subject: u32) -> Result<(), Error> {
        for (i, val) in self.0.iter().enumerate() {
            if *val == 0 {
                self.0[i] = NOC_CAT_SUBJECT_PREFIX | (subject as u64);
                return Ok(());
            }
        }
        Err(ErrorCode::NoSpace.into())
    }

    /// Match the match_subject with any of the current subjects
    /// If a NOC CAT is specified, CAT aware matching is also performed
    pub fn matches(&self, acl_subject: u64) -> bool {
        for v in self.0.iter() {
            if *v == 0 {
                continue;
            }

            if *v == acl_subject {
                return true;
            } else {
                // NOC CAT match
                if is_noc_cat(*v)
                    && is_noc_cat(acl_subject)
                    && (get_noc_cat_id(*v) == get_noc_cat_id(acl_subject))
                    && (get_noc_cat_version(*v) >= get_noc_cat_version(acl_subject))
                {
                    return true;
                }
            }
        }

        false
    }
}

impl Display for AccessorSubjects {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
        write!(f, "[")?;
        for i in self.0 {
            if is_noc_cat(i) {
                write!(f, "CAT({} - {})", get_noc_cat_id(i), get_noc_cat_version(i))?;
            } else if i != 0 {
                write!(f, "{}, ", i)?;
            }
        }
        write!(f, "]")
    }
}

/// The Accessor Object
pub struct Accessor<'a> {
    /// The fabric index of the accessor
    pub fab_idx: u8,
    /// Accessor's subject: could be node-id, NoC CAT, group id
    subjects: AccessorSubjects,
    /// The Authmode of this session
    auth_mode: AuthMode,
    // TODO: Is this the right place for this though, or should we just use a global-acl-handle-get
    acl_mgr: &'a RefCell<AclMgr>,
}

impl<'a> Accessor<'a> {
    pub fn for_session(session: &Session, acl_mgr: &'a RefCell<AclMgr>) -> Self {
        match session.get_session_mode() {
            SessionMode::Case {
                fab_idx, cat_ids, ..
            } => {
                let mut subject =
                    AccessorSubjects::new(session.get_peer_node_id().unwrap_or_default());
                for i in *cat_ids {
                    if i != 0 {
                        let _ = subject.add_catid(i);
                    }
                }
                Accessor::new(fab_idx.get(), subject, AuthMode::Case, acl_mgr)
            }
            SessionMode::Pase { fab_idx } => {
                Accessor::new(*fab_idx, AccessorSubjects::new(1), AuthMode::Pase, acl_mgr)
            }

            SessionMode::PlainText => {
                Accessor::new(0, AccessorSubjects::new(1), AuthMode::Invalid, acl_mgr)
            }
        }
    }

    pub const fn new(
        fab_idx: u8,
        subjects: AccessorSubjects,
        auth_mode: AuthMode,
        acl_mgr: &'a RefCell<AclMgr>,
    ) -> Self {
        Self {
            fab_idx,
            subjects,
            auth_mode,
            acl_mgr,
        }
    }
}

#[derive(Debug)]
pub struct AccessDesc {
    /// The object to be acted upon
    path: GenericPath,
    /// The target permissions
    target_perms: Option<Access>,
    // The operation being done
    // TODO: Currently this is Access, but we need a way to represent the 'invoke' somehow too
    operation: Access,
}

/// Access Request Object
pub struct AccessReq<'a> {
    accessor: &'a Accessor<'a>,
    object: AccessDesc,
}

impl<'a> AccessReq<'a> {
    /// Creates an access request object
    ///
    /// An access request specifies the _accessor_ attempting to access _path_
    /// with _operation_
    pub fn new(accessor: &'a Accessor, path: GenericPath, operation: Access) -> Self {
        AccessReq {
            accessor,
            object: AccessDesc {
                path,
                target_perms: None,
                operation,
            },
        }
    }

    pub fn operation(&self) -> Access {
        self.object.operation
    }

    /// Add target's permissions to the request
    ///
    /// The permissions that are associated with the target (identified by the
    /// path in the AccessReq) are added to the request
    pub fn set_target_perms(&mut self, perms: Access) {
        self.object.target_perms = Some(perms);
    }

    /// Checks if access is allowed
    ///
    /// This checks all the ACL list to identify if any of the ACLs provides the
    /// _accessor_ the necessary privileges to access the target as per its
    /// permissions
    pub fn allow(&self) -> bool {
        self.accessor.acl_mgr.borrow().allow(self)
    }
}

#[derive(FromTLV, ToTLV, Clone, Debug, PartialEq)]
pub struct Target {
    cluster: Option<ClusterId>,
    endpoint: Option<EndptId>,
    device_type: Option<u32>,
}

impl Target {
    pub fn new(
        endpoint: Option<EndptId>,
        cluster: Option<ClusterId>,
        device_type: Option<u32>,
    ) -> Self {
        Self {
            cluster,
            endpoint,
            device_type,
        }
    }
}

type Subjects = [Option<u64>; SUBJECTS_PER_ENTRY];

type Targets = Nullable<[Option<Target>; TARGETS_PER_ENTRY]>;
impl Targets {
    fn init_notnull() -> Self {
        const INIT_TARGETS: Option<Target> = None;
        Nullable::NotNull([INIT_TARGETS; TARGETS_PER_ENTRY])
    }
}

#[derive(ToTLV, FromTLV, Clone, Debug, PartialEq)]
#[tlvargs(start = 1)]
pub struct AclEntry {
    privilege: Privilege,
    auth_mode: AuthMode,
    subjects: Subjects,
    targets: Targets,
    // TODO: Instead of the direct value, we should consider GlobalElements::FabricIndex
    // Note that this field will always be `Some(NN)` when the entry is persisted in storage,
    // however, it will be `None` when the entry is coming from the other peer
    #[tagval(0xFE)]
    pub fab_idx: Option<NonZeroU8>,
}

impl AclEntry {
    pub fn new(fab_idx: NonZeroU8, privilege: Privilege, auth_mode: AuthMode) -> Self {
        const INIT_SUBJECTS: Option<u64> = None;
        Self {
            fab_idx: Some(fab_idx),
            privilege,
            auth_mode,
            subjects: [INIT_SUBJECTS; SUBJECTS_PER_ENTRY],
            targets: Targets::init_notnull(),
        }
    }

    pub fn add_subject(&mut self, subject: u64) -> Result<(), Error> {
        let index = self
            .subjects
            .iter()
            .position(|s| s.is_none())
            .ok_or(ErrorCode::NoSpace)?;
        self.subjects[index] = Some(subject);
        Ok(())
    }

    pub fn add_subject_catid(&mut self, cat_id: u32) -> Result<(), Error> {
        self.add_subject(NOC_CAT_SUBJECT_PREFIX | cat_id as u64)
    }

    pub fn add_target(&mut self, target: Target) -> Result<(), Error> {
        if self.targets.is_null() {
            self.targets = Targets::init_notnull();
        }
        let index = self
            .targets
            .as_ref()
            .notnull()
            .unwrap()
            .iter()
            .position(|s| s.is_none())
            .ok_or(ErrorCode::NoSpace)?;

        self.targets.as_mut().notnull().unwrap()[index] = Some(target);

        Ok(())
    }

    fn match_accessor(&self, accessor: &Accessor) -> bool {
        if self.auth_mode != accessor.auth_mode {
            return false;
        }

        let mut allow = false;
        let mut entries_exist = false;
        for i in self.subjects.iter().flatten() {
            entries_exist = true;
            if accessor.subjects.matches(*i) {
                allow = true;
            }
        }
        if !entries_exist {
            // Subjects array empty implies allow for all subjects
            allow = true;
        }

        // true if both are true
        allow
            && self
                .fab_idx
                .map(|fab_idx| fab_idx.get() == accessor.fab_idx)
                .unwrap_or(false)
    }

    fn match_access_desc(&self, object: &AccessDesc) -> bool {
        let mut allow = false;
        let mut entries_exist = false;
        match self.targets.as_ref().notnull() {
            None => allow = true, // Allow if targets are NULL
            Some(targets) => {
                for t in targets.iter().flatten() {
                    entries_exist = true;
                    if (t.endpoint.is_none() || t.endpoint == object.path.endpoint)
                        && (t.cluster.is_none() || t.cluster == object.path.cluster)
                    {
                        allow = true
                    }
                }
            }
        }
        if !entries_exist {
            // Targets array empty implies allow for all targets
            allow = true;
        }

        if allow {
            // Check that the object's access allows this operation with this privilege
            if let Some(access) = object.target_perms {
                access.is_ok(object.operation, self.privilege)
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn allow(&self, req: &AccessReq) -> bool {
        self.match_accessor(req.accessor) && self.match_access_desc(&req.object)
    }
}

const MAX_ACL_ENTRIES: usize = ENTRIES_PER_FABRIC * fabric::MAX_SUPPORTED_FABRICS;

type AclEntries = crate::utils::storage::Vec<Option<AclEntry>, MAX_ACL_ENTRIES>;

pub struct AclMgr {
    entries: AclEntries,
    changed: bool,
}

impl Default for AclMgr {
    fn default() -> Self {
        Self::new()
    }
}

impl AclMgr {
    /// Create a new ACL Manager
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            entries: AclEntries::new(),
            changed: false,
        }
    }

    /// Return an in-place initializer for ACL Manager
    pub fn init() -> impl Init<Self> {
        init!(Self {
            entries <- AclEntries::init(),
            changed: false,
        })
    }

    pub fn erase_all(&mut self) -> Result<(), Error> {
        self.entries.clear();
        self.changed = true;

        Ok(())
    }

    pub fn add(&mut self, entry: AclEntry) -> Result<u8, Error> {
        let Some(fab_idx) = entry.fab_idx else {
            // When persisting entries, the `fab_idx` should always be set
            return Err(ErrorCode::Invalid.into());
        };

        if entry.auth_mode == AuthMode::Pase {
            // Reserved for future use
            // TODO: Should be something that results in IMStatusCode::ConstraintError
            Err(ErrorCode::Invalid)?;
        }

        let cnt = self.get_index_in_fabric(MAX_ACL_ENTRIES, fab_idx);
        if cnt >= ENTRIES_PER_FABRIC as u8 {
            Err(ErrorCode::NoSpace)?;
        }

        let slot = self.entries.iter().position(|a| a.is_none());

        if slot.is_some() || self.entries.len() < MAX_ACL_ENTRIES {
            let slot = if let Some(slot) = slot {
                self.entries[slot] = Some(entry);

                slot
            } else {
                self.entries
                    .push(Some(entry))
                    .map_err(|_| ErrorCode::NoSpace)
                    .unwrap();

                self.entries.len() - 1
            };

            self.changed = true;

            Ok(self.get_index_in_fabric(slot, fab_idx))
        } else {
            Err(ErrorCode::NoSpace.into())
        }
    }

    // Since the entries are fabric-scoped, the index is only for entries with the matching fabric index
    pub fn edit(&mut self, index: u8, fab_idx: NonZeroU8, new: AclEntry) -> Result<(), Error> {
        let old = self.for_index_in_fabric(index, fab_idx)?;
        *old = Some(new);

        self.changed = true;

        Ok(())
    }

    pub fn delete(&mut self, index: u8, fab_idx: NonZeroU8) -> Result<(), Error> {
        let old = self.for_index_in_fabric(index, fab_idx)?;
        *old = None;

        self.changed = true;

        Ok(())
    }

    pub fn delete_for_fabric(&mut self, fab_idx: NonZeroU8) -> Result<(), Error> {
        for entry in &mut self.entries {
            if entry
                .as_ref()
                .map(|e| e.fab_idx == Some(fab_idx))
                .unwrap_or(false)
            {
                *entry = None;
                self.changed = true;
            }
        }

        Ok(())
    }

    pub fn for_each_acl<T>(&self, mut f: T) -> Result<(), Error>
    where
        T: FnMut(&AclEntry) -> Result<(), Error>,
    {
        for entry in self.entries.iter().flatten() {
            f(entry)?;
        }

        Ok(())
    }

    pub fn allow(&self, req: &AccessReq) -> bool {
        // PASE Sessions with no fabric index have implicit access grant,
        // but only as long as the ACL list is empty
        //
        // As per the spec:
        // The Access Control List is able to have an initial entry added because the Access Control Privilege
        // Granting algorithm behaves as if, over a PASE commissioning channel during the commissioning
        // phase, the following implicit Access Control Entry were present on the Commissionee (but not on
        // the Commissioner):
        // Access Control Cluster: {
        //     ACL: [
        //         0: {
        //             // implicit entry only; does not explicitly exist!
        //             FabricIndex: 0, // not fabric-specific
        //             Privilege: Administer,
        //             AuthMode: PASE,
        //             Subjects: [],
        //             Targets: [] // entire node
        //         }
        //     ],
        //     Extension: []
        // }
        if req.accessor.auth_mode == AuthMode::Pase {
            return true;
        }

        for e in self.entries.iter().flatten() {
            if e.allow(req) {
                return true;
            }
        }
        error!(
            "ACL Disallow for subjects {} fab idx {}",
            req.accessor.subjects, req.accessor.fab_idx
        );
        error!("{}", self);
        false
    }

    pub fn load(&mut self, data: &[u8]) -> Result<(), Error> {
        let root = TLVList::new(data).iter().next().ok_or(ErrorCode::Invalid)?;

        tlv::vec_from_tlv(&mut self.entries, &root)?;
        self.changed = false;

        Ok(())
    }

    pub fn store<'a>(&mut self, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        if self.changed {
            let mut wb = WriteBuf::new(buf);
            let mut tw = TLVWriter::new(&mut wb);
            self.entries
                .as_slice()
                .to_tlv(&mut tw, TagType::Anonymous)?;

            self.changed = false;

            let len = tw.get_tail();

            Ok(Some(&buf[..len]))
        } else {
            Ok(None)
        }
    }

    pub fn is_changed(&self) -> bool {
        self.changed
    }

    /// Traverse fabric specific entries to find the index
    ///
    /// If the ACL Mgr has 3 entries with fabric indexes, 1, 2, 1, then the list
    /// index 1 for Fabric 1 in the ACL Mgr will be the actual index 2 (starting from  0)
    fn for_index_in_fabric(
        &mut self,
        index: u8,
        fab_idx: NonZeroU8,
    ) -> Result<&mut Option<AclEntry>, Error> {
        // Can't use flatten as we need to borrow the Option<> not the 'AclEntry'
        for (curr_index, entry) in self
            .entries
            .iter_mut()
            .filter(|e| {
                e.as_ref()
                    .filter(|e1| e1.fab_idx == Some(fab_idx))
                    .is_some()
            })
            .enumerate()
        {
            if curr_index == index as usize {
                return Ok(entry);
            }
        }
        Err(ErrorCode::NotFound.into())
    }

    /// Traverse fabric specific entries to find the index of an entry relative to its fabric.
    ///
    /// If the ACL Mgr has 3 entries with fabric indexes, 1, 2, 1, then the actual
    /// index 2 in the ACL Mgr will be the list index 1 for Fabric 1
    fn get_index_in_fabric(&self, till_slot_index: usize, fab_idx: NonZeroU8) -> u8 {
        self.entries
            .iter()
            .take(till_slot_index)
            .flatten()
            .filter(|e| e.fab_idx == Some(fab_idx))
            .count() as u8
    }
}

impl core::fmt::Display for AclMgr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ACLS: [")?;
        for i in self.entries.iter().flatten() {
            write!(f, "  {{ {:?} }}, ", i)?;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
#[allow(clippy::bool_assert_comparison)]
pub(crate) mod tests {
    use core::num::NonZeroU8;

    use crate::{
        acl::{gen_noc_cat, AccessorSubjects},
        data_model::objects::{Access, Privilege},
        interaction_model::messages::GenericPath,
    };

    use crate::utils::cell::RefCell;

    use super::{AccessReq, Accessor, AclEntry, AclMgr, AuthMode, Target};

    pub(crate) const FAB_1: NonZeroU8 = match NonZeroU8::new(1) {
        Some(f) => f,
        None => unreachable!(),
    };
    pub(crate) const FAB_2: NonZeroU8 = match NonZeroU8::new(2) {
        Some(f) => f,
        None => unreachable!(),
    };
    pub(crate) const FAB_3: NonZeroU8 = match NonZeroU8::new(3) {
        Some(f) => f,
        None => unreachable!(),
    };

    #[test]
    fn test_basic_empty_subject_target() {
        let am = RefCell::new(AclMgr::new());
        am.borrow_mut().erase_all().unwrap();

        let accessor = Accessor::new(0, AccessorSubjects::new(112233), AuthMode::Pase, &am);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req_pase = AccessReq::new(&accessor, path, Access::READ);
        req_pase.set_target_perms(Access::RWVA);

        // Always allow for PASE sessions
        assert!(req_pase.allow());

        let accessor = Accessor::new(2, AccessorSubjects::new(112233), AuthMode::Case, &am);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Default deny for CASE
        assert_eq!(req.allow(), false);

        // Deny adding invalid auth mode (PASE is reserved for future)
        let new = AclEntry::new(FAB_1, Privilege::VIEW, AuthMode::Pase);
        assert!(am.borrow_mut().add(new).is_err());

        // Deny for fab idx mismatch
        let new = AclEntry::new(FAB_1, Privilege::VIEW, AuthMode::Case);
        assert_eq!(am.borrow_mut().add(new).unwrap(), 0);
        assert_eq!(req.allow(), false);

        // Always allow for PASE sessions
        assert!(req_pase.allow());

        // Allow
        let new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        assert_eq!(am.borrow_mut().add(new).unwrap(), 0);
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_subject() {
        let am = RefCell::new(AclMgr::new());
        am.borrow_mut().erase_all().unwrap();
        let accessor = Accessor::new(2, AccessorSubjects::new(112233), AuthMode::Case, &am);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for subject mismatch
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_subject(112232).unwrap();
        assert_eq!(am.borrow_mut().add(new).unwrap(), 0);
        assert_eq!(req.allow(), false);

        // Allow for subject match - target is wildcard
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_subject(112233).unwrap();
        assert_eq!(am.borrow_mut().add(new).unwrap(), 1);
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_cat() {
        let am = RefCell::new(AclMgr::new());
        am.borrow_mut().erase_all().unwrap();

        let allow_cat = 0xABCD;
        let disallow_cat = 0xCAFE;
        let v2 = 2;
        let v3 = 3;
        // Accessor has nodeif and CAT 0xABCD_0002
        let mut subjects = AccessorSubjects::new(112233);
        subjects.add_catid(gen_noc_cat(allow_cat, v2)).unwrap();

        let accessor = Accessor::new(2, subjects, AuthMode::Case, &am);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for CAT id mismatch
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(disallow_cat, v2))
            .unwrap();
        am.borrow_mut().add(new).unwrap();
        assert_eq!(req.allow(), false);

        // Deny of CAT version mismatch
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v3)).unwrap();
        am.borrow_mut().add(new).unwrap();
        assert_eq!(req.allow(), false);

        // Allow for CAT match
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v2)).unwrap();
        am.borrow_mut().add(new).unwrap();
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_cat_version() {
        let am = RefCell::new(AclMgr::new());
        am.borrow_mut().erase_all().unwrap();

        let allow_cat = 0xABCD;
        let disallow_cat = 0xCAFE;
        let v2 = 2;
        let v3 = 3;
        // Accessor has nodeif and CAT 0xABCD_0003
        let mut subjects = AccessorSubjects::new(112233);
        subjects.add_catid(gen_noc_cat(allow_cat, v3)).unwrap();

        let accessor = Accessor::new(2, subjects, AuthMode::Case, &am);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for CAT id mismatch
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(disallow_cat, v2))
            .unwrap();
        am.borrow_mut().add(new).unwrap();
        assert_eq!(req.allow(), false);

        // Allow for CAT match and version more than ACL version
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v2)).unwrap();
        am.borrow_mut().add(new).unwrap();
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_target() {
        let am = RefCell::new(AclMgr::new());
        am.borrow_mut().erase_all().unwrap();
        let accessor = Accessor::new(2, AccessorSubjects::new(112233), AuthMode::Case, &am);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for target mismatch
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(2),
            endpoint: Some(4567),
            device_type: None,
        })
        .unwrap();
        am.borrow_mut().add(new).unwrap();
        assert_eq!(req.allow(), false);

        // Allow for cluster match - subject wildcard
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(1234),
            endpoint: None,
            device_type: None,
        })
        .unwrap();
        am.borrow_mut().add(new).unwrap();
        assert_eq!(req.allow(), true);

        // Clean Slate
        am.borrow_mut().erase_all().unwrap();

        // Allow for endpoint match - subject wildcard
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: None,
            endpoint: Some(1),
            device_type: None,
        })
        .unwrap();
        am.borrow_mut().add(new).unwrap();
        assert_eq!(req.allow(), true);

        // Clean Slate
        am.borrow_mut().erase_all().unwrap();

        // Allow for exact match
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(1234),
            endpoint: Some(1),
            device_type: None,
        })
        .unwrap();
        new.add_subject(112233).unwrap();
        am.borrow_mut().add(new).unwrap();
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_privilege() {
        let am = RefCell::new(AclMgr::new());
        am.borrow_mut().erase_all().unwrap();
        let accessor = Accessor::new(2, AccessorSubjects::new(112233), AuthMode::Case, &am);
        let path = GenericPath::new(Some(1), Some(1234), None);

        // Create an Exact Match ACL with View privilege
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(1234),
            endpoint: Some(1),
            device_type: None,
        })
        .unwrap();
        new.add_subject(112233).unwrap();
        am.borrow_mut().add(new).unwrap();

        // Write on an RWVA without admin access - deny
        let mut req = AccessReq::new(&accessor, path.clone(), Access::WRITE);
        req.set_target_perms(Access::RWVA);
        assert_eq!(req.allow(), false);

        // Create an Exact Match ACL with Admin privilege
        let mut new = AclEntry::new(FAB_2, Privilege::ADMIN, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(1234),
            endpoint: Some(1),
            device_type: None,
        })
        .unwrap();
        new.add_subject(112233).unwrap();
        am.borrow_mut().add(new).unwrap();

        // Write on an RWVA with admin access - allow
        let mut req = AccessReq::new(&accessor, path, Access::WRITE);
        req.set_target_perms(Access::RWVA);
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_delete_for_fabric() {
        let am = RefCell::new(AclMgr::new());
        am.borrow_mut().erase_all().unwrap();
        let path = GenericPath::new(Some(1), Some(1234), None);
        let accessor2 = Accessor::new(2, AccessorSubjects::new(112233), AuthMode::Case, &am);
        let mut req2 = AccessReq::new(&accessor2, path.clone(), Access::READ);
        req2.set_target_perms(Access::RWVA);
        let accessor3 = Accessor::new(3, AccessorSubjects::new(112233), AuthMode::Case, &am);
        let mut req3 = AccessReq::new(&accessor3, path, Access::READ);
        req3.set_target_perms(Access::RWVA);

        // Allow for subject match - target is wildcard - Fabric idx 2
        let mut new = AclEntry::new(FAB_2, Privilege::VIEW, AuthMode::Case);
        new.add_subject(112233).unwrap();
        assert_eq!(am.borrow_mut().add(new).unwrap(), 0);

        // Allow for subject match - target is wildcard - Fabric idx 3
        let mut new = AclEntry::new(FAB_3, Privilege::VIEW, AuthMode::Case);
        new.add_subject(112233).unwrap();
        assert_eq!(am.borrow_mut().add(new).unwrap(), 0);

        // Req for Fabric idx 2 gets denied, and that for Fabric idx 3 is allowed
        assert_eq!(req2.allow(), true);
        assert_eq!(req3.allow(), true);
        am.borrow_mut().delete_for_fabric(FAB_2).unwrap();
        assert_eq!(req2.allow(), false);
        assert_eq!(req3.allow(), true);
    }
}
