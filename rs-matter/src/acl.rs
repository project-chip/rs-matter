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

use num_derive::FromPrimitive;

use crate::data_model::objects::{Access, ClusterId, EndptId, Privilege};
use crate::error::{Error, ErrorCode};
use crate::fabric::FabricMgr;
use crate::interaction_model::messages::GenericPath;
use crate::tlv::{EitherIter, FromTLV, Nullable, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};
use crate::transport::session::{Session, SessionMode, MAX_CAT_IDS_PER_NOC};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;

/// Max subjects per ACL entry
// TODO: Make this configurable via a cargo feature
pub const SUBJECTS_PER_ENTRY: usize = 4;

/// Max targets per ACL entry
// TODO: Make this configurable via a cargo feature
pub const TARGETS_PER_ENTRY: usize = 3;

/// Max ACL entries per fabric
// TODO: Make this configurable via a cargo feature
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
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        match self {
            AuthMode::Invalid => Ok(()),
            _ => tw.u8(tag, *self as u8),
        }
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        match self {
            AuthMode::Invalid => EitherIter::First(core::iter::empty()),
            _ => EitherIter::Second(TLV::u8(tag, *self as u8).into_tlv_iter()),
        }
    }
}

/// An accessor can have as many identities: one node id and up to MAX_CAT_IDS_PER_NOC
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
    fabric_mgr: &'a RefCell<FabricMgr>,
}

impl<'a> Accessor<'a> {
    pub fn for_session(session: &Session, fabric_mgr: &'a RefCell<FabricMgr>) -> Self {
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
                Accessor::new(fab_idx.get(), subject, AuthMode::Case, fabric_mgr)
            }
            SessionMode::Pase { fab_idx } => Accessor::new(
                *fab_idx,
                AccessorSubjects::new(1),
                AuthMode::Pase,
                fabric_mgr,
            ),

            SessionMode::PlainText => {
                Accessor::new(0, AccessorSubjects::new(1), AuthMode::Invalid, fabric_mgr)
            }
        }
    }

    pub const fn new(
        fab_idx: u8,
        subjects: AccessorSubjects,
        auth_mode: AuthMode,
        fabric_mgr: &'a RefCell<FabricMgr>,
    ) -> Self {
        Self {
            fab_idx,
            subjects,
            auth_mode,
            fabric_mgr,
        }
    }

    pub fn subjects(&self) -> &AccessorSubjects {
        &self.subjects
    }

    pub fn auth_mode(&self) -> AuthMode {
        self.auth_mode
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

    pub fn accessor(&self) -> &Accessor {
        self.accessor
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
        self.accessor.fabric_mgr.borrow().allow(self)
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

#[derive(ToTLV, FromTLV, Clone, Debug, PartialEq)]
#[tlvargs(start = 1)]
pub struct AclEntry {
    privilege: Privilege,
    auth_mode: AuthMode,
    subjects: Vec<u64, SUBJECTS_PER_ENTRY>,
    targets: Nullable<Vec<Target, TARGETS_PER_ENTRY>>,
    // TODO: Instead of the direct value, we should consider GlobalElements::FabricIndex
    // Note that this field will always be `Some(NN)` when the entry is persisted in storage,
    // however, it will be `None` when the entry is coming from the other peer
    #[tagval(0xFE)]
    pub fab_idx: Option<NonZeroU8>,
}

impl AclEntry {
    pub fn new(privilege: Privilege, auth_mode: AuthMode) -> Self {
        Self {
            fab_idx: None,
            privilege,
            auth_mode,
            subjects: Vec::new(),
            targets: Nullable::some(Vec::new()),
        }
    }

    pub fn init(privilege: Privilege, auth_mode: AuthMode) -> impl Init<Self> {
        init!(Self {
            fab_idx: None,
            privilege,
            auth_mode,
            subjects <- Vec::init(),
            targets <- Nullable::init_some(Vec::init()),
        })
    }

    pub fn add_subject(&mut self, subject: u64) -> Result<(), Error> {
        self.subjects
            .push(subject)
            .map_err(|_| ErrorCode::NoSpace.into())
    }

    pub fn add_subject_catid(&mut self, cat_id: u32) -> Result<(), Error> {
        self.add_subject(NOC_CAT_SUBJECT_PREFIX | cat_id as u64)
    }

    pub fn add_target(&mut self, target: Target) -> Result<(), Error> {
        if self.targets.is_none() {
            self.targets.reinit(Nullable::init_some(Vec::init()));
        }

        self.targets
            .as_mut()
            .unwrap()
            .push(target)
            .map_err(|_| ErrorCode::NoSpace.into())
    }

    pub fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    fn match_accessor(&self, accessor: &Accessor) -> bool {
        if self.auth_mode != accessor.auth_mode {
            return false;
        }

        let mut allow = false;
        let mut entries_exist = false;
        for s in &self.subjects {
            entries_exist = true;
            if accessor.subjects.matches(*s) {
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
        match self.targets.as_ref() {
            None => allow = true, // Allow if targets are NULL
            Some(targets) => {
                for t in targets {
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

#[cfg(test)]
#[allow(clippy::bool_assert_comparison)]
pub(crate) mod tests {
    use core::num::NonZeroU8;

    use crate::acl::{gen_noc_cat, AccessorSubjects};
    use crate::crypto::KeyPair;
    use crate::data_model::objects::{Access, Privilege};
    use crate::fabric::FabricMgr;
    use crate::interaction_model::messages::GenericPath;
    use crate::utils::cell::RefCell;
    use crate::utils::rand::sys_rand;

    use super::{AccessReq, Accessor, AclEntry, AuthMode, Target};

    pub(crate) const FAB_1: NonZeroU8 = match NonZeroU8::new(1) {
        Some(f) => f,
        None => unreachable!(),
    };

    pub(crate) const FAB_2: NonZeroU8 = match NonZeroU8::new(2) {
        Some(f) => f,
        None => unreachable!(),
    };

    #[test]
    fn test_basic_empty_subject_target() {
        let fm = RefCell::new(FabricMgr::new());

        let accessor = Accessor::new(0, AccessorSubjects::new(112233), AuthMode::Pase, &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req_pase = AccessReq::new(&accessor, path, Access::READ);
        req_pase.set_target_perms(Access::RWVA);

        // Always allow for PASE sessions
        assert!(req_pase.allow());

        let accessor = Accessor::new(2, AccessorSubjects::new(112233), AuthMode::Case, &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Default deny for CASE
        assert_eq!(req.allow(), false);

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(sys_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Deny adding invalid auth mode (PASE is reserved for future)
        let new = AclEntry::new(Privilege::VIEW, AuthMode::Pase);
        assert!(fm.borrow_mut().acl_add(FAB_1, new).is_err());

        // Deny for fab idx mismatch
        let new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        assert_eq!(fm.borrow_mut().acl_add(FAB_1, new).unwrap(), 0);
        assert_eq!(req.allow(), false);

        // Always allow for PASE sessions
        assert!(req_pase.allow());

        // Add fabric with ID 2
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(sys_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Allow
        let new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        assert_eq!(fm.borrow_mut().acl_add(FAB_2, new).unwrap(), 0);
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_subject() {
        let fm = RefCell::new(FabricMgr::new());

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(sys_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let accessor = Accessor::new(1, AccessorSubjects::new(112233), AuthMode::Case, &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for subject mismatch
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_subject(112232).unwrap();
        assert_eq!(fm.borrow_mut().acl_add(FAB_1, new).unwrap(), 0);
        assert_eq!(req.allow(), false);

        // Allow for subject match - target is wildcard
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_subject(112233).unwrap();
        assert_eq!(fm.borrow_mut().acl_add(FAB_1, new).unwrap(), 1);
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_cat() {
        let fm = RefCell::new(FabricMgr::new());

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(sys_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let allow_cat = 0xABCD;
        let disallow_cat = 0xCAFE;
        let v2 = 2;
        let v3 = 3;
        // Accessor has nodeif and CAT 0xABCD_0002
        let mut subjects = AccessorSubjects::new(112233);
        subjects.add_catid(gen_noc_cat(allow_cat, v2)).unwrap();

        let accessor = Accessor::new(1, subjects, AuthMode::Case, &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for CAT id mismatch
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(disallow_cat, v2))
            .unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), false);

        // Deny of CAT version mismatch
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v3)).unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), false);

        // Allow for CAT match
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v2)).unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_cat_version() {
        let fm = RefCell::new(FabricMgr::new());

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(sys_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let allow_cat = 0xABCD;
        let disallow_cat = 0xCAFE;
        let v2 = 2;
        let v3 = 3;
        // Accessor has nodeif and CAT 0xABCD_0003
        let mut subjects = AccessorSubjects::new(112233);
        subjects.add_catid(gen_noc_cat(allow_cat, v3)).unwrap();

        let accessor = Accessor::new(1, subjects, AuthMode::Case, &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for CAT id mismatch
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(disallow_cat, v2))
            .unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), false);

        // Allow for CAT match and version more than ACL version
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v2)).unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_target() {
        let fm = RefCell::new(FabricMgr::new());

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(sys_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let accessor = Accessor::new(1, AccessorSubjects::new(112233), AuthMode::Case, &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for target mismatch
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(2),
            endpoint: Some(4567),
            device_type: None,
        })
        .unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), false);

        // Allow for cluster match - subject wildcard
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(1234),
            endpoint: None,
            device_type: None,
        })
        .unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), true);

        // Clean state
        fm.borrow_mut().get_mut(FAB_1).unwrap().acl_remove_all();

        // Allow for endpoint match - subject wildcard
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: None,
            endpoint: Some(1),
            device_type: None,
        })
        .unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), true);

        // Clean state
        fm.borrow_mut().get_mut(FAB_1).unwrap().acl_remove_all();

        // Allow for exact match
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(1234),
            endpoint: Some(1),
            device_type: None,
        })
        .unwrap();
        new.add_subject(112233).unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_privilege() {
        let fm = RefCell::new(FabricMgr::new());

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(sys_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let accessor = Accessor::new(1, AccessorSubjects::new(112233), AuthMode::Case, &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);

        // Create an Exact Match ACL with View privilege
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(1234),
            endpoint: Some(1),
            device_type: None,
        })
        .unwrap();
        new.add_subject(112233).unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();

        // Write on an RWVA without admin access - deny
        let mut req = AccessReq::new(&accessor, path.clone(), Access::WRITE);
        req.set_target_perms(Access::RWVA);
        assert_eq!(req.allow(), false);

        // Create an Exact Match ACL with Admin privilege
        let mut new = AclEntry::new(Privilege::ADMIN, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(1234),
            endpoint: Some(1),
            device_type: None,
        })
        .unwrap();
        new.add_subject(112233).unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();

        // Write on an RWVA with admin access - allow
        let mut req = AccessReq::new(&accessor, path, Access::WRITE);
        req.set_target_perms(Access::RWVA);
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_delete_for_fabric() {
        let fm = RefCell::new(FabricMgr::new());

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(sys_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Add fabric with ID 2
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(sys_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let path = GenericPath::new(Some(1), Some(1234), None);
        let accessor2 = Accessor::new(1, AccessorSubjects::new(112233), AuthMode::Case, &fm);
        let mut req1 = AccessReq::new(&accessor2, path.clone(), Access::READ);
        req1.set_target_perms(Access::RWVA);
        let accessor3 = Accessor::new(2, AccessorSubjects::new(112233), AuthMode::Case, &fm);
        let mut req2 = AccessReq::new(&accessor3, path, Access::READ);
        req2.set_target_perms(Access::RWVA);

        // Allow for subject match - target is wildcard - Fabric idx 2
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_subject(112233).unwrap();
        assert_eq!(fm.borrow_mut().acl_add(FAB_1, new).unwrap(), 0);

        // Allow for subject match - target is wildcard - Fabric idx 3
        let mut new = AclEntry::new(Privilege::VIEW, AuthMode::Case);
        new.add_subject(112233).unwrap();
        assert_eq!(fm.borrow_mut().acl_add(FAB_2, new).unwrap(), 0);

        // Req for Fabric idx 1 gets denied, and that for Fabric idx 2 is allowed
        assert_eq!(req1.allow(), true);
        assert_eq!(req2.allow(), true);
        fm.borrow_mut().acl_remove_all(FAB_1).unwrap();
        assert_eq!(req1.allow(), false);
        assert_eq!(req2.allow(), true);
    }
}
