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

//! This module contains the implementation of the `rs-matter` Access Control List (ACL)

use core::fmt::Display;
use core::num::NonZeroU8;
use core::ops::RangeInclusive;

use cfg_if::cfg_if;
use num_derive::FromPrimitive;

use crate::dm::clusters::acl::{
    AccessControlEntryAuthModeEnum, AccessControlEntryPrivilegeEnum, AccessControlEntryStruct,
    AccessControlEntryStructBuilder,
};
use crate::dm::{Access, ClusterId, EndptId, Privilege};
use crate::error::{Error, ErrorCode};
use crate::fabric::FabricMgr;
use crate::im::GenericPath;
use crate::tlv::{FromTLV, Nullable, TLVBuilderParent, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};
use crate::transport::session::{Session, SessionMode, MAX_CAT_IDS_PER_NOC};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init, IntoFallibleInit};
use crate::utils::storage::Vec;

cfg_if! {
    if #[cfg(feature = "max-subjects-per-acl-32")] {
        /// Max subjects per ACL entry
        pub const MAX_SUBJECTS_PER_ACL_ENTRY: usize = 32;
    } else if #[cfg(feature = "max-subjects-per-acl-16")] {
        /// Max subjects per ACL entry
        pub const MAX_SUBJECTS_PER_ACL_ENTRY: usize = 16;
    } else if #[cfg(feature = "max-subjects-per-acl-8")] {
        /// Max subjects per ACL entry
        pub const MAX_SUBJECTS_PER_ACL_ENTRY: usize = 8;
    } else if #[cfg(feature = "max-subjects-per-acl-7")] {
        /// Max subjects per ACL entry
        pub const MAX_SUBJECTS_PER_ACL_ENTRY: usize = 7;
    } else if #[cfg(feature = "max-subjects-per-acl-6")] {
        /// Max subjects per ACL entry
        pub const MAX_SUBJECTS_PER_ACL_ENTRY: usize = 6;
    } else if #[cfg(feature = "max-subjects-per-acl-5")] {
        /// Max subjects per ACL entry
        pub const MAX_SUBJECTS_PER_ACL_ENTRY: usize = 5;
    } else if #[cfg(feature = "max-subjects-per-acl-4")] {
        /// Max subjects per ACL entry
        pub const MAX_SUBJECTS_PER_ACL_ENTRY: usize = 4;
    } else if #[cfg(feature = "max-subjects-per-acl-3")] {
        /// Max subjects per ACL entry
        pub const MAX_SUBJECTS_PER_ACL_ENTRY: usize = 3;
    } else if #[cfg(feature = "max-subjects-per-acl-2")] {
        /// Max subjects per ACL entry
        pub const MAX_SUBJECTS_PER_ACL_ENTRY: usize = 2;
    } else if #[cfg(feature = "max-subjects-per-acl-1")] {
        /// Max subjects per ACL entry
        pub const MAX_SUBJECTS_PER_ACL_ENTRY: usize = 1;
    } else {
        /// Max subjects per ACL entry
        pub const MAX_SUBJECTS_PER_ACL_ENTRY: usize = 4;
    }
}

cfg_if! {
    if #[cfg(feature = "max-targets-per-acl-32")] {
        /// Max targets per ACL entry
        pub const MAX_TARGETS_PER_ACL_ENTRY: usize = 32;
    } else if #[cfg(feature = "max-targets-per-acl-16")] {
        /// Max targets per ACL entry
        pub const MAX_TARGETS_PER_ACL_ENTRY: usize = 16;
    } else if #[cfg(feature = "max-targets-per-acl-8")] {
        /// Max targets per ACL entry
        pub const MAX_TARGETS_PER_ACL_ENTRY: usize = 8;
    } else if #[cfg(feature = "max-targets-per-acl-7")] {
        /// Max targets per ACL entry
        pub const MAX_TARGETS_PER_ACL_ENTRY: usize = 7;
    } else if #[cfg(feature = "max-targets-per-acl-6")] {
        /// Max targets per ACL entry
        pub const MAX_TARGETS_PER_ACL_ENTRY: usize = 6;
    } else if #[cfg(feature = "max-targets-per-acl-5")] {
        /// Max targets per ACL entry
        pub const MAX_TARGETS_PER_ACL_ENTRY: usize = 5;
    } else if #[cfg(feature = "max-targets-per-acl-4")] {
        /// Max targets per ACL entry
        pub const MAX_TARGETS_PER_ACL_ENTRY: usize = 4;
    } else if #[cfg(feature = "max-targets-per-acl-3")] {
        /// Max targets per ACL entry
        pub const MAX_TARGETS_PER_ACL_ENTRY: usize = 3;
    } else if #[cfg(feature = "max-targets-per-acl-2")] {
        /// Max targets per ACL entry
        pub const MAX_TARGETS_PER_ACL_ENTRY: usize = 2;
    } else if #[cfg(feature = "max-targets-per-acl-1")] {
        /// Max targets per ACL entry
        pub const MAX_TARGETS_PER_ACL_ENTRY: usize = 1;
    } else {
        /// Max targets per ACL entry
        pub const MAX_TARGETS_PER_ACL_ENTRY: usize = 3;
    }
}

cfg_if! {
    if #[cfg(feature = "max-acls-per-fabric-32")] {
        /// Max ACL entries per fabric
        pub const MAX_ACL_ENTRIES_PER_FABRIC: usize = 32;
    } else if #[cfg(feature = "max-acls-per-fabric-16")] {
        /// Max ACL entries per fabric
        pub const MAX_ACL_ENTRIES_PER_FABRIC: usize = 16;
    } else if #[cfg(feature = "max-acls-per-fabric-8")] {
        /// Max ACL entries per fabric
        pub const MAX_ACL_ENTRIES_PER_FABRIC: usize = 8;
    } else if #[cfg(feature = "max-acls-per-fabric-7")] {
        /// Max ACL entries per fabric
        pub const MAX_ACL_ENTRIES_PER_FABRIC: usize = 7;
    } else if #[cfg(feature = "max-acls-per-fabric-6")] {
        /// Max ACL entries per fabric
        pub const MAX_ACL_ENTRIES_PER_FABRIC: usize = 6;
    } else if #[cfg(feature = "max-acls-per-fabric-5")] {
        /// Max ACL entries per fabric
        pub const MAX_ACL_ENTRIES_PER_FABRIC: usize = 5;
    } else if #[cfg(feature = "max-acls-per-fabric-4")] {
        /// Max ACL entries per fabric
        pub const MAX_ACL_ENTRIES_PER_FABRIC: usize = 4;
    } else if #[cfg(feature = "max-acls-per-fabric-3")] {
        /// Max ACL entries per fabric
        pub const MAX_ACL_ENTRIES_PER_FABRIC: usize = 3;
    } else if #[cfg(feature = "max-acls-per-fabric-2")] {
        /// Max ACL entries per fabric
        pub const MAX_ACL_ENTRIES_PER_FABRIC: usize = 2;
    } else if #[cfg(feature = "max-acls-per-fabric-1")] {
        /// Max ACL entries per fabric
        pub const MAX_ACL_ENTRIES_PER_FABRIC: usize = 1;
    } else {
        /// Max ACL entries per fabric
        pub const MAX_ACL_ENTRIES_PER_FABRIC: usize = 4;
    }
}

/// An enum modeling the different authentication modes
// TODO: Check if this and the SessionMode can be combined into some generic data structure
#[derive(FromPrimitive, Copy, Clone, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum AuthMode {
    /// PASE authentication
    Pase = AccessControlEntryAuthModeEnum::PASE as _,
    /// CASE authentication
    Case = AccessControlEntryAuthModeEnum::CASE as _,
    /// Group authentication
    Group = AccessControlEntryAuthModeEnum::Group as _,
}

impl FromTLV<'_> for AuthMode {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(AccessControlEntryAuthModeEnum::from_tlv(t)?.into())
    }
}

impl ToTLV for AuthMode {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        AccessControlEntryAuthModeEnum::from(*self).to_tlv(tag, &mut tw)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        TLV::u8(tag, AccessControlEntryAuthModeEnum::from(*self) as _).into_tlv_iter()
    }
}

impl From<AuthMode> for AccessControlEntryAuthModeEnum {
    fn from(value: AuthMode) -> Self {
        match value {
            AuthMode::Pase => AccessControlEntryAuthModeEnum::PASE,
            AuthMode::Case => AccessControlEntryAuthModeEnum::CASE,
            AuthMode::Group => AccessControlEntryAuthModeEnum::Group,
        }
    }
}

impl From<AccessControlEntryAuthModeEnum> for AuthMode {
    fn from(value: AccessControlEntryAuthModeEnum) -> Self {
        match value {
            AccessControlEntryAuthModeEnum::PASE => AuthMode::Pase,
            AccessControlEntryAuthModeEnum::CASE => AuthMode::Case,
            AccessControlEntryAuthModeEnum::Group => AuthMode::Group,
        }
    }
}

/// An accessor can have as many identities: one node id and up to MAX_CAT_IDS_PER_NOC
const MAX_ACCESSOR_SUBJECTS: usize = 1 + MAX_CAT_IDS_PER_NOC;

/// The CAT Prefix used in Subjects
pub const NOC_CAT_SUBJECT_PREFIX: u64 = 0xFFFF_FFFD_0000_0000;

const NOC_CAT_ID_MASK: u64 = 0xFFFF_0000;
const NOC_CAT_VERSION_MASK: u64 = 0xFFFF;

/// The Node ID min range
const NODE_ID_RANGE: RangeInclusive<u64> = 1..=0xFFFF_FFEF_FFFF_FFFF;

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

/// Is this identifier a node id
fn is_node(id: u64) -> bool {
    NODE_ID_RANGE.contains(&id)
}

/// The Subjects that identify the Accessor
pub struct AccessorSubjects([u64; MAX_ACCESSOR_SUBJECTS]);

impl AccessorSubjects {
    /// Create a new AccessorSubjects object
    /// The first subject is the node id
    pub fn new(id: u64) -> Self {
        let mut a = Self(Default::default());
        a.0[0] = id;
        a
    }

    /// Add a CAT id to the AccessorSubjects
    pub fn add_catid(&mut self, subject: u32) -> Result<(), Error> {
        for (i, val) in self.0.iter().enumerate() {
            if *val == 0 {
                self.0[i] = NOC_CAT_SUBJECT_PREFIX | (subject as u64);
                return Ok(());
            }
        }
        Err(ErrorCode::ResourceExhausted.into())
    }

    /// Match the acl_subject with any of the current subjects
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

#[cfg(feature = "defmt")]
impl defmt::Format for AccessorSubjects {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "[");
        for i in self.0 {
            if is_noc_cat(i) {
                defmt::write!(f, "CAT({} - {})", get_noc_cat_id(i), get_noc_cat_version(i));
            } else if i != 0 {
                defmt::write!(f, "{}, ", i);
            }
        }
        defmt::write!(f, "]")
    }
}

/// The Accessor Object
pub struct Accessor<'a> {
    /// The fabric index of the accessor
    pub fab_idx: u8,
    /// Accessor's subject: could be node-id, NoC CAT, group id
    subjects: AccessorSubjects,
    /// The auth mode of this session. Might be `None` for plain-text sessions
    auth_mode: Option<AuthMode>,
    // TODO: Is this the right place for this though, or should we just use a global-acl-handle-get
    fabric_mgr: &'a RefCell<FabricMgr>,
}

impl<'a> Accessor<'a> {
    /// Create a new Accessor object for the given session
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
                Accessor::new(fab_idx.get(), subject, Some(AuthMode::Case), fabric_mgr)
            }
            SessionMode::Pase { fab_idx } => Accessor::new(
                *fab_idx,
                AccessorSubjects::new(1),
                Some(AuthMode::Pase),
                fabric_mgr,
            ),
            SessionMode::PlainText => Accessor::new(0, AccessorSubjects::new(1), None, fabric_mgr),
        }
    }

    /// Create a new Accessor object
    ///
    /// # Arguments
    /// - `fab_idx`: The fabric index of the accessor (0 means no fabric index)
    /// - `subjects`: The subjects of the accessor
    /// - `auth_mode`: The auth mode of the accessor
    /// - `fabric_mgr`: The fabric manager
    pub const fn new(
        fab_idx: u8,
        subjects: AccessorSubjects,
        auth_mode: Option<AuthMode>,
        fabric_mgr: &'a RefCell<FabricMgr>,
    ) -> Self {
        Self {
            fab_idx,
            subjects,
            auth_mode,
            fabric_mgr,
        }
    }

    /// Return the subjects of the accessor
    pub fn subjects(&self) -> &AccessorSubjects {
        &self.subjects
    }

    /// Return the auth mode of the accessor
    pub fn auth_mode(&self) -> Option<AuthMode> {
        self.auth_mode
    }
}

/// Access Descriptor Object
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    /// The accessor requesting access
    accessor: &'a Accessor<'a>,
    /// The object being accessed
    object: AccessDesc,
}

impl<'a> AccessReq<'a> {
    /// Create an access request object
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

    /// Return the accessor of the request
    pub fn accessor(&self) -> &Accessor<'_> {
        self.accessor
    }

    /// Return the operation of the request
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

    /// Check if access is allowed
    ///
    /// This checks all the ACL list to identify if any of the ACLs provides the
    /// _accessor_ the necessary privileges to access the target as per its
    /// permissions
    pub fn allow(&self) -> bool {
        self.accessor.fabric_mgr.borrow().allow(self)
    }
}

/// The target object
#[derive(FromTLV, ToTLV, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Target {
    pub cluster: Option<ClusterId>,
    pub endpoint: Option<EndptId>,
    pub device_type: Option<u32>,
}

impl Target {
    /// Create a new target object
    pub const fn new(
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

/// The ACL entry object
#[derive(ToTLV, FromTLV, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1)]
pub struct AclEntry {
    /// The privilege of the entry
    privilege: Privilege,
    /// The auth mode of the entry
    auth_mode: AuthMode,
    /// The subjects of the entry
    subjects: Nullable<Vec<u64, MAX_SUBJECTS_PER_ACL_ENTRY>>,
    /// The targets of the entry
    targets: Nullable<Vec<Target, MAX_TARGETS_PER_ACL_ENTRY>>,
    // TODO: Instead of the direct value, we should consider GlobalElements::FabricIndex
    // Note that this field will always be `Some(NN)` when the entry is persisted in storage,
    // however, it will be `None` when the entry is coming from the other peer
    #[tagval(0xFE)]
    pub fab_idx: Option<NonZeroU8>,
}

impl AclEntry {
    /// Create a new ACL entry object
    pub const fn new(
        fab_idx: Option<NonZeroU8>,
        privilege: Privilege,
        auth_mode: AuthMode,
    ) -> Self {
        Self {
            fab_idx,
            privilege,
            auth_mode,
            subjects: Nullable::none(),
            targets: Nullable::none(),
        }
    }

    /// Return an initializer for an ACL entry object
    /// using the given fabric index, privilege and auth mode as input
    pub fn init(
        fab_idx: Option<NonZeroU8>,
        privilege: Privilege,
        auth_mode: AuthMode,
    ) -> impl Init<Self> {
        init!(Self {
            fab_idx,
            privilege,
            auth_mode,
            subjects <- Nullable::init_none(),
            targets <- Nullable::init_none(),
        })
    }

    /// Return an initializer for an ACL entry object
    /// using the given fabric index and TLV entry struct as input
    pub fn init_with<'a>(
        fab_idx: NonZeroU8,
        entry: &'a AccessControlEntryStruct<'a>,
    ) -> impl Init<Self, Error> + 'a {
        Self::init(Some(fab_idx), Privilege::empty(), AuthMode::Pase)
            .into_fallible()
            .chain(|e| {
                let auth_mode = entry.auth_mode()?.ok_or(ErrorCode::ConstraintError)?;
                let privilege = entry.privilege()?.ok_or(ErrorCode::ConstraintError)?;
                let subjects = entry.subjects()?.ok_or(ErrorCode::ConstraintError)?;
                let targets = entry.targets()?.ok_or(ErrorCode::ConstraintError)?;

                if
                    // As per spec, PASE auth mode is reserved for future use
                    matches!(auth_mode, AccessControlEntryAuthModeEnum::PASE)
                    // As per spec, Group auth mode cannot have Admin privilege
                    || matches!(auth_mode, AccessControlEntryAuthModeEnum::Group) && matches!(privilege, AccessControlEntryPrivilegeEnum::Administer)
                {
                    Err(ErrorCode::ConstraintError)?;
                }

                e.privilege = privilege.into();
                e.auth_mode = auth_mode.into();

                // Start with null subjects and targets
                // so that we can keep those to null if we receive empty subjects' array or empty targets' array
                // This is what the YAML tests expect
                e.subjects.clear();
                e.targets.clear();

                if let Some(subjects) = subjects.into_option() {
                    for subject in subjects {
                        if e.subjects.is_none() {
                            // Initialize our subjects to non-null lazily, only if we have at least one incoming subject
                            // This ensures that if the incoming subjects is empty, we keep our subjects as null
                            // which is what the YAML tests expect, even if we internally treat null and empty subjects the same way
                            e.subjects.reinit(Nullable::init_some(Vec::init()));
                        }

                        let esubjects = unwrap!(e.subjects.as_opt_mut());

                        let subject = subject?;

                        if matches!(auth_mode, AccessControlEntryAuthModeEnum::CASE) && !is_node(subject) && !is_noc_cat(subject) {
                            // As per spec, CASE auth mode only allows node ids and NOC CATs as subjects
                            Err(ErrorCode::ConstraintError)?;
                        }

                        // As per spec, on too many subjects we should return a FAILURE status code
                        // `ErrorCode::BufferTooSmall` translates to a generic FAILURE status code
                        esubjects
                            .push(subject)
                            .map_err(|_| ErrorCode::BufferTooSmall)?;
                    }
                }

                if let Some(targets) = targets.into_option() {
                    for target in targets {
                        if e.targets.is_none() {
                            // Initialize our targets to non-null lazily, only if we have at least one incoming target
                            // This ensures that if the incoming targets is empty, we keep our targets as null
                            // which is what the YAML tests expect, even if we internally treat null and empty targets the same way
                            e.targets.reinit(Nullable::init_some(Vec::init()));
                        }

                        let etargets = unwrap!(e.targets.as_opt_mut());

                        let target = target?;

                        if
                            // As per spec, either the device type or the endpoint/cluster shuld be set, but not all
                            target.device_type()?.is_some() && (target.endpoint()?.is_some() || target.cluster()?.is_some())
                            // As per spec, at least one of device type, endpoint or cluster should be set
                            || target.device_type()?.is_none() && target.endpoint()?.is_none() && target.cluster()?.is_none()
                        {
                            Err(ErrorCode::ConstraintError)?;
                        }

                        // As per spec, on too many targets we should return a FAILURE status code
                        // `ErrorCode::BufferTooSmall` translates to a generic FAILURE status code
                        etargets
                            .push(Target::new(
                                target.endpoint()?.into_option(),
                                target.cluster()?.into_option(),
                                target.device_type()?.into_option(),
                            ))
                            .map_err(|_| ErrorCode::BufferTooSmall)?;
                    }
                }

                Ok(())
            })
    }

    /// Return the data of the ACL entry object
    /// into the provided TLV builder
    pub fn read_into<P: TLVBuilderParent>(
        &self,
        accessing_fab_idx: u8,
        fab_idx: Option<u8>,
        builder: AccessControlEntryStructBuilder<P>,
    ) -> Result<P, Error> {
        let same_fab_idx = Some(accessing_fab_idx) == fab_idx;

        builder
            .privilege(same_fab_idx.then(|| self.privilege.into()))?
            .auth_mode(same_fab_idx.then(|| self.auth_mode.into()))?
            .subjects()?
            .with_some_if(same_fab_idx, |builder| {
                builder.with_non_null(self.subjects(), |subjects, mut builder| {
                    for subject in *subjects {
                        builder = builder.push(subject)?;
                    }

                    builder.end()
                })
            })?
            .targets()?
            .with_some_if(same_fab_idx, |builder| {
                builder.with_non_null(self.targets(), |targets, mut builder| {
                    for target in *targets {
                        builder = builder
                            .push()?
                            .cluster(Nullable::new(target.cluster))?
                            .endpoint(Nullable::new(target.endpoint))?
                            .device_type(Nullable::new(target.device_type))?
                            .end()?;
                    }

                    builder.end()
                })
            })?
            .fabric_index(fab_idx)?
            .end()
    }

    /// Normalize the ACL entry by converting non-null but empty
    /// subjects/targets to null, as the spec and YAML tests expect
    pub fn normalize(&mut self) {
        if self
            .subjects
            .as_opt_ref()
            .map(|subjects| subjects.is_empty())
            .unwrap_or(false)
        {
            self.subjects.clear();
        }

        if self
            .targets
            .as_opt_ref()
            .map(|targets| targets.is_empty())
            .unwrap_or(false)
        {
            self.targets.clear();
        }
    }

    /// Return the auth mode of the ACL entry
    pub fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    /// Return the subjects of the ACL entry
    pub fn subjects(&self) -> Nullable<&[u64]> {
        Nullable::new(self.subjects.as_opt_ref().map(|v| v.as_slice()))
    }

    /// Return the targets of the ACL entry
    pub fn targets(&self) -> Nullable<&[Target]> {
        Nullable::new(self.targets.as_opt_ref().map(|v| v.as_slice()))
    }

    /// Check if the ACL entry allows access to the given accessor and object
    pub fn allow(&self, req: &AccessReq) -> bool {
        self.match_accessor(req.accessor) && self.match_access_desc(&req.object)
    }

    /// Add a subject to the ACL entry
    pub fn add_subject(&mut self, subject: u64) -> Result<(), Error> {
        if self.subjects.is_none() {
            self.subjects.reinit(Nullable::init_some(Vec::init()));
        }

        unwrap!(self.subjects.as_opt_mut())
            .push(subject)
            .map_err(|_| ErrorCode::ResourceExhausted.into())
    }

    /// Add a CAT id to the ACL entry
    pub fn add_subject_catid(&mut self, cat_id: u32) -> Result<(), Error> {
        self.add_subject(NOC_CAT_SUBJECT_PREFIX | cat_id as u64)
    }

    /// Add a target to the ACL entry
    pub fn add_target(&mut self, target: Target) -> Result<(), Error> {
        if self.targets.is_none() {
            self.targets.reinit(Nullable::init_some(Vec::init()));
        }

        unwrap!(self.targets.as_opt_mut())
            .push(target)
            .map_err(|_| ErrorCode::ResourceExhausted.into())
    }

    fn match_accessor(&self, accessor: &Accessor) -> bool {
        if Some(self.auth_mode) != accessor.auth_mode {
            return false;
        }

        let allow = self.subjects().as_opt_ref().is_none_or(|subjects| {
            // Subjects array null or empty implies allow for all subjects
            // Otherwise, check if the accessor's subject matches any of the ACL entry's subjects
            subjects.is_empty() || subjects.iter().any(|s| accessor.subjects.matches(*s))
        });

        // true if both are true
        allow
            && self
                .fab_idx
                .map(|fab_idx| fab_idx.get() == accessor.fab_idx)
                .unwrap_or(false)
    }

    fn match_access_desc(&self, object: &AccessDesc) -> bool {
        let allow = self.targets.as_opt_ref().is_none_or(|targets| {
            // Targets array null or empty implies allow for all targets
            // Otherwise, check if the target matches any of the ACL entry's targets
            targets.is_empty()
                || targets.iter().any(|t| {
                    (t.endpoint.is_none() || t.endpoint == object.path.endpoint)
                        && (t.cluster.is_none() || t.cluster == object.path.cluster)
                })
        });

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
}

#[cfg(test)]
#[allow(clippy::bool_assert_comparison)]
pub(crate) mod tests {
    use core::num::NonZeroU8;

    use crate::acl::{gen_noc_cat, AccessorSubjects};
    use crate::crypto::KeyPair;
    use crate::dm::{Access, Privilege};
    use crate::fabric::FabricMgr;
    use crate::im::GenericPath;
    use crate::utils::cell::RefCell;
    use crate::utils::rand::dummy_rand;

    use super::{AccessReq, Accessor, AclEntry, AuthMode, Target};

    pub(crate) const FAB_1: NonZeroU8 = match NonZeroU8::new(1) {
        Some(f) => f,
        None => ::core::unreachable!(),
    };

    pub(crate) const FAB_2: NonZeroU8 = match NonZeroU8::new(2) {
        Some(f) => f,
        None => ::core::unreachable!(),
    };

    #[test]
    fn test_basic_empty_subject_target() {
        let fm = RefCell::new(FabricMgr::new());

        let accessor = Accessor::new(0, AccessorSubjects::new(112233), Some(AuthMode::Pase), &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req_pase = AccessReq::new(&accessor, path, Access::READ);
        req_pase.set_target_perms(Access::RWVA);

        // Always allow for PASE sessions
        assert!(req_pase.allow());

        let accessor = Accessor::new(2, AccessorSubjects::new(112233), Some(AuthMode::Case), &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Default deny for CASE
        assert_eq!(req.allow(), false);

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Deny adding invalid auth mode (PASE is reserved for future)
        let new = AclEntry::new(None, Privilege::VIEW, AuthMode::Pase);
        assert!(fm.borrow_mut().acl_add(FAB_1, new).is_err());

        // Deny for fab idx mismatch
        let new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        assert_eq!(fm.borrow_mut().acl_add(FAB_1, new).unwrap(), 0);
        assert_eq!(req.allow(), false);

        // Always allow for PASE sessions
        assert!(req_pase.allow());

        // Add fabric with ID 2
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Allow
        let new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        assert_eq!(fm.borrow_mut().acl_add(FAB_2, new).unwrap(), 0);
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_subject() {
        let fm = RefCell::new(FabricMgr::new());

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let accessor = Accessor::new(1, AccessorSubjects::new(112233), Some(AuthMode::Case), &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for subject mismatch
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject(112232).unwrap();
        assert_eq!(fm.borrow_mut().acl_add(FAB_1, new).unwrap(), 0);
        assert_eq!(req.allow(), false);

        // Allow for subject match - target is wildcard
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject(112233).unwrap();
        assert_eq!(fm.borrow_mut().acl_add(FAB_1, new).unwrap(), 1);
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_cat() {
        let fm = RefCell::new(FabricMgr::new());

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let allow_cat = 0xABCD;
        let disallow_cat = 0xCAFE;
        let v2 = 2;
        let v3 = 3;
        // Accessor has nodeif and CAT 0xABCD_0002
        let mut subjects = AccessorSubjects::new(112233);
        subjects.add_catid(gen_noc_cat(allow_cat, v2)).unwrap();

        let accessor = Accessor::new(1, subjects, Some(AuthMode::Case), &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for CAT id mismatch
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(disallow_cat, v2))
            .unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), false);

        // Deny of CAT version mismatch
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v3)).unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), false);

        // Allow for CAT match
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v2)).unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_cat_version() {
        let fm = RefCell::new(FabricMgr::new());

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let allow_cat = 0xABCD;
        let disallow_cat = 0xCAFE;
        let v2 = 2;
        let v3 = 3;
        // Accessor has nodeif and CAT 0xABCD_0003
        let mut subjects = AccessorSubjects::new(112233);
        subjects.add_catid(gen_noc_cat(allow_cat, v3)).unwrap();

        let accessor = Accessor::new(1, subjects, Some(AuthMode::Case), &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for CAT id mismatch
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(disallow_cat, v2))
            .unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), false);

        // Allow for CAT match and version more than ACL version
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v2)).unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), true);
    }

    #[test]
    fn test_target() {
        let fm = RefCell::new(FabricMgr::new());

        // Add fabric with ID 1
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let accessor = Accessor::new(1, AccessorSubjects::new(112233), Some(AuthMode::Case), &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ);
        req.set_target_perms(Access::RWVA);

        // Deny for target mismatch
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(2),
            endpoint: Some(4567),
            device_type: None,
        })
        .unwrap();
        fm.borrow_mut().acl_add(FAB_1, new).unwrap();
        assert_eq!(req.allow(), false);

        // Allow for cluster match - subject wildcard
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
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
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
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
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
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
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let accessor = Accessor::new(1, AccessorSubjects::new(112233), Some(AuthMode::Case), &fm);
        let path = GenericPath::new(Some(1), Some(1234), None);

        // Create an Exact Match ACL with View privilege
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
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
        let mut new = AclEntry::new(None, Privilege::ADMIN, AuthMode::Case);
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
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        // Add fabric with ID 2
        fm.borrow_mut()
            .add_with_post_init(KeyPair::new(dummy_rand).unwrap(), |_| Ok(()))
            .unwrap();

        let path = GenericPath::new(Some(1), Some(1234), None);
        let accessor2 = Accessor::new(1, AccessorSubjects::new(112233), Some(AuthMode::Case), &fm);
        let mut req1 = AccessReq::new(&accessor2, path.clone(), Access::READ);
        req1.set_target_perms(Access::RWVA);
        let accessor3 = Accessor::new(2, AccessorSubjects::new(112233), Some(AuthMode::Case), &fm);
        let mut req2 = AccessReq::new(&accessor3, path, Access::READ);
        req2.set_target_perms(Access::RWVA);

        // Allow for subject match - target is wildcard - Fabric idx 2
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject(112233).unwrap();
        assert_eq!(fm.borrow_mut().acl_add(FAB_1, new).unwrap(), 0);

        // Allow for subject match - target is wildcard - Fabric idx 3
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
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
