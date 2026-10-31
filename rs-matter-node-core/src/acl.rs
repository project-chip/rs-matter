/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

use num::FromPrimitive;
use num_derive::FromPrimitive;

use crate::dm::{Access, ClusterId, DeviceType, EndptId, NodeId, Privilege};
use crate::error::{Error, ErrorCode};
use crate::fabric::Fabrics;
use crate::im::GenericPath;
use crate::session::{SessionMode, MAX_CAT_IDS_PER_NOC};
use crate::tlv::{FromTLV, Nullable, TLVElement, TLVTag, TLVWrite, ToTLV, TLV};
use crate::utils::init::{init, Init};
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
///
/// The values are the ones of the Access Control cluster.
pub enum AuthMode {
    /// PASE authentication
    Pase = 1,
    /// CASE authentication
    Case = 2,
    /// Group authentication
    Group = 3,
}

impl FromTLV<'_> for AuthMode {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Self::from_u8(t.u8()?).ok_or(ErrorCode::Invalid.into())
    }
}

impl ToTLV for AuthMode {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.u8(tag, *self as _)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        TLV::u8(tag, *self as _).into_tlv_iter()
    }
}

/// The type of an auxiliary ACL entry: one that the node synthesizes rather
/// than an administrator writes.
///
/// The values are the ones of the Access Control cluster.
#[derive(FromPrimitive, Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum AuxiliaryType {
    /// Synthesized by the system
    System = 0,
    /// Synthesized for the Groupcast cluster
    Groupcast = 1,
}

impl FromTLV<'_> for AuxiliaryType {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Self::from_u8(t.u8()?).ok_or(ErrorCode::Invalid.into())
    }
}

impl ToTLV for AuxiliaryType {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.u8(tag, *self as _)
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV<'_>, Error>> {
        TLV::u8(tag, *self as _).into_tlv_iter()
    }
}

/// An accessor can have as many identities: one node id and up to MAX_CAT_IDS_PER_NOC
const MAX_ACCESSOR_SUBJECTS: usize = 1 + MAX_CAT_IDS_PER_NOC;

/// The CAT Prefix used in Subjects
pub const NOC_CAT_SUBJECT_PREFIX: u64 = 0xFFFF_FFFD_0000_0000;
pub const NOC_CAT_SUBJECT_MASK: u64 = 0xFFFF_FFFF_0000_0000;

const NOC_CAT_ID_MASK: u64 = 0xFFFF_0000;
const NOC_CAT_VERSION_MASK: u64 = 0xFFFF;

/// The Node ID min range
const NODE_ID_RANGE: RangeInclusive<u64> = 1..=0xFFFF_FFEF_FFFF_FFFF;

/// Is this identifier a NOC CAT
pub fn is_noc_cat(id: u64) -> bool {
    ((id & NOC_CAT_SUBJECT_MASK) == NOC_CAT_SUBJECT_PREFIX)
        && ((id & (NOC_CAT_ID_MASK | NOC_CAT_VERSION_MASK)) > 0)
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
pub fn is_node(id: u64) -> bool {
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

/// Who is making an access request.
///
/// `Accessor`, in `rs-matter-node`, puts this together with the fabric
/// table that the requests are checked against.
pub struct SubjectDescriptor {
    /// The fabric index of the accessor
    pub fab_idx: u8,
    /// Whether AUX ACL was enabled at the time this accessor was instantiated
    aux_acl_enabled: bool,
    /// Accessor's subject: could be node-id, NoC CAT, group id
    subjects: AccessorSubjects,
    /// The auth mode of this session. Might be `None` for plain-text sessions
    auth_mode: Option<AuthMode>,
}

impl SubjectDescriptor {
    /// Create the subject descriptor of a session
    ///
    /// # Arguments
    /// - `session_mode`: The mode of the session
    /// - `peer_node_id`: The node ID of the peer of the session, if the session has one
    /// - `aux_acl_enabled`: Whether AUX ACL is enabled
    pub fn for_session(
        session_mode: &SessionMode,
        peer_node_id: Option<NodeId>,
        aux_acl_enabled: bool,
    ) -> Self {
        match session_mode {
            SessionMode::Case {
                fab_idx, cat_ids, ..
            } => {
                let mut subject = AccessorSubjects::new(peer_node_id.unwrap_or_default());
                for i in *cat_ids {
                    if i != 0 {
                        let _ = subject.add_catid(i);
                    }
                }
                Self::new(
                    fab_idx.get(),
                    aux_acl_enabled,
                    subject,
                    Some(AuthMode::Case),
                )
            }
            SessionMode::Pase { fab_idx } => Self::new(
                *fab_idx,
                aux_acl_enabled,
                AccessorSubjects::new(1),
                Some(AuthMode::Pase),
            ),
            SessionMode::Group { fab_idx, group_id } => Self::new(
                fab_idx.get(),
                aux_acl_enabled,
                AccessorSubjects::new(*group_id as u64),
                Some(AuthMode::Group),
            ),
            SessionMode::PlainText => Self::new(0, aux_acl_enabled, AccessorSubjects::new(1), None),
        }
    }

    /// Create a new subject descriptor
    ///
    /// # Arguments
    /// - `fab_idx`: The fabric index of the accessor (0 means no fabric index)
    /// - `aux_acl_enabled`: Whether AUX ACL was enabled at the time this accessor was instantiated
    /// - `subjects`: The subjects of the accessor
    /// - `auth_mode`: The auth mode of the accessor
    pub const fn new(
        fab_idx: u8,
        aux_acl_enabled: bool,
        subjects: AccessorSubjects,
        auth_mode: Option<AuthMode>,
    ) -> Self {
        Self {
            fab_idx,
            aux_acl_enabled,
            subjects,
            auth_mode,
        }
    }

    pub fn fab_idx(&self) -> Result<NonZeroU8, Error> {
        NonZeroU8::new(self.fab_idx).ok_or(ErrorCode::UnsupportedAccess.into())
    }

    /// Return whether AUX ACL was enabled at the time this accessor was instantiated
    pub const fn aux_acl_enabled(&self) -> bool {
        self.aux_acl_enabled
    }

    /// Return the subjects of the accessor
    pub const fn subjects(&self) -> &AccessorSubjects {
        &self.subjects
    }

    /// Return the auth mode of the accessor
    pub const fn auth_mode(&self) -> Option<AuthMode> {
        self.auth_mode
    }

    /// Return whether the given endpoint is accessible for this accessor.
    ///
    /// For group sessions, only endpoints that are members of the group are accessible.
    /// For all other session types, all endpoints are accessible.
    pub fn is_endpoint_accessible(&self, endpoint_id: EndptId, fabrics: &Fabrics) -> bool {
        if self.auth_mode != Some(AuthMode::Group) {
            return true;
        }

        // A group session reaches an endpoint only if that endpoint is a member
        // of the session's group.
        #[cfg(feature = "groups")]
        {
            let group_id = self.subjects.0[0] as u16;

            let Some(fab_idx) = core::num::NonZeroU8::new(self.fab_idx) else {
                return false;
            };

            let Some(fabric) = fabrics.get(fab_idx) else {
                return false;
            };

            fabric
                .groups()
                .get(group_id)
                .is_some_and(|e| e.endpoints.contains(&endpoint_id))
        }

        // Without multicast group support there are no group sessions, so
        // `auth_mode` above is never `Group` and this point is unreachable. Deny
        // anyway (fail closed): if a `Group` auth mode ever did reach here, it must
        // not silently grant access to an endpoint.
        #[cfg(not(feature = "groups"))]
        {
            let _ = (endpoint_id, fabrics);
            false
        }
    }

    /// Return the peer node ID (admin node ID) for CASE sessions, or None for PASE/other sessions.
    pub fn peer_node_id(&self) -> Option<u64> {
        if matches!(self.auth_mode, Some(AuthMode::Case)) {
            let id = self.subjects.0[0];
            if is_node(id) {
                Some(id)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Access Descriptor Object
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AccessDesc<'a> {
    /// The object to be acted upon
    path: GenericPath,
    /// The target permissions
    target_perms: Option<Access>,
    // The operation being done
    operation: Access,
    /// The device types of the endpoint hosting `path`. Used by ACL `Target`
    /// entries that filter by `DeviceType` (Matter Core spec).
    /// Empty when the access target's endpoint is unknown / not yet expanded.
    device_types: &'a [DeviceType],
}

/// Access Request Object
pub struct AccessReq<'a> {
    /// The accessor requesting access
    accessor: &'a SubjectDescriptor,
    /// The object being accessed
    object: AccessDesc<'a>,
}

impl<'a> AccessReq<'a> {
    /// Create an access request object.
    ///
    /// An access request specifies the _accessor_ attempting to access _path_
    /// with _operation_. `device_types` lists the device types declared by
    /// the endpoint that hosts `path`; pass an empty slice when this is not
    /// applicable (e.g. for unit tests that don't exercise `DeviceType` ACL
    /// targets).
    pub const fn new(
        accessor: &'a SubjectDescriptor,
        path: GenericPath,
        operation: Access,
        device_types: &'a [DeviceType],
    ) -> Self {
        AccessReq {
            accessor,
            object: AccessDesc {
                path,
                target_perms: None,
                operation,
                device_types,
            },
        }
    }

    /// Return the accessor of the request
    pub fn accessor(&self) -> &SubjectDescriptor {
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
    pub fn allow(&self, fabrics: &Fabrics) -> bool {
        let allow = fabrics.allow(self, self.accessor.aux_acl_enabled());

        #[cfg(feature = "groups")]
        let allow = allow || self.allow_groupcast_auxiliary(fabrics);

        allow
    }

    /// Check whether access is granted by an auxiliary ACL entry synthesized
    /// from the Groupcast group table: a Group-auth accessor whose group has
    /// `HasAuxiliaryACL` set is granted the `Operate` privilege on the
    /// group's endpoints (see the Groupcast Auxiliary ACL Handling section of
    /// the Matter Core spec).
    #[cfg(feature = "groups")]
    fn allow_groupcast_auxiliary(&self, fabrics: &Fabrics) -> bool {
        if !self.accessor.aux_acl_enabled() {
            return false;
        }

        if self.accessor.auth_mode != Some(AuthMode::Group) {
            return false;
        }

        let Ok(fab_idx) = self.accessor.fab_idx() else {
            return false;
        };

        let Some(fabric) = fabrics.get(fab_idx) else {
            return false;
        };

        // Synthesized entries always carry concrete endpoint targets
        let Some(endpoint) = self.object.path.endpoint else {
            return false;
        };

        let granted = fabric.groups().iter().any(|entry| {
            entry.has_aux_acl()
                && entry.endpoints.contains(&endpoint)
                && self.accessor.subjects.matches(entry.group_id as u64)
        });

        granted
            && self
                .object
                .target_perms
                .is_some_and(|access| access.is_ok(self.object.operation, Privilege::OPERATE))
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
    // TODO: Figure out what this is, document and use
    auxiliary_type: Option<AuxiliaryType>,
    // Note that this field will always be `Some(NN)` when the entry is persisted in storage,
    // however, it will be `None` when the entry is coming from the other peer.
    #[tagval(crate::im::FABRIC_INDEX_TAG)]
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
            auxiliary_type: None,
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
            auxiliary_type: None,
        })
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

    /// Return the privilege of the ACL entry
    pub fn privilege(&self) -> Privilege {
        self.privilege
    }

    /// Set the privilege of the ACL entry
    pub fn set_privilege(&mut self, privilege: Privilege) {
        self.privilege = privilege;
    }

    /// Return the auth mode of the ACL entry
    pub fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    /// Set the auth mode of the ACL entry
    pub fn set_auth_mode(&mut self, auth_mode: AuthMode) {
        self.auth_mode = auth_mode;
    }

    /// Return the subjects of the ACL entry
    pub fn subjects(&self) -> Nullable<&[u64]> {
        Nullable::new(self.subjects.as_opt_ref().map(|v| v.as_slice()))
    }

    /// Return the targets of the ACL entry
    pub fn targets(&self) -> Nullable<&[Target]> {
        Nullable::new(self.targets.as_opt_ref().map(|v| v.as_slice()))
    }

    /// Return the auxiliary type of the ACL entry, if it is an auxiliary one
    pub fn auxiliary_type(&self) -> Option<AuxiliaryType> {
        self.auxiliary_type
    }

    /// Check if the ACL entry allows access to the given accessor and object
    ///
    /// `aux_acl_enabled` conveys whether the node advertises the Access Control
    /// cluster's `AUXILIARY` feature, which changes how wildcard-target
    /// Group-auth entries are evaluated - see [`Self::match_access_desc`].
    pub fn allow(&self, req: &AccessReq, aux_acl_enabled: bool) -> bool {
        self.match_accessor(req.accessor) && self.match_access_desc(&req.object, aux_acl_enabled)
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

    fn match_accessor(&self, accessor: &SubjectDescriptor) -> bool {
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

    fn match_access_desc(&self, object: &AccessDesc, aux_acl_enabled: bool) -> bool {
        // Per the Matter Core spec, when the Access Control cluster's
        // `AUXILIARY` feature is advertised, an empty (wildcard) targets
        // list on a Group-auth entry grants access to all endpoints
        // *except* the root endpoint; without the feature it covers the
        // whole node. (Explicitly-listed targets are unaffected.)
        if aux_acl_enabled
            && matches!(self.auth_mode, AuthMode::Group)
            && object.path.endpoint == Some(crate::dm::ROOT_ENDPOINT_ID)
            && self
                .targets
                .as_opt_ref()
                .is_none_or(|targets| targets.is_empty())
        {
            return false;
        }

        let allow = self.targets.as_opt_ref().is_none_or(|targets| {
            // Targets array null or empty implies allow for all targets
            // Otherwise, check if the target matches any of the ACL entry's targets
            targets.is_empty()
                || targets.iter().any(|t| {
                    let endpoint_match = t.endpoint.is_none() || t.endpoint == object.path.endpoint;
                    let cluster_match = t.cluster.is_none() || t.cluster == object.path.cluster;
                    // When `Target.device_type` is set, the access target's endpoint
                    // must declare a matching device type in its `DeviceTypeList`
                    // (Matter Core spec).
                    let device_type_match = match t.device_type {
                        Some(dt) => object
                            .device_types
                            .iter()
                            .any(|endpoint_dt| endpoint_dt.dtype as u32 == dt),
                        None => true,
                    };
                    endpoint_match && cluster_match && device_type_match
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
    use crate::dm::{Access, Privilege};
    use crate::error::Error;
    use crate::fabric::Fabrics;
    use crate::im::GenericPath;

    use super::{AccessReq, AclEntry, AuthMode, SubjectDescriptor, Target};

    pub(crate) const FAB_1: NonZeroU8 = match NonZeroU8::new(1) {
        Some(f) => f,
        None => ::core::unreachable!(),
    };

    pub(crate) const FAB_2: NonZeroU8 = match NonZeroU8::new(2) {
        Some(f) => f,
        None => ::core::unreachable!(),
    };

    fn add_fabric(fabrics: &mut Fabrics) {
        // Add fabric with ID 1
        fabrics.add_with_post_init(|_| Ok(())).unwrap();
    }

    fn add_acl(fabrics: &mut Fabrics, fab_idx: NonZeroU8, entry: AclEntry) -> Result<usize, Error> {
        fabrics.fabric_mut(fab_idx)?.acl_add(entry)
    }

    fn remove_all_acl(fabrics: &mut Fabrics, fab_idx: NonZeroU8) {
        fabrics.fabric_mut(fab_idx).unwrap().acl_remove_all()
    }

    #[test]
    fn test_basic_empty_subject_target() {
        let mut fabrics = Fabrics::new();
        let accessor = SubjectDescriptor::new(
            0,
            false,
            AccessorSubjects::new(112233),
            Some(AuthMode::Pase),
        );
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req_pase = AccessReq::new(&accessor, path, Access::READ, &[]);
        req_pase.set_target_perms(Access::RWVA);

        // Always allow for PASE sessions
        assert!(req_pase.allow(&fabrics));

        let accessor = SubjectDescriptor::new(
            2,
            false,
            AccessorSubjects::new(112233),
            Some(AuthMode::Case),
        );
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ, &[]);
        req.set_target_perms(Access::RWVA);

        // Default deny for CASE
        assert_eq!(req.allow(&fabrics), false);

        // Add fabric with ID 1
        add_fabric(&mut fabrics);

        // Deny adding invalid auth mode (PASE is reserved for future)
        let new = AclEntry::new(None, Privilege::VIEW, AuthMode::Pase);
        assert!(add_acl(&mut fabrics, FAB_1, new).is_err());

        // Deny for fab idx mismatch
        let new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        assert_eq!(add_acl(&mut fabrics, FAB_1, new).unwrap(), 0);
        assert_eq!(req.allow(&fabrics), false);

        // Always allow for PASE sessions
        assert!(req_pase.allow(&fabrics));

        // Add fabric with ID 2
        add_fabric(&mut fabrics);

        // Allow
        let new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        assert_eq!(add_acl(&mut fabrics, FAB_2, new).unwrap(), 0);
        assert_eq!(req.allow(&fabrics), true);
    }

    #[test]
    fn test_subject() {
        let mut fabrics = Fabrics::new();

        // Add fabric with ID 1
        add_fabric(&mut fabrics);

        let accessor = SubjectDescriptor::new(
            1,
            false,
            AccessorSubjects::new(112233),
            Some(AuthMode::Case),
        );
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ, &[]);
        req.set_target_perms(Access::RWVA);

        // Deny for subject mismatch
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject(112232).unwrap();
        assert_eq!(add_acl(&mut fabrics, FAB_1, new).unwrap(), 0);
        assert_eq!(req.allow(&fabrics), false);

        // Allow for subject match - target is wildcard
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject(112233).unwrap();
        assert_eq!(add_acl(&mut fabrics, FAB_1, new).unwrap(), 1);
        assert_eq!(req.allow(&fabrics), true);
    }

    #[test]
    fn test_cat() {
        let mut fabrics = Fabrics::new();

        // Add fabric with ID 1
        add_fabric(&mut fabrics);

        let allow_cat = 0xABCD;
        let disallow_cat = 0xCAFE;
        let v2 = 2;
        let v3 = 3;
        // Accessor has nodeif and CAT 0xABCD_0002
        let mut subjects = AccessorSubjects::new(112233);
        subjects.add_catid(gen_noc_cat(allow_cat, v2)).unwrap();

        let accessor = SubjectDescriptor::new(1, false, subjects, Some(AuthMode::Case));
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ, &[]);
        req.set_target_perms(Access::RWVA);

        // Deny for CAT id mismatch
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(disallow_cat, v2))
            .unwrap();
        add_acl(&mut fabrics, FAB_1, new).unwrap();
        assert_eq!(req.allow(&fabrics), false);

        // Deny of CAT version mismatch
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v3)).unwrap();
        add_acl(&mut fabrics, FAB_1, new).unwrap();
        assert_eq!(req.allow(&fabrics), false);

        // Allow for CAT match
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v2)).unwrap();
        add_acl(&mut fabrics, FAB_1, new).unwrap();
        assert_eq!(req.allow(&fabrics), true);
    }

    #[test]
    fn test_cat_version() {
        let mut fabrics = Fabrics::new();

        // Add fabric with ID 1
        add_fabric(&mut fabrics);

        let allow_cat = 0xABCD;
        let disallow_cat = 0xCAFE;
        let v2 = 2;
        let v3 = 3;
        // Accessor has nodeif and CAT 0xABCD_0003
        let mut subjects = AccessorSubjects::new(112233);
        subjects.add_catid(gen_noc_cat(allow_cat, v3)).unwrap();

        let accessor = SubjectDescriptor::new(1, false, subjects, Some(AuthMode::Case));
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ, &[]);
        req.set_target_perms(Access::RWVA);

        // Deny for CAT id mismatch
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(disallow_cat, v2))
            .unwrap();
        add_acl(&mut fabrics, FAB_1, new).unwrap();
        assert_eq!(req.allow(&fabrics), false);

        // Allow for CAT match and version more than ACL version
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject_catid(gen_noc_cat(allow_cat, v2)).unwrap();
        add_acl(&mut fabrics, FAB_1, new).unwrap();
        assert_eq!(req.allow(&fabrics), true);
    }

    #[test]
    fn test_target() {
        let mut fabrics = Fabrics::new();

        // Add fabric with ID 1
        add_fabric(&mut fabrics);

        let accessor = SubjectDescriptor::new(
            1,
            false,
            AccessorSubjects::new(112233),
            Some(AuthMode::Case),
        );
        let path = GenericPath::new(Some(1), Some(1234), None);
        let mut req = AccessReq::new(&accessor, path, Access::READ, &[]);
        req.set_target_perms(Access::RWVA);

        // Deny for target mismatch
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(2),
            endpoint: Some(4567),
            device_type: None,
        })
        .unwrap();
        add_acl(&mut fabrics, FAB_1, new).unwrap();
        assert_eq!(req.allow(&fabrics), false);

        // Allow for cluster match - subject wildcard
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(1234),
            endpoint: None,
            device_type: None,
        })
        .unwrap();
        add_acl(&mut fabrics, FAB_1, new).unwrap();
        assert_eq!(req.allow(&fabrics), true);

        // Clean state
        remove_all_acl(&mut fabrics, FAB_1);

        // Allow for endpoint match - subject wildcard
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: None,
            endpoint: Some(1),
            device_type: None,
        })
        .unwrap();
        add_acl(&mut fabrics, FAB_1, new).unwrap();
        assert_eq!(req.allow(&fabrics), true);

        // Clean state
        remove_all_acl(&mut fabrics, FAB_1);

        // Allow for exact match
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(1234),
            endpoint: Some(1),
            device_type: None,
        })
        .unwrap();
        new.add_subject(112233).unwrap();
        add_acl(&mut fabrics, FAB_1, new).unwrap();
        assert_eq!(req.allow(&fabrics), true);
    }

    #[test]
    fn test_privilege() {
        let mut fabrics = Fabrics::new();

        // Add fabric with ID 1
        add_fabric(&mut fabrics);

        let accessor = SubjectDescriptor::new(
            1,
            false,
            AccessorSubjects::new(112233),
            Some(AuthMode::Case),
        );
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
        add_acl(&mut fabrics, FAB_1, new).unwrap();

        // Write on an RWVA without admin access - deny
        let mut req = AccessReq::new(&accessor, path.clone(), Access::WRITE, &[]);
        req.set_target_perms(Access::RWVA);
        assert_eq!(req.allow(&fabrics), false);

        // Create an Exact Match ACL with Admin privilege
        let mut new = AclEntry::new(None, Privilege::ADMIN, AuthMode::Case);
        new.add_target(Target {
            cluster: Some(1234),
            endpoint: Some(1),
            device_type: None,
        })
        .unwrap();
        new.add_subject(112233).unwrap();
        add_acl(&mut fabrics, FAB_1, new).unwrap();

        // Write on an RWVA with admin access - allow
        let mut req = AccessReq::new(&accessor, path, Access::WRITE, &[]);
        req.set_target_perms(Access::RWVA);
        assert_eq!(req.allow(&fabrics), true);
    }

    #[test]
    fn test_delete_for_fabric() {
        let mut fabrics = Fabrics::new();

        // Add fabric with ID 1
        add_fabric(&mut fabrics);

        // Add fabric with ID 2
        add_fabric(&mut fabrics);

        let path = GenericPath::new(Some(1), Some(1234), None);
        let accessor2 = SubjectDescriptor::new(
            1,
            false,
            AccessorSubjects::new(112233),
            Some(AuthMode::Case),
        );
        let mut req1 = AccessReq::new(&accessor2, path.clone(), Access::READ, &[]);
        req1.set_target_perms(Access::RWVA);
        let accessor3 = SubjectDescriptor::new(
            2,
            false,
            AccessorSubjects::new(112233),
            Some(AuthMode::Case),
        );
        let mut req2 = AccessReq::new(&accessor3, path, Access::READ, &[]);
        req2.set_target_perms(Access::RWVA);

        // Allow for subject match - target is wildcard - Fabric idx 2
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject(112233).unwrap();
        assert_eq!(add_acl(&mut fabrics, FAB_1, new).unwrap(), 0);

        // Allow for subject match - target is wildcard - Fabric idx 3
        let mut new = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
        new.add_subject(112233).unwrap();
        assert_eq!(add_acl(&mut fabrics, FAB_2, new).unwrap(), 0);

        // Req for Fabric idx 1 gets denied, and that for Fabric idx 2 is allowed
        assert_eq!(req1.allow(&fabrics), true);
        assert_eq!(req2.allow(&fabrics), true);
        remove_all_acl(&mut fabrics, FAB_1);
        assert_eq!(req1.allow(&fabrics), false);
        assert_eq!(req2.allow(&fabrics), true);
    }

    /// With the `AUXILIARY` feature advertised, a wildcard-target Group-auth
    /// entry no longer covers the root endpoint (but explicit targets and
    /// other endpoints are unaffected).
    #[test]
    fn test_aux_wildcard_group_excludes_root_endpoint() {
        let mut fabrics = Fabrics::new();
        add_fabric(&mut fabrics);

        const GROUP_ID: u64 = 0x12AB;

        // A regular (writable) ACL entry: Group auth, wildcard targets
        let mut entry = AclEntry::new(None, Privilege::OPERATE, AuthMode::Group);
        entry.add_subject(GROUP_ID).unwrap();
        add_acl(&mut fabrics, FAB_1, entry).unwrap();

        let accessor = SubjectDescriptor::new(
            FAB_1.get(),
            false,
            AccessorSubjects::new(GROUP_ID),
            Some(AuthMode::Group),
        );

        let ep0 = GenericPath::new(Some(0), Some(1234), None);
        let ep1 = GenericPath::new(Some(1), Some(1234), None);

        // Without the feature: the wildcard covers the whole node
        for path in [ep0.clone(), ep1.clone()] {
            let mut req = AccessReq::new(&accessor, path, Access::WRITE, &[]);
            req.set_target_perms(Access::WO);
            assert!(req.allow(&fabrics));
        }

        let accessor = SubjectDescriptor::new(
            FAB_1.get(),
            true,
            AccessorSubjects::new(GROUP_ID),
            Some(AuthMode::Group),
        );

        // With the feature: the root endpoint is excluded...
        let mut req = AccessReq::new(&accessor, ep0.clone(), Access::WRITE, &[]);
        req.set_target_perms(Access::WO);
        assert!(!req.allow(&fabrics));

        // ...other endpoints are unaffected...
        let mut req = AccessReq::new(&accessor, ep1, Access::WRITE, &[]);
        req.set_target_perms(Access::WO);
        assert!(req.allow(&fabrics));

        // ...and an entry explicitly targeting the root endpoint still works.
        remove_all_acl(&mut fabrics, FAB_1);
        let mut entry = AclEntry::new(None, Privilege::OPERATE, AuthMode::Group);
        entry.add_subject(GROUP_ID).unwrap();
        entry.add_target(Target::new(Some(0), None, None)).unwrap();
        add_acl(&mut fabrics, FAB_1, entry).unwrap();

        let mut req = AccessReq::new(&accessor, ep0, Access::WRITE, &[]);
        req.set_target_perms(Access::WO);
        assert!(req.allow(&fabrics));
    }
}
