/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

use core::mem::MaybeUninit;
use core::num::NonZeroU8;

use cfg_if::cfg_if;
use heapless::String;

use crate::acl::{self, AccessReq, AclEntry, AuthMode};
use crate::cert::{CertRef, MAX_CERT_TLV_LEN};
use crate::crypto::{
    CanonAeadKeyRef, CanonPkcPublicKeyRef, CanonPkcSecretKey, CanonPkcSecretKeyRef, Crypto,
    CryptoSensitive, Digest, Hash, Kdf, PKC_CANON_PUBLIC_KEY_LEN,
};
use crate::dm::Privilege;
use crate::error::{Error, ErrorCode};
use crate::group_keys::KeySet;
use crate::persist::{KvBlobStore, KvBlobStoreAccess, Persist, FABRIC_KEYS_START};
#[cfg(feature = "groups")]
use crate::tlv::Skippable;
use crate::tlv::{FromTLV, TLVElement, ToTLV};
use crate::transport::network::MatterLocalService;
use crate::utils::init::{init, Init, InitMaybeUninit, IntoFallibleInit};
use crate::utils::storage::Vec;

const COMPRESSED_FABRIC_ID_LEN: usize = 8;

/// All multicast-group fabric state: the group key sets, the group→keyset
/// mapping, and the group table. Gated as one inline module so the whole block
/// (consts, TLV structs and the `Groups` container) is compiled out with a
/// single `#[cfg]` when the `groups` feature is off, and re-exported so the rest
/// of `fabric` refers to these items unqualified.
#[cfg(feature = "groups")]
mod groups {
    use core::str::FromStr;

    use cfg_if::cfg_if;

    use heapless::String;

    use crate::dm::clusters::decl::groupcast::MulticastAddrPolicyEnum;
    use crate::error::{Error, ErrorCode};
    use crate::group_keys::GroupKeySet;
    use crate::tlv::{FromTLV, ToTLV};
    use crate::utils::init::{init, Init, InitDefault};
    use crate::utils::storage::Vec;

    cfg_if! {
        if #[cfg(feature = "max-group-keys-per-fabric-5")] {
            /// Max number of group key sets per fabric (excluding IPK at index 0).
            pub const MAX_GROUP_KEYS_PER_FABRIC: usize = 5;
        } else if #[cfg(feature = "max-group-keys-per-fabric-4")] {
            /// Max number of group key sets per fabric (excluding IPK at index 0).
            pub const MAX_GROUP_KEYS_PER_FABRIC: usize = 4;
        } else if #[cfg(feature = "max-group-keys-per-fabric-3")] {
            /// Max number of group key sets per fabric (excluding IPK at index 0).
            pub const MAX_GROUP_KEYS_PER_FABRIC: usize = 3;
        } else if #[cfg(feature = "max-group-keys-per-fabric-2")] {
            /// Max number of group key sets per fabric (excluding IPK at index 0).
            pub const MAX_GROUP_KEYS_PER_FABRIC: usize = 2;
        } else { // Matter requires a minimum of 3 group key sets per fabric
            /// Max number of group key sets per fabric (excluding IPK at index 0).
            pub const MAX_GROUP_KEYS_PER_FABRIC: usize = 3;
        }
    }

    /// Max length of a group name (per Matter spec).
    pub const MAX_GROUP_NAME_LEN: usize = 16;

    cfg_if! {
        if #[cfg(feature = "max-groups-per-fabric-32")] {
            /// Max number of group key map entries per fabric.
            pub const MAX_GROUPS_PER_FABRIC: usize = 32;
        } else if #[cfg(feature = "max-groups-per-fabric-16")] {
            /// Max number of group key map entries per fabric.
            pub const MAX_GROUPS_PER_FABRIC: usize = 16;
        } else if #[cfg(feature = "max-groups-per-fabric-12")] {
            /// Max number of group key map entries per fabric.
            pub const MAX_GROUPS_PER_FABRIC: usize = 12;
        } else if #[cfg(feature = "max-groups-per-fabric-8")] {
            /// Max number of group key map entries per fabric.
            pub const MAX_GROUPS_PER_FABRIC: usize = 9;
        } else if #[cfg(feature = "max-groups-per-fabric-7")] {
            /// Max number of group key map entries per fabric.
            pub const MAX_GROUPS_PER_FABRIC: usize = 7;
        } else if #[cfg(feature = "max-groups-per-fabric-6")] {
            /// Max number of group key map entries per fabric.
            pub const MAX_GROUPS_PER_FABRIC: usize = 6;
        } else if #[cfg(feature = "max-groups-per-fabric-5")] {
            /// Max number of group key map entries per fabric.
            pub const MAX_GROUPS_PER_FABRIC: usize = 5;
        } else if #[cfg(feature = "max-groups-per-fabric-4")] {
            /// Max number of group key map entries per fabric.
            pub const MAX_GROUPS_PER_FABRIC: usize = 4;
        } else { // Matter requires a minimum of 4 group table entries per fabric
            /// Max number of group key map entries per fabric.
            pub const MAX_GROUPS_PER_FABRIC: usize = 4;
        }
    }

    cfg_if! {
        if #[cfg(feature = "max-group-endpoints-per-fabric-5")] {
            /// Max number of endpoints per group entry.
            pub const GROUP_ENDPOINTS_PER_FABRIC: usize = 5;
        } else if #[cfg(feature = "max-group-endpoints-per-fabric-4")] {
            /// Max number of endpoints per group entry.
            pub const GROUP_ENDPOINTS_PER_FABRIC: usize = 4;
        } else if #[cfg(feature = "max-group-endpoints-per-fabric-3")] {
            /// Max number of endpoints per group entry.
            pub const GROUP_ENDPOINTS_PER_FABRIC: usize = 3;
        } else if #[cfg(feature = "max-group-endpoints-per-fabric-2")] {
            /// Max number of endpoints per group entry.
            pub const GROUP_ENDPOINTS_PER_FABRIC: usize = 2;
        } else if #[cfg(feature = "max-group-endpoints-per-fabric-1")] {
            /// Max number of endpoints per group entry.
            pub const GROUP_ENDPOINTS_PER_FABRIC: usize = 1;
        } else { // Default: 3 endpoints per group entry
            /// Max number of endpoints per group entry.
            pub const GROUP_ENDPOINTS_PER_FABRIC: usize = 3;
        }
    }

    /// A group table entry mapping a group ID to its endpoints and name.
    #[derive(Debug, FromTLV, ToTLV)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct GroupEndpointMapping {
        pub group_id: u16,
        pub endpoints: Vec<u16, GROUP_ENDPOINTS_PER_FABRIC>,
        pub group_name: String<MAX_GROUP_NAME_LEN>,
        /// Whether the (Groupcast-managed) group has auxiliary ACL entries
        /// generated for its endpoints - see the Groupcast cluster's
        /// `ConfigureAuxiliaryACL` command and the `AuxiliaryACL` attribute
        /// of the Access Control cluster.
        ///
        /// `None` (in blobs persisted before the field existed) means `false`.
        pub has_aux_acl: Option<bool>,
        /// The multicast-address policy of the group, when it is managed by
        /// the Groupcast cluster.
        ///
        /// `None` means the group was created via the legacy Groups cluster,
        /// which behaves like the `PerGroup` policy (such nodes join the
        /// fabric+group-scoped multicast address) - the `PerGroup` policy
        /// exists precisely for interop with them.
        pub mcast_policy: Option<MulticastAddrPolicyEnum>,
    }

    impl GroupEndpointMapping {
        /// Whether the group has auxiliary ACL entries generated for its
        /// endpoints.
        pub fn has_aux_acl(&self) -> bool {
            self.has_aux_acl.unwrap_or(false)
        }

        /// The effective multicast-address policy of the group (legacy
        /// Groups-cluster entries behave as `PerGroup`).
        pub fn effective_mcast_policy(&self) -> MulticastAddrPolicyEnum {
            self.mcast_policy
                .unwrap_or(MulticastAddrPolicyEnum::PerGroup)
        }

        /// Whether the group is managed by the Groupcast cluster (as opposed
        /// to the legacy Groups cluster).
        pub fn groupcast_managed(&self) -> bool {
            self.mcast_policy.is_some()
        }
    }

    /// A stored group key map entry (maps group ID to key set).
    #[derive(Debug, Clone, Default, FromTLV, ToTLV)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct GroupKeyMapping {
        pub group_id: u16,
        pub group_key_set_id: u16,
    }

    #[derive(Debug, FromTLV, ToTLV)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Groups {
        /// Group key sets (excluding IPK which is stored in `ipk`)
        key_sets: Vec<GroupKeySet, MAX_GROUP_KEYS_PER_FABRIC>,
        /// Groups keyset mapping
        key_map: Vec<GroupKeyMapping, MAX_GROUPS_PER_FABRIC>,
        /// Group table (group ID → endpoints + name)
        endpoint_mapping: Vec<GroupEndpointMapping, MAX_GROUPS_PER_FABRIC>,
    }

    impl Groups {
        pub(crate) const fn new() -> Self {
            Self {
                key_sets: Vec::new(),
                key_map: Vec::new(),
                endpoint_mapping: Vec::new(),
            }
        }

        pub(crate) fn init() -> impl Init<Self> {
            init!(Self {
                key_sets <- Vec::init(),
                key_map <- Vec::init(),
                endpoint_mapping <- Vec::init(),
            })
        }

        /// Return an iterator over the group key sets of the fabric
        pub fn key_set_iter(&self) -> impl Iterator<Item = &GroupKeySet> {
            self.key_sets.iter()
        }

        /// Find a group key set by ID
        pub fn key_set_get(&self, id: u16) -> Option<&GroupKeySet> {
            self.key_sets.iter().find(|e| e.group_key_set_id == id)
        }

        /// Add or update a group key set
        pub fn key_set_add(&mut self, entry: GroupKeySet) -> Result<(), Error> {
            if let Some(existing) = self
                .key_sets
                .iter_mut()
                .find(|e| e.group_key_set_id == entry.group_key_set_id)
            {
                *existing = entry;
            } else {
                self.key_sets
                    .push(entry)
                    .map_err(|_| ErrorCode::ResourceExhausted)?;
            }
            Ok(())
        }

        /// Remove a group key set by ID. Returns true if found and removed.
        pub fn key_set_remove(&mut self, id: u16) -> Result<(), Error> {
            let before = self.key_sets.len();
            self.key_sets.retain(|e| e.group_key_set_id != id);
            let removed = self.key_sets.len() < before;

            self.key_map_remove_by_key_set(id);

            // Check if element was actually removed
            if removed {
                Ok(())
            } else {
                Err(Error::new(ErrorCode::NotFound))
            }
        }

        pub fn key_map_add(&mut self, entry: GroupKeyMapping) -> Result<(), Error> {
            self.key_map
                .push(entry)
                .map_err(|_| ErrorCode::ResourceExhausted)?;

            Ok(())
        }

        /// Return an iterator over the group key map entries of the fabric
        pub fn key_map_iter(&self) -> impl Iterator<Item = &GroupKeyMapping> {
            self.key_map.iter()
        }

        /// Replace all group key map entries
        pub fn key_map_replace(
            &mut self,
            entries: impl Iterator<Item = GroupKeyMapping>,
        ) -> Result<(), Error> {
            self.key_map.clear();
            for entry in entries {
                self.key_map
                    .push(entry)
                    .map_err(|_| ErrorCode::ResourceExhausted)?;
            }
            Ok(())
        }

        /// Remove group key map entries that reference a specific key set ID
        pub fn key_map_remove_by_key_set(&mut self, key_set_id: u16) {
            self.key_map.retain(|e| e.group_key_set_id != key_set_id);
        }

        /// Return an iterator over the group table entries
        pub fn iter(&self) -> impl Iterator<Item = &GroupEndpointMapping> {
            self.endpoint_mapping.iter()
        }

        /// Look up a group by ID
        pub fn get(&self, group_id: u16) -> Option<&GroupEndpointMapping> {
            self.endpoint_mapping
                .iter()
                .find(|e| e.group_id == group_id)
        }

        /// Look up a group by ID, mutably
        pub fn get_mut(&mut self, group_id: u16) -> Option<&mut GroupEndpointMapping> {
            self.endpoint_mapping
                .iter_mut()
                .find(|e| e.group_id == group_id)
        }

        /// Add an endpoint to a group.
        /// Returns true if the endpoint was already a member (name still updated per spec).
        pub fn add(
            &mut self,
            endpoint_id: u16,
            group_id: u16,
            group_name: &str,
        ) -> Result<bool, Error> {
            // Validate the name up-front, so that a rejected command leaves the table untouched
            let group_name =
                String::from_str(group_name).map_err(|_| ErrorCode::ConstraintError)?;

            let entry = if let Some(entry) = self
                .endpoint_mapping
                .iter_mut()
                .find(|e| e.group_id == group_id)
            {
                entry
            } else {
                self.endpoint_mapping
                    .push(GroupEndpointMapping {
                        group_id,
                        endpoints: Vec::new(),
                        group_name: group_name.clone(),
                        has_aux_acl: None,
                        mcast_policy: None,
                    })
                    .map_err(|_| ErrorCode::ResourceExhausted)?;
                unwrap!(self.endpoint_mapping.last_mut())
            };

            // Update group name
            entry.group_name = group_name;

            if entry.endpoints.contains(&endpoint_id) {
                return Ok(true);
            }

            entry
                .endpoints
                .push(endpoint_id)
                .map_err(|_| ErrorCode::ResourceExhausted)?;

            Ok(false)
        }

        /// Remove an endpoint from a group, or from all groups if `group_id` is `None`.
        /// Returns true if the endpoint was removed from at least one group.
        pub fn remove(&mut self, endpoint_id: u16, group_id: Option<u16>) -> bool {
            let mut removed = false;

            for entry in self.endpoint_mapping.iter_mut() {
                if group_id.is_some_and(|id| id != entry.group_id) {
                    continue;
                }
                let before = entry.endpoints.len();
                entry.endpoints.retain(|&ep| ep != endpoint_id);
                if entry.endpoints.len() < before {
                    removed = true;
                }
            }

            // Remove entries with no endpoints left - except Groupcast-managed
            // ones, which may legitimately exist with no endpoints (a
            // sender-only membership); the Groupcast cluster removes those
            // explicitly via its `LeaveGroup` command.
            self.endpoint_mapping
                .retain(|e| !e.endpoints.is_empty() || e.groupcast_managed());

            removed
        }

        /// Join endpoints to a group on behalf of the Groupcast cluster,
        /// creating the membership if it does not exist.
        ///
        /// - `endpoints`: the endpoints to add (may be empty for a
        ///   sender-only membership); duplicates are omitted;
        /// - `replace`: when `true`, the given endpoints replace the
        ///   existing list instead of being appended;
        /// - `mcast_policy`: the multicast-address policy; applied on
        ///   creation, or updated when `Some` on an existing membership.
        ///
        /// Errors with `ResourceExhausted` when the membership or endpoint
        /// capacity is exceeded; the membership is left unchanged in that
        /// case, except that a possibly-performed `replace` clearing is
        /// rolled back by restoring nothing (the caller re-checks capacity
        /// upfront via [`Self::group_count`] and the endpoint capacity).
        pub fn groupcast_join(
            &mut self,
            group_id: u16,
            endpoints: &[u16],
            replace: bool,
            mcast_policy: Option<MulticastAddrPolicyEnum>,
        ) -> Result<(), Error> {
            let entry = if let Some(entry) = self
                .endpoint_mapping
                .iter_mut()
                .find(|e| e.group_id == group_id)
            {
                entry
            } else {
                self.endpoint_mapping
                    .push(GroupEndpointMapping {
                        group_id,
                        endpoints: Vec::new(),
                        group_name: String::new(),
                        has_aux_acl: Some(false),
                        mcast_policy: Some(
                            mcast_policy.unwrap_or(MulticastAddrPolicyEnum::IanaAddr),
                        ),
                    })
                    .map_err(|_| ErrorCode::ResourceExhausted)?;
                unwrap!(self.endpoint_mapping.last_mut())
            };

            // Joining via Groupcast upgrades a legacy entry to
            // Groupcast-managed (the default policy matches the legacy
            // behavior)
            if entry.mcast_policy.is_none() {
                entry.mcast_policy = Some(MulticastAddrPolicyEnum::PerGroup);
            }

            if let Some(mcast_policy) = mcast_policy {
                entry.mcast_policy = Some(mcast_policy);
            }

            if replace {
                entry.endpoints.clear();
            }

            for endpoint in endpoints {
                if !entry.endpoints.contains(endpoint) {
                    entry
                        .endpoints
                        .push(*endpoint)
                        .map_err(|_| ErrorCode::ResourceExhausted)?;
                }
            }

            Ok(())
        }

        /// Remove a whole group membership. Returns `true` if it existed.
        pub fn groupcast_remove(&mut self, group_id: u16) -> bool {
            let before = self.endpoint_mapping.len();
            self.endpoint_mapping.retain(|e| e.group_id != group_id);

            before != self.endpoint_mapping.len()
        }

        /// Set the `has_aux_acl` flag of a group membership.
        /// Returns `true` if the flag changed.
        pub fn set_has_aux_acl(&mut self, group_id: u16, has_aux_acl: bool) -> bool {
            let Some(entry) = self
                .endpoint_mapping
                .iter_mut()
                .find(|e| e.group_id == group_id)
            else {
                return false;
            };

            let changed = entry.has_aux_acl() != has_aux_acl;
            entry.has_aux_acl = Some(has_aux_acl);

            changed
        }

        /// The number of group memberships of this fabric.
        pub fn group_count(&self) -> usize {
            self.endpoint_mapping.len()
        }

        /// Look up the key set ID mapped to a group, if any.
        pub fn key_map_get(&self, group_id: u16) -> Option<u16> {
            self.key_map
                .iter()
                .find(|e| e.group_id == group_id)
                .map(|e| e.group_key_set_id)
        }

        /// Map a group to a key set, replacing any previous mapping of that
        /// group.
        pub fn key_map_set_group(&mut self, group_id: u16, key_set_id: u16) -> Result<(), Error> {
            if let Some(entry) = self.key_map.iter_mut().find(|e| e.group_id == group_id) {
                entry.group_key_set_id = key_set_id;
                return Ok(());
            }

            self.key_map
                .push(GroupKeyMapping {
                    group_id,
                    group_key_set_id: key_set_id,
                })
                .map_err(|_| ErrorCode::ResourceExhausted.into())
        }

        /// Remove all key-set mappings of the given group.
        pub fn key_map_remove_group(&mut self, group_id: u16) {
            self.key_map.retain(|e| e.group_id != group_id);
        }
    }

    impl Default for Groups {
        fn default() -> Self {
            Self::new()
        }
    }

    impl InitDefault for Groups {
        fn init_default() -> impl Init<Self> {
            Self::init()
        }
    }
}

#[cfg(feature = "groups")]
pub use groups::*;

/// Fabric type
#[derive(Debug, ToTLV, FromTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Fabric {
    /// Fabric local index
    fab_idx: NonZeroU8,
    /// Fabric node ID
    node_id: u64,
    /// Fabric ID
    fabric_id: u64,
    /// Vendor ID
    vendor_id: u16,
    /// Compressed ID
    compressed_fabric_id: u64,
    /// Fabric secret key
    secret_key: CanonPkcSecretKey,
    /// Root CA certificate to be used when verifying the node's certificate
    ///
    /// Note that we deviate from the Matter spec here, in that we store the
    /// root certificate in the Fabric type itself, rather than - as the
    /// spec mandates - in a separate Root CA store
    ///
    /// This simplifies the implementation, but results in potentially multiple
    /// copies of the same Root CA used accross multiple fabrics.
    root_ca: Vec<u8, { MAX_CERT_TLV_LEN }>,
    /// Either the Intermediate CA certificate (`vvsc_set == false`) or the
    /// Vendor Verification Signing Cert (`vvsc_set == true`). The two are
    /// mutually exclusive in the cert chain (Matter Core spec) —
    /// a fabric with an ICAC cannot also carry a VVSC and vice
    /// versa — so we share one buffer instead of paying for both. Empty
    /// means neither is set; in that case `vvsc_set` is meaningless.
    icac_or_vvsc: Vec<u8, { MAX_CERT_TLV_LEN }>,
    /// Selector for what `icac_or_vvsc` holds: `false` for an ICAC,
    /// `true` for a VVSC.
    vvsc_set: bool,
    /// Node Operational Certificate
    noc: Vec<u8, { MAX_CERT_TLV_LEN }>,
    /// Identity Protection Key
    ipk: KeySet,
    /// Fabric label; unique accross all fabrics on the device
    label: String<32>,
    /// Access Control List
    acl: Vec<AclEntry, { acl::MAX_ACL_ENTRIES_PER_FABRIC }>,
    /// Fabric group information.
    #[cfg(feature = "groups")]
    #[tagval(13)]
    groups: Skippable<Groups>,
    /// VID Verification Statement (Matter Core spec).
    /// Either empty (not set) or exactly `VID_VERIFICATION_STATEMENT_LEN`
    /// bytes long; the cluster XML enforces both bounds at the schema
    /// level (`length="85" minLength="85"`).
    #[tagval(14)]
    vid_verification_statement: Vec<u8, VID_VERIFICATION_STATEMENT_LEN>,
}

/// Exact length of a non-empty VID Verification Statement.
/// Matches `length="85" minLength="85"` on
/// `OperationalCredentials::SetVIDVerificationStatement.vid_verification_statement`.
pub const VID_VERIFICATION_STATEMENT_LEN: usize = 85;

impl Fabric {
    /// Return an in-place-initializer for a Fabric type, with the
    /// provided Fabric Index and KeyPair
    ///
    /// All other fields are initialized to default values, which are NOT
    /// valid for the operation of the fabric.
    ///
    /// The Fabric must be updated with the correct values before it can be
    /// used, via `Fabric::update`.
    fn init(fab_idx: NonZeroU8) -> impl Init<Self> {
        // NOTE: the `init!` macro does not accept `#[cfg]` on its field entries,
        // so the `groups` field (present only under the `groups` feature) forces
        // two variants of the initializer that differ solely by that last field.
        #[cfg(feature = "groups")]
        let r = init!(Self {
            fab_idx,
            node_id: 0,
            fabric_id: 0,
            vendor_id: 0,
            compressed_fabric_id: 0,
            secret_key <- CanonPkcSecretKey::init(),
            root_ca <- Vec::init(),
            icac_or_vvsc <- Vec::init(),
            vvsc_set: false,
            noc <- Vec::init(),
            ipk <- KeySet::init(),
            label: String::new(),
            acl <- Vec::init(),
            vid_verification_statement <- Vec::init(),
            groups <- Skippable::init_default(),
        });

        #[cfg(not(feature = "groups"))]
        let r = init!(Self {
            fab_idx,
            node_id: 0,
            fabric_id: 0,
            vendor_id: 0,
            compressed_fabric_id: 0,
            secret_key <- CanonPkcSecretKey::init(),
            root_ca <- Vec::init(),
            icac_or_vvsc <- Vec::init(),
            vvsc_set: false,
            noc <- Vec::init(),
            ipk <- KeySet::init(),
            label: String::new(),
            acl <- Vec::init(),
            vid_verification_statement <- Vec::init(),
        });
        r
    }

    /// Update the fabric with the provided data so that it can operate.
    ///
    /// This method is supposed to be called right after `Fabric::init` or
    /// when the NOC of the fabric needs to be updated.
    ///
    /// `root_ca` is `None` when called from the `UpdateNOC` flow — Matter
    /// Core spec keeps the fabric's root cert unchanged
    /// across `UpdateNOC`, and re-passing the existing bytes here would
    /// require a (large) caller-side copy of `self.root_ca`. `Some(...)`
    /// is used by the initial `AddNOC` flow, where the cert was just
    /// staged in the fail-safe context.
    #[allow(clippy::too_many_arguments)]
    fn update<C: Crypto>(
        &mut self,
        crypto: C,
        root_ca: Option<&[u8]>,
        noc: &[u8],
        icac: &[u8],
        secret_key: CanonPkcSecretKeyRef<'_>,
        epoch_key: Option<CanonAeadKeyRef<'_>>,
        vendor_id: Option<u16>,
        case_admin_subject: Option<u64>,
    ) -> Result<(), Error> {
        if let Some(root_ca) = root_ca {
            self.root_ca.clear();
            self.root_ca
                .extend_from_slice(root_ca)
                .map_err(|_| ErrorCode::BufferTooSmall)?;
        }
        // `AddNOC` / `UpdateNOC` always replace the cert chain, so any
        // previously-staged VVSC for this fabric is implicitly cleared
        // here — the spec doesn't allow an ICAC and a VVSC to coexist.
        self.icac_or_vvsc.clear();
        self.icac_or_vvsc
            .extend_from_slice(icac)
            .map_err(|_| ErrorCode::BufferTooSmall)?;
        self.vvsc_set = false;
        self.noc.clear();
        self.noc
            .extend_from_slice(noc)
            .map_err(|_| ErrorCode::BufferTooSmall)?;

        let root_cert = CertRef::new(TLVElement::new(self.root_ca.as_slice()));
        let noc_cert = CertRef::new(TLVElement::new(noc));

        self.node_id = noc_cert.get_node_id()?;
        self.fabric_id = noc_cert.get_fabric_id()?;
        self.compressed_fabric_id = Self::compute_compressed_fabric_id(
            &crypto,
            root_cert.pubkey()?.try_into()?,
            self.fabric_id,
        );

        if let Some(epoch_key) = epoch_key {
            self.ipk
                .update(&crypto, epoch_key, &self.compressed_fabric_id)?;
        }

        if let Some(vendor_id) = vendor_id {
            self.vendor_id = vendor_id;
        }

        if let Some(case_admin_subject) = case_admin_subject {
            self.acl.clear();
            self.acl.push_init(
                AclEntry::init(None, Privilege::ADMIN, AuthMode::Case)
                    .into_fallible()
                    .chain(|e| {
                        e.fab_idx = Some(self.fab_idx);
                        e.add_subject(case_admin_subject)
                    }),
                || ErrorCode::ResourceExhausted.into(),
            )?;
        }

        self.secret_key.load(secret_key);

        Ok(())
    }

    pub fn mdns_service(&self) -> Option<MatterLocalService> {
        self.mdns_service_for(self.node_id)
    }

    pub fn mdns_service_for(&self, node_id: u64) -> Option<MatterLocalService> {
        (!self.noc.is_empty()).then_some(MatterLocalService::Commissioned {
            compressed_fabric_id: self.compressed_fabric_id,
            node_id,
        })
    }

    /// Is the fabric matching the privided destination ID
    pub fn is_dest_id<C: Crypto>(
        &self,
        crypto: C,
        random: &[u8],
        target: &[u8],
    ) -> Result<(), Error> {
        let mut mac = crypto.hmac(self.ipk.op_key())?;

        mac.update(random)?;
        mac.update(CertRef::new(TLVElement::new(self.root_ca())).pubkey()?)?;

        mac.update(&self.fabric_id.to_le_bytes())?;
        mac.update(&self.node_id.to_le_bytes())?;

        let mut id = MaybeUninit::<Hash>::uninit(); // TODO MEDIUM BUFFER
        let id = id.init_with(Hash::init());
        mac.finish(id)?;
        if id.access() == target {
            Ok(())
        } else {
            Err(ErrorCode::NotFound.into())
        }
    }

    /// Compute the destination identifier for a target node on this fabric.
    ///
    /// Used by the CASE initiator to build Sigma1 (spec).
    /// destinationMessage = initiatorRandom || rootPublicKey || fabricId(LE) || nodeId(LE)
    /// destinationIdentifier = Crypto_HMAC(key=IPK, message=destinationMessage)
    ///
    /// # Arguments
    /// - `target_node_id`: The node ID of the destination (peer) node, NOT the local node.
    pub fn compute_dest_id<C: Crypto>(
        &self,
        crypto: C,
        random: &[u8],
        target_node_id: u64,
        out: &mut Hash,
    ) -> Result<(), Error> {
        let mut mac = crypto.hmac(self.ipk.op_key())?;

        mac.update(random)?;
        mac.update(CertRef::new(TLVElement::new(self.root_ca())).pubkey()?)?;
        mac.update(&self.fabric_id.to_le_bytes())?;
        mac.update(&target_node_id.to_le_bytes())?;

        mac.finish(out)?;
        Ok(())
    }

    /// Return the secret key of the fabric
    pub fn secret_key(&self) -> CanonPkcSecretKeyRef<'_> {
        self.secret_key.reference()
    }

    /// Return the fabric's node ID
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Return the fabric's fabric ID
    pub fn fabric_id(&self) -> u64 {
        self.fabric_id
    }

    /// Return the fabric's local index
    pub fn fab_idx(&self) -> NonZeroU8 {
        self.fab_idx
    }

    /// Return the fabric's compressed fabric ID
    pub fn compressed_fabric_id(&self) -> u64 {
        self.compressed_fabric_id
    }

    /// Return the fabric's Vendor ID
    pub fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    /// Return the fabric's label
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return the fabric's Root CA in encoded TLV form
    ///
    /// Use `CertRef` to decode on the fly
    pub fn root_ca(&self) -> &[u8] {
        &self.root_ca
    }

    /// Return the fabric's ICAC in encoded TLV form
    ///
    /// Use `CertRef` to decode on the fly.
    ///
    /// Note that this method might return an empty slice,
    /// which indicates that this fabric does not have an ICAC.
    /// (The shared `icac_or_vvsc` slot may instead hold a VVSC; see
    /// `vvsc()`.)
    pub fn icac(&self) -> &[u8] {
        if self.vvsc_set {
            &[]
        } else {
            &self.icac_or_vvsc
        }
    }

    /// Return the fabric's NOC
    pub fn noc(&self) -> &[u8] {
        &self.noc
    }

    /// Return the fabric's IPK
    pub fn ipk(&self) -> &KeySet {
        &self.ipk
    }

    /// Return the fabric's groups, or an empty group state if this fabric was
    /// persisted before the `groups` field existed (see [`Fabric::groups`]).
    #[cfg(feature = "groups")]
    pub fn groups(&self) -> &Groups {
        self.groups.value()
    }

    /// Return a mutable reference to the fabric's groups, materializing empty
    /// group state on first access if it was absent.
    #[cfg(feature = "groups")]
    pub fn groups_mut(&mut self) -> &mut Groups {
        self.groups.value_mut()
    }

    /// Return the fabric's VVSC bytes (Matter Core spec).
    /// Empty when `SetVIDVerificationStatement` has never been called with
    /// a non-empty VVSC for this fabric, or when the fabric instead carries
    /// an ICAC (see `icac()`) — VVSC and ICAC share storage and are
    /// mutually exclusive per spec.
    pub fn vvsc(&self) -> &[u8] {
        if self.vvsc_set {
            &self.icac_or_vvsc
        } else {
            &[]
        }
    }

    /// Return the fabric's VID Verification Statement bytes (Matter Core
    /// spec). Either empty (not set) or
    /// exactly `VID_VERIFICATION_STATEMENT_LEN` bytes.
    pub fn vid_verification_statement(&self) -> &[u8] {
        &self.vid_verification_statement
    }

    /// Apply a `SetVIDVerificationStatement` mutation to the fabric. Each
    /// field is `Some(slice)` for "replace with this value" (where an
    /// empty slice clears the value), or `None` for "leave unchanged".
    /// The caller is responsible for spec-level validation (size limits,
    /// VVSC vs ICAC mutual exclusion, "all fields absent" → INVALID_COMMAND,
    /// VendorID range, …); this method only enforces the storage
    /// invariants (heapless `Vec` capacity).
    pub fn set_vid_verification(
        &mut self,
        vendor_id: Option<u16>,
        vid_verification_statement: Option<&[u8]>,
        vvsc: Option<&[u8]>,
    ) -> Result<(), Error> {
        if let Some(vid) = vendor_id {
            self.vendor_id = vid;
        }

        if let Some(vvs) = vid_verification_statement {
            self.vid_verification_statement.clear();
            self.vid_verification_statement
                .extend_from_slice(vvs)
                .map_err(|_| ErrorCode::BufferTooSmall)?;
        }

        if let Some(v) = vvsc {
            // VVSC and ICAC share `icac_or_vvsc`. Clearing the VVSC must
            // not stomp on an existing ICAC: per spec the
            // two never coexist on the same fabric, so an empty-VVSC
            // request against a fabric that holds an ICAC is a no-op
            // here. The cluster handler still rejects a *non-empty* VVSC
            // against such a fabric upstream.
            if !v.is_empty() {
                self.icac_or_vvsc.clear();
                self.icac_or_vvsc
                    .extend_from_slice(v)
                    .map_err(|_| ErrorCode::BufferTooSmall)?;
                self.vvsc_set = true;
            } else if self.vvsc_set {
                self.icac_or_vvsc.clear();
                self.vvsc_set = false;
            }
        }

        Ok(())
    }

    /// Return the ACL entries of the fabric
    pub fn acl(&self) -> &[AclEntry] {
        &self.acl
    }

    /// Return an iterator over the ACL entries of the fabric
    pub fn acl_iter(&self) -> impl Iterator<Item = &AclEntry> {
        self.acl.iter()
    }

    /// Add a new ACL entry to the fabric.
    ///
    /// Return the index of the added entry.
    pub fn acl_add(&mut self, mut entry: AclEntry) -> Result<usize, Error> {
        if entry.auth_mode() == AuthMode::Pase {
            // Reserved for future use
            Err(ErrorCode::ConstraintError)?;
        }

        // Overwrite the fabric index with our accessing fabric index
        entry.fab_idx = Some(self.fab_idx);

        self.acl
            .push(entry)
            .map_err(|_| ErrorCode::ResourceExhausted)?;

        Ok(self.acl.len() - 1)
    }

    /// Add a new ACL entry to the fabric using the supplied initializer.
    ///
    /// Return the index of the added entry.
    pub fn acl_add_init<I>(&mut self, init: I) -> Result<usize, Error>
    where
        I: Init<AclEntry, Error>,
    {
        self.acl
            .push_init(init, || ErrorCode::ResourceExhausted.into())?;

        let idx = self.acl.len() - 1;

        if self.acl[idx].auth_mode() == AuthMode::Pase {
            // Reserved for future use
            self.acl.pop();
            Err(ErrorCode::ConstraintError)?;
        }

        let entry = &mut self.acl[idx];

        // Overwrite the fabric index with our accessing fabric index
        entry.fab_idx = Some(self.fab_idx);

        Ok(idx)
    }

    /// Update an existing ACL entry in the fabric
    pub fn acl_update(&mut self, idx: usize, mut entry: AclEntry) -> Result<(), Error> {
        if self.acl.len() <= idx {
            return Err(ErrorCode::NotFound.into());
        }

        // Overwrite the fabric index with our accessing fabric index
        entry.fab_idx = Some(self.fab_idx);

        self.acl[idx] = entry;

        Ok(())
    }

    /// Update an existing ACL entry in the fabric using the supplied initializer
    pub fn acl_update_init<I>(&mut self, idx: usize, init: I) -> Result<(), Error>
    where
        I: Init<AclEntry, Error>,
    {
        if self.acl.len() <= idx {
            return Err(ErrorCode::NotFound.into());
        }

        // TODO: Needs #214
        let mut entry = MaybeUninit::uninit();
        let entry = entry.try_init_with(init)?.clone();

        self.acl[idx] = entry;

        // Overwrite the fabric index with our accessing fabric index
        self.acl[idx].fab_idx = Some(self.fab_idx);

        Ok(())
    }

    /// Remove an ACL entry from the fabric
    pub fn acl_remove(&mut self, idx: usize) -> Result<(), Error> {
        if self.acl.len() <= idx {
            return Err(ErrorCode::NotFound.into());
        }

        self.acl.remove(idx);

        Ok(())
    }

    /// Remove all ACL entries from the fabric
    pub fn acl_remove_all(&mut self) {
        // pub for tests
        self.acl.clear();
    }

    /// Check if the fabric allows the given access request
    ///
    /// Note that the fabric index in the access request needs to be checked before that.
    /// `aux_acl_enabled` conveys whether the node advertises the Access Control
    /// cluster's `AUXILIARY` feature - see `AclEntry::allow`.
    fn allow(&self, req: &AccessReq, aux_acl_enabled: bool) -> bool {
        for e in &self.acl {
            if e.allow(req, aux_acl_enabled) {
                return true;
            }
        }

        debug!(
            "ACL Disallow for subjects {} fab idx {}",
            req.accessor().subjects(),
            req.accessor().fab_idx
        );

        false
    }

    /// Compute the compressed fabric ID
    pub(crate) fn compute_compressed_fabric_id<C: Crypto>(
        crypto: C,
        root_pubkey: CanonPkcPublicKeyRef<'_>,
        fabric_id: u64,
    ) -> u64 {
        const COMPRESSED_FABRIC_ID_INFO: &[u8; 16] = &[
            0x43, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x46, 0x61, 0x62, 0x72,
            0x69, 0x63,
        ];

        let mut compressed_fabric_id = CryptoSensitive::<{ COMPRESSED_FABRIC_ID_LEN }>::new();
        unwrap!(unwrap!(crypto.kdf()).expand(
            &fabric_id.to_be_bytes(),
            root_pubkey.split::<1, { PKC_CANON_PUBLIC_KEY_LEN - 1 }>().1,
            COMPRESSED_FABRIC_ID_INFO,
            &mut compressed_fabric_id,
        ));

        u64::from_be_bytes(*compressed_fabric_id.access())
    }
}

cfg_if! {
    if #[cfg(feature = "max-fabrics-32")] {
        /// Max number of supported fabrics
        pub const MAX_FABRICS: usize = 32;
    } else if #[cfg(feature = "max-fabrics-16")] {
        /// Max number of supported fabrics
        pub const MAX_FABRICS: usize = 16;
    } else if #[cfg(feature = "max-fabrics-8")] {
        /// Max number of supported fabrics
        pub const MAX_FABRICS: usize = 8;
    } else if #[cfg(feature = "max-fabrics-7")] {
        /// Max number of supported fabrics
        pub const MAX_FABRICS: usize = 7;
    } else if #[cfg(feature = "max-fabrics-6")] {
        /// Max number of supported fabrics
        pub const MAX_FABRICS: usize = 6;
    } else { // Matter requires a minimum of 5 fabrics
        /// Max number of supported fabrics
        pub const MAX_FABRICS: usize = 5;
    }
}

/// All fabrics
pub struct Fabrics {
    fabrics: Vec<Fabric, MAX_FABRICS>,
}

impl Default for Fabrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Fabrics {
    /// Create a new Fabrics instance
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            fabrics: Vec::new(),
        }
    }

    /// Return an in-place-initializer for a Fabrics type
    pub fn init() -> impl Init<Self> {
        init!(Self {
            fabrics <- Vec::init(),
        })
    }

    /// Remove all fabrics
    pub(crate) fn reset(&mut self) {
        self.fabrics.clear();
    }

    /// Remove all fabrics from the provided BLOB store as well as from memory.
    ///
    /// # Arguments
    /// - `store`: the BLOB store to remove the fabrics from
    /// - `buf`: a temporary buffer to use for removing the fabrics
    pub(crate) fn reset_persist<S: KvBlobStore>(
        &mut self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.reset();

        for idx in 1..=255u8 {
            store.remove(FABRIC_KEYS_START + idx as u16, buf)?;
        }

        info!("Removed all fabrics from storage");

        Ok(())
    }

    /// Load all fabrics from the provided BLOB store
    ///
    /// # Arguments
    /// - `store`: the BLOB store to load the fabrics from
    /// - `buf`: a temporary buffer to use for loading the fabrics
    pub(crate) fn load_persist<S: KvBlobStore>(
        &mut self,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.reset();

        for fab_idx in 1..=255u8 {
            self.add_load(fab_idx, &mut store, buf)?;
        }

        Ok(())
    }

    pub(crate) fn add_load<S: KvBlobStore>(
        &mut self,
        fab_idx: u8,
        mut store: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        if let Some(data) = store.load(FABRIC_KEYS_START + fab_idx as u16, buf)? {
            self.fabrics
                .push_init(Fabric::init_from_tlv(TLVElement::new(data)), || {
                    ErrorCode::ResourceExhausted.into()
                })?;

            let fabric = unwrap!(self.fabrics.last());

            info!(
                "Loaded fabric {} with ID {:x} from storage",
                fabric.fab_idx(),
                fabric.compressed_fabric_id()
            );
        }

        Ok(())
    }

    /// Add a new fabric to the fabrics with the provided data and immediately updates it with the provided post-init updater.
    ///
    /// This method is unlikely to be useful outside of tests.
    ///
    /// If this operation succeeds, the fabric immediately becomes operational.
    pub fn add_with_post_init<F>(&mut self, post_init: F) -> Result<&mut Fabric, Error>
    where
        F: FnOnce(&mut Fabric) -> Result<(), Error>,
    {
        let max_fab_idx = self
            .iter()
            .map(|fabric| fabric.fab_idx().get())
            .max()
            .unwrap_or(0);
        let fab_idx = unwrap!(NonZeroU8::new(if max_fab_idx < u8::MAX - 1 {
            // First try with the next available fabric index larger than all currently used
            max_fab_idx + 1
        } else {
            // If there is already a fabric with index 254, try to find the first unused one
            let Some(fab_idx) = (1..u8::MAX)
                .find(|fab_idx| self.iter().all(|fabric| fabric.fab_idx().get() != *fab_idx))
            else {
                return Err(ErrorCode::ResourceExhausted.into());
            };

            fab_idx
        })); // We never use 0 as a fabric index, nor u8::MAX

        self.fabrics.push_init(
            Fabric::init(fab_idx)
                .into_fallible::<Error>()
                .chain(post_init),
            || ErrorCode::ResourceExhausted.into(),
        )?;

        let fabric = unwrap!(self.fabrics.last_mut());

        Ok(fabric)
    }

    /// Add a new fabric to the fabrics with the provided data.
    ///
    /// If this operation succeeds, the fabric immediately becomes operational.
    #[allow(clippy::too_many_arguments)]
    pub fn add<C: Crypto>(
        &mut self,
        crypto: C,
        secret_key: CanonPkcSecretKeyRef<'_>,
        root_ca: &[u8],
        noc: &[u8],
        icac: &[u8],
        epoch_key: Option<CanonAeadKeyRef<'_>>,
        vendor_id: u16,
        case_admin_subject: u64,
    ) -> Result<&mut Fabric, Error> {
        self.add_with_post_init(|fabric| {
            fabric.update(
                crypto,
                Some(root_ca),
                noc,
                icac,
                secret_key,
                epoch_key,
                Some(vendor_id),
                Some(case_admin_subject),
            )
        })
    }

    /// Add a new fabric with an explicit ACL instead of the single admin entry
    /// [`Fabrics::add`] seeds.
    ///
    /// If this operation succeeds, the fabric immediately becomes operational.
    #[allow(clippy::too_many_arguments)]
    pub fn add_with_acl<C, I>(
        &mut self,
        crypto: C,
        secret_key: CanonPkcSecretKeyRef<'_>,
        root_ca: &[u8],
        noc: &[u8],
        icac: &[u8],
        epoch_key: Option<CanonAeadKeyRef<'_>>,
        vendor_id: u16,
        acl: I,
    ) -> Result<&mut Fabric, Error>
    where
        C: Crypto,
        I: IntoIterator<Item = Result<AclEntry, Error>>,
    {
        self.add_with_post_init(|fabric| {
            fabric.update(
                crypto,
                Some(root_ca),
                noc,
                icac,
                secret_key,
                epoch_key,
                Some(vendor_id),
                None,
            )?;

            for entry in acl {
                fabric.acl_add(entry?)?;
            }

            Ok(())
        })
    }

    /// Update an existing fabric with the provided data (usually, as a result of an `UpdateNOC` IM command).
    ///
    /// The fabric's existing root cert is preserved across this call —
    /// `UpdateNOC` per Matter Core spec is not allowed
    /// to change the root, and re-passing the bytes would force the
    /// caller to take a (large) heap-less copy of `Fabric::root_ca`.
    ///
    /// If this operation succeeds, the fabric immediately becomes operational.
    /// Note however, that the caller is expected to remove all sessions associated with the fabric, as they would
    /// contain invalid keys after the NOC update.
    pub fn update<C: Crypto>(
        &mut self,
        crypto: C,
        fab_idx: NonZeroU8,
        secret_key: CanonPkcSecretKeyRef<'_>,
        noc: &[u8],
        icac: &[u8],
    ) -> Result<&mut Fabric, Error> {
        let fabric = self.fabric_mut(fab_idx)?;

        fabric.update(crypto, None, noc, icac, secret_key, None, None, None)?;

        Ok(fabric)
    }

    pub fn update_label(&mut self, fab_idx: NonZeroU8, label: &str) -> Result<&mut Fabric, Error> {
        if self.iter().any(|fabric| {
            fabric.fab_idx != fab_idx && !fabric.label.is_empty() && fabric.label == label
        }) {
            return Err(ErrorCode::Invalid.into());
        }

        let fabric = self.fabric_mut(fab_idx)?;
        fabric.label.clear();
        fabric
            .label
            .push_str(label)
            .map_err(|_| ErrorCode::ConstraintError)?;

        Ok(fabric)
    }

    /// Remove a fabric from the fabrics
    pub fn remove(&mut self, fab_idx: NonZeroU8) -> Result<(), Error> {
        let _ = self.fabric(fab_idx)?;

        self.fabrics.retain(|fabric| fabric.fab_idx != fab_idx);

        Ok(())
    }

    /// Get a fabric that matches the provided destination ID
    pub fn get_by_dest_id<C: Crypto>(
        &self,
        crypto: C,
        random: &[u8],
        target: &[u8],
    ) -> Option<&Fabric> {
        self.iter()
            .find(|fabric| fabric.is_dest_id(&crypto, random, target).is_ok())
    }

    /// Get a fabric by its local index
    pub fn get(&self, fab_idx: NonZeroU8) -> Option<&Fabric> {
        self.iter().find(|fabric| fabric.fab_idx == fab_idx)
    }

    /// Get a mutable fabric reference by its local index
    pub fn get_mut(&mut self, fab_idx: NonZeroU8) -> Option<&mut Fabric> {
        // pub for testing
        self.fabrics
            .iter_mut()
            .find(|fabric| fabric.fab_idx == fab_idx)
    }

    /// Iterate over the fabrics
    pub fn iter(&self) -> impl Iterator<Item = &Fabric> {
        self.fabrics.iter()
    }

    /// Get a fabric by its local index
    ///
    /// Returns an error if the fabric is not found
    pub fn fabric(&self, fab_idx: NonZeroU8) -> Result<&Fabric, Error> {
        self.get(fab_idx).ok_or(ErrorCode::NotFound.into())
    }

    /// Get a mutable fabric reference by its local index
    ///
    /// Returns an error if the fabric is not found
    pub fn fabric_mut(&mut self, fab_idx: NonZeroU8) -> Result<&mut Fabric, Error> {
        self.get_mut(fab_idx).ok_or(ErrorCode::NotFound.into())
    }

    /// Check if the given access request should be allowed, based on all operational fabrics
    /// and their ACLs
    ///
    /// `aux_acl_enabled` conveys whether the node advertises the Access Control
    /// cluster's `AUXILIARY` feature - see `AclEntry::allow`.
    pub fn allow(&self, req: &AccessReq, aux_acl_enabled: bool) -> bool {
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
        if req.accessor().auth_mode() == Some(AuthMode::Pase) {
            return true;
        }

        let Ok(fab_idx) = req.accessor().fab_idx() else {
            return false;
        };

        let Some(fabric) = self.get(fab_idx) else {
            return false;
        };

        fabric.allow(req, aux_acl_enabled)
    }
}

/// A utility for persisting a fabric in a `KvBlobStore` instance.
pub struct FabricPersist<S>(Persist<S>);

impl<S> FabricPersist<S>
where
    S: KvBlobStoreAccess,
{
    /// Create a new `FabricPersist` with the given key-value store instance.
    pub const fn new(kvb: S) -> Self {
        Self(Persist::new(kvb))
    }

    /// Return a reference to the underlying `Persist` instance.
    pub(crate) fn persist_mut(&mut self) -> &mut Persist<S> {
        &mut self.0
    }

    /// Save the provided fabric in the persistent storage.
    pub fn store(&mut self, fabric: &Fabric) -> Result<(), Error> {
        self.0
            .store_tlv(FABRIC_KEYS_START + fabric.fab_idx().get() as u16, fabric)
    }

    /// Remove the fabric with the given index from the persistent storage.
    pub fn remove(&mut self, fab_idx: NonZeroU8) -> Result<(), Error> {
        self.0.remove(FABRIC_KEYS_START + fab_idx.get() as u16)
    }

    /// Call at the end when finished with everything else
    /// No-op for now
    pub fn run(self) -> Result<(), Error> {
        self.0.run()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use core::cell::RefCell;
    use core::mem::MaybeUninit;
    use core::num::NonZeroU8;

    use std::collections::BTreeMap;
    use std::rc::Rc;

    use crate::acl::{AccessReq, Accessor, AccessorSubjects, AclEntry, AuthMode, Target};
    use crate::cert::gen::{CertGenerator, CertType, IssuerDN, SubjectDN, Validity, VALID_FOREVER};
    use crate::cert::{CertRef, MAX_CERT_TLV_AND_ASN1_LEN};
    use crate::crypto::test_only_crypto;
    use crate::crypto::{
        CanonAeadKeyRef, CanonPkcPublicKey, CanonPkcPublicKeyRef, CanonPkcSecretKey,
        CanonPkcSecretKeyRef, Crypto, Hash, PublicKey, SecretKey, SigningSecretKey,
        AEAD_CANON_KEY_LEN,
    };
    use crate::dm::{Access, Privilege};
    use crate::error::{Error, ErrorCode};
    use crate::im::encoding::GenericPath;
    use crate::onboard::cac::IcacGenerator;
    use crate::persist::{KvBlobStore, KvBlobStoreAccess, FABRIC_KEYS_START};
    use crate::tlv::TLVElement;
    use crate::transport::network::MatterLocalService;
    use crate::utils::init::{Init, InitMaybeUninit, IntoFallibleInit};

    use super::{Fabric, FabricPersist, Fabrics, MAX_FABRICS, VID_VERIFICATION_STATEMENT_LEN};

    /// The raw blob map shared between an in-memory store and the test that
    /// inspects it.
    type Blobs = Rc<RefCell<BTreeMap<u16, std::vec::Vec<u8>>>>;

    /// An in-memory `KvBlobStore` that retains what it stores, so a value
    /// written by one `Fabrics` incarnation can be read back by a later one.
    #[derive(Default, Clone)]
    pub(crate) struct MemKvBlobStore {
        blobs: Blobs,
    }

    impl MemKvBlobStore {
        /// Whether a value is stored under `key`.
        pub(crate) fn contains_key(&self, key: u16) -> bool {
            self.blobs.borrow().contains_key(&key)
        }

        /// The number of stored blobs.
        pub(crate) fn len(&self) -> usize {
            self.blobs.borrow().len()
        }
    }

    impl KvBlobStore for MemKvBlobStore {
        fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
            Ok(self.blobs.borrow().get(&key).map(|v| {
                buf[..v.len()].copy_from_slice(v);
                &buf[..v.len()]
            }))
        }

        fn store(&mut self, key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
            self.blobs.borrow_mut().insert(key, data.to_vec());
            Ok(())
        }

        fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), Error> {
            self.blobs.borrow_mut().remove(&key);
            Ok(())
        }
    }

    /// A `KvBlobStoreAccess` over a [`MemKvBlobStore`] with its own scratch
    /// buffer.
    pub(crate) struct MemKv {
        store: RefCell<MemKvBlobStore>,
        buf: RefCell<std::vec::Vec<u8>>,
    }

    impl MemKv {
        pub(crate) fn new(store: MemKvBlobStore) -> Self {
            Self {
                store: RefCell::new(store),
                buf: RefCell::new(std::vec![0; 8192]),
            }
        }
    }

    impl KvBlobStoreAccess for MemKv {
        fn access<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&mut dyn KvBlobStore, &mut [u8]) -> R,
        {
            let mut store = self.store.borrow_mut();
            let mut buf = self.buf.borrow_mut();

            f(&mut *store, &mut buf)
        }
    }

    /// A freshly minted, self-signed RCAC.
    pub(crate) struct TestRcac {
        pub(crate) key: CanonPkcSecretKey,
        pub(crate) cert: std::vec::Vec<u8>,
    }

    /// A freshly minted NOC, chained (directly or via an ICAC) to some RCAC.
    pub(crate) struct TestNoc {
        pub(crate) key: CanonPkcSecretKey,
        pub(crate) cert: std::vec::Vec<u8>,
    }

    /// Write the canonical public key of a secret key into `out`.
    pub(crate) fn pubkey_of<C: Crypto>(
        crypto: &C,
        key: CanonPkcSecretKeyRef<'_>,
    ) -> CanonPkcPublicKey {
        let mut out = CanonPkcPublicKey::new();
        crypto
            .secret_key(key)
            .unwrap()
            .pub_key()
            .unwrap()
            .write_canon(&mut out)
            .unwrap();
        out
    }

    /// Mint a self-signed RCAC for `fabric_id` with subject CA ID `rcac_id`.
    pub(crate) fn mint_rcac<C: Crypto>(crypto: &C, fabric_id: u64, rcac_id: u64) -> TestRcac {
        let rcac_secret_key = crypto.generate_secret_key().unwrap();
        let mut rcac_pubkey = CanonPkcPublicKey::new();
        rcac_secret_key
            .pub_key()
            .unwrap()
            .write_canon(&mut rcac_pubkey)
            .unwrap();

        let mut buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let len = CertGenerator::new(&mut buf)
            .generate(
                crypto,
                CertType::Rcac,
                &[0x01],
                VALID_FOREVER,
                SubjectDN {
                    node_id: None,
                    fabric_id: Some(fabric_id),
                    cat_ids: &[],
                    ca_id: Some(rcac_id),
                },
                IssuerDN {
                    ca_id: None,
                    fabric_id: None,
                    is_rcac: false,
                },
                rcac_pubkey.reference(),
                None,
                &rcac_secret_key,
            )
            .unwrap();

        let mut key = CanonPkcSecretKey::new();
        rcac_secret_key.write_canon(&mut key).unwrap();

        TestRcac {
            key,
            cert: buf[..len].to_vec(),
        }
    }

    /// Mint an ICAC signed by `rcac`.
    pub(crate) fn mint_icac<C: Crypto>(crypto: &C, rcac: &TestRcac) -> TestRcac {
        let mut buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut generator = IcacGenerator::new(&mut buf);
        let (key, cert) = generator
            .generate(crypto, rcac.key.reference(), &rcac.cert, VALID_FOREVER)
            .unwrap();

        TestRcac {
            key,
            cert: cert.to_vec(),
        }
    }

    /// Mint a NOC for `node_id` carrying `noc_pubkey`, signed by `issuer`
    /// (an RCAC when `issuer_is_rcac`, an ICAC otherwise). The fabric ID and
    /// the issuer CA ID are taken from the issuer certificate.
    pub(crate) fn mint_noc_for_pubkey<C: Crypto>(
        crypto: &C,
        issuer: &TestRcac,
        issuer_is_rcac: bool,
        noc_pubkey: CanonPkcPublicKeyRef<'_>,
        node_id: u64,
    ) -> std::vec::Vec<u8> {
        let issuer_ref = CertRef::new(TLVElement::new(&issuer.cert));
        let fabric_id = issuer_ref.get_fabric_id().unwrap();
        let ca_id = issuer_ref.get_ca_id().unwrap();
        let issuer_pubkey = pubkey_of(crypto, issuer.key.reference());
        let signing_key = crypto.secret_key(issuer.key.reference()).unwrap();

        let mut buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let len = CertGenerator::new(&mut buf)
            .generate(
                crypto,
                CertType::Noc,
                &[0x02],
                VALID_FOREVER,
                SubjectDN {
                    node_id: Some(node_id),
                    fabric_id: Some(fabric_id),
                    cat_ids: &[],
                    ca_id: None,
                },
                IssuerDN {
                    ca_id: Some(ca_id),
                    fabric_id: Some(fabric_id),
                    is_rcac: issuer_is_rcac,
                },
                noc_pubkey,
                Some(issuer_pubkey.reference()),
                &signing_key,
            )
            .unwrap();

        buf[..len].to_vec()
    }

    /// Mint a NOC with a fresh keypair for `node_id`, signed by `issuer`.
    pub(crate) fn mint_noc<C: Crypto>(
        crypto: &C,
        issuer: &TestRcac,
        issuer_is_rcac: bool,
        node_id: u64,
    ) -> TestNoc {
        let noc_secret_key = crypto.generate_secret_key().unwrap();
        let mut key = CanonPkcSecretKey::new();
        noc_secret_key.write_canon(&mut key).unwrap();

        let cert = mint_noc_for_pubkey(
            crypto,
            issuer,
            issuer_is_rcac,
            pubkey_of(crypto, key.reference()).reference(),
            node_id,
        );

        TestNoc { key, cert }
    }

    /// The IPK epoch key used by every fabric these tests add.
    pub(crate) const TEST_IPK: [u8; AEAD_CANON_KEY_LEN] = [0x5a; AEAD_CANON_KEY_LEN];

    /// Add an RCAC-direct fabric for (`fabric_id`, `node_id`) with vendor ID
    /// `0x8000` and `node_id` as the CASE admin subject. Returns its index.
    pub(crate) fn add_fabric<C: Crypto>(
        crypto: &C,
        fabrics: &mut Fabrics,
        fabric_id: u64,
        node_id: u64,
    ) -> NonZeroU8 {
        let rcac = mint_rcac(crypto, fabric_id, 0x10 + fabric_id);
        let noc = mint_noc(crypto, &rcac, true, node_id);

        fabrics
            .add(
                crypto,
                noc.key.reference(),
                &rcac.cert,
                &noc.cert,
                &[],
                Some(CanonAeadKeyRef::new(&TEST_IPK)),
                0x8000,
                node_id,
            )
            .unwrap()
            .fab_idx()
    }

    fn idx(i: u8) -> NonZeroU8 {
        NonZeroU8::new(i).unwrap()
    }

    /// The Matter spec's "Compressed Fabric Identifier" example: this root
    /// public key and fabric ID compress to `87e1b004e235a130`.
    #[test]
    fn compressed_fabric_id_matches_spec_example() {
        const ROOT_PUBKEY: [u8; 65] = [
            0x04, 0x4a, 0x9f, 0x42, 0xb1, 0xca, 0x48, 0x40, 0xd3, 0x72, 0x92, 0xbb, 0xc7, 0xf6,
            0xa7, 0xe1, 0x1e, 0x22, 0x20, 0x0c, 0x97, 0x6f, 0xc9, 0x00, 0xdb, 0xc9, 0x8a, 0x7a,
            0x38, 0x3a, 0x64, 0x1c, 0xb8, 0x25, 0x4a, 0x2e, 0x56, 0xd4, 0xe2, 0x95, 0xa8, 0x47,
            0x94, 0x3b, 0x4e, 0x38, 0x97, 0xc4, 0xa7, 0x73, 0xe9, 0x30, 0x27, 0x7b, 0x4d, 0x9f,
            0xbe, 0xde, 0x8a, 0x05, 0x26, 0x86, 0xbf, 0xac, 0xfa,
        ];

        let crypto = test_only_crypto();

        let compressed = Fabric::compute_compressed_fabric_id(
            &crypto,
            CanonPkcPublicKeyRef::new(&ROOT_PUBKEY),
            0x2906_c908_d115_d362,
        );

        assert_eq!(compressed, 0x87e1_b004_e235_a130);
    }

    /// Lock the on-disk TLV tag layout of the fields whose position is sensitive
    /// to the `groups` feature. A released `rs-matter` persists `groups` at
    /// context tag 13 and `vid_verification_statement` at 14; gating `groups` in
    /// or out must not move either. Serializing an (empty) `Fabric` and checking
    /// the raw tags catches any future reorder that would silently corrupt
    /// existing persisted fabrics.
    #[test]
    fn fabric_tlv_tag_layout_is_stable() {
        use crate::tlv::{TLVElement, TLVTag, ToTLV};
        use crate::utils::init::InitMaybeUninit;
        use crate::utils::storage::WriteBuf;

        let mut fabric = core::mem::MaybeUninit::<Fabric>::uninit();
        let fabric = fabric.init_with(Fabric::init(unwrap!(NonZeroU8::new(1))));

        let mut buf = [0u8; 512];
        let mut wb = WriteBuf::new(&mut buf);
        fabric.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
        let len = wb.get_tail();

        let root = TLVElement::new(&buf[..len]).structure().unwrap();

        // `find_ctx` returns an EMPTY element (not an error) when the tag is
        // absent, so presence is `!is_empty()` and absence is `is_empty()`.

        // `acl` (the last always-present field before the sensitive pair) is at 12.
        assert!(
            !root.find_ctx(12).unwrap().is_empty(),
            "acl must stay at TLV tag 12"
        );

        // `vid_verification_statement` must always be at context tag 14.
        assert!(
            !root.find_ctx(14).unwrap().is_empty(),
            "vid_verification_statement must stay at TLV tag 14"
        );

        // With `groups` compiled in it must be at tag 13; compiled out, tag 13 is
        // simply absent (and a reader defaults it).
        #[cfg(feature = "groups")]
        assert!(
            !root.find_ctx(13).unwrap().is_empty(),
            "groups must be at TLV tag 13 when compiled in"
        );
        #[cfg(not(feature = "groups"))]
        assert!(
            root.find_ctx(13).unwrap().is_empty(),
            "no field should occupy tag 13 when groups is compiled out"
        );
    }

    /// Verify that `compute_dest_id` and `is_dest_id` agree: the hash output by
    /// `compute_dest_id` must be accepted by `is_dest_id` on the same fabric with
    /// the same random nonce.
    ///
    /// Uses runtime-generated certs (via `CertGenerator`) with a real keypair
    /// so the fabric is in a valid state — the secret key matches the NOC's public key.
    #[test]
    fn test_compute_dest_id_matches_is_dest_id() {
        let crypto = test_only_crypto();

        let fabric_id: u64 = 1;
        let rcac_id: u64 = 1;
        let node_id: u64 = 100;

        // Generate RCAC keypair and build self-signed RCAC
        let rcac_secret_key = crypto.generate_secret_key().unwrap();
        let mut rcac_pubkey_canon = crate::crypto::CanonPkcPublicKey::new();
        rcac_secret_key
            .pub_key()
            .unwrap()
            .write_canon(&mut rcac_pubkey_canon)
            .unwrap();

        let validity = Validity {
            not_before: 0,
            not_after: 0,
        };

        let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let rcac_len = CertGenerator::new(&mut rcac_buf)
            .generate(
                &crypto,
                CertType::Rcac,
                &[0x01],
                validity,
                SubjectDN {
                    node_id: None,
                    fabric_id: Some(fabric_id),
                    cat_ids: &[],
                    ca_id: Some(rcac_id),
                },
                IssuerDN {
                    ca_id: None,
                    fabric_id: None,
                    is_rcac: false,
                },
                rcac_pubkey_canon.reference(),
                None,
                &rcac_secret_key,
            )
            .unwrap();

        // Generate NOC keypair and build NOC signed by RCAC
        let noc_secret_key = crypto.generate_secret_key().unwrap();
        let mut noc_pubkey_canon = crate::crypto::CanonPkcPublicKey::new();
        noc_secret_key
            .pub_key()
            .unwrap()
            .write_canon(&mut noc_pubkey_canon)
            .unwrap();

        let mut noc_secret_key_canon = CanonPkcSecretKey::new();
        noc_secret_key
            .write_canon(&mut noc_secret_key_canon)
            .unwrap();

        let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let noc_len = CertGenerator::new(&mut noc_buf)
            .generate(
                &crypto,
                CertType::Noc,
                &[0x02],
                validity,
                SubjectDN {
                    node_id: Some(node_id),
                    fabric_id: Some(fabric_id),
                    cat_ids: &[],
                    ca_id: None,
                },
                IssuerDN {
                    ca_id: Some(rcac_id),
                    fabric_id: Some(fabric_id),
                    is_rcac: true,
                },
                noc_pubkey_canon.reference(),
                Some(rcac_pubkey_canon.reference()),
                &rcac_secret_key,
            )
            .unwrap();

        // Build fabric with real certs and matching secret key
        let epoch_key = [0x5a_u8; AEAD_CANON_KEY_LEN];
        let mut fabrics = Fabrics::new();
        fabrics
            .add(
                &crypto,
                noc_secret_key_canon.reference(),
                &rcac_buf[..rcac_len],
                &noc_buf[..noc_len],
                &[], // no ICAC
                Some(CanonAeadKeyRef::new(&epoch_key)),
                0x8000,
                node_id,
            )
            .expect("Fabrics::add should succeed");

        let fab_idx = core::num::NonZeroU8::new(1).unwrap();
        let fabric = fabrics
            .get(fab_idx)
            .expect("fabric at index 1 should exist");

        let random = [0xABu8; 32];

        // Compute the destination ID (targeting this fabric's own node).
        let mut dest_id = MaybeUninit::<Hash>::uninit();
        let dest_id = dest_id.init_with(Hash::init());
        fabric
            .compute_dest_id(&crypto, &random, fabric.node_id(), dest_id)
            .expect("compute_dest_id should not fail");

        // is_dest_id must accept the computed value.
        fabric
            .is_dest_id(&crypto, &random, dest_id.access())
            .expect("is_dest_id should accept hash produced by compute_dest_id");
    }

    #[test]
    fn add_assigns_sequential_indices_and_iter_is_insertion_ordered() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        assert_eq!(fabrics.iter().count(), 0);

        let a = add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        let b = add_fabric(&crypto, &mut fabrics, 0xb, 0x1b);
        let c = add_fabric(&crypto, &mut fabrics, 0xc, 0x1c);

        assert_eq!((a, b, c), (idx(1), idx(2), idx(3)));

        let order: std::vec::Vec<_> = fabrics.iter().map(|f| f.fab_idx().get()).collect();
        assert_eq!(order, [1, 2, 3]);
    }

    #[test]
    fn add_populates_fabric_fields() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let noc = mint_noc(&crypto, &rcac, true, 0x1234);

        let fabric = fabrics
            .add(
                &crypto,
                noc.key.reference(),
                &rcac.cert,
                &noc.cert,
                &[],
                Some(CanonAeadKeyRef::new(&TEST_IPK)),
                0xfff1,
                0x1234,
            )
            .unwrap();

        assert_eq!(fabric.fab_idx(), idx(1));
        assert_eq!(fabric.node_id(), 0x1234);
        assert_eq!(fabric.fabric_id(), 0xfab);
        assert_eq!(fabric.vendor_id(), 0xfff1);
        assert_eq!(fabric.root_ca(), rcac.cert.as_slice());
        assert_eq!(fabric.noc(), noc.cert.as_slice());
        assert!(fabric.icac().is_empty());
        assert!(fabric.vvsc().is_empty());
        assert!(fabric.vid_verification_statement().is_empty());
        assert_eq!(fabric.label(), "");
        assert_eq!(fabric.secret_key().access(), noc.key.access());

        // The compressed fabric ID is derived from the root pubkey + fabric ID
        let root_cert = CertRef::new(TLVElement::new(&rcac.cert));
        let root_pubkey = root_cert.pubkey().unwrap();
        assert_eq!(
            fabric.compressed_fabric_id(),
            Fabric::compute_compressed_fabric_id(&crypto, root_pubkey.try_into().unwrap(), 0xfab)
        );

        // The IPK epoch key is stored and an operational key derived from it
        assert_eq!(fabric.ipk().epoch_key().access(), &TEST_IPK);
        assert_ne!(fabric.ipk().op_key().access(), &[0u8; AEAD_CANON_KEY_LEN]);

        // A single CASE admin entry for the admin subject is seeded
        let mut expected = AclEntry::new(Some(idx(1)), Privilege::ADMIN, AuthMode::Case);
        expected.add_subject(0x1234).unwrap();
        assert_eq!(fabric.acl(), &[expected]);
    }

    #[test]
    fn add_with_icac_stores_icac() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let icac = mint_icac(&crypto, &rcac);
        let noc = mint_noc(&crypto, &icac, false, 0x1234);

        let fabric = fabrics
            .add(
                &crypto,
                noc.key.reference(),
                &rcac.cert,
                &noc.cert,
                &icac.cert,
                Some(CanonAeadKeyRef::new(&TEST_IPK)),
                0xfff1,
                0x1234,
            )
            .unwrap();

        assert_eq!(fabric.icac(), icac.cert.as_slice());
        assert!(fabric.vvsc().is_empty());
        assert_eq!(fabric.fabric_id(), 0xfab);
    }

    #[test]
    fn add_with_post_init_error_leaves_no_fabric() {
        let mut fabrics = Fabrics::new();

        let err = fabrics
            .add_with_post_init(|_| Err(ErrorCode::Invalid.into()))
            .unwrap_err();

        assert_eq!(err.code(), ErrorCode::Invalid);
        assert_eq!(fabrics.iter().count(), 0);
    }

    #[test]
    fn add_fails_with_resource_exhausted_when_full() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        for i in 0..MAX_FABRICS as u64 {
            add_fabric(&crypto, &mut fabrics, 0x100 + i, 0x200 + i);
        }
        assert_eq!(fabrics.iter().count(), MAX_FABRICS);

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let noc = mint_noc(&crypto, &rcac, true, 0x1234);
        let err = fabrics
            .add(
                &crypto,
                noc.key.reference(),
                &rcac.cert,
                &noc.cert,
                &[],
                Some(CanonAeadKeyRef::new(&TEST_IPK)),
                0xfff1,
                0x1234,
            )
            .unwrap_err();

        assert_eq!(err.code(), ErrorCode::ResourceExhausted);
        assert_eq!(fabrics.iter().count(), MAX_FABRICS);
    }

    #[test]
    fn remove_drops_fabric_and_next_add_uses_max_index_plus_one() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        add_fabric(&crypto, &mut fabrics, 0xb, 0x1b);
        add_fabric(&crypto, &mut fabrics, 0xc, 0x1c);

        fabrics.remove(idx(2)).unwrap();

        assert!(fabrics.get(idx(2)).is_none());
        assert_eq!(
            fabrics.fabric(idx(2)).unwrap_err().code(),
            ErrorCode::NotFound
        );
        assert_eq!(
            fabrics.remove(idx(2)).unwrap_err().code(),
            ErrorCode::NotFound
        );

        let order: std::vec::Vec<_> = fabrics.iter().map(|f| f.fab_idx().get()).collect();
        assert_eq!(order, [1, 3]);

        // Freed indices are not reused while a larger one is in use
        assert_eq!(add_fabric(&crypto, &mut fabrics, 0xd, 0x1d), idx(4));
    }

    #[test]
    fn get_and_fabric_accessors_agree() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        add_fabric(&crypto, &mut fabrics, 0xb, 0x1b);

        assert_eq!(fabrics.get(idx(2)).unwrap().fabric_id(), 0xb);
        assert_eq!(fabrics.get_mut(idx(2)).unwrap().fabric_id(), 0xb);
        assert_eq!(fabrics.fabric(idx(1)).unwrap().fabric_id(), 0xa);
        assert_eq!(fabrics.fabric_mut(idx(1)).unwrap().fabric_id(), 0xa);

        assert!(fabrics.get(idx(3)).is_none());
        assert!(fabrics.get_mut(idx(3)).is_none());
        assert_eq!(
            fabrics.fabric(idx(3)).unwrap_err().code(),
            ErrorCode::NotFound
        );
        assert_eq!(
            fabrics.fabric_mut(idx(3)).unwrap_err().code(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn update_replaces_noc_and_key_but_keeps_root_acl_and_label() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let icac = mint_icac(&crypto, &rcac);
        let noc = mint_noc(&crypto, &icac, false, 0x1234);

        let fab_idx = fabrics
            .add(
                &crypto,
                noc.key.reference(),
                &rcac.cert,
                &noc.cert,
                &icac.cert,
                Some(CanonAeadKeyRef::new(&TEST_IPK)),
                0xfff1,
                0x1234,
            )
            .unwrap()
            .fab_idx();
        fabrics.update_label(fab_idx, "home").unwrap();

        let fabric = fabrics.get_mut(fab_idx).unwrap();
        fabric
            .set_vid_verification(None, None, Some(&[0xaa; 40]))
            .unwrap();
        assert!(!fabric.vvsc().is_empty());
        let old_compressed = fabric.compressed_fabric_id();
        let old_acl = fabric.acl().to_vec();

        // A new NOC for a different node ID, signed directly by the RCAC
        let new_noc = mint_noc(&crypto, &rcac, true, 0x5678);
        let fabric = fabrics
            .update(
                &crypto,
                fab_idx,
                new_noc.key.reference(),
                &new_noc.cert,
                &[],
            )
            .unwrap();

        assert_eq!(fabric.node_id(), 0x5678);
        assert_eq!(fabric.fabric_id(), 0xfab);
        assert_eq!(fabric.noc(), new_noc.cert.as_slice());
        assert_eq!(fabric.secret_key().access(), new_noc.key.access());
        assert_eq!(fabric.root_ca(), rcac.cert.as_slice());
        assert_eq!(fabric.compressed_fabric_id(), old_compressed);
        assert_eq!(fabric.vendor_id(), 0xfff1);
        assert_eq!(fabric.label(), "home");
        assert_eq!(fabric.acl(), old_acl.as_slice());
        assert_eq!(fabric.ipk().epoch_key().access(), &TEST_IPK);

        // The cert chain is replaced wholesale: ICAC gone, staged VVSC gone
        assert!(fabric.icac().is_empty());
        assert!(fabric.vvsc().is_empty());

        assert_eq!(
            fabrics
                .update(&crypto, idx(9), new_noc.key.reference(), &new_noc.cert, &[])
                .unwrap_err()
                .code(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn update_label_rejects_duplicates_and_overlong_labels() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        add_fabric(&crypto, &mut fabrics, 0xb, 0x1b);

        assert_eq!(
            fabrics.update_label(idx(1), "home").unwrap().label(),
            "home"
        );

        // Re-labelling the same fabric with its own label is fine
        assert_eq!(
            fabrics.update_label(idx(1), "home").unwrap().label(),
            "home"
        );

        // Another fabric may not take a label already in use
        assert_eq!(
            fabrics.update_label(idx(2), "home").unwrap_err().code(),
            ErrorCode::Invalid
        );
        assert_eq!(fabrics.get(idx(2)).unwrap().label(), "");

        // Empty labels never conflict
        assert_eq!(fabrics.update_label(idx(2), "").unwrap().label(), "");
        assert_eq!(fabrics.update_label(idx(1), "").unwrap().label(), "");

        // At most 32 bytes
        assert_eq!(
            fabrics
                .update_label(idx(2), &"x".repeat(32))
                .unwrap()
                .label()
                .len(),
            32
        );
        assert_eq!(
            fabrics
                .update_label(idx(2), &"y".repeat(33))
                .unwrap_err()
                .code(),
            ErrorCode::ConstraintError
        );

        assert_eq!(
            fabrics.update_label(idx(7), "x").unwrap_err().code(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn get_by_dest_id_finds_only_the_matching_fabric() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        add_fabric(&crypto, &mut fabrics, 0xb, 0x1b);

        let random = [0x42u8; 32];
        let mut dest_id = Hash::new();
        fabrics
            .get(idx(2))
            .unwrap()
            .compute_dest_id(&crypto, &random, 0x1b, &mut dest_id)
            .unwrap();

        let found = fabrics
            .get_by_dest_id(&crypto, &random, dest_id.access())
            .unwrap();
        assert_eq!(found.fab_idx(), idx(2));

        // A different initiator random yields a different destination ID
        let other_random = [0x43u8; 32];
        assert!(fabrics
            .get_by_dest_id(&crypto, &other_random, dest_id.access())
            .is_none());

        // ...and so does a destination ID computed for some other node
        let mut other_dest_id = Hash::new();
        fabrics
            .get(idx(2))
            .unwrap()
            .compute_dest_id(&crypto, &random, 0x1c, &mut other_dest_id)
            .unwrap();
        assert!(fabrics
            .get_by_dest_id(&crypto, &random, other_dest_id.access())
            .is_none());
    }

    #[test]
    fn acl_add_update_remove() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        let fab_idx = add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        let fabric = fabrics.get_mut(fab_idx).unwrap();
        assert_eq!(fabric.acl().len(), 1);

        // The entry's fabric index is overwritten with the fabric's own
        let mut entry = AclEntry::new(Some(idx(9)), Privilege::VIEW, AuthMode::Case);
        entry.add_subject(0x99).unwrap();
        assert_eq!(fabric.acl_add(entry.clone()).unwrap(), 1);
        entry.fab_idx = Some(fab_idx);
        assert_eq!(fabric.acl()[1], entry);
        assert_eq!(fabric.acl_iter().count(), 2);

        // PASE entries are reserved
        assert_eq!(
            fabric
                .acl_add(AclEntry::new(None, Privilege::VIEW, AuthMode::Pase))
                .unwrap_err()
                .code(),
            ErrorCode::ConstraintError
        );
        assert_eq!(fabric.acl().len(), 2);

        // Update in place, again forcing the fabric index
        let mut updated = AclEntry::new(None, Privilege::OPERATE, AuthMode::Case);
        updated
            .add_target(Target::new(Some(1), None, None))
            .unwrap();
        fabric.acl_update(1, updated.clone()).unwrap();
        updated.fab_idx = Some(fab_idx);
        assert_eq!(fabric.acl()[1], updated);

        assert_eq!(
            fabric.acl_update(2, entry.clone()).unwrap_err().code(),
            ErrorCode::NotFound
        );

        // Remove shifts the remaining entries down
        fabric.acl_remove(0).unwrap();
        assert_eq!(fabric.acl(), &[updated]);
        assert_eq!(
            fabric.acl_remove(1).unwrap_err().code(),
            ErrorCode::NotFound
        );

        fabric.acl_remove_all();
        assert!(fabric.acl().is_empty());
    }

    #[test]
    fn acl_add_init_rejects_pase_entries() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        let fab_idx = add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        let fabric = fabrics.get_mut(fab_idx).unwrap();
        let count = fabric.acl().len();

        assert_eq!(
            fabric
                .acl_add_init(
                    AclEntry::init(None, Privilege::VIEW, AuthMode::Pase).into_fallible::<Error>()
                )
                .unwrap_err()
                .code(),
            ErrorCode::ConstraintError
        );
        assert_eq!(fabric.acl().len(), count);
    }

    #[test]
    fn acl_add_init_and_update_init() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        let fab_idx = add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        let fabric = fabrics.get_mut(fab_idx).unwrap();

        let i = fabric
            .acl_add_init(
                AclEntry::init(None, Privilege::MANAGE, AuthMode::Case)
                    .into_fallible::<Error>()
                    .chain(|e| e.add_subject(0x55)),
            )
            .unwrap();
        assert_eq!(i, 1);
        let mut expected = AclEntry::new(Some(fab_idx), Privilege::MANAGE, AuthMode::Case);
        expected.add_subject(0x55).unwrap();
        assert_eq!(fabric.acl()[1], expected);

        // The entry's fabric index is overwritten with the fabric's own
        fabric
            .acl_update_init(
                1,
                AclEntry::init(Some(idx(9)), Privilege::VIEW, AuthMode::Case)
                    .into_fallible::<Error>()
                    .chain(|e| e.add_subject(0x66)),
            )
            .unwrap();
        let mut expected = AclEntry::new(Some(fab_idx), Privilege::VIEW, AuthMode::Case);
        expected.add_subject(0x66).unwrap();
        assert_eq!(fabric.acl()[1], expected);

        assert_eq!(
            fabric
                .acl_update_init(
                    5,
                    AclEntry::init(None, Privilege::VIEW, AuthMode::Case).into_fallible::<Error>()
                )
                .unwrap_err()
                .code(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn acl_add_fails_with_resource_exhausted_when_full() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        let fab_idx = add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        let fabric = fabrics.get_mut(fab_idx).unwrap();

        // One admin entry is seeded on add
        for _ in 1..crate::acl::MAX_ACL_ENTRIES_PER_FABRIC {
            fabric
                .acl_add(AclEntry::new(None, Privilege::VIEW, AuthMode::Case))
                .unwrap();
        }
        assert_eq!(fabric.acl().len(), crate::acl::MAX_ACL_ENTRIES_PER_FABRIC);

        assert_eq!(
            fabric
                .acl_add(AclEntry::new(None, Privilege::VIEW, AuthMode::Case))
                .unwrap_err()
                .code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            fabric
                .acl_add_init(
                    AclEntry::init(None, Privilege::VIEW, AuthMode::Case).into_fallible::<Error>()
                )
                .unwrap_err()
                .code(),
            ErrorCode::ResourceExhausted
        );
    }

    /// Whether `fabrics` grants a `READ` of endpoint `endpoint` (with `RV`
    /// target permissions) to the given accessor.
    fn allowed(
        fabrics: &Fabrics,
        fab_idx: u8,
        subject: u64,
        auth_mode: Option<AuthMode>,
        endpoint: u16,
        aux_acl_enabled: bool,
    ) -> bool {
        let matter = crate::test::test_matter();
        let accessor = Accessor::new(
            fab_idx,
            aux_acl_enabled,
            AccessorSubjects::new(subject),
            auth_mode,
            &matter,
        );
        let mut req = AccessReq::new(
            &accessor,
            GenericPath::new(Some(endpoint), Some(0x1d), None),
            Access::READ,
            &[],
        );
        req.set_target_perms(Access::RV);

        fabrics.allow(&req, aux_acl_enabled)
    }

    #[test]
    fn allow_matches_subject_fabric_and_auth_mode() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        add_fabric(&crypto, &mut fabrics, 0xb, 0x1b);

        // The seeded admin entry grants the admin subject over CASE
        assert!(allowed(&fabrics, 1, 0x1a, Some(AuthMode::Case), 1, false));

        // ...but not other subjects, other fabrics, or other auth modes
        assert!(!allowed(&fabrics, 1, 0x1b, Some(AuthMode::Case), 1, false));
        assert!(!allowed(&fabrics, 2, 0x1a, Some(AuthMode::Case), 1, false));
        assert!(!allowed(&fabrics, 1, 0x1a, Some(AuthMode::Group), 1, false));

        // PASE accessors get the implicit administer grant
        assert!(allowed(&fabrics, 0, 1, Some(AuthMode::Pase), 1, false));

        // Plain-text accessors (no fabric) and unknown fabrics are denied
        assert!(!allowed(&fabrics, 0, 0x1a, None, 1, false));
        assert!(!allowed(&fabrics, 7, 0x1a, Some(AuthMode::Case), 1, false));

        // A wildcard-subject entry admits anyone on that fabric
        fabrics
            .get_mut(idx(2))
            .unwrap()
            .acl_add(AclEntry::new(None, Privilege::VIEW, AuthMode::Case))
            .unwrap();
        assert!(allowed(&fabrics, 2, 0x1a, Some(AuthMode::Case), 1, false));
        assert!(!allowed(&fabrics, 1, 0x999, Some(AuthMode::Case), 1, false));
    }

    #[test]
    fn allow_aux_acl_excludes_root_endpoint_for_wildcard_group_entries() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);

        let mut entry = AclEntry::new(None, Privilege::OPERATE, AuthMode::Group);
        entry.add_subject(0x1234).unwrap();
        fabrics.get_mut(idx(1)).unwrap().acl_add(entry).unwrap();

        // Without the AUXILIARY feature a wildcard-target group entry covers the whole node
        assert!(allowed(
            &fabrics,
            1,
            0x1234,
            Some(AuthMode::Group),
            0,
            false
        ));
        assert!(allowed(
            &fabrics,
            1,
            0x1234,
            Some(AuthMode::Group),
            1,
            false
        ));

        // With it, the root endpoint is excluded
        assert!(!allowed(
            &fabrics,
            1,
            0x1234,
            Some(AuthMode::Group),
            0,
            true
        ));
        assert!(allowed(&fabrics, 1, 0x1234, Some(AuthMode::Group), 1, true));

        // CASE entries are unaffected either way
        assert!(allowed(&fabrics, 1, 0x1a, Some(AuthMode::Case), 0, true));
    }

    #[test]
    fn mdns_service_reflects_commissioned_state() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        // A fabric with no NOC has no operational service to advertise
        let bare = fabrics.add_with_post_init(|_| Ok(())).unwrap();
        assert!(bare.mdns_service().is_none());
        assert!(bare.mdns_service_for(0x55).is_none());

        let fab_idx = add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        let fabric = fabrics.get(fab_idx).unwrap();

        assert_eq!(
            fabric.mdns_service(),
            Some(MatterLocalService::Commissioned {
                compressed_fabric_id: fabric.compressed_fabric_id(),
                node_id: 0x1a,
            })
        );
        assert_eq!(
            fabric.mdns_service_for(0x55),
            Some(MatterLocalService::Commissioned {
                compressed_fabric_id: fabric.compressed_fabric_id(),
                node_id: 0x55,
            })
        );
    }

    #[test]
    fn set_vid_verification_updates_only_the_given_fields() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        let fab_idx = add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        let fabric = fabrics.get_mut(fab_idx).unwrap();

        // Vendor ID alone
        fabric
            .set_vid_verification(Some(0x1234), None, None)
            .unwrap();
        assert_eq!(fabric.vendor_id(), 0x1234);
        assert!(fabric.vid_verification_statement().is_empty());
        assert!(fabric.vvsc().is_empty());

        // Statement of the exact allowed length; longer is rejected
        let stmt = [0xab; VID_VERIFICATION_STATEMENT_LEN];
        fabric
            .set_vid_verification(None, Some(&stmt), None)
            .unwrap();
        assert_eq!(fabric.vid_verification_statement(), &stmt);
        assert_eq!(fabric.vendor_id(), 0x1234);

        let too_long = [0xab; VID_VERIFICATION_STATEMENT_LEN + 1];
        assert_eq!(
            fabric
                .set_vid_verification(None, Some(&too_long), None)
                .unwrap_err()
                .code(),
            ErrorCode::BufferTooSmall
        );

        // Empty statement clears it
        fabric.set_vid_verification(None, Some(&[]), None).unwrap();
        assert!(fabric.vid_verification_statement().is_empty());

        // A VVSC occupies the (otherwise empty) ICAC slot
        fabric
            .set_vid_verification(None, None, Some(&[0xcd; 30]))
            .unwrap();
        assert_eq!(fabric.vvsc(), &[0xcd; 30]);
        assert!(fabric.icac().is_empty());

        // An empty VVSC clears it
        fabric.set_vid_verification(None, None, Some(&[])).unwrap();
        assert!(fabric.vvsc().is_empty());
        assert!(fabric.icac().is_empty());
    }

    #[test]
    fn set_vid_verification_empty_vvsc_does_not_clear_icac() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let icac = mint_icac(&crypto, &rcac);
        let noc = mint_noc(&crypto, &icac, false, 0x1234);

        let fabric = fabrics
            .add(
                &crypto,
                noc.key.reference(),
                &rcac.cert,
                &noc.cert,
                &icac.cert,
                Some(CanonAeadKeyRef::new(&TEST_IPK)),
                0xfff1,
                0x1234,
            )
            .unwrap();

        fabric.set_vid_verification(None, None, Some(&[])).unwrap();
        assert_eq!(fabric.icac(), icac.cert.as_slice());
        assert!(fabric.vvsc().is_empty());
    }

    /// Persist every fabric of `fabrics` into `kv`.
    fn store_all(fabrics: &Fabrics, kv: &MemKv) {
        let mut persist = FabricPersist::new(kv);
        for fabric in fabrics.iter() {
            persist.store(fabric).unwrap();
        }
        persist.run().unwrap();
    }

    /// Load a fresh `Fabrics` from `kv`.
    fn load_all(kv: &MemKv) -> Fabrics {
        let mut fabrics = Fabrics::new();
        kv.access(|kv, buf| fabrics.load_persist(kv, buf)).unwrap();
        fabrics
    }

    /// Assert that `a` and `b` carry the same persisted state.
    fn assert_same_fabric(a: &Fabric, b: &Fabric) {
        assert_eq!(a.fab_idx(), b.fab_idx());
        assert_eq!(a.node_id(), b.node_id());
        assert_eq!(a.fabric_id(), b.fabric_id());
        assert_eq!(a.vendor_id(), b.vendor_id());
        assert_eq!(a.compressed_fabric_id(), b.compressed_fabric_id());
        assert_eq!(a.secret_key().access(), b.secret_key().access());
        assert_eq!(a.root_ca(), b.root_ca());
        assert_eq!(a.icac(), b.icac());
        assert_eq!(a.vvsc(), b.vvsc());
        assert_eq!(a.noc(), b.noc());
        assert_eq!(a.ipk().epoch_key().access(), b.ipk().epoch_key().access());
        assert_eq!(a.ipk().op_key().access(), b.ipk().op_key().access());
        assert_eq!(a.label(), b.label());
        assert_eq!(a.acl(), b.acl());
        assert_eq!(
            a.vid_verification_statement(),
            b.vid_verification_statement()
        );

        #[cfg(feature = "groups")]
        {
            let ga = a.groups();
            let gb = b.groups();

            let ks_a: std::vec::Vec<_> = ga
                .key_set_iter()
                .map(|k| {
                    (
                        k.group_key_set_id,
                        k.group_key_security_policy,
                        k.epoch_keys.len(),
                    )
                })
                .collect();
            let ks_b: std::vec::Vec<_> = gb
                .key_set_iter()
                .map(|k| {
                    (
                        k.group_key_set_id,
                        k.group_key_security_policy,
                        k.epoch_keys.len(),
                    )
                })
                .collect();
            assert_eq!(ks_a, ks_b);
            for (ka, kb) in ga.key_set_iter().zip(gb.key_set_iter()) {
                for (ea, eb) in ka.epoch_keys.iter().zip(kb.epoch_keys.iter()) {
                    assert_eq!(ea.epoch_start_time, eb.epoch_start_time);
                    assert_eq!(ea.epoch_key.access(), eb.epoch_key.access());
                }
            }

            let km_a: std::vec::Vec<_> = ga
                .key_map_iter()
                .map(|m| (m.group_id, m.group_key_set_id))
                .collect();
            let km_b: std::vec::Vec<_> = gb
                .key_map_iter()
                .map(|m| (m.group_id, m.group_key_set_id))
                .collect();
            assert_eq!(km_a, km_b);

            let ep_a: std::vec::Vec<_> = ga
                .iter()
                .map(|e| {
                    (
                        e.group_id,
                        e.endpoints.to_vec(),
                        e.group_name.clone(),
                        e.has_aux_acl(),
                        e.groupcast_managed(),
                    )
                })
                .collect();
            let ep_b: std::vec::Vec<_> = gb
                .iter()
                .map(|e| {
                    (
                        e.group_id,
                        e.endpoints.to_vec(),
                        e.group_name.clone(),
                        e.has_aux_acl(),
                        e.groupcast_managed(),
                    )
                })
                .collect();
            assert_eq!(ep_a, ep_b);
        }
    }

    #[test]
    fn store_then_load_yields_equal_fabrics() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let icac = mint_icac(&crypto, &rcac);
        let noc = mint_noc(&crypto, &icac, false, 0x1234);
        fabrics
            .add(
                &crypto,
                noc.key.reference(),
                &rcac.cert,
                &noc.cert,
                &icac.cert,
                Some(CanonAeadKeyRef::new(&TEST_IPK)),
                0xfff1,
                0x1234,
            )
            .unwrap();
        add_fabric(&crypto, &mut fabrics, 0xb, 0x1b);

        fabrics.update_label(idx(1), "first").unwrap();
        {
            let fabric = fabrics.get_mut(idx(1)).unwrap();
            let mut entry = AclEntry::new(None, Privilege::VIEW, AuthMode::Case);
            entry.add_subject(0x99).unwrap();
            entry
                .add_target(Target::new(Some(1), Some(6), None))
                .unwrap();
            fabric.acl_add(entry).unwrap();
            fabric
                .set_vid_verification(
                    Some(0x4321),
                    Some(&[0x11; VID_VERIFICATION_STATEMENT_LEN]),
                    None,
                )
                .unwrap();
        }
        {
            let fabric = fabrics.get_mut(idx(2)).unwrap();
            fabric
                .set_vid_verification(None, None, Some(&[0xcd; 30]))
                .unwrap();

            #[cfg(feature = "groups")]
            {
                use crate::group_keys::{GroupEpochKeyEntry, GroupKeySet};

                let groups = fabric.groups_mut();
                let mut key_set = GroupKeySet {
                    group_key_set_id: 0x11,
                    group_key_security_policy: 1,
                    epoch_keys: crate::utils::storage::Vec::new(),
                };
                key_set
                    .epoch_keys
                    .push(GroupEpochKeyEntry {
                        epoch_key: crate::crypto::CanonAeadKey::new_from_ref(CanonAeadKeyRef::new(
                            &[0x77; AEAD_CANON_KEY_LEN],
                        )),
                        epoch_start_time: 1234,
                    })
                    .unwrap();
                groups.key_set_add(key_set).unwrap();
                groups.key_map_set_group(0x100, 0x11).unwrap();
                groups.add(1, 0x100, "kitchen").unwrap();
                groups.groupcast_join(0x101, &[2, 3], false, None).unwrap();
                groups.set_has_aux_acl(0x101, true);
            }
        }

        let store = MemKvBlobStore::default();
        let kv = MemKv::new(store.clone());
        store_all(&fabrics, &kv);

        assert!(store.contains_key(FABRIC_KEYS_START + 1));
        assert!(store.contains_key(FABRIC_KEYS_START + 2));
        assert_eq!(store.len(), 2);

        let loaded = load_all(&kv);
        assert_eq!(loaded.iter().count(), 2);

        for fabric in fabrics.iter() {
            assert_same_fabric(fabric, loaded.get(fabric.fab_idx()).unwrap());
        }

        // Loaded fabrics remain fully functional (e.g. for destination ID lookups)
        let random = [0x42u8; 32];
        let mut dest_id = Hash::new();
        fabrics
            .get(idx(1))
            .unwrap()
            .compute_dest_id(&crypto, &random, 0x1234, &mut dest_id)
            .unwrap();
        assert_eq!(
            loaded
                .get_by_dest_id(&crypto, &random, dest_id.access())
                .unwrap()
                .fab_idx(),
            idx(1)
        );
    }

    #[test]
    fn persist_remove_deletes_the_blob() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        add_fabric(&crypto, &mut fabrics, 0xb, 0x1b);

        let store = MemKvBlobStore::default();
        let kv = MemKv::new(store.clone());
        store_all(&fabrics, &kv);
        assert_eq!(store.len(), 2);

        let mut persist = FabricPersist::new(&kv);
        persist.remove(idx(1)).unwrap();
        persist.run().unwrap();

        assert!(!store.contains_key(FABRIC_KEYS_START + 1));
        assert!(store.contains_key(FABRIC_KEYS_START + 2));

        let loaded = load_all(&kv);
        let order: std::vec::Vec<_> = loaded.iter().map(|f| f.fab_idx().get()).collect();
        assert_eq!(order, [2]);

        // Removing a blob that is not there is not an error
        FabricPersist::new(&kv).remove(idx(1)).unwrap();
    }

    #[test]
    fn reset_persist_clears_memory_and_storage() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        add_fabric(&crypto, &mut fabrics, 0xa, 0x1a);
        add_fabric(&crypto, &mut fabrics, 0xb, 0x1b);

        let store = MemKvBlobStore::default();
        let kv = MemKv::new(store.clone());
        store_all(&fabrics, &kv);
        assert_eq!(store.len(), 2);

        kv.access(|kv, buf| fabrics.reset_persist(kv, buf)).unwrap();

        assert_eq!(fabrics.iter().count(), 0);
        assert_eq!(store.len(), 0);
        assert_eq!(load_all(&kv).iter().count(), 0);
    }

    #[test]
    fn fabric_removal_drops_its_acl_and_groups() {
        let crypto = test_only_crypto();
        let mut fabrics = Fabrics::new();

        let rcac = mint_rcac(&crypto, 0xfab, 0x77);
        let noc = mint_noc(&crypto, &rcac, true, 0x1234);

        let add = |fabrics: &mut Fabrics| -> NonZeroU8 {
            fabrics
                .add(
                    &crypto,
                    noc.key.reference(),
                    &rcac.cert,
                    &noc.cert,
                    &[],
                    Some(CanonAeadKeyRef::new(&TEST_IPK)),
                    0xfff1,
                    0x1234,
                )
                .unwrap()
                .fab_idx()
        };

        let fab_idx = add(&mut fabrics);
        {
            let fabric = fabrics.get_mut(fab_idx).unwrap();
            fabric
                .acl_add(AclEntry::new(None, Privilege::VIEW, AuthMode::Case))
                .unwrap();
            assert_eq!(fabric.acl().len(), 2);

            #[cfg(feature = "groups")]
            {
                fabric.groups_mut().add(1, 0x100, "g").unwrap();
                assert_eq!(fabric.groups().group_count(), 1);
            }
        }

        fabrics.remove(fab_idx).unwrap();
        assert_eq!(fabrics.iter().count(), 0);

        // A fabric re-added with the same identity starts from a clean slate
        let fab_idx = add(&mut fabrics);
        let fabric = fabrics.get(fab_idx).unwrap();
        assert_eq!(fabric.acl().len(), 1);
        assert_eq!(fabric.label(), "");

        #[cfg(feature = "groups")]
        {
            assert_eq!(fabric.groups().group_count(), 0);
            assert_eq!(fabric.groups().key_set_iter().count(), 0);
            assert_eq!(fabric.groups().key_map_iter().count(), 0);
        }
    }

    #[cfg(feature = "groups")]
    mod groups {
        use crate::crypto::{CanonAeadKey, CanonAeadKeyRef, AEAD_CANON_KEY_LEN};
        use crate::dm::clusters::decl::groupcast::MulticastAddrPolicyEnum;
        use crate::error::ErrorCode;
        use crate::fabric::{
            GroupKeyMapping, Groups, GROUP_ENDPOINTS_PER_FABRIC, MAX_GROUPS_PER_FABRIC,
            MAX_GROUP_KEYS_PER_FABRIC, MAX_GROUP_NAME_LEN,
        };
        use crate::group_keys::{GroupEpochKeyEntry, GroupKeySet};

        fn key_set(id: u16, policy: u8) -> GroupKeySet {
            let mut key_set = GroupKeySet {
                group_key_set_id: id,
                group_key_security_policy: policy,
                epoch_keys: crate::utils::storage::Vec::new(),
            };
            key_set
                .epoch_keys
                .push(GroupEpochKeyEntry {
                    epoch_key: CanonAeadKey::new_from_ref(CanonAeadKeyRef::new(
                        &[id as u8; AEAD_CANON_KEY_LEN],
                    )),
                    epoch_start_time: id as u64,
                })
                .unwrap();
            key_set
        }

        #[test]
        fn key_set_add_get_remove_iter_and_capacity() {
            let mut groups = Groups::new();

            assert!(groups.key_set_get(1).is_none());
            assert_eq!(groups.key_set_iter().count(), 0);

            groups.key_set_add(key_set(1, 0)).unwrap();
            groups.key_set_add(key_set(2, 0)).unwrap();
            assert_eq!(groups.key_set_get(1).unwrap().group_key_security_policy, 0);
            assert_eq!(
                groups.key_set_get(2).unwrap().epoch_keys[0].epoch_start_time,
                2
            );

            // Re-adding an existing ID replaces it in place
            groups.key_set_add(key_set(1, 1)).unwrap();
            assert_eq!(groups.key_set_get(1).unwrap().group_key_security_policy, 1);
            let ids: std::vec::Vec<_> = groups.key_set_iter().map(|k| k.group_key_set_id).collect();
            assert_eq!(ids, [1, 2]);

            for id in 3..=MAX_GROUP_KEYS_PER_FABRIC as u16 {
                groups.key_set_add(key_set(id, 0)).unwrap();
            }
            assert_eq!(groups.key_set_iter().count(), MAX_GROUP_KEYS_PER_FABRIC);
            assert_eq!(
                groups
                    .key_set_add(key_set(MAX_GROUP_KEYS_PER_FABRIC as u16 + 1, 0))
                    .unwrap_err()
                    .code(),
                ErrorCode::ResourceExhausted
            );

            groups.key_set_remove(1).unwrap();
            assert!(groups.key_set_get(1).is_none());
            assert_eq!(groups.key_set_iter().count(), MAX_GROUP_KEYS_PER_FABRIC - 1);
            assert_eq!(
                groups.key_set_remove(1).unwrap_err().code(),
                ErrorCode::NotFound
            );
        }

        #[test]
        fn key_set_remove_drops_key_map_entries_referencing_it() {
            let mut groups = Groups::new();

            groups.key_set_add(key_set(1, 0)).unwrap();
            groups.key_set_add(key_set(2, 0)).unwrap();
            groups.key_map_set_group(0x100, 1).unwrap();
            groups.key_map_set_group(0x101, 2).unwrap();
            groups.key_map_set_group(0x102, 1).unwrap();

            groups.key_set_remove(1).unwrap();

            let map: std::vec::Vec<_> = groups
                .key_map_iter()
                .map(|m| (m.group_id, m.group_key_set_id))
                .collect();
            assert_eq!(map, [(0x101, 2)]);
            assert_eq!(groups.key_map_get(0x100), None);
            assert_eq!(groups.key_map_get(0x101), Some(2));
        }

        #[test]
        fn key_map_add_replace_get_set_and_remove() {
            let mut groups = Groups::new();

            groups
                .key_map_add(GroupKeyMapping {
                    group_id: 0x100,
                    group_key_set_id: 1,
                })
                .unwrap();
            assert_eq!(groups.key_map_get(0x100), Some(1));
            assert_eq!(groups.key_map_get(0x101), None);

            // `key_map_add` does not dedupe; `key_map_get` returns the first match
            groups
                .key_map_add(GroupKeyMapping {
                    group_id: 0x100,
                    group_key_set_id: 2,
                })
                .unwrap();
            assert_eq!(groups.key_map_iter().count(), 2);
            assert_eq!(groups.key_map_get(0x100), Some(1));

            // `key_map_set_group` replaces the (first) mapping of the group
            groups.key_map_set_group(0x100, 3).unwrap();
            assert_eq!(groups.key_map_get(0x100), Some(3));
            groups.key_map_set_group(0x101, 1).unwrap();
            assert_eq!(groups.key_map_get(0x101), Some(1));
            assert_eq!(groups.key_map_iter().count(), 3);

            // `key_map_remove_group` drops every mapping of the group
            groups.key_map_remove_group(0x100);
            let map: std::vec::Vec<_> = groups
                .key_map_iter()
                .map(|m| (m.group_id, m.group_key_set_id))
                .collect();
            assert_eq!(map, [(0x101, 1)]);

            // `key_map_replace` swaps the whole table
            groups
                .key_map_replace([(0x200, 5), (0x201, 6)].into_iter().map(
                    |(group_id, group_key_set_id)| GroupKeyMapping {
                        group_id,
                        group_key_set_id,
                    },
                ))
                .unwrap();
            let map: std::vec::Vec<_> = groups
                .key_map_iter()
                .map(|m| (m.group_id, m.group_key_set_id))
                .collect();
            assert_eq!(map, [(0x200, 5), (0x201, 6)]);

            groups.key_map_remove_by_key_set(5);
            assert_eq!(groups.key_map_get(0x200), None);
            assert_eq!(groups.key_map_get(0x201), Some(6));
        }

        #[test]
        fn key_map_capacity() {
            let mut groups = Groups::new();

            for i in 0..MAX_GROUPS_PER_FABRIC as u16 {
                groups.key_map_set_group(0x100 + i, 1).unwrap();
            }
            assert_eq!(groups.key_map_iter().count(), MAX_GROUPS_PER_FABRIC);

            assert_eq!(
                groups.key_map_set_group(0x1ff, 1).unwrap_err().code(),
                ErrorCode::ResourceExhausted
            );
            assert_eq!(
                groups
                    .key_map_add(GroupKeyMapping {
                        group_id: 0x1ff,
                        group_key_set_id: 1,
                    })
                    .unwrap_err()
                    .code(),
                ErrorCode::ResourceExhausted
            );

            // Replacing an existing group's mapping still works when full
            groups.key_map_set_group(0x100, 2).unwrap();
            assert_eq!(groups.key_map_get(0x100), Some(2));

            assert_eq!(
                groups
                    .key_map_replace((0..=MAX_GROUPS_PER_FABRIC as u16).map(|i| GroupKeyMapping {
                        group_id: i,
                        group_key_set_id: 1,
                    }))
                    .unwrap_err()
                    .code(),
                ErrorCode::ResourceExhausted
            );
        }

        #[test]
        fn endpoint_mapping_add_get_and_remove() {
            let mut groups = Groups::new();

            assert!(groups.get(0x100).is_none());
            assert_eq!(groups.group_count(), 0);

            // First membership creates the group; a repeat reports it as existing
            assert!(!groups.add(1, 0x100, "kitchen").unwrap());
            assert!(groups.add(1, 0x100, "kitchen").unwrap());
            assert!(!groups.add(2, 0x100, "cuisine").unwrap());
            assert!(!groups.add(2, 0x101, "hall").unwrap());
            assert_eq!(groups.group_count(), 2);

            let entry = groups.get(0x100).unwrap();
            assert_eq!(entry.endpoints.as_slice(), &[1, 2]);
            // The most recent add renames the group
            assert_eq!(entry.group_name.as_str(), "cuisine");
            assert!(!entry.has_aux_acl());
            assert!(!entry.groupcast_managed());
            assert!(matches!(
                entry.effective_mcast_policy(),
                MulticastAddrPolicyEnum::PerGroup
            ));

            let ids: std::vec::Vec<_> = groups.iter().map(|e| e.group_id).collect();
            assert_eq!(ids, [0x100, 0x101]);

            groups.get_mut(0x101).unwrap().group_name.clear();
            assert_eq!(groups.get(0x101).unwrap().group_name.as_str(), "");
            assert!(groups.get_mut(0x1ff).is_none());

            // Removing a non-member is a no-op
            assert!(!groups.remove(7, Some(0x100)));
            assert!(!groups.remove(1, Some(0x101)));

            // Removing from one group leaves the others alone
            assert!(groups.remove(1, Some(0x100)));
            assert_eq!(groups.get(0x100).unwrap().endpoints.as_slice(), &[2]);

            // Removing from all groups; legacy groups left empty disappear
            assert!(groups.remove(2, None));
            assert!(groups.get(0x100).is_none());
            assert!(groups.get(0x101).is_none());
            assert_eq!(groups.group_count(), 0);
        }

        #[test]
        fn endpoint_mapping_capacity_and_name_length() {
            let mut groups = Groups::new();

            for i in 0..MAX_GROUPS_PER_FABRIC as u16 {
                groups.add(1, 0x100 + i, "g").unwrap();
            }
            assert_eq!(groups.group_count(), MAX_GROUPS_PER_FABRIC);
            assert_eq!(
                groups.add(1, 0x1ff, "g").unwrap_err().code(),
                ErrorCode::ResourceExhausted
            );

            // An existing group still accepts endpoints up to its own capacity
            for ep in 2..=GROUP_ENDPOINTS_PER_FABRIC as u16 {
                groups.add(ep, 0x100, "g").unwrap();
            }
            assert_eq!(
                groups.get(0x100).unwrap().endpoints.len(),
                GROUP_ENDPOINTS_PER_FABRIC
            );
            assert_eq!(
                groups
                    .add(GROUP_ENDPOINTS_PER_FABRIC as u16 + 1, 0x100, "g")
                    .unwrap_err()
                    .code(),
                ErrorCode::ResourceExhausted
            );

            let mut fresh = Groups::new();
            fresh
                .add(1, 0x100, &"n".repeat(MAX_GROUP_NAME_LEN))
                .unwrap();
            assert_eq!(
                fresh
                    .add(1, 0x101, &"n".repeat(MAX_GROUP_NAME_LEN + 1))
                    .unwrap_err()
                    .code(),
                ErrorCode::ConstraintError
            );
            assert_eq!(fresh.group_count(), 1);

            // A rejected name leaves an existing group's name and members untouched
            assert_eq!(
                fresh
                    .add(2, 0x100, &"n".repeat(MAX_GROUP_NAME_LEN + 1))
                    .unwrap_err()
                    .code(),
                ErrorCode::ConstraintError
            );
            let entry = fresh.get(0x100).unwrap();
            assert_eq!(entry.group_name.as_str(), "n".repeat(MAX_GROUP_NAME_LEN));
            assert_eq!(entry.endpoints.as_slice(), &[1]);
        }

        #[test]
        fn groupcast_join_and_remove() {
            let mut groups = Groups::new();

            // A new Groupcast membership defaults to the IANA address policy
            groups
                .groupcast_join(0x100, &[1, 2, 2], false, None)
                .unwrap();
            let entry = groups.get(0x100).unwrap();
            assert_eq!(entry.endpoints.as_slice(), &[1, 2]);
            assert_eq!(entry.group_name.as_str(), "");
            assert!(entry.groupcast_managed());
            assert!(!entry.has_aux_acl());
            assert!(matches!(
                entry.effective_mcast_policy(),
                MulticastAddrPolicyEnum::IanaAddr
            ));

            // Appending dedupes; replacing swaps the list; policy updates when given
            groups
                .groupcast_join(
                    0x100,
                    &[2, 3],
                    false,
                    Some(MulticastAddrPolicyEnum::PerGroup),
                )
                .unwrap();
            let entry = groups.get(0x100).unwrap();
            assert_eq!(entry.endpoints.as_slice(), &[1, 2, 3]);
            assert!(matches!(
                entry.effective_mcast_policy(),
                MulticastAddrPolicyEnum::PerGroup
            ));

            groups.groupcast_join(0x100, &[9], true, None).unwrap();
            let entry = groups.get(0x100).unwrap();
            assert_eq!(entry.endpoints.as_slice(), &[9]);
            assert!(matches!(
                entry.effective_mcast_policy(),
                MulticastAddrPolicyEnum::PerGroup
            ));

            // A sender-only membership has no endpoints but still exists
            groups.groupcast_join(0x101, &[], false, None).unwrap();
            assert_eq!(groups.get(0x101).unwrap().endpoints.len(), 0);
            assert_eq!(groups.group_count(), 2);

            // Joining a legacy (Groups cluster) entry upgrades it, keeping the
            // legacy-compatible PerGroup policy unless told otherwise
            groups.add(4, 0x102, "legacy").unwrap();
            groups.groupcast_join(0x102, &[5], false, None).unwrap();
            let entry = groups.get(0x102).unwrap();
            assert!(entry.groupcast_managed());
            assert_eq!(entry.endpoints.as_slice(), &[4, 5]);
            assert_eq!(entry.group_name.as_str(), "legacy");
            assert!(matches!(
                entry.effective_mcast_policy(),
                MulticastAddrPolicyEnum::PerGroup
            ));

            // Endpoint removal keeps an emptied Groupcast-managed entry around
            assert!(groups.remove(9, None));
            assert!(groups.get(0x100).is_some());
            assert_eq!(groups.get(0x100).unwrap().endpoints.len(), 0);

            assert!(groups.groupcast_remove(0x100));
            assert!(groups.get(0x100).is_none());
            assert!(!groups.groupcast_remove(0x100));
            assert_eq!(groups.group_count(), 2);
        }

        #[test]
        fn groupcast_join_capacity() {
            let mut groups = Groups::new();

            for i in 0..MAX_GROUPS_PER_FABRIC as u16 {
                groups.groupcast_join(0x100 + i, &[], false, None).unwrap();
            }
            assert_eq!(
                groups
                    .groupcast_join(0x1ff, &[], false, None)
                    .unwrap_err()
                    .code(),
                ErrorCode::ResourceExhausted
            );

            let endpoints: std::vec::Vec<u16> = (1..=GROUP_ENDPOINTS_PER_FABRIC as u16).collect();
            groups
                .groupcast_join(0x100, &endpoints, false, None)
                .unwrap();
            assert_eq!(
                groups
                    .groupcast_join(0x100, &[0xee], false, None)
                    .unwrap_err()
                    .code(),
                ErrorCode::ResourceExhausted
            );
            assert_eq!(
                groups.get(0x100).unwrap().endpoints.len(),
                GROUP_ENDPOINTS_PER_FABRIC
            );
        }

        #[test]
        fn set_has_aux_acl_reports_changes() {
            let mut groups = Groups::new();

            assert!(!groups.set_has_aux_acl(0x100, true));

            groups.groupcast_join(0x100, &[1], false, None).unwrap();
            assert!(!groups.get(0x100).unwrap().has_aux_acl());

            assert!(groups.set_has_aux_acl(0x100, true));
            assert!(groups.get(0x100).unwrap().has_aux_acl());
            assert!(!groups.set_has_aux_acl(0x100, true));
            assert!(groups.set_has_aux_acl(0x100, false));
            assert!(!groups.get(0x100).unwrap().has_aux_acl());

            // Legacy entries have no flag set; setting one works the same way
            groups.add(1, 0x101, "g").unwrap();
            assert!(!groups.set_has_aux_acl(0x101, false));
            assert!(groups.set_has_aux_acl(0x101, true));
            assert!(groups.get(0x101).unwrap().has_aux_acl());
        }
    }
}
