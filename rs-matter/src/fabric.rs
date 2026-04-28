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

use core::mem::MaybeUninit;
use core::num::NonZeroU8;
use core::str::FromStr;

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
use crate::group_keys::{GroupKeySet, KeySet};
use crate::persist::{KvBlobStore, KvBlobStoreAccess, Persist, FABRIC_KEYS_START};
use crate::tlv::{FromTLV, TLVElement, ToTLV};
use crate::utils::init::{init, Init, InitMaybeUninit, IntoFallibleInit};
use crate::utils::storage::Vec;
use crate::MatterMdnsService;

const COMPRESSED_FABRIC_ID_LEN: usize = 8;

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
    } else {
        /// Max number of group key sets per fabric (excluding IPK at index 0).
        pub const MAX_GROUP_KEYS_PER_FABRIC: usize = 0;
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
    } else {
        /// Max number of group key map entries per fabric.
        pub const MAX_GROUPS_PER_FABRIC: usize = 0;
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
    } else {
        /// Max number of endpoints per group entry.
        pub const GROUP_ENDPOINTS_PER_FABRIC: usize = 0;
    }
}

/// A group table entry mapping a group ID to its endpoints and name.
#[derive(Debug, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GroupEndpointMapping {
    pub group_id: u16,
    pub endpoints: Vec<u16, GROUP_ENDPOINTS_PER_FABRIC>,
    pub group_name: String<MAX_GROUP_NAME_LEN>,
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
    fn init() -> impl Init<Self> {
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
        self.key_map.push(entry).map_err(|_| ErrorCode::Failure)?;

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

    /// Add an endpoint to a group.
    /// Returns true if the endpoint was already a member (name still updated per spec).
    pub fn add(
        &mut self,
        endpoint_id: u16,
        group_id: u16,
        group_name: &str,
    ) -> Result<bool, Error> {
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
                    group_name: unwrap!(String::from_str(group_name)),
                })
                .map_err(|_| ErrorCode::ResourceExhausted)?;
            unwrap!(self.endpoint_mapping.last_mut())
        };

        // Update group name
        entry.group_name.clear();
        unwrap!(entry.group_name.push_str(group_name));

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

        // Remove entries with no endpoints left
        self.endpoint_mapping.retain(|e| !e.endpoints.is_empty());

        removed
    }
}

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
    /// Intermediate CA certificate
    icac: Vec<u8, { MAX_CERT_TLV_LEN }>,
    /// Node Operational Certificate
    noc: Vec<u8, { MAX_CERT_TLV_LEN }>,
    /// Identity Protection Key
    ipk: KeySet,
    /// Fabric label; unique accross all fabrics on the device
    label: String<32>,
    /// Access Control List
    acl: Vec<AclEntry, { acl::MAX_ACL_ENTRIES_PER_FABRIC }>,
    /// Fabric group information
    groups: Groups,
}

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
        init!(Self {
            fab_idx,
            node_id: 0,
            fabric_id: 0,
            vendor_id: 0,
            compressed_fabric_id: 0,
            secret_key <- CanonPkcSecretKey::init(),
            root_ca <- Vec::init(),
            icac <- Vec::init(),
            noc <- Vec::init(),
            ipk <- KeySet::init(),
            label: String::new(),
            acl <- Vec::init(),
            groups <- Groups::init(),
        })
    }

    /// Update the fabric with the provided data so that it can operate.
    ///
    /// This method is supposed to be called right after `Fabric::init` or
    /// when the NOC of the fabric needs to be updated.
    ///
    /// `root_ca` is `None` when called from the `UpdateNOC` flow — Matter
    /// Core spec section 11.18.6.7 keeps the fabric's root cert unchanged
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
        self.icac.clear();
        self.icac
            .extend_from_slice(icac)
            .map_err(|_| ErrorCode::BufferTooSmall)?;
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

    pub fn mdns_service(&self) -> Option<MatterMdnsService> {
        self.mdns_service_for(self.node_id)
    }

    pub fn mdns_service_for(&self, node_id: u64) -> Option<MatterMdnsService> {
        (!self.noc.is_empty()).then_some(MatterMdnsService::Commissioned {
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
    /// Used by the CASE initiator to build Sigma1 (spec 4.14.2.4).
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
    pub fn icac(&self) -> &[u8] {
        &self.icac
    }

    /// Return the fabric's NOC
    pub fn noc(&self) -> &[u8] {
        &self.noc
    }

    /// Return the fabric's IPK
    pub fn ipk(&self) -> &KeySet {
        &self.ipk
    }

    /// Return the fabric's groups
    pub fn groups(&self) -> &Groups {
        &self.groups
    }

    /// Return a mutable reference to the fabric's groups
    pub fn groups_mut(&mut self) -> &mut Groups {
        &mut self.groups
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
        // if entry.auth_mode() == AuthMode::Pase {
        //     // Reserved for future use
        //     Err(ErrorCode::ConstraintError)?;
        // }

        self.acl
            .push_init(init, || ErrorCode::ResourceExhausted.into())?;

        let idx = self.acl.len() - 1;
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
    fn allow(&self, req: &AccessReq) -> bool {
        for e in &self.acl {
            if e.allow(req) {
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
    pub fn reset(&mut self) {
        self.fabrics.clear();
    }

    /// Remove all fabrics from the provided BLOB store as well as from memory.
    ///
    /// # Arguments
    /// - `store`: the BLOB store to remove the fabrics from
    /// - `buf`: a temporary buffer to use for removing the fabrics
    pub async fn reset_persist<S: KvBlobStore>(
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
    pub async fn load_persist<S: KvBlobStore>(
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

    /// Update an existing fabric with the provided data (usually, as a result of an `UpdateNOC` IM command).
    ///
    /// The fabric's existing root cert is preserved across this call —
    /// `UpdateNOC` per Matter Core spec section 11.18.6.7 is not allowed
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
        if req.accessor().auth_mode() == Some(AuthMode::Pase) {
            return true;
        }

        let Ok(fab_idx) = req.accessor().fab_idx() else {
            return false;
        };

        let Some(fabric) = self.get(fab_idx) else {
            return false;
        };

        fabric.allow(req)
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
    pub fn persist_mut(&mut self) -> &mut Persist<S> {
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
mod tests {
    use core::mem::MaybeUninit;

    use crate::cert::builder::{IssuerDN, NocBuilder, RcacBuilder, SubjectDN, Validity};
    use crate::cert::MAX_CERT_TLV_AND_ASN1_LEN;
    use crate::crypto::test_only_crypto;
    use crate::crypto::{
        CanonAeadKeyRef, CanonPkcSecretKey, Crypto, Hash, SecretKey, SigningSecretKey,
        AEAD_CANON_KEY_LEN,
    };
    use crate::utils::init::InitMaybeUninit;

    use super::Fabrics;

    /// Verify that `compute_dest_id` and `is_dest_id` agree: the hash output by
    /// `compute_dest_id` must be accepted by `is_dest_id` on the same fabric with
    /// the same random nonce.
    ///
    /// Uses runtime-generated certs (RcacBuilder + NocBuilder) with a real keypair
    /// so the fabric is in a valid state — the secret key matches the NOC's public key.
    #[test]
    fn test_compute_dest_id_matches_is_dest_id() {
        let crypto = test_only_crypto();

        let fabric_id: u64 = 1;
        let rcac_id: u64 = 1;
        let node_id: u64 = 100;

        // Generate RCAC keypair and build self-signed RCAC
        let rcac_secret_key = crypto.generate_secret_key().unwrap();
        let rcac_pubkey = rcac_secret_key.pub_key().unwrap();

        let validity = Validity {
            not_before: 0,
            not_after: 0,
        };

        let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let rcac_len = RcacBuilder::new(&mut rcac_buf)
            .build(
                &crypto,
                SubjectDN {
                    node_id: None,
                    fabric_id: Some(fabric_id),
                    cat_ids: &[],
                    ca_id: Some(rcac_id),
                },
                validity,
                &rcac_pubkey,
                &rcac_secret_key,
                &[0x01],
            )
            .unwrap();

        // Generate NOC keypair and build NOC signed by RCAC
        let noc_secret_key = crypto.generate_secret_key().unwrap();
        let noc_pubkey = noc_secret_key.pub_key().unwrap();

        let mut noc_secret_key_canon = CanonPkcSecretKey::new();
        noc_secret_key
            .write_canon(&mut noc_secret_key_canon)
            .unwrap();

        let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let noc_len = NocBuilder::new(&mut noc_buf)
            .build(
                &crypto,
                SubjectDN {
                    node_id: Some(node_id),
                    fabric_id: Some(fabric_id),
                    cat_ids: &[],
                    ca_id: None,
                },
                validity,
                &noc_pubkey,
                &rcac_pubkey,
                &rcac_secret_key,
                &[0x02],
                IssuerDN {
                    ca_id: Some(rcac_id),
                    fabric_id: Some(fabric_id),
                    is_rcac: true,
                },
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
}
