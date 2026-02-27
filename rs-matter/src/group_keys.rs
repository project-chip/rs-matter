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

use core::num::NonZeroU8;

use cfg_if::cfg_if;
use heapless::String;

use crate::crypto::{self, CanonAeadKey, CanonAeadKeyRef, Crypto, Kdf};
use crate::error::{Error, ErrorCode};
use crate::fabric::MAX_FABRICS;
use crate::tlv::{FromTLV, ToTLV};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;

pub const GROUP_MAX_EPOCH_KEYS: usize = 3;

/// Max number of group key sets per fabric (excluding IPK at index 0).
/// The spec requires maxGroupKeysPerFabric >= 3, so 2 + IPK = 3.
pub const MAX_GROUP_KEY_PER_FABRIC: usize = 2;

/// Max length of a group name (per Matter spec).
pub const MAX_GROUP_NAME_LEN: usize = 16;

cfg_if! {
    if #[cfg(feature = "max-groups-per-fabric-32")] {
        pub const MAX_GROUPS_PER_FABRIC: usize = 32;
    } else if #[cfg(feature = "max-groups-per-fabric-16")] {
        pub const MAX_GROUPS_PER_FABRIC: usize = 16;
    } else if #[cfg(feature = "max-groups-per-fabric-12")] {
        pub const MAX_GROUPS_PER_FABRIC: usize = 12;
    } else if #[cfg(feature = "max-groups-per-fabric-8")] {
        pub const MAX_GROUPS_PER_FABRIC: usize = 9;
    } else if #[cfg(feature = "max-groups-per-fabric-7")] {
        pub const MAX_GROUPS_PER_FABRIC: usize = 7;
    } else if #[cfg(feature = "max-groups-per-fabric-6")] {
        pub const MAX_GROUPS_PER_FABRIC: usize = 6;
    } else if #[cfg(feature = "max-groups-per-fabric-5")] {
        pub const MAX_GROUPS_PER_FABRIC: usize = 5;
    } else {  // The spec requires maxGroupsPerFabric >= 4
        pub const MAX_GROUPS_PER_FABRIC: usize = 4;
    }
}

/// A stored group entry representing membership of an endpoint in a group.
#[derive(Debug, Clone, Default, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GroupEntry {
    pub group_id: u16,
    pub endpoint_id: u16,
    pub group_name: String<MAX_GROUP_NAME_LEN>,
}

/// A stored group key map entry (maps group ID to key set).
#[derive(Debug, Clone, Default, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GrpKeyMapEntry {
    pub group_id: u16,
    pub group_key_set_id: u16,
}

/// A stored group key set entry.
#[derive(Debug, Clone, Default, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GroupEpochKeyEntry {
    pub epoch_key: CanonAeadKey,
    pub epoch_start_time: u64,
}

/// A stored group key set entry.
#[derive(Debug, Clone, Default, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GrpKeySetEntry {
    pub group_key_set_id: u16,
    pub group_key_security_policy: u8,
    pub epoch_keys: Vec<GroupEpochKeyEntry, GROUP_MAX_EPOCH_KEYS>,
}

#[derive(Debug, Default, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeySet {
    pub epoch_key: CanonAeadKey,
    pub op_key: CanonAeadKey,
}

impl KeySet {
    pub const fn new() -> Self {
        Self {
            epoch_key: crypto::AEAD_KEY_ZEROED,
            op_key: crypto::AEAD_KEY_ZEROED,
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            epoch_key <- CanonAeadKey::init(),
            op_key <- CanonAeadKey::init(),
        })
    }

    pub fn update<C: Crypto>(
        &mut self,
        crypto: C,
        epoch_key: CanonAeadKeyRef<'_>,
        compressed_fabric_id: &u64,
    ) -> Result<(), Error> {
        const GRP_KEY_INFO: &[u8] = &[
            0x47, 0x72, 0x6f, 0x75, 0x70, 0x4b, 0x65, 0x79, 0x20, 0x76, 0x31, 0x2e, 0x30,
        ];

        crypto
            .kdf()?
            .expand(
                &compressed_fabric_id.to_be_bytes(),
                epoch_key,
                GRP_KEY_INFO,
                &mut self.op_key,
            )
            .map_err(|_| ErrorCode::InvalidData)?;

        self.epoch_key.load(epoch_key);

        Ok(())
    }

    pub fn op_key(&self) -> CanonAeadKeyRef<'_> {
        self.op_key.reference()
    }

    pub fn epoch_key(&self) -> CanonAeadKeyRef<'_> {
        self.epoch_key.reference()
    }
}

/// Per-endpoint group memberships within a fabric.
struct EndpointGroups {
    endpoint_id: u16,

    // TODO: update this type to not include redundant endpoint_id
    memberships: Vec<GroupEntry, MAX_GROUPS_PER_FABRIC>,
}

impl EndpointGroups {
    fn new(endpoint_id: u16) -> Self {
        Self {
            endpoint_id,
            memberships: Vec::new(),
        }
    }
}

/// Per-fabric group data stored inside GroupStoreImpl.
struct FabricGroupData<const ENDPOINTS: usize> {
    fab_idx: NonZeroU8,
    group_key_sets: Vec<GrpKeySetEntry, MAX_GROUP_KEY_PER_FABRIC>,
    group_key_map: Vec<GrpKeyMapEntry, MAX_GROUPS_PER_FABRIC>,
    groups: Vec<EndpointGroups, ENDPOINTS>,
}

impl<const ENDPOINTS: usize> FabricGroupData<ENDPOINTS> {
    fn new(fab_idx: NonZeroU8) -> Self {
        Self {
            fab_idx,
            group_key_sets: Vec::new(),
            group_key_map: Vec::new(),
            groups: Vec::new(),
        }
    }
}

/// External trait for group-related storage.
pub trait GroupStore {
    /// Calls `callback` for each `(fab_idx, GrpKeyMapEntry)` that matches the filter.
    fn for_each_group_key_map(
        &self,
        fab_filter: Option<NonZeroU8>,
        callback: &mut dyn FnMut(NonZeroU8, &GrpKeyMapEntry),
    );

    /// Calls `callback` for each `(fab_idx, GroupEntry)` that matches the filter.
    fn for_each_group(
        &self,
        fab_filter: Option<NonZeroU8>,
        callback: &mut dyn FnMut(NonZeroU8, &GroupEntry),
    );

    /// Calls `callback` for each `(fab_idx, GrpKeySetEntry)` that matches the filter.
    fn for_each_group_key_set(
        &self,
        fab_filter: Option<NonZeroU8>,
        callback: &mut dyn FnMut(NonZeroU8, &GrpKeySetEntry),
    );

    /// Find a group key set by fabric and key set ID.
    fn group_key_set_get(
        &self,
        fab_idx: NonZeroU8,
        id: u16,
    ) -> Result<Option<GrpKeySetEntry>, Error>;

    /// Add or update a group key set for a fabric.
    fn group_key_set_add(&self, fab_idx: NonZeroU8, entry: GrpKeySetEntry) -> Result<(), Error>;

    /// Remove a group key set by ID. Also removes referencing key map entries.
    fn group_key_set_remove(&self, fab_idx: NonZeroU8, id: u16) -> Result<(), Error>;

    /// Replace all group key map entries for a fabric.
    fn group_key_map_replace(
        &self,
        fab_idx: NonZeroU8,
        entries: &[GrpKeyMapEntry],
    ) -> Result<(), Error>;

    /// Add a single group key map entry.
    fn group_key_map_add(&self, fab_idx: NonZeroU8, entry: GrpKeyMapEntry) -> Result<(), Error>;

    /// Check if a fabric has a group key map entry for the given group ID.
    fn has_group_key_map_entry(&self, fab_idx: NonZeroU8, group_id: u16) -> bool;

    /// Check if an endpoint is a member of a group on a fabric.
    fn has_group(&self, fab_idx: NonZeroU8, group_id: u16, endpoint_id: u16) -> bool;

    /// Get the group name for a group ID on a fabric.
    fn group_name(
        &self,
        fab_idx: NonZeroU8,
        group_id: u16,
    ) -> Result<Option<String<MAX_GROUP_NAME_LEN>>, Error>;

    /// Add an endpoint to a group. Returns true if already a member (update).
    fn group_add(
        &self,
        fab_idx: NonZeroU8,
        group_id: u16,
        endpoint_id: u16,
        group_name: &str,
    ) -> Result<bool, Error>;

    /// Remove an endpoint from a group. Returns true if was a member.
    fn group_remove(
        &self,
        fab_idx: NonZeroU8,
        group_id: u16,
        endpoint_id: u16,
    ) -> Result<bool, Error>;

    /// Remove all group memberships for an endpoint on a fabric.
    fn group_remove_all_for_endpoint(
        &self,
        fab_idx: NonZeroU8,
        endpoint_id: u16,
    ) -> Result<(), Error>;

    /// Remove all group data for a fabric (called on fabric removal).
    fn remove_fabric(&self, fab_idx: NonZeroU8);

    /// Max groups per fabric.
    fn max_groups_per_fabric(&self) -> u16;

    /// Max group key sets per fabric (excluding IPK).
    fn max_group_keys_per_fabric(&self) -> u16;
}

/// Concrete implementation of `GroupStore` backed by fixed-size storage.
///
/// The const generic `ENDPOINTS` is the number of endpoints implementing the groups cluster on the node.
/// Not having the accurate number of endpoints here might lead to errors while accessing the groups cluster.
/// Note: Currently the root endpoint also implements the groups cluster, so `ENDPOINTS` must be at least 1.
pub struct GroupStoreImpl<const ENDPOINTS: usize> {
    data: RefCell<Vec<FabricGroupData<ENDPOINTS>, MAX_FABRICS>>,
}

impl<const ENDPOINTS: usize> GroupStoreImpl<ENDPOINTS> {
    pub const fn new() -> Self {
        Self {
            data: RefCell::new(Vec::new()),
        }
    }

    /// Ensure a fabric entry exists, creating one if needed.
    fn ensure_fabric(data: &mut Vec<FabricGroupData<ENDPOINTS>, MAX_FABRICS>, fab_idx: NonZeroU8) {
        if !data.iter().any(|d| d.fab_idx == fab_idx) {
            // Ignore error if full - caller will get ResourceExhausted on operations
            let _ = data.push(FabricGroupData::new(fab_idx));
        }
    }
}

impl<const ENDPOINTS: usize> Default for GroupStoreImpl<ENDPOINTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const ENDPOINTS: usize> GroupStore for GroupStoreImpl<ENDPOINTS> {
    fn for_each_group_key_map(
        &self,
        fab_filter: Option<NonZeroU8>,
        callback: &mut dyn FnMut(NonZeroU8, &GrpKeyMapEntry),
    ) {
        let data = self.data.borrow();
        for fabric_group_data in data.iter() {
            if fab_filter.is_some_and(|f| f != fabric_group_data.fab_idx) {
                continue;
            }
            for entry in fabric_group_data.group_key_map.iter() {
                callback(fabric_group_data.fab_idx, entry);
            }
        }
    }

    fn for_each_group(
        &self,
        fab_filter: Option<NonZeroU8>,
        callback: &mut dyn FnMut(NonZeroU8, &GroupEntry),
    ) {
        let data = self.data.borrow();
        for fabric_group_data in data.iter() {
            if fab_filter.is_some_and(|f| f != fabric_group_data.fab_idx) {
                continue;
            }
            for groups in fabric_group_data.groups.iter() {
                for entry in groups.memberships.iter() {
                    callback(fabric_group_data.fab_idx, entry);
                }
            }
        }
    }

    fn for_each_group_key_set(
        &self,
        fab_filter: Option<NonZeroU8>,
        callback: &mut dyn FnMut(NonZeroU8, &GrpKeySetEntry),
    ) {
        let data = self.data.borrow();
        for fabric_group_data in data.iter() {
            if fab_filter.is_some_and(|f| f != fabric_group_data.fab_idx) {
                continue;
            }
            for entry in fabric_group_data.group_key_sets.iter() {
                callback(fabric_group_data.fab_idx, entry);
            }
        }
    }

    fn group_key_set_get(
        &self,
        fab_idx: NonZeroU8,
        id: u16,
    ) -> Result<Option<GrpKeySetEntry>, Error> {
        let data = self.data.borrow();
        let Some(fd) = data.iter().find(|d| d.fab_idx == fab_idx) else {
            return Ok(None);
        };
        Ok(fd
            .group_key_sets
            .iter()
            .find(|e| e.group_key_set_id == id)
            .cloned())
    }

    fn group_key_set_add(&self, fab_idx: NonZeroU8, entry: GrpKeySetEntry) -> Result<(), Error> {
        let mut data = self.data.borrow_mut();
        Self::ensure_fabric(&mut data, fab_idx);
        let fd = data.iter_mut().find(|d| d.fab_idx == fab_idx).unwrap();

        if let Some(existing) = fd
            .group_key_sets
            .iter_mut()
            .find(|e| e.group_key_set_id == entry.group_key_set_id)
        {
            *existing = entry;
        } else {
            fd.group_key_sets
                .push(entry)
                .map_err(|_| ErrorCode::ResourceExhausted)?;
        }
        Ok(())
    }

    fn group_key_set_remove(&self, fab_idx: NonZeroU8, id: u16) -> Result<(), Error> {
        let mut data = self.data.borrow_mut();
        let Some(fd) = data.iter_mut().find(|d| d.fab_idx == fab_idx) else {
            return Err(ErrorCode::NotFound.into());
        };

        let before = fd.group_key_sets.len();
        fd.group_key_sets.retain(|e| e.group_key_set_id != id);

        if fd.group_key_sets.len() >= before {
            return Err(ErrorCode::NotFound.into());
        }

        // Also remove referencing key map entries
        fd.group_key_map.retain(|e| e.group_key_set_id != id);

        Ok(())
    }

    fn group_key_map_replace(
        &self,
        fab_idx: NonZeroU8,
        entries: &[GrpKeyMapEntry],
    ) -> Result<(), Error> {
        let mut data = self.data.borrow_mut();
        Self::ensure_fabric(&mut data, fab_idx);
        let fabric_group_data = data.iter_mut().find(|d| d.fab_idx == fab_idx).unwrap();

        fabric_group_data.group_key_map.clear();
        for entry in entries {
            fabric_group_data
                .group_key_map
                .push(entry.clone())
                .map_err(|_| ErrorCode::ResourceExhausted)?;
        }
        Ok(())
    }

    fn group_key_map_add(&self, fab_idx: NonZeroU8, entry: GrpKeyMapEntry) -> Result<(), Error> {
        let mut data = self.data.borrow_mut();
        Self::ensure_fabric(&mut data, fab_idx);
        let fd = data.iter_mut().find(|d| d.fab_idx == fab_idx).unwrap();

        fd.group_key_map
            .push(entry)
            .map_err(|_| ErrorCode::Failure)?;
        Ok(())
    }

    fn has_group_key_map_entry(&self, fab_idx: NonZeroU8, group_id: u16) -> bool {
        let data = self.data.borrow();
        data.iter()
            .find(|d| d.fab_idx == fab_idx)
            .is_some_and(|fd| fd.group_key_map.iter().any(|e| e.group_id == group_id))
    }

    fn has_group(&self, fab_idx: NonZeroU8, group_id: u16, endpoint_id: u16) -> bool {
        let data = self.data.borrow();
        data.iter()
            .find(|d| d.fab_idx == fab_idx)
            .is_some_and(|fd| {
                fd.groups
                    .iter()
                    .find(|eg| eg.endpoint_id == endpoint_id)
                    .is_some_and(|eg| eg.memberships.iter().any(|e| e.group_id == group_id))
            })
    }

    fn group_name(
        &self,
        fab_idx: NonZeroU8,
        group_id: u16,
    ) -> Result<Option<String<MAX_GROUP_NAME_LEN>>, Error> {
        let data = self.data.borrow();
        let Some(fd) = data.iter().find(|d| d.fab_idx == fab_idx) else {
            return Ok(None);
        };
        for eg in fd.groups.iter() {
            if let Some(entry) = eg.memberships.iter().find(|e| e.group_id == group_id) {
                return Ok(Some(entry.group_name.clone()));
            }
        }
        Ok(None)
    }

    fn group_add(
        &self,
        fab_idx: NonZeroU8,
        group_id: u16,
        endpoint_id: u16,
        group_name: &str,
    ) -> Result<bool, Error> {
        let mut data = self.data.borrow_mut();
        Self::ensure_fabric(&mut data, fab_idx);
        let fd = data.iter_mut().find(|d| d.fab_idx == fab_idx).unwrap();

        // Update group name for all entries with this group_id across all endpoints
        if !group_name.is_empty() {
            for eg in fd.groups.iter_mut() {
                for entry in eg.memberships.iter_mut() {
                    if entry.group_id == group_id {
                        entry.group_name.clear();
                        let _ = entry.group_name.push_str(group_name);
                    }
                }
            }
        }

        // Find or create endpoint slot
        let eg = if let Some(eg) = fd
            .groups
            .iter_mut()
            .find(|eg| eg.endpoint_id == endpoint_id)
        {
            eg
        } else {
            fd.groups
                .push(EndpointGroups::new(endpoint_id))
                .map_err(|_| ErrorCode::ResourceExhausted)?;
            fd.groups.last_mut().unwrap()
        };

        // Check if already a member of this group on this endpoint
        if eg.memberships.iter().any(|e| e.group_id == group_id) {
            return Ok(true);
        }

        // Add new entry
        let name = core::str::FromStr::from_str(group_name).unwrap_or_default();
        eg.memberships
            .push(GroupEntry {
                group_id,
                endpoint_id,
                group_name: name,
            })
            .map_err(|_| ErrorCode::ResourceExhausted)?;

        Ok(false)
    }

    fn group_remove(
        &self,
        fab_idx: NonZeroU8,
        group_id: u16,
        endpoint_id: u16,
    ) -> Result<bool, Error> {
        let mut data = self.data.borrow_mut();
        let Some(fd) = data.iter_mut().find(|d| d.fab_idx == fab_idx) else {
            return Err(ErrorCode::NotFound.into());
        };

        let mut removed = false;
        for eg in fd.groups.iter_mut() {
            if eg.endpoint_id == endpoint_id {
                let before = eg.memberships.len();
                eg.memberships.retain(|e| e.group_id != group_id);
                removed = eg.memberships.len() < before;
                break;
            }
        }
        Ok(removed)
    }

    fn group_remove_all_for_endpoint(
        &self,
        fab_idx: NonZeroU8,
        endpoint_id: u16,
    ) -> Result<(), Error> {
        let mut data = self.data.borrow_mut();
        let Some(fd) = data.iter_mut().find(|d| d.fab_idx == fab_idx) else {
            return Err(ErrorCode::NotFound.into());
        };

        fd.groups.retain(|eg| eg.endpoint_id != endpoint_id);
        Ok(())
    }

    fn remove_fabric(&self, fab_idx: NonZeroU8) {
        let mut data = self.data.borrow_mut();
        data.retain(|d| d.fab_idx != fab_idx);
    }

    fn max_groups_per_fabric(&self) -> u16 {
        MAX_GROUPS_PER_FABRIC as u16
    }

    fn max_group_keys_per_fabric(&self) -> u16 {
        MAX_GROUP_KEY_PER_FABRIC as u16
    }
}
