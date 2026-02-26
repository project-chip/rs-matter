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

use crate::crypto::{self, CanonAeadKey, CanonAeadKeyRef, Crypto, Kdf};
use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, ToTLV};
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;

pub const GROUP_MAX_EPOCH_KEYS: usize = 3;

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
