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

use crate::crypto::{self, CanonAeadKey, CanonAeadKeyRef, Crypto, Kdf};
use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, ToTLV};
use crate::utils::init::{init, Init};
#[cfg(feature = "groups")]
use crate::utils::storage::Vec;

#[cfg(feature = "groups")]
pub const GROUP_MAX_EPOCH_KEYS: usize = 3;

/// A stored group key set entry.
#[cfg(feature = "groups")]
#[derive(Debug, Clone, Default, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GroupEpochKeyEntry {
    pub epoch_key: CanonAeadKey,
    pub epoch_start_time: u64,
}

/// A stored group key set entry.
#[cfg(feature = "groups")]
#[derive(Debug, Clone, Default, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GroupKeySet {
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

#[cfg(test)]
mod tests {
    use crate::crypto::{test_only_crypto, CanonAeadKeyRef, AEAD_CANON_KEY_LEN};

    use super::KeySet;

    /// Compressed fabric ID of the Matter spec's "Compressed Fabric Identifier"
    /// example (`87e1b004e235a130`), also used as the salt by the CHIP SDK's
    /// group key derivation test vectors.
    const COMPRESSED_FABRIC_ID: u64 = 0x87e1_b004_e235_a130;

    /// `(epoch key, expected operational key)` pairs derived with
    /// `COMPRESSED_FABRIC_ID` as the salt: the three `kEpochKeys0` /
    /// `kGroupKeys0.encryption_key` entries from the CHIP SDK's
    /// `TestGroupOperationalCredentials.cpp`, plus the IPK example from
    /// `TestGroupDataProvider.cpp` (`kIpkEpochKeyFromSpec` /
    /// `kExpectedIpkFromSpec`).
    const VECTORS: &[([u8; AEAD_CANON_KEY_LEN], [u8; AEAD_CANON_KEY_LEN])] = &[
        (
            [0x00; 16],
            [
                0xc5, 0xf2, 0x69, 0x01, 0x87, 0x11, 0x51, 0x50, 0xc3, 0x56, 0xad, 0x93, 0xb3, 0x85,
                0xbb, 0x0f,
            ],
        ),
        (
            [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ],
            [
                0xae, 0xd9, 0x56, 0x95, 0xf3, 0x75, 0xd2, 0xce, 0x78, 0x55, 0x6a, 0x41, 0x73, 0x0c,
                0x3f, 0x43,
            ],
        ),
        (
            [
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f,
            ],
            [
                0x35, 0xca, 0x34, 0x6e, 0x5e, 0x24, 0xbb, 0xbe, 0x88, 0x9c, 0xf4, 0xd3, 0x5c, 0x5e,
                0x82, 0x0a,
            ],
        ),
        (
            [
                0x23, 0x5b, 0xf7, 0xe6, 0x28, 0x23, 0xd3, 0x58, 0xdc, 0xa4, 0xba, 0x50, 0xb1, 0x53,
                0x5f, 0x4b,
            ],
            [
                0xa6, 0xf5, 0x30, 0x6b, 0xaf, 0x6d, 0x05, 0x0a, 0xf2, 0x3b, 0xa4, 0xbd, 0x6b, 0x9d,
                0xd9, 0x60,
            ],
        ),
    ];

    #[test]
    fn new_is_zeroed() {
        let ks = KeySet::new();

        assert_eq!(ks.epoch_key().access(), &[0u8; AEAD_CANON_KEY_LEN]);
        assert_eq!(ks.op_key().access(), &[0u8; AEAD_CANON_KEY_LEN]);
    }

    #[test]
    fn init_is_zeroed() {
        use crate::utils::init::InitMaybeUninit;

        let mut ks = core::mem::MaybeUninit::<KeySet>::uninit();
        let ks = ks.init_with(KeySet::init());

        assert_eq!(ks.epoch_key().access(), &[0u8; AEAD_CANON_KEY_LEN]);
        assert_eq!(ks.op_key().access(), &[0u8; AEAD_CANON_KEY_LEN]);
    }

    #[test]
    fn update_derives_op_key_matching_chip_vectors() {
        let crypto = test_only_crypto();

        for (epoch_key, expected_op_key) in VECTORS {
            let mut ks = KeySet::new();
            ks.update(
                &crypto,
                CanonAeadKeyRef::new(epoch_key),
                &COMPRESSED_FABRIC_ID,
            )
            .unwrap();

            assert_eq!(ks.epoch_key().access(), epoch_key);
            assert_eq!(ks.op_key().access(), expected_op_key);
        }
    }

    #[test]
    fn update_with_different_fabric_id_yields_different_op_key() {
        let crypto = test_only_crypto();
        let (epoch_key, expected_op_key) = &VECTORS[1];

        let mut ks = KeySet::new();
        ks.update(
            &crypto,
            CanonAeadKeyRef::new(epoch_key),
            &(COMPRESSED_FABRIC_ID ^ 1),
        )
        .unwrap();

        assert_eq!(ks.epoch_key().access(), epoch_key);
        assert_ne!(ks.op_key().access(), expected_op_key);
    }

    #[test]
    fn update_twice_replaces_both_keys() {
        let crypto = test_only_crypto();
        let (epoch_a, op_a) = &VECTORS[1];
        let (epoch_b, op_b) = &VECTORS[2];

        let mut ks = KeySet::new();

        ks.update(
            &crypto,
            CanonAeadKeyRef::new(epoch_a),
            &COMPRESSED_FABRIC_ID,
        )
        .unwrap();
        assert_eq!(ks.epoch_key().access(), epoch_a);
        assert_eq!(ks.op_key().access(), op_a);

        ks.update(
            &crypto,
            CanonAeadKeyRef::new(epoch_b),
            &COMPRESSED_FABRIC_ID,
        )
        .unwrap();
        assert_eq!(ks.epoch_key().access(), epoch_b);
        assert_eq!(ks.op_key().access(), op_b);
    }
}
