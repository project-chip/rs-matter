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

use crate::crypto::{self, CanonAeadKey, Crypto, Kdf};
use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, ToTLV};
use crate::utils::init::{init, init_zeroed, Init};

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
            epoch_key <- init_zeroed(),
            op_key <- init_zeroed(),
        })
    }

    pub fn new_from<C: Crypto>(
        crypto: C,
        epoch_key: &[u8],
        compressed_fabric_id: &u64,
    ) -> Result<Self, Error> {
        let mut ks = KeySet::new();
        Self::op_key_from_ipk(
            crypto,
            epoch_key,
            &compressed_fabric_id.to_be_bytes(),
            &mut ks.op_key,
        )?;
        ks.epoch_key.copy_from_slice(epoch_key);
        Ok(ks)
    }

    fn op_key_from_ipk<C: Crypto>(
        crypto: C,
        ipk: &[u8],
        compressed_id: &[u8],
        opkey: &mut CanonAeadKey,
    ) -> Result<(), Error> {
        const GRP_KEY_INFO: &[u8] = &[
            0x47, 0x72, 0x6f, 0x75, 0x70, 0x4b, 0x65, 0x79, 0x20, 0x76, 0x31, 0x2e, 0x30,
        ];

        crypto
            .kdf()?
            .expand(compressed_id, ipk, GRP_KEY_INFO, opkey)
            .map_err(|_| ErrorCode::InvalidData.into())
    }

    pub fn op_key(&self) -> &CanonAeadKey {
        &self.op_key
    }

    pub fn epoch_key(&self) -> &CanonAeadKey {
        &self.epoch_key
    }
}
