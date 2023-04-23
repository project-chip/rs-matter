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

use crate::{crypto, error::Error};

#[derive(Debug, Default)]
pub struct KeySet {
    pub epoch_key: [u8; crypto::SYMM_KEY_LEN_BYTES],
    pub op_key: [u8; crypto::SYMM_KEY_LEN_BYTES],
}

impl KeySet {
    pub fn new(epoch_key: &[u8], compressed_id: &[u8]) -> Result<Self, Error> {
        let mut ks = KeySet::default();
        KeySet::op_key_from_ipk(epoch_key, compressed_id, &mut ks.op_key)?;
        ks.epoch_key.copy_from_slice(epoch_key);
        Ok(ks)
    }

    fn op_key_from_ipk(ipk: &[u8], compressed_id: &[u8], opkey: &mut [u8]) -> Result<(), Error> {
        const GRP_KEY_INFO: [u8; 13] = [
            0x47, 0x72, 0x6f, 0x75, 0x70, 0x4b, 0x65, 0x79, 0x20, 0x76, 0x31, 0x2e, 0x30,
        ];

        crypto::hkdf_sha256(compressed_id, ipk, &GRP_KEY_INFO, opkey).map_err(|_| Error::NoSpace)
    }

    pub fn op_key(&self) -> &[u8] {
        &self.op_key
    }

    pub fn epoch_key(&self) -> &[u8] {
        &self.epoch_key
    }
}
