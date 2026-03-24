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

//! Identity Protection Key (IPK) generation and management.
//!
//! The IPK is a 16-byte key used for fabric-level encryption. Each fabric
//! has a unique IPK that is provisioned during commissioning via the AddNOC
//! command.

use crate::crypto::{Crypto, RngCore};
use crate::error::Error;

/// IPK (Identity Protection Key) length in bytes.
pub const IPK_LEN: usize = 16;

/// IPK Epoch Key for fabric security.
///
/// This is the key value that gets sent in the AddNOC command's
/// `IPKValue` field.
#[derive(Debug, Clone)]
pub struct IpkEpochKey {
    key: [u8; IPK_LEN],
}

impl IpkEpochKey {
    /// Generate a new random IPK.
    pub fn generate<C: Crypto>(crypto: &C) -> Result<Self, Error> {
        let mut key = [0u8; IPK_LEN];
        crypto.rand()?.fill_bytes(&mut key);
        Ok(Self { key })
    }

    /// Create an IPK from existing key material.
    pub fn from_bytes(bytes: [u8; IPK_LEN]) -> Self {
        Self { key: bytes }
    }

    /// Get the key bytes for use in AddNOC command.
    pub fn as_bytes(&self) -> &[u8; IPK_LEN] {
        &self.key
    }

    /// Get a reference to the key bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.key
    }
}

impl Default for IpkEpochKey {
    fn default() -> Self {
        Self {
            key: [0u8; IPK_LEN],
        }
    }
}

impl AsRef<[u8]> for IpkEpochKey {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

impl From<[u8; IPK_LEN]> for IpkEpochKey {
    fn from(bytes: [u8; IPK_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipk_from_bytes() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let ipk = IpkEpochKey::from_bytes(bytes);
        assert_eq!(ipk.as_bytes(), &bytes);
    }

    #[test]
    fn test_ipk_default() {
        let ipk = IpkEpochKey::default();
        assert_eq!(ipk.as_bytes(), &[0u8; IPK_LEN]);
    }

    #[test]
    fn test_ipk_as_ref() {
        let bytes = [1u8; IPK_LEN];
        let ipk = IpkEpochKey::from_bytes(bytes);
        let slice: &[u8] = ipk.as_ref();
        assert_eq!(slice, &bytes);
    }

    #[test]
    fn test_ipk_from_array() {
        let bytes = [2u8; IPK_LEN];
        let ipk: IpkEpochKey = bytes.into();
        assert_eq!(ipk.as_bytes(), &bytes);
    }
}
