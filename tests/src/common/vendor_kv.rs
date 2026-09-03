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

#![allow(dead_code)]

//! Device state the test drivers keep across a restart, stored in the Matter
//! KVS under the vendor key range.
//!
//! The drivers model devices whose application state outlives a restart - a
//! light's OnOff state, its startup color temperature - because several tests
//! restart the DUT mid-run and then assert on what came back.
//!
//! Keeping that state in the same store as the Matter state is what makes a
//! factory reset mean what the tests assume: the harness unlinks the KVS file
//! between tests, so the device really does come back with default application
//! state. State kept in a file of its own would survive that reset and leak
//! into whichever test ran next.

use rs_matter::error::Error;
use rs_matter::persist::{KvBlobStoreAccess, VENDOR_KEYS_START};

/// The OnOff state and `StartUpOnOff` of the light, as one byte.
pub const ON_OFF_STATE_KEY: u16 = VENDOR_KEYS_START;

/// `StartUpColorTemperatureMireds`, as a little-endian `u16`. Absent for null.
pub const START_UP_CT_KEY: u16 = VENDOR_KEYS_START + 1;

/// An object-safe view of a [`KvBlobStoreAccess`].
///
/// [`KvBlobStoreAccess::access`] is generic over its closure, so there is no
/// `&dyn KvBlobStoreAccess`. The device-logic structs need to hold a handle to
/// the store without becoming generic themselves - they are named bare in
/// `EpClMatcher` expressions, as `OnOffDeviceLogic::CLUSTER` - so this narrows
/// the store down to the three whole-blob operations they actually use.
pub trait VendorKv {
    /// Read the blob at `key` into `out`, returning how many bytes were
    /// written, or `None` if the key holds nothing.
    ///
    /// A blob longer than `out` is truncated: every caller here stores a fixed
    /// small value and reads it back with a buffer of exactly that size.
    fn load_blob(&self, key: u16, out: &mut [u8]) -> Result<Option<usize>, Error>;

    /// Write `data` to `key`.
    fn store_blob(&self, key: u16, data: &[u8]) -> Result<(), Error>;

    /// Remove `key`, which need not exist.
    fn remove_blob(&self, key: u16) -> Result<(), Error>;
}

impl<K> VendorKv for K
where
    K: KvBlobStoreAccess,
{
    fn load_blob(&self, key: u16, out: &mut [u8]) -> Result<Option<usize>, Error> {
        self.access(|store, buf| {
            let Some(data) = store.load(key, buf)? else {
                return Ok(None);
            };

            let len = data.len().min(out.len());
            out[..len].copy_from_slice(&data[..len]);

            Ok(Some(len))
        })
    }

    fn store_blob(&self, key: u16, data: &[u8]) -> Result<(), Error> {
        self.access(|store, buf| store.store(key, data, buf))
    }

    fn remove_blob(&self, key: u16) -> Result<(), Error> {
        self.access(|store, buf| store.remove(key, buf))
    }
}
