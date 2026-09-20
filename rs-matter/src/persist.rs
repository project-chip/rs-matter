/*
 *
 *    Copyright (c) 2023-2026 Project CHIP Authors
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

//! This module provides the key-value BLOB store traits used throughout `rs-matter` for persistence, as well as some implementations for those.

use cfg_if::cfg_if;

use crate::error::Error;
use crate::tlv::{TLVTag, ToTLV};
use crate::utils::cell::RefCell;
use crate::utils::storage::WriteBuf;
use crate::utils::sync::blocking::Mutex;

#[cfg(feature = "std")]
pub use fileio::*;

cfg_if! {
    if #[cfg(feature = "kv-blob-store-65536")] {
        /// The size (in bytes) of the scratch buffer used by the key-value
        /// persistence machinery for (de)serializing BLOBs. This is the buffer
        /// owned by [`Matter`](crate::Matter) and recombined with the user's
        /// raw [`KvBlobStore`] by [`Matter::kv`](crate::Matter::kv) into a full
        /// [`KvBlobStoreAccess`].
        pub const KV_BUF_SIZE: usize = 65536;
    } else if #[cfg(feature = "kv-blob-store-32768")] {
        /// The size (in bytes) of the scratch buffer used by the key-value
        /// persistence machinery for (de)serializing BLOBs.
        pub const KV_BUF_SIZE: usize = 32768;
    } else if #[cfg(feature = "kv-blob-store-16384")] {
        /// The size (in bytes) of the scratch buffer used by the key-value
        /// persistence machinery for (de)serializing BLOBs.
        pub const KV_BUF_SIZE: usize = 16384;
    } else if #[cfg(feature = "kv-blob-store-8192")] {
        /// The size (in bytes) of the scratch buffer used by the key-value
        /// persistence machinery for (de)serializing BLOBs.
        pub const KV_BUF_SIZE: usize = 8192;
    } else if #[cfg(feature = "kv-blob-store-2048")] {
        /// The size (in bytes) of the scratch buffer used by the key-value
        /// persistence machinery for (de)serializing BLOBs.
        pub const KV_BUF_SIZE: usize = 2048;
    } else if #[cfg(feature = "kv-blob-store-1024")] {
        /// The size (in bytes) of the scratch buffer used by the key-value
        /// persistence machinery for (de)serializing BLOBs.
        pub const KV_BUF_SIZE: usize = 1024;
    } else { // Default (`kv-blob-store-4096`)
        /// The size (in bytes) of the scratch buffer used by the key-value
        /// persistence machinery for (de)serializing BLOBs.
        pub const KV_BUF_SIZE: usize = 4096;
    }
}

/// The first key available for the vendor-specific data.
pub const VENDOR_KEYS_START: u16 = 0x1000;

/// The key range reserved for fabrics (256 keys).
pub const FABRIC_KEYS_START: u16 = 0;

/// The key used for storing the basic info settings.
pub const BASIC_INFO_KEY: u16 = FABRIC_KEYS_START + 256;

/// The key used for storing the events epoch number.
pub const EVENT_EPOCH_KEY: u16 = BASIC_INFO_KEY + 1;

/// The key used for storing the wireless networks state.
pub const NETWORKS_KEY: u16 = EVENT_EPOCH_KEY + 1;

/// The key used for storing all UserLabel `LabelList` data across every
/// endpoint that hosts the UserLabel cluster.
pub const USER_LABELS_KEY: u16 = NETWORKS_KEY + 1;

/// The key used for storing all Binding entries across every
/// endpoint+fabric pair that hosts the Binding cluster.
pub const BINDINGS_KEY: u16 = USER_LABELS_KEY + 1;

/// The key used for storing the Last-Known-Good UTC Time value
/// (Matter Core spec). A single u64 Matter-epoch microseconds
/// payload, updated synchronously from
/// [`crate::Matter::set_utc_time`].
pub const LKG_UTC_KEY: u16 = BINDINGS_KEY + 1;

/// The key used for storing the Trusted Time Source configured by
/// the `SetTrustedTimeSource` command (Matter Core spec).
/// A single 11-byte payload: `[fab_idx:1 | node_id:8 (LE) | endpoint:2 (LE)]`,
/// updated synchronously from [`crate::Matter::set_trusted_time_source`].
/// The key is absent on disk when no trusted source is configured.
pub const TRUSTED_TIME_SOURCE_KEY: u16 = LKG_UTC_KEY + 1;

/// The key used for storing the entire Scenes Management cluster
/// state (scene table + per-fabric `CurrentScene`) as a single TLV
/// blob. Re-persisted on every successful mutation.
pub const SCENES_KEY: u16 = TRUSTED_TIME_SOURCE_KEY + 1;

/// The key used for storing the OTA Requestor's `DefaultOTAProviders` list
/// (at most one entry per fabric) as a single TLV blob. Re-persisted on every
/// successful write. Providers learned transiently via `AnnounceOTAProvider`
/// are **not** persisted.
pub const OTA_PROVIDERS_KEY: u16 = SCENES_KEY + 1;

/// The key used for storing the ICD Management cluster's `RegisteredClients`
/// list (across all fabrics) as a single TLV blob. Re-persisted on every
/// successful registration change.
pub const ICD_REGISTERED_CLIENTS_KEY: u16 = OTA_PROVIDERS_KEY + 1;

/// The key used for storing the ICD Check-In counter's epoch boundary (a 4-byte
/// little-endian value). Written only when a new epoch is crossed, so a restart
/// resumes past every counter value the previous run may have used.
pub const ICD_CHECK_IN_COUNTER_KEY: u16 = ICD_REGISTERED_CLIENTS_KEY + 1;

/// The key used for storing the CASE session resumption cache — a
/// single TLV blob holding up to
/// [`MAX_RESUMPTION_RECORDS`](crate::sc::case::MAX_RESUMPTION_RECORDS)
/// entries. Re-persisted by the background snapshot task whenever the
/// in-memory cache diverges from what was last written.
pub const CASE_RESUMPTION_KEY: u16 = ICD_CHECK_IN_COUNTER_KEY + 1;

/// The key used for storing the TimeSynchronization cluster's `TimeZone` +
/// `DSTOffset` lists (both `nonVolatile` quality per the Matter Core spec) as
/// a single TLV blob. See
/// [`TimeZoneStore`](crate::dm::clusters::time_sync::TimeZoneStore).
pub const TIME_ZONE_KEY: u16 = CASE_RESUMPTION_KEY + 1;

/// The key used for storing the Global Group Encrypted Data Message Counter's
/// epoch boundary (a 4-byte little-endian value). Written only when a new
/// epoch is crossed, so a restart resumes past every counter value the
/// previous run may have used - otherwise peers tracking us in their group
/// counter store would drop our post-restart group messages as replays.
///
/// NOTE: the key is reserved unconditionally (not behind the `groups`
/// feature), so that a device's key layout never depends on which Cargo
/// features it was built with.
pub const GROUP_DATA_COUNTER_KEY: u16 = TIME_ZONE_KEY + 1;

/// The node's reboot counter, backing `GeneralDiagnostics::RebootCount`.
pub const REBOOT_COUNT_KEY: u16 = GROUP_DATA_COUNTER_KEY + 1;

/// The first key past the singleton keys above - i.e. the next free slot for
/// a *new* singleton key.
///
/// Only used by [`SINGLETON_KEYS_FIT`] to prove that the singleton block has
/// not grown into [`PERSISTENT_SUBSCRIPTIONS_START`]; bump the key it is
/// derived from whenever a singleton is added.
const SINGLETON_KEYS_END: u16 = REBOOT_COUNT_KEY + 1;

/// The first key of the range reserved for persisted subscriptions.
///
/// Each persisted subscription occupies its own key
/// (`PERSISTENT_SUBSCRIPTIONS_START + slot`), so that a single record never grows
/// the value beyond one subscribe request (already bounded to one RX packet,
/// comfortably under the ~4 KiB per-value cap that some MCU key-value backends
/// impose). The range runs up to (but not including)
/// [`PERSISTENT_SUBSCRIPTIONS_END`].
///
/// IMPORTANT: the range is carved *downwards* from the top of the rs-matter
/// key space, deliberately *not* derived from the singleton keys below it.
/// Deriving it from those would mean that adding (or feature-gating) any
/// singleton key silently shifts every persisted subscription onto a different
/// key, so a device upgrading to a newer firmware would read another record's
/// bytes - or would lose its subscriptions. New singleton keys therefore grow
/// *into the gap* below this anchor, and [`SINGLETON_KEYS_FIT`] turns
/// exhausting that gap into a compile error rather than silent corruption.
pub const PERSISTENT_SUBSCRIPTIONS_START: u16 =
    PERSISTENT_SUBSCRIPTIONS_END - MAX_PERSISTED_SUBSCRIPTIONS as u16;

/// The first key past the range reserved for persisted subscriptions - i.e.
/// the top of the rs-matter key space, where the vendor keys begin.
pub const PERSISTENT_SUBSCRIPTIONS_END: u16 = VENDOR_KEYS_START;

/// How many persisted subscriptions the reserved range can hold.
///
/// The range is explicitly bounded (rather than running open-ended down from
/// [`PERSISTENT_SUBSCRIPTIONS_END`]) so that a `Subscriptions<N>` table sized
/// beyond it is caught at compile time instead of quietly overwriting the
/// singleton keys below.
pub const MAX_PERSISTED_SUBSCRIPTIONS: usize = 2048;

/// Compile-time proof that the singleton keys have not grown into the
/// persisted-subscription range.
///
/// If adding a singleton key ever breaks this, do NOT make room by shrinking
/// [`MAX_PERSISTED_SUBSCRIPTIONS`] or by moving [`VENDOR_KEYS_START`] - either
/// relocates [`PERSISTENT_SUBSCRIPTIONS_START`], and with it every
/// subscription an earlier firmware already persisted. That is a deliberate,
/// breaking key-layout migration, not a constant tweak.
// `::core::assert!` rather than the crate-wide `assert!`, which maps to
// `defmt::assert!` under the `defmt` feature and is not const-callable.
const SINGLETON_KEYS_FIT: () = ::core::assert!(
    SINGLETON_KEYS_END <= PERSISTENT_SUBSCRIPTIONS_START,
    "the rs-matter singleton keys have grown into the persisted-subscription range"
);

/// Compile-time proof that the persisted-subscription range has not moved.
///
/// [`PERSISTENT_SUBSCRIPTIONS_START`] is part of the on-device key layout:
/// every subscription persisted by an earlier firmware lives at
/// `PERSISTENT_SUBSCRIPTIONS_START + slot`. Deriving it from the two constants
/// above keeps the intent readable, but the result must stay pinned to the
/// value already shipped.
const SUBSCRIPTION_RANGE_PINNED: () = ::core::assert!(
    PERSISTENT_SUBSCRIPTIONS_START == 0x0800,
    "the persisted-subscription range has moved - existing devices would look for their subscriptions under the wrong keys"
);

/// Force the assertions to be evaluated.
const _: () = SINGLETON_KEYS_FIT;
const _: () = SUBSCRIPTION_RANGE_PINNED;

/// A trait representing a key-value BLOB storage.
///
/// NOTE: For now, the trait is deliberately modeled as non-async, so that it can be used from
/// regular `Handler` non-async instances so as to avoid code bloat due to too much async handlers.
///
/// However, this might change in future once/if rustc starts to optimize the generated async code a bit better.
pub trait KvBlobStore {
    /// Load a BLOB with the specified key from the storage.
    ///
    /// # Arguments
    /// - `key` - the key of the BLOB
    /// - `buf` - a buffer that the `KvBlobStore` implementation might use for its own purposes
    ///
    /// # Returns
    /// - `Ok(Some(&[u8]))` if the BLOB was successfully loaded,
    /// - `Ok(None)` if the BLOB with the specified key does not exist,
    /// - `Err` if an error occurred during loading.
    fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error>;

    /// Store a BLOB with the specified key in the storage.
    ///
    /// # Arguments
    /// - `key` - the key of the BLOB
    /// - `data` - the data to store
    /// - `buf` - a buffer that the `KvBlobStore` implementation might use for its own purposes
    ///
    /// # Returns
    /// - `Ok(())` if the BLOB was successfully stored,
    /// - `Err` if an error occurred during storing.
    fn store(&mut self, key: u16, data: &[u8], buf: &mut [u8]) -> Result<(), Error>;

    /// Remove a BLOB with the specified key from the storage.
    ///
    /// # Arguments
    /// - `key` - the key of the BLOB
    /// - `buf` - a buffer that the `KvBlobStore` implementation might use for its own purposes
    ///
    /// # Returns
    /// - `Ok(())` if the BLOB was successfully removed or did not exist
    /// - `Err` if an error occurred during removing.
    fn remove(&mut self, key: u16, buf: &mut [u8]) -> Result<(), Error>;
}

impl<T> KvBlobStore for &mut T
where
    T: KvBlobStore,
{
    fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        T::load(self, key, buf)
    }

    fn store(&mut self, key: u16, data: &[u8], buf: &mut [u8]) -> Result<(), Error> {
        T::store(self, key, data, buf)
    }

    fn remove(&mut self, key: u16, buf: &mut [u8]) -> Result<(), Error> {
        T::remove(self, key, buf)
    }
}

impl KvBlobStore for &mut dyn KvBlobStore {
    fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        (**self).load(key, buf)
    }

    fn store(&mut self, key: u16, data: &[u8], buf: &mut [u8]) -> Result<(), Error> {
        (**self).store(key, data, buf)
    }

    fn remove(&mut self, key: u16, buf: &mut [u8]) -> Result<(), Error> {
        (**self).remove(key, buf)
    }
}

/// A noop implementation of the `KvBlobStore` trait.
pub struct DummyKvBlobStore;

impl KvBlobStore for DummyKvBlobStore {
    fn load<'a>(&mut self, _key: u16, _buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        Ok(None)
    }

    fn store(&mut self, _key: u16, _data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }

    fn remove(&mut self, _key: u16, _buf: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }
}

/// A trait representing access to a `KvBlobStore` instance and a buffer for its use.
pub trait KvBlobStoreAccess {
    /// Get the `KvBlobStore` instance and buffer provided by this access.
    fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut dyn KvBlobStore, &mut [u8]) -> R;
}

impl<T> KvBlobStoreAccess for &T
where
    T: KvBlobStoreAccess,
{
    fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut dyn KvBlobStore, &mut [u8]) -> R,
    {
        T::access(self, f)
    }
}

/// Combines a (store-only) raw [`KvBlobStore`] with a scratch buffer to present a
/// full [`KvBlobStoreAccess`].
///
/// This is the concrete type returned by [`Matter::kv`](crate::Matter::kv), where
/// the buffer is owned by [`Matter`](crate::Matter). It owns the user's raw store
/// (behind a blocking mutex for interior mutability) and borrows the buffer. The
/// buffer lock is always taken first, then the store lock, so the two-lock order
/// is consistent across all persistence paths (and single-threaded executors never
/// actually block on either).
///
/// It can also be constructed directly (e.g. in tests, or to exercise a
/// persistence-consuming API without a real store) by pairing a
/// [`DummyKvBlobStore`] with a caller-owned buffer.
pub struct SharedKvBlobStore<'a, S, const KB: usize> {
    store: Mutex<RefCell<S>>,
    buf: &'a Mutex<RefCell<[u8; KB]>>,
}

impl<'a, S, const KB: usize> SharedKvBlobStore<'a, S, KB> {
    /// Create a new access object owning `store` and borrowing `buf`.
    pub const fn new(store: S, buf: &'a Mutex<RefCell<[u8; KB]>>) -> Self {
        Self {
            store: Mutex::new(RefCell::new(store)),
            buf,
        }
    }
}

impl<S, const KB: usize> KvBlobStoreAccess for SharedKvBlobStore<'_, S, KB>
where
    S: KvBlobStore,
{
    fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut dyn KvBlobStore, &mut [u8]) -> R,
    {
        self.buf.lock(|cell| {
            let mut buf = cell.borrow_mut();

            self.store
                .lock(|store| f(&mut *store.borrow_mut(), &mut *buf))
        })
    }
}

/// A utility for persisting a value in a `KvBlobStore` instance.
pub struct Persist<S> {
    kvb: S,
}

impl<S> Persist<S>
where
    S: KvBlobStoreAccess,
{
    /// Create a new `Persist` instance with the given key-value store instance.
    pub const fn new(kvb: S) -> Self {
        Self { kvb }
    }

    /// Save a value in the storage with the specified key by calling the provided closure to serialize the value into a buffer.
    pub fn store<F: FnOnce(&mut [u8]) -> Result<Option<usize>, Error>>(
        &mut self,
        key: u16,
        f: F,
    ) -> Result<(), Error> {
        self.kvb.access(|kvb, buf| {
            if !buf.is_empty() {
                // A no-op access (e.g. a dummy store with an empty buffer) skips persistence
                if let Some(len) = f(buf)? {
                    let (data, buf) = buf.split_at_mut(len);
                    kvb.store(key, data, buf)?;
                }
            }

            Ok(())
        })
    }

    /// Save a value that implements the `ToTLV` trait in the storage with the specified key.
    pub fn store_tlv<T: ToTLV>(&mut self, key: u16, tlv: T) -> Result<(), Error> {
        self.store(key, |buf| {
            let mut wb = WriteBuf::new(buf);

            tlv.to_tlv(&TLVTag::Anonymous, &mut wb)?;

            Ok(Some(wb.get_tail()))
        })
    }

    /// Remove the value with the specified key from the storage.
    pub fn remove(&mut self, key: u16) -> Result<(), Error> {
        self.kvb.access(|kvb, buf| {
            if !buf.is_empty() {
                // A no-op access (e.g. a dummy store with an empty buffer) skips persistence
                kvb.remove(key, buf)?;
            }

            Ok(())
        })
    }

    /// Call at the end when finished with everything else
    /// No-op for now
    pub fn run(self) -> Result<(), Error> {
        // No-op for now

        Ok(())
    }
}

#[cfg(feature = "std")]
mod fileio {
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};

    use crate::error::Error;

    use super::KvBlobStore;

    extern crate std;

    /// An implementation of the `KvBlobStore` trait that stores the BLOBs in a directory.
    ///
    /// The BLOBs are stored in files named after the keys in the specified directory.
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct DirKvBlobStore(
        #[cfg_attr(feature = "defmt", defmt(Debug2Format))] std::path::PathBuf,
    );

    impl DirKvBlobStore {
        /// Create a new `DirKvBlobStore` instance, which will persist
        /// its settings in `<tmp-dir>/rs-matter`.
        pub fn new_default() -> Self {
            Self(std::env::temp_dir().join("rs-matter"))
        }

        /// Create a new `DirKvBlobStore` instance.
        pub const fn new(path: std::path::PathBuf) -> Self {
            Self(path)
        }

        /// Load a BLOB with the specified key from the directory.
        pub fn load(&self, key: u16, buf: &mut [u8]) -> Result<Option<usize>, Error> {
            let path = self.key_path(key);

            match File::open(path) {
                Ok(mut file) => {
                    let mut offset = 0;

                    loop {
                        if offset == buf.len() {
                            // The buffer is full: the blob fits only if the
                            // file ends right here
                            let mut probe = [0u8; 1];

                            if file.read(&mut probe)? != 0 {
                                Err(crate::error::ErrorCode::BufferTooSmall)?;
                            }

                            break;
                        }

                        let len = file.read(&mut buf[offset..])?;

                        if len == 0 {
                            break;
                        }

                        offset += len;
                    }

                    let data = &buf[..offset];

                    debug!("Key {}: loaded {}B ({:?})", key, data.len(), data);

                    Ok(Some(data.len()))
                }
                Err(_) => Ok(None),
            }
        }

        /// Store a BLOB with the specified key in the directory.
        pub fn store(&self, key: u16, data: &[u8]) -> Result<(), Error> {
            let path = self.key_path(key);

            std::fs::create_dir_all(unwrap!(path.parent()))?;

            let mut file = File::create(path)?;

            file.write_all(data)?;

            debug!("Key {}: stored {}B ({:?})", key, data.len(), data);

            Ok(())
        }

        /// Remove a BLOB with the specified key from the directory.
        /// If the BLOB does not exist, this method does nothing.
        pub fn remove(&self, key: u16) -> Result<(), Error> {
            let path = self.key_path(key);

            if std::fs::remove_file(path).is_ok() {
                debug!("Key {}: removed", key);
            }

            Ok(())
        }

        fn key_path(&self, key: u16) -> std::path::PathBuf {
            self.0.join(format!("k_{key:04x}"))
        }
    }

    impl Default for DirKvBlobStore {
        fn default() -> Self {
            Self::new_default()
        }
    }

    impl KvBlobStore for DirKvBlobStore {
        fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
            Ok(Self::load(self, key, buf)?.map(|len| &buf[..len]))
        }

        fn store(&mut self, key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
            Self::store(self, key, data)
        }

        fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), Error> {
            Self::remove(self, key)
        }
    }

    /// An implementation of the `KvBlobStore` trait that stores all BLOBs in a single file.
    ///
    /// While the implementation is very inefficient, it is necessary when testing with the C++ SDK test harness,
    /// as it expects all data to be persisted as a single file (`/tmp/chip_kvs`).
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct FileKvBlobStore {
        #[cfg_attr(feature = "defmt", defmt(Debug2Format))]
        path: std::path::PathBuf,
        #[cfg_attr(feature = "defmt", defmt(Debug2Format))]
        blobs: Option<HashMap<u16, Vec<u8>>>,
    }

    impl FileKvBlobStore {
        /// Create a new `FileKvBlobStore` instance, which will persist its settings in `/tmp/chip_kvs`.
        pub fn new_default() -> Self {
            Self::new(PathBuf::from("/tmp/chip_kvs"))
        }

        /// Create a new `FileKvBlobStore` instance.
        pub const fn new(path: PathBuf) -> Self {
            Self { path, blobs: None }
        }

        /// Load a BLOB with the specified key from the file.
        pub fn load(&mut self, key: u16, buf: &mut [u8]) -> Result<Option<usize>, Error> {
            self.initialize()?;

            let blobs = self.blobs.as_ref().unwrap();

            if let Some(blob) = blobs.get(&key) {
                if blob.len() > buf.len() {
                    Err(crate::error::ErrorCode::BufferTooSmall)?;
                }

                buf[..blob.len()].copy_from_slice(blob);

                Ok(Some(blob.len()))
            } else {
                Ok(None)
            }
        }

        /// Store a BLOB with the specified key in the directory.
        pub fn store(&mut self, key: u16, data: &[u8]) -> Result<(), Error> {
            self.initialize()?;

            let blobs = self.blobs.as_mut().unwrap();

            blobs.insert(key, data.to_vec());

            Self::save_all(&self.path, blobs)
        }

        /// Remove a BLOB with the specified key from the directory.
        /// If the BLOB does not exist, this method does nothing.
        pub fn remove(&mut self, key: u16) -> Result<(), Error> {
            self.initialize()?;

            let blobs = self.blobs.as_mut().unwrap();

            blobs.remove(&key);

            Self::save_all(&self.path, blobs)
        }

        fn initialize(&mut self) -> Result<(), Error> {
            if self.blobs.is_none() {
                let mut blobs = HashMap::new();

                Self::load_all(&self.path, &mut blobs)?;

                self.blobs = Some(blobs);
            }

            Ok(())
        }

        fn load_all(path: &Path, blobs: &mut HashMap<u16, Vec<u8>>) -> Result<(), Error> {
            if let Ok(mut file) = File::open(path) {
                loop {
                    let mut key_buf = [0; 2];

                    if file.read_exact(&mut key_buf).is_err() {
                        break;
                    }

                    let key = u16::from_le_bytes(key_buf);

                    let mut len_buf = [0; 4];

                    file.read_exact(&mut len_buf)?;

                    let len = u32::from_le_bytes(len_buf) as usize;

                    let mut data = vec![0; len];

                    file.read_exact(&mut data)?;

                    blobs.insert(key, data);
                }
            }

            Ok(())
        }

        fn save_all(path: &Path, blobs: &HashMap<u16, Vec<u8>>) -> Result<(), Error> {
            let mut file = File::create(path)?;

            for (key, data) in blobs {
                file.write_all(&key.to_le_bytes())?;
                file.write_all(&(data.len() as u32).to_le_bytes())?;
                file.write_all(data)?;
            }

            Ok(())
        }
    }

    impl Default for FileKvBlobStore {
        fn default() -> Self {
            Self::new_default()
        }
    }

    impl KvBlobStore for FileKvBlobStore {
        fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
            Ok(Self::load(self, key, buf)?.map(|len| &buf[..len]))
        }

        fn store(&mut self, key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
            Self::store(self, key, data)
        }

        fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), Error> {
            Self::remove(self, key)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell as StdRefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use crate::error::{Error, ErrorCode};
    use crate::tlv::{FromTLV, TLVElement, TLVTag, ToTLV};
    use crate::utils::cell::RefCell;
    use crate::utils::sync::blocking::Mutex;

    use super::{DummyKvBlobStore, KvBlobStore, KvBlobStoreAccess, Persist, SharedKvBlobStore};

    /// A minimal in-memory `KvBlobStore` whose contents can be inspected
    /// from outside via the shared `Rc`.
    #[derive(Default, Clone)]
    struct MemKvBlobStore {
        blobs: Rc<StdRefCell<HashMap<u16, Vec<u8>>>>,
        /// Fail every `store` call with `NoSpace` when set.
        fail_store: bool,
    }

    impl MemKvBlobStore {
        fn get(&self, key: u16) -> Option<Vec<u8>> {
            self.blobs.borrow().get(&key).cloned()
        }

        fn len(&self) -> usize {
            self.blobs.borrow().len()
        }
    }

    impl KvBlobStore for MemKvBlobStore {
        fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
            match self.blobs.borrow().get(&key) {
                Some(v) => {
                    if v.len() > buf.len() {
                        return Err(ErrorCode::NoSpace.into());
                    }
                    buf[..v.len()].copy_from_slice(v);
                    Ok(Some(&buf[..v.len()]))
                }
                None => Ok(None),
            }
        }

        fn store(&mut self, key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
            if self.fail_store {
                return Err(ErrorCode::NoSpace.into());
            }
            self.blobs.borrow_mut().insert(key, data.to_vec());
            Ok(())
        }

        fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), Error> {
            self.blobs.borrow_mut().remove(&key);
            Ok(())
        }
    }

    /// Load `key` through the access object, copying the bytes out.
    fn load<A: KvBlobStoreAccess>(access: &A, key: u16) -> Option<Vec<u8>> {
        access.access(|kvb, buf| kvb.load(key, buf).unwrap().map(|d| d.to_vec()))
    }

    #[test]
    fn key_layout_is_pinned() {
        // Vendor keys begin right after the subscription range
        assert_eq!(
            super::PERSISTENT_SUBSCRIPTIONS_END,
            super::VENDOR_KEYS_START
        );
        assert_eq!(super::PERSISTENT_SUBSCRIPTIONS_START, 0x0800);
        assert_eq!(
            super::PERSISTENT_SUBSCRIPTIONS_END - super::PERSISTENT_SUBSCRIPTIONS_START,
            super::MAX_PERSISTED_SUBSCRIPTIONS as u16
        );

        // Singleton keys live above the fabric block and below the subscriptions
        assert_eq!(super::BASIC_INFO_KEY, 256);
        assert!(super::REBOOT_COUNT_KEY < super::PERSISTENT_SUBSCRIPTIONS_START);
        assert!(super::KV_BUF_SIZE >= 1024);
    }

    #[test]
    fn dummy_store_is_noop() {
        let mut store = DummyKvBlobStore;
        let mut buf = [0u8; 16];

        assert!(store.load(1, &mut buf).unwrap().is_none());
        store.store(1, &[1, 2, 3], &mut buf).unwrap();
        assert!(store.load(1, &mut buf).unwrap().is_none());
        store.remove(1, &mut buf).unwrap();
        store.remove(0xffff, &mut buf).unwrap();
    }

    #[test]
    fn shared_store_access_lends_store_and_buffer() {
        let mem = MemKvBlobStore::default();
        let buf = Mutex::new(RefCell::new([0u8; 64]));
        let shared = SharedKvBlobStore::new(mem.clone(), &buf);

        shared.access(|kvb, buf| {
            assert_eq!(buf.len(), 64);
            kvb.store(7, &[0xaa, 0xbb], buf).unwrap();
        });
        assert_eq!(mem.get(7).as_deref(), Some(&[0xaa, 0xbb][..]));

        assert_eq!(load(&shared, 7).as_deref(), Some(&[0xaa, 0xbb][..]));
        assert_eq!(load(&shared, 8), None);

        // `&T` forwards `KvBlobStoreAccess`
        assert_eq!(load(&&shared, 7).as_deref(), Some(&[0xaa, 0xbb][..]));

        // The access returns the closure's value
        let n: usize = shared.access(|_, buf| buf.len() * 2);
        assert_eq!(n, 128);
    }

    #[test]
    fn mut_ref_forwarding_impls() {
        let mut mem = MemKvBlobStore::default();
        let mut buf = [0u8; 16];

        {
            let mut r: &mut MemKvBlobStore = &mut mem;
            <&mut MemKvBlobStore as KvBlobStore>::store(&mut r, 1, &[9], &mut buf).unwrap();
            assert_eq!(
                <&mut MemKvBlobStore as KvBlobStore>::load(&mut r, 1, &mut buf).unwrap(),
                Some(&[9][..])
            );
        }
        {
            let mut d: &mut dyn KvBlobStore = &mut mem;
            assert_eq!(
                <&mut dyn KvBlobStore as KvBlobStore>::load(&mut d, 1, &mut buf).unwrap(),
                Some(&[9][..])
            );
            <&mut dyn KvBlobStore as KvBlobStore>::remove(&mut d, 1, &mut buf).unwrap();
            assert_eq!(
                <&mut dyn KvBlobStore as KvBlobStore>::load(&mut d, 1, &mut buf).unwrap(),
                None
            );
        }
    }

    #[test]
    fn persist_store_closure_some_writes_prefix() {
        let mem = MemKvBlobStore::default();
        let buf = Mutex::new(RefCell::new([0u8; 32]));
        let shared = SharedKvBlobStore::new(mem.clone(), &buf);
        let mut persist = Persist::new(&shared);

        persist
            .store(0x1000, |buf| {
                assert_eq!(buf.len(), 32);
                buf[..4].copy_from_slice(&[1, 2, 3, 4]);
                // Bytes beyond the returned length are scratch and must not be stored
                buf[4] = 0xee;
                Ok(Some(4))
            })
            .unwrap();

        assert_eq!(mem.get(0x1000).as_deref(), Some(&[1, 2, 3, 4][..]));
        assert_eq!(mem.len(), 1);
    }

    #[test]
    fn persist_store_closure_none_skips_write() {
        let mem = MemKvBlobStore::default();
        let buf = Mutex::new(RefCell::new([0u8; 32]));
        let shared = SharedKvBlobStore::new(mem.clone(), &buf);
        let mut persist = Persist::new(&shared);

        persist.store(5, |_| Ok(Some(2))).unwrap();
        assert!(mem.get(5).is_some());

        // `None` is "nothing to persist": the existing value stays as-is
        persist.store(5, |_| Ok(None)).unwrap();
        assert_eq!(mem.get(5).as_deref(), Some(&[0, 0][..]));

        persist.store(6, |_| Ok(None)).unwrap();
        assert_eq!(mem.get(6), None);
        assert_eq!(mem.len(), 1);
    }

    #[test]
    fn persist_store_propagates_errors() {
        let mem = MemKvBlobStore::default();
        let buf = Mutex::new(RefCell::new([0u8; 32]));
        let shared = SharedKvBlobStore::new(mem.clone(), &buf);
        let mut persist = Persist::new(&shared);

        // Serializer error
        let err = persist
            .store(1, |_| Err::<Option<usize>, _>(ErrorCode::NoSpace.into()))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoSpace);
        assert_eq!(mem.len(), 0);

        // Backend error
        let failing = MemKvBlobStore {
            fail_store: true,
            ..Default::default()
        };
        let shared = SharedKvBlobStore::new(failing, &buf);
        let mut persist = Persist::new(&shared);
        let err = persist.store(1, |_| Ok(Some(1))).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoSpace);
    }

    #[test]
    fn persist_empty_buffer_skips_everything() {
        let mem = MemKvBlobStore::default();
        let buf = Mutex::new(RefCell::new([0u8; 0]));
        let shared = SharedKvBlobStore::new(mem.clone(), &buf);
        let mut persist = Persist::new(&shared);

        // With no scratch space the serializer is never invoked and nothing is stored
        persist
            .store(1, |_| -> Result<Option<usize>, Error> {
                panic!("serializer must not run with an empty buffer")
            })
            .unwrap();
        assert_eq!(mem.len(), 0);

        // ... and removes are skipped as well
        mem.blobs.borrow_mut().insert(1, vec![1]);
        persist.remove(1).unwrap();
        assert_eq!(mem.len(), 1);

        persist.run().unwrap();
    }

    #[test]
    fn persist_store_tlv_roundtrips_through_load() {
        #[derive(Debug, PartialEq, Eq, FromTLV, ToTLV)]
        struct Rec {
            a: u32,
            b: bool,
        }

        let mem = MemKvBlobStore::default();
        let buf = Mutex::new(RefCell::new([0u8; 64]));
        let shared = SharedKvBlobStore::new(mem.clone(), &buf);
        let mut persist = Persist::new(&shared);

        let rec = Rec {
            a: 0x0102_0304,
            b: true,
        };
        persist.store_tlv(0x1001, &rec).unwrap();

        // Plain values serialize as the anonymous TLV element
        persist.store_tlv(0x1002, 42u8).unwrap();
        assert_eq!(mem.get(0x1002).as_deref(), Some(&[0x04, 42][..]));

        let raw = load(&shared, 0x1001).unwrap();
        let back = Rec::from_tlv(&TLVElement::new(&raw)).unwrap();
        assert_eq!(back, rec);

        // Overwrite replaces the value
        persist.store_tlv(0x1001, 7u8).unwrap();
        assert_eq!(load(&shared, 0x1001).as_deref(), Some(&[0x04, 7][..]));

        // A value that does not fit the scratch buffer is an error, not a truncation
        let big = [0u8; 100];
        let err = persist
            .store(0x1003, |buf| {
                let mut wb = crate::utils::storage::WriteBuf::new(buf);
                big.to_tlv(&TLVTag::Anonymous, &mut wb)?;
                Ok(Some(wb.get_tail()))
            })
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoSpace);
        assert_eq!(mem.get(0x1003), None);
    }

    #[test]
    fn persist_remove_then_load_is_none() {
        let mem = MemKvBlobStore::default();
        let buf = Mutex::new(RefCell::new([0u8; 32]));
        let shared = SharedKvBlobStore::new(mem.clone(), &buf);
        let mut persist = Persist::new(&shared);

        persist.store_tlv(3, 1u8).unwrap();
        persist.store_tlv(4, 2u8).unwrap();
        assert!(load(&shared, 3).is_some());

        persist.remove(3).unwrap();
        assert_eq!(load(&shared, 3), None);
        // Other keys are untouched
        assert!(load(&shared, 4).is_some());

        // Removing a missing key is fine
        persist.remove(3).unwrap();
        persist.remove(0xffff).unwrap();

        persist.run().unwrap();
    }

    #[test]
    fn persist_with_dummy_store() {
        let buf = Mutex::new(RefCell::new([0u8; 32]));
        let shared = SharedKvBlobStore::new(DummyKvBlobStore, &buf);
        let mut persist = Persist::new(&shared);

        persist.store_tlv(1, 5u8).unwrap();
        assert_eq!(load(&shared, 1), None);
        persist.remove(1).unwrap();
        persist.run().unwrap();
    }

    #[cfg(feature = "std")]
    mod fileio {
        use super::super::{DirKvBlobStore, FileKvBlobStore, KvBlobStore};
        use crate::error::ErrorCode;

        fn exercise(store: &mut dyn KvBlobStore) {
            let mut buf = [0u8; 64];

            // Missing key
            assert_eq!(store.load(1, &mut buf).unwrap(), None);

            // Store / load
            store.store(1, &[1, 2, 3], &mut buf).unwrap();
            assert_eq!(store.load(1, &mut buf).unwrap(), Some(&[1, 2, 3][..]));

            // Second key, then overwrite the first
            store.store(2, &[9; 40], &mut buf).unwrap();
            store.store(1, &[4, 5], &mut buf).unwrap();
            assert_eq!(store.load(1, &mut buf).unwrap(), Some(&[4, 5][..]));
            assert_eq!(store.load(2, &mut buf).unwrap(), Some(&[9; 40][..]));

            // Empty value is stored as such and distinguishable from a missing key
            store.store(3, &[], &mut buf).unwrap();
            assert_eq!(store.load(3, &mut buf).unwrap(), Some(&[][..]));

            // Buffer too small
            let mut small = [0u8; 10];
            assert_eq!(
                store.load(2, &mut small).unwrap_err().code(),
                ErrorCode::BufferTooSmall
            );
            // Remove (twice) then load
            store.remove(1, &mut buf).unwrap();
            store.remove(1, &mut buf).unwrap();
            assert_eq!(store.load(1, &mut buf).unwrap(), None);
            assert_eq!(store.load(2, &mut buf).unwrap(), Some(&[9; 40][..]));
        }

        #[test]
        fn dir_store_roundtrip() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("kv");

            let mut store = DirKvBlobStore::new(path.clone());
            exercise(&mut store);

            // Keys are files named after the key; data survives a fresh instance
            assert!(path.join("k_0002").is_file());
            assert!(!path.join("k_0001").exists());

            let mut reopened = DirKvBlobStore::new(path);
            let reopened: &mut dyn KvBlobStore = &mut reopened;
            let mut buf = [0u8; 64];
            assert_eq!(reopened.load(2, &mut buf).unwrap(), Some(&[9; 40][..]));
            assert_eq!(reopened.load(1, &mut buf).unwrap(), None);
        }

        /// A value that exactly fills the caller's buffer loads fine.
        #[test]
        fn dir_store_exact_fit_buffer() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = DirKvBlobStore::new(dir.path().join("kv"));
            let store: &mut dyn KvBlobStore = &mut store;

            let mut buf = [0u8; 64];
            store.store(2, &[9; 40], &mut buf).unwrap();

            let mut exact = [0u8; 40];
            assert_eq!(store.load(2, &mut exact).unwrap(), Some(&[9; 40][..]));
        }

        #[test]
        fn dir_store_missing_dir_loads_none() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = DirKvBlobStore::new(dir.path().join("does-not-exist"));
            let store: &mut dyn KvBlobStore = &mut store;

            let mut buf = [0u8; 8];
            assert_eq!(store.load(1, &mut buf).unwrap(), None);
            store.remove(1, &mut buf).unwrap();
        }

        #[test]
        fn file_store_roundtrip() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("chip_kvs");

            let mut store = FileKvBlobStore::new(path.clone());
            exercise(&mut store);

            // Everything lives in the single file and survives a fresh instance
            assert!(path.is_file());

            let mut reopened = FileKvBlobStore::new(path);
            let reopened: &mut dyn KvBlobStore = &mut reopened;
            let mut buf = [0u8; 64];
            assert_eq!(reopened.load(2, &mut buf).unwrap(), Some(&[9; 40][..]));
            assert_eq!(reopened.load(3, &mut buf).unwrap(), Some(&[][..]));
            assert_eq!(reopened.load(1, &mut buf).unwrap(), None);
        }

        /// A value that exactly fills the caller's buffer loads fine.
        #[test]
        fn file_store_exact_fit_buffer() {
            let dir = tempfile::tempdir().unwrap();
            let mut store = FileKvBlobStore::new(dir.path().join("chip_kvs"));
            let store: &mut dyn KvBlobStore = &mut store;

            let mut buf = [0u8; 64];
            store.store(2, &[9; 40], &mut buf).unwrap();

            let mut exact = [0u8; 40];
            assert_eq!(store.load(2, &mut exact).unwrap(), Some(&[9; 40][..]));
        }

        #[test]
        fn file_store_missing_file_loads_none() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("absent");
            let mut store = FileKvBlobStore::new(path.clone());
            let store: &mut dyn KvBlobStore = &mut store;

            let mut buf = [0u8; 8];
            assert_eq!(store.load(1, &mut buf).unwrap(), None);
            // A load alone does not create the file
            assert!(!path.exists());

            // A remove of a missing key writes the (empty) file
            store.remove(1, &mut buf).unwrap();
            assert!(path.is_file());
        }
    }
}
