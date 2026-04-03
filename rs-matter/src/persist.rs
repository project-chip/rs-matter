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

//! This module provides the key-value BLOB store traits used throughout `rs-matter` for persistence, as well as some implementations for those.

use core::borrow::BorrowMut;

use crate::error::Error;
use crate::tlv::{TLVTag, ToTLV};
use crate::utils::cell::RefCell;
use crate::utils::storage::WriteBuf;
use crate::utils::sync::blocking::Mutex;

#[cfg(feature = "std")]
pub use fileio::*;

/// The first key available for the vendor-specific data.
pub const VENDOR_KEYS_START: u16 = 0x1000;

/// The key range reserved for fabrics (256 keys).
pub const FABRIC_KEYS_START: u16 = 0;

/// The key used for storing the basic info settings.
pub const BASIC_INFO_KEY: u16 = FABRIC_KEYS_START + 256;

/// The key used for storing the events epoch number.
pub const EVENT_EPOCH_KEY: u16 = BASIC_INFO_KEY + 1;

/// The key used for storing the wireless networks state.
pub const NETWORKS_KEY: u16 = BASIC_INFO_KEY + 2;

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
    fn load(&mut self, key: u16, buf: &mut [u8]) -> Result<Option<usize>, Error>;

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
    fn load(&mut self, key: u16, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        T::load(self, key, buf)
    }

    fn store(&mut self, key: u16, data: &[u8], buf: &mut [u8]) -> Result<(), Error> {
        T::store(self, key, data, buf)
    }

    fn remove(&mut self, key: u16, buf: &mut [u8]) -> Result<(), Error> {
        T::remove(self, key, buf)
    }
}

/// A noop implementation of the `KvBlobStore` trait.
pub struct DummyKvBlobStore;

impl KvBlobStore for DummyKvBlobStore {
    fn load(&mut self, _key: u16, _buf: &mut [u8]) -> Result<Option<usize>, Error> {
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

/// A noop implementation of the `KvBlobStoreAccess` trait.
pub struct DummyKvBlobStoreAccess;

impl KvBlobStoreAccess for DummyKvBlobStoreAccess {
    fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut dyn KvBlobStore, &mut [u8]) -> R,
    {
        f(&mut DummyKvBlobStore, &mut [])
    }
}

/// An implementation of the `KvBlobStoreAccess` trait that provides access
/// to a shared `KvBlobStore` instance and a shared buffer using async mutex.
pub struct SharedKvBlobStore<S, T>(Mutex<RefCell<(S, T)>>);

impl<S, T> SharedKvBlobStore<S, T> {
    /// Create a new `SharedKvBlobStore` instance.
    ///
    /// # Arguments
    /// - `store` - the wrapped `KvBlobStore` instance
    /// - `buf` - the wrapped buffer
    pub const fn new(store: S, buf: T) -> Self {
        Self(Mutex::new(RefCell::new((store, buf))))
    }
}

impl<S, T> KvBlobStoreAccess for SharedKvBlobStore<S, T>
where
    S: KvBlobStore,
    T: BorrowMut<[u8]>,
{
    fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut dyn KvBlobStore, &mut [u8]) -> R,
    {
        self.0.lock(|cell| {
            let mut kvb = cell.borrow_mut();
            let kvb = &mut *kvb;

            f(&mut kvb.0, kvb.1.borrow_mut())
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
                // DummyKvBlobStoreAccess uses an empty buffer
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
                // DummyKvBlobStoreAccess uses an empty buffer
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
                            Err(crate::error::ErrorCode::NoSpace)?;
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
        fn load(&mut self, key: u16, buf: &mut [u8]) -> Result<Option<usize>, Error> {
            Self::load(self, key, buf)
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
                    Err(crate::error::ErrorCode::NoSpace)?;
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
        fn load(&mut self, key: u16, buf: &mut [u8]) -> Result<Option<usize>, Error> {
            Self::load(self, key, buf)
        }

        fn store(&mut self, key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
            Self::store(self, key, data)
        }

        fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), Error> {
            Self::remove(self, key)
        }
    }
}
