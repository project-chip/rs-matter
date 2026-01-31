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

//! This module provides a simple persistent storage manager (PSM) for `rs-matter`.

#[cfg(feature = "std")]
pub use fileio::*;

#[cfg(feature = "std")]
pub mod fileio {
    use core::mem::MaybeUninit;

    use std::fs;
    use std::io::{Read, Write};
    use std::path::Path;

    use embassy_futures::select::select;
    use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};

    use crate::dm::networks::wireless::{Wifi, WirelessNetwork, WirelessNetworks};
    use crate::error::{Error, ErrorCode};
    use crate::tlv::{Octets, TLVArray, TLVContainerIter, TLVElement, TLVTag, TLVWrite};
    use crate::utils::init::{init, Init};
    use crate::utils::storage::WriteBuf;
    use crate::Matter;

    /// A constant representing the absence of wireless networks.
    pub const NO_NETWORKS: Option<&'static WirelessNetworks<0, NoopRawMutex, Wifi>> = None;

    /// A simple persistent storage manager (PSM) for `rs-matter`.
    ///
    /// This storage saves everything (fabrics, basic info settings and wireless networks (if any))
    /// as a single file, which is compatible with the `chip-tool` YAML tests which - at least in V1.3.0.0 -
    /// do expect a single file for all persistent data.
    ///
    /// Moreover, this storage always persists the whole state, regardless what had changed, which
    /// requires a large memory buffer, which can keep the TLV data of all fabrics, basic info settings and wireless networks.
    ///
    /// NOTE: Production applications might need a more sophisticated persistent storage where e.g.
    /// each fabric is stored as a separate item.
    pub struct Psm<const N: usize = 32768> {
        buf: MaybeUninit<[u8; N]>,
    }

    impl<const N: usize> Default for Psm<N> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<const N: usize> Psm<N> {
        /// Create a new `Psm` instance.
        #[inline(always)]
        pub const fn new() -> Self {
            Self {
                buf: MaybeUninit::uninit(),
            }
        }

        /// Return an in-place initializer for `Psm`.
        pub fn init() -> impl Init<Self> {
            init!(Self {
                buf <- crate::utils::init::zeroed(),
            })
        }

        /// Load the persistent state from the given file path into the provided `Matter` instance
        ///
        /// Arguments:
        /// - `path`: The file path from where to load the persistent state.
        /// - `matter`: The `Matter` instance to load the state into (for fabrics and basic info settings).
        /// - `networks`: An optional reference to `WirelessNetworks` to load the wireless networks state into (if provided).
        pub fn load<P, const W: usize, M, T>(
            &mut self,
            path: P,
            matter: &Matter,
            networks: Option<&WirelessNetworks<W, M, T>>,
        ) -> Result<(), Error>
        where
            P: AsRef<Path>,
            M: RawMutex,
            T: WirelessNetwork,
        {
            let buf = unsafe { self.buf.assume_init_mut() };

            let Some(data) = Self::load_storage(path.as_ref(), buf)? else {
                return Ok(());
            };

            let mut items: TLVContainerIter<'_, Octets<'_>> =
                TLVArray::new(TLVElement::new(data))?.iter();

            matter.load_fabrics(items.next().ok_or(ErrorCode::Invalid)??.0)?;
            matter.load_basic_info(items.next().ok_or(ErrorCode::Invalid)??.0)?;

            if let Some(networks) = networks {
                networks.load(items.next().ok_or(ErrorCode::Invalid)??.0)?;
            }

            Ok(())
        }

        /// Store the persistent state from the provided `Matter` instance
        ///
        /// If the fabrics, basic info settings or wireless networks (if provided) have not changed,
        /// this method does nothing.
        ///
        /// Arguments:
        /// - `path`: The file path where to store the persistent state.
        /// - `matter`: The `Matter` instance whose state to store (for fabrics and basic info settings).
        /// - `networks`: An optional reference to `WirelessNetworks` whose state to store.
        pub fn store<P, const W: usize, M, T>(
            &mut self,
            path: P,
            matter: &Matter,
            networks: Option<&WirelessNetworks<W, M, T>>,
        ) -> Result<(), Error>
        where
            P: AsRef<Path>,
            M: RawMutex,
            T: WirelessNetwork,
        {
            if !matter.fabrics_changed()
                && !matter.basic_info_changed()
                && !networks.map(|networks| networks.changed()).unwrap_or(false)
            {
                return Ok(());
            }

            let buf = unsafe { self.buf.assume_init_mut() };

            let mut wb = WriteBuf::new(buf);

            wb.start_array(&TLVTag::Anonymous)?;

            wb.str_cb(&TLVTag::Anonymous, |buf| matter.store_fabrics(buf))?;

            wb.str_cb(&TLVTag::Anonymous, |buf| matter.store_basic_info(buf))?;

            if let Some(networks) = networks {
                wb.str_cb(&TLVTag::Anonymous, |buf| networks.store(buf))?;
            }

            wb.end_container()?;

            Self::save_storage(path.as_ref(), wb.as_slice())?;

            Ok(())
        }

        /// Run the persistent storage, which waits for changes in the `Matter` instance
        /// and the optional `WirelessNetworks` instance (if provided) and stores the state
        /// to the given file path whenever a change occurs.
        ///
        /// Arguments:
        /// - `path`: The file path where to store the persistent state.
        /// - `matter`: The `Matter` instance to monitor for changes and for state to store (for fabrics and basic info settings).
        /// - `networks`: An optional reference to `WirelessNetworks` to monitor for changes and for state to store (if provided).
        pub async fn run<P, const W: usize, M, T>(
            &mut self,
            path: P,
            matter: &Matter<'_>,
            networks: Option<&WirelessNetworks<W, M, T>>,
        ) -> Result<(), Error>
        where
            P: AsRef<Path>,
            M: RawMutex,
            T: WirelessNetwork,
        {
            // NOTE: Calling `load` here does not make sense, because the `Psm::run` future / async method is executed
            // concurrently with other `rs-matter` futures. Including the future (`Matter::run`) that takes a decision whether
            // the state of `rs-matter` is such that it is not provisioned yet (no fabrics) and as such
            // it has to open the basic commissioning window and print the QR code.
            //
            // User is supposed to instead explicitly call `load` before calling `Psm::run` and `Matter::run`
            // self.load_networks(dir, networks)?;

            loop {
                if let Some(networks) = networks {
                    select(matter.wait_persist(), networks.wait_persist()).await;
                } else {
                    matter.wait_persist().await;
                }

                self.store(path.as_ref(), matter, networks)?;
            }
        }

        /// Loads the data from the provided file path into the given buffer.
        ///
        /// Returns `Ok(Some(&[u8]))` if data was successfully loaded,
        /// `Ok(None)` if the file does not exist, or an `Err` if an error occurred.
        fn load_storage<'b>(path: &Path, buf: &'b mut [u8]) -> Result<Option<&'b [u8]>, Error> {
            match fs::File::open(path) {
                Ok(mut file) => {
                    let mut offset = 0;

                    loop {
                        if offset == buf.len() {
                            Err(ErrorCode::BufferTooSmall)?;
                        }

                        let len = file.read(&mut buf[offset..])?;

                        if len == 0 {
                            break;
                        }

                        offset += len;
                    }

                    let data = &buf[..offset];

                    trace!("Loaded {} bytes {:?}", data.len(), data);

                    Ok(Some(data))
                }
                Err(_) => Ok(None),
            }
        }

        /// Saves the given data to the specified file path.
        fn save_storage(path: &Path, data: &[u8]) -> Result<(), Error> {
            let mut file = fs::File::create(path)?;

            file.write_all(data)?;

            trace!("Stored {} bytes {:?}", data.len(), data);

            Ok(())
        }
    }
}
