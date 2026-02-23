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

    use embassy_futures::select::{select, select3};
    use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};

    use crate::dm::events::Events;
    use crate::dm::networks::wireless::{Wifi, WirelessNetwork, WirelessNetworks};
    use crate::error::{Error, ErrorCode};
    use crate::tlv::{
        Octets, TLVArray, TLVContainerIter, TLVElement, TLVTag, TLVValueType, TLVWrite,
    };
    use crate::utils::init::{init, Init};
    use crate::utils::storage::WriteBuf;
    use crate::Matter;

    /// A constant representing the absence of wireless networks.
    pub const NO_NETWORKS: Option<&'static WirelessNetworks<0, NoopRawMutex, Wifi>> = None;

    /// A constant representing the absence of events.
    pub const NO_EVENTS: Option<&'static Events<0, NoopRawMutex>> = None;

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
        /// - `events`: An optional reference to `Events` to load the events state into (if provided).
        pub fn load<P, const W: usize, M, T, const NE: usize>(
            &mut self,
            path: P,
            matter: &Matter,
            networks: Option<&WirelessNetworks<W, M, T>>,
            events: Option<&Events<NE, M>>,
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

            let root = TLVElement::new(data);

            if root.control()?.value_type == TLVValueType::Array {
                // Legacy format: anonymous array with positional octet-strings
                let mut items: TLVContainerIter<'_, Octets<'_>> = TLVArray::new(root)?.iter();

                matter.load_fabrics(items.next().ok_or(ErrorCode::Invalid)??.0)?;
                matter.load_basic_info(items.next().ok_or(ErrorCode::Invalid)??.0)?;

                if let Some(networks) = networks {
                    networks.load(items.next().ok_or(ErrorCode::Invalid)??.0)?;
                }
            } else {
                // New format: struct with context-tagged octet-strings
                let container = root.container()?;

                matter.load_fabrics(container.find_ctx(0)?.octets()?)?;
                matter.load_basic_info(container.find_ctx(1)?.octets()?)?;

                if let Some(networks) = networks {
                    networks.load(container.find_ctx(2)?.octets()?)?;
                }

                if let Some(events) = events {
                    events.load(container.find_ctx(3)?.octets()?)?;
                }
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
        /// - `events`: An optional reference to `Events` whose state to store.
        pub fn store<P, const W: usize, M, T, const NE: usize>(
            &mut self,
            path: P,
            matter: &Matter,
            networks: Option<&WirelessNetworks<W, M, T>>,
            events: Option<&Events<NE, M>>,
        ) -> Result<(), Error>
        where
            P: AsRef<Path>,
            M: RawMutex,
            T: WirelessNetwork,
        {
            if !matter.fabrics_changed()
                && !matter.basic_info_changed()
                && !networks.map(|networks| networks.changed()).unwrap_or(false)
                && !events.map(|events| events.changed()).unwrap_or(false)
            {
                return Ok(());
            }

            let buf = unsafe { self.buf.assume_init_mut() };

            let mut wb = WriteBuf::new(buf);

            wb.start_struct(&TLVTag::Anonymous)?;

            wb.str_cb(&TLVTag::Context(0), |buf| matter.store_fabrics(buf))?;

            wb.str_cb(&TLVTag::Context(1), |buf| matter.store_basic_info(buf))?;

            if let Some(networks) = networks {
                wb.str_cb(&TLVTag::Context(2), |buf| networks.store(buf))?;
            }

            if let Some(events) = events {
                wb.str_cb(&TLVTag::Context(3), |buf| events.store(buf))?;
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
        /// - `events`: An optional reference to `Events` to monitor for changes and for state to store (if provided).
        pub async fn run<P, const W: usize, M, T, const NE: usize>(
            &mut self,
            path: P,
            matter: &Matter<'_>,
            networks: Option<&WirelessNetworks<W, M, T>>,
            events: Option<&Events<NE, M>>,
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
                match (networks, events) {
                    (Some(networks), Some(events)) => {
                        select3(
                            matter.wait_persist(),
                            networks.wait_persist(),
                            events.wait_persist(),
                        )
                        .await;
                    }
                    (Some(networks), None) => {
                        select(matter.wait_persist(), networks.wait_persist()).await;
                    }
                    (None, Some(events)) => {
                        select(matter.wait_persist(), events.wait_persist()).await;
                    }
                    (None, None) => {
                        matter.wait_persist().await;
                    }
                }

                self.store(path.as_ref(), matter, networks, events)?;
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

    #[cfg(test)]
    mod tests {
        use crate::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
        use crate::dm::events::{Events, PersistedState};
        use crate::utils::epoch::sys_epoch;
        use crate::MATTER_PORT;

        use super::*;

        fn new_test_matter() -> Matter<'static> {
            let matter = Matter::new(
                &TEST_DEV_DET,
                TEST_DEV_COMM,
                &TEST_DEV_ATT,
                sys_epoch,
                MATTER_PORT,
            );

            matter
                .fabric_mgr
                .borrow_mut()
                .add_with_post_init(|_| Ok(()))
                .unwrap();

            matter
        }

        #[test]
        fn test_store_load_roundtrip() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("persist.bin");

            // Set up a matter instance with some non-default config
            let initial_matter = new_test_matter();
            {
                let mut basic = initial_matter.basic_info_settings.borrow_mut();
                basic.node_label = heapless::String::try_from("my-test-node").unwrap();
                basic.location = Some(heapless::String::try_from("ab").unwrap());
                basic.changed = true;
            }

            // Set up events with a recognizable epoch value
            let events = Events::<64>::new(sys_epoch);
            events.persisted_state.lock(|cell| {
                cell.set(PersistedState {
                    next_event_no: 0,
                    event_epoch_end: 0xDEADBEEF,
                    changed: true,
                });
            });

            let mut psm = Psm::<32768>::new();
            psm.store(&path, &initial_matter, NO_NETWORKS, Some(&events))
                .unwrap();

            assert!(path.exists());
            assert!(std::fs::metadata(&path).unwrap().len() > 0);

            // Load into fresh instances
            let roundtripped = Matter::new(
                &TEST_DEV_DET,
                TEST_DEV_COMM,
                &TEST_DEV_ATT,
                sys_epoch,
                MATTER_PORT,
            );
            let roundtripped_events = Events::<64>::new(sys_epoch);

            let mut psm2 = Psm::<32768>::new();
            psm2.load(
                &path,
                &roundtripped,
                NO_NETWORKS,
                Some(&roundtripped_events),
            )
            .unwrap();

            // Basic info fields should've been restored
            let basic = roundtripped.basic_info_settings.borrow();
            assert_eq!(basic.node_label, "my-test-node");
            assert_eq!(basic.location.as_deref(), Some("ab"));

            // Events epoch should've been restored and bumped by one epoch
            let events = roundtripped_events.persisted_state.lock(|cell| cell.get());
            assert_eq!(events.next_event_no, 0xDEADBEEF);
            assert_eq!(events.event_epoch_end, 0xDEADBEEF + 0x10000);
        }

        #[test]
        fn test_load_legacy_format() {
            // Generate a "legacy" blob using the old array-based format
            // (anonymous array with positional anonymous octet-strings)
            let source_matter = new_test_matter();
            {
                let mut basic = source_matter.basic_info_settings.borrow_mut();
                basic.node_label = heapless::String::try_from("my-test-node").unwrap();
                basic.location = Some(heapless::String::try_from("ab").unwrap());
            }

            let mut buf = [0u8; 4096];
            let mut wb = crate::utils::storage::WriteBuf::new(&mut buf);
            wb.start_array(&crate::tlv::TLVTag::Anonymous).unwrap();
            wb.str_cb(&crate::tlv::TLVTag::Anonymous, |buf| {
                source_matter.store_fabrics(buf)
            })
            .unwrap();
            wb.str_cb(&crate::tlv::TLVTag::Anonymous, |buf| {
                source_matter.store_basic_info(buf)
            })
            .unwrap();
            wb.end_container().unwrap();
            let tail = wb.get_tail();
            let legacy_blob = &buf[..tail];

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("legacy.bin");
            std::fs::write(&path, legacy_blob).unwrap();

            let matter = Matter::new(
                &TEST_DEV_DET,
                TEST_DEV_COMM,
                &TEST_DEV_ATT,
                sys_epoch,
                MATTER_PORT,
            );

            let mut psm = Psm::<32768>::new();
            psm.load(&path, &matter, NO_NETWORKS, NO_EVENTS).unwrap();

            let basic = matter.basic_info_settings.borrow();
            assert_eq!(basic.node_label, "my-test-node");
            assert_eq!(basic.location.as_deref(), Some("ab"));
        }
    }
}
