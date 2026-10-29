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

//! The networks store of the node: the credentials of the wireless networks
//! it may connect to, and their persistence.

use core::fmt;

use crate::error::{Error, ErrorCode};
use crate::persist::{KvBlobStoreAccess, Persist};
use crate::utils::sync::MaybeSendSync;

/// Wireless credentials used for connecting to a network
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum WirelessCreds<'a> {
    /// WiFi credentials
    Wifi { ssid: &'a [u8], pass: &'a [u8] },
    /// Thread credentials
    Thread { dataset_tlv: &'a [u8] },
}

impl WirelessCreds<'_> {
    /// Return the network ID of the credentials
    /// For Wifi networks, this is the SSID
    /// For Thread networks, this is the extended PAN ID
    pub fn id(&self) -> Result<&[u8], Error> {
        match self {
            WirelessCreds::Wifi { ssid, .. } => Ok(ssid),
            WirelessCreds::Thread { dataset_tlv } => ThreadTLV::new(dataset_tlv).ext_pan_id(),
        }
    }
}

impl fmt::Display for WirelessCreds<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WirelessCreds::Wifi { ssid, .. } => write!(
                f,
                "SSID({})",
                core::str::from_utf8(ssid).ok().unwrap_or("???")
            ),
            WirelessCreds::Thread { dataset_tlv } => write!(
                f,
                "ExtEpanId({:?})",
                ThreadTLV::new(dataset_tlv).ext_pan_id().ok().unwrap_or(&[])
            ),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for WirelessCreds<'_> {
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            WirelessCreds::Wifi { ssid, .. } => defmt::write!(
                fmt,
                "SSID({})",
                core::str::from_utf8(ssid).ok().unwrap_or("???")
            ),
            WirelessCreds::Thread { dataset_tlv } => defmt::write!(
                fmt,
                "ExtEpanId({:?})",
                ThreadTLV::new(dataset_tlv).ext_pan_id().ok().unwrap_or(&[])
            ),
        }
    }
}

/// Network error type for the `Networks` trait
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworksError {
    NetworkIdNotFound,
    DuplicateNetworkId,
    OutOfRange,
    BoundsExceeded,
    Other(Error),
}

impl From<Error> for NetworksError {
    fn from(err: Error) -> Self {
        NetworksError::Other(err)
    }
}

/// Trait for managing networks' credentials storage
pub trait Networks: MaybeSendSync {
    /// Return the maximum number of networks supported by the implementation
    ///
    /// For `NetworkType::Ethernet` this method should always return 1
    fn max_networks(&self) -> Result<u8, Error>;

    /// Iterate over the networks recorded in the implementation and call the provided function for each network
    fn networks(&self, f: &mut dyn FnMut(&[u8]) -> Result<(), Error>) -> Result<(), Error>;

    /// Get the credentials for the given network ID by calling the provided function
    ///
    /// For `NetworkType::Ethernet` this method should always fail with an error.
    ///
    /// The function will be called with the credentials for the network ID, or an error if the network ID is not found.
    ///
    /// Return the index of the network ID if found, or an error if not found.
    fn creds(
        &self,
        network_id: &[u8],
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<u8, NetworksError>;

    /// Return the next credentials after the ones corresponding to the given network ID by calling the provided function
    ///
    /// For `NetworkType::Ethernet` this method should always fail with an error.
    ///
    /// If the network ID is `None` or credentials with the provided network ID cannot be found,
    /// the first credentials will be returned.
    ///
    /// If the credentials corresponding to the network ID are the last ones recorded in the `Netwrks` trait implementation,
    /// the method will wrap-over and will return the first credentials or even the same credentials again if there is only one
    /// recorded network.
    ///
    /// Return `true` if the credentials were found, `false` otherwise.
    fn next_creds(
        &self,
        last_network_id: Option<&[u8]>,
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<bool, Error>;

    /// Return whether the network interface is enabled
    fn enabled(&self) -> Result<bool, Error>;

    /// Set the network interface enabled or disabled
    fn set_enabled(&mut self, enabled: bool) -> Result<(), Error>;

    /// Add or update the credentials for the given network ID
    ///
    /// For `NetworkType::Ethernet` this method should always fail with an error.
    ///
    /// The network ID is derived from the credentials.
    ///
    /// Return the index of the network ID if it was added or updated, or an error if the operation failed.
    fn add_or_update(&mut self, creds: &WirelessCreds<'_>) -> Result<u8, NetworksError>;

    /// Reorder the network with the given index
    ///
    /// For `NetworkType::Ethernet` this method should always fail with an error.
    ///
    /// The index is the new index of the network ID.
    ///
    /// Return the index of the network ID if it was reordered, or an error if the operation failed.
    fn reorder(&mut self, index: u8, network_id: &[u8]) -> Result<u8, NetworksError>;

    /// Remove the network with the given network ID
    ///
    /// For `NetworkType::Ethernet` this method should always fail with an error.
    ///
    /// Return the index of the network ID if it was removed, or an error if the operation failed.
    fn remove(&mut self, network_id: &[u8]) -> Result<u8, NetworksError>;

    /// Return whether the networks store is in "managed" state.
    ///
    /// Managed means: the store holds *committed* operational network
    /// configuration, and the operational connectivity manager
    /// (`WirelessMgr`) may act on it. The store starts unmanaged (never
    /// commissioned, empty), and temporarily *becomes* unmanaged again while
    /// network changes are staged under an armed fail-safe (any successful
    /// `AddOrUpdate*Network` / `RemoveNetwork` / `ReorderNetwork` /
    /// `ConnectNetwork` flips it to `false`) - during such a window the
    /// commissioner drives connectivity explicitly, and the manager must
    /// stand down.
    ///
    /// The state comes back to managed on either exit from the window:
    /// - commit: `CommissioningComplete` calls `set_managed(true)` and
    ///   persists the store;
    /// - revert: the fail-safe expiry reloads the persisted store, which
    ///   always carries the committed - hence managed - state.
    ///
    /// Note that a window which stages no network changes (e.g. opened only
    /// to commission an additional fabric) leaves the store managed, so
    /// connectivity maintenance of the operational network continues
    /// throughout - matching CHIP's behavior.
    fn managed(&self) -> Result<bool, Error>;

    /// Set the managed state of the networks store (see `managed`).
    fn set_managed(&mut self, managed: bool) -> Result<(), Error>;

    /// Reset the networks to the initial state, removing all recorded network credentials
    fn reset(&mut self) -> Result<(), Error>;

    /// Load the networks' credentials from the given data
    fn load(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Save the networks' credentials into the given buffer and return the number of bytes written
    /// or `None` if the networks do not need persistence.
    fn save(&self, buf: &mut [u8]) -> Result<Option<usize>, Error>;
}

impl<T> Networks for &mut T
where
    T: Networks,
{
    fn max_networks(&self) -> Result<u8, Error> {
        (**self).max_networks()
    }

    fn networks(&self, f: &mut dyn FnMut(&[u8]) -> Result<(), Error>) -> Result<(), Error> {
        (**self).networks(f)
    }

    fn creds(
        &self,
        network_id: &[u8],
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<u8, NetworksError> {
        (**self).creds(network_id, f)
    }

    fn next_creds(
        &self,
        last_network_id: Option<&[u8]>,
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        (**self).next_creds(last_network_id, f)
    }

    fn enabled(&self) -> Result<bool, Error> {
        (**self).enabled()
    }

    fn set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        (*self).set_enabled(enabled)
    }

    fn add_or_update(&mut self, creds: &WirelessCreds<'_>) -> Result<u8, NetworksError> {
        (*self).add_or_update(creds)
    }

    fn reorder(&mut self, index: u8, network_id: &[u8]) -> Result<u8, NetworksError> {
        (*self).reorder(index, network_id)
    }

    fn remove(&mut self, network_id: &[u8]) -> Result<u8, NetworksError> {
        (*self).remove(network_id)
    }

    fn managed(&self) -> Result<bool, Error> {
        (**self).managed()
    }

    fn set_managed(&mut self, managed: bool) -> Result<(), Error> {
        (**self).set_managed(managed)
    }

    fn reset(&mut self) -> Result<(), Error> {
        (**self).reset()
    }

    fn load(&mut self, data: &[u8]) -> Result<(), Error> {
        (**self).load(data)
    }

    fn save(&self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        (**self).save(buf)
    }
}

impl Networks for &mut dyn Networks {
    fn max_networks(&self) -> Result<u8, Error> {
        (**self).max_networks()
    }

    fn networks(&self, f: &mut dyn FnMut(&[u8]) -> Result<(), Error>) -> Result<(), Error> {
        (**self).networks(f)
    }

    fn creds(
        &self,
        network_id: &[u8],
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<u8, NetworksError> {
        (**self).creds(network_id, f)
    }

    fn next_creds(
        &self,
        last_network_id: Option<&[u8]>,
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        (**self).next_creds(last_network_id, f)
    }

    fn enabled(&self) -> Result<bool, Error> {
        (**self).enabled()
    }

    fn set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        (**self).set_enabled(enabled)
    }

    fn add_or_update(&mut self, creds: &WirelessCreds<'_>) -> Result<u8, NetworksError> {
        (**self).add_or_update(creds)
    }

    fn reorder(&mut self, index: u8, network_id: &[u8]) -> Result<u8, NetworksError> {
        (**self).reorder(index, network_id)
    }

    fn remove(&mut self, network_id: &[u8]) -> Result<u8, NetworksError> {
        (**self).remove(network_id)
    }

    fn managed(&self) -> Result<bool, Error> {
        (**self).managed()
    }

    fn set_managed(&mut self, managed: bool) -> Result<(), Error> {
        (**self).set_managed(managed)
    }

    fn reset(&mut self) -> Result<(), Error> {
        (**self).reset()
    }

    fn load(&mut self, data: &[u8]) -> Result<(), Error> {
        (**self).load(data)
    }

    fn save(&self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        (**self).save(buf)
    }
}

/// A `Networks` implementation with no networks, which refuses to record any.
pub struct DummyNetworks;

impl Networks for DummyNetworks {
    fn max_networks(&self) -> Result<u8, Error> {
        Ok(0)
    }

    fn networks(&self, _f: &mut dyn FnMut(&[u8]) -> Result<(), Error>) -> Result<(), Error> {
        Ok(())
    }

    fn creds(
        &self,
        _network_id: &[u8],
        _f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<u8, NetworksError> {
        Err(NetworksError::NetworkIdNotFound)
    }

    fn next_creds(
        &self,
        _last_network_id: Option<&[u8]>,
        _f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        Ok(false)
    }

    fn enabled(&self) -> Result<bool, Error> {
        Ok(false)
    }

    fn set_enabled(&mut self, _enabled: bool) -> Result<(), Error> {
        Ok(())
    }

    fn add_or_update(&mut self, _creds: &WirelessCreds<'_>) -> Result<u8, NetworksError> {
        Err(NetworksError::Other(ErrorCode::InvalidAction.into()))
    }

    fn reorder(&mut self, _index: u8, _network_id: &[u8]) -> Result<u8, NetworksError> {
        Err(NetworksError::Other(ErrorCode::InvalidAction.into()))
    }

    fn remove(&mut self, _network_id: &[u8]) -> Result<u8, NetworksError> {
        Err(NetworksError::Other(ErrorCode::InvalidAction.into()))
    }

    fn managed(&self) -> Result<bool, Error> {
        Ok(false)
    }

    fn set_managed(&mut self, _managed: bool) -> Result<(), Error> {
        Ok(())
    }

    fn reset(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn load(&mut self, _data: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn save(&self, _buf: &mut [u8]) -> Result<Option<usize>, Error> {
        Ok(None)
    }
}

/// Reload the committed networks of `networks` from `kv`, where they are
/// persisted under `key`; reset the store if nothing is persisted, or if what
/// is cannot be loaded.
pub fn load_networks<N, K>(mut networks: N, key: u16, kv: K) -> Result<(), Error>
where
    N: Networks,
    K: KvBlobStoreAccess,
{
    let loaded = Persist::new(kv).load(key, |data| networks.load(data))?;

    // A load that failed may have stopped half-way
    match loaded {
        Some(()) => Ok(()),
        None => networks.reset(),
    }
}

/// Persist `networks` into `kv`, under `key`.
pub fn store_networks<N, K>(networks: N, key: u16, kv: K) -> Result<(), Error>
where
    N: Networks,
    K: KvBlobStoreAccess,
{
    let mut persist = Persist::new(kv);

    persist.store(key, |buf| networks.save(buf))?;

    persist.run()
}

/// Reset `networks` and remove what is persisted for it in `kv`, under `key`.
pub fn remove_networks<N, K>(mut networks: N, key: u16, kv: K) -> Result<(), Error>
where
    N: Networks,
    K: KvBlobStoreAccess,
{
    networks.reset()?;

    // Strict, as credentials surviving a factory reset must not go unreported
    let mut persist = Persist::strict(kv);

    persist.remove(key)?;

    persist.run()
}

/// A simple Thread TLV reader
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ThreadTLV<'a>(&'a [u8]);

impl<'a> ThreadTLV<'a> {
    /// Create a new `ThreadTLV` instance with the given TLV data
    pub const fn new(tlv: &'a [u8]) -> Self {
        Self(tlv)
    }

    /// Get the Extended PAN ID from the operational dataset
    pub fn ext_pan_id(&mut self) -> Result<&'a [u8], Error> {
        const EXT_PAN_ID: u8 = 2;

        let ext_pan_id =
            self.find_map(|(tlv_type, tlv_value)| (tlv_type == EXT_PAN_ID).then_some(tlv_value));

        let Some(ext_pan_id) = ext_pan_id else {
            return Err(ErrorCode::InvalidData.into());
        };

        Ok(ext_pan_id)
    }

    /// Get the next TLV from the data
    ///
    /// Returns `Some` with the TLV type and value if there is a TLV available,
    /// otherwise returns `None`.
    pub fn next_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        const LONG_VALUE_ID: u8 = 255;

        // Adopted from here:
        // https://github.com/openthread/openthread/blob/main/tools/tcat_ble_client/tlv/tlv.py

        let mut slice = self.0;

        (slice.len() >= 2).then_some(())?;

        let tlv_type = slice[0];
        slice = &slice[1..];

        let tlv_len_size = if slice[0] == LONG_VALUE_ID {
            slice = &slice[1..];
            3
        } else {
            1
        };

        (slice.len() >= tlv_len_size).then_some(())?;

        let tlv_len = if tlv_len_size == 1 {
            slice[0] as usize
        } else {
            u32::from_be_bytes([0, slice[0], slice[1], slice[2]]) as usize
        };

        slice = &slice[tlv_len_size..];
        (slice.len() >= tlv_len).then_some(())?;

        let tlv_value = &slice[..tlv_len];

        slice = &slice[tlv_len..];

        self.0 = slice;

        Some((tlv_type, tlv_value))
    }
}

impl<'a> Iterator for ThreadTLV<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        self.next_tlv()
    }
}
