/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

//! A module containing various types for managing Thread and Wifi networks.

use core::fmt::{Debug, Display};

use crate::dm::clusters::net_comm::{
    self, NetCtlError, NetworkCommissioningStatusEnum, NetworkType, Networks, NetworksError,
    ThreadCapabilitiesBitmap, WirelessCreds,
};
use crate::dm::clusters::{thread_diag, wifi_diag};
use crate::error::{Error, ErrorCode};
use crate::fmt::Bytes;
use crate::persist::{KvBlobStore, NETWORKS_KEY};
use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV};
use crate::transport::network::btp::Btp;
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::{Vec, WriteBuf};
use crate::utils::sync::blocking;
use crate::utils::sync::DynBase;

use super::NetChangeNotif;

pub use mgr::*;
pub use thread::*;
pub use wifi::*;

mod mgr;
mod thread;
mod wifi;

/// The maximum length of a wireless network ID.
/// Coincides with the SSID maximum length because
pub const MAX_WIRELESS_NETWORK_ID_LEN: usize = 32;

/// A type alias for representing an owned ID of a wireless (Thread or Wifi) network.
/// Both Thread and Wifi networks use the same ID type which is just an octet string.
///
/// For Thread networks, this is the Extended PAN ID (`u64` as 8 bytes, network order).
/// For Wifi networks, this is the SSID (`u8` array of max length 32 bytes).
pub type OwnedWirelessNetworkId = Vec<u8, MAX_WIRELESS_NETWORK_ID_LEN>;

/// A trait representing the credentials of a wireless network (Wifi or Thread).
///
/// The trait has only two implementations: `Wifi` and `Thread`.
pub trait WirelessNetwork: Send + for<'a> FromTLV<'a> + ToTLV {
    /// Return the network ID
    ///
    /// For Wifi networks, this is the SSID
    /// For Thread networks, this is the Extended PAN ID (`u64` as 8 bytes, network order)
    fn id(&self) -> &[u8];

    /// Return an in-place initializer for the type
    ///
    /// # Arguments
    /// - `creds`: The credentials of the network with which to initialize the type
    fn init_from<'a>(creds: &'a WirelessCreds<'a>) -> impl Init<Self, Error> + 'a;

    /// Update the credentials of the network
    ///
    /// # Arguments
    /// - `creds`: The new credentials to set
    fn update(&mut self, creds: &WirelessCreds<'_>) -> Result<(), Error>;

    /// Return the credentials of the network
    fn creds(&self) -> WirelessCreds<'_>;

    /// Return a displayable representation of the network
    #[cfg(not(feature = "defmt"))]
    fn display(&self) -> impl Display {
        Self::display_id(self.id())
    }

    /// Return a displayable representation of the network
    #[cfg(feature = "defmt")]
    fn display(&self) -> impl Display + defmt::Format {
        Self::display_id(self.id())
    }

    /// Return a displayable representation of the provided network ID
    #[cfg(not(feature = "defmt"))]
    fn display_id(id: &[u8]) -> impl Display;

    /// Return a displayable representation of the provided network ID
    #[cfg(feature = "defmt")]
    fn display_id(id: &[u8]) -> impl Display + defmt::Format;
}

/// A fixed-size storage for wireless networks credentials.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct WirelessNetworks<const N: usize, T> {
    networks: crate::utils::storage::Vec<T, N>,
    commissioned: bool,
}

impl<const N: usize, T> Default for WirelessNetworks<N, T>
where
    T: WirelessNetwork,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, T> WirelessNetworks<N, T>
where
    T: WirelessNetwork,
{
    pub const fn new() -> Self {
        Self {
            networks: crate::utils::storage::Vec::new(),
            commissioned: false,
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            networks <- crate::utils::storage::Vec::init(),
            commissioned: false,
        })
    }

    /// Reset the state
    pub fn reset(&mut self) {
        self.networks.clear();
        self.commissioned = false;
    }

    /// Remove all networks from the provided BLOB store and from memory
    ///
    /// # Arguments
    /// - `store`: the BLOB store to remove the networks from
    /// - `buf`: a temporary buffer to use for removing the networks
    pub async fn reset_persist<S: KvBlobStore>(
        &mut self,
        mut kv: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.reset();

        kv.remove(NETWORKS_KEY, buf)?;

        info!("Removed all wireless networks from storage");

        Ok(())
    }

    /// Load all networks from the provided BLOB store
    ///
    /// # Arguments
    /// - `store`: the BLOB store to load the networks from
    /// - `buf`: a temporary buffer to use for loading the networks
    pub async fn load_persist<S: KvBlobStore>(
        &mut self,
        mut kv: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.reset();

        if let Some(data) = kv.load(NETWORKS_KEY, buf)? {
            self.load(data)?;

            info!(
                "Loaded {} wireless networks from storage",
                self.networks.len()
            );
        }

        Ok(())
    }

    /// Load the state from a byte slice.
    ///
    /// # Arguments
    /// - `data`: The byte slice to load the state from
    pub fn load(&mut self, data: &[u8]) -> Result<(), Error> {
        let root = TLVElement::new(data);

        self.networks.clear();

        // Try new format: struct { ctx(0): networks array, ctx(1): commissioned bool }
        // Fall back to old format: bare TLV array (with commissioned defaulting to false)
        if let Ok(structure) = root.structure() {
            for network in structure.ctx(0)?.array()?.iter() {
                let network = network?;

                self.networks.push_init(T::init_from_tlv(network), || {
                    ErrorCode::ResourceExhausted.into()
                })?;
            }

            self.commissioned = structure.ctx(1)?.bool()?;
        } else {
            for network in root.array()?.iter() {
                let network = network?;

                self.networks.push_init(T::init_from_tlv(network), || {
                    ErrorCode::ResourceExhausted.into()
                })?;
            }

            self.commissioned = false;
        }

        Ok(())
    }

    /// Store the state into a byte slice.
    ///
    /// # Arguments
    /// - `buf`: The byte slice to store the state into
    ///
    /// Returns the number of bytes written into the buffer.
    pub fn store(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut wb = WriteBuf::new(buf);

        wb.start_struct(&TLVTag::Anonymous)?;

        self.networks.to_tlv(&TLVTag::Context(0), &mut wb)?;
        self.commissioned.to_tlv(&TLVTag::Context(1), &mut wb)?;

        wb.end_container()?;

        let tail = wb.get_tail();

        Ok(tail)
    }

    /// Iterate over the registered network credentials
    ///
    /// # Arguments
    /// - `f`: A closure that will be called for each network registered in the storage
    pub fn networks<F>(&self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(&T) -> Result<(), Error>,
    {
        for network in self.networks.iter() {
            f(network)?;
        }

        Ok(())
    }

    /// Get the credentials of a network by its ID
    ///
    /// # Arguments
    /// - `network_id`: The ID of the network to get
    /// - `f`: A closure that will be called with the credentials of the network, if the network exists
    ///
    /// Returns the index of the network in the storage if the network exists, `NetworkError::NetworkIdNotFound` otherwise
    pub fn network<F>(&self, network_id: &[u8], f: F) -> Result<u8, NetworksError>
    where
        F: FnOnce(&T) -> Result<(), Error>,
    {
        let networks = self
            .networks
            .iter()
            .enumerate()
            .find(|(_, network)| network.id() == network_id);

        if let Some((index, network)) = networks {
            f(network)?;

            Ok(index as _)
        } else {
            Err(NetworksError::NetworkIdNotFound)
        }
    }

    /// Get the next network credentials after the one with the given ID
    ///
    /// # Arguments
    /// - `after_network_id`: The ID of the network to get the next one after.
    ///   If no network with the provided network ID exists, the first network in the storage will be returned.
    pub fn next_network<F>(&self, last_network_id: Option<&[u8]>, f: F) -> Result<bool, Error>
    where
        F: FnOnce(&T) -> Result<(), Error>,
    {
        if let Some(last_network_id) = last_network_id {
            info!(
                "Looking for network after the one with ID: {}",
                T::display_id(last_network_id)
            );

            // Return the network positioned after the last one used

            let mut networks = self.networks.iter();

            for network in &mut networks {
                if network.id() == last_network_id {
                    break;
                }
            }

            let network = networks.next();
            if let Some(network) = network {
                info!("Trying with next network - ID: {}", network.display());

                f(network)?;
                return Ok(true);
            }
        }

        // Wrap over
        info!("Wrapping over");

        if let Some(network) = self.networks.first() {
            info!("Trying with first network - ID: {}", network.display());

            f(network)?;
            Ok(true)
        } else {
            info!("No networks available");
            Ok(false)
        }
    }

    /// Add or update a network in the storage
    ///
    /// # Arguments
    /// - `network_id`: The ID of the network to add or update
    /// - `add`: An in-place initializer for the network to add. The initializer will be used only if a network with the provided
    ///   network ID does not exist in the storage
    /// - `update`: A closure that will be called with the network to update. The closure will be called only if a network with the provided
    ///   network ID exists in the storage
    pub fn add_or_update<A, U>(
        &mut self,
        network_id: &[u8],
        add: A,
        update: U,
    ) -> Result<u8, NetworksError>
    where
        A: Init<T, Error>,
        U: FnOnce(&mut T) -> Result<(), Error>,
    {
        let unetwork = self
            .networks
            .iter_mut()
            .enumerate()
            .find(|(_, unetwork)| unetwork.id() == network_id);

        if let Some((index, unetwork)) = unetwork {
            // Update
            update(unetwork)?;

            info!("Updated network with ID {}", unetwork.display());

            Ok(index as _)
        } else if self.networks.len() >= N {
            warn!(
                "Adding network with ID {} failed: too many",
                T::display_id(network_id)
            );

            Err(NetworksError::BoundsExceeded)
        } else {
            // Add
            self.networks
                .push_init(add, || ErrorCode::ResourceExhausted.into())?;

            info!("Added network with ID {}", T::display_id(network_id));

            Ok((self.networks.len() - 1) as _)
        }
    }

    /// Reorder a network in the storage
    ///
    /// # Arguments
    /// - `index`: The new index of the network
    /// - `network_id`: The ID of the network to reorder
    ///
    /// Returns the new index of the network in the storage, if a network with the provided ID exists
    /// or `NetworkError::NetworkIdNotFound` otherwise
    pub fn reorder(&mut self, index: u8, network_id: &[u8]) -> Result<u8, NetworksError> {
        let cur_index = self
            .networks
            .iter()
            .position(|conf| conf.id() == network_id);

        if let Some(cur_index) = cur_index {
            // Found

            if index < self.networks.len() as u8 {
                let conf = self.networks.remove(cur_index);
                unwrap!(self.networks.insert(index as usize, conf).map_err(|_| ()));

                info!(
                    "Network with ID {} reordered to index {}",
                    T::display_id(network_id),
                    index
                );
            } else {
                warn!(
                    "Reordering network with ID {} to index {} failed: out of range",
                    T::display_id(network_id),
                    index
                );

                Err(NetworksError::OutOfRange)?;
            }
        } else {
            warn!("Network with ID {} not found", T::display_id(network_id));
            Err(NetworksError::NetworkIdNotFound)?;
        }

        Ok(index)
    }

    /// Remove a network from the storage
    ///
    /// # Arguments
    /// - `network_id`: The ID of the network to remove
    ///
    /// Returns the index of the network in the storage if the network exists and was removed, `NetworkError::NetworkIdNotFound` otherwise
    pub fn remove(&mut self, network_id: &[u8]) -> Result<u8, NetworksError> {
        let index = self
            .networks
            .iter()
            .position(|conf| conf.id() == network_id);

        if let Some(index) = index {
            // Found
            self.networks.remove(index);

            info!("Removed network with ID {}", T::display_id(network_id));

            Ok(index as _)
        } else {
            warn!("Network with ID {} not found", T::display_id(network_id));

            Err(NetworksError::NetworkIdNotFound)
        }
    }

    pub fn commissioned(&self) -> bool {
        self.commissioned
    }

    pub fn set_commissioned(&mut self, commissioned: bool) {
        self.commissioned = commissioned;
    }
}

impl<const N: usize, T> Networks for WirelessNetworks<N, T>
where
    T: WirelessNetwork,
{
    fn max_networks(&self) -> Result<u8, Error> {
        Ok(N as _)
    }

    fn networks(
        &self,
        f: &mut dyn FnMut(&net_comm::NetworkInfo) -> Result<(), Error>,
    ) -> Result<(), Error> {
        WirelessNetworks::networks(self, |network| {
            let network_id = network.id();

            let network_info = net_comm::NetworkInfo {
                network_id,
                connected: false, // TODO
            };

            f(&network_info)
        })
    }

    fn creds(
        &self,
        network_id: &[u8],
        f: &mut dyn FnMut(&net_comm::WirelessCreds) -> Result<(), Error>,
    ) -> Result<u8, NetworksError> {
        WirelessNetworks::network(self, network_id, |network| f(&network.creds()))
    }

    fn next_creds(
        &self,
        last_network_id: Option<&[u8]>,
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        WirelessNetworks::next_network(self, last_network_id, |network| f(&network.creds()))
    }

    fn enabled(&self) -> Result<bool, Error> {
        Ok(true)
    }

    fn set_enabled(&mut self, _enabled: bool) -> Result<(), Error> {
        Ok(())
    }

    fn add_or_update(
        &mut self,
        creds: &net_comm::WirelessCreds<'_>,
    ) -> Result<u8, net_comm::NetworksError> {
        WirelessNetworks::add_or_update(self, creds.id()?, T::init_from(creds), |network| {
            network.update(creds)
        })
    }

    fn reorder(&mut self, index: u8, network_id: &[u8]) -> Result<u8, NetworksError> {
        WirelessNetworks::reorder(self, index, network_id)
    }

    fn remove(&mut self, network_id: &[u8]) -> Result<u8, NetworksError> {
        WirelessNetworks::remove(self, network_id)
    }

    fn commissioned(&self) -> Result<bool, Error> {
        Ok(self.commissioned())
    }

    fn set_commissioned(&mut self, commissioned: bool) -> Result<(), Error> {
        WirelessNetworks::set_commissioned(self, commissioned);

        Ok(())
    }

    fn reset(&mut self) -> Result<(), Error> {
        WirelessNetworks::reset(self);

        Ok(())
    }

    fn load(&mut self, data: &[u8]) -> Result<(), Error> {
        WirelessNetworks::load(self, data)
    }

    fn save(&self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        WirelessNetworks::store(self, buf).map(Some)
    }
}

/// An enum capable of displaying a network ID in a human-readable format.
#[derive(Debug)]
enum DisplayId<'a> {
    Wifi(&'a [u8]),
    Thread(&'a [u8]),
}

impl Display for DisplayId<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DisplayId::Wifi(id) => {
                if let Ok(str) = core::str::from_utf8(id) {
                    write!(f, "Wifi SSID({})", str)
                } else {
                    write!(f, "Wifi SSID({:?})", Bytes(id))
                }
            }
            DisplayId::Thread(id) => write!(f, "Thread ExtPanID({:?})", Bytes(id)),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for DisplayId<'_> {
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            DisplayId::Wifi(id) => {
                if let Ok(str) = core::str::from_utf8(id) {
                    defmt::write!(fmt, "Wifi SSID({})", str)
                } else {
                    defmt::write!(fmt, "Wifi SSID({:?})", Bytes(id))
                }
            }
            DisplayId::Thread(id) => defmt::write!(fmt, "Thread ExtPanID({:?})", Bytes(id)),
        }
    }
}

/// A no-op implementation of the `net_comm::NetCtl` trait suitable when non-concurrent provisioning over BTP is used.
///
/// This implementation will throw `NetworkError::Other(ErrorCode::InvalidAction)` for the `scan` method
/// and will silently return `Ok(())` for the `connect` method, which is meeting the non-concurrent provisioning expectations.
pub struct NoopWirelessNetCtl(NetworkType);

impl NoopWirelessNetCtl {
    /// Create a new instance of `NoopWirelessNetCtl` for the provided network type.
    ///
    /// Note that it does not make any sense to use `NetworkType::Ethernet` here, as the Ethernet
    /// network controller should return errors for both `scan` and `connect` methods.
    ///
    /// For Ethernet networks, use `EthNetctl` instead.
    pub const fn new(net_type: NetworkType) -> Self {
        Self(net_type)
    }
}

impl net_comm::NetCtl for NoopWirelessNetCtl {
    fn net_type(&self) -> NetworkType {
        self.0
    }

    async fn scan<F>(&self, _network: Option<&[u8]>, _f: F) -> Result<(), NetCtlError>
    where
        F: FnOnce(&net_comm::NetworkScanInfo) -> Result<(), Error>,
    {
        Err(NetCtlError::Other(ErrorCode::InvalidAction.into()))
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        Ok(creds.check_match(self.0)?)
    }
}

impl NetChangeNotif for NoopWirelessNetCtl {
    async fn wait_changed(&self) {
        core::future::pending().await
    }
}

impl DynBase for NoopWirelessNetCtl {}

impl wifi_diag::WirelessDiag for NoopWirelessNetCtl {}

impl wifi_diag::WifiDiag for NoopWirelessNetCtl {}

impl thread_diag::ThreadDiag for NoopWirelessNetCtl {}

/// A type holding the status of the last `connect` or `scan` operation for the `NetCtlWithStatus` `NetCtl` + `NetCtlStatus` implementation.
pub struct NetCtlState {
    /// The network ID used in the last scan or connect operation
    pub network_id: OwnedWirelessNetworkId,
    /// The status of the last scan or connect operation
    pub networking_status: Option<NetworkCommissioningStatusEnum>,
    /// The error code of the last scan or connect operation.
    /// If the last operation was scan, this value is `None`.
    pub connect_error_value: Option<i32>,
}

impl NetCtlState {
    /// Create a new, empty instance of `NetCtlState`.
    pub const fn new() -> Self {
        Self {
            network_id: OwnedWirelessNetworkId::new(),
            networking_status: None,
            connect_error_value: None,
        }
    }

    /// Return an in-place initializer for a new, empty `NetCtlState`.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            network_id <- OwnedWirelessNetworkId::init(),
            networking_status: None,
            connect_error_value: None,
        })
    }

    /// Create a new, empty instance of `NetCtlState` wrapped in a mutex.
    pub const fn new_with_mutex() -> NetCtlStateMutex {
        blocking::Mutex::new(RefCell::new(Self::new()))
    }

    /// Return an in-place initializer for a new, empty `NetCtlState` wrapped in a mutex.
    pub fn init_with_mutex() -> impl Init<NetCtlStateMutex> {
        blocking::Mutex::init(RefCell::init(init!(Self {
            network_id <- OwnedWirelessNetworkId::init(),
            networking_status: None,
            connect_error_value: None,
        })))
    }

    /// Return `true` if the network ID is set and the last operation was successful.
    pub fn is_prov_ready(&self) -> bool {
        !self.network_id.is_empty()
            && matches!(
                self.networking_status,
                Some(NetworkCommissioningStatusEnum::Success)
            )
            && self.connect_error_value.is_none()
    }

    /// Update the state with the provided network ID and result of the last operation.
    ///
    /// Return the result of the last operation.
    pub fn update<R>(
        &mut self,
        network_id: Option<&[u8]>,
        result: Result<R, NetCtlError>,
    ) -> Result<R, NetCtlError> {
        self.network_id.clear();

        if let Some(network_id) = network_id {
            unwrap!(self.network_id.extend_from_slice(network_id));
        }

        if let Some((status, err_code)) = NetworkCommissioningStatusEnum::map_ctl_status(&result) {
            self.networking_status = Some(status);
            self.connect_error_value = err_code;
        } else {
            self.networking_status = None;
            self.connect_error_value = None;
        }

        result
    }

    /// Update the state with the provided network ID and result of the last operation.
    ///
    /// Return the result of the last operation.
    pub fn update_with_mutex<R>(
        state: &NetCtlStateMutex,
        network_id: Option<&[u8]>,
        result: Result<R, NetCtlError>,
    ) -> Result<R, NetCtlError> {
        state.lock(|state| state.borrow_mut().update(network_id, result))
    }

    /// A utility to wait for provisioning over BTP to be ready.
    /// Provisioning over BTP is considered complete when there is no longer an active connection
    /// and the network ID is set (i.e. method `NetCtl::connect` was called successfully).
    ///
    /// This method is only useful for non-concurrent commisioning using wireless networks and BLE,
    /// and is likely to be used together with `NoopWirelessNetCtl`.
    pub async fn wait_prov_ready(state: &NetCtlStateMutex, _btp: &Btp) {
        while !state.lock(|state| state.borrow().is_prov_ready()) {
            // Provisioning over BTP is considered complete when there is no longer an active connection
            // and the network ID is set (i.e. method `NetCtl::connect` was called successfully)

            embassy_time::Timer::after_secs(1).await;
        }
    }
}

impl Default for NetCtlState {
    fn default() -> Self {
        Self::new()
    }
}

/// A type alias for a `NetCtlState` instance wrapped in a mutex.
pub type NetCtlStateMutex = blocking::Mutex<RefCell<NetCtlState>>;

/// A wrapper around a `NetCtl` network controller that additionally implements the `NetCtlStatus`trait.
pub struct NetCtlWithStatusImpl<'a, T> {
    state: &'a NetCtlStateMutex,
    net_ctl: T,
}

impl<'a, T> NetCtlWithStatusImpl<'a, T> {
    /// Create a new instance of `NetCtlWithStatusImpl`.
    ///
    /// # Arguments
    /// - `state`: A reference to a `NetCtlState` instance wrapped in a mutex
    /// - `net_ctl`: A network controller that implements the `NetCtl` trait
    pub const fn new(state: &'a NetCtlStateMutex, net_ctl: T) -> Self {
        Self { state, net_ctl }
    }
}

impl<T> net_comm::NetCtl for NetCtlWithStatusImpl<'_, T>
where
    T: net_comm::NetCtl,
{
    fn net_type(&self) -> NetworkType {
        self.net_ctl.net_type()
    }

    fn connect_max_time_seconds(&self) -> u8 {
        self.net_ctl.connect_max_time_seconds()
    }

    fn scan_max_time_seconds(&self) -> u8 {
        self.net_ctl.scan_max_time_seconds()
    }

    fn supported_wifi_bands<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnMut(net_comm::WiFiBandEnum) -> Result<(), Error>,
    {
        self.net_ctl.supported_wifi_bands(f)
    }

    fn supported_thread_features(&self) -> ThreadCapabilitiesBitmap {
        self.net_ctl.supported_thread_features()
    }

    fn thread_version(&self) -> u16 {
        self.net_ctl.thread_version()
    }

    async fn scan<F>(&self, network: Option<&[u8]>, f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&net_comm::NetworkScanInfo) -> Result<(), Error>,
    {
        self.net_ctl.scan(network, f).await
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        NetCtlState::update_with_mutex(
            self.state,
            Some(creds.id()?),
            self.net_ctl.connect(creds).await,
        )
    }
}

impl<T> net_comm::NetCtlStatus for NetCtlWithStatusImpl<'_, T>
where
    T: net_comm::NetCtl,
{
    fn last_networking_status(&self) -> Result<Option<NetworkCommissioningStatusEnum>, Error> {
        Ok(self.state.lock(|state| state.borrow().networking_status))
    }

    fn last_network_id<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(Option<&[u8]>) -> Result<R, Error>,
    {
        self.state.lock(|state| {
            let state = state.borrow();

            if state.network_id.is_empty() {
                f(None)
            } else {
                f(Some(&state.network_id))
            }
        })
    }

    fn last_connect_error_value(&self) -> Result<Option<i32>, Error> {
        Ok(self.state.lock(|state| state.borrow().connect_error_value))
    }
}

impl<T> NetChangeNotif for NetCtlWithStatusImpl<'_, T>
where
    T: NetChangeNotif,
{
    async fn wait_changed(&self) {
        self.net_ctl.wait_changed().await
    }
}

#[cfg(feature = "sync-mutex")]
impl<T> DynBase for NetCtlWithStatusImpl<'_, T> where T: Send + Sync {}

#[cfg(not(feature = "sync-mutex"))]
impl<T> DynBase for NetCtlWithStatusImpl<'_, T> {}

impl<T> wifi_diag::WirelessDiag for NetCtlWithStatusImpl<'_, T>
where
    T: wifi_diag::WirelessDiag,
{
    fn connected(&self) -> Result<bool, Error> {
        self.net_ctl.connected()
    }
}

impl<T> wifi_diag::WifiDiag for NetCtlWithStatusImpl<'_, T>
where
    T: wifi_diag::WifiDiag,
{
    fn bssid(&self, f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>) -> Result<(), Error> {
        self.net_ctl.bssid(f)
    }

    fn security_type(&self) -> Result<crate::tlv::Nullable<wifi_diag::SecurityTypeEnum>, Error> {
        self.net_ctl.security_type()
    }

    fn wi_fi_version(&self) -> Result<crate::tlv::Nullable<wifi_diag::WiFiVersionEnum>, Error> {
        self.net_ctl.wi_fi_version()
    }

    fn channel_number(&self) -> Result<crate::tlv::Nullable<u16>, Error> {
        self.net_ctl.channel_number()
    }

    fn rssi(&self) -> Result<crate::tlv::Nullable<i8>, Error> {
        self.net_ctl.rssi()
    }
}

impl<T> thread_diag::ThreadDiag for NetCtlWithStatusImpl<'_, T>
where
    T: thread_diag::ThreadDiag,
{
    fn channel(&self) -> Result<Option<u16>, Error> {
        self.net_ctl.channel()
    }

    fn routing_role(&self) -> Result<Option<thread_diag::RoutingRoleEnum>, Error> {
        self.net_ctl.routing_role()
    }

    fn network_name(
        &self,
        f: &mut dyn FnMut(Option<&str>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.net_ctl.network_name(f)
    }

    fn pan_id(&self) -> Result<Option<u16>, Error> {
        self.net_ctl.pan_id()
    }

    fn extended_pan_id(&self) -> Result<Option<u64>, Error> {
        self.net_ctl.extended_pan_id()
    }

    fn mesh_local_prefix(
        &self,
        f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.net_ctl.mesh_local_prefix(f)
    }

    fn neighbor_table(
        &self,
        f: &mut dyn FnMut(&thread_diag::NeighborTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.net_ctl.neighbor_table(f)
    }

    fn route_table(
        &self,
        f: &mut dyn FnMut(&thread_diag::RouteTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.net_ctl.route_table(f)
    }

    fn partition_id(&self) -> Result<Option<u32>, Error> {
        self.net_ctl.partition_id()
    }

    fn weighting(&self) -> Result<Option<u16>, Error> {
        self.net_ctl.weighting()
    }

    fn data_version(&self) -> Result<Option<u16>, Error> {
        self.net_ctl.data_version()
    }

    fn stable_data_version(&self) -> Result<Option<u16>, Error> {
        self.net_ctl.stable_data_version()
    }

    fn leader_router_id(&self) -> Result<Option<u8>, Error> {
        self.net_ctl.leader_router_id()
    }

    fn security_policy(&self) -> Result<Option<thread_diag::SecurityPolicy>, Error> {
        self.net_ctl.security_policy()
    }

    fn channel_page0_mask(
        &self,
        f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.net_ctl.channel_page0_mask(f)
    }

    fn operational_dataset_components(
        &self,
        f: &mut dyn FnMut(Option<&thread_diag::OperationalDatasetComponents>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.net_ctl.operational_dataset_components(f)
    }

    fn active_network_faults_list(
        &self,
        f: &mut dyn FnMut(thread_diag::NetworkFaultEnum) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.net_ctl.active_network_faults_list(f)
    }
}

#[cfg(test)]
mod tests {
    use crate::dm::clusters::net_comm::{
        NetworksAccess, NetworksError, SharedNetworks, WirelessCreds,
    };

    use super::wifi::{Wifi, WifiNetworks};
    use super::WirelessNetwork;

    // ── Helper ──

    fn wifi_creds<'a>(ssid: &'a [u8], pass: &'a [u8]) -> WirelessCreds<'a> {
        WirelessCreds::Wifi { ssid, pass }
    }

    fn collect_ssids(nets: &WifiNetworks<4>) -> Vec<Vec<u8>> {
        let mut ids = Vec::new();
        nets.networks(|n| {
            ids.push(n.id().to_vec());
            Ok(())
        })
        .unwrap();
        ids
    }

    // ── WirelessNetworks: add / update / remove ──

    #[test]
    fn add_networks() {
        let mut nets = WifiNetworks::<4>::new();

        let idx = nets
            .add_or_update(b"A", Wifi::init_from(&wifi_creds(b"A", b"PassA")), |_| {
                Ok(())
            })
            .unwrap();
        assert_eq!(idx, 0);

        let idx = nets
            .add_or_update(b"B", Wifi::init_from(&wifi_creds(b"B", b"PassB")), |_| {
                Ok(())
            })
            .unwrap();
        assert_eq!(idx, 1);

        assert_eq!(collect_ssids(&nets), vec![b"A".to_vec(), b"B".to_vec()]);
    }

    #[test]
    fn update_existing_network() {
        let mut nets = WifiNetworks::<4>::new();
        nets.add_or_update(b"A", Wifi::init_from(&wifi_creds(b"A", b"Old")), |_| Ok(()))
            .unwrap();

        // Update: same SSID, new password
        nets.add_or_update(b"A", Wifi::init_from(&wifi_creds(b"A", b"New")), |wifi| {
            wifi.update(&wifi_creds(b"A", b"New"))
        })
        .unwrap();

        // Still one network
        assert_eq!(collect_ssids(&nets).len(), 1);

        // Verify updated password via creds
        let mut pass = Vec::new();
        nets.network(b"A", |w| {
            if let WirelessCreds::Wifi { pass: p, .. } = w.creds() {
                pass.extend_from_slice(p);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(pass, b"New");
    }

    #[test]
    fn add_exceeds_capacity() {
        let mut nets = WifiNetworks::<2>::new();
        nets.add_or_update(b"A", Wifi::init_from(&wifi_creds(b"A", b"p")), |_| Ok(()))
            .unwrap();
        nets.add_or_update(b"B", Wifi::init_from(&wifi_creds(b"B", b"p")), |_| Ok(()))
            .unwrap();

        let err = nets.add_or_update(b"C", Wifi::init_from(&wifi_creds(b"C", b"p")), |_| Ok(()));
        assert!(matches!(err, Err(NetworksError::BoundsExceeded)));
    }

    #[test]
    fn remove_network() {
        let mut nets = WifiNetworks::<4>::new();
        nets.add_or_update(b"A", Wifi::init_from(&wifi_creds(b"A", b"p")), |_| Ok(()))
            .unwrap();
        nets.add_or_update(b"B", Wifi::init_from(&wifi_creds(b"B", b"p")), |_| Ok(()))
            .unwrap();

        let idx = nets.remove(b"A").unwrap();
        assert_eq!(idx, 0);
        assert_eq!(collect_ssids(&nets), vec![b"B".to_vec()]);
    }

    #[test]
    fn remove_nonexistent() {
        let mut nets = WifiNetworks::<4>::new();
        assert!(matches!(
            nets.remove(b"X"),
            Err(NetworksError::NetworkIdNotFound)
        ));
    }

    // ── WirelessNetworks: reorder ──

    #[test]
    fn reorder_moves_to_front() {
        let mut nets = WifiNetworks::<4>::new();
        for id in [b"A", b"B", b"C"] {
            nets.add_or_update(
                id.as_slice(),
                Wifi::init_from(&wifi_creds(id, b"p")),
                |_| Ok(()),
            )
            .unwrap();
        }

        // Move C (index 2) to index 0
        nets.reorder(0, b"C").unwrap();
        assert_eq!(
            collect_ssids(&nets),
            vec![b"C".to_vec(), b"A".to_vec(), b"B".to_vec()]
        );
    }

    #[test]
    fn reorder_out_of_range() {
        let mut nets = WifiNetworks::<4>::new();
        nets.add_or_update(b"A", Wifi::init_from(&wifi_creds(b"A", b"p")), |_| Ok(()))
            .unwrap();

        assert!(matches!(
            nets.reorder(5, b"A"),
            Err(NetworksError::OutOfRange)
        ));
    }

    #[test]
    fn reorder_nonexistent() {
        let mut nets = WifiNetworks::<4>::new();
        assert!(matches!(
            nets.reorder(0, b"X"),
            Err(NetworksError::NetworkIdNotFound)
        ));
    }

    // ── WirelessNetworks: next_network round-robin ──

    #[test]
    fn next_network_iterates_and_wraps() {
        let mut nets = WifiNetworks::<4>::new();
        for id in [b"A", b"B", b"C"] {
            nets.add_or_update(
                id.as_slice(),
                Wifi::init_from(&wifi_creds(id, b"p")),
                |_| Ok(()),
            )
            .unwrap();
        }

        let get_next = |last: Option<&[u8]>| -> Option<Vec<u8>> {
            let mut result = None;
            let found = nets
                .next_network(last, |w| {
                    result = Some(w.id().to_vec());
                    Ok(())
                })
                .unwrap();
            if found {
                result
            } else {
                None
            }
        };

        assert_eq!(get_next(None), Some(b"A".to_vec()));
        assert_eq!(get_next(Some(b"A")), Some(b"B".to_vec()));
        assert_eq!(get_next(Some(b"B")), Some(b"C".to_vec()));
        // After last → wraps to first
        assert_eq!(get_next(Some(b"C")), Some(b"A".to_vec()));
        // Unknown ID → first
        assert_eq!(get_next(Some(b"Z")), Some(b"A".to_vec()));
    }

    #[test]
    fn next_network_empty_returns_false() {
        let nets = WifiNetworks::<4>::new();
        let found = nets.next_network(None, |_| Ok(())).unwrap();
        assert!(!found);
    }

    // ── WirelessNetworks: store / load round-trip ──

    #[test]
    fn store_load_round_trip() {
        let mut nets = WifiNetworks::<4>::new();
        nets.add_or_update(
            b"Net1",
            Wifi::init_from(&wifi_creds(b"Net1", b"P1")),
            |_| Ok(()),
        )
        .unwrap();
        nets.add_or_update(
            b"Net2",
            Wifi::init_from(&wifi_creds(b"Net2", b"P2")),
            |_| Ok(()),
        )
        .unwrap();
        nets.set_commissioned(true);

        let mut buf = [0u8; 512];
        let len = nets.store(&mut buf).unwrap();

        let mut loaded = WifiNetworks::<4>::new();
        loaded.load(&buf[..len]).unwrap();

        assert_eq!(collect_ssids(&loaded), collect_ssids(&nets));
        assert!(loaded.commissioned());
    }

    // ── WirelessNetworks: commissioned state ──

    #[test]
    fn commissioned_default_false() {
        let nets = WifiNetworks::<4>::new();
        assert!(!nets.commissioned());
    }

    #[test]
    fn set_commissioned() {
        let mut nets = WifiNetworks::<4>::new();
        nets.set_commissioned(true);
        assert!(nets.commissioned());
        nets.set_commissioned(false);
        assert!(!nets.commissioned());
    }

    // ── WirelessNetworks: reset ──

    #[test]
    fn reset_clears_all() {
        let mut nets = WifiNetworks::<4>::new();
        nets.add_or_update(b"A", Wifi::init_from(&wifi_creds(b"A", b"p")), |_| Ok(()))
            .unwrap();
        nets.set_commissioned(true);

        nets.reset();
        assert!(collect_ssids(&nets).is_empty());
        assert!(!nets.commissioned());
    }

    // ── SharedNetworks: delegates to inner WifiNetworks correctly ──

    #[test]
    fn shared_networks_access_add_and_read() {
        let shared = SharedNetworks::new(WifiNetworks::<4>::new());

        shared.access(|networks| {
            networks
                .add_or_update(&wifi_creds(b"SSID1", b"pass1"))
                .unwrap();
            networks
                .add_or_update(&wifi_creds(b"SSID2", b"pass2"))
                .unwrap();
        });

        // Read back via Networks trait
        let count = shared.access(|networks| {
            let mut count = 0u8;
            networks
                .networks(&mut |_info| {
                    count += 1;
                    Ok(())
                })
                .unwrap();
            count
        });

        assert_eq!(count, 2);
    }

    #[test]
    fn shared_networks_commissioned_via_access() {
        let shared = SharedNetworks::new(WifiNetworks::<4>::new());

        let commissioned = shared.access(|networks| networks.commissioned().unwrap());
        assert!(!commissioned);

        shared.access(|networks| networks.set_commissioned(true).unwrap());

        let commissioned = shared.access(|networks| networks.commissioned().unwrap());
        assert!(commissioned);
    }

    #[test]
    fn shared_networks_next_creds_round_robin() {
        let shared = SharedNetworks::new(WifiNetworks::<4>::new());

        shared.access(|networks| {
            for (ssid, pass) in [(b"A", b"pA"), (b"B", b"pB"), (b"C", b"pC")] {
                networks
                    .add_or_update(&wifi_creds(ssid.as_slice(), pass.as_slice()))
                    .unwrap();
            }
        });

        let get_next_ssid = |last: Option<&[u8]>| -> Option<Vec<u8>> {
            shared.access(|networks| {
                let mut result = None;
                let found = networks
                    .next_creds(last, &mut |creds| {
                        if let WirelessCreds::Wifi { ssid, .. } = creds {
                            result = Some(ssid.to_vec());
                        }
                        Ok(())
                    })
                    .unwrap();
                if found {
                    result
                } else {
                    None
                }
            })
        };

        assert_eq!(get_next_ssid(None), Some(b"A".to_vec()));
        assert_eq!(get_next_ssid(Some(b"A")), Some(b"B".to_vec()));
        assert_eq!(get_next_ssid(Some(b"C")), Some(b"A".to_vec()));
    }

    // ── Regression: load old-format (bare TLV array, no commissioned field) ──

    #[test]
    fn load_old_format_bare_array() {
        use crate::tlv::{TLVTag, TLVWrite};
        use crate::utils::storage::WriteBuf;

        // Build old-format TLV data: bare anonymous array of Wifi structs.
        // Before the `commissioned` field was added, `store` just serialized the
        // networks Vec directly (without wrapping in a struct).
        let mut buf = [0u8; 512];
        let mut wb = WriteBuf::new(&mut buf);

        wb.start_array(&TLVTag::Anonymous).unwrap();

        // Wifi entry "A" with password "pA"
        wb.start_struct(&TLVTag::Anonymous).unwrap();
        wb.str(&TLVTag::Context(0), b"A").unwrap();
        wb.str(&TLVTag::Context(1), b"pA").unwrap();
        wb.end_container().unwrap();

        // Wifi entry "B" with password "pB"
        wb.start_struct(&TLVTag::Anonymous).unwrap();
        wb.str(&TLVTag::Context(0), b"B").unwrap();
        wb.str(&TLVTag::Context(1), b"pB").unwrap();
        wb.end_container().unwrap();

        wb.end_container().unwrap();
        let len = wb.get_tail();

        // Load using new code (should handle old format gracefully)
        let mut nets = WifiNetworks::<4>::new();
        nets.load(&buf[..len]).unwrap();

        assert_eq!(collect_ssids(&nets), vec![b"A".to_vec(), b"B".to_vec()]);
        assert!(
            !nets.commissioned(),
            "Old format should default commissioned to false"
        );
    }

    // ── Regression: save() must not trigger a change notification ──

    #[test]
    fn shared_networks_save_does_not_trigger_change() {
        use core::pin::pin;
        use embassy_futures::select::{select, Either};

        let shared = SharedNetworks::new(WifiNetworks::<4>::new());

        // Add a network → triggers notification
        shared.access(|n| n.add_or_update(&wifi_creds(b"A", b"p")).unwrap());

        // Consume the notification
        embassy_futures::block_on(shared.wait_state_changed());

        // Save (should NOT trigger notification)
        shared.access(|n| {
            let mut buf = [0u8; 512];
            n.save(&mut buf).unwrap();
        });

        // Check: wait_state_changed should NOT be ready.
        // `select` is biased towards the first future, so if the notification was
        // triggered, it would resolve first. `ready(())` resolves immediately so
        // if the notification was NOT triggered, the second branch wins.
        let notified = embassy_futures::block_on(async {
            match select(
                pin!(shared.wait_state_changed()),
                pin!(core::future::ready(())),
            )
            .await
            {
                Either::First(_) => true,
                Either::Second(_) => false,
            }
        });

        assert!(!notified, "save() must not trigger change notification");
    }
}
