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

//! A module containing various types for managing Thread and Wifi networks.

use core::borrow::Borrow;
use core::fmt::{Debug, Display};

use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::dm::clusters::net_comm::{
    self, NetCtlError, NetworkCommissioningStatusEnum, NetworkType, NetworksError,
    ThreadCapabilitiesBitmap, WirelessCreds,
};
use crate::dm::clusters::{thread_diag, wifi_diag};
use crate::error::{Error, ErrorCode};
use crate::fmt::Bytes;
use crate::tlv::{FromTLV, TLVElement, TLVTag, ToTLV};
use crate::transport::network::btp::{Btp, BtpContext, GattPeripheral};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::{Vec, WriteBuf};
use crate::utils::sync::blocking::{self, Mutex};
use crate::utils::sync::Notification;

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
pub trait WirelessNetwork: for<'a> FromTLV<'a> + ToTLV {
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
pub struct WirelessNetworks<const N: usize, M, T>
where
    M: RawMutex,
{
    state: Mutex<M, RefCell<WirelessNetworksStore<N, T>>>,
    state_changed: Notification<M>,
    persist_state_changed: Notification<M>,
}

impl<const N: usize, M, T> WirelessNetworks<N, M, T>
where
    M: RawMutex,
    T: WirelessNetwork,
{
    /// Create a new instance.
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(WirelessNetworksStore::new())),
            state_changed: Notification::new(),
            persist_state_changed: Notification::new(),
        }
    }

    /// Return an in-place initializer for the struct.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(WirelessNetworksStore::init())),
            state_changed: Notification::new(),
            persist_state_changed: Notification::new(),
        })
    }

    /// Reset the state
    ///
    /// # Arguments
    /// - `flag_changed`: If `true`, the state will be marked as changed
    pub fn reset(&self, flag_changed: bool) {
        self.state
            .lock(|state| state.borrow_mut().reset(flag_changed));

        self.state_changed.notify();

        if flag_changed {
            self.persist_state_changed.notify();
        }
    }

    /// Load the state from a byte slice.
    ///
    /// # Arguments
    /// - `data`: The byte slice to load the state from
    pub fn load(&self, data: &[u8]) -> Result<(), Error> {
        self.state.lock(|state| state.borrow_mut().load(data))
    }

    /// Store the state into a byte slice.
    ///
    /// # Arguments
    /// - `buf`: The byte slice to store the state into
    ///
    /// Returns the number of bytes written into the buffer.
    pub fn store(&self, buf: &mut [u8]) -> Result<usize, Error> {
        self.state.lock(|state| state.borrow_mut().store(buf))
    }

    /// Return `true` if the state has changed.
    pub fn changed(&self) -> bool {
        self.state.lock(|state| state.borrow().changed)
    }

    /// Wait for the state to change.
    pub async fn wait_state_changed(&self) {
        loop {
            if self.state.lock(|state| state.borrow().changed) {
                break;
            }

            self.state_changed.wait().await;
        }
    }

    /// Wait for the state to be changed in a way that requires persisting.
    pub async fn wait_persist(&self) {
        loop {
            if self.state.lock(|state| state.borrow().changed) {
                break;
            }

            self.persist_state_changed.wait().await;
        }
    }

    /// Iterate over the registered network credentials
    ///
    /// # Arguments
    /// - `f`: A closure that will be called for each network registered in the storage
    pub fn networks<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnMut(&T) -> Result<(), Error>,
    {
        self.state.lock(|state| state.borrow().networks(f))
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
        self.state
            .lock(|state| state.borrow().network(network_id, f))
    }

    /// Get the next network credentials after the one with the given ID
    ///
    /// # Arguments
    /// - `after_network_id`: The ID of the network to get the next one after.
    ///   If no network with the provided network ID exists, the first network in the storage will be returned.
    pub fn next_network<F>(&self, after_network_id: Option<&[u8]>, f: F) -> Result<bool, Error>
    where
        F: FnOnce(&T) -> Result<(), Error>,
    {
        self.state
            .lock(|state| state.borrow_mut().next_network(after_network_id, f))
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
        &self,
        network_id: &[u8],
        add: A,
        update: U,
    ) -> Result<u8, NetworksError>
    where
        A: Init<T, Error>,
        U: FnOnce(&mut T) -> Result<(), Error>,
    {
        self.state.lock(|state| {
            let index = state.borrow_mut().add_or_update(network_id, add, update)?;

            self.state_changed.notify();
            self.persist_state_changed.notify();

            Ok(index)
        })
    }

    /// Reorder a network in the storage
    ///
    /// # Arguments
    /// - `index`: The new index of the network
    /// - `network_id`: The ID of the network to reorder
    ///
    /// Returns the new index of the network in the storage, if a network with the provided ID exists
    /// or `NetworkError::NetworkIdNotFound` otherwise
    pub fn reorder(&self, index: u8, network_id: &[u8]) -> Result<u8, NetworksError> {
        self.state.lock(|state| {
            let index = state.borrow_mut().reorder(index, network_id)?;

            self.state_changed.notify();
            self.persist_state_changed.notify();

            Ok(index)
        })
    }

    /// Remove a network from the storage
    ///
    /// # Arguments
    /// - `network_id`: The ID of the network to remove
    ///
    /// Returns the index of the network in the storage if the network exists and was removed, `NetworkError::NetworkIdNotFound` otherwise
    pub fn remove(&self, network_id: &[u8]) -> Result<u8, NetworksError> {
        self.state.lock(|state| {
            let index = state.borrow_mut().remove(network_id)?;

            self.state_changed.notify();
            self.persist_state_changed.notify();

            Ok(index)
        })
    }
}

impl<const N: usize, M, T> Default for WirelessNetworks<N, M, T>
where
    M: RawMutex,
    T: WirelessNetwork + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, M, T> net_comm::Networks for WirelessNetworks<N, M, T>
where
    M: RawMutex,
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

    fn set_enabled(&self, _enabled: bool) -> Result<(), Error> {
        Ok(())
    }

    fn add_or_update(
        &self,
        creds: &net_comm::WirelessCreds<'_>,
    ) -> Result<u8, net_comm::NetworksError> {
        WirelessNetworks::add_or_update(self, creds.id()?, T::init_from(creds), |network| {
            network.update(creds)
        })
    }

    fn reorder(&self, index: u8, network_id: &[u8]) -> Result<u8, NetworksError> {
        WirelessNetworks::reorder(self, index, network_id)
    }

    fn remove(&self, network_id: &[u8]) -> Result<u8, NetworksError> {
        WirelessNetworks::remove(self, network_id)
    }
}

impl<const N: usize, M, T> NetChangeNotif for WirelessNetworks<N, M, T>
where
    M: RawMutex,
    T: WirelessNetwork,
{
    async fn wait_changed(&self) {
        self.state_changed.wait().await;
    }
}

/// The internal unsychronized storage for network credentials.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct WirelessNetworksStore<const N: usize, T> {
    networks: crate::utils::storage::Vec<T, N>,
    changed: bool,
}

impl<const N: usize, T> WirelessNetworksStore<N, T>
where
    T: WirelessNetwork,
{
    const fn new() -> Self {
        Self {
            networks: crate::utils::storage::Vec::new(),
            changed: false,
        }
    }

    fn init() -> impl Init<Self> {
        init!(Self {
            networks <- crate::utils::storage::Vec::init(),
            changed: false,
        })
    }

    fn reset(&mut self, flag_changed: bool) {
        self.networks.clear();
        self.changed = flag_changed;
    }

    fn load(&mut self, data: &[u8]) -> Result<(), Error> {
        let root = TLVElement::new(data);

        let iter = root.array()?.iter();

        self.networks.clear();

        for network in iter {
            let network = network?;

            self.networks.push_init(T::init_from_tlv(network), || {
                ErrorCode::ResourceExhausted.into()
            })?;
        }

        self.changed = false;

        Ok(())
    }

    fn store(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut wb = WriteBuf::new(buf);

        self.networks.to_tlv(&TLVTag::Anonymous, &mut wb)?;

        self.changed = false;

        let tail = wb.get_tail();

        Ok(tail)
    }

    fn networks<F>(&self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(&T) -> Result<(), Error>,
    {
        for network in self.networks.iter() {
            f(network)?;
        }

        Ok(())
    }

    fn network<F>(&self, network_id: &[u8], f: F) -> Result<u8, NetworksError>
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

    fn next_network<F>(&mut self, last_network_id: Option<&[u8]>, f: F) -> Result<bool, Error>
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

    fn add_or_update<A, U>(
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

            self.changed = true;

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

            self.changed = true;

            info!("Added network with ID {}", T::display_id(network_id));

            Ok((self.networks.len() - 1) as _)
        }
    }

    fn reorder(&mut self, index: u8, network_id: &[u8]) -> Result<u8, NetworksError> {
        let cur_index = self
            .networks
            .iter()
            .position(|conf| conf.id() == network_id);

        if let Some(cur_index) = cur_index {
            // Found

            if index < self.networks.len() as u8 {
                let conf = self.networks.remove(cur_index);
                unwrap!(self.networks.insert(index as usize, conf).map_err(|_| ()));

                self.changed = true;

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

    fn remove(&mut self, network_id: &[u8]) -> Result<u8, NetworksError> {
        let index = self
            .networks
            .iter()
            .position(|conf| conf.id() == network_id);

        if let Some(index) = index {
            // Found
            self.networks.remove(index);

            self.changed = true;

            info!("Removed network with ID {}", T::display_id(network_id));

            Ok(index as _)
        } else {
            warn!("Network with ID {} not found", T::display_id(network_id));

            Err(NetworksError::NetworkIdNotFound)
        }
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
    pub const fn new_with_mutex<M>() -> NetCtlStateMutex<M>
    where
        M: RawMutex,
    {
        blocking::Mutex::new(RefCell::new(Self::new()))
    }

    /// Return an in-place initializer for a new, empty `NetCtlState` wrapped in a mutex.
    pub fn init_with_mutex<M>() -> impl Init<NetCtlStateMutex<M>>
    where
        M: RawMutex,
    {
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
    pub fn update_with_mutex<M, R>(
        state: &NetCtlStateMutex<M>,
        network_id: Option<&[u8]>,
        result: Result<R, NetCtlError>,
    ) -> Result<R, NetCtlError>
    where
        M: RawMutex,
    {
        state.lock(|state| state.borrow_mut().update(network_id, result))
    }

    /// A utility to wait for provisioning over BTP to be ready.
    /// Provisioning over BTP is considered complete when there is no longer an active connection
    /// and the network ID is set (i.e. method `NetCtl::connect` was called successfully).
    ///
    /// This method is only useful for non-concurrent commisioning using wireless networks and BLE,
    /// and is likely to be used together with `NoopWirelessNetCtl`.
    pub async fn wait_prov_ready<M, C, M2, G>(state: &NetCtlStateMutex<M>, btp: &Btp<C, M2, G>)
    where
        M: RawMutex,
        C: Borrow<BtpContext<M2>> + Clone + Send + Sync + 'static,
        M2: RawMutex + Send + Sync,
        G: GattPeripheral,
    {
        while !state.lock(|state| state.borrow().is_prov_ready() && btp.conn_ct() == 0) {
            // Provisioning over BTP is considered complete when there is no longer an active connection
            // and the network ID is set (i.e. method `NetCtl::connect` was called successfully)

            btp.wait_changed().await;
        }
    }
}

impl Default for NetCtlState {
    fn default() -> Self {
        Self::new()
    }
}

/// A type alias for a `NetCtlState` instance wrapped in a mutex.
pub type NetCtlStateMutex<M> = blocking::Mutex<M, RefCell<NetCtlState>>;

/// A wrapper around a `NetCtl` network controller that additionally implements the `NetCtlStatus`trait.
pub struct NetCtlWithStatusImpl<'a, M, T>
where
    M: RawMutex,
{
    state: &'a NetCtlStateMutex<M>,
    net_ctl: T,
}

impl<'a, M, T> NetCtlWithStatusImpl<'a, M, T>
where
    M: RawMutex,
{
    /// Create a new instance of `NetCtlWithStatusImpl`.
    ///
    /// # Arguments
    /// - `state`: A reference to a `NetCtlState` instance wrapped in a mutex
    /// - `net_ctl`: A network controller that implements the `NetCtl` trait
    pub const fn new(state: &'a NetCtlStateMutex<M>, net_ctl: T) -> Self {
        Self { state, net_ctl }
    }
}

impl<M, T> net_comm::NetCtl for NetCtlWithStatusImpl<'_, M, T>
where
    M: RawMutex,
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

impl<M, T> net_comm::NetCtlStatus for NetCtlWithStatusImpl<'_, M, T>
where
    M: RawMutex,
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

impl<M, T> NetChangeNotif for NetCtlWithStatusImpl<'_, M, T>
where
    M: RawMutex,
    T: NetChangeNotif,
{
    async fn wait_changed(&self) {
        self.net_ctl.wait_changed().await
    }
}

impl<M, T> wifi_diag::WirelessDiag for NetCtlWithStatusImpl<'_, M, T>
where
    M: RawMutex,
    T: wifi_diag::WirelessDiag,
{
    fn connected(&self) -> Result<bool, Error> {
        self.net_ctl.connected()
    }
}

impl<M, T> wifi_diag::WifiDiag for NetCtlWithStatusImpl<'_, M, T>
where
    M: RawMutex,
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

impl<M, T> thread_diag::ThreadDiag for NetCtlWithStatusImpl<'_, M, T>
where
    M: RawMutex,
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

    fn neightbor_table(
        &self,
        f: &mut dyn FnMut(&thread_diag::NeighborTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.net_ctl.neightbor_table(f)
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
