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

//! This module contains the implementation of the Network Commissioning cluster and its handler.

use core::fmt;

use crate::data_model::networks::wireless::{Thread, ThreadTLV, MAX_WIRELESS_NETWORK_ID_LEN};
use crate::data_model::objects::{
    ArrayAttributeRead, Cluster, Dataver, InvokeContext, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{
    Nullable, NullableBuilder, Octets, OctetsBuilder, TLVBuilder, TLVBuilderParent, TLVWrite,
    ToTLVArrayBuilder, ToTLVBuilder,
};
use crate::{clusters, with};

pub use crate::data_model::clusters::network_commissioning::*;

/// Network type supported by the `NetCtl` implementations
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworkType {
    Ethernet,
    Wifi,
    Thread,
}

impl NetworkType {
    /// Return an instance of the Network Commissioning cluster meta-data for the given network type.
    pub const fn cluster(&self) -> Cluster<'static> {
        match self {
            Self::Ethernet => FULL_CLUSTER
                .with_revision(1)
                .with_features(Feature::ETHERNET_NETWORK_INTERFACE.bits())
                .with_attrs(with!(required))
                .with_cmds(with!()),
            Self::Wifi => FULL_CLUSTER
                .with_revision(1)
                .with_features(Feature::WI_FI_NETWORK_INTERFACE.bits())
                .with_attrs(with!(required; AttributeId::ScanMaxTimeSeconds | AttributeId::ConnectMaxTimeSeconds | AttributeId::SupportedWiFiBands))
                .with_cmds(with!(CommandId::AddOrUpdateWiFiNetwork | CommandId::ScanNetworks | CommandId::RemoveNetwork | CommandId::ConnectNetwork | CommandId::ReorderNetwork)),
            Self::Thread => FULL_CLUSTER
                .with_revision(1)
                .with_features(Feature::THREAD_NETWORK_INTERFACE.bits())
                .with_attrs(with!(required; AttributeId::ScanMaxTimeSeconds | AttributeId::ConnectMaxTimeSeconds | AttributeId::ThreadVersion | AttributeId::SupportedThreadFeatures))
                .with_cmds(with!(CommandId::AddOrUpdateThreadNetwork | CommandId::ScanNetworks | CommandId::RemoveNetwork | CommandId::ConnectNetwork | CommandId::ReorderNetwork)),
        }
    }

    /// Return the root clusters necessary for the given network type
    /// These are the Network Commissioning cluster tailored with attributes suitable for the
    /// concrete nework type as well as one of the Ethernet Network Diagnostics, WiFi Network
    /// Diagnostics or Thread Network Diagnostics clusters.
    pub const fn root_clusters(&self) -> &'static [Cluster<'static>] {
        static ETH: &[Cluster<'static>] = clusters!(eth;);
        static WIFI: &[Cluster<'static>] = clusters!(wifi;);
        static THREAD: &[Cluster<'static>] = clusters!(thread;);

        match self {
            Self::Ethernet => ETH,
            Self::Wifi => WIFI,
            Self::Thread => THREAD,
        }
    }
}

/// Network information as returned by the `Networks` trait
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkInfo<'a> {
    /// The network ID of the network
    pub network_id: &'a [u8],
    /// Whether this network is currently connected
    pub connected: bool,
}

impl NetworkInfo<'_> {
    /// Read the network information into the given `NetworkInfoStructBuilder`.
    fn read_into<P: TLVBuilderParent>(
        &self,
        builder: NetworkInfoStructBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .network_id(Octets::new(self.network_id))?
            .connected(self.connected)?
            .network_identifier(None)?
            .client_identifier(None)?
            .end()
    }
}

/// Network scan information as returned by the `NetCtl::scan` method
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworkScanInfo<'a> {
    /// WiFi network scan information when the network type is `NetworkType::Wifi`
    Wifi {
        security: WiFiSecurityBitmap,
        ssid: &'a [u8],
        bssid: &'a [u8],
        channel: u16,
        band: WiFiBandEnum,
        rssi: i8,
    },
    /// Thread network scan information when the network type is `NetworkType::Thread`
    Thread {
        pan_id: u16,
        ext_pan_id: u64,
        network_name: &'a str,
        channel: u16,
        version: u8,
        ext_addr: &'a [u8],
        rssi: i8,
        lqi: u8,
    },
}

impl NetworkScanInfo<'_> {
    /// Read the network scan information into the given `NetworkScanInfoStructBuilder`.
    /// If the network type is not `NetworkType::Wifi`, this method will panic.
    pub fn wifi_read_into<P: TLVBuilderParent>(
        &self,
        builder: WiFiInterfaceScanResultStructBuilder<P>,
    ) -> Result<P, Error> {
        let NetworkScanInfo::Wifi {
            security,
            ssid,
            bssid,
            channel,
            band,
            rssi,
        } = self
        else {
            panic!("Wifi scan info expected");
        };

        builder
            .security(*security)?
            .ssid(Octets::new(ssid))?
            .bssid(Octets::new(bssid))?
            .channel(*channel)?
            .wi_fi_band(*band)?
            .rssi(*rssi)?
            .end()
    }

    /// Read the network scan information into the given `ThreadInterfaceScanResultStructBuilder`.
    /// If the network type is not `NetworkType::Thread`, this method will panic.
    pub fn thread_read_into<P: TLVBuilderParent>(
        &self,
        builder: ThreadInterfaceScanResultStructBuilder<P>,
    ) -> Result<P, Error> {
        let NetworkScanInfo::Thread {
            pan_id,
            ext_pan_id: extended_pan_id,
            network_name,
            channel,
            version,
            ext_addr,
            rssi,
            lqi,
        } = self
        else {
            panic!("Thread scan info expected");
        };

        builder
            .pan_id(*pan_id)?
            .extended_pan_id(*extended_pan_id)?
            .network_name(network_name)?
            .channel(*channel)?
            .version(*version)?
            .extended_address(Octets::new(ext_addr))?
            .rssi(*rssi)?
            .lqi(*lqi)?
            .end()
    }
}

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
            WirelessCreds::Thread { dataset_tlv } => Thread::dataset_ext_pan_id(dataset_tlv),
        }
    }

    /// Check if the credentials match the given network type
    pub fn check_match(&self, net_type: NetworkType) -> Result<(), Error> {
        match self {
            WirelessCreds::Wifi { .. } if matches!(net_type, NetworkType::Wifi) => Ok(()),
            WirelessCreds::Thread { .. } if matches!(net_type, NetworkType::Thread) => Ok(()),
            _ => Err(ErrorCode::InvalidAction.into()),
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

/// Network error type for the `NetCtl` trait
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetCtlError {
    NetworkNotFound,
    UnsupportedSecurity,
    AuthFailure,
    OtherConnectionFailure,
    IpBindFailed,
    IpV6Failed,
    Other(Error),
}

impl From<Error> for NetCtlError {
    fn from(err: Error) -> Self {
        NetCtlError::Other(err)
    }
}

impl NetworkCommissioningStatusEnum {
    /// Map the result of a network storage operation to a `NetworkCommissioningStatusEnum` if the operation
    /// failed, or return the index of the network if it succeeded.
    pub fn map<T>(
        result: Result<T, NetworksError>,
    ) -> Result<(NetworkCommissioningStatusEnum, Option<i32>, Option<T>), Error> {
        if let Some((status, err_code)) = NetworkCommissioningStatusEnum::map_status(&result) {
            Ok((status, err_code, result.ok()))
        } else {
            match result {
                Err(NetworksError::Other(e)) => Err(e),
                _ => unreachable!(),
            }
        }
    }

    /// Map the result of a network storage operation to a `NetworkCommissioningStatusEnum` and error code  if the operation
    /// failed, or return the index of the network if it succeeded.
    pub fn map_status<T>(
        result: &Result<T, NetworksError>,
    ) -> Option<(NetworkCommissioningStatusEnum, Option<i32>)> {
        match result {
            Ok(_) => Some((NetworkCommissioningStatusEnum::Success, None)),
            Err(NetworksError::NetworkIdNotFound) => {
                Some((NetworkCommissioningStatusEnum::NetworkIDNotFound, None))
            }
            Err(NetworksError::DuplicateNetworkId) => {
                Some((NetworkCommissioningStatusEnum::DuplicateNetworkID, None))
            }
            Err(NetworksError::OutOfRange) => {
                Some((NetworkCommissioningStatusEnum::OutOfRange, None))
            }
            Err(NetworksError::BoundsExceeded) => {
                Some((NetworkCommissioningStatusEnum::BoundsExceeded, None))
            }
            Err(NetworksError::Other(_)) => None,
        }
    }

    /// Map the result of a network IO operation to a `NetworkCommissioningStatusEnum` if the operation
    /// failed, or return the index of the network if it succeeded.
    pub fn map_ctl<T>(
        result: Result<T, NetCtlError>,
    ) -> Result<(NetworkCommissioningStatusEnum, Option<i32>, Option<T>), Error> {
        if let Some((status, err_code)) = NetworkCommissioningStatusEnum::map_ctl_status(&result) {
            Ok((status, err_code, result.ok()))
        } else {
            match result {
                Err(NetCtlError::Other(e)) => Err(e),
                _ => unreachable!(),
            }
        }
    }

    /// Map the result of a network IO operation to a `NetworkCommissioningStatusEnum` and error code  if the operation
    /// failed, or return the index of the network if it succeeded.
    pub fn map_ctl_status<T>(
        result: &Result<T, NetCtlError>,
    ) -> Option<(NetworkCommissioningStatusEnum, Option<i32>)> {
        match result {
            Ok(_) => Some((NetworkCommissioningStatusEnum::Success, None)),
            Err(NetCtlError::UnsupportedSecurity) => {
                Some((NetworkCommissioningStatusEnum::UnsupportedSecurity, None))
            }
            Err(NetCtlError::AuthFailure) => {
                Some((NetworkCommissioningStatusEnum::AuthFailure, None))
            }
            Err(NetCtlError::IpBindFailed) => {
                Some((NetworkCommissioningStatusEnum::IPBindFailed, None))
            }
            Err(NetCtlError::IpV6Failed) => {
                Some((NetworkCommissioningStatusEnum::IPV6Failed, None))
            }
            Err(NetCtlError::OtherConnectionFailure) => {
                Some((NetworkCommissioningStatusEnum::OtherConnectionFailure, None))
            }
            Err(NetCtlError::NetworkNotFound) => {
                Some((NetworkCommissioningStatusEnum::NetworkNotFound, None))
            }
            Err(NetCtlError::Other(_)) => None,
        }
    }

    /// Read the networking status and the provided optional index into the given `NetworkConfigResponseBuilder`.
    pub fn read_into<P: TLVBuilderParent>(
        &self,
        index: Option<u8>,
        builder: NetworkConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .networking_status(*self)?
            .debug_text(None)?
            .network_index(index)?
            .client_identity(None)?
            .possession_signature(None)?
            .end()
    }
}

/// Trait for managing networks' credentials storage
pub trait Networks {
    /// Return the maximum number of networks supported by the implementation
    ///
    /// For `NetworkType::Ethernet` this method should always return 1
    fn max_networks(&self) -> Result<u8, Error>;

    /// Iterate over the networks recorded in the implementation and call the provided function for each network
    fn networks(&self, f: &mut dyn FnMut(&NetworkInfo) -> Result<(), Error>) -> Result<(), Error>;

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
    fn set_enabled(&self, enabled: bool) -> Result<(), Error>;

    /// Add or update the credentials for the given network ID
    ///
    /// For `NetworkType::Ethernet` this method should always fail with an error.
    ///
    /// The network ID is derived from the credentials.
    ///
    /// Return the index of the network ID if it was added or updated, or an error if the operation failed.
    fn add_or_update(&self, creds: &WirelessCreds<'_>) -> Result<u8, NetworksError>;

    /// Reorder the network with the given index
    ///
    /// For `NetworkType::Ethernet` this method should always fail with an error.
    ///
    /// The index is the new index of the network ID.
    ///
    /// Return the index of the network ID if it was reordered, or an error if the operation failed.
    fn reorder(&self, index: u8, network_id: &[u8]) -> Result<u8, NetworksError>;

    /// Remove the network with the given network ID
    ///
    /// For `NetworkType::Ethernet` this method should always fail with an error.
    ///
    /// Return the index of the network ID if it was removed, or an error if the operation failed.
    fn remove(&self, network_id: &[u8]) -> Result<u8, NetworksError>;
}

impl<T> Networks for &T
where
    T: Networks,
{
    fn max_networks(&self) -> Result<u8, Error> {
        (*self).max_networks()
    }

    fn networks(&self, f: &mut dyn FnMut(&NetworkInfo) -> Result<(), Error>) -> Result<(), Error> {
        (*self).networks(f)
    }

    fn creds(
        &self,
        network_id: &[u8],
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<u8, NetworksError> {
        (*self).creds(network_id, f)
    }

    fn next_creds(
        &self,
        last_network_id: Option<&[u8]>,
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        (*self).next_creds(last_network_id, f)
    }

    fn enabled(&self) -> Result<bool, Error> {
        (*self).enabled()
    }

    fn set_enabled(&self, enabled: bool) -> Result<(), Error> {
        (*self).set_enabled(enabled)
    }

    fn add_or_update(&self, creds: &WirelessCreds<'_>) -> Result<u8, NetworksError> {
        (*self).add_or_update(creds)
    }

    fn reorder(&self, index: u8, network_id: &[u8]) -> Result<u8, NetworksError> {
        (*self).reorder(index, network_id)
    }

    fn remove(&self, network_id: &[u8]) -> Result<u8, NetworksError> {
        (*self).remove(network_id)
    }
}

/// Trait for managing network connectivity
pub trait NetCtl {
    /// Return the network type of the implementation
    fn net_type(&self) -> NetworkType;

    /// Return the maximum time in seconds for connecting to a network
    ///
    /// Default implementation returns 30 seconds
    fn connect_max_time_seconds(&self) -> u8 {
        30
    }

    /// Return the maximum time in seconds for scanning for networks
    ///
    /// Default implementation returns 30 seconds
    fn scan_max_time_seconds(&self) -> u8 {
        30
    }

    /// Return the supported WiFi bands for the implementation in the provided closure
    ///
    /// Default implementation returns 2.4GHz band only
    ///
    /// NOTE: This method is only relevant when `net_type` is `NetworkType::Wifi`
    fn supported_wifi_bands<F>(&self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(WiFiBandEnum) -> Result<(), Error>,
    {
        f(WiFiBandEnum::V2G4)
    }

    /// Return the supported Thread features for the implementation
    ///
    /// Default implementation returns an empty bitmap
    ///
    /// NOTE: This method is only relevant when `net_type` is `NetworkType::Thread`
    fn supported_thread_features(&self) -> ThreadCapabilitiesBitmap {
        ThreadCapabilitiesBitmap::empty()
    }

    /// Return the Thread version for the implementation
    ///
    /// Default implementation returns 4 (Thread 1.3.0)
    ///
    /// NOTE: This method is only relevant when `net_type` is `NetworkType::Thread`
    fn thread_version(&self) -> u16 {
        4
    }

    /// Scan for networks and call the provided function for each network found
    ///
    /// For `NetworkType::Ethernet` this method should always fail with an error.
    async fn scan<F>(&self, network: Option<&[u8]>, f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>;

    /// Connect to the network with the given credentials
    ///
    /// For `NetworkType::Ethernet` this method should always fail with an error.
    async fn connect(&self, creds: &WirelessCreds) -> Result<(), NetCtlError>;
}

impl<T> NetCtl for &T
where
    T: NetCtl,
{
    fn net_type(&self) -> NetworkType {
        (*self).net_type()
    }

    fn connect_max_time_seconds(&self) -> u8 {
        (*self).connect_max_time_seconds()
    }

    fn scan_max_time_seconds(&self) -> u8 {
        (*self).scan_max_time_seconds()
    }

    fn supported_wifi_bands<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnMut(WiFiBandEnum) -> Result<(), Error>,
    {
        (*self).supported_wifi_bands(f)
    }

    fn supported_thread_features(&self) -> ThreadCapabilitiesBitmap {
        (*self).supported_thread_features()
    }

    fn thread_version(&self) -> u16 {
        (*self).thread_version()
    }

    async fn scan<F>(&self, network: Option<&[u8]>, f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>,
    {
        (*self).scan(network, f).await
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        (*self).connect(creds).await
    }
}

/// Trait for providing the status of the last `scan` / `connect` operation
pub trait NetCtlStatus {
    /// Return the networking status of the last scan or connect operation
    ///
    /// For `NetworkType::Ethernet` this method should always return `Ok(None)`
    fn last_networking_status(&self) -> Result<Option<NetworkCommissioningStatusEnum>, Error>;

    /// Return the network ID of the last connect operation
    ///
    /// For `NetworkType::Ethernet` this method should always return `Ok(None)`
    fn last_network_id<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(Option<&[u8]>) -> Result<R, Error>;

    /// Return the error value of the last connect operation
    ///
    /// For `NetworkType::Ethernet` this method should always return `Ok(None)`
    fn last_connect_error_value(&self) -> Result<Option<i32>, Error>;
}

impl<T> NetCtlStatus for &T
where
    T: NetCtlStatus,
{
    fn last_networking_status(&self) -> Result<Option<NetworkCommissioningStatusEnum>, Error> {
        (*self).last_networking_status()
    }

    fn last_network_id<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(Option<&[u8]>) -> Result<R, Error>,
    {
        (*self).last_network_id(f)
    }

    fn last_connect_error_value(&self) -> Result<Option<i32>, Error> {
        (*self).last_connect_error_value()
    }
}

/// The system implementation of a handler for the Network Commissioning Matter cluster.
pub struct NetCommHandler<'a, T> {
    dataver: Dataver,
    networks: &'a dyn Networks,
    net_ctl: T,
}

impl<'a, T> NetCommHandler<'a, T> {
    /// Create a new instance of `NetCommHandler` with the given `Dataver`, `Networks` and `NetCtl`.
    pub const fn new(dataver: Dataver, networks: &'a dyn Networks, net_ctl: T) -> Self {
        Self {
            dataver,
            networks,
            net_ctl,
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `AsyncHandler` trait
    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }
}

impl<T> ClusterAsyncHandler for NetCommHandler<'_, T>
where
    T: NetCtl + NetCtlStatus,
{
    const CLUSTER: Cluster<'static> = NetworkType::Ethernet.cluster(); // TODO

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn max_networks(&self, _ctx: &ReadContext<'_>) -> Result<u8, Error> {
        self.networks.max_networks()
    }

    async fn connect_max_time_seconds(&self, _ctx: &ReadContext<'_>) -> Result<u8, Error> {
        Ok(self.net_ctl.connect_max_time_seconds())
    }

    async fn scan_max_time_seconds(&self, _ctx: &ReadContext<'_>) -> Result<u8, Error> {
        Ok(self.net_ctl.scan_max_time_seconds())
    }

    async fn supported_wi_fi_bands<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<
            ToTLVArrayBuilder<P, WiFiBandEnum>,
            ToTLVBuilder<P, WiFiBandEnum>,
        >,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(builder) => builder.with(|builder| {
                let mut builder = Some(builder);

                self.net_ctl.supported_wifi_bands(|band| {
                    builder = Some(unwrap!(builder.take()).push(&band)?);

                    Ok(())
                })?;

                unwrap!(builder.take()).end()
            }),
            ArrayAttributeRead::ReadOne(index, builder) => {
                let mut current = 0;
                let mut builder = Some(builder);
                let mut parent = None;

                self.net_ctl.supported_wifi_bands(|band| {
                    if current == index {
                        parent = Some(unwrap!(builder.take()).set(&band)?);
                    }

                    current += 1;

                    Ok(())
                })?;

                if let Some(parent) = parent {
                    Ok(parent)
                } else {
                    Err(ErrorCode::ConstraintError.into())
                }
            }
        }
    }

    async fn supported_thread_features(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<ThreadCapabilitiesBitmap, Error> {
        Ok(self.net_ctl.supported_thread_features())
    }

    async fn thread_version(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        Ok(self.net_ctl.thread_version())
    }

    async fn networks<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<NetworkInfoStructArrayBuilder<P>, NetworkInfoStructBuilder<P>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(builder) => builder.with(|builder| {
                let mut builder = Some(builder);

                self.networks.networks(&mut |ni| {
                    builder = Some(ni.read_into(unwrap!(builder.take()).push()?)?);

                    Ok(())
                })?;

                unwrap!(builder.take()).end()
            }),
            ArrayAttributeRead::ReadOne(index, builder) => {
                let mut current = 0;
                let mut builder = Some(builder);
                let mut parent = None;

                self.networks.networks(&mut |ni| {
                    if current == index {
                        parent = Some(ni.read_into(unwrap!(builder.take()))?);
                    }

                    current += 1;

                    Ok(())
                })?;

                if let Some(parent) = parent {
                    Ok(parent)
                } else {
                    Err(ErrorCode::ConstraintError.into())
                }
            }
        }
    }

    async fn interface_enabled(&self, _ctx: &ReadContext<'_>) -> Result<bool, Error> {
        self.networks.enabled()
    }

    async fn last_networking_status(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<NetworkCommissioningStatusEnum>, Error> {
        Ok(Nullable::new(self.net_ctl.last_networking_status()?))
    }

    async fn last_network_id<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: NullableBuilder<P, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        self.net_ctl.last_network_id(|network_id| {
            if let Some(network_id) = network_id {
                builder.non_null()?.set(Octets::new(network_id))
            } else {
                builder.null()
            }
        })
    }

    async fn last_connect_error_value(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<i32>, Error> {
        Ok(Nullable::new(self.net_ctl.last_connect_error_value()?))
    }

    async fn set_interface_enabled(
        &self,
        _ctx: &WriteContext<'_>,
        value: bool,
    ) -> Result<(), Error> {
        self.networks.set_enabled(value)
    }

    async fn handle_scan_networks<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: ScanNetworksRequest<'_>,
        response: ScanNetworksResponseBuilder<P>,
    ) -> Result<P, Error> {
        match self.net_ctl.net_type() {
            NetworkType::Thread => {
                let mut builder = Some(response);
                let mut array_builder = None;

                let (status, _, _) = NetworkCommissioningStatusEnum::map_ctl(
                    self.net_ctl
                        .scan(
                            request
                                .ssid()?
                                .as_ref()
                                .and_then(|ssid| ssid.as_opt_ref())
                                .map(|ssid| ssid.0),
                            |network| {
                                let abuilder = if let Some(builder) = builder.take() {
                                    builder
                                        .networking_status(NetworkCommissioningStatusEnum::Success)?
                                        .debug_text(None)?
                                        .wi_fi_scan_results()?
                                        .none()
                                        .thread_scan_results()?
                                        .some()?
                                } else {
                                    unwrap!(array_builder.take())
                                };

                                array_builder = Some(network.thread_read_into(abuilder.push()?)?);

                                Ok(())
                            },
                        )
                        .await
                        .map(|_| 0),
                )?;

                if let Some(builder) = builder {
                    builder
                        .networking_status(status)?
                        .debug_text(None)?
                        .wi_fi_scan_results()?
                        .none()
                        .thread_scan_results()?
                        .none()
                        .end()
                } else {
                    unwrap!(array_builder.take()).end()?.end()
                }
            }
            NetworkType::Wifi => {
                let mut builder = Some(response);
                let mut array_builder = None;

                let (status, _, _) = NetworkCommissioningStatusEnum::map_ctl(
                    self.net_ctl
                        .scan(
                            request
                                .ssid()?
                                .as_ref()
                                .and_then(|ssid| ssid.as_opt_ref())
                                .map(|ssid| ssid.0),
                            |network| {
                                let abuilder = if let Some(builder) = builder.take() {
                                    builder
                                        .networking_status(NetworkCommissioningStatusEnum::Success)?
                                        .debug_text(None)?
                                        .wi_fi_scan_results()?
                                        .some()?
                                } else {
                                    unwrap!(array_builder.take())
                                };

                                array_builder = Some(network.wifi_read_into(abuilder.push()?)?);

                                Ok(())
                            },
                        )
                        .await
                        .map(|_| 0),
                )?;

                if let Some(builder) = builder {
                    builder
                        .networking_status(status)?
                        .debug_text(None)?
                        .wi_fi_scan_results()?
                        .none()
                        .thread_scan_results()?
                        .none()
                        .end()
                } else {
                    unwrap!(array_builder.take())
                        .end()?
                        .thread_scan_results()?
                        .none()
                        .end()
                }
            }
            NetworkType::Ethernet => Err(ErrorCode::InvalidAction.into()), // TODO
        }
    }

    async fn handle_add_or_update_wi_fi_network<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: AddOrUpdateWiFiNetworkRequest<'_>,
        response: NetworkConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        let (status, _, index) = NetworkCommissioningStatusEnum::map(self.networks.add_or_update(
            &WirelessCreds::Wifi {
                ssid: request.ssid()?.0,
                pass: request.credentials()?.0,
            },
        ))?;

        status.read_into(index, response)
    }

    async fn handle_add_or_update_thread_network<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: AddOrUpdateThreadNetworkRequest<'_>,
        response: NetworkConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        let (status, _, index) = NetworkCommissioningStatusEnum::map(self.networks.add_or_update(
            &WirelessCreds::Thread {
                dataset_tlv: request.operational_dataset()?.0,
            },
        ))?;

        status.read_into(index, response)
    }

    async fn handle_remove_network<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: RemoveNetworkRequest<'_>,
        response: NetworkConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        let (status, _, index) =
            NetworkCommissioningStatusEnum::map(self.networks.remove(request.network_id()?.0))?;

        status.read_into(index, response)
    }

    async fn handle_connect_network<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: ConnectNetworkRequest<'_>,
        mut response: ConnectNetworkResponseBuilder<P>,
    ) -> Result<P, Error> {
        if request.network_id()?.0.len() > MAX_WIRELESS_NETWORK_ID_LEN {
            return Err(ErrorCode::InvalidAction.into());
        }

        let (status, err_code) = match self.net_ctl.net_type() {
            NetworkType::Thread => {
                let dataset_buf = response.writer().available_space();
                let mut dataset_len = 0;

                let (mut status, mut err_code, _) = NetworkCommissioningStatusEnum::map(
                    self.networks.creds(request.network_id()?.0, &mut |creds| {
                        let WirelessCreds::Thread { dataset_tlv } = creds else {
                            error!("Thread creds expected");
                            return Err(ErrorCode::InvalidAction.into());
                        };

                        if dataset_tlv.len() > dataset_buf.len() {
                            error!("Dataset too large");
                            return Err(ErrorCode::ConstraintError.into());
                        }

                        dataset_buf[..dataset_tlv.len()].copy_from_slice(dataset_tlv);
                        dataset_len = dataset_tlv.len();

                        Ok(())
                    }),
                )?;

                if matches!(status, NetworkCommissioningStatusEnum::Success) {
                    (status, err_code, _) = NetworkCommissioningStatusEnum::map_ctl(
                        self.net_ctl
                            .connect(&WirelessCreds::Thread {
                                dataset_tlv: &dataset_buf[..dataset_len],
                            })
                            .await,
                    )?;
                }

                (status, err_code)
            }
            NetworkType::Wifi => {
                let buf = response.writer().available_space();
                let (ssid_buf, pass_buf) = buf.split_at_mut(buf.len() / 2);
                let mut ssid_len = 0;
                let mut pass_len = 0;

                let (mut status, mut err_code, _) = NetworkCommissioningStatusEnum::map(
                    self.networks.creds(request.network_id()?.0, &mut |creds| {
                        let WirelessCreds::Wifi { ssid, pass } = creds else {
                            error!("Wifi creds expected");
                            return Err(ErrorCode::InvalidAction.into());
                        };

                        if ssid.len() > ssid_buf.len() {
                            error!("SSID too large");
                            return Err(ErrorCode::ConstraintError.into());
                        }

                        if pass.len() > pass_buf.len() {
                            error!("Password too large");
                            return Err(ErrorCode::ConstraintError.into());
                        }

                        ssid_buf[..ssid.len()].copy_from_slice(ssid);
                        ssid_len = ssid.len();
                        pass_buf[..pass.len()].copy_from_slice(pass);
                        pass_len = pass.len();

                        Ok(())
                    }),
                )?;

                if matches!(status, NetworkCommissioningStatusEnum::Success) {
                    (status, err_code, _) = NetworkCommissioningStatusEnum::map_ctl(
                        self.net_ctl
                            .connect(&WirelessCreds::Wifi {
                                ssid: &ssid_buf[..ssid_len],
                                pass: &pass_buf[..pass_len],
                            })
                            .await,
                    )?;
                }

                (status, err_code)
            }
            NetworkType::Ethernet => {
                return Err(ErrorCode::InvalidAction.into());
            }
        };

        response
            .networking_status(status)?
            .debug_text(None)?
            .error_value(Nullable::new(err_code))?
            .end()
    }

    async fn handle_reorder_network<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: ReorderNetworkRequest<'_>,
        response: NetworkConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        let (status, _, index) = NetworkCommissioningStatusEnum::map(
            self.networks
                .reorder(request.network_index()? as _, request.network_id()?.0),
        )?;

        status.read_into(index, response)
    }

    async fn handle_query_identity<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: QueryIdentityRequest<'_>,
        _response: QueryIdentityResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
}
