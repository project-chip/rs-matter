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

use strum::FromRepr;

use crate::data_model::objects::{
    Access, AttrDataEncoder, AttrDataWriter, AttrDetails, AttrType, Attribute, ChangeNotifier,
    Cluster, Dataver, Handler, NonBlockingHandler, Quality, ATTRIBUTE_LIST, FEATURE_MAP,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, OctetStr, TLVArray, TLVTag, TLVWrite, ToTLV};
use crate::transport::exchange::Exchange;
use crate::utils::bitflags::bitflags;
use crate::{attribute_enum, bitflags_tlv, command_enum};

pub const ID: u32 = 0x0031;

#[derive(FromRepr)]
#[repr(u16)]
pub enum Attributes {
    MaxNetworks = 0x00,
    Networks = 0x01,
    ScanMaxTimeSecs = 0x02,
    ConnectMaxTimeSecs = 0x03,
    InterfaceEnabled = 0x04,
    LastNetworkingStatus = 0x05,
    LastNetworkID = 0x06,
    LastConnectErrorValue = 0x07,
}

attribute_enum!(Attributes);

#[derive(Debug, FromRepr)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u32)]
pub enum Commands {
    ScanNetworks = 0x00,
    AddOrUpdateWifiNetwork = 0x02,
    AddOrUpdateThreadNetwork = 0x03,
    RemoveNetwork = 0x04,
    ConnectNetwork = 0x06,
    ReorderNetwork = 0x08,
}

#[derive(FromRepr)]
#[repr(u32)]
pub enum ResponseCommands {
    ScanNetworksResponse = 0x01,
    NetworkConfigResponse = 0x05,
    ConnectNetworkResponse = 0x07,
}

command_enum!(Commands);

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum FeatureMap {
    Wifi = 0x01,
    Thread = 0x02,
    Ethernet = 0x04,
}

pub const ATTR_MAX_NETWORKS: Attribute =
    Attribute::new(Attributes::MaxNetworks as u16, Access::RA, Quality::F);
pub const ATTR_NETWORKS: Attribute =
    Attribute::new(Attributes::Networks as u16, Access::RA, Quality::NONE);
pub const ATTR_SCAN_MAX_TIME_SECS: Attribute =
    Attribute::new(Attributes::ScanMaxTimeSecs as u16, Access::RV, Quality::F);
pub const ATTR_CONNECT_MAX_TIME_SECS: Attribute = Attribute::new(
    Attributes::ConnectMaxTimeSecs as u16,
    Access::RV,
    Quality::F,
);
pub const ATTR_INTERFACE_ENABLED: Attribute = Attribute::new(
    Attributes::InterfaceEnabled as u16,
    Access::RWVA,
    Quality::N,
);
pub const ATTR_LAST_NETWORKING_STATUS: Attribute = Attribute::new(
    Attributes::LastNetworkingStatus as u16,
    Access::RA,
    Quality::X,
);
pub const ATTR_LAST_NETWORK_ID: Attribute =
    Attribute::new(Attributes::LastNetworkID as u16, Access::RA, Quality::X);
pub const ATTR_LAST_CONNECT_ERROR_VALUE: Attribute = Attribute::new(
    Attributes::LastConnectErrorValue as u16,
    Access::RA,
    Quality::X,
);

const fn cluster(feature_map: FeatureMap) -> Cluster<'static> {
    Cluster {
        id: ID as _,
        feature_map: feature_map as u32,
        attributes: match feature_map {
            FeatureMap::Wifi | FeatureMap::Thread => &[
                FEATURE_MAP,
                ATTRIBUTE_LIST,
                ATTR_MAX_NETWORKS,
                ATTR_NETWORKS,
                ATTR_SCAN_MAX_TIME_SECS,
                ATTR_CONNECT_MAX_TIME_SECS,
                ATTR_INTERFACE_ENABLED,
                ATTR_LAST_NETWORKING_STATUS,
                ATTR_LAST_NETWORK_ID,
                ATTR_LAST_CONNECT_ERROR_VALUE,
            ],
            FeatureMap::Ethernet => &[
                FEATURE_MAP,
                ATTRIBUTE_LIST,
                ATTR_MAX_NETWORKS,
                ATTR_NETWORKS,
                ATTR_CONNECT_MAX_TIME_SECS,
                ATTR_INTERFACE_ENABLED,
                ATTR_LAST_NETWORKING_STATUS,
                ATTR_LAST_NETWORK_ID,
                ATTR_LAST_CONNECT_ERROR_VALUE,
            ],
        },
        commands: match feature_map {
            FeatureMap::Wifi => &[
                Commands::ScanNetworks as _,
                Commands::AddOrUpdateWifiNetwork as _,
                Commands::RemoveNetwork as _,
                Commands::ConnectNetwork as _,
                Commands::ReorderNetwork as _,
            ],
            FeatureMap::Thread => &[
                Commands::ScanNetworks as _,
                Commands::AddOrUpdateThreadNetwork as _,
                Commands::RemoveNetwork as _,
                Commands::ConnectNetwork as _,
                Commands::ReorderNetwork as _,
            ],
            FeatureMap::Ethernet => &[],
        },
    }
}

pub const ETH_CLUSTER: Cluster<'static> = cluster(FeatureMap::Ethernet);
pub const WIFI_CLUSTER: Cluster<'static> = cluster(FeatureMap::Wifi);
pub const THR_CLUSTER: Cluster<'static> = cluster(FeatureMap::Thread);

bitflags! {
    #[repr(transparent)]
    #[derive(Default)]
    pub struct WiFiSecurity: u8 {
        const UNENCRYPTED = 0x01;
        const WEP = 0x02;
        const WPA_PERSONAL = 0x04;
        const WPA2_PERSONAL = 0x08;
        const WPA3_PERSONAL = 0x10;
    }
}

bitflags_tlv!(WiFiSecurity, u8);

#[derive(Debug, Copy, Clone, Eq, PartialEq, FromTLV, ToTLV, FromRepr)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum WifiBand {
    B2G4 = 0,
    B3G65 = 1,
    B5G = 2,
    B6G = 3,
    B60G = 4,
    B1G = 5,
}

#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct ScanNetworksRequest<'a> {
    pub ssid: Option<OctetStr<'a>>,
    pub breadcrumb: Option<u64>,
}

#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct ScanNetworksResponse<'a> {
    pub status: NetworkCommissioningStatus,
    pub debug_text: Option<OctetStr<'a>>,
    pub wifi_scan_results: Option<TLVArray<'a, WiFiInterfaceScanResult<'a>>>,
    pub thread_scan_results: Option<TLVArray<'a, ThreadInterfaceScanResult<'a>>>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ScanNetworksResponseTag {
    Status = 0,
    DebugText = 1,
    WifiScanResults = 2,
    ThreadScanResults = 3,
}

#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct AddWifiNetworkRequest<'a> {
    pub ssid: OctetStr<'a>,
    pub credentials: OctetStr<'a>,
    pub breadcrumb: Option<u64>,
}

#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct AddThreadNetworkRequest<'a> {
    pub op_dataset: OctetStr<'a>,
    pub breadcrumb: Option<u64>,
}

#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct RemoveNetworkRequest<'a> {
    pub network_id: OctetStr<'a>,
    pub breadcrumb: Option<u64>,
}

#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct NetworkConfigResponse<'a> {
    pub status: NetworkCommissioningStatus,
    pub debug_text: Option<OctetStr<'a>>,
    pub network_index: Option<u8>,
}

pub type ConnectNetworkRequest<'a> = RemoveNetworkRequest<'a>;

#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct ReorderNetworkRequest<'a> {
    pub network_id: OctetStr<'a>,
    pub index: u8,
    pub breadcrumb: Option<u64>,
}

#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct ConnectNetworkResponse<'a> {
    pub status: NetworkCommissioningStatus,
    pub debug_text: Option<OctetStr<'a>>,
    pub error_value: i32,
}

#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct WiFiInterfaceScanResult<'a> {
    pub security: WiFiSecurity,
    pub ssid: OctetStr<'a>,
    pub bssid: OctetStr<'a>,
    pub channel: u16,
    pub band: Option<WifiBand>,
    pub rssi: Option<i8>,
}

#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct ThreadInterfaceScanResult<'a> {
    pub pan_id: u16,
    pub extended_pan_id: u64,
    pub network_name: OctetStr<'a>,
    pub channel: u16,
    pub version: u8,
    pub extended_address: OctetStr<'a>,
    pub rssi: i8,
    pub lqi: u8,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EthNwCommCluster {
    data_ver: Dataver,
}

impl EthNwCommCluster {
    pub const fn new(data_ver: Dataver) -> Self {
        Self { data_ver }
    }

    pub fn read(
        &self,
        _exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        let info = self.get_network_info();
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                ETH_CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::MaxNetworks => AttrType::<u8>::new().encode(writer, 1),
                    Attributes::Networks => {
                        writer.start_array(&AttrDataWriter::TAG)?;
                        info.nw_info.to_tlv(&TLVTag::Anonymous, &mut *writer)?;
                        writer.end_container()?;
                        writer.complete()
                    }
                    Attributes::ConnectMaxTimeSecs => {
                        AttrType::<u8>::new().encode(writer, info.connect_max_time_secs)
                    }
                    Attributes::InterfaceEnabled => {
                        AttrType::<bool>::new().encode(writer, info.interface_enabled)
                    }
                    Attributes::LastNetworkingStatus => {
                        AttrType::<u8>::new().encode(writer, info.last_nw_status as u8)
                    }
                    Attributes::LastNetworkID => {
                        info.nw_info
                            .network_id
                            .to_tlv(&AttrDataWriter::TAG, &mut *writer)?;
                        writer.complete()
                    }
                    Attributes::LastConnectErrorValue => {
                        writer.null(&AttrDataWriter::TAG)?;
                        writer.complete()
                    }
                    _ => Err(ErrorCode::AttributeNotFound.into()),
                }
            }
        } else {
            Ok(())
        }
    }

    fn get_network_info(&self) -> NwMetaInfo<'static> {
        // Only single, Ethernet, supported for now
        let nw_info = NwInfo {
            network_id: OctetStr::new(b"en0"),
            connected: true,
        };
        NwMetaInfo {
            nw_info,
            connect_max_time_secs: 60,
            interface_enabled: true,
            last_nw_status: NetworkCommissioningStatus::Success,
        }
    }
}

#[derive(Debug, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct NwInfo<'a> {
    pub network_id: OctetStr<'a>,
    pub connected: bool,
}

struct NwMetaInfo<'a> {
    nw_info: NwInfo<'a>,
    connect_max_time_secs: u8,
    interface_enabled: bool,
    last_nw_status: NetworkCommissioningStatus,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, FromRepr, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum NetworkCommissioningStatus {
    Success = 0,
    OutOfRange = 1,
    BoundsExceeded = 2,
    NetworkIdNotFound = 3,
    DuplicateNetworkId = 4,
    NetworkNotFound = 5,
    RegulatoryError = 6,
    AuthFailure = 7,
    UnsupportedSecurity = 8,
    OtherConnectionFailure = 9,
    IPV6Failed = 10,
    IPBindFailed = 11,
    UnknownError = 12,
}

impl Handler for EthNwCommCluster {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        EthNwCommCluster::read(self, exchange, attr, encoder)
    }
}

impl NonBlockingHandler for EthNwCommCluster {}

impl ChangeNotifier<()> for EthNwCommCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
