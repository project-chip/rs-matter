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

use crate::{
    attribute_enum,
    data_model::objects::{
        Access, AttrDataEncoder, AttrDataWriter, AttrDetails, AttrType, Attribute, ChangeNotifier,
        Cluster, Dataver, Handler, NonBlockingHandler, Quality, ATTRIBUTE_LIST, FEATURE_MAP,
    },
    error::Error,
    tlv::{OctetStr, TagType, ToTLV},
    utils::rand::Rand,
};

pub const ID: u32 = 0x0031;

#[derive(FromRepr)]
#[repr(u16)]
pub enum Attributes {
    MaxNetworks = 0x00,
    Networks = 0x01,
    ConnectMaxTimeSecs = 0x03,
    InterfaceEnabled = 0x04,
    LastNetworkingStatus = 0x05,
    LastNetworkID = 0x06,
    LastConnectErrorValue = 0x07,
}

attribute_enum!(Attributes);

enum FeatureMap {
    _Wifi = 0x01,
    _Thread = 0x02,
    Ethernet = 0x04,
}

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    feature_map: FeatureMap::Ethernet as _,
    attributes: &[
        FEATURE_MAP,
        ATTRIBUTE_LIST,
        Attribute::new(Attributes::MaxNetworks as u16, Access::RA, Quality::F),
        Attribute::new(Attributes::Networks as u16, Access::RA, Quality::NONE),
        Attribute::new(
            Attributes::ConnectMaxTimeSecs as u16,
            Access::RV,
            Quality::F,
        ),
        Attribute::new(
            Attributes::InterfaceEnabled as u16,
            Access::RWVA,
            Quality::N,
        ),
        Attribute::new(
            Attributes::LastNetworkingStatus as u16,
            Access::RA,
            Quality::X,
        ),
        Attribute::new(Attributes::LastNetworkID as u16, Access::RA, Quality::X),
        Attribute::new(
            Attributes::LastConnectErrorValue as u16,
            Access::RA,
            Quality::X,
        ),
    ],
    commands: &[],
};

#[derive(Clone)]
pub struct NwCommCluster {
    data_ver: Dataver,
}

impl NwCommCluster {
    pub fn new(rand: Rand) -> Self {
        Self {
            data_ver: Dataver::new(rand),
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

#[derive(ToTLV)]
struct NwInfo<'a> {
    network_id: OctetStr<'a>,
    connected: bool,
}

struct NwMetaInfo<'a> {
    nw_info: NwInfo<'a>,
    connect_max_time_secs: u8,
    interface_enabled: bool,
    last_nw_status: NetworkCommissioningStatus,
}

#[allow(dead_code)]
enum NetworkCommissioningStatus {
    Success = 0,
    OutOfRange = 1,
    BoundsExceeded = 2,
    NetworkIDNotFound = 3,
    DuplicateNetworkID = 4,
    NetworkNotFound = 5,
    RegulatoryError = 6,
    AuthFailure = 7,
    UnsupportedSecurity = 8,
    OtherConnectionFailure = 9,
    IPV6Failed = 10,
    IPBindFailed = 11,
    UnknownError = 12,
}

impl Handler for NwCommCluster {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        let info = self.get_network_info();
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::MaxNetworks => AttrType::<u8>::new().encode(writer, 1),
                    Attributes::Networks => {
                        writer.start_array(AttrDataWriter::TAG)?;
                        info.nw_info.to_tlv(&mut writer, TagType::Anonymous)?;
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
                            .to_tlv(&mut writer, AttrDataWriter::TAG)?;
                        writer.complete()
                    }
                    Attributes::LastConnectErrorValue => {
                        writer.null(AttrDataWriter::TAG)?;
                        writer.complete()
                    }
                }
            }
        } else {
            Ok(())
        }
    }
}

impl NonBlockingHandler for NwCommCluster {}

impl ChangeNotifier<()> for NwCommCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
