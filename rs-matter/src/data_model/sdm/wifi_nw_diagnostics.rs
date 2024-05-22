/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
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

use core::cell::RefCell;

use crate::{
    attribute_enum, command_enum,
    data_model::objects::*,
    error::{Error, ErrorCode},
    tlv::{TLVElement, TagType},
    transport::exchange::Exchange,
    utils::rand::Rand,
};

use log::info;

use rs_matter_macros::{FromTLV, ToTLV};
use strum::{EnumDiscriminants, FromRepr};

pub const ID: u32 = 0x0036;

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u16)]
pub enum Attributes {
    Bssid = 0x00,
    SecurityType(AttrType<WiFiSecurity>) = 0x01,
    WifiVersion(AttrType<WiFiVersion>) = 0x02,
    ChannelNumber(AttrType<u16>) = 0x03,
    Rssi(AttrType<i8>) = 0x04,
    BeaconLostCount(AttrType<u32>) = 0x05,
    BeaconRxCount(AttrType<u32>) = 0x06,
    PacketMulticastRxCount(AttrType<u32>) = 0x07,
    PacketMulticastTxCount(AttrType<u32>) = 0x08,
    PacketUnicastRxCount(AttrType<u32>) = 0x09,
    PacketUnicastTxCount(AttrType<u32>) = 0x0a,
    CurrentMaxRate(AttrType<u64>) = 0x0b,
    OverrunCount(AttrType<u64>) = 0x0c,
}

attribute_enum!(Attributes);

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u32)]
pub enum Commands {
    ResetCounts = 0x0,
}

command_enum!(Commands);

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    feature_map: 0,
    attributes: &[
        FEATURE_MAP,
        ATTRIBUTE_LIST,
        Attribute::new(
            AttributesDiscriminants::Bssid as u16,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::SecurityType as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::WifiVersion as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::ChannelNumber as u16,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::Rssi as u16,
            Access::RV,
            Quality::FIXED,
        ),
    ],
    commands: &[CommandsDiscriminants::ResetCounts as _],
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, FromTLV, ToTLV, FromRepr)]
#[repr(u8)]
pub enum WiFiSecurity {
    Unspecified = 0,
    Unencrypted = 1,
    Wep = 2,
    WpaPersonal = 3,
    Wpa2Personal = 4,
    Wpa3Personal = 5,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, FromTLV, ToTLV, FromRepr)]
#[repr(u8)]
pub enum WiFiVersion {
    A = 0,
    B = 1,
    G = 2,
    N = 3,
    AC = 4,
    AX = 5,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, FromTLV, ToTLV, FromRepr)]
#[repr(u8)]
pub enum AssociationFailure {
    Unknown = 0,
    AssociationFailed = 1,
    AuthenticationFailed = 2,
    SsidNotFound = 3,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, FromTLV, ToTLV, FromRepr)]
#[repr(u8)]
pub enum ConnectionStatus {
    Connected = 0,
    NotConnected = 1,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WifiNwDiagData {
    pub bssid: [u8; 6],
    pub security_type: WiFiSecurity,
    pub wifi_version: WiFiVersion,
    pub channel_number: u16,
    pub rssi: i8,
}

/// A cluster implementing the Matter Wifi Diagnostics Cluster.
#[derive(Clone)]
pub struct WifiNwDiagCluster {
    data_ver: Dataver,
    data: RefCell<WifiNwDiagData>,
}

impl WifiNwDiagCluster {
    /// Create a new instance.
    pub fn new(rand: Rand, data: WifiNwDiagData) -> Self {
        Self {
            data_ver: Dataver::new(rand),
            data: RefCell::new(data),
        }
    }

    pub fn set(&self, data: WifiNwDiagData) -> bool {
        if *self.data.borrow() != data {
            *self.data.borrow_mut() = data;
            self.data_ver.changed();

            true
        } else {
            false
        }
    }

    /// Read the value of an attribute.
    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                let data = self.data.borrow();

                match attr.attr_id.try_into()? {
                    Attributes::Bssid => writer.str8(TagType::Anonymous, &data.bssid),
                    Attributes::SecurityType(codec) => codec.encode(writer, data.security_type),
                    Attributes::WifiVersion(codec) => codec.encode(writer, data.wifi_version),
                    Attributes::ChannelNumber(codec) => codec.encode(writer, data.channel_number),
                    Attributes::Rssi(codec) => codec.encode(writer, data.rssi),
                    _ => Err(ErrorCode::AttributeNotFound.into()),
                }
            }
        } else {
            Ok(())
        }
    }

    /// Write the value of an attribute.
    pub fn write(&self, _attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        let _data = data.with_dataver(self.data_ver.get())?;

        self.data_ver.changed();

        Ok(())
    }

    /// Invoke a command.
    pub fn invoke(
        &self,
        _exchange: &Exchange,
        cmd: &CmdDetails,
        _data: &TLVElement,
        _encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        match cmd.cmd_id.try_into()? {
            Commands::ResetCounts => {
                info!("ResetCounts: Not yet supported");
            }
        }

        self.data_ver.changed();

        Ok(())
    }
}

impl Handler for WifiNwDiagCluster {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        WifiNwDiagCluster::read(self, attr, encoder)
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        WifiNwDiagCluster::write(self, attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        WifiNwDiagCluster::invoke(self, exchange, cmd, data, encoder)
    }
}

impl NonBlockingHandler for WifiNwDiagCluster {}
