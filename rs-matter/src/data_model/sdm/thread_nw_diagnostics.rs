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

use core::net::Ipv6Addr;

use strum::{EnumDiscriminants, FromRepr};

use crate::data_model::objects::*;
use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV};
use crate::transport::exchange::Exchange;
use crate::{attribute_enum, cluster_attrs, command_enum};

pub const ID: u32 = 0x0036;

#[derive(FromRepr, EnumDiscriminants)]
#[repr(u32)]
pub enum Attributes {
    Channel(AttrType<u16>) = 0x00,
    RoutingRole(AttrType<RoutingRole>) = 0x01,
    NetworkName = 0x02,
    PanId(AttrType<u16>) = 0x03,
    ExtendedPanId(AttrType<u64>) = 0x04,
    MeshLocalPrefix = 0x05,
    OverrunCount(AttrType<u64>) = 0x06,
    NeightborTable = 0x07,
    RouteTable = 0x08,
    PartitionId(AttrType<u32>) = 0x09,
    Weighting(AttrType<u16>) = 0x0a,
    DataVersion(AttrType<u16>) = 0x0b,
    StableDataVersion(AttrType<u16>) = 0x0c,
    LeaderRouterId(AttrType<u8>) = 0x0d,
    DetachedRoleCount(AttrType<u16>) = 0x0e,
    ChildRoleCount(AttrType<u16>) = 0x0f,
    RouterRoleCount(AttrType<u16>) = 0x10,
    LeaderRoleCount(AttrType<u16>) = 0x11,
    AttachAttemptCount(AttrType<u16>) = 0x12,
    PartitionIdChangeCount(AttrType<u16>) = 0x13,
    BetterPartitionAttachChangeCount(AttrType<u16>) = 0x14,
    ParentChangeCount(AttrType<u16>) = 0x15,
    TxTotalCount(AttrType<u32>) = 0x16,
    TxUnicastCount(AttrType<u32>) = 0x17,
    TxBroadcastCount(AttrType<u32>) = 0x18,
    TxAckRequestedCount(AttrType<u32>) = 0x19,
    TxAckedCount(AttrType<u32>) = 0x1a,
    TxNoAckRequestedCount(AttrType<u32>) = 0x1b,
    TxDataCount(AttrType<u32>) = 0x1c,
    TxDataPollCount(AttrType<u32>) = 0x1d,
    TxBeaconCount(AttrType<u32>) = 0x1e,
    TxBeaconRequestCount(AttrType<u32>) = 0x1f,
    TxOtherCount(AttrType<u32>) = 0x20,
    TxRetryCount(AttrType<u32>) = 0x21,
    TxDirectMaxRetryExpiryCount(AttrType<u32>) = 0x22,
    TxIndirectMaxRetryExpiryCount(AttrType<u32>) = 0x23,
    TxErrCcaCount(AttrType<u32>) = 0x24,
    TxErrAbortCount(AttrType<u32>) = 0x25,
    TxErrBusyChannelCount(AttrType<u32>) = 0x26,
    RxTotalCount(AttrType<u32>) = 0x27,
    RxUnicastCount(AttrType<u32>) = 0x28,
    RxBroadcastCount(AttrType<u32>) = 0x29,
    RxDataCount(AttrType<u32>) = 0x2a,
    RxDataPollCount(AttrType<u32>) = 0x2b,
    RxBeaconCount(AttrType<u32>) = 0x2c,
    RxBeaconRequestCount(AttrType<u32>) = 0x2d,
    RxOtherCount(AttrType<u32>) = 0x2e,
    RxAddressFilteredCount(AttrType<u32>) = 0x2f,
    RxDestAddressFilteredCount(AttrType<u32>) = 0x30,
    RxDuplicatedCount(AttrType<u32>) = 0x31,
    RxErrNoFrameCount(AttrType<u32>) = 0x32,
    RxErrUnknownNeightborCount(AttrType<u32>) = 0x33,
    RxErrInvalidSrcAddrCount(AttrType<u32>) = 0x34,
    RxErrSecCount(AttrType<u32>) = 0x35,
    RxErrFcsCount(AttrType<u32>) = 0x36,
    RxErrOtherCount(AttrType<u32>) = 0x37,
    ActiveTimestamp(AttrType<u64>) = 0x38,
    PendingTimestamp(AttrType<u64>) = 0x39,
    Delay(AttrType<u32>) = 0x3a,
    SecurityPolicy = 0x3b,
    ChannelPage0Mask = 0x3c,
    OperationalDatasetComponents = 0x3d,
    ActiveNetworkFaultsList = 0x3e,
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
    revision: 1,
    feature_map: 0,
    attributes: cluster_attrs!(
        Attribute::new(
            AttributesDiscriminants::Channel as _,
            Access::RV,
            Quality::NONE,
        ),
        Attribute::new(
            AttributesDiscriminants::RoutingRole as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::NetworkName as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::PanId as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::ExtendedPanId as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::MeshLocalPrefix as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::NeightborTable as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::RouteTable as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::PartitionId as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::Weighting as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::DataVersion as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::StableDataVersion as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::LeaderRouterId as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::SecurityPolicy as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::ChannelPage0Mask as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::OperationalDatasetComponents as _,
            Access::RV,
            Quality::FIXED,
        ),
        Attribute::new(
            AttributesDiscriminants::ActiveNetworkFaultsList as _,
            Access::RV,
            Quality::FIXED,
        ),
    ),
    accepted_commands: &[CommandsDiscriminants::ResetCounts as _],
    generated_commands: &[],
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV, FromRepr)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum RoutingRole {
    Unspecified = 0,
    Unassigned = 1,
    SleepyEndDevice = 2,
    EndDevice = 3,
    REED = 4,
    Router = 5,
    Leader = 6,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV, FromRepr)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum NetworkFault {
    Unspecified = 0,
    Linkdown = 1,
    HardwareFailure = 2,
    NetworkJammed = 3,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV, FromRepr)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum ConnectionStatus {
    Connected = 0,
    NotConnected = 1,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NeightborTable {
    pub ext_address: u64,
    pub age: u32,
    pub rloc16: u16,
    pub link_frame_counter: u32,
    pub mle_frame_counter: u32,
    pub lqi: u8,
    pub average_rssi: i8,
    pub last_rssi: i8,
    pub frame_error_rate: u8,
    pub message_error_rate: u8,
    pub rx_on_when_idle: bool,
    pub full_thread_device: bool,
    pub full_network_data: bool,
    pub is_child: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteTable {
    pub ext_address: u64,
    pub rloc16: u16,
    pub router_id: u8,
    pub next_hop: u8,
    pub path_cost: u8,
    pub lqi_in: u8,
    pub lqi_out: u8,
    pub age: u8,
    pub allocated: bool,
    pub established: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecurityPolicy {
    pub rotation_time: u16,
    pub flags: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OperationalDatasetComponents {
    pub active_timestamp_present: bool,
    pub pending_timestamp_present: bool,
    pub master_key_present: bool,
    pub network_name_present: bool,
    pub extended_pan_id_present: bool,
    pub mesh_local_prefix_present: bool,
    pub delay_present: bool,
    pub pan_id_present: bool,
    pub channel_present: bool,
    pub pskc_present: bool,
    pub security_policy_present: bool,
    pub channel_mask_present: bool,
}

/// The minimal set of data required to implement the Thread Network Diagnostics Cluster.
pub trait ThreadNwDiagData {
    fn channel(&self) -> u16;

    fn routing_role(&self) -> RoutingRole;

    fn network_name(&self) -> &str;

    fn pan_id(&self) -> u16;

    fn extended_pan_id(&self) -> u64;

    fn mesh_local_prefix(&self) -> (Ipv6Addr, u8);

    fn overrun_count(&self) -> u64;

    fn neightbor_table(&self) -> &[NeightborTable];

    fn route_table(&self) -> &[RouteTable];

    fn partition_id(&self) -> u32;

    fn weighting(&self) -> u16;

    fn data_version(&self) -> u16;

    fn stable_data_version(&self) -> u16;

    fn leader_router_id(&self) -> u8;

    fn security_policy(&self) -> &SecurityPolicy;

    fn channel_page0_mask(&self) -> &[u8];

    fn operational_dataset_components(&self) -> &OperationalDatasetComponents;

    fn active_network_faults_list(&self) -> &[NetworkFault];
}

/// A cluster implementing the Matter Thread Diagnostics Cluster.
pub struct ThreadNwDiagCluster<'a> {
    data_ver: Dataver,
    data: &'a dyn ThreadNwDiagData,
}

impl<'a> ThreadNwDiagCluster<'a> {
    /// Create a new instance.
    pub const fn new(data_ver: Dataver, data: &'a dyn ThreadNwDiagData) -> Self {
        Self { data_ver, data }
    }

    /// Read the value of an attribute.
    pub fn read(
        &self,
        _exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::Channel(codec) => codec.encode(writer, self.data.channel()),
                    Attributes::RoutingRole(codec) => {
                        codec.encode(writer, self.data.routing_role())
                    }
                    Attributes::NetworkName => writer.set(self.data.network_name()),
                    Attributes::PanId(codec) => codec.encode(writer, self.data.pan_id()),
                    Attributes::ExtendedPanId(codec) => {
                        codec.encode(writer, self.data.extended_pan_id())
                    }
                    Attributes::MeshLocalPrefix => {
                        let (ip, mask) = self.data.mesh_local_prefix();

                        let ip_size = (mask / 8 + if mask % 8 > 0 { 1 } else { 0 }) as usize;

                        writer.stri(
                            &AttrDataWriter::TAG,
                            ip_size + 1,
                            core::iter::once(mask).chain(ip.octets().into_iter().take(ip_size)),
                        )
                    }
                    Attributes::OverrunCount(codec) => {
                        codec.encode(writer, self.data.overrun_count())
                    }
                    Attributes::NeightborTable => {
                        writer.start_array(&AttrDataWriter::TAG)?;

                        for table in self.data.neightbor_table() {
                            table.to_tlv(&TLVTag::Anonymous, &mut *writer)?;
                        }

                        writer.end_container()
                    }
                    Attributes::RouteTable => {
                        writer.start_array(&AttrDataWriter::TAG)?;

                        for table in self.data.route_table() {
                            table.to_tlv(&TLVTag::Anonymous, &mut *writer)?;
                        }

                        writer.end_container()
                    }
                    Attributes::PartitionId(codec) => {
                        codec.encode(writer, self.data.partition_id())
                    }
                    Attributes::Weighting(codec) => codec.encode(writer, self.data.weighting()),
                    Attributes::DataVersion(codec) => {
                        codec.encode(writer, self.data.data_version())
                    }
                    Attributes::StableDataVersion(codec) => {
                        codec.encode(writer, self.data.stable_data_version())
                    }
                    Attributes::LeaderRouterId(codec) => {
                        codec.encode(writer, self.data.leader_router_id())
                    }
                    Attributes::SecurityPolicy => writer.set(self.data.security_policy()),
                    Attributes::ChannelPage0Mask => {
                        writer.str(&AttrDataWriter::TAG, self.data.channel_page0_mask())
                    }
                    Attributes::OperationalDatasetComponents => {
                        writer.set(self.data.operational_dataset_components())
                    }
                    Attributes::ActiveNetworkFaultsList => {
                        writer.start_array(&AttrDataWriter::TAG)?;

                        for table in self.data.active_network_faults_list() {
                            table.to_tlv(&TLVTag::Anonymous, &mut *writer)?;
                        }

                        writer.end_container()
                    }
                    _ => Err(ErrorCode::AttributeNotFound.into()),
                }
            }
        } else {
            Ok(())
        }
    }

    /// Write the value of an attribute.
    pub fn write(
        &self,
        _exchange: &Exchange,
        _attr: &AttrDetails,
        data: AttrData,
    ) -> Result<(), Error> {
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

impl Handler for ThreadNwDiagCluster<'_> {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        ThreadNwDiagCluster::read(self, exchange, attr, encoder)
    }

    fn write(&self, exchange: &Exchange, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        ThreadNwDiagCluster::write(self, exchange, attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        ThreadNwDiagCluster::invoke(self, exchange, cmd, data, encoder)
    }
}

impl NonBlockingHandler for ThreadNwDiagCluster<'_> {}
