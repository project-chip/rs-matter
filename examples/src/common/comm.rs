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

//! A module containing a "fake" Wifi Network Commissioning cluster

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use log::{error, info, warn};

use rs_matter::data_model::objects::{
    AttrDataEncoder, AttrDataWriter, AttrDetails, AttrType, CmdDataEncoder, CmdDetails, Dataver,
    Handler, NonBlockingHandler,
};
use rs_matter::data_model::sdm::nw_commissioning::{
    AddWifiNetworkRequest, Attributes, Commands, ConnectNetworkRequest, ConnectNetworkResponse,
    NetworkCommissioningStatus, NetworkConfigResponse, RemoveNetworkRequest, ReorderNetworkRequest,
    ResponseCommands, ScanNetworksRequest, WIFI_CLUSTER,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::interaction_model::core::IMStatusCode;
use rs_matter::interaction_model::messages::ib::Status;
use rs_matter::tlv::{FromTLV, Octets, TLVElement, TLVWrite};
use rs_matter::transport::exchange::Exchange;
use rs_matter::utils::sync::Notification;

/// A _fake_ cluster implementing the Matter Network Commissioning Cluster
/// for managing WiFi networks.
///
/// We only pretend to manage these for the purposes of the BT demo.
pub struct WifiNwCommCluster<'a> {
    data_ver: Dataver,
    nw_setup_complete: &'a Notification<NoopRawMutex>,
}

impl<'a> WifiNwCommCluster<'a> {
    /// Create a new instance.
    pub const fn new(data_ver: Dataver, nw_setup_complete: &'a Notification<NoopRawMutex>) -> Self {
        Self {
            data_ver,
            nw_setup_complete,
        }
    }

    /// Read an attribute.
    pub fn read(
        &self,
        _exchange: &Exchange,
        attr: &AttrDetails<'_>,
        encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? else {
            return Ok(());
        };

        if attr.is_system() {
            return WIFI_CLUSTER.read(attr.attr_id, writer);
        }

        match attr.attr_id.try_into()? {
            Attributes::MaxNetworks => AttrType::<u8>::new().encode(writer, 1_u8),
            Attributes::Networks => {
                writer.start_array(&AttrDataWriter::TAG)?;

                writer.end_container()?;
                writer.complete()
            }
            Attributes::ScanMaxTimeSecs => AttrType::new().encode(writer, 30_u8),
            Attributes::ConnectMaxTimeSecs => AttrType::new().encode(writer, 60_u8),
            Attributes::InterfaceEnabled => AttrType::new().encode(writer, true),
            Attributes::LastNetworkingStatus => AttrType::new().encode(writer, 0_u8),
            Attributes::LastNetworkID => AttrType::new().encode(writer, Octets("ssid".as_bytes())),
            Attributes::LastConnectErrorValue => AttrType::new().encode(writer, 0),
        }
    }

    /// Invoke a command.
    pub fn invoke(
        &self,
        exchange: &Exchange<'_>,
        cmd: &CmdDetails<'_>,
        data: &TLVElement<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        match cmd.cmd_id.try_into()? {
            Commands::ScanNetworks => {
                info!("ScanNetworks");
                self.scan_networks(exchange, &ScanNetworksRequest::from_tlv(data)?, encoder)?;
            }
            Commands::AddOrUpdateWifiNetwork => {
                info!("AddOrUpdateWifiNetwork");
                self.add_network(exchange, &AddWifiNetworkRequest::from_tlv(data)?, encoder)?;
            }
            Commands::RemoveNetwork => {
                info!("RemoveNetwork");
                self.remove_network(exchange, &RemoveNetworkRequest::from_tlv(data)?, encoder)?;
            }
            Commands::ConnectNetwork => {
                info!("ConnectNetwork");
                self.connect_network(exchange, &ConnectNetworkRequest::from_tlv(data)?, encoder)?;
            }
            Commands::ReorderNetwork => {
                info!("ReorderNetwork");
                self.reorder_network(exchange, &ReorderNetworkRequest::from_tlv(data)?, encoder)?;
            }
            other => {
                error!("{other:?} (not supported)");
                Err(ErrorCode::CommandNotFound)?
            }
        }

        self.data_ver.changed();

        Ok(())
    }

    fn scan_networks(
        &self,
        _exchange: &Exchange<'_>,
        _req: &ScanNetworksRequest<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        let writer = encoder.with_command(ResponseCommands::ScanNetworksResponse as _)?;

        warn!("Scan network not supported");

        writer.set(Status::new(IMStatusCode::Busy, 0))?;

        Ok(())
    }

    fn add_network(
        &self,
        _exchange: &Exchange<'_>,
        req: &AddWifiNetworkRequest<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        let writer = encoder.with_command(ResponseCommands::NetworkConfigResponse as _)?;

        info!(
            "Updated network with SSID {}",
            core::str::from_utf8(req.ssid.0).unwrap()
        );

        writer.set(NetworkConfigResponse {
            status: NetworkCommissioningStatus::Success,
            debug_text: None,
            network_index: Some(0 as _),
        })?;

        Ok(())
    }

    fn remove_network(
        &self,
        _exchange: &Exchange<'_>,
        req: &RemoveNetworkRequest<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        let writer = encoder.with_command(ResponseCommands::NetworkConfigResponse as _)?;

        info!(
            "Removed network with SSID {}",
            core::str::from_utf8(req.network_id.0).unwrap()
        );

        writer.set(NetworkConfigResponse {
            status: NetworkCommissioningStatus::Success,
            debug_text: None,
            network_index: Some(0 as _),
        })?;

        Ok(())
    }

    fn connect_network(
        &self,
        _exchange: &Exchange<'_>,
        req: &ConnectNetworkRequest<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        // Non-concurrent commissioning scenario
        // (i.e. only BLE is active, and the device BLE+Wifi co-exist
        // driver is not running, or does not even exist)

        info!(
            "Request to connect to network with SSID {} received",
            core::str::from_utf8(req.network_id.0).unwrap(),
        );

        let writer = encoder.with_command(ResponseCommands::ConnectNetworkResponse as _)?;

        // As per spec, return success even though though whether we'll be able to connect to the network
        // will become apparent later, once we switch to Wifi
        writer.set(ConnectNetworkResponse {
            status: NetworkCommissioningStatus::Success,
            debug_text: None,
            error_value: 0,
        })?;

        // Wifi setup is complete, UDP stack can run now
        self.nw_setup_complete.notify();

        Ok(())
    }

    fn reorder_network(
        &self,
        _exchange: &Exchange<'_>,
        req: &ReorderNetworkRequest<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        let writer = encoder.with_command(ResponseCommands::NetworkConfigResponse as _)?;

        info!(
            "Network with SSID {} reordered to index {}",
            core::str::from_utf8(req.network_id.0).unwrap(),
            req.index
        );

        writer.set(NetworkConfigResponse {
            status: NetworkCommissioningStatus::Success,
            debug_text: None,
            network_index: Some(req.index as _),
        })?;

        Ok(())
    }
}

impl Handler for WifiNwCommCluster<'_> {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        WifiNwCommCluster::read(self, exchange, attr, encoder)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        WifiNwCommCluster::invoke(self, exchange, cmd, data, encoder)
    }
}

impl NonBlockingHandler for WifiNwCommCluster<'_> {}
