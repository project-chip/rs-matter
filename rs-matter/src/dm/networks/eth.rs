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

//! This module contains the `Networks` trait implementation and the `NetCtl` trait implementation for Ethernet.

use crate::dm::sdm::net_comm::{
    self, NetCtl, NetCtlError, NetCtlStatus, NetworkCommissioningStatusEnum, NetworkScanInfo,
    NetworkType, NetworksError,
};
use crate::error::{Error, ErrorCode};

use crate::dm::sdm::net_comm::WirelessCreds;

/// A fixed `Networks` trait implementation for Ethernet.
///
/// Ethernet does not need to manage networks, so it always reports 1 network
/// and returns an error when trying to add or update networks.
pub struct EthNetwork<'a> {
    network_id: &'a str,
}

impl<'a> EthNetwork<'a> {
    /// Creates a new `EthNetwork` instance.
    pub const fn new(network_id: &'a str) -> Self {
        Self { network_id }
    }
}

impl net_comm::Networks for EthNetwork<'_> {
    fn max_networks(&self) -> Result<u8, Error> {
        Ok(1)
    }

    fn networks(
        &self,
        f: &mut dyn FnMut(&net_comm::NetworkInfo) -> Result<(), Error>,
    ) -> Result<(), Error> {
        f(&net_comm::NetworkInfo {
            network_id: self.network_id.as_bytes(),
            connected: false, // TODO
        })
    }

    fn creds(
        &self,
        _network_id: &[u8],
        _f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<u8, NetworksError> {
        Err(NetworksError::Other(ErrorCode::InvalidAction.into()))
    }

    fn next_creds(
        &self,
        _last_network_id: Option<&[u8]>,
        _f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn enabled(&self) -> Result<bool, Error> {
        Ok(true)
    }

    fn set_enabled(&self, _enabled: bool) -> Result<(), Error> {
        Ok(())
    }

    fn add_or_update(&self, _creds: &WirelessCreds<'_>) -> Result<u8, NetworksError> {
        Err(NetworksError::Other(ErrorCode::InvalidAction.into()))
    }

    fn reorder(&self, _index: u8, _network_id: &[u8]) -> Result<u8, NetworksError> {
        Err(NetworksError::Other(ErrorCode::InvalidAction.into()))
    }

    fn remove(&self, _network_id: &[u8]) -> Result<u8, NetworksError> {
        Err(NetworksError::Other(ErrorCode::InvalidAction.into()))
    }
}

/// A `net_comm::NetCtl` implementation for Ethernet that errors out on all methods.
pub struct EthNetCtl;

impl NetCtl for EthNetCtl {
    fn net_type(&self) -> NetworkType {
        NetworkType::Ethernet
    }

    async fn scan<F>(&self, _network: Option<&[u8]>, _f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>,
    {
        Err(NetCtlError::Other(ErrorCode::InvalidAction.into()))
    }

    async fn connect(&self, _creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        Err(NetCtlError::Other(ErrorCode::InvalidAction.into()))
    }
}

impl NetCtlStatus for EthNetCtl {
    fn last_networking_status(&self) -> Result<Option<NetworkCommissioningStatusEnum>, Error> {
        Ok(None)
    }

    fn last_network_id<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(Option<&[u8]>) -> Result<R, Error>,
    {
        f(None)
    }

    fn last_connect_error_value(&self) -> Result<Option<i32>, Error> {
        Ok(None)
    }
}
