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

//! This module contains Wifi-specific types.

use core::fmt::{Debug, Display};

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, OctetsOwned, ToTLV};
use crate::utils::init::{init, Init, IntoFallibleInit};
use crate::utils::storage::Vec;

use crate::dm::sdm::net_comm::WirelessCreds;

use super::{WirelessNetwork, WirelessNetworks};

pub type WifiNetworks<const N: usize, M> = WirelessNetworks<N, M, Wifi>;

/// A struct implementing the `WirelessNetwork` trait for Wifi networks.
#[derive(Debug, Clone, Eq, PartialEq, Hash, ToTLV, FromTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Wifi {
    /// Wifi SSID
    pub ssid: OctetsOwned<32>,
    /// Wifi password
    pub password: OctetsOwned<64>,
}

impl Default for Wifi {
    fn default() -> Self {
        Self::new()
    }
}

impl Wifi {
    /// Create a new, empty instance of `Wifi`.
    pub const fn new() -> Self {
        Self {
            ssid: OctetsOwned { vec: Vec::new() },
            password: OctetsOwned { vec: Vec::new() },
        }
    }

    /// Return an in-place initializer for an empty `Wifi` instance.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            ssid <- OctetsOwned::init(),
            password <- OctetsOwned::init(),
        })
    }
}

impl WirelessNetwork for Wifi {
    fn id(&self) -> &[u8] {
        &self.ssid
    }

    #[cfg(not(feature = "defmt"))]
    fn display_id(id: &[u8]) -> impl Display {
        use super::DisplayId;

        DisplayId::Wifi(id)
    }

    #[cfg(feature = "defmt")]
    fn display_id(id: &[u8]) -> impl Display + defmt::Format {
        use super::DisplayId;

        DisplayId::Wifi(id)
    }

    fn init_from<'a>(creds: &'a WirelessCreds<'a>) -> impl Init<Self, Error> + 'a {
        Self::init().into_fallible().chain(move |network| {
            let WirelessCreds::Wifi { ssid, pass } = creds else {
                return Err(ErrorCode::InvalidData.into());
            };

            network
                .ssid
                .vec
                .extend_from_slice(ssid)
                .map_err(|_| ErrorCode::InvalidData)?;
            network
                .password
                .vec
                .extend_from_slice(pass)
                .map_err(|_| ErrorCode::InvalidData)?;

            Ok(())
        })
    }

    fn update(&mut self, creds: &WirelessCreds<'_>) -> Result<(), Error> {
        let WirelessCreds::Wifi { ssid, pass } = creds else {
            return Err(ErrorCode::InvalidData.into());
        };

        if ssid.len() > self.ssid.vec.capacity() {
            return Err(ErrorCode::InvalidData.into());
        }

        if pass.len() > self.password.vec.capacity() {
            return Err(ErrorCode::InvalidData.into());
        }

        self.ssid.vec.clear();
        self.password.vec.clear();

        unwrap!(self.ssid.vec.extend_from_slice(ssid));
        unwrap!(self.password.vec.extend_from_slice(pass));

        Ok(())
    }

    fn creds(&self) -> WirelessCreds<'_> {
        WirelessCreds::Wifi {
            ssid: &self.ssid.vec,
            pass: &self.password.vec,
        }
    }
}
