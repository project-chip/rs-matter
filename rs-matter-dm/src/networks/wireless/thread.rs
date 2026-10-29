/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! This module contains Thread-specific types.

use core::fmt::{Debug, Display};

use crate::dm::clusters::net_comm::{NetworkType, WirelessCreds};
use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, OctetsOwned, ToTLV};
use crate::utils::init::{init, Init, IntoFallibleInit};
use crate::utils::storage::Vec;

use super::{WirelessNetwork, WirelessNetworks};

pub use rs_matter_node_core::networks::ThreadTLV;

pub type ThreadNetworks<const N: usize> = WirelessNetworks<N, Thread>;

/// A struct implementing the `WirelessNetwork` trait for Thread networks.
#[derive(Debug, Clone, Eq, PartialEq, Hash, ToTLV, FromTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Thread {
    /// Thread dataset in TLV format
    pub dataset: OctetsOwned<256>,
}

impl Default for Thread {
    fn default() -> Self {
        Self::new()
    }
}

impl Thread {
    /// Create a new, empty instance of `Thread`.
    pub const fn new() -> Self {
        Self {
            dataset: OctetsOwned { vec: Vec::new() },
        }
    }

    /// Return an in-place initializer for an empty `Thread` insrtance.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            dataset <- OctetsOwned::init(),
        })
    }

    /// Get the Extended PAN ID from the operational dataset
    pub fn dataset_ext_pan_id(dataset_tlv: &[u8]) -> Result<&[u8], Error> {
        ThreadTLV::new(dataset_tlv).ext_pan_id()
    }

    /// Get the Extended PAN ID from the operational dataset
    pub fn ext_pan_id(&self) -> &[u8] {
        // This unwrap! should never fail because the Thread TLV dataset
        // is checked - upon creation of the `Thread` instance - to be valid,
        // i.e. to contain an Extended PAN ID TLV.
        unwrap!(Self::dataset_ext_pan_id(&self.dataset.vec))
    }
}

impl WirelessNetwork for Thread {
    const NET_TYPE: NetworkType = NetworkType::Thread;

    fn id(&self) -> &[u8] {
        self.ext_pan_id()
    }

    #[cfg(not(feature = "defmt"))]
    fn display_id(id: &[u8]) -> impl Display {
        use super::DisplayId;

        DisplayId::Thread(id)
    }

    #[cfg(feature = "defmt")]
    fn display_id(id: &[u8]) -> impl Display + defmt::Format {
        use super::DisplayId;

        DisplayId::Thread(id)
    }

    fn init_from<'a>(creds: &'a WirelessCreds<'a>) -> impl Init<Self, Error> + 'a {
        Self::init().into_fallible().chain(move |network| {
            let WirelessCreds::Thread { dataset_tlv } = creds else {
                return Err(ErrorCode::InvalidData.into());
            };

            network
                .dataset
                .vec
                .extend_from_slice(dataset_tlv)
                .map_err(|_| ErrorCode::InvalidData)?;

            Ok(())
        })
    }

    fn update(&mut self, creds: &WirelessCreds<'_>) -> Result<(), Error> {
        let WirelessCreds::Thread { dataset_tlv } = creds else {
            return Err(ErrorCode::InvalidData.into());
        };

        if dataset_tlv.len() > self.dataset.vec.capacity() {
            return Err(ErrorCode::InvalidData.into());
        }

        self.dataset.vec.clear();

        unwrap!(self.dataset.vec.extend_from_slice(dataset_tlv));

        Ok(())
    }

    fn creds(&self) -> WirelessCreds<'_> {
        WirelessCreds::Thread {
            dataset_tlv: &self.dataset.vec,
        }
    }
}
