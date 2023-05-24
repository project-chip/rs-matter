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

//! This module contains the logic for generating the pairing code and the QR code for easy pairing.

pub mod code;
pub mod qr;
pub mod vendor_identifiers;

use log::info;
use verhoeff::Verhoeff;

use crate::{
    codec::base38, data_model::cluster_basic_information::BasicInfoConfig, error::Error,
    secure_channel::spake2p::VerifierOption, CommissioningData,
};

use self::{
    code::{compute_pairing_code, pretty_print_pairing_code},
    qr::{compute_qr_code, print_qr_code},
};

pub struct DiscoveryCapabilities {
    on_ip_network: bool,
    ble: bool,
    soft_access_point: bool,
}

impl DiscoveryCapabilities {
    pub fn new(on_ip_network: bool, ble: bool, soft_access_point: bool) -> Self {
        DiscoveryCapabilities {
            on_ip_network,
            ble,
            soft_access_point,
        }
    }

    pub fn has_value(&self) -> bool {
        self.on_ip_network || self.ble || self.soft_access_point
    }
}

impl Default for DiscoveryCapabilities {
    fn default() -> Self {
        DiscoveryCapabilities {
            on_ip_network: true,
            ble: false,
            soft_access_point: false,
        }
    }
}

impl DiscoveryCapabilities {
    fn as_bits(&self) -> u8 {
        let mut bits = 0;
        if self.soft_access_point {
            bits |= 1 << 0;
        }
        if self.ble {
            bits |= 1 << 1;
        }
        if self.on_ip_network {
            bits |= 1 << 2;
        }
        bits
    }
}

/// Prepares and prints the pairing code and the QR code for easy pairing.
pub fn print_pairing_code_and_qr(
    dev_det: &BasicInfoConfig,
    comm_data: &CommissioningData,
    discovery_capabilities: DiscoveryCapabilities,
    buf: &mut [u8],
) -> Result<(), Error> {
    let pairing_code = compute_pairing_code(comm_data);
    let qr_code = compute_qr_code(dev_det, comm_data, discovery_capabilities, buf)?;

    pretty_print_pairing_code(&pairing_code);
    print_qr_code(qr_code);

    Ok(())
}

pub(self) fn passwd_from_comm_data(comm_data: &CommissioningData) -> u32 {
    // todo: should this be part of the comm_data implementation?
    match comm_data.verifier.data {
        VerifierOption::Password(pwd) => pwd,
        VerifierOption::Verifier(_) => 0,
    }
}
