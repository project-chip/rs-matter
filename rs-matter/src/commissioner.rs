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

//! Matter Commissioner support.
//!
//! This module provides the building blocks for implementing a Matter commissioner,
//! which is responsible for commissioning devices into a fabric.
//!
//! # Overview
//!
//! A commissioner needs to:
//! 1. Discover commissionable devices (via mDNS)
//! 2. Establish a PASE session using the device's setup code
//! 3. Configure the device (regulatory config, time, etc.)
//! 4. Generate and provision operational credentials (NOC, ICAC, RCAC)
//! 5. Establish a CASE session using the provisioned credentials
//!
//! This module provides the credential generation components (steps 4).
//!
//! # Modules
//!
//! - [`ipk`] - Identity Protection Key (IPK) generation
//! - [`noc_generator`] - NOC/ICAC/RCAC certificate generation
//! - [`fabric_credentials`] - High-level fabric credential management
//!
//! # Example
//!
//! ```ignore
//! use rs_matter::commissioner::FabricCredentials;
//!
//! // Choose a unique fabric ID for your fabric
//! let fabric_id = 0x0000_0000_0000_0001u64;
//!
//! // Create credentials for a new fabric
//! let mut fabric_creds = FabricCredentials::new(&crypto, fabric_id)?;
//!
//! // After PASE session is established, request a CSR from the device
//! let csr = im_client.csr_request(&mut exchange, &nonce, false).await?;
//!
//! // Generate credentials for the device
//! let device_creds = fabric_creds.generate_device_credentials(&crypto, &csr, &[])?;
//!
//! // Provision the device
//! im_client.add_trusted_root_certificate(&mut exchange, &device_creds.root_cert).await?;
//! im_client.add_noc(
//!     &mut exchange,
//!     &device_creds.noc,
//!     device_creds.icac.as_deref(),
//!     &device_creds.ipk,
//!     admin_subject,
//!     vendor_id,
//! ).await?;
//! ```

pub mod fabric_credentials;
pub mod noc_generator;

pub use fabric_credentials::{DeviceCredentials, FabricCredentials};
pub use noc_generator::{NocCredentials, NocGenerator};
