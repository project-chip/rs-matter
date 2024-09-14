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

//! Native Rust Implementation of Matter (Smart-Home)
//!
//! This crate implements the Matter specification that can be run on embedded devices
//! to build Matter-compatible smart-home/IoT devices.
//!
//! Currently Ethernet based transport is supported.
//!
//! # Examples
//! ```ignore
//! /// TODO: Fix once new API has stabilized a bit
//! use rs_matter::{Matter, CommissioningData};
//! use rs_matter::data_model::device_types::device_type_add_on_off_light;
//! use rs_matter::data_model::cluster_basic_information::BasicInfoConfig;
//! use rs_matter::secure_channel::spake2p::VerifierData;
//!
//! # use rs_matter::data_model::sdm::dev_att::{DataType, DevAttDataFetcher};
//! # use rs_matter::error::Error;
//! # pub struct DevAtt{}
//! # impl DevAttDataFetcher for DevAtt{
//! # fn get_devatt_data(&self, data_type: DataType, data: &mut [u8]) -> Result<usize, Error> { Ok(0) }
//! # }
//! # let dev_att = Box::new(DevAtt{});
//!
//! /// The commissioning data for this device
//! let comm_data = CommissioningData {
//!     verifier: VerifierData::new_with_pw(123456),
//!     discriminator: 250,
//! };
//!
//! /// The basic information about this device
//! let dev_info = BasicInfoConfig {
//!     vid: 0x8000,
//!     pid: 0xFFF1,
//!     hw_ver: 2,
//!     sw_ver: 1,
//!     sw_ver_str: "1".to_string(),
//!     serial_no: "aabbcc".to_string(),
//!     device_name: "OnOff Light".to_string(),
//! };
//!
//! /// Get the Matter Object
//! /// The dev_att is an object that implements the DevAttDataFetcher trait.
//! let mut matter = Matter::new(dev_info, dev_att, comm_data).unwrap();
//! let dm = matter.get_data_model();
//! {
//!     let mut node = dm.node.write().unwrap();
//!     /// Add our device-types
//!     let endpoint = device_type_add_on_off_light(&mut node).unwrap();
//! }
//! // Start the Matter Daemon
//! // matter.start_daemon().unwrap();
//! ```
//!
//! Start off exploring by going to the [Matter] object.
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(async_fn_in_trait)]
#![recursion_limit = "256"]

pub mod acl;
pub mod cert;
pub mod codec;
pub mod core;
pub mod crypto;
pub mod data_model;
pub mod error;
pub mod fabric;
pub mod group_keys;
pub mod interaction_model;
pub mod mdns;
pub mod pairing;
pub mod persist;
pub mod respond;
pub mod secure_channel;
pub mod tlv;
pub mod transport;
pub mod utils;

pub use crate::core::*;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! alloc {
    ($val:expr) => {
        alloc::boxed::Box::new($val)
    };
}

#[cfg(not(feature = "alloc"))]
#[macro_export]
macro_rules! alloc {
    ($val:expr) => {
        $val
    };
}
