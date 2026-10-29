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

//! Logging for the generated cluster code.
//!
//! Depending on the enabled features, these functions log with `log`, with `defmt`, or not at all.
//! They exist so that the generated code does not need a logging macro for each of its
//! thousands of call sites, as each one takes time to type-check.

use crate::{AttrDetails, CmdDetails};

/// A value that can be logged.
///
/// This trait extends `Debug` with feature `log` and `defmt::Format` with feature `defmt`,
/// and is implemented for every type that is both.
#[cfg(all(feature = "log", feature = "defmt"))]
pub trait Loggable: core::fmt::Debug + defmt::Format {}

#[cfg(all(feature = "log", feature = "defmt"))]
impl<T: ?Sized + core::fmt::Debug + defmt::Format> Loggable for T {}

/// A value that can be logged.
///
/// This trait extends `Debug` with feature `log` and `defmt::Format` with feature `defmt`,
/// and is implemented for every type that is both.
#[cfg(all(feature = "log", not(feature = "defmt")))]
pub trait Loggable: core::fmt::Debug {}

#[cfg(all(feature = "log", not(feature = "defmt")))]
impl<T: ?Sized + core::fmt::Debug> Loggable for T {}

/// A value that can be logged.
///
/// This trait extends `Debug` with feature `log` and `defmt::Format` with feature `defmt`,
/// and is implemented for every type that is both.
#[cfg(all(not(feature = "log"), feature = "defmt"))]
pub trait Loggable: defmt::Format {}

#[cfg(all(not(feature = "log"), feature = "defmt"))]
impl<T: ?Sized + defmt::Format> Loggable for T {}

/// A value that can be logged.
///
/// This trait extends `Debug` with feature `log` and `defmt::Format` with feature `defmt`,
/// and is implemented for every type that is both.
#[cfg(not(any(feature = "log", feature = "defmt")))]
pub trait Loggable {}

#[cfg(not(any(feature = "log", feature = "defmt")))]
impl<T: ?Sized> Loggable for T {}

/// Log the writing of a field by a TLV builder.
pub fn log_field<B: Loggable, V: Loggable>(builder: &B, name: &str, value: &V) {
    debug!("{:?}::{} -> {:?} +", builder, name, value);
}

/// Log the start of an attribute read or a command that builds its reply.
pub fn log_build_start<I: Loggable>(id: &I) {
    debug!("{:?} -> (build) +", id);
}

/// Log the start of a command with data that builds its reply.
pub fn log_data_build_start<I: Loggable, D: Loggable>(id: &I, data: &D) {
    debug!("{:?}({:?}) -> (build) +", id, data);
}

/// Log the end of an attribute read or a command that built its reply.
pub fn log_build_end<I: Loggable, R: Loggable>(id: &I, result: &R) {
    debug!("{:?} (end) -> {:?}", id, result);
}

/// Log the result of an attribute read or a command without data.
pub fn log_result<I: Loggable, R: Loggable>(id: &I, result: &R) {
    debug!("{:?} -> {:?}", id, result);
}

/// Log the result of an attribute write or a command with data.
pub fn log_data_result<I: Loggable, D: Loggable, R: Loggable>(id: &I, data: &D, result: &R) {
    debug!("{:?}({:?}) -> {:?}", id, data, result);
}

/// Log an attribute that the cluster does not have.
pub fn log_attr_not_supported(attr: &AttrDetails) {
    error!(
        "Endpt(0x{:02x})::Cluster(0x{:04x})::Attr(0x{:04x}) not supported",
        attr.endpoint_id, attr.cluster_id, attr.attr_id
    );
}

/// Log a command that the cluster does not have.
pub fn log_cmd_not_supported(cmd: &CmdDetails) {
    error!(
        "Endpt(0x{:02x})::Cluster(0x{:04x})::Cmd(0x{:04x}) not supported",
        cmd.endpoint_id, cmd.cluster_id, cmd.cmd_id
    );
}
