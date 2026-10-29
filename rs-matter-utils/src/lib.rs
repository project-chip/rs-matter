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

//! Utilities used across `rs-matter`: the error type, synchronization primitives,
//! storage, timers, futures, I/O and in-place initialization.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(async_fn_in_trait)]
#![allow(unknown_lints)]
#![allow(clippy::uninlined_format_args)]
// `cargo llvm-cov` sets `coverage_nightly` when it runs on a nightly toolchain;
// the test modules are then excluded from the coverage report
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

#[cfg(feature = "alloc")]
extern crate alloc;

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

pub mod bitflags;
pub mod cell;
pub mod codec;
pub mod epoch;
pub mod error;
pub mod futures;
pub mod init;
pub mod io;
pub mod ipv6;
pub mod iter;
pub mod maybe;
pub mod storage;
pub mod sync;
pub mod timers;
#[cfg(feature = "zbus")]
pub mod zbus;
#[cfg(feature = "zbus")]
pub mod zbus_proxies;
