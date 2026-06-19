/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

//! The Data Model as defined by the Matter Core spec: the structure and schema
//! of a node - its endpoints, clusters, attributes, commands and events - and
//! the handlers that give them behaviour.
//!
//! The Interaction Model engine that drives reads, writes, subscriptions and
//! invokes against this data model lives in [`crate::im`].

pub use types::*;

pub mod clusters;
pub mod devices;
pub mod endpoints;
pub mod networks;

mod types;
