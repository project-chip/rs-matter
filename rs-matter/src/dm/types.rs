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

use crate::tlv::ToTLV;

pub use attribute::*;
pub use cluster::*;
pub use command::*;
pub use dataver::*;
pub use endpoint::*;
pub use handler::*;
pub use metadata::*;
pub use node::*;
pub use privilege::*;
pub use reply::*;

mod attribute;
mod cluster;
mod command;
mod dataver;
mod endpoint;
mod handler;
mod metadata;
mod node;
mod privilege;
mod reply;

pub type EndptId = crate::im::EndptId;
pub type ClusterId = crate::im::ClusterId;
pub type AttrId = crate::im::AttrId;
pub type EventId = crate::im::EventId;
pub type CmdId = crate::im::CmdId;
pub type FabricId = crate::im::FabricId;

#[derive(Debug, ToTLV, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceType {
    pub dtype: u16,
    pub drev: u16,
}
