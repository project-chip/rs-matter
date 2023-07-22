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
use crate::error::Error;
use crate::tlv::{TLVWriter, TagType, ToTLV};

mod attribute;
pub use attribute::*;

mod cluster;
pub use cluster::*;

mod endpoint;
pub use endpoint::*;

mod node;
pub use node::*;

mod privilege;
pub use privilege::*;

mod encoder;
pub use encoder::*;

mod handler;
pub use handler::*;

mod dataver;
pub use dataver::*;

mod metadata;
pub use metadata::*;

pub type EndptId = u16;
pub type ClusterId = u32;
pub type AttrId = u16;
pub type CmdId = u32;

#[derive(Debug, ToTLV, Copy, Clone)]
pub struct DeviceType {
    pub dtype: u16,
    pub drev: u16,
}
