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

use crate::tlv::ToTLV;

pub use attribute::*;
pub use cluster::*;
pub use command::*;
pub use dataver::*;
pub use endpoint::*;
pub use event::*;
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
mod event;
mod handler;
mod metadata;
mod node;
mod privilege;
mod reply;

pub use crate::im::encoding::types::*;

#[derive(Debug, ToTLV, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceType {
    pub dtype: u16,
    pub drev: u16,
}

/// A semantic tag describing an endpoint, as reported by
/// `Descriptor::TagList`.
///
/// Matter Core spec 9.5 requires these to disambiguate endpoints that would
/// otherwise be indistinguishable: when a node exposes two or more endpoints
/// with the *same* device type under the same parent, each of them must carry a
/// non-empty `TagList`, and no two of those lists may be identical. A
/// certification harness enforces exactly that (`TC_DESC_2_2`).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SemanticTag<'a> {
    /// The manufacturer code scoping `namespace_id`, or `None` when the tag
    /// comes from a standard (CSA-defined) namespace.
    pub mfg_code: Option<u16>,
    /// The namespace `tag` is drawn from.
    pub namespace_id: u8,
    /// The tag value within `namespace_id`.
    pub tag: u8,
    /// An optional human-readable label for the tag.
    pub label: Option<&'a str>,
}

impl<'a> SemanticTag<'a> {
    /// Create a tag in a standard (CSA-defined) namespace, with no label.
    pub const fn new(namespace_id: u8, tag: u8) -> Self {
        Self {
            mfg_code: None,
            namespace_id,
            tag,
            label: None,
        }
    }

    /// Attach a human-readable label to this tag.
    pub const fn with_label(self, label: &'a str) -> Self {
        Self {
            label: Some(label),
            ..self
        }
    }
}
