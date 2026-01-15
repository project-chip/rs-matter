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
use core::fmt::{self, Debug};

use strum::FromRepr;

use crate::attribute_enum;
use crate::error::{Error, ErrorCode};
use crate::im::{AttrPath, AttrStatus, IMStatusCode};
use crate::tlv::{AsNullable, FromTLV, Nullable, TLVBuilder, TLVBuilderParent, TLVElement, TLVTag};
use crate::utils::maybe::Maybe;

use super::{Access, AttrId, Cluster, ClusterId, EventId, EndptId, Node, Quality};


/// TODO(events) docs
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EventDetails<'a> {
    /// The node meta-data
    pub node: &'a Node<'a>,
    /// The concrete (expanded) endpoint ID
    pub endpoint_id: EndptId,
    /// The concrete (expanded) cluster ID
    pub cluster_id: ClusterId,
    /// The concrete (expanded) event ID
    pub event_id: EventId,
    // TODO(events): Verify if any of these should be kept/have equivalents on events
    // /// List index, if any
    // pub list_index: Option<Nullable<u16>>,
    // /// Valid only when the operation is attrubute read of
    // /// an individual array item
    // /// When `true`, the path written to the output will contain
    // /// `null` as a list index. This is necessary when we are returning
    // /// an array attribute in a chunked manner
    // pub list_chunked: bool,
    // /// The fabric index associated with this request
    // pub fab_idx: u8,
    // /// Whether fabric filtering is active for this request
    // pub fab_filter: bool,
    // /// Attribute expected data version (when writing)
    // pub dataver: Option<u32>,
    // /// Whether the original attribute was a wildcard one
    // pub wildcard: bool,
}

impl EventDetails<'_> {
    // TODO(events): Lets see if we need any equivalents of these or otherwise delete them
    // /// Return `true` if the attribute is a system one (i.e. a global attribute).
    // pub const fn is_system(&self) -> bool {
    //     Attribute::is_system_attr(self.attr_id)
    // }

    // /// Return the path with which this attribute read/write request
    // /// should be replied.
    // pub fn reply_path(&self) -> AttrPath {
    //     AttrPath {
    //         node: None,
    //         endpoint: Some(self.endpoint_id),
    //         cluster: Some(self.cluster_id),
    //         attr: Some(self.attr_id),
    //         list_index: if self.list_chunked {
    //             match self.list_index.as_ref().map(|li| li.as_opt_ref()) {
    //                 // Convert specific indexed item to item with index null (= append)
    //                 Some(Some(_)) => Some(Nullable::none()),
    //                 // Convert the `rs-matter`-specific request for an empty array to Matter spec compliant result
    //                 Some(None) | None => None,
    //             }
    //         } else {
    //             self.list_index.clone()
    //         },
    //         tag_compression: None,
    //     }
    // }

    // pub fn cluster(&self) -> Result<&Cluster<'_>, Error> {
    //     self.node
    //         .endpoint(self.endpoint_id)
    //         .and_then(|endpoint| endpoint.cluster(self.cluster_id))
    //         .ok_or_else(|| {
    //             error!("Cluster not found");
    //             ErrorCode::ClusterNotFound.into()
    //         })
    // }

    // pub fn status(&self, status: IMStatusCode) -> Option<EventStatus> {
    //     if self.should_report(status) {
    //         Some(EventStatus::new(self.reply_path(), status, None))
    //     } else {
    //         None
    //     }
    // }

    // const fn should_report(&self, status: IMStatusCode) -> bool {
    //     !self.wildcard
    //         || !matches!(
    //             status,
    //             IMStatusCode::UnsupportedEndpoint
    //                 | IMStatusCode::UnsupportedCluster
    //                 | IMStatusCode::UnsupportedAttribute
    //                 | IMStatusCode::UnsupportedCommand
    //                 | IMStatusCode::UnsupportedAccess
    //                 | IMStatusCode::UnsupportedRead
    //                 | IMStatusCode::UnsupportedWrite
    //                 | IMStatusCode::DataVersionMismatch
    //         )
    // }
}