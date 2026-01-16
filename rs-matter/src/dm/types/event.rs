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
use core::fmt::{Debug};

use super::{ClusterId, EventId, EndptId, Node};


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
    // TODO(events): The attr equivalent of this has many more metadata fields, validate if we need any of them
}
