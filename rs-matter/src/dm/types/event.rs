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
use crate::im::{AttrPath, AttrStatus, IMStatusCode, EventData};
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

pub type EventEntryIdx = u8;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EventEntry<'a> {
    event: Option<EventData<'a>>,
    next: Option<EventEntryIdx>,
}

// This implements the per-node bounded priority queue that stores generated events
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EventQueue<'a> {
    // Ordered list of events, most recent first
    head: Option<EventEntryIdx>,
    // Free-list, if there are any unused entries
    free: Option<EventEntryIdx>,
    // Event number sequencer
    next_event_no: u64,
    // Actual event entry structs
    pool: [EventEntry<'a>; 16],
}

// TODO(events): This obviously needs extensive testing
// TODO(events): What are the concurrency semantics / rules in rs-matter, do we assume single thread?
impl<'a> EventQueue<'a> {
    pub const fn new() -> Self {
        let mut pool = core::array::from_fn(|idx| EventEntry {
            event: None,
            next: Some((idx + 1) as u8),
        });
        pool[15].next = None;

        Self {
            head: None,
            free: Some(0),
            next_event_no: 0,
            pool,
        }
    }

    pub fn push(&mut self, mut payload: EventData<'a>) {
        // First we assign a new event number to the event. We do this even though we are not sure
        // we can fit this event in the queue yet, creating gaps for consumers to detect missing events
        // TODO(events): I think above semantics is the right interpretation of the spec, but verify
        payload.event_number = self.next_event_no;
        self.next_event_no += 1;

        // Attempt to obtain an entry record to store this event in
        let entry_idx = if let Some(idx) = self.free {
            // There were entries on the free list, take from there
            self.free = self.pool[idx as usize].next;
            idx
        } else {
            // Queue is full: Attempt to evict a same-or-lower prio event
            match self.evict_one(payload.priority) {
                Some(victim) => victim,
                None => {
                    // TODO(events): logging here?
                    // There are no equal-or-lower priority events we could evict, drop the event
                    return
                },
            }
        };

        // Fill the entry and insert it at the head of the queue
        self.pool[entry_idx as usize] = EventEntry {
            event: Some(payload),
            next: self.head, // New entry points to old head
        };
        self.head = Some(entry_idx);
    }

    /// Evicts one entry in the active queue, if one can be found that meets the eviction rules of the spec
    /// This is used to insert a new entry, max_prio should be the priority of the event you want to insert.
    fn evict_one(&mut self, max_prio: u8) -> Option<EventEntryIdx> {
        let mut prev_idx = None;
        let mut curr_idx = self.head;

        let mut lowest_prio_val: u8 = 0;
        let mut lowest_idx = None;
        let mut lowest_prev_idx = None;

        // Traverse the active list to find the next eviction target 
        while let Some(idx) = curr_idx {
            let entry = &self.pool[idx as usize];
            
            // See 7.14.2 in the spec for this rule
            if entry.event.priority >= max_prio && (lowest_idx.is_none() || entry.event.priority >= lowest_prio_val) {
                lowest_prio_val = entry.event.priority;
                lowest_idx = Some(idx);
                lowest_prev_idx = prev_idx;
            }
            
            prev_idx = curr_idx;
            curr_idx = entry.next;
        }

        match (lowest_prev_idx, lowest_idx) { 
            (_, None) => None,
            (Some(victim_prev_idx), Some(victim_idx)) => {
                // Victim is in middle of linked list, update the prior entry
                self.pool[victim_prev_idx as usize].next = self.pool[victim_idx as usize].next;
                Some(victim_idx)
            },
            (None, Some(victim_idx)) => {
                // Victim is at HEAD, update HEAD
                self.head = self.pool[victim_idx as usize].next;
                Some(victim_idx)
            },
        }
    }
}

impl<'a> IntoIterator for &'a EventQueue<'a> {
    type Item = &'a EventData<'a>;
    type IntoIter = EventQueueIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        EventQueueIter{
            queue: self, 
            curr: self.head,
        }
    }
}

pub struct EventQueueIter<'a> {
    queue: &'a EventQueue<'a>,
    curr: Option<EventEntryIdx>,
}

impl<'a> Iterator for EventQueueIter<'a> {
    type Item = &'a EventData<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(idx) = self.curr {
                let entry = &self.queue.pool[idx as usize];
                self.curr = entry.next;
                // TODO(events): Getting None here is a programming error, it means we have an entry in the queue
                //               that didn't get it's event field populated; what do? Log at least?
                if let Some(event) = &entry.event {
                    return Some(event)
                }
            } else {
                return None
            }
        }
    }
}
