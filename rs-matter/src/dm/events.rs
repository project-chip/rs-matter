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
use core::fmt::Debug;

use crate::utils::cell::RefCell;
use crate::utils::sync::blocking::Mutex;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::im::EventData;

pub const DEFAULT_MAX_QUEUED_EVENTS: usize = 16; // TODO(events) what to set this to?

/// A type alias for `Events` with the default maximum number of subscriptions.
/// TODO(events) the lifetime here is because the queued events have TLV data entries.. not sure if there's a way around this?
pub type DefaultEvents = Events<'static, DEFAULT_MAX_QUEUED_EVENTS>;

// TODO(events): This would be approximately analogue to Subscriptions, except for the event queue,
// But there are multiple open questions, like how to iterate over the queue while ensuring the iteratee
// doesn't go off an do something like a network write while we're holding a lock
pub struct Events<'a, const N: usize = DEFAULT_MAX_QUEUED_EVENTS, M = NoopRawMutex>
where
    M: RawMutex,
{
    state: Mutex<M, RefCell<EventQueue<'a, N>>>,
}

impl<'a, const N: usize, M> Events<'a, N, M>
where
    M: RawMutex,
{
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(EventQueue::new())),
        }
    }

    // TODO(events): The subsciptions structure has an in-place init option here,
    // I guess to allow creating these heavy structures and avoid having them be moved? We likely
    // want that here too, I would assume.

    pub fn push(&self, payload: EventData<'a>) {
        self.state
            .lock(|internal| internal.borrow_mut().push(payload));
    }

    // Iterate over each entry in the queue, aborts if f returns Err
    pub fn for_each<E>(&self, f: impl FnMut(&EventData<'a>) -> Result<(), E>) -> Result<(), E> {
        self.state.lock(|internal| internal.borrow().for_each(f))
    }
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
pub struct EventQueue<'a, const N: usize> {
    // Ordered list of events, most recent first
    head: Option<EventEntryIdx>,
    // Free-list, if there are any unused entries
    free: Option<EventEntryIdx>,
    // Event number sequencer
    next_event_no: u64,
    // All event entry structs, free and in use
    pool: [EventEntry<'a>; N],
}

// TODO(events): This obviously needs extensive testing
// TODO(events): What are the concurrency semantics / rules in rs-matter, do we assume single thread?
impl<'a, const N: usize> EventQueue<'a, N> {
    pub const fn new() -> Self {
        // Create the pool of event entries and link them up to each other into a free-list
        let mut pool = [const {
            EventEntry {
                event: None,
                next: None,
            }
        }; N];

        let mut i = 0;
        while i < N - 1 {
            pool[i].next = Some(i as u8 + 1);
            i += 1;
        }

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
                    return;
                }
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

            if let Some(event) = &entry.event {
                // See 7.14.2 in the spec for this rule
                if event.priority >= max_prio
                    && (lowest_idx.is_none() || event.priority >= lowest_prio_val)
                {
                    lowest_prio_val = event.priority;
                    lowest_idx = Some(idx);
                    lowest_prev_idx = prev_idx;
                }
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
            }
            (None, Some(victim_idx)) => {
                // Victim is at HEAD, update HEAD
                self.head = self.pool[victim_idx as usize].next;
                Some(victim_idx)
            }
        }
    }

    fn for_each<E>(&self, mut f: impl FnMut(&EventData<'a>) -> Result<(), E>) -> Result<(), E> {
        let mut curr = self.head;
        loop {
            if let Some(idx) = curr {
                let entry = &self.pool[idx as usize];
                curr = entry.next;
                // TODO(events): Getting None here is a programming error, it means we have an entry in the queue
                //               that didn't get it's event field populated; what do? Log at least?
                if let Some(event) = &entry.event {
                    f(event)?
                }
            } else {
                return Ok(());
            }
        }
    }
}
