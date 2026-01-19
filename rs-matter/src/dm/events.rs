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

use crate::error::{Error, ErrorCode};
use crate::im::{EventDataTag, EventDataTimestamp, EventPath, EventRespTag};
use crate::tlv::{FromTLV, TLVElement, TLVSequence, TLVTag, TLVWrite, TagType, ToTLV};
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


#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]

struct EventQueue2 {
    buf_debug: TLVRingBuffer,
    buf_info: TLVRingBuffer,
    buf_critical: TLVRingBuffer,
}

impl EventQueue2 {
    fn new() -> Self {
        Self {
            buf_debug: TLVRingBuffer::new(),
            buf_info: TLVRingBuffer::new(),
            buf_critical: TLVRingBuffer::new(),
        }
    }

    pub fn push<'a>(&'a mut self, path: EventPath, event_number: u64, priority: u8, timestamp: EventDataTimestamp) -> Result<EventQueueWriter<'a>, Error> {
        let mut tw = EventQueueWriter::new(self, BufferRef::from_prio_level(priority)?);
        tw.start_struct(&TLVTag::Context(EventRespTag::Data as _))?;
        path
            .to_tlv(&TagType::Context(EventDataTag::Path as _), &mut tw)?;
        tw.u64(
            &TagType::Context(EventDataTag::EventNumber as _),
            event_number,
        )?;
        tw.u8(
            &TagType::Context(EventDataTag::Priority as _),
            priority,
        )?;
        match timestamp {
            EventDataTimestamp::EpochTimestamp(ts) => {
                tw.u64(&TagType::Context(EventDataTag::EpochTimestamp as _), ts)?
            }
            EventDataTimestamp::SystemTimestamp(ts) => {
                tw.u64(&TagType::Context(EventDataTag::SystemTimestamp as _), ts)?
            }
            EventDataTimestamp::DeltaEpochTimestamp(ts) => tw.u64(
                &TagType::Context(EventDataTag::DeltaEpochTimestamp as _),
                ts,
            )?,
            EventDataTimestamp::DeltaSystemTimestamp(ts) => tw.u64(
                &TagType::Context(EventDataTag::DeltaSystemTimestamp as _),
                ts,
            )?,
        };
        Ok(tw)
    }


    fn iter<'a>(&'a self) -> EventQueueIter<'a> {
        EventQueueIter{ queue: self, buf_ref: BufferRef::Critical, buf_iter: self.buf_critical.iter() }
    }

}

struct EventQueueIter<'a> {
    queue: &'a EventQueue2,
    buf_ref: BufferRef,
    buf_iter: TLVRingBufIter<'a>,
}

impl<'a> EventQueueIter<'a> {

    fn parse_event(tr: TLVElement<'a>) -> Result<EventData<'a>, Error> {
        let mut path = None;
        let mut event_number = None;
        let mut priority = None;
        let mut timestamp = None;
        let mut data = None;

        tr.structure()?.scan_map(|elem| {
            if elem.is_empty() {
                return Ok(Some(elem));
            }
            
            match EventDataTag::try_from(elem.ctx()?) {
                Ok(EventDataTag::Path) => path = Some(EventPath::from_tlv(&elem)?),
                Ok(EventDataTag::EventNumber) => event_number = Some(elem.u64()?),
                Ok(EventDataTag::Priority) => priority = Some(elem.u8()?),
                Ok(EventDataTag::SystemTimestamp) => timestamp = Some(EventDataTimestamp::SystemTimestamp(elem.u64()?)),
                Ok(EventDataTag::EpochTimestamp) => timestamp = Some(EventDataTimestamp::EpochTimestamp(elem.u64()?)),
                Ok(EventDataTag::DeltaSystemTimestamp) => timestamp = Some(EventDataTimestamp::DeltaSystemTimestamp(elem.u64()?)),
                Ok(EventDataTag::DeltaEpochTimestamp) => timestamp = Some(EventDataTimestamp::DeltaEpochTimestamp(elem.u64()?)),
                Ok(EventDataTag::Data) => data = Some(elem.clone()),
                Err(_) => todo!(),
            }
            Ok(None)
        })?;
        
        Ok(EventData::new(
            path.ok_or(Error::new(ErrorCode::AttributeNotFound))?, 
            event_number.ok_or(Error::new(ErrorCode::AttributeNotFound))?, 
            priority.ok_or(Error::new(ErrorCode::AttributeNotFound))?, 
            timestamp.ok_or(Error::new(ErrorCode::AttributeNotFound))?, 
            data.ok_or(Error::new(ErrorCode::AttributeNotFound))?, 
        ))
    }
}

impl<'a> Iterator for EventQueueIter<'a> {
    type Item = Result<EventData<'a>, Error>;
    
    fn next(&mut self) -> Option<Self::Item> {
        match self.buf_iter.next() {
            None => None,
            Some(Err(e)) => Some(Err(e)),
            Some(Ok(tr)) => Some(EventQueueIter::parse_event(tr)),
        }
    }
}

struct EventQueueWriter<'a> {
    queue: &'a mut EventQueue2,
    buf_ref: BufferRef,
}

impl<'a> EventQueueWriter<'a> {
    fn new(queue: &'a mut EventQueue2, buf_ref: BufferRef) -> Self {
        Self { queue, buf_ref }
    }

    pub fn end(mut self) -> Result<(), Error> {
        self.end_container()
    }
}

impl<'a> TLVWrite for EventQueueWriter<'a> {
    type Position = (BufferRef, u32);


    fn write(&mut self, byte: u8) -> Result<(), Error> {
        let mut buf = self.buf_ref.get_mut(self.queue);
        buf.write(byte);
        Ok(())
    }

    fn get_tail(&self) -> Self::Position {
        // n.b. TLVWrite calls the next position to be written "tail", but our ring buffer calls that position "head"
        (self.buf_ref.clone(), self.buf_ref.get(self.queue).head)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct TLVRingBuffer {
    data: [u8; 64],
    head: u32,
    tail: u32,
}

impl TLVRingBuffer {
    fn new() -> Self {
        Self {
            data: [0; 64],
            head: 0,
            tail: 0,
        }
    }

    fn write(&mut self, byte: u8) -> WriteOutcome {
        self.data[self.head as usize] = byte;
        self.head += 1;
        WriteOutcome::Ok
    }

    fn iter(&self) -> TLVRingBufIter<'_> {
        TLVRingBufIter { buf: self, pos: self.tail as usize }
    }
}

struct TLVRingBufIter<'a> {
    buf: &'a TLVRingBuffer,
    pos: usize,
}

impl<'a> TLVRingBufIter<'a> {
    fn peek<'p>(&'p self) -> Result<usize, Error> {
        let seq = TLVSequence(&self.buf.data[self.pos..]);
        // TODO(events): We end up reading the whole record here just to tell its size.. 
        //               only to further up read it again, we could skip one read-through with some smarts
        // TODO(events): Sooo the +2 is mega shady but: The length I'm getting here is, in the one case I've tested,
        //               off-by-2. I *think* that's the control byte and maybe the struct trailer byte, and the
        //               length then just being the "innards" of the container. But I don't think I can rely on the
        //               struct start/end data being exactly 2 bytes all the time, so this likely needs something better
        Ok(seq.raw_value()?.len() + 2)
    }
}

impl<'a> Iterator for TLVRingBufIter<'a> {
    type Item = Result<TLVElement<'a>, Error>;
    
    fn next(&mut self) -> Option<Self::Item> {
        // TODO(events) this doesn't handle wrap-around
        if self.pos >= self.buf.head as _ {
            return None
        }
        let record_len = match self.peek() {
            Ok(raw) => raw,
            Err(e) => return Some(Err(e)),
        };

        let start = self.pos;
        self.pos += record_len;
        
        Some(Ok(TLVElement::new(&self.buf.data[start..start + record_len])))
    }
}

enum WriteOutcome {
    Ok,
    Wraparound,
}

#[derive(PartialEq, Clone, Copy)]
enum BufferRef {
    Debug,
    Info,
    Critical
}

impl BufferRef {
    fn from_prio_level(priority: u8) -> Result<BufferRef, Error> {
        match priority {
            // 7.19.2.17
            0 => Ok(BufferRef::Debug),
            1 => Ok(BufferRef::Info),
            2 => Ok(BufferRef::Critical),
            _ => todo!()
        }
    }

    fn get_mut<'a> (&self, queue: &'a mut EventQueue2) -> &'a mut TLVRingBuffer {
        match self {
            BufferRef::Debug => &mut queue.buf_debug,
            BufferRef::Info => &mut queue.buf_info,
            BufferRef::Critical => &mut queue.buf_critical,
        }
    }

    fn get<'a> (&self, queue: &'a EventQueue2) -> &'a TLVRingBuffer {
        match self {
            BufferRef::Debug => &queue.buf_debug,
            BufferRef::Info => &queue.buf_info,
            BufferRef::Critical => &queue.buf_critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EP1: EventPath = EventPath{ node: Some(1337), endpoint: Some(42), cluster: Some(1), event: Some(0xB33F), is_urgent: Some(true) };

    #[test]
    fn test_first_entry_read_write() {
        let mut q = EventQueue2::new();

        let mut tw = q.push(EP1.clone(), 1, 2, EventDataTimestamp::EpochTimestamp(12345)).unwrap();
        tw.u64(&TLVTag::Context(EventDataTag::Data as _), 54321).unwrap();
        tw.end().unwrap();

        let mut it =  q.iter();
        let ev1 = it.next().unwrap().unwrap();
        assert_eq!(ev1.event_number, 1);
        assert!(it.next().is_none());
    }
}