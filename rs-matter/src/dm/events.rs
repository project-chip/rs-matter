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
use tokio::io::BufStream;

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
    buf_debug: TLVRingBuf,
    buf_info: TLVRingBuf,
    buf_critical: TLVRingBuf,
}

impl EventQueue2 {
    fn new() -> Self {
        Self {
            buf_debug: TLVRingBuf::new(),
            buf_info: TLVRingBuf::new(),
            buf_critical: TLVRingBuf::new(),
        }
    }

    pub fn push<'a>(&'a mut self, path: EventPath, event_number: u64, priority: u8, timestamp: EventDataTimestamp) -> Result<EventQueueWriter<'a>, Error> {
        let mut tw = EventQueueWriter::new(self, BufLevel::Debug);
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
        EventQueueIter{ queue: self, buf_ref: BufLevel::Critical, buf_iter: self.buf_critical.iter() }
    }

}

struct EventQueueIter<'a> {
    queue: &'a EventQueue2,
    buf_ref: BufLevel,
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
    buf_ref: BufLevel,
}

impl<'a> EventQueueWriter<'a> {
    fn new(queue: &'a mut EventQueue2, buf_ref: BufLevel) -> Self {
        Self { queue, buf_ref }
    }

    // TODO(events): do we need to also call this via a Drop trait? Otherwise wrong API usage would lead to corrupted data
    pub fn end(mut self) -> Result<(), Error> {
        self.end_container()
    }

    // Evict one entry from the given buffer, potentially promoting it to the next buffer if
    // it meets the priority threshold. If promotion happens the eviction "cascades", until
    // we either evict an event that doesn't meet the next buffers prio level or we run out of
    // ring buffers and drop the oldest critical event.
    fn evict(&mut self, buf_ref: BufLevel) -> Result<(), Error> {
        let (victim_prio, victim_ref) = self.prepare_eviction(buf_ref.get(self.queue))?;
        
        if let Some(next_buf_ref) = buf_ref.next_level() {
            if next_buf_ref.threshold() <= victim_prio {
                // There is another level and our victim record meets the priority threshold, we should promote it
                self.promote(buf_ref, next_buf_ref, victim_ref)?;
            }
        }

        buf_ref.get_mut(self.queue).evict(victim_ref);
        Ok(())
    }

    fn prepare_eviction(&self, buf: &TLVRingBuf) -> Result<(u8, VictimRef), Error> {
        let victim_ref = buf.prepare_eviction()?;
        let priority = victim_ref.tlv(buf).structure()?.find_ctx(EventDataTag::Priority as _)?.u8()?;
        Ok((priority, victim_ref))
    }

    fn promote(&mut self, src_buf: BufLevel, dst_buf: BufLevel, victim_ref: VictimRef) -> Result<(), Error> {
        // Make space
        while dst_buf.get(self.queue).capacity() < victim_ref.len() {
            self.evict(dst_buf)?;
        }

        let (src, dst) = src_buf.get_mut_and_next(self.queue); 
        // TODO(events): dst being None here is a programming error, what's the right way to signal that?
        let dst = dst.expect("there should always be a dst buffer at this point");
        match dst.write_slice(victim_ref.raw(src)) {
            WriteOutcome::Ok => Ok(()),
            // TODO(events)Again this is a programming error, the while further up should have guaranteed space
            WriteOutcome::Overflow => todo!(),
        }
    }
}

impl<'a> TLVWrite for EventQueueWriter<'a> {
    type Position = usize;

    fn write(&mut self, byte: u8) -> Result<(), Error> {
        while let WriteOutcome::Overflow = self.buf_ref.get_mut(self.queue).write(byte) {
            // Overflow, need to evict an entry
            self.evict(BufLevel::Debug)?;
        }
        Ok(())
    }

    fn get_tail(&self) -> Self::Position {
        // n.b. TLVWrite calls the next position to be written "tail", but our ring buffer calls that position "head"
        self.queue.buf_debug.head
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct TLVRingBuf {
    data: [u8; 64],
    head: usize,
    // n.b. there is no tail. We don't have a way to read streaming TLVs, so we can't have a TLV "wrap around" at the end
    // and continue at the start of data. Instead, tail is always zero, and whenever we evict we left-shift the entire buffer
    // see evict.
}

impl TLVRingBuf {
    fn new() -> Self {
        Self {
            data: [0; 64],
            head: 0,
        }
    }

    fn write(&mut self, byte: u8) -> WriteOutcome {
        if self.capacity() == 0 {
            return WriteOutcome::Overflow;
        }
        self.data[self.head] = byte;
        self.head += 1;
        WriteOutcome::Ok
    }

    fn write_slice(&mut self, data: &[u8]) -> WriteOutcome {
        if self.capacity() < data.len() {
            return WriteOutcome::Overflow;
        }
        self.data[self.head..self.head + data.len()].copy_from_slice(data);
        self.head += data.len();
        WriteOutcome::Ok
    }

    // Get the size of the record at the given position; the caller is responsible for ensuring pos is aligned on a record
    fn record_len(&self, pos: usize) -> Result<usize, Error> {
        let seq = TLVSequence(&self.data[pos..]);
        // TODO(events): Sooo the +2 is mega shady but: The length I'm getting here is, in the one case I've tested,
        //               off-by-2. I *think* that's the control byte and maybe the struct trailer byte, and the
        //               length then just being the "innards" of the container. But I don't think I can rely on the
        //               struct start/end data being exactly 2 bytes all the time, so this likely needs something better
        Ok(seq.raw_value()?.len() + 2)
    }

    fn capacity(&self) -> usize {
        self.data.len() - self.head
    }

    fn prepare_eviction(&self) -> Result<VictimRef, Error> {
        // TODO(events): Handle empty / wrap-around
        Ok(VictimRef{ victim_len: self.record_len(0)?})
    }

    fn evict(&mut self, victim: VictimRef) {
        self.data.copy_within(victim.len()..self.head, 0);
        self.head -= victim.len();
    }

    fn iter(&self) -> TLVRingBufIter<'_> {
        TLVRingBufIter { buf: self, pos: 0 }
    }
}

/// During eviction we need the size of the record to be evicted several times (for promotion and then for actual moving the tail index)
/// to avoid reading the whole entry lots of times for this we read it once to get its size and store that in this reference
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct VictimRef {
    victim_len: usize,
}

impl VictimRef {
    fn tlv<'a>(&'a self, buf: &'a TLVRingBuf) -> TLVElement<'a> {
        TLVElement::new(self.raw(buf))
    }

    fn raw<'a>(&'a self, buf: &'a TLVRingBuf) -> &'a[u8] {
        &buf.data[0..self.victim_len]
    }

    fn len(&self) -> usize {
        self.victim_len
    }
}


#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct TLVRingBufIter<'a> {
    buf: &'a TLVRingBuf,
    pos: usize,
}

impl<'a> Iterator for TLVRingBufIter<'a> {
    type Item = Result<TLVElement<'a>, Error>;
    
    fn next(&mut self) -> Option<Self::Item> {
        // TODO(events) this doesn't handle wrap-around
        if self.pos >= self.buf.head as _ {
            return None
        }
        let record_len = match self.buf.record_len(self.pos) {
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
    // The write failed because the head is caught up with the tail, 
    // evict an entry to move the tail forward and try again
    Overflow,
}

// This is how we handle the "levels" of buffers, using this reference we can access the current
// level and get access to the next level, if there is one
#[derive(PartialEq, Clone, Copy)]
enum BufLevel {
    Debug,
    Info,
    Critical
}

impl BufLevel {
    fn from_prio_level(priority: u8) -> Result<BufLevel, Error> {
        // 7.19.2.17
        match priority {
            0 => Ok(BufLevel::Debug),
            1 => Ok(BufLevel::Info),
            2 => Ok(BufLevel::Critical),
            _ => todo!()
        }
    }

    fn threshold(&self) -> u8 {
        // 7.19.2.17
        match self {
            BufLevel::Debug => 0,
            BufLevel::Info => 1,
            BufLevel::Critical => 2,
        }
    }

    fn get_mut<'a> (&self, queue: &'a mut EventQueue2) -> &'a mut TLVRingBuf {
        match self {
            BufLevel::Debug => &mut queue.buf_debug,
            BufLevel::Info => &mut queue.buf_info,
            BufLevel::Critical => &mut queue.buf_critical,
        }
    }

    fn get<'a> (&self, queue: &'a EventQueue2) -> &'a TLVRingBuf {
        match self {
            BufLevel::Debug => &queue.buf_debug,
            BufLevel::Info => &queue.buf_info,
            BufLevel::Critical => &queue.buf_critical,
        }
    }

    /// Used during promotion, when we need both the src and dst buffers at the same time
    fn get_mut_and_next<'a> (&self, queue: &'a mut EventQueue2) -> (&'a mut TLVRingBuf, Option<&'a mut TLVRingBuf>) {
        match self {
            BufLevel::Debug => (&mut queue.buf_debug, Some(&mut queue.buf_info)),
            BufLevel::Info => (&mut queue.buf_info, Some(&mut queue.buf_critical)),
            BufLevel::Critical => (&mut queue.buf_critical, None),
        }
    }

    fn next_level(&self) -> Option<BufLevel> {
        match self {
            BufLevel::Debug => Some(BufLevel::Info),
            BufLevel::Info => Some(BufLevel::Critical),
            BufLevel::Critical => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EP1: EventPath = EventPath{ node: Some(1337), endpoint: Some(42), cluster: Some(1), event: Some(0xB33F), is_urgent: Some(true) };

    #[test]
    fn one_entry() {
        let crit1 = TestEvent::new(1, 2);
        let mut q = EventQueue2::new();
        
        crit1.push_into(&mut q).unwrap();

        assert_eq!(
            TestEvent::vec_from(&q.buf_debug).unwrap(), 
            &[crit1]
        );
    }

    #[test]
    fn critical_is_promoted() {
        let crit1 = TestEvent::new(1, 2);
        let crit2 = TestEvent::new(2, 2);
        let crit3 = TestEvent::new(3, 2);
        let mut q = EventQueue2::new();
        
        crit1.push_into(&mut q).unwrap();
        crit2.push_into(&mut q).unwrap();
        crit3.push_into(&mut q).unwrap();

        assert_eq!(
            TestEvent::vec_from(&q.buf_debug).unwrap(), 
            &[crit3]
        );

        assert_eq!(
            TestEvent::vec_from(&q.buf_info).unwrap(), 
            &[crit2]
        );
        assert_eq!(
            TestEvent::vec_from(&q.buf_critical).unwrap(), 
            &[crit1]
        );
    }

    // TODO(events): Need test cases for:
    // - writing an entry that's bigger than an individual ring buffer
    // - dropping events that don't meet next prio level

    // Test utilities for this suite

    #[derive(PartialEq, Clone, Debug)]
    struct TestEvent {
        path: EventPath,
        event_number: u64,
        priority: u8,
        timestamp: EventDataTimestamp,
        data: u64, // TODO(events): Need to test mixed-sized, incl zero-sized, payloads
    }

    impl TestEvent {
        fn new(event_number: u64, priority: u8) -> Self {
            Self {
                path: EP1.clone(),
                event_number,
                priority,
                timestamp: EventDataTimestamp::EpochTimestamp(10_000 + event_number),
                data: 1337,
            }
        }

        fn vec_from(buf: &TLVRingBuf) -> Result<heapless::Vec<TestEvent, 16>, Error> {
            let mut out = heapless::Vec::new();
            for tr in buf.iter() {
                let e = EventQueueIter::parse_event(tr?)?;
                out.push(TestEvent {
                    path: e.path,
                    event_number: e.event_number,
                    priority: e.priority,
                    timestamp: e.timestamp,
                    data: e.data.u64()?,
                }).unwrap();
            }
            Ok(out)
        }

        fn push_into(&self, q: &mut EventQueue2) -> Result<(), Error> {
            let mut tw = q.push(self.path.clone(), self.event_number, self.priority, self.timestamp.clone())?;
            tw.u64(&TLVTag::Context(EventDataTag::Data as _), self.data)?;
            tw.end()
        }
    }
}