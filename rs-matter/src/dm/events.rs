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
use crate::utils::init::{init, Init};
use crate::utils::sync::blocking::Mutex;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::im::EventData;

pub const DEFAULT_BYTES_PER_BUF: usize = 16; // TODO(events) what to set this to?

/// A type alias for `Events` with the default maximum number of subscriptions.
pub type DefaultEvents = Events<DEFAULT_BYTES_PER_BUF>;

pub struct Events<const N: usize = DEFAULT_BYTES_PER_BUF, M = NoopRawMutex>
where
    M: RawMutex,
{
    state: Mutex<M, RefCell<EventsInner<N>>>,
}

impl<const N: usize, M> Events<N, M>
where
    M: RawMutex,
{
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(EventsInner::new())),
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(EventsInner::init())),
        })
    }

    pub fn push(
        &self,
        path: EventPath,
        priority: u8,
        data: impl FnOnce(&mut EventQueueWriter<N>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.state.lock(|internal| {
            let mut q = internal.borrow_mut();
            let event_no = q.next_event_no;
            q.next_event_no += 1;
            // TODO(events): actual timestamps
            let timestamp = EventDataTimestamp::SystemTimestamp(0);
            let mut tw = q.push(path, event_no, priority, timestamp)?;
            data(&mut tw)?;
            tw.end()
        })
    }

    // Iterate over each entry in the queue, aborts if f returns Err
    pub fn for_each<'a, F>(&'a self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(&EventData<'_>) -> Result<(), Error>,
    {
        self.state.lock(|internal| {
            let q = internal.borrow();
            for entry in q.iter() {
                let entry = entry?;
                f(&entry)?;
            }
            Ok(())
        })
    }
}

/// This is the central event queue storage system. It's modeled after the tiered ring buffer design
/// used in the C++ matter SDK. Every new event is written to the next slot in the DEBUG ring buffer.
/// If there is not space for the new event, events are FIFO evicted from the first ring buffer.
/// If the evicted event has a priority level as high as or higher than the next ring buffer in the chain,
/// then the evicted event is promoted to there, surviving to see another day.
/// Promotion may in turn require more eviction in the next buffer, and so on up the chain.
/// The end result is that critical events get to live in any of the ring buffers, making their way through
/// all three until they finally age out. Info lives in one of the first two, and debug only in the first.
///
/// TODO(events): Per discussion in PR, I don't understand how this design does not violate the spec; I don't mind
///               violating the spec if the C++ impl does so as well, but I'm worried I've misunderstood something about
///               the C++ implementation. Specifically this design allows critical events to be evicted to make space
///               for Debug and/or info events. This happens when the oldest event in the debug and info ring buffers are
///               Critical events, which will cause promotion to the last buffer and eviction there of the oldest critical event
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct EventsInner<const N: usize> {
    // TODO(events): Allow per-ring const generics
    buf_debug: TLVRingBuf<N>,
    buf_info: TLVRingBuf<N>,
    buf_critical: TLVRingBuf<N>,
    next_event_no: u64,
}

impl<const N: usize> EventsInner<N> {
    const fn new() -> Self {
        Self {
            buf_debug: TLVRingBuf::new(),
            buf_info: TLVRingBuf::new(),
            buf_critical: TLVRingBuf::new(),
            // TODO(events): This needs persistence
            next_event_no: 0,
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            buf_debug <- TLVRingBuf::init(),
            buf_info <- TLVRingBuf::init(),
            buf_critical <- TLVRingBuf::init(),
            // TODO(events): This needs persistence
            next_event_no: 0,
        })
    }

    pub fn push<'a>(
        &'a mut self,
        path: EventPath,
        event_number: u64,
        priority: u8,
        timestamp: EventDataTimestamp,
    ) -> Result<EventQueueWriter<'a, N>, Error> {
        let mut tw = EventQueueWriter::new(self, BufLevel::Debug);
        tw.start_struct(&TLVTag::Context(EventRespTag::Data as _))?;
        path.to_tlv(&TagType::Context(EventDataTag::Path as _), &mut tw)?;
        tw.u64(
            &TagType::Context(EventDataTag::EventNumber as _),
            event_number,
        )?;
        tw.u8(&TagType::Context(EventDataTag::Priority as _), priority)?;
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

    fn iter<'a>(&'a self) -> EventQueueIter<'a, N> {
        EventQueueIter {
            queue: self,
            buf_ref: BufLevel::Debug,
            buf_iter: self.buf_debug.iter(),
        }
    }
}

struct EventQueueIter<'a, const N: usize> {
    queue: &'a EventsInner<N>,
    buf_ref: BufLevel<N>,
    buf_iter: TLVRingBufIter<'a, N>,
}

impl<'a, const N: usize> Iterator for EventQueueIter<'a, N> {
    type Item = Result<EventData<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(res) = self.buf_iter.next() {
            match res {
                Ok(tr) => return Some(parse_event(tr)),
                Err(e) => return Some(Err(e)),
            }
        }

        if let Some(next_buf_ref) = self.buf_ref.next_level() {
            self.buf_iter = next_buf_ref.get(self.queue).iter();
            self.buf_ref = next_buf_ref;
            return self.next();
        }
        None
    }
}

fn parse_event<'a>(tr: TLVElement<'a>) -> Result<EventData<'a>, Error> {
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
            Ok(EventDataTag::SystemTimestamp) => {
                timestamp = Some(EventDataTimestamp::SystemTimestamp(elem.u64()?))
            }
            Ok(EventDataTag::EpochTimestamp) => {
                timestamp = Some(EventDataTimestamp::EpochTimestamp(elem.u64()?))
            }
            Ok(EventDataTag::DeltaSystemTimestamp) => {
                timestamp = Some(EventDataTimestamp::DeltaSystemTimestamp(elem.u64()?))
            }
            Ok(EventDataTag::DeltaEpochTimestamp) => {
                timestamp = Some(EventDataTimestamp::DeltaEpochTimestamp(elem.u64()?))
            }
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

pub struct EventQueueWriter<'a, const N: usize> {
    queue: &'a mut EventsInner<N>,
    buf_ref: BufLevel<N>,
    // Used in Drop to ensure clients call end(), otherwise data corruption happens
    ended: bool,
}

impl<'a, const N: usize> EventQueueWriter<'a, N> {
    fn new(queue: &'a mut EventsInner<N>, buf_ref: BufLevel<N>) -> Self {
        Self {
            queue,
            buf_ref,
            ended: false,
        }
    }

    pub fn end(&mut self) -> Result<(), Error> {
        if self.ended {
            return Ok(());
        }
        self.end_container()?;
        self.ended = true;
        Ok(())
    }

    // Evict one entry from the given buffer, potentially promoting it to the next buffer if
    // it meets the priority threshold. If promotion happens the eviction "cascades", until
    // we either evict an event that doesn't meet the next buffers prio level or we run out of
    // ring buffers and drop the oldest critical event.
    fn evict(&mut self, buf_ref: BufLevel<N>) -> Result<(), Error> {
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

    // Work out the size and priority of the next victim in the given buffer
    fn prepare_eviction(&self, buf: &TLVRingBuf<N>) -> Result<(u8, VictimRef), Error> {
        let victim_ref = buf.prepare_eviction()?;
        let priority = victim_ref
            .tlv(buf)
            .structure()?
            .find_ctx(EventDataTag::Priority as _)?
            .u8()?;
        Ok((priority, victim_ref))
    }

    // Promotes victim_ref from src to dst, making space in dst (potentially cascading) if needed
    fn promote(
        &mut self,
        src_buf: BufLevel<N>,
        dst_buf: BufLevel<N>,
        victim_ref: VictimRef,
    ) -> Result<(), Error> {
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

impl<'a, const N: usize> Drop for EventQueueWriter<'a, N> {
    fn drop(&mut self) {
        if !self.ended {
            // TODO(events) what do we do, error log?
            todo!()
        }
    }
}

impl<'a, const N: usize> TLVWrite for EventQueueWriter<'a, N> {
    type Position = usize;

    fn write(&mut self, byte: u8) -> Result<(), Error> {
        if self.ended {
            // TODO(events) context and/or logging?
            return Err(Error::new(ErrorCode::Failure));
        }
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
struct TLVRingBuf<const N: usize> {
    data: [u8; N],
    head: usize,
    // n.b. there is no tail. We don't have a way to read streaming TLVs, so we can't have a TLV "wrap around" at the end
    // and continue at the start of data. Instead, tail is always zero, and whenever we evict we left-shift the entire buffer
    // see evict.
}

impl<const N: usize> TLVRingBuf<N> {
    const fn new() -> Self {
        Self {
            data: [0; N],
            head: 0,
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            data: [0; N],
            head: 1,
        })
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
        Ok(VictimRef {
            victim_len: self.record_len(0)?,
        })
    }

    fn evict(&mut self, victim: VictimRef) {
        self.data.copy_within(victim.len()..self.head, 0);
        self.head -= victim.len();
    }

    fn iter(&self) -> TLVRingBufIter<'_, N> {
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
    fn tlv<'a, const N: usize>(&'a self, buf: &'a TLVRingBuf<N>) -> TLVElement<'a> {
        TLVElement::new(self.raw(buf))
    }

    fn raw<'a, const N: usize>(&'a self, buf: &'a TLVRingBuf<N>) -> &'a [u8] {
        &buf.data[0..self.victim_len]
    }

    fn len(&self) -> usize {
        self.victim_len
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct TLVRingBufIter<'a, const N: usize> {
    buf: &'a TLVRingBuf<N>,
    pos: usize,
}

impl<'a, const N: usize> Iterator for TLVRingBufIter<'a, N> {
    type Item = Result<TLVElement<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        // TODO(events) this doesn't handle wrap-around
        if self.pos >= self.buf.head as _ {
            return None;
        }
        let record_len = match self.buf.record_len(self.pos) {
            Ok(raw) => raw,
            Err(e) => return Some(Err(e)),
        };

        let start = self.pos;
        self.pos += record_len;

        Some(Ok(TLVElement::new(
            &self.buf.data[start..start + record_len],
        )))
    }
}

enum WriteOutcome {
    Ok,
    // The write failed because the head is caught up with the tail,
    // evict an entry and try again
    Overflow,
}

// This is how we handle the "levels" of buffers, using this reference we can access the current
// level and get access to the next level, if there is one
#[derive(PartialEq, Clone, Copy)]
enum BufLevel<const N: usize> {
    Debug,
    Info,
    Critical,
}

impl<const N: usize> BufLevel<N> {
    fn threshold(&self) -> u8 {
        // 7.19.2.17
        match self {
            BufLevel::Debug => 0,
            BufLevel::Info => 1,
            BufLevel::Critical => 2,
        }
    }

    fn get_mut<'a>(&self, queue: &'a mut EventsInner<N>) -> &'a mut TLVRingBuf<N> {
        match self {
            BufLevel::Debug => &mut queue.buf_debug,
            BufLevel::Info => &mut queue.buf_info,
            BufLevel::Critical => &mut queue.buf_critical,
        }
    }

    fn get<'a>(&self, queue: &'a EventsInner<N>) -> &'a TLVRingBuf<N> {
        match self {
            BufLevel::Debug => &queue.buf_debug,
            BufLevel::Info => &queue.buf_info,
            BufLevel::Critical => &queue.buf_critical,
        }
    }

    /// Used during promotion, when we need both the src and dst buffers at the same time
    fn get_mut_and_next<'a>(
        &self,
        queue: &'a mut EventsInner<N>,
    ) -> (&'a mut TLVRingBuf<N>, Option<&'a mut TLVRingBuf<N>>) {
        match self {
            BufLevel::Debug => (&mut queue.buf_debug, Some(&mut queue.buf_info)),
            BufLevel::Info => (&mut queue.buf_info, Some(&mut queue.buf_critical)),
            BufLevel::Critical => (&mut queue.buf_critical, None),
        }
    }

    fn next_level(&self) -> Option<BufLevel<N>> {
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

    const EP1: EventPath = EventPath {
        node: Some(1337),
        endpoint: Some(42),
        cluster: Some(1),
        event: Some(0xB33F),
        is_urgent: Some(true),
    };

    #[test]
    fn one_entry() {
        let crit1 = TestEvent::new(1, 2);
        let mut q = EventsInner::new();

        crit1.push_into(&mut q).unwrap();

        assert_eq!(TestEvent::vec_from(&q.buf_debug).unwrap(), &[crit1]);
    }

    #[test]
    fn critical_is_promoted() {
        let crit1 = TestEvent::new(1, 2);
        let crit2 = TestEvent::new(2, 2);
        let crit3 = TestEvent::new(3, 2);
        let mut q = EventsInner::new();

        crit1.push_into(&mut q).unwrap();
        crit2.push_into(&mut q).unwrap();
        crit3.push_into(&mut q).unwrap();

        assert_eq!(TestEvent::vec_from(&q.buf_debug).unwrap(), &[crit3]);

        assert_eq!(TestEvent::vec_from(&q.buf_info).unwrap(), &[crit2]);
        assert_eq!(TestEvent::vec_from(&q.buf_critical).unwrap(), &[crit1]);
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

        fn vec_from(buf: &TLVRingBuf<64>) -> Result<heapless::Vec<TestEvent, 16>, Error> {
            let mut out = heapless::Vec::new();
            for tr in buf.iter() {
                let e = parse_event(tr?)?;
                out.push(TestEvent {
                    path: e.path,
                    event_number: e.event_number,
                    priority: e.priority,
                    timestamp: e.timestamp,
                    data: e.data.u64()?,
                })
                .unwrap();
            }
            Ok(out)
        }

        fn push_into(&self, q: &mut EventsInner<64>) -> Result<(), Error> {
            let mut tw = q.push(
                self.path.clone(),
                self.event_number,
                self.priority,
                self.timestamp.clone(),
            )?;
            tw.u64(&TLVTag::Context(EventDataTag::Data as _), self.data)?;
            tw.end()
        }
    }
}
