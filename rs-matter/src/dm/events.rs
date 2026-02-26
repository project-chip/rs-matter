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
use core::cell::Cell;
use core::fmt::Debug;

use crate::error::{Error, ErrorCode};
use crate::im::{EventDataTag, EventDataTimestamp, EventPath, EventRespTag};
use crate::tlv::{
    FromTLV, TLVElement, TLVSequence, TLVSequenceIter, TLVTag, TLVWrite, TagType, ToTLV,
};
use crate::utils::epoch::Epoch;
use crate::utils::init::{init, Init};
use crate::utils::storage::WriteBuf;
use crate::utils::sync::blocking;
use crate::utils::sync::Notification;
use crate::utils::sync::{IfMutex, IfMutexGuard};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::im::EventData;

// TODO we currently only have this singular config to set the size, but the events are stored in three "tiered" buffers, and
//      we probably want to allow configuring them separately. We also should spend some thinking tokens on what a good default here is.
pub const DEFAULT_BYTES_PER_BUF: usize = 64;

/// See EventsPersist for details
const EVENT_NO_EPOCH_SIZE: u64 = 0x10000;

/// How far before the epoch boundary to trigger a persist, so the persistence
/// system has time to write before we actually reach the boundary.
/// TODO: While this helps, there's till a proper race condition here; we should update the code to wait if persistence is lagging behind
const EVENT_ID_COUNTER_PERSIST_AHEAD: u64 = 1000;

/// Persistence state for events.
///
/// We need event numbers to always be incrementing and never be reused.
/// To handle that we need to persist them, so reboots don't cause event number reuse.
/// However, we can't persist every event number increment, because of flash wear. Hence
/// this thing. We store "epoch" increments of 2^16; then we use up that epoch to emit events
/// and then persist another epoch. The result is that we only write once every ~2h if we're
/// writing 10 events per second, but we still ensure we don't re-use event numbers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PersistedState {
    /// The next event number to assign; this is actually *not* persisted, ironically, but
    /// the locking is simpler if we keep this here next to the epoch stuff
    pub(crate) next_event_no: u64,
    /// The persisted epoch boundary. Events up to `epoch_end - 1` can be
    /// emitted without a new flash write. When we approach this boundary
    /// (within `EVENT_ID_COUNTER_PERSIST_AHEAD`), we bump it by another epoch.
    pub(crate) event_epoch_end: u64,
    pub(crate) changed: bool,
}

/// A type alias for `Events` with the default maximum number of subscriptions.
pub type DefaultEvents = Events<DEFAULT_BYTES_PER_BUF>;

/// This is the event queue system, it lets you publish Matter Events into a priority queue,
/// and allows subscribers and remote clients to read the data you've published.
///
/// NOTE: The API of this is provisional and subject to change
///
/// If you are in a concurrent environment you need to select an appropriate mutex implementation for M
/// The queue is implemented as three equally sized ring buffers, the size of the buffers is set by N.
/// Hence the memory use of the buffers will be 3 * N. If you pick a very small N clients that poll may
/// miss events as they fall out of the queue, but a large N of course uses more memory. You may need
/// to experiment to pick an appropriate size for your event write load.
///
/// If your application emits no events you can set N to 0.
pub struct Events<const N: usize = DEFAULT_BYTES_PER_BUF, M = NoopRawMutex>
where
    M: RawMutex,
{
    state: IfMutex<M, EventsInner<N>>,
    epoch: Epoch,
    pub(crate) persisted_state: blocking::Mutex<M, Cell<PersistedState>>,
    persist_notification: Notification<M>,
}

impl<const N: usize, M> Events<N, M>
where
    M: RawMutex,
{
    const PERSIST_INIT: PersistedState = PersistedState {
        next_event_no: 0,
        event_epoch_end: 0,
        changed: false,
    };

    #[inline(always)]
    pub const fn new(epoch: Epoch) -> Self {
        Self {
            state: IfMutex::new(EventsInner::new()),
            epoch,
            persisted_state: blocking::Mutex::new(Cell::new(Self::PERSIST_INIT)),
            persist_notification: Notification::new(),
        }
    }

    #[cfg(feature = "std")]
    #[inline(always)]
    pub const fn new_default() -> Self {
        use crate::utils::epoch::sys_epoch;
        Self::new(sys_epoch)
    }

    pub fn init(epoch: Epoch) -> impl Init<Self> {
        init!(Self {
            state <- IfMutex::init(EventsInner::init()),
            epoch,
            persisted_state: blocking::Mutex::new(Cell::new(Self::PERSIST_INIT)),
            persist_notification: Notification::new(),
        })
    }

    /// Push a new event into the event queue, making it visible to any subscribers.
    /// NOTE: This API is unstable and may change, for instance it currently requires knowing the tag number for writing data
    ///
    /// To write event data you use the provided EventQueueWriter and write the tag EventDataTag::Data.
    pub async fn push(
        &self,
        path: EventPath,
        priority: u8,
        data: impl FnOnce(&mut EventQueueWriter<N>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let (event_no, notify) = self.persisted_state.lock(|cell| {
            let mut state = cell.get();
            let event_no = state.next_event_no;
            state.next_event_no += 1;

            let notify = if state.next_event_no
                >= state
                    .event_epoch_end
                    .saturating_sub(EVENT_ID_COUNTER_PERSIST_AHEAD)
            {
                state.event_epoch_end = state.next_event_no.saturating_add(EVENT_NO_EPOCH_SIZE);
                state.changed = true;
                true
            } else {
                false
            };

            cell.set(state);
            (event_no, notify)
        });

        if notify {
            self.persist_notification.notify();
        }

        let mut internal = self.state.lock().await;
        let timestamp = EventDataTimestamp::EpochTimestamp((self.epoch)().as_millis() as u64);
        let mut tw = internal.push(path, event_no, priority, timestamp)?;
        data(&mut tw)?;
        tw.end()
    }

    /// Lock the events queue so you can read it; the returned guard gives you the ability to iterate over stored events.
    /// TODO: Note that this guard is held across long reads, which will cause writers to be stalled over network waits; we should fix this, see https://github.com/project-chip/rs-matter/pull/361#issuecomment-3906929345
    pub async fn lock(&'_ self) -> EventsGuard<'_, M, N> {
        let internal = self.state.lock().await;
        EventsGuard::new(internal)
    }

    // TODO(events) we can't do it like this, this will miss events when pushing happens after for_each but before we call this
    //              we need to return the last processed one from for_each or something like that
    pub fn peek_next_event_no(&self) -> u64 {
        self.persisted_state.lock(|cell| cell.get().next_event_no)
    }

    /// True if the persisted state has changed since the last time store() was called.
    pub fn changed(&self) -> bool {
        self.persisted_state.lock(|cell| cell.get().changed)
    }

    /// Restore events from previously persisted state.
    pub fn load(&self, data: &[u8]) -> Result<(), Error> {
        let epoch_end = TLVElement::new(data).u64()?;

        self.persisted_state.lock(|cell| {
            cell.set(PersistedState {
                next_event_no: epoch_end,
                event_epoch_end: epoch_end.saturating_add(EVENT_NO_EPOCH_SIZE),
                changed: true,
            });
        });

        Ok(())
    }

    /// Store events persistence state into a byte slice.
    pub fn store(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let epoch_end = self.persisted_state.lock(|cell| {
            let mut state = cell.get();
            state.changed = false;
            cell.set(state);
            state.event_epoch_end
        });

        let mut wb = WriteBuf::new(buf);
        wb.u64(&TLVTag::Anonymous, epoch_end)?;
        Ok(wb.get_tail())
    }

    /// Wait until the persistent state needs re-persisting.
    pub async fn wait_persist(&self) {
        loop {
            if self.persisted_state.lock(|cell| cell.get().changed) {
                break;
            }
            self.persist_notification.wait().await;
        }
    }
}

/// A thin guard that acts both to keep the event queue stable while we iterate over it, but also
/// as back-pressure to writers. If writers are faster than we're able to publish events on the network,
/// events will get dropped, leading to errors. Hence, while we write to the network we force writers to stall.
///
/// Most of the time the stalling of writers is very short, just enough to move the events into outbound
/// network buffers. However if there are a lot of events, such that we need to chunk publishing into multiple packets,
/// then we will hold this across network calls, forcing writers to slow down until readers have caught up.
pub struct EventsGuard<'a, M, const N: usize>
where
    M: RawMutex,
{
    guard: IfMutexGuard<'a, M, EventsInner<N>>,
}

impl<'a, M, const N: usize> EventsGuard<'a, M, N>
where
    M: RawMutex,
{
    fn new(guard: IfMutexGuard<'a, M, EventsInner<N>>) -> Self {
        Self { guard }
    }

    pub fn iter(&'_ self) -> EventQueueIter<'_, N> {
        self.guard.iter()
    }
}

/// This is the central event queue storage system. It's modeled after the tiered ring buffer design
/// used in the C++ matter SDK. *Every* new event is written to the next slot in the DEBUG level buffer.
/// If there is not space for the new event, events are FIFO evicted from the first level buffer.
/// If the evicted event has a priority level as high as or higher than the next level buffer in the chain,
/// then the evicted event is promoted to there, surviving to see another day.
/// Promotion may in turn require more eviction in the next buffer, and so on up the chain.
/// The end result is that critical events get to live in any of the level buffers, making their way through
/// all three until they finally age out. Info lives in one of the first two, and debug only in the first.
///
/// n.b. the discussion in PR #361 that introduced this: We were not able to determine a way to
/// implement a priority queue that both met the specs requirements (low-prio events must not cause
/// eviction of high-prio events) while also allowing debug and info-prio events to be emitted at all.
/// Instead we opted to replicate the approach used in the C++ impl, which we believe is reasonable but
/// also seemingly in violation of the spec.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct EventsInner<const N: usize> {
    // TODO(events): Allow per-ring const generics, so the rings can be sized independently
    buf_debug: LevelBuf<N>,
    buf_info: LevelBuf<N>,
    buf_critical: LevelBuf<N>,
}

impl<const N: usize> EventsInner<N> {
    const fn new() -> Self {
        Self {
            buf_debug: LevelBuf::new(),
            buf_info: LevelBuf::new(),
            buf_critical: LevelBuf::new(),
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            buf_debug <- LevelBuf::init(),
            buf_info <- LevelBuf::init(),
            buf_critical <- LevelBuf::init(),
        })
    }

    pub fn push<'a>(
        &'a mut self,
        path: EventPath,
        event_number: u64,
        priority: u8,
        timestamp: EventDataTimestamp,
    ) -> Result<EventQueueWriter<'a, N>, Error> {
        let mut tw = EventQueueWriter::new(self, Level::Debug);
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
            buf_ref: Level::Critical,
            buf_iter: self.buf_critical.iter(),
        }
    }
}

pub struct EventQueueIter<'a, const N: usize> {
    queue: &'a EventsInner<N>,
    buf_ref: Level<N>,
    buf_iter: TLVSequenceIter<'a>,
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

        if let Some(next_buf_ref) = self.buf_ref.prior_level() {
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

        match EventDataTag::try_from(elem.ctx()?)? {
            EventDataTag::Path => path = Some(EventPath::from_tlv(&elem)?),
            EventDataTag::EventNumber => event_number = Some(elem.u64()?),
            EventDataTag::Priority => priority = Some(elem.u8()?),
            EventDataTag::SystemTimestamp => {
                timestamp = Some(EventDataTimestamp::SystemTimestamp(elem.u64()?))
            }
            EventDataTag::EpochTimestamp => {
                timestamp = Some(EventDataTimestamp::EpochTimestamp(elem.u64()?))
            }
            EventDataTag::DeltaSystemTimestamp => {
                timestamp = Some(EventDataTimestamp::DeltaSystemTimestamp(elem.u64()?))
            }
            EventDataTag::DeltaEpochTimestamp => {
                timestamp = Some(EventDataTimestamp::DeltaEpochTimestamp(elem.u64()?))
            }
            EventDataTag::Data => data = Some(elem.clone()),
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
    buf_ref: Level<N>,
    bytes_written: usize,
}

impl<'a, const N: usize> EventQueueWriter<'a, N> {
    fn new(queue: &'a mut EventsInner<N>, buf_ref: Level<N>) -> Self {
        Self {
            queue,
            buf_ref,
            bytes_written: 0,
        }
    }

    fn end(&mut self) -> Result<(), Error> {
        self.end_container()?;
        Ok(())
    }

    // Evict one entry from the given buffer, potentially promoting it to the next buffer if
    // it meets the priority threshold. If promotion happens the eviction "cascades", until
    // we either evict an event that doesn't meet the next buffers prio level or we run out of
    // level buffers and drop the oldest critical event.
    fn evict(&mut self, buf_ref: Level<N>) -> Result<(), Error> {
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
    fn prepare_eviction(&self, buf: &LevelBuf<N>) -> Result<(u8, VictimRef), Error> {
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
        src_buf: Level<N>,
        dst_buf: Level<N>,
        victim_ref: VictimRef,
    ) -> Result<(), Error> {
        // Make space (n.b. this assumes the next level is always at least as large as the current level, which is currently always true)
        while dst_buf.get(self.queue).capacity() < victim_ref.len() {
            self.evict(dst_buf)?;
        }

        let (src, dst) = src_buf.get_mut_and_next(self.queue);
        let dst = dst.expect("dst buffer should always exist as this is checked in evict()");
        dst.write_slice(victim_ref.raw(src))
            .expect("should not overflow as eviction should have cleared space");
        Ok(())
    }
}

impl<'a, const N: usize> TLVWrite for EventQueueWriter<'a, N> {
    type Position = usize;

    fn write(&mut self, byte: u8) -> Result<(), Error> {
        if self.bytes_written == N {
            // This event is larger than the buffer, the client needs to change the buffer size for this to work
            return Err(Error::new(ErrorCode::NoSpace));
        }
        while let Err(OverflowError {}) = self.buf_ref.get_mut(self.queue).write(byte) {
            // Overflow, need to evict an entry
            self.evict(Level::Debug)?;
        }
        self.bytes_written += 1;
        Ok(())
    }

    fn get_tail(&self) -> Self::Position {
        // n.b. TLVWrite calls the next position to be written "tail", but our level buffer calls that position "head"
        self.queue.buf_debug.head
    }

    fn rewind_to(&mut self, pos: Self::Position) {
        self.queue.buf_debug.head = pos;
    }
}

/// LevelBuf stores one "level" of events, see the doc string on EventsInner for more info on that.
///
/// This behaves very similar to a ring buffer - you can append data at the write head, and eventually
/// the head will catch up and "eat" the tail, implementing a sort of sliding window of visible data.
///
/// This is a much less efficient variant though - it left-shifts the entire buffer to "evict" old records,
/// rather than just track head/tail pointers with wrap-around.
///
/// The thing we gain from the less efficient implementation is that records are never "split up", they are
/// always complete TLVs in contiguous memory, which allows us to use TLVElement to read the records.
///
/// If you feel enthusiastic, it might give some performance gains to replace this with a real ring buffer.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct LevelBuf<const N: usize> {
    data: [u8; N],
    head: usize,
}

impl<const N: usize> LevelBuf<N> {
    const fn new() -> Self {
        Self {
            data: [0; N],
            head: 0,
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            data <- crate::utils::init::zeroed(),
            head: 0,
        })
    }

    fn write(&mut self, byte: u8) -> Result<(), OverflowError> {
        if self.capacity() == 0 {
            return Err(OverflowError {});
        }
        self.data[self.head] = byte;
        self.head += 1;
        Ok(())
    }

    fn write_slice(&mut self, data: &[u8]) -> Result<(), OverflowError> {
        if self.capacity() < data.len() {
            return Err(OverflowError {});
        }
        self.data[self.head..self.head + data.len()].copy_from_slice(data);
        self.head += data.len();
        Ok(())
    }

    // Get the size of the record at the given position; the caller is responsible for ensuring pos is aligned on a record
    fn record_len(&self, pos: usize) -> Result<usize, Error> {
        TLVSequence(&self.data[pos..]).container_len()
    }

    fn capacity(&self) -> usize {
        self.data.len() - self.head
    }

    fn prepare_eviction(&self) -> Result<VictimRef, Error> {
        Ok(VictimRef {
            victim_len: self.record_len(0)?,
        })
    }

    fn evict(&mut self, victim: VictimRef) {
        self.data.copy_within(victim.len()..self.head, 0);
        self.head -= victim.len();
    }

    fn iter(&self) -> TLVSequenceIter<'_> {
        TLVSequence(&self.data[0..self.head]).iter()
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
    fn tlv<'a, const N: usize>(&self, buf: &'a LevelBuf<N>) -> TLVElement<'a> {
        TLVElement::new(self.raw(buf))
    }

    fn raw<'a, const N: usize>(&self, buf: &'a LevelBuf<N>) -> &'a [u8] {
        &buf.data[0..self.victim_len]
    }

    fn len(&self) -> usize {
        self.victim_len
    }
}

#[derive(Debug)]
struct OverflowError;

// This is how we handle the "levels" of buffers, using this reference we can access the current
// level and get access to the next level, if there is one
#[derive(PartialEq, Clone, Copy)]
enum Level<const N: usize> {
    Debug,
    Info,
    Critical,
}

impl<const N: usize> Level<N> {
    fn threshold(&self) -> u8 {
        // 7.19.2.17
        match self {
            Level::Debug => 0,
            Level::Info => 1,
            Level::Critical => 2,
        }
    }

    fn get_mut<'a>(&self, queue: &'a mut EventsInner<N>) -> &'a mut LevelBuf<N> {
        match self {
            Level::Debug => &mut queue.buf_debug,
            Level::Info => &mut queue.buf_info,
            Level::Critical => &mut queue.buf_critical,
        }
    }

    fn get<'a>(&self, queue: &'a EventsInner<N>) -> &'a LevelBuf<N> {
        match self {
            Level::Debug => &queue.buf_debug,
            Level::Info => &queue.buf_info,
            Level::Critical => &queue.buf_critical,
        }
    }

    /// Used during promotion, when we need both the src and dst buffers at the same time
    fn get_mut_and_next<'a>(
        &self,
        queue: &'a mut EventsInner<N>,
    ) -> (&'a mut LevelBuf<N>, Option<&'a mut LevelBuf<N>>) {
        match self {
            Level::Debug => (&mut queue.buf_debug, Some(&mut queue.buf_info)),
            Level::Info => (&mut queue.buf_info, Some(&mut queue.buf_critical)),
            Level::Critical => (&mut queue.buf_critical, None),
        }
    }

    fn next_level(&self) -> Option<Level<N>> {
        match self {
            Level::Debug => Some(Level::Info),
            Level::Info => Some(Level::Critical),
            Level::Critical => None,
        }
    }

    /// Used during iteration, note that this goes "backwards" compared to get_mut_and_next;
    /// when iterating we want to start with the oldest events, so we start with the "highest"
    /// level where the oldest survivors are and work back
    fn prior_level(&self) -> Option<Level<N>> {
        match self {
            Level::Debug => None,
            Level::Info => Some(Level::Debug),
            Level::Critical => Some(Level::Info),
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
        let mut q: EventsInner<64> = EventsInner::new();

        crit1.push_into(&mut q).unwrap();

        assert_eq!(TestEvent::vec_from(&q.buf_debug).unwrap(), &[crit1]);
    }

    #[test]
    fn critical_is_promoted() {
        let crit1 = TestEvent::new(1, 2);
        let crit2 = TestEvent::new(2, 2);
        let crit3 = TestEvent::new(3, 2);
        let mut q: EventsInner<64> = EventsInner::new();

        crit1.push_into(&mut q).unwrap();
        crit2.push_into(&mut q).unwrap();
        crit3.push_into(&mut q).unwrap();

        assert_eq!(TestEvent::vec_from(&q.buf_debug).unwrap(), &[crit3]);
        assert_eq!(TestEvent::vec_from(&q.buf_info).unwrap(), &[crit2]);
        assert_eq!(TestEvent::vec_from(&q.buf_critical).unwrap(), &[crit1]);
    }

    #[test]
    fn debug_is_dropped() {
        let crit1 = TestEvent::new(1, 2);
        let dbg2 = TestEvent::new(2, 0);
        let crit3: TestEvent = TestEvent::new(3, 2);
        let mut q: EventsInner<64> = EventsInner::new();

        crit1.push_into(&mut q).unwrap();
        dbg2.push_into(&mut q).unwrap();
        crit3.push_into(&mut q).unwrap();

        // Then the dbg level has the last event - crit3
        assert_eq!(TestEvent::vec_from(&q.buf_debug).unwrap(), &[crit3]);
        // The info level has the first critical event, the dbg event evicted it to there
        // but when crit3 was pushed the debug event didn't get promoted, so crit1 stays put
        assert_eq!(TestEvent::vec_from(&q.buf_info).unwrap(), &[crit1]);
        // And finally there's then nothing here
        assert_eq!(TestEvent::vec_from(&q.buf_critical).unwrap(), &[]);
    }

    #[test]
    fn event_larger_than_buffer() {
        let crit1 = TestEvent::new(1, 2);
        let mut q: EventsInner<8> = EventsInner::new();

        assert_eq!(
            crit1.push_into(&mut q).expect_err("").code(),
            ErrorCode::NoSpace
        );
    }

    // Test utilities for this suite

    #[derive(PartialEq, Clone, Debug)]
    struct TestEvent {
        path: EventPath,
        event_number: u64,
        priority: u8,
        timestamp: EventDataTimestamp,
        data: u64,
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

        fn vec_from<const N: usize>(
            buf: &LevelBuf<N>,
        ) -> Result<heapless::Vec<TestEvent, 16>, Error> {
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

        fn push_into<const N: usize>(&self, q: &mut EventsInner<N>) -> Result<(), Error> {
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
