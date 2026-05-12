/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

use crate::dm::{ClusterId, EndptId, EventId};
use crate::error::{Error, ErrorCode};
use crate::im::{
    EventData, EventDataTag, EventDataTimestamp, EventNumber, EventPath, EventPriority,
    EventRespTag,
};
use crate::persist::{KvBlobStore, KvBlobStoreAccess, Persist, EVENT_EPOCH_KEY};
use crate::tlv::{
    FromTLV, TLVBuilderParent, TLVElement, TLVSequence, TLVSequenceIter, TLVTag, TLVWrite,
};
use crate::utils::cell::RefCell;
use crate::utils::epoch::Epoch;
use crate::utils::init::{init, Init};
use crate::utils::sync::blocking::Mutex;

/// The default size of each event buffer in bytes.
/// This is a tradeoff between memory use and the risk of evicting events before subscribers have had a chance to read them.
pub const DEFAULT_MAX_EVENTS_BUF_SIZE: usize = 256;

/// The size when events won't be used
pub const NO_EVENTS_BUF_SIZE: usize = 0;

/// A type alias for `Events` with zero capacity, for when events need to be disabled.
pub type NoEvents = Events<NO_EVENTS_BUF_SIZE>;

/// Only persist every `EVENT_NUMBER_EPOCH_SIZE` event numbers to avoid flash wear.
const EVENT_NUMBER_EPOCH_SIZE: EventNumber = 10000;

/// Events queue.
///
/// It lets one publish Matter Events into a priority queue,
/// and allows subscribers and remote clients to read the published events.
///
/// The queue is implemented as three equally sized ring buffers, the size of the buffers is set by N.
/// Hence the memory use of the buffers will be 3 * N.
/// If a very small N is picked, then clients that poll may miss events as they fall out of the queue;
/// but a large N of course uses more memory.
///
/// If the app emits no events, this subsystem can be disabled by using the `NoEvents` type alias.
pub struct Events<const N: usize = DEFAULT_MAX_EVENTS_BUF_SIZE> {
    inner: Mutex<RefCell<EventsInner<N>>>,
    epoch: Epoch,
}

impl<const N: usize> Events<N> {
    #[inline(always)]
    pub const fn new(epoch: Epoch) -> Self {
        Self {
            inner: Mutex::new(RefCell::new(EventsInner::new())),
            epoch,
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
            inner <- Mutex::init(RefCell::init(EventsInner::init())),
            epoch,
        })
    }

    #[cfg(feature = "std")]
    pub fn init_default() -> impl Init<Self> {
        init!(Self {
            inner <- Mutex::init(RefCell::init(EventsInner::init())),
            epoch: crate::utils::epoch::sys_epoch,
        })
    }

    pub fn reset(&mut self) {
        self.inner.get_mut().borrow_mut().reset();
    }

    /// Remove persisted state from the given key-value store.
    pub async fn reset_persist<S>(&mut self, kv: S, buf: &mut [u8]) -> Result<(), Error>
    where
        S: KvBlobStore,
    {
        self.inner
            .get_mut()
            .borrow_mut()
            .reset_persist(kv, buf)
            .await
    }

    /// Load persisted state from the given key-value store, so that we can continue emitting events without reusing event numbers.
    pub async fn load_persist<S>(&mut self, kv: S, buf: &mut [u8]) -> Result<(), Error>
    where
        S: KvBlobStore,
    {
        self.inner
            .get_mut()
            .borrow_mut()
            .load_persist(kv, buf)
            .await
    }

    pub(crate) fn fetch<F, R>(&self, f: F) -> R
    where
        F: FnOnce(EventsIter<'_, N>) -> R,
    {
        self.inner.lock(|state| {
            let state = state.borrow();

            f(state.iter())
        })
    }

    pub(crate) fn watermark(&self) -> EventNumber {
        self.inner
            .lock(|state| state.borrow().next_event_number.wrapping_sub(1))
    }

    /// Push a new event into the event queue.
    ///
    /// # Arguments
    /// - `endpoint_id`: The endpoint ID of the event source.
    /// - `cluster_id`: The cluster ID of the event source.
    /// - `event_id`: The event ID of the event source.
    /// - `priority`: The priority of the event.
    /// - `kv`: A key-value store access object for persisting event state as needed.
    /// - `f`: A closure that takes an `EventTLVWrite` and writes
    ///   the event data into it using TLV encoding. The closure should return an error if writing the event data fails for any reason, in which case the event will not be pushed into the queue.
    ///
    /// # Returns
    /// - `Ok(EventNumber)`: The sequence number of the emitted event, if the event was successfully emitted.
    /// - `Err(Error)`: An error if the event could not be emitted.
    pub fn push<S, F>(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        event_id: EventId,
        priority: EventPriority,
        kv: S,
        f: F,
    ) -> Result<EventNumber, Error>
    where
        S: KvBlobStoreAccess,
        F: FnOnce(EventTLVWrite<'_>) -> Result<(), Error>,
    {
        let mut persist = Persist::new(kv);

        let event_number = self.inner.lock(|state| {
            let mut state = state.borrow_mut();

            let event_number = state.next_event_number(&mut persist)?;

            let timestamp = EventDataTimestamp::EpochTimestamp((self.epoch)().as_millis() as u64);

            state.push(
                endpoint_id,
                cluster_id,
                event_id,
                event_number,
                priority,
                timestamp,
                f,
            )?;

            Ok::<_, Error>(event_number)
        })?;

        persist.run()?;

        Ok(event_number)
    }
}

/// The inner state of the events queue, protected by a mutex in the outer Events struct. This is where all the actual logic lives.
///
/// It's modeled after the tiered ring buffer design used in the C++ matter SDK:
/// - *Every* new event is written to the next slot in the DEBUG buffer.
/// - If there is no space for the new event, events are FIFO evicted from the first buffer.
/// - If the evicted event has a priority as high as or higher than the next buffer in the chain,
///   then the evicted event is promoted to there, surviving to see another day.
/// - Promotion may in turn require more eviction in the next buffer, and so on up the chain.
/// - The end result is that critical events get to live in any of the buffers, making their way through
///   all three until they finally age out. Info lives in one of the first two, and debug only in the first.
///
/// N.B: the discussion in PR 361 that introduced this:
/// We were not able to determine a way to implement a priority queue that both met the specs requirements
/// (low-prio events must not cause eviction of high-prio events) while also allowing debug and info-prio events
/// to be emitted at all.
/// Instead we opted to replicate the approach used in the C++ impl, which we believe is reasonable but also seemingly in violation of the spec.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct EventsInner<const N: usize> {
    // TODO(events): Allow per-ring const generics, so the rings can be sized independently
    buf_debug: EventsBuf<N>,
    buf_info: EventsBuf<N>,
    buf_critical: EventsBuf<N>,
    /// The first assigned event number is 1; `0` is reserved as the "no events seen yet"
    /// sentinel used by fresh subscriptions.
    next_event_number: EventNumber,
}

impl<const N: usize> EventsInner<N> {
    const fn new() -> Self {
        Self {
            buf_debug: EventsBuf::new(),
            buf_info: EventsBuf::new(),
            buf_critical: EventsBuf::new(),
            next_event_number: 1,
        }
    }

    fn init() -> impl Init<Self> {
        init!(Self {
            buf_debug <- EventsBuf::init(),
            buf_info <- EventsBuf::init(),
            buf_critical <- EventsBuf::init(),
            next_event_number: 1,
        })
    }

    fn reset(&mut self) {
        self.buf_debug.reset();
        self.buf_info.reset();
        self.buf_critical.reset();
        self.next_event_number = 1;
    }

    /// Remove persisted state from the given key-value store.
    async fn reset_persist<S>(&mut self, mut kv: S, buf: &mut [u8]) -> Result<(), Error>
    where
        S: KvBlobStore,
    {
        self.reset();

        kv.remove(EVENT_EPOCH_KEY, buf)?;

        info!("Removed events counter from storage");

        Ok(())
    }

    /// Load persisted state from the given key-value store, so that we can continue emitting events without reusing event numbers.
    async fn load_persist<S>(&mut self, mut kv: S, buf: &mut [u8]) -> Result<(), Error>
    where
        S: KvBlobStore,
    {
        self.reset();

        if let Some(data) = kv.load(EVENT_EPOCH_KEY, buf)? {
            self.load(data)?;

            info!("Loaded events counter from storage");
        }

        Ok(())
    }

    /// Restore events from previously persisted state.
    fn load(&mut self, data: &[u8]) -> Result<(), Error> {
        self.next_event_number = TLVElement::new(data).u64()?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn push<F>(
        &mut self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        event_id: EventId,
        event_number: EventNumber,
        priority: EventPriority,
        timestamp: EventDataTimestamp,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(EventTLVWrite<'_>) -> Result<(), Error>,
    {
        let mut event_writer = EventWriter::new(self);

        let pos = event_writer.get_tail();

        let result = (|| {
            EventData {
                path: EventPath {
                    endpoint: Some(endpoint_id),
                    cluster: Some(cluster_id),
                    event: Some(event_id),
                    ..Default::default()
                },
                event_number,
                priority,
                timestamp,
                data: TLVElement::new(&[]),
            }
            .write_preamble(&EVENT_TAG, event_writer.tw())?;

            f(event_writer.tw())?;

            event_writer.tw().end_container()
        })();

        if result.is_err() {
            event_writer.rewind_to(pos);
        }

        result
    }

    fn next_event_number<S>(&mut self, persist: &mut Persist<S>) -> Result<EventNumber, Error>
    where
        S: KvBlobStoreAccess,
    {
        let event_number = self.next_event_number;

        if event_number == 1 || event_number.is_multiple_of(EVENT_NUMBER_EPOCH_SIZE) {
            // We're at an epoch start boundary. Therefore, we need to persist the new epoch to storage
            // so we don't lose it on reboot and end up reusing event numbers.
            persist.store_tlv(
                EVENT_EPOCH_KEY,
                if event_number == 1 {
                    EVENT_NUMBER_EPOCH_SIZE
                } else {
                    event_number.wrapping_add(EVENT_NUMBER_EPOCH_SIZE).max(1)
                },
            )?;
        }

        self.next_event_number = event_number.wrapping_add(1).max(1);

        Ok(event_number)
    }

    fn iter(&self) -> EventsIter<'_, N> {
        EventsIter {
            events: self,
            buf_ref: EventPriority::Critical,
            buf_iter: self.buf_critical.iter(),
        }
    }

    /// Return a reference to the buffer corresponding to the provided priority level
    fn buf(&self, priority: EventPriority) -> &EventsBuf<N> {
        match priority {
            EventPriority::Debug => &self.buf_debug,
            EventPriority::Info => &self.buf_info,
            EventPriority::Critical => &self.buf_critical,
        }
    }

    /// Return a mutable reference to the buffer corresponding to the provided priority level
    fn buf_mut(&mut self, priority: EventPriority) -> &mut EventsBuf<N> {
        match priority {
            EventPriority::Debug => &mut self.buf_debug,
            EventPriority::Info => &mut self.buf_info,
            EventPriority::Critical => &mut self.buf_critical,
        }
    }

    /// Return a reference to the buffer corresponding to the provided priority level, and a mutable reference to the next buffer in the chain if it exists
    fn buf_and_next_mut(
        &mut self,
        priority: EventPriority,
    ) -> (&EventsBuf<N>, Option<&mut EventsBuf<N>>) {
        match priority {
            EventPriority::Debug => (&self.buf_debug, Some(&mut self.buf_info)),
            EventPriority::Info => (&self.buf_info, Some(&mut self.buf_critical)),
            EventPriority::Critical => (&self.buf_critical, None),
        }
    }
}

/// An iterator over the events in the queue, starting from the highest priority and oldest event.
pub struct EventsIter<'a, const N: usize> {
    events: &'a EventsInner<N>,
    buf_ref: EventPriority,
    buf_iter: TLVSequenceIter<'a>,
}

impl<'a, const N: usize> Iterator for EventsIter<'a, N> {
    type Item = EventData<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(res) = self.buf_iter.next() {
            let event = unwrap!(
                res,
                "Should not have iter errors as we only put well-formed TLVs in the buffer"
            );
            let event = unwrap!(
                EventData::from_tlv(&event),
                "Should not have parsing errors as we only put well-formed TLVs in the buffer"
            );

            return Some(event);
        }

        if let Some(next_buf_ref) = self.buf_ref.prev() {
            self.buf_iter = self.events.buf(next_buf_ref).iter();
            self.buf_ref = next_buf_ref;

            self.next()
        } else {
            None
        }
    }
}

/// A helper struct for writing event data into the buffers, handling eviction and promotion as needed to make space for the new event.
struct EventWriter<'a, const N: usize> {
    events: &'a mut EventsInner<N>,
    bytes_written: usize,
}

impl<'a, const N: usize> EventWriter<'a, N> {
    // We always write at the end of the debug buffer
    // Events are flowing to higher-prio buffers by eviction
    const OPER_BUF: EventPriority = EventPriority::Debug;

    /// Create a new EventWriter for the given EventsInner, starting with zero bytes written.
    #[inline(always)]
    const fn new(events: &'a mut EventsInner<N>) -> Self {
        Self {
            events,
            bytes_written: 0,
        }
    }

    /// Get a TLVWrite decorator for this EventWriter,
    /// which handles writing TLV data and rolling back on errors by rewinding the write head to the position before the write started.
    #[inline(always)]
    fn tw(&mut self) -> EventTLVWrite<'_> {
        EventTLVWrite(self)
    }

    /// Write a byte to the current buffer, evicting and promoting events as needed to make space for the new byte.
    fn write(&mut self, byte: u8) -> Result<(), Error> {
        if N == 0 {
            // Events are disabled, we should never write anything to the buffer and should always succeed.
            return Ok(());
        }

        if self.bytes_written == N {
            // This event is larger than the buffer, the client needs to change the buffer size for this to work
            return Err(Error::new(ErrorCode::ResourceExhausted));
        }

        while self.events.buf_mut(Self::OPER_BUF).append(byte).is_err() {
            // Overflow, need to evict an event to make space.
            // This may cascade and cause evictions in the higher priority buffers, but that's fine,
            // as we just want to make space for this new event and the priority guarantees are maintained by the eviction logic.
            self.evict(Self::OPER_BUF);
        }

        self.bytes_written += 1;

        Ok(())
    }

    /// Rewind the write head to the position before the current event started being written, effectively discarding any bytes written for the current event so far. This is used to roll back writes when an error occurs during event writing.
    fn rewind_to(&mut self, bytes_written: usize) {
        assert!(self.bytes_written >= bytes_written);

        self.events
            .buf_mut(Self::OPER_BUF)
            .rewind_by(self.bytes_written - bytes_written);
        self.bytes_written = bytes_written;
    }

    /// Evict the first event from the buffer corresponding to the provided priority level,
    /// promoting it to the next buffer if its priority meets the threshold, and cascading evictions/promotions as needed.
    fn evict(&mut self, buf_ref: EventPriority) {
        let event_len = self.events.buf(buf_ref).first_event_len();

        if let Some(next_buf_ref) = buf_ref.next() {
            let event_prio = self.events.buf(buf_ref).first_event_prio();

            if next_buf_ref as u8 <= event_prio {
                // There is another level and our event meets the priority threshold, so we should promote it
                self.promote(buf_ref, next_buf_ref, event_len);
            }
        }

        // Evict the event from the current buffer, whether we promoted it or not
        self.events.buf_mut(buf_ref).evict_first_event();
    }

    // Promote the first event from the source buffer to the destination buffer,
    // evicting events from the destination buffer as needed to make space and potentially
    // cascading promotion to higher buffers if evicted events meet the priority threshold
    fn promote(&mut self, src_buf: EventPriority, dst_buf: EventPriority, event_len: usize) {
        // Make space (n.b. this assumes the next buffer is always at least as large as the current buffer, which is currently always true)
        while self.events.buf(dst_buf).capacity() < event_len {
            self.evict(dst_buf);
        }

        let (src, dst) = self.events.buf_and_next_mut(src_buf);

        let dst = unwrap!(
            dst,
            "Dst buffer should always exist as this is checked in evict()"
        );

        unwrap!(
            dst.append_slice(src.slice(event_len)),
            "Should not overflow as eviction should have cleared space"
        );
    }
}

/// A dyn-compatible writer for event data
/// Necessary so that we can implement `EventTLVWrite`, which is a `TLVWrite` with an erased `const N: usize` generic
trait DynEventWriter {
    fn write(&mut self, byte: u8) -> Result<(), Error>;

    fn get_tail(&self) -> usize;

    fn rewind_to(&mut self, pos: usize);
}

impl<'a, const N: usize> DynEventWriter for EventWriter<'a, N> {
    fn write(&mut self, byte: u8) -> Result<(), Error> {
        EventWriter::write(self, byte)
    }

    fn get_tail(&self) -> usize {
        self.bytes_written
    }

    fn rewind_to(&mut self, pos: usize) {
        EventWriter::rewind_to(self, pos)
    }
}

/// A `TLVWrite` wrapper around EventWriter that erases the const generic,
/// allowing it to be used in the closure passed to `Events::push()` and the various `emit_event` handler context methods.
pub struct EventTLVWrite<'a>(&'a mut dyn DynEventWriter);

impl core::fmt::Debug for EventTLVWrite<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("EventTLVWrite").finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for EventTLVWrite<'_> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "EventTLVWrite")
    }
}

impl TLVWrite for EventTLVWrite<'_> {
    type Position = usize;

    fn write(&mut self, byte: u8) -> Result<(), Error> {
        self.0.write(byte)
    }

    fn get_tail(&self) -> Self::Position {
        self.0.get_tail()
    }

    fn rewind_to(&mut self, pos: Self::Position) {
        self.0.rewind_to(pos)
    }
}

impl TLVBuilderParent for EventTLVWrite<'_> {
    type Write = Self;

    fn writer(&mut self) -> &mut Self::Write {
        self
    }
}

const EVENT_TAG: TLVTag = TLVTag::Context(EventRespTag::Data as _);

/// The context tag corresponding to the event data field in the Event Response TLV structure.
pub const EVENT_DATA_TAG: TLVTag = TLVTag::Context(EventDataTag::Data as _);

/// Stores one "priority level" of events, see the doc string on EventsInner for more info on that.
///
/// This behaves very similar to a ring buffer - you can append data at the write head, and eventually
/// the head will catch up and "eat" the tail, implementing a sort of sliding window of visible data.
///
/// This is a much less efficient variant though - it left-shifts the entire buffer to "evict" old events,
/// rather than just track head/tail pointers with wrap-around.
///
/// The thing we gain from the less efficient implementation is that events are never "split up", they are
/// always complete TLVs in contiguous memory, which allows to use TLVElement to read/iterate over the events.
///
/// If you feel enthusiastic, it might give some performance gains to replace this with a real ring buffer.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct EventsBuf<const N: usize> {
    data: [u8; N],
    head: usize,
}

impl<const N: usize> EventsBuf<N> {
    const fn new() -> Self {
        Self {
            data: [0; N],
            head: 0,
        }
    }

    fn init() -> impl Init<Self> {
        init!(Self {
            data <- crate::utils::init::zeroed(),
            head: 0,
        })
    }

    fn reset(&mut self) {
        self.head = 0;
    }

    fn rewind_by(&mut self, bytes_written: usize) {
        assert!(self.head >= bytes_written);

        self.head -= bytes_written;
    }

    fn slice(&self, len: usize) -> &[u8] {
        assert!(self.head >= len);
        &self.data[..len]
    }

    fn append(&mut self, byte: u8) -> Result<(), OverflowError> {
        if self.capacity() == 0 {
            return Err(OverflowError);
        }

        self.data[self.head] = byte;
        self.head += 1;
        Ok(())
    }

    fn append_slice(&mut self, data: &[u8]) -> Result<(), OverflowError> {
        if self.capacity() < data.len() {
            return Err(OverflowError);
        }

        self.data[self.head..self.head + data.len()].copy_from_slice(data);
        self.head += data.len();

        Ok(())
    }

    fn capacity(&self) -> usize {
        self.data.len() - self.head
    }

    /// Get the TLV length of the event in the buffer
    ///
    /// The method will panic if the buffer is empty or if the buffer contains invalid data
    fn first_event_len(&self) -> usize {
        assert!(self.head > 0);
        unwrap!(TLVSequence(&self.data[..self.head]).container_len())
    }

    /// Get the priority of the event at the start of the buffer
    ///
    /// The method will panic if the buffer is empty or if the buffer contains invalid data
    fn first_event_prio(&self) -> u8 {
        unwrap!(unwrap!(
            unwrap!(TLVElement::new(&self.data[..self.head]).structure())
                .find_ctx(EventDataTag::Priority as _)
        )
        .u8())
    }

    fn evict_first_event(&mut self) {
        let tlv_len = self.first_event_len();

        self.data.copy_within(tlv_len..self.head, 0);
        self.head -= tlv_len;
    }

    fn iter(&self) -> TLVSequenceIter<'_> {
        TLVSequence(&self.data[0..self.head]).iter()
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct OverflowError;

#[cfg(test)]
mod tests {
    use crate::tlv::ToTLV;

    use super::*;

    #[test]
    fn one_entry() {
        let crit1 = TestEvent::new(1, EventPriority::Critical);
        let mut q: EventsInner<32> = EventsInner::new();

        crit1.push_into(&mut q).unwrap();

        assert_eq!(TestEvent::vec_from(&q.buf_debug).unwrap(), &[crit1]);
    }

    #[test]
    fn critical_is_promoted() {
        let crit1 = TestEvent::new(1, EventPriority::Critical);
        let crit2 = TestEvent::new(2, EventPriority::Info);
        let crit3 = TestEvent::new(3, EventPriority::Info);
        let mut q: EventsInner<32> = EventsInner::new();

        crit1.push_into(&mut q).unwrap();
        crit2.push_into(&mut q).unwrap();
        crit3.push_into(&mut q).unwrap();

        assert_eq!(TestEvent::vec_from(&q.buf_debug).unwrap(), &[crit3]);
        assert_eq!(TestEvent::vec_from(&q.buf_info).unwrap(), &[crit2]);
        assert_eq!(TestEvent::vec_from(&q.buf_critical).unwrap(), &[crit1]);
    }

    #[test]
    fn debug_is_dropped() {
        let crit1 = TestEvent::new(1, EventPriority::Critical);
        let dbg2 = TestEvent::new(2, EventPriority::Debug);
        let crit3: TestEvent = TestEvent::new(3, EventPriority::Critical);
        let mut q: EventsInner<32> = EventsInner::new();

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
        let crit1 = TestEvent::new(1, EventPriority::Critical);
        let mut q: EventsInner<8> = EventsInner::new();

        assert_eq!(
            crit1.push_into(&mut q).expect_err("").code(),
            ErrorCode::ResourceExhausted
        );
    }

    // Test utilities for this suite

    #[derive(PartialEq, Clone, Debug)]
    struct TestEvent {
        endpoint: EndptId,
        cluster: ClusterId,
        event: EventId,
        event_number: EventNumber,
        priority: EventPriority,
        timestamp: EventDataTimestamp,
        data: u64,
    }

    impl TestEvent {
        const fn new(event_number: EventNumber, priority: EventPriority) -> Self {
            Self {
                endpoint: 42,
                cluster: 1,
                event: 0xB33F,
                event_number,
                priority,
                timestamp: EventDataTimestamp::EpochTimestamp(10_000 + event_number),
                data: 1337,
            }
        }

        fn vec_from<const N: usize>(
            buf: &EventsBuf<N>,
        ) -> Result<heapless::Vec<TestEvent, N>, Error> {
            let mut out = heapless::Vec::new();
            for tr in buf.iter() {
                let e = EventData::from_tlv(&tr?)?;
                out.push(TestEvent {
                    endpoint: e.path.endpoint.unwrap(),
                    cluster: e.path.cluster.unwrap(),
                    event: e.path.event.unwrap(),
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
            q.push(
                self.endpoint,
                self.cluster,
                self.event,
                self.event_number,
                self.priority,
                self.timestamp.clone(),
                |tw| self.data.to_tlv(&EVENT_DATA_TAG, tw),
            )
        }
    }
}
