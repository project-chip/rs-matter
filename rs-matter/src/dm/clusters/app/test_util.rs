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

//! Helpers shared by the application clusters' unit tests.

use core::cell::RefCell;

use crate::dm::{AttrChangeNotifier, AttrId, ClusterId, EndptId, EventEmitter, EventId};
use crate::error::Error;
use crate::im::events::{EventTLVWrite, Events};
use crate::im::{EventData, EventNumber, EventPriority};
use crate::persist::{DummyKvBlobStore, SharedKvBlobStore};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;

/// An [`AttrChangeNotifier`] that records what it was told about, so that a
/// test can assert on the re-reports an operation produces.
///
/// The handlers that accumulate out-of-band changes into a bitmask - because
/// [`crate::utils::sync::Signal`] is a single slot that *replaces* on signal,
/// and would drop the first of two changes landing back to back - take an
/// `AttrChangeNotifier` rather than the `HandlerContext` they are called with
/// precisely so that this can drive them. A `HandlerContext` can only be built
/// around a live `Matter` instance.
#[derive(Default)]
pub struct RecordingNotifier(RefCell<Vec<(EndptId, ClusterId, AttrId), 16>>);

impl RecordingNotifier {
    /// Take the recorded notifications, leaving the notifier empty.
    pub fn take(&self) -> Vec<(EndptId, ClusterId, AttrId), 16> {
        core::mem::take(&mut self.0.borrow_mut())
    }

    /// The attribute IDs recorded so far, in the order they arrived.
    pub fn attrs(&self) -> Vec<AttrId, 16> {
        self.take().iter().map(|(_, _, attr)| *attr).collect()
    }
}

impl AttrChangeNotifier for RecordingNotifier {
    fn notify_attr_changed(&self, endpoint_id: EndptId, cluster_id: ClusterId, attr_id: AttrId) {
        unwrap!(self.0.borrow_mut().push((endpoint_id, cluster_id, attr_id)));
    }

    fn notify_cluster_changed(&self, _endpoint_id: EndptId, _cluster_id: ClusterId) {
        unreachable!("The application cluster handlers notify individual attributes")
    }

    fn notify_endpoint_changed(&self, _endpoint_id: EndptId) {
        unreachable!("The application cluster handlers notify individual attributes")
    }

    fn notify_all_changed(&self) {
        unreachable!("The application cluster handlers notify individual attributes")
    }
}

/// An [`AttrChangeNotifier`] and [`EventEmitter`] keeping the events emitted
/// in a queue of its own, so that a test can read them back.
#[derive(Default)]
pub struct RecordingEvents(Events<1024>);

impl RecordingEvents {
    /// The events emitted so far, oldest first.
    pub fn with_events<R>(&self, f: impl FnOnce(&[EventData<'_>]) -> R) -> R {
        self.0.fetch(|iter| {
            let mut events: Vec<EventData<'_>, 32> = iter.collect();
            events.sort_unstable_by_key(|e| e.event_number);
            f(&events)
        })
    }
}

impl AttrChangeNotifier for RecordingEvents {
    fn notify_attr_changed(&self, _endpoint_id: EndptId, _cluster_id: ClusterId, _attr_id: AttrId) {
    }

    fn notify_cluster_changed(&self, _endpoint_id: EndptId, _cluster_id: ClusterId) {}

    fn notify_endpoint_changed(&self, _endpoint_id: EndptId) {}

    fn notify_all_changed(&self) {}
}

impl EventEmitter for RecordingEvents {
    fn emit_event<F>(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        event_id: EventId,
        priority: EventPriority,
        f: F,
    ) -> Result<EventNumber, Error>
    where
        F: FnOnce(EventTLVWrite<'_>) -> Result<(), Error>,
    {
        let buf = Mutex::new(crate::utils::cell::RefCell::new([0; 64]));
        let kv = SharedKvBlobStore::new(DummyKvBlobStore, &buf);

        self.0
            .push(endpoint_id, cluster_id, event_id, priority, &kv, f)
    }
}
