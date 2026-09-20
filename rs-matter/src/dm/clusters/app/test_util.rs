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

use crate::dm::{AttrChangeNotifier, AttrId, ClusterId, EndptId};

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
pub struct RecordingNotifier(RefCell<heapless::Vec<(EndptId, ClusterId, AttrId), 16>>);

impl RecordingNotifier {
    /// Take the recorded notifications, leaving the notifier empty.
    pub fn take(&self) -> heapless::Vec<(EndptId, ClusterId, AttrId), 16> {
        core::mem::take(&mut self.0.borrow_mut())
    }

    /// The attribute IDs recorded so far, in the order they arrived.
    pub fn attrs(&self) -> heapless::Vec<AttrId, 16> {
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
