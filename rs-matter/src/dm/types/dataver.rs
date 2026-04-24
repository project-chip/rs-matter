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
use core::num::Wrapping;

use rand_core::RngCore;

use crate::dm::{AttrChangeNotifier, AttrId, ClusterId, EndptId};
use crate::utils::sync::blocking::Mutex;

pub struct Dataver(Mutex<Cell<Wrapping<u32>>>);

impl Dataver {
    pub fn new_rand<R: RngCore>(rand: &mut R) -> Self {
        Self::new(rand.next_u32())
    }

    pub const fn new(initial: u32) -> Self {
        Self(Mutex::new(Cell::new(Wrapping(initial))))
    }

    pub fn get(&self) -> u32 {
        self.0.lock(|state| state.get().0)
    }

    pub fn changed(&self) -> u32 {
        self.0.lock(|state| {
            state.set(state.get() + Wrapping(1));

            state.get().0
        })
    }

    /// Bump the cluster data version and notify any subscribers that the
    /// given attribute has changed.
    ///
    /// This is the preferred way to signal an attribute mutation that happens
    /// outside the normal write/invoke dispatch path (e.g. from a timer, an
    /// async I/O completion, or a state-machine transition), because it keeps
    /// the cluster data version and the subscription notification in lockstep.
    ///
    /// For mutations that happen *inside* the normal write/invoke dispatch
    /// path, the generated `HandlerAdaptor` already bumps the data version;
    /// call [`AttrChangeNotifier::notify_attr_changed`] directly in that case.
    pub fn changed_and_notify_attr<N>(
        &self,
        notifier: N,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        attr_id: AttrId,
    ) -> u32
    where
        N: AttrChangeNotifier,
    {
        let v = self.changed();
        notifier.notify_attr_changed(endpoint_id, cluster_id, attr_id);
        v
    }

    /// Bump the cluster data version and notify any subscribers that every
    /// attribute on the given cluster may have changed.
    ///
    /// Use this when a single operation mutates many attributes of the same
    /// cluster and enumerating them would be cumbersome or error-prone.
    pub fn changed_and_notify_cluster<N>(
        &self,
        notifier: N,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
    ) -> u32
    where
        N: AttrChangeNotifier,
    {
        let v = self.changed();
        notifier.notify_cluster_changed(endpoint_id, cluster_id);
        v
    }
}

impl Clone for Dataver {
    fn clone(&self) -> Self {
        Self(Mutex::new(Cell::new(Wrapping(self.get()))))
    }
}

impl Debug for Dataver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.lock(|state| write!(f, "Dataver({})", state.get()))
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Dataver {
    fn format(&self, fmt: defmt::Formatter) {
        self.0
            .lock(|state| defmt::write!(fmt, "Dataver({})", state.get().0))
    }
}
