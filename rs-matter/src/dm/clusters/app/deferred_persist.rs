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

//! Deferred persistence of fast-changing cluster state.

use core::cell::Cell;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use crate::error::Error;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;

/// Saves the state of a cluster handler once it has not changed for a while.
///
/// Every change marks the state dirty and restarts the delay, so a burst of
/// changes (a transition, a slider being dragged) results in a single save
/// once things settle.
pub(crate) struct DeferredPersist {
    dirty: Mutex<Cell<bool>>,
    changed: Notification,
}

impl DeferredPersist {
    pub const fn new() -> Self {
        Self {
            dirty: Mutex::new(Cell::new(false)),
            changed: Notification::new(),
        }
    }

    /// Mark the state as changed, (re)starting the delay.
    pub fn mark_dirty(&self) {
        self.dirty.lock(|dirty| dirty.set(true));
        self.changed.notify();
    }

    /// Drop a pending save, e.g. because the state was just saved (or
    /// erased) by other means.
    pub fn clear(&self) {
        self.dirty.lock(|dirty| dirty.set(false));
    }

    /// Call `save` whenever the state has been dirty and then unchanged for
    /// `delay_ms`. Never returns.
    pub async fn run<F>(&self, delay_ms: u32, mut save: F)
    where
        F: FnMut() -> Result<(), Error>,
    {
        let delay = Duration::from_millis(delay_ms as _);

        loop {
            self.changed.wait().await;

            // Restart the delay on every further change.
            while let Either::Second(()) = select(Timer::after(delay), self.changed.wait()).await {}

            if self.dirty.lock(|dirty| dirty.replace(false)) {
                if let Err(err) = save() {
                    warn!("Saving the cluster state failed: {:?}", err);
                }
            }
        }
    }
}
