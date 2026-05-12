/*
 *
 *    Copyright (c) 2024-2026 Project CHIP Authors
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

use embassy_sync::blocking_mutex::raw::RawMutex;

use super::blocking::raw::MatterRawMutex;
use super::signal::Signal;

/// A notification primitive that allows for notifying a single waiter.
pub struct Notification<M = MatterRawMutex>(Signal<Option<()>, M>);

impl<M> Default for Notification<M>
where
    M: RawMutex,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<M> Notification<M>
where
    M: RawMutex,
{
    /// Create a new `Notification`.
    pub const fn new() -> Self {
        Self(Signal::new(None))
    }

    /// Notify the waiter.
    pub fn notify(&self) {
        self.0.signal(());
    }

    /// Wait for the notification.
    pub async fn wait(&self) {
        self.0.wait_signalled().await;
    }
}
