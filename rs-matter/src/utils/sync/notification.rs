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

use core::future::Future;

use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::utils::init::{init, Init};

use super::blocking::raw::MatterRawMutex;
use super::signal::Signal;

/// A notification primitive that allows for notifying a single waiter.
pub struct Notification<M = MatterRawMutex> {
    signal: Signal<Option<()>, M>,
}

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
        Self {
            signal: Signal::new(None),
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            signal <- Signal::init(None),
        })
    }

    /// Notify the waiter.
    pub fn notify(&self) {
        self.signal.signal(());
    }

    /// Wait for the notification.
    pub async fn wait(&self) {
        self.signal.wait_signalled().await;
    }
}

/// A notification primitive that allows for notifying multiple waiters,
/// as long as all waiters are scheduled from a single async task (or else the notification would busy-loop).
pub(crate) struct MultiNotification<M = MatterRawMutex> {
    signal: Signal<u32, M>,
}

impl<M> Default for MultiNotification<M>
where
    M: RawMutex,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<M> MultiNotification<M>
where
    M: RawMutex,
{
    /// Create a new `MultiNotification`.
    pub const fn new() -> Self {
        Self {
            signal: Signal::new(0),
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            signal <- Signal::init(0),
        })
    }

    /// Notify all waiters.
    pub fn notify(&self) {
        self.signal.modify(|v| {
            *v = v.wrapping_add(1);
            (true, ())
        });
    }

    /// Wait for the notification.
    pub fn wait(&self) -> impl Future<Output = ()> + '_ {
        let initial = self.signal.access(|v| *v);

        self.signal
            .wait(move |v| if *v != initial { Some(()) } else { None })
    }
}
