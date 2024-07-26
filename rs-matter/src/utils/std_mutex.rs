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

#![cfg(feature = "std")]

use embassy_sync::blocking_mutex::raw::RawMutex;

/// An `embassy-sync` `RawMutex` implementation using `std::sync::Mutex`.
/// TODO: Upstream into `embassy-sync` itself.
#[derive(Default)]
pub struct StdRawMutex(std::sync::Mutex<()>);

impl StdRawMutex {
    pub const fn new() -> Self {
        Self(std::sync::Mutex::new(()))
    }
}

unsafe impl RawMutex for StdRawMutex {
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT: Self = StdRawMutex(std::sync::Mutex::new(()));

    fn lock<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = self.0.lock().unwrap();

        f()
    }
}
