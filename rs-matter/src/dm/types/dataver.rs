/*
 *
 *    Copyright (c) 2023-2026 Project CHIP Authors
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
