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
use core::num::Wrapping;

use crate::utils::rand::Rand;

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Dataver {
    #[cfg_attr(feature = "defmt", defmt(Debug2Format))]
    ver: Cell<Wrapping<u32>>,
    changed: Cell<bool>,
}

impl Dataver {
    pub fn new_rand(rand: Rand) -> Self {
        let mut bytes = [0; 4];

        rand(&mut bytes);

        Self::new(u32::from_le_bytes(bytes))
    }

    pub const fn new(initial: u32) -> Self {
        Self {
            ver: Cell::new(Wrapping(initial)),
            changed: Cell::new(false),
        }
    }

    pub fn get(&self) -> u32 {
        self.ver.get().0
    }

    pub fn changed(&self) -> u32 {
        self.ver.set(self.ver.get() + Wrapping(1));
        self.changed.set(true);

        self.get()
    }

    pub fn consume_change<T>(&self, change: T) -> Option<T> {
        if self.changed.get() {
            self.changed.set(false);
            Some(change)
        } else {
            None
        }
    }
}
