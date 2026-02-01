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

use rand_core::RngCore;

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Dataver(#[cfg_attr(feature = "defmt", defmt(Debug2Format))] Cell<Wrapping<u32>>);

impl Dataver {
    pub fn new_rand<R: RngCore>(rand: &mut R) -> Self {
        Self::new(rand.next_u32())
    }

    pub const fn new(initial: u32) -> Self {
        Self(Cell::new(Wrapping(initial)))
    }

    pub fn get(&self) -> u32 {
        self.0.get().0
    }

    pub fn changed(&self) -> u32 {
        self.0.set(self.0.get() + Wrapping(1));

        self.get()
    }
}
