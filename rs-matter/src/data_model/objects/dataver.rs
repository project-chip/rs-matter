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

use crate::utils::rand::Rand;

#[derive(Clone)]
pub struct Dataver {
    ver: Cell<u32>,
    changed: Cell<bool>,
}

impl Dataver {
    pub fn new(rand: Rand) -> Self {
        let mut buf = [0; 4];
        rand(&mut buf);

        Self {
            ver: Cell::new(u32::from_be_bytes(buf)),
            changed: Cell::new(false),
        }
    }

    pub fn get(&self) -> u32 {
        self.ver.get()
    }

    pub fn changed(&self) -> u32 {
        self.ver.set(self.ver.get().overflowing_add(1).0);
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
