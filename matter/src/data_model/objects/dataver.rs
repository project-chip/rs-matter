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

 use crate::utils::rand::Rand;

pub struct Dataver {
    ver: u32,
    changed: bool,
}

impl Dataver {
    pub fn new(rand: Rand) -> Self {
        let mut buf = [0; 4];
        rand(&mut buf);

        Self {
            ver: u32::from_be_bytes(buf),
            changed: false,
        }
    }

    pub fn get(&self) -> u32 {
        self.ver
    }

    pub fn changed(&mut self) -> u32 {
        (self.ver, _) = self.ver.overflowing_add(1);
        self.changed = true;

        self.get()
    }

    pub fn consume_change<T>(&mut self, change: T) -> Option<T> {
        if self.changed {
            self.changed = false;
            Some(change)
        } else {
            None
        }
    }
}
