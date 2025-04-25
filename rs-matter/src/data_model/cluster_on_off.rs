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

use rs_matter_macros::idl_import;

use crate::error::Error;

use super::objects::{Dataver, InvokeContext, ReadContext};

idl_import!(clusters = ["OnOff"]);

#[derive(Clone)]
pub struct OnOffCluster {
    dataver: Dataver,
    on: Cell<bool>,
}

impl OnOffCluster {
    pub const fn new(dataver: Dataver) -> Self {
        Self {
            dataver,
            on: Cell::new(false),
        }
    }

    pub const fn adapt(self) -> OnOffAdaptor<Self> {
        OnOffAdaptor(self)
    }

    pub fn get(&self) -> bool {
        self.on.get()
    }

    pub fn set(&self, on: bool) {
        if self.on.get() != on {
            self.on.set(on);
            self.dataver.changed();
        }
    }
}

impl OnOffHandler for OnOffCluster {
    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn on_off(&self, _ctx: &ReadContext) -> Result<bool, Error> {
        Ok(self.on.get())
    }

    fn handle_off(&self, _ctx: &InvokeContext) -> Result<(), Error> {
        self.set(false);
        Ok(())
    }

    fn handle_on(&self, _ctx: &InvokeContext) -> Result<(), Error> {
        self.set(true);
        Ok(())
    }

    fn handle_toggle(&self, _ctx: &InvokeContext) -> Result<(), Error> {
        self.set(!self.on.get());
        Ok(())
    }

    fn handle_off_with_effect(
        &self,
        _ctx: &InvokeContext,
        _request: OffWithEffectRequest,
    ) -> Result<(), Error> {
        // TODO
        Ok(())
    }

    fn handle_on_with_recall_global_scene(&self, _ctx: &InvokeContext) -> Result<(), Error> {
        // TODO
        Ok(())
    }

    fn handle_on_with_timed_off(
        &self,
        _ctx: &InvokeContext,
        _request: OnWithTimedOffRequest,
    ) -> Result<(), Error> {
        // TODO
        Ok(())
    }
}
