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

use crate::error::{Error, ErrorCode};
use crate::with;

use super::objects::{Cluster, Dataver, InvokeContext, ReadContext};

pub use crate::data_model::clusters::on_off::*;

#[derive(Clone)]
pub struct OnOffHandler {
    dataver: Dataver,
    on: Cell<bool>,
}

impl OnOffHandler {
    pub const fn new(dataver: Dataver) -> Self {
        Self {
            dataver,
            on: Cell::new(false),
        }
    }

    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
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

impl ClusterHandler for OnOffHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_revision(1)
        .with_attrs(with!(required))
        .with_cmds(with!(CommandId::On | CommandId::Off | CommandId::Toggle));

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
        Err(ErrorCode::InvalidCommand.into())
    }

    fn handle_on_with_recall_global_scene(&self, _ctx: &InvokeContext) -> Result<(), Error> {
        Err(ErrorCode::InvalidCommand.into())
    }

    fn handle_on_with_timed_off(
        &self,
        _ctx: &InvokeContext,
        _request: OnWithTimedOffRequest,
    ) -> Result<(), Error> {
        Err(ErrorCode::InvalidCommand.into())
    }
}
