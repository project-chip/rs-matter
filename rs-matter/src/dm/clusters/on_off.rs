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

//! This module contains the implementation of the On/Off cluster and its handler.
//!
//! While this cluster is not necessary for the operation of `rs-matter`, this
//! implementation is useful in examples and tests.

use core::cell::Cell;

use crate::dm::{Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::with;

pub use crate::dm::clusters::decl::on_off::*;

/// A sample implementation of a handler for the On/Off Matter cluster.
#[derive(Clone, Debug)]
pub struct OnOffHandler {
    dataver: Dataver,
    on: Cell<bool>,
}

impl OnOffHandler {
    /// Creates a new instance of `OnOffHandler` with the given `Dataver`.
    pub const fn new(dataver: Dataver) -> Self {
        Self {
            dataver,
            on: Cell::new(false),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    /// Return the current state of the On/Off attribute.
    pub fn get(&self) -> bool {
        self.on.get()
    }

    /// Set the On/Off attribute to the given value and notify potential subscribers.
    /// Returns `true` if the value was changed, `false` otherwise.
    pub fn set(&self, on: bool) -> bool {
        if self.on.get() != on {
            self.on.set(on);
            self.dataver.changed();
            true
        } else {
            false
        }
    }

    // The method that should be used by coupled clusters to update the on_off state.
    pub(crate) fn coupled_cluster_set_on_off(&self, on: bool) {
        self.on.set(on)

        // todo call user logic from OnOffHooks
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

    fn on_off(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        Ok(self.on.get())
    }

    fn handle_off(&self, ctx: impl InvokeContext) -> Result<(), Error> {
        if self.set(false) {
            ctx.notify_changed();
        }

        Ok(())
    }

    fn handle_on(&self, ctx: impl InvokeContext) -> Result<(), Error> {
        if self.set(true) {
            ctx.notify_changed();
        }

        Ok(())
    }

    fn handle_toggle(&self, ctx: impl InvokeContext) -> Result<(), Error> {
        if self.set(!self.on.get()) {
            ctx.notify_changed();
        }

        Ok(())
    }

    fn handle_off_with_effect(
        &self,
        _ctx: impl InvokeContext,
        _request: OffWithEffectRequest,
    ) -> Result<(), Error> {
        Err(ErrorCode::InvalidCommand.into())
    }

    fn handle_on_with_recall_global_scene(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        Err(ErrorCode::InvalidCommand.into())
    }

    fn handle_on_with_timed_off(
        &self,
        _ctx: impl InvokeContext,
        _request: OnWithTimedOffRequest,
    ) -> Result<(), Error> {
        Err(ErrorCode::InvalidCommand.into())
    }
}
