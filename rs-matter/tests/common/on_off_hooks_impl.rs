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

//! This is as common implementation of the OnOffHooks trait for the OnOffHandler to be used by the tests.

use std::sync::RwLock;

use rs_matter::error::Error;
use rs_matter::tlv::Nullable;

use rs_matter::dm::clusters::decl::on_off as on_off_cluster;
use rs_matter::dm::clusters::on_off::{EffectVariantEnum, OnOffHooks, StartUpOnOffEnum};
use rs_matter::dm::Cluster;

use rs_matter::with;

#[derive(Default)]
pub struct OnOffDeviceLogic {
    on_off: RwLock<bool>,
    start_up_on_off: RwLock<Option<StartUpOnOffEnum>>,
}

impl OnOffDeviceLogic {
    pub const fn new() -> Self {
        Self {
            on_off: RwLock::new(false),
            start_up_on_off: RwLock::new(None),
        }
    }
}

impl OnOffHooks for OnOffDeviceLogic {
    const CLUSTER: Cluster<'static> = on_off_cluster::FULL_CLUSTER
        .with_revision(6)
        .with_attrs(with!(
            required;
            on_off_cluster::AttributeId::OnOff
        ))
        .with_cmds(with!(
            on_off_cluster::CommandId::Off
                | on_off_cluster::CommandId::On
                | on_off_cluster::CommandId::Toggle
        ));

    fn on_off(&self) -> bool {
        self.on_off.read().unwrap().clone()
    }

    fn set_on_off(&self, on: bool) {
        let mut w = self.on_off.write().unwrap();
        *w = on;
    }

    fn start_up_on_off(&self) -> Nullable<StartUpOnOffEnum> {
        match self.start_up_on_off.read().unwrap().clone() {
            Some(value) => Nullable::some(value),
            None => Nullable::none(),
        }
    }

    fn set_start_up_on_off(&self, value: Nullable<StartUpOnOffEnum>) -> Result<(), Error> {
        let mut w = self.start_up_on_off.write().unwrap();
        *w = value.into_option();
        Ok(())
    }

    async fn handle_off_with_effect(&self, _effect: EffectVariantEnum) {
        // no effect
    }
}
