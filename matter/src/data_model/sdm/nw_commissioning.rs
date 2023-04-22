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

use crate::{
    data_model::objects::{
        AttrDataEncoder, AttrDetails, ChangeNotifier, Cluster, Dataver, Handler,
        NonBlockingHandler, ATTRIBUTE_LIST, FEATURE_MAP,
    },
    error::Error,
    utils::rand::Rand,
};

pub const ID: u32 = 0x0031;

enum FeatureMap {
    _Wifi = 0x01,
    _Thread = 0x02,
    Ethernet = 0x04,
}

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    feature_map: FeatureMap::Ethernet as _,
    attributes: &[FEATURE_MAP, ATTRIBUTE_LIST],
    commands: &[],
};

pub struct NwCommCluster {
    data_ver: Dataver,
}

impl NwCommCluster {
    pub fn new(rand: Rand) -> Self {
        Self {
            data_ver: Dataver::new(rand),
        }
    }
}

impl Handler for NwCommCluster {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                Err(Error::AttributeNotFound)
            }
        } else {
            Ok(())
        }
    }
}

impl NonBlockingHandler for NwCommCluster {}

impl ChangeNotifier<()> for NwCommCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
