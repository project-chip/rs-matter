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
    data_model::objects::{Cluster, ClusterType},
    error::Error,
};

pub const ID: u32 = 0x0031;

pub struct NwCommCluster {
    base: Cluster,
}

impl ClusterType for NwCommCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }
}

enum FeatureMap {
    _Wifi = 0x01,
    _Thread = 0x02,
    Ethernet = 0x04,
}

impl NwCommCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        let mut c = Box::new(Self {
            base: Cluster::new(ID)?,
        });
        // TODO: Arch-Specific
        c.base.set_feature_map(FeatureMap::Ethernet as u32)?;
        Ok(c)
    }
}
