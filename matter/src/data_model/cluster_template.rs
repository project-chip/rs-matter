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

const CLUSTER_NETWORK_COMMISSIONING_ID: u32 = 0x0031;

pub struct TemplateCluster {
    base: Cluster,
}

impl ClusterType for TemplateCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }
}

impl TemplateCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        Ok(Box::new(Self {
            base: Cluster::new(CLUSTER_NETWORK_COMMISSIONING_ID)?,
        }))
    }
}
