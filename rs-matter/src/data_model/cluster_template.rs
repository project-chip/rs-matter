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

use crate::data_model::objects::{Cluster, Handler};
use crate::error::{Error, ErrorCode};
use crate::transport::exchange::Exchange;

use super::objects::{
    AttrDataEncoder, AttrDetails, ChangeNotifier, Dataver, NonBlockingHandler, ATTRIBUTE_LIST,
    FEATURE_MAP,
};

const CLUSTER_NETWORK_COMMISSIONING_ID: u32 = 0x0031;

pub const CLUSTER: Cluster<'static> = Cluster {
    id: CLUSTER_NETWORK_COMMISSIONING_ID as _,
    feature_map: 0,
    attributes: &[FEATURE_MAP, ATTRIBUTE_LIST],
    commands: &[],
};

pub struct TemplateCluster {
    data_ver: Dataver,
}

impl TemplateCluster {
    pub const fn new(data_ver: Dataver) -> Self {
        Self { data_ver }
    }

    pub fn read(
        &self,
        _exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        if let Some(writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                Err(ErrorCode::AttributeNotFound.into())
            }
        } else {
            Ok(())
        }
    }
}

impl Handler for TemplateCluster {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        TemplateCluster::read(self, exchange, attr, encoder)
    }
}

impl NonBlockingHandler for TemplateCluster {}

impl ChangeNotifier<()> for TemplateCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
