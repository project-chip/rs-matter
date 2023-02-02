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

use core::convert::TryInto;

use strum::FromRepr;

use crate::attribute_enum;
use crate::data_model::objects::*;
use crate::error::Error;
use crate::tlv::{TLVWriter, TagType, ToTLV};
use crate::utils::rand::Rand;

pub const ID: u32 = 0x001D;

#[derive(FromRepr)]
#[repr(u16)]
#[allow(clippy::enum_variant_names)]
pub enum Attributes {
    DeviceTypeList = 0,
    ServerList = 1,
    ClientList = 2,
    PartsList = 3,
}

attribute_enum!(Attributes);

pub const CLUSTER: Cluster<'static> = Cluster {
    id: ID as _,
    feature_map: 0,
    attributes: &[
        FEATURE_MAP,
        ATTRIBUTE_LIST,
        Attribute::new(Attributes::DeviceTypeList as u16, Access::RV, Quality::NONE),
        Attribute::new(Attributes::ServerList as u16, Access::RV, Quality::NONE),
        Attribute::new(Attributes::PartsList as u16, Access::RV, Quality::NONE),
        Attribute::new(Attributes::ClientList as u16, Access::RV, Quality::NONE),
    ],
    commands: &[],
};

pub struct DescriptorCluster {
    data_ver: Dataver,
}

impl DescriptorCluster {
    pub fn new(rand: Rand) -> Self {
        Self {
            data_ver: Dataver::new(rand),
        }
    }

    pub fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::DeviceTypeList => {
                        self.encode_devtype_list(attr.node, AttrDataWriter::TAG, &mut writer)?;
                        writer.complete()
                    }
                    Attributes::ServerList => {
                        self.encode_server_list(
                            attr.node,
                            attr.endpoint_id,
                            AttrDataWriter::TAG,
                            &mut writer,
                        )?;
                        writer.complete()
                    }
                    Attributes::PartsList => {
                        self.encode_parts_list(
                            attr.node,
                            attr.endpoint_id,
                            AttrDataWriter::TAG,
                            &mut writer,
                        )?;
                        writer.complete()
                    }
                    Attributes::ClientList => {
                        self.encode_client_list(
                            attr.node,
                            attr.endpoint_id,
                            AttrDataWriter::TAG,
                            &mut writer,
                        )?;
                        writer.complete()
                    }
                }
            }
        } else {
            Ok(())
        }
    }

    fn encode_devtype_list(
        &self,
        node: &Node,
        tag: TagType,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        tw.start_array(tag)?;
        for endpoint in node.endpoints {
            let dev_type = endpoint.device_type;
            dev_type.to_tlv(tw, TagType::Anonymous)?;
        }

        tw.end_container()
    }

    fn encode_server_list(
        &self,
        node: &Node,
        endpoint_id: u16,
        tag: TagType,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        tw.start_array(tag)?;
        for endpoint in node.endpoints {
            if endpoint.id == endpoint_id {
                for cluster in endpoint.clusters {
                    tw.u32(TagType::Anonymous, cluster.id as _)?;
                }
            }
        }

        tw.end_container()
    }

    fn encode_parts_list(
        &self,
        node: &Node,
        endpoint_id: u16,
        tag: TagType,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        tw.start_array(tag)?;

        if endpoint_id == 0 {
            // TODO: If endpoint is another than 0, need to figure out what to do
            for endpoint in node.endpoints {
                if endpoint.id != 0 {
                    tw.u16(TagType::Anonymous, endpoint.id)?;
                }
            }
        }

        tw.end_container()
    }

    fn encode_client_list(
        &self,
        _node: &Node,
        _endpoint_id: u16,
        tag: TagType,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        // No Clients supported
        tw.start_array(tag)?;
        tw.end_container()
    }
}

impl Handler for DescriptorCluster {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        DescriptorCluster::read(self, attr, encoder)
    }
}

impl NonBlockingHandler for DescriptorCluster {}

impl ChangeNotifier<()> for DescriptorCluster {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
