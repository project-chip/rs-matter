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

use core::fmt::Debug;

use strum::FromRepr;

use crate::attribute_enum;
use crate::data_model::objects::*;
use crate::error::Error;
use crate::tlv::TLVTag;
use crate::tlv::{TLVWrite, TLVWriter, TagType, ToTLV};
use crate::transport::exchange::Exchange;

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

#[derive(Debug)]
struct StandardPartsMatcher;

impl PartsMatcher for StandardPartsMatcher {
    fn describe(&self, our_endpoint: EndptId, endpoint: EndptId) -> bool {
        our_endpoint == 0 && endpoint != our_endpoint
    }
}

#[derive(Debug)]
struct AggregatorPartsMatcher;

impl PartsMatcher for AggregatorPartsMatcher {
    fn describe(&self, our_endpoint: EndptId, endpoint: EndptId) -> bool {
        endpoint != our_endpoint && endpoint != 0
    }
}

pub trait PartsMatcher: Debug {
    fn describe(&self, our_endpoint: EndptId, endpoint: EndptId) -> bool;
}

impl<T> PartsMatcher for &T
where
    T: PartsMatcher,
{
    fn describe(&self, our_endpoint: EndptId, endpoint: EndptId) -> bool {
        (**self).describe(our_endpoint, endpoint)
    }
}

impl<T> PartsMatcher for &mut T
where
    T: PartsMatcher,
{
    fn describe(&self, our_endpoint: EndptId, endpoint: EndptId) -> bool {
        (**self).describe(our_endpoint, endpoint)
    }
}

#[derive(Clone)]
pub struct DescriptorCluster<'a> {
    data_ver: Dataver,
    matcher: &'a dyn PartsMatcher,
}

impl DescriptorCluster<'static> {
    pub const fn new(data_ver: Dataver) -> Self {
        Self::new_matching(data_ver, &StandardPartsMatcher)
    }

    pub const fn new_aggregator(data_ver: Dataver) -> Self {
        Self::new_matching(data_ver, &AggregatorPartsMatcher)
    }
}

impl<'a> DescriptorCluster<'a> {
    pub const fn new_matching(
        data_ver: Dataver,
        matcher: &'a dyn PartsMatcher,
    ) -> DescriptorCluster<'a> {
        Self { data_ver, matcher }
    }

    pub fn read(
        &self,
        _exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        if let Some(mut writer) = encoder.with_dataver(self.data_ver.get())? {
            if attr.is_system() {
                CLUSTER.read(attr.attr_id, writer)
            } else {
                match attr.attr_id.try_into()? {
                    Attributes::DeviceTypeList => {
                        self.encode_devtype_list(
                            attr.node,
                            attr.endpoint_id,
                            &AttrDataWriter::TAG,
                            &mut writer,
                        )?;
                        writer.complete()
                    }
                    Attributes::ServerList => {
                        self.encode_server_list(
                            attr.node,
                            attr.endpoint_id,
                            &AttrDataWriter::TAG,
                            &mut writer,
                        )?;
                        writer.complete()
                    }
                    Attributes::PartsList => {
                        self.encode_parts_list(
                            attr.node,
                            attr.endpoint_id,
                            &AttrDataWriter::TAG,
                            &mut writer,
                        )?;
                        writer.complete()
                    }
                    Attributes::ClientList => {
                        self.encode_client_list(
                            attr.node,
                            attr.endpoint_id,
                            &AttrDataWriter::TAG,
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
        endpoint_id: u16,
        tag: &TLVTag,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        tw.start_array(tag)?;
        for endpoint in node.endpoints {
            if endpoint.id == endpoint_id {
                for dev_type in endpoint.device_types {
                    dev_type.to_tlv(&TagType::Anonymous, &mut *tw)?;
                }
            }
        }

        tw.end_container()
    }

    fn encode_server_list(
        &self,
        node: &Node,
        endpoint_id: u16,
        tag: &TLVTag,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        tw.start_array(tag)?;
        for endpoint in node.endpoints {
            if endpoint.id == endpoint_id {
                for cluster in endpoint.clusters {
                    tw.u32(&TLVTag::Anonymous, cluster.id as _)?;
                }
            }
        }

        tw.end_container()
    }

    fn encode_parts_list(
        &self,
        node: &Node,
        endpoint_id: u16,
        tag: &TLVTag,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        tw.start_array(tag)?;

        for endpoint in node.endpoints {
            if self.matcher.describe(endpoint_id, endpoint.id) {
                tw.u16(&TLVTag::Anonymous, endpoint.id)?;
            }
        }

        tw.end_container()
    }

    fn encode_client_list(
        &self,
        _node: &Node,
        _endpoint_id: u16,
        tag: &TLVTag,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        // No Clients supported
        tw.start_array(tag)?;
        tw.end_container()
    }
}

impl Handler for DescriptorCluster<'_> {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        DescriptorCluster::read(self, exchange, attr, encoder)
    }
}

impl NonBlockingHandler for DescriptorCluster<'_> {}

impl ChangeNotifier<()> for DescriptorCluster<'_> {
    fn consume_change(&mut self) -> Option<()> {
        self.data_ver.consume_change(())
    }
}
