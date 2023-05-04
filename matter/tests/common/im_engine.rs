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

use crate::common::echo_cluster;
use core::borrow::Borrow;
use matter::{
    acl::{AclEntry, AuthMode},
    data_model::{
        cluster_basic_information::{self, BasicInfoConfig},
        cluster_on_off::{self, OnOffCluster},
        core::DataModel,
        device_types::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE},
        objects::{Endpoint, Node, Privilege},
        root_endpoint::{self, RootEndpointHandler},
        sdm::{
            admin_commissioning,
            dev_att::{DataType, DevAttDataFetcher},
            general_commissioning, noc, nw_commissioning,
        },
        system_model::{
            access_control,
            descriptor::{self, DescriptorCluster},
        },
    },
    error::Error,
    handler_chain_type,
    interaction_model::core::{InteractionModel, OpCode},
    mdns::Mdns,
    tlv::{TLVWriter, TagType, ToTLV},
    transport::packet::Packet,
    transport::{
        exchange::{self, Exchange, ExchangeCtx},
        network::{Address, IpAddr, Ipv4Addr, SocketAddr},
        packet::MAX_RX_BUF_SIZE,
        proto_ctx::ProtoCtx,
        session::{CaseDetails, CloneData, NocCatIds, SessionMgr, SessionMode},
    },
    utils::{rand::dummy_rand, writebuf::WriteBuf},
    Matter,
};

use super::echo_cluster::EchoCluster;

const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    vid: 10,
    pid: 11,
    hw_ver: 12,
    sw_ver: 13,
    sw_ver_str: "13",
    serial_no: "aabbccdd",
    device_name: "Test Device",
};

pub struct DummyDevAtt {}

impl DevAttDataFetcher for DummyDevAtt {
    fn get_devatt_data(&self, _data_type: DataType, _data: &mut [u8]) -> Result<usize, Error> {
        Ok(2)
    }
}

pub const IM_ENGINE_PEER_ID: u64 = 445566;

pub struct ImInput<'a> {
    action: OpCode,
    data: &'a dyn ToTLV,
    peer_id: u64,
    cat_ids: NocCatIds,
}

impl<'a> ImInput<'a> {
    pub fn new(action: OpCode, data: &'a dyn ToTLV) -> Self {
        Self {
            action,
            data,
            peer_id: IM_ENGINE_PEER_ID,
            cat_ids: Default::default(),
        }
    }

    pub fn set_peer_node_id(&mut self, peer: u64) {
        self.peer_id = peer;
    }

    pub fn set_cat_ids(&mut self, cat_ids: &NocCatIds) {
        self.cat_ids = *cat_ids;
    }
}

pub type DmHandler<'a> = handler_chain_type!(OnOffCluster, EchoCluster, DescriptorCluster, EchoCluster | RootEndpointHandler<'a>);

pub fn matter(mdns: &mut dyn Mdns) -> Matter<'_> {
    #[cfg(feature = "std")]
    use matter::utils::epoch::sys_epoch as epoch;
    #[cfg(feature = "std")]
    use matter::utils::epoch::sys_utc_calendar as utc_calendar;

    #[cfg(not(feature = "std"))]
    use matter::utils::epoch::dummy_epoch as epoch;
    #[cfg(not(feature = "std"))]
    use matter::utils::epoch::dummy_utc_calendar as utc_calendar;

    Matter::new(&BASIC_INFO, mdns, epoch, dummy_rand, utc_calendar, 5540)
}

/// An Interaction Model Engine to facilitate easy testing
pub struct ImEngine<'a> {
    pub matter: &'a Matter<'a>,
    pub im: InteractionModel<DataModel<'a, DmHandler<'a>>>,
    // By default, a new exchange is created for every run, if you wish to instead using a specific
    // exchange, set this variable. This is helpful in situations where you have to run multiple
    // actions in the same transaction (exchange)
    pub exch: Option<Exchange>,
}

impl<'a> ImEngine<'a> {
    /// Create the interaction model engine
    pub fn new(matter: &'a Matter<'a>) -> Self {
        let mut default_acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
        // Only allow the standard peer node id of the IM Engine
        default_acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
        matter.acl_mgr.borrow_mut().add(default_acl).unwrap();

        let dm = DataModel::new(
            matter.borrow(),
            &Node {
                id: 0,
                endpoints: &[
                    Endpoint {
                        id: 0,
                        clusters: &[
                            descriptor::CLUSTER,
                            cluster_basic_information::CLUSTER,
                            general_commissioning::CLUSTER,
                            nw_commissioning::CLUSTER,
                            admin_commissioning::CLUSTER,
                            noc::CLUSTER,
                            access_control::CLUSTER,
                            echo_cluster::CLUSTER,
                        ],
                        device_type: DEV_TYPE_ROOT_NODE,
                    },
                    Endpoint {
                        id: 1,
                        clusters: &[
                            descriptor::CLUSTER,
                            cluster_on_off::CLUSTER,
                            echo_cluster::CLUSTER,
                        ],
                        device_type: DEV_TYPE_ON_OFF_LIGHT,
                    },
                ],
            },
            root_endpoint::handler(0, &DummyDevAtt {}, matter)
                .chain(0, echo_cluster::ID, EchoCluster::new(2, *matter.borrow()))
                .chain(1, descriptor::ID, DescriptorCluster::new(*matter.borrow()))
                .chain(1, echo_cluster::ID, EchoCluster::new(3, *matter.borrow()))
                .chain(1, cluster_on_off::ID, OnOffCluster::new(*matter.borrow())),
        );

        Self {
            matter,
            im: InteractionModel(dm),
            exch: None,
        }
    }

    pub fn echo_cluster(&self, endpoint: u16) -> &EchoCluster {
        match endpoint {
            0 => &self.im.0.handler.next.next.next.handler,
            1 => &self.im.0.handler.next.handler,
            _ => panic!(),
        }
    }

    /// Run a transaction through the interaction model engine
    pub fn process<'b>(&mut self, input: &ImInput, data_out: &'b mut [u8]) -> (u8, &'b [u8]) {
        let mut new_exch = Exchange::new(1, 0, exchange::Role::Responder);
        // Choose whether to use a new exchange, or use the one from the ImEngine configuration
        let exch = self.exch.as_mut().unwrap_or(&mut new_exch);

        let mut sess_mgr = SessionMgr::new(*self.matter.borrow(), *self.matter.borrow());

        let clone_data = CloneData::new(
            123456,
            input.peer_id,
            10,
            30,
            Address::Udp(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                5542,
            )),
            SessionMode::Case(CaseDetails::new(1, &input.cat_ids)),
        );
        let sess_idx = sess_mgr.clone_session(&clone_data).unwrap();
        let sess = sess_mgr.get_session_handle(sess_idx);
        let exch_ctx = ExchangeCtx {
            exch,
            sess,
            epoch: *self.matter.borrow(),
        };
        let mut rx_buf = [0; MAX_RX_BUF_SIZE];
        let mut tx_buf = [0; 1440]; // For the long read tests to run unchanged
        let mut rx = Packet::new_rx(&mut rx_buf);
        let mut tx = Packet::new_tx(&mut tx_buf);
        // Create fake rx packet
        rx.set_proto_id(0x01);
        rx.set_proto_opcode(input.action as u8);
        rx.peer = Address::default();

        {
            let mut buf = [0u8; 400];
            let mut wb = WriteBuf::new(&mut buf);
            let mut tw = TLVWriter::new(&mut wb);

            input.data.to_tlv(&mut tw, TagType::Anonymous).unwrap();

            let input_data = wb.as_slice();
            let in_data_len = input_data.len();
            let rx_buf = rx.as_mut_slice();
            rx_buf[..in_data_len].copy_from_slice(input_data);
            rx.get_parsebuf().unwrap().set_len(in_data_len);
        }

        let mut ctx = ProtoCtx::new(exch_ctx, &rx, &mut tx);
        self.im.handle(&mut ctx).unwrap();
        let out_data_len = ctx.tx.as_slice().len();
        data_out[..out_data_len].copy_from_slice(ctx.tx.as_slice());
        let response = ctx.tx.get_proto_opcode();
        (response, &data_out[..out_data_len])
    }
}

// TODO - Remove?
// // Create an Interaction Model, Data Model and run a rx/tx transaction through it
// pub fn im_engine<'a>(
//     matter: &'a Matter,
//     action: OpCode,
//     data: &dyn ToTLV,
//     data_out: &'a mut [u8],
// ) -> (DmHandler<'a>, u8, &'a mut [u8]) {
//     let mut engine = ImEngine::new(matter);
//     let input = ImInput::new(action, data);
//     let (response, output) = engine.process(&input, data_out);
//     (engine.dm.handler, response, output)
// }
