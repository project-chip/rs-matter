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
use boxslab::Slab;
use matter::{
    acl::{AclEntry, AclMgr, AuthMode},
    data_model::{
        cluster_basic_information::BasicInfoConfig,
        core::DataModel,
        device_types::device_type_add_on_off_light,
        objects::Privilege,
        sdm::dev_att::{DataType, DevAttDataFetcher},
    },
    error::Error,
    fabric::FabricMgr,
    interaction_model::{core::OpCode, messages::ib::CmdPath, messages::msg, InteractionModel},
    tlv::{TLVWriter, TagType, ToTLV},
    transport::packet::Packet,
    transport::proto_demux::HandleProto,
    transport::{
        exchange::{self, Exchange, ExchangeCtx},
        network::Address,
        packet::PacketPool,
        proto_demux::ProtoCtx,
        session::{CloneData, SessionMgr, SessionMode},
    },
    utils::writebuf::WriteBuf,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

pub struct DummyDevAtt {}
impl DevAttDataFetcher for DummyDevAtt {
    fn get_devatt_data(&self, _data_type: DataType, _data: &mut [u8]) -> Result<usize, Error> {
        Ok(2)
    }
}

/// An Interaction Model Engine to facilitate easy testing
pub struct ImEngine {
    pub dm: DataModel,
    pub acl_mgr: Arc<AclMgr>,
    pub im: Box<InteractionModel>,
    // By default, a new exchange is created for every run, if you wish to instead using a specific
    // exchange, set this variable. This is helpful in situations where you have to run multiple
    // actions in the same transaction (exchange)
    pub exch: Option<Exchange>,
}

pub struct ImInput<'a> {
    action: OpCode,
    data_in: &'a [u8],
    peer_id: u64,
}

pub const IM_ENGINE_PEER_ID: u64 = 445566;
impl<'a> ImInput<'a> {
    pub fn new(action: OpCode, data_in: &'a [u8]) -> Self {
        Self {
            action,
            data_in,
            peer_id: IM_ENGINE_PEER_ID,
        }
    }

    pub fn set_peer_node_id(&mut self, peer: u64) {
        self.peer_id = peer;
    }
}

impl ImEngine {
    /// Create the interaction model engine
    pub fn new() -> Self {
        let dev_det = BasicInfoConfig {
            vid: 10,
            pid: 11,
            hw_ver: 12,
            sw_ver: 13,
        };
        let dev_att = Box::new(DummyDevAtt {});
        let fabric_mgr = Arc::new(FabricMgr::new().unwrap());
        let acl_mgr = Arc::new(AclMgr::new_with(false).unwrap());
        acl_mgr.erase_all();
        let mut default_acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
        // Only allow the standard peer node id of the IM Engine
        default_acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
        acl_mgr.add(default_acl).unwrap();
        let dm = DataModel::new(dev_det, dev_att, fabric_mgr.clone(), acl_mgr.clone()).unwrap();

        {
            let mut d = dm.node.write().unwrap();
            let light_endpoint = device_type_add_on_off_light(&mut d).unwrap();
            d.add_cluster(0, echo_cluster::EchoCluster::new(2).unwrap())
                .unwrap();
            d.add_cluster(light_endpoint, echo_cluster::EchoCluster::new(3).unwrap())
                .unwrap();
        }

        let im = Box::new(InteractionModel::new(Box::new(dm.clone())));

        Self {
            dm,
            acl_mgr,
            im,
            exch: None,
        }
    }

    /// Run a transaction through the interaction model engine
    pub fn process(&mut self, input: &ImInput, data_out: &mut [u8]) -> usize {
        let mut new_exch = Exchange::new(1, 0, exchange::Role::Responder);
        // Choose whether to use a new exchange, or use the one from the ImEngine configuration
        let mut exch = self.exch.as_mut().unwrap_or_else(|| &mut new_exch);

        let mut sess_mgr: SessionMgr = Default::default();

        let clone_data = CloneData::new(
            123456,
            input.peer_id,
            10,
            30,
            Address::Udp(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                5542,
            )),
            SessionMode::Case(1),
        );
        let sess_idx = sess_mgr.clone_session(&clone_data).unwrap();
        let sess = sess_mgr.get_session_handle(sess_idx);
        let exch_ctx = ExchangeCtx {
            exch: &mut exch,
            sess,
        };
        let mut rx = Slab::<PacketPool>::new(Packet::new_rx().unwrap()).unwrap();
        let tx = Slab::<PacketPool>::new(Packet::new_tx().unwrap()).unwrap();
        // Create fake rx packet
        rx.set_proto_id(0x01);
        rx.set_proto_opcode(input.action as u8);
        rx.peer = Address::default();
        let in_data_len = input.data_in.len();
        let rx_buf = rx.as_borrow_slice();
        rx_buf[..in_data_len].copy_from_slice(input.data_in);
        rx.get_parsebuf().unwrap().set_len(in_data_len);

        let mut ctx = ProtoCtx::new(exch_ctx, rx, tx);
        self.im.handle_proto_id(&mut ctx).unwrap();
        let out_data_len = ctx.tx.as_borrow_slice().len();
        data_out[..out_data_len].copy_from_slice(ctx.tx.as_borrow_slice());
        out_data_len
    }
}

// Create an Interaction Model, Data Model and run a rx/tx transaction through it
pub fn im_engine(action: OpCode, data_in: &[u8], data_out: &mut [u8]) -> (DataModel, usize) {
    let mut engine = ImEngine::new();
    let input = ImInput::new(action, data_in);
    let output_len = engine.process(&input, data_out);
    (engine.dm, output_len)
}

pub struct TestData<'a, 'b> {
    tw: TLVWriter<'a, 'b>,
}

impl<'a, 'b> TestData<'a, 'b> {
    pub fn new(buf: &'b mut WriteBuf<'a>) -> Self {
        Self {
            tw: TLVWriter::new(buf),
        }
    }

    pub fn commands(&mut self, cmds: &[(CmdPath, Option<u8>)]) -> Result<(), Error> {
        self.tw.start_struct(TagType::Anonymous)?;
        self.tw.bool(
            TagType::Context(msg::InvReqTag::SupressResponse as u8),
            false,
        )?;
        self.tw
            .bool(TagType::Context(msg::InvReqTag::TimedReq as u8), false)?;
        self.tw
            .start_array(TagType::Context(msg::InvReqTag::InvokeRequests as u8))?;

        for (cmd, data) in cmds {
            self.tw.start_struct(TagType::Anonymous)?;
            cmd.to_tlv(&mut self.tw, TagType::Context(0))?;
            if let Some(d) = *data {
                self.tw.u8(TagType::Context(1), d)?;
            }
            self.tw.end_container()?;
        }

        self.tw.end_container()?;
        self.tw.end_container()
    }
}
