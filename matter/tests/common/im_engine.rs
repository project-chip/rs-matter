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
    interaction_model::{core::OpCode, InteractionModel},
    secure_channel::pake::PaseMgr,
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
    data: &'a dyn ToTLV,
    peer_id: u64,
}

pub const IM_ENGINE_PEER_ID: u64 = 445566;
impl<'a> ImInput<'a> {
    pub fn new(action: OpCode, data: &'a dyn ToTLV) -> Self {
        Self {
            action,
            data,
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
            serial_no: "aabbccdd".to_string(),
            device_name: "Test Device".to_string(),
        };

        let dev_att = Box::new(DummyDevAtt {});
        let fabric_mgr = Arc::new(FabricMgr::new().unwrap());
        let acl_mgr = Arc::new(AclMgr::new_with(false).unwrap());
        let pase_mgr = PaseMgr::new();
        acl_mgr.erase_all();
        let mut default_acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
        // Only allow the standard peer node id of the IM Engine
        default_acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
        acl_mgr.add(default_acl).unwrap();
        let dm = DataModel::new(dev_det, dev_att, fabric_mgr, acl_mgr.clone(), pase_mgr).unwrap();

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
    pub fn process<'a>(&mut self, input: &ImInput, data_out: &'a mut [u8]) -> (u8, &'a mut [u8]) {
        let mut new_exch = Exchange::new(1, 0, exchange::Role::Responder);
        // Choose whether to use a new exchange, or use the one from the ImEngine configuration
        let exch = self.exch.as_mut().unwrap_or(&mut new_exch);

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
        let exch_ctx = ExchangeCtx { exch, sess };
        let mut rx = Slab::<PacketPool>::try_new(Packet::new_rx().unwrap()).unwrap();
        let tx = Slab::<PacketPool>::try_new(Packet::new_tx().unwrap()).unwrap();
        // Create fake rx packet
        rx.set_proto_id(0x01);
        rx.set_proto_opcode(input.action as u8);
        rx.peer = Address::default();

        {
            let mut buf = [0u8; 400];
            let buf_len = buf.len();
            let mut wb = WriteBuf::new(&mut buf, buf_len);
            let mut tw = TLVWriter::new(&mut wb);

            input.data.to_tlv(&mut tw, TagType::Anonymous).unwrap();

            let input_data = wb.as_borrow_slice();
            let in_data_len = input_data.len();
            let rx_buf = rx.as_borrow_slice();
            rx_buf[..in_data_len].copy_from_slice(input_data);
            rx.get_parsebuf().unwrap().set_len(in_data_len);
        }

        let mut ctx = ProtoCtx::new(exch_ctx, rx, tx);
        self.im.handle_proto_id(&mut ctx).unwrap();
        let out_data_len = ctx.tx.as_borrow_slice().len();
        data_out[..out_data_len].copy_from_slice(ctx.tx.as_borrow_slice());
        let response = ctx.tx.get_proto_opcode();
        (response, &mut data_out[..out_data_len])
    }
}

// Create an Interaction Model, Data Model and run a rx/tx transaction through it
pub fn im_engine<'a>(
    action: OpCode,
    data: &dyn ToTLV,
    data_out: &'a mut [u8],
) -> (DataModel, u8, &'a mut [u8]) {
    let mut engine = ImEngine::new();
    let input = ImInput::new(action, data);
    let (response, output) = engine.process(&input, data_out);
    (engine.dm, response, output)
}
