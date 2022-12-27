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

use boxslab::Slab;
use matter::error::Error;
use matter::interaction_model::core::OpCode;
use matter::interaction_model::messages::msg::InvReq;
use matter::interaction_model::messages::msg::ReadReq;
use matter::interaction_model::messages::msg::WriteReq;
use matter::interaction_model::InteractionConsumer;
use matter::interaction_model::InteractionModel;
use matter::interaction_model::Transaction;
use matter::tlv::TLVWriter;
use matter::transport::exchange::Exchange;
use matter::transport::exchange::ExchangeCtx;
use matter::transport::network::Address;
use matter::transport::packet::Packet;
use matter::transport::packet::PacketPool;
use matter::transport::proto_demux::HandleProto;
use matter::transport::proto_demux::ProtoCtx;
use matter::transport::session::SessionMgr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

struct Node {
    pub endpoint: u16,
    pub cluster: u32,
    pub command: u16,
    pub variable: u8,
}

struct DataModel {
    node: Arc<Mutex<Node>>,
}

impl DataModel {
    pub fn new(node: Node) -> Self {
        DataModel {
            node: Arc::new(Mutex::new(node)),
        }
    }
}

impl Clone for DataModel {
    fn clone(&self) -> Self {
        Self {
            node: self.node.clone(),
        }
    }
}

impl InteractionConsumer for DataModel {
    fn consume_invoke_cmd(
        &self,
        inv_req_msg: &InvReq,
        _trans: &mut Transaction,
        _tlvwriter: &mut TLVWriter,
    ) -> Result<(), Error> {
        if let Some(inv_requests) = &inv_req_msg.inv_requests {
            for i in inv_requests.iter() {
                let data = if let Some(data) = i.data.unwrap_tlv() {
                    data
                } else {
                    continue;
                };
                let cmd_path_ib = i.path;
                let mut common_data = self.node.lock().unwrap();
                common_data.endpoint = cmd_path_ib.path.endpoint.unwrap_or(1);
                common_data.cluster = cmd_path_ib.path.cluster.unwrap_or(0);
                common_data.command = cmd_path_ib.path.leaf.unwrap_or(0) as u16;
                data.confirm_struct().unwrap();
                common_data.variable = data.find_tag(0).unwrap().u8().unwrap();
            }
        }

        Ok(())
    }

    fn consume_read_attr(
        &self,
        _req: &ReadReq,
        _trans: &mut Transaction,
        _tlvwriter: &mut TLVWriter,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn consume_write_attr(
        &self,
        _req: &WriteReq,
        _trans: &mut Transaction,
        _tlvwriter: &mut TLVWriter,
    ) -> Result<(), Error> {
        Ok(())
    }
}

fn handle_data(action: OpCode, data_in: &[u8], data_out: &mut [u8]) -> (DataModel, usize) {
    let data_model = DataModel::new(Node {
        endpoint: 0,
        cluster: 0,
        command: 0,
        variable: 0,
    });
    let mut interaction_model = InteractionModel::new(Box::new(data_model.clone()));
    let mut exch: Exchange = Default::default();
    let mut sess_mgr: SessionMgr = Default::default();
    let sess_idx = sess_mgr
        .get_or_add(
            0,
            Address::Udp(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                5542,
            )),
            None,
            false,
        )
        .unwrap();
    let sess = sess_mgr.get_session_handle(sess_idx);
    let exch_ctx = ExchangeCtx {
        exch: &mut exch,
        sess,
    };
    let mut rx = Slab::<PacketPool>::new(Packet::new_rx().unwrap()).unwrap();
    let tx = Slab::<PacketPool>::new(Packet::new_tx().unwrap()).unwrap();
    // Create fake rx packet
    rx.set_proto_id(0x01);
    rx.set_proto_opcode(action as u8);
    rx.peer = Address::default();
    let in_data_len = data_in.len();
    let rx_buf = rx.as_borrow_slice();
    rx_buf[..in_data_len].copy_from_slice(data_in);

    let mut ctx = ProtoCtx::new(exch_ctx, rx, tx);

    interaction_model.handle_proto_id(&mut ctx).unwrap();

    let out_len = ctx.tx.as_borrow_slice().len();
    data_out[..out_len].copy_from_slice(ctx.tx.as_borrow_slice());
    (data_model, out_len)
}

#[test]
fn test_valid_invoke_cmd() -> Result<(), Error> {
    // An invoke command for endpoint 0, cluster 49, command 12 and a u8 variable value of 0x05

    let b = [
        0x15, 0x28, 0x00, 0x28, 0x01, 0x36, 0x02, 0x15, 0x37, 0x00, 0x24, 0x00, 0x00, 0x24, 0x01,
        0x31, 0x24, 0x02, 0x0c, 0x18, 0x35, 0x01, 0x24, 0x00, 0x05, 0x18, 0x18, 0x18, 0x18,
    ];

    let mut out_buf: [u8; 20] = [0; 20];

    let (data_model, _) = handle_data(OpCode::InvokeRequest, &b, &mut out_buf);
    let data = data_model.node.lock().unwrap();
    assert_eq!(data.endpoint, 0);
    assert_eq!(data.cluster, 49);
    assert_eq!(data.command, 12);
    assert_eq!(data.variable, 5);
    Ok(())
}
