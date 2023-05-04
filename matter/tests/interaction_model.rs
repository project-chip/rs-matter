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

use matter::data_model::core::DataHandler;
use matter::error::Error;
use matter::interaction_model::core::Interaction;
use matter::interaction_model::core::InteractionModel;
use matter::interaction_model::core::OpCode;
use matter::interaction_model::core::Transaction;
use matter::transport::exchange::Exchange;
use matter::transport::exchange::ExchangeCtx;
use matter::transport::network::Address;
use matter::transport::network::IpAddr;
use matter::transport::network::Ipv4Addr;
use matter::transport::network::SocketAddr;
use matter::transport::packet::Packet;
use matter::transport::packet::MAX_RX_BUF_SIZE;
use matter::transport::packet::MAX_TX_BUF_SIZE;
use matter::transport::proto_ctx::ProtoCtx;
use matter::transport::session::SessionMgr;
use matter::utils::epoch::dummy_epoch;
use matter::utils::rand::dummy_rand;

struct Node {
    pub endpoint: u16,
    pub cluster: u32,
    pub command: u16,
    pub variable: u8,
}

struct DataModel {
    node: Node,
}

impl DataModel {
    pub fn new(node: Node) -> Self {
        DataModel { node }
    }
}

impl DataHandler for DataModel {
    fn handle(
        &mut self,
        interaction: Interaction,
        _tx: &mut Packet,
        _transaction: &mut Transaction,
    ) -> Result<bool, Error> {
        if let Interaction::Invoke(req) = interaction {
            if let Some(inv_requests) = &req.inv_requests {
                for i in inv_requests.iter() {
                    let data = if let Some(data) = i.data.unwrap_tlv() {
                        data
                    } else {
                        continue;
                    };
                    let cmd_path_ib = i.path;
                    let mut common_data = &mut self.node;
                    common_data.endpoint = cmd_path_ib.path.endpoint.unwrap_or(1);
                    common_data.cluster = cmd_path_ib.path.cluster.unwrap_or(0);
                    common_data.command = cmd_path_ib.path.leaf.unwrap_or(0) as u16;
                    data.confirm_struct().unwrap();
                    common_data.variable = data.find_tag(0).unwrap().u8().unwrap();
                }
            }
        }

        Ok(false)
    }
}

fn handle_data(action: OpCode, data_in: &[u8], data_out: &mut [u8]) -> (DataModel, usize) {
    let data_model = DataModel::new(Node {
        endpoint: 0,
        cluster: 0,
        command: 0,
        variable: 0,
    });
    let mut interaction_model = InteractionModel(data_model);
    let mut exch: Exchange = Default::default();
    let mut sess_mgr = SessionMgr::new(dummy_epoch, dummy_rand);
    let sess_idx = sess_mgr
        .get_or_add(
            0,
            Address::Udp(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
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
        epoch: dummy_epoch,
    };
    let mut rx_buf = [0; MAX_RX_BUF_SIZE];
    let mut tx_buf = [0; MAX_TX_BUF_SIZE];
    let mut rx = Packet::new_rx(&mut rx_buf);
    let mut tx = Packet::new_tx(&mut tx_buf);
    // Create fake rx packet
    rx.set_proto_id(0x01);
    rx.set_proto_opcode(action as u8);
    rx.peer = Address::default();
    let in_data_len = data_in.len();
    let rx_buf = rx.as_mut_slice();
    rx_buf[..in_data_len].copy_from_slice(data_in);

    let mut ctx = ProtoCtx::new(exch_ctx, &rx, &mut tx);

    interaction_model.handle(&mut ctx).unwrap();

    let out_len = ctx.tx.as_mut_slice().len();
    data_out[..out_len].copy_from_slice(ctx.tx.as_mut_slice());
    (interaction_model.0, out_len)
}

#[test]
fn test_valid_invoke_cmd() -> Result<(), Error> {
    // An invoke command for endpoint 0, cluster 49, command 12 and a u8 variable value of 0x05

    let b = [
        0x15, 0x28, 0x00, 0x28, 0x01, 0x36, 0x02, 0x15, 0x37, 0x00, 0x25, 0x00, 0x00, 0x00, 0x26,
        0x01, 0x31, 0x00, 0x00, 0x00, 0x26, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x18, 0x35, 0x01, 0x24,
        0x00, 0x05, 0x18, 0x18, 0x18, 0x18,
    ];

    let mut out_buf: [u8; 20] = [0; 20];

    let (data_model, _) = handle_data(OpCode::InvokeRequest, &b, &mut out_buf);
    let data = &data_model.node;
    assert_eq!(data.endpoint, 0);
    assert_eq!(data.cluster, 49);
    assert_eq!(data.command, 12);
    assert_eq!(data.variable, 5);
    Ok(())
}
