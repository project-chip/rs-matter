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

use log::error;

use crate::{
    error::Error,
    tlv::{get_root_node_struct, FromTLV, TLVWriter, TagType},
    transport::{packet::Packet, proto_demux::ResponseRequired},
};

use super::{core::OpCode, messages::msg::WriteReq, InteractionModel, Transaction};

impl InteractionModel {
    pub fn handle_write_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut Packet,
    ) -> Result<ResponseRequired, Error> {
        if InteractionModel::req_timeout_handled(trans, proto_tx)? == true {
            return Ok(ResponseRequired::Yes);
        }
        proto_tx.set_proto_opcode(OpCode::WriteResponse as u8);

        let mut tw = TLVWriter::new(proto_tx.get_writebuf()?);
        let root = get_root_node_struct(rx_buf)?;
        let write_req = WriteReq::from_tlv(&root)?;
        let supress_response = write_req.supress_response.unwrap_or_default();

        tw.start_struct(TagType::Anonymous)?;
        self.consumer
            .consume_write_attr(&write_req, trans, &mut tw)?;
        tw.end_container()?;

        trans.complete();
        if supress_response {
            error!("Supress response is set, is this the expected handling?");
            Ok(ResponseRequired::No)
        } else {
            Ok(ResponseRequired::Yes)
        }
    }
}
