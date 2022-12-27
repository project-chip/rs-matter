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
    error::Error,
    interaction_model::core::OpCode,
    tlv::{get_root_node_struct, FromTLV, TLVWriter, TagType},
    transport::{packet::Packet, proto_demux::ResponseRequired},
};

use super::{
    messages::msg::{self, ReadReq},
    InteractionModel, Transaction,
};

impl InteractionModel {
    pub fn handle_read_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut Packet,
    ) -> Result<ResponseRequired, Error> {
        proto_tx.set_proto_opcode(OpCode::ReportData as u8);

        let mut tw = TLVWriter::new(proto_tx.get_writebuf()?);
        let root = get_root_node_struct(rx_buf)?;
        let read_req = ReadReq::from_tlv(&root)?;

        tw.start_struct(TagType::Anonymous)?;
        self.consumer.consume_read_attr(&read_req, trans, &mut tw)?;
        // Supress response always true for read interaction
        tw.bool(
            TagType::Context(msg::ReportDataTag::SupressResponse as u8),
            true,
        )?;
        tw.end_container()?;

        trans.complete();
        Ok(ResponseRequired::Yes)
    }
}
