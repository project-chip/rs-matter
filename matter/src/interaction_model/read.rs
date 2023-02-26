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
    tlv::{TLVWriter, TagType},
    transport::{packet::Packet, proto_demux::ResponseRequired},
    utils::writebuf::WriteBuf,
    wb_shrink, wb_unshrink,
};

use super::{InteractionModel, Transaction};

impl InteractionModel {
    pub fn handle_read_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut Packet,
    ) -> Result<ResponseRequired, Error> {
        proto_tx.set_proto_opcode(OpCode::ReportData as u8);
        // We have to do these gymnastics because we have to reserve some bytes towards the
        // end of the slice for adding our terminating TLVs
        const RESERVE_SIZE: usize = 8;
        let proto_tx_wb = proto_tx.get_writebuf()?;
        let mut child_wb = wb_shrink!(proto_tx_wb, RESERVE_SIZE);
        let mut tw = TLVWriter::new(&mut child_wb);

        tw.start_struct(TagType::Anonymous)?;
        self.consumer.consume_read_attr(rx_buf, trans, &mut tw)?;

        //Now that we have everything, start using the proto_tx_wb, by unshrinking it
        wb_unshrink!(proto_tx_wb, child_wb);
        let mut tw = TLVWriter::new(proto_tx_wb);
        tw.end_container()?;
        Ok(ResponseRequired::Yes)
    }
}
