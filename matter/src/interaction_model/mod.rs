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
    tlv::TLVWriter,
    transport::{exchange::Exchange, proto_demux::ResponseRequired, session::SessionHandle},
};

use self::{
    core::OpCode,
    messages::msg::{InvReq, StatusResp, WriteReq},
};

#[derive(PartialEq)]
pub enum TransactionState {
    Ongoing,
    Complete,
    Terminate,
}
pub struct Transaction<'a, 'b> {
    pub state: TransactionState,
    pub session: &'a mut SessionHandle<'b>,
    pub exch: &'a mut Exchange,
}

pub trait InteractionConsumer {
    fn consume_invoke_cmd(
        &self,
        req: &InvReq,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
    ) -> Result<(), Error>;

    fn consume_read_attr(
        &self,
        // TODO: This handling is different from the other APIs here, identify
        // consistent options for this trait
        req: &[u8],
        trans: &mut Transaction,
        tw: &mut TLVWriter,
    ) -> Result<(), Error>;

    fn consume_write_attr(
        &self,
        req: &WriteReq,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
    ) -> Result<(), Error>;

    fn consume_status_report(
        &self,
        _req: &StatusResp,
        _trans: &mut Transaction,
        _tw: &mut TLVWriter,
    ) -> Result<(OpCode, ResponseRequired), Error>;

    fn consume_subscribe(
        &self,
        _req: &[u8],
        _trans: &mut Transaction,
        _tw: &mut TLVWriter,
    ) -> Result<(OpCode, ResponseRequired), Error>;
}

pub struct InteractionModel {
    consumer: Box<dyn InteractionConsumer>,
}
pub mod command;
pub mod core;
pub mod messages;
pub mod read;
pub mod write;
