/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! The Interaction-Model engine's per-item handler invoker.
//!
//! [`HandlerInvoker`] drives a single attribute read/write or command invoke
//! against the cluster handlers: it builds the handler-facing context and reply
//! (the concrete `dm` `*Instance` realizations), calls the handler, and encodes
//! the wire-format outcome (`AttrResp`/`CmdResp`/status), handling `NoSpace`
//! rewind and subscription change-notification. Driven by the responders in
//! [`crate::im`].

use crate::dm::{
    AsyncHandler, AttrDetails, CmdDetails, HandlerContext, InvokeContextInstance,
    InvokeReplyInstance, ReadContextInstance, ReadReplyInstance, WriteContextInstance,
};
use crate::error::{Error, ErrorCode};
use crate::im::encoding::{AttrResp, AttrStatus, CmdResp, CmdStatus, IMStatusCode};
use crate::tlv::{TLVElement, TLVWrite, TagType, ToTLV};
use crate::transport::exchange::Exchange;
use crate::utils::storage::WriteBuf;

pub struct HandlerInvoker<'a, 'b, C> {
    exchange: &'b mut Exchange<'a>,
    context: C,
}

impl<'a, 'b, C> HandlerInvoker<'a, 'b, C>
where
    C: HandlerContext,
{
    pub const fn new(exchange: &'b mut Exchange<'a>, context: C) -> Self {
        Self { exchange, context }
    }

    pub fn exchange(&mut self) -> &mut Exchange<'a> {
        self.exchange
    }

    pub async fn process_read(
        &mut self,
        item: &Result<AttrDetails, AttrStatus>,
        tw: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let tail = tw.get_tail();

        let result = self.do_process_read(item, &mut *tw).await;

        if result.is_err() {
            // If there was an error, rewind to the tail so we don't write any data.
            tw.rewind_to(tail);
        }

        result
    }

    async fn do_process_read(
        &mut self,
        item: &Result<AttrDetails, AttrStatus>,
        tw: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let result = match item {
            Ok(attr) => {
                let pos = tw.get_tail();

                let result = self.read(attr, &mut *tw).await;

                match result {
                    Ok(()) => Ok(None),
                    Err(e) if e.code() != ErrorCode::NoSpace => {
                        error!("Error reading attribute: {}", e);

                        tw.rewind_to(pos);

                        Ok(attr.status(e.into()))
                    }
                    Err(e) => Err(e),
                }
            }
            Err(status) => {
                error!("Error processing attribute read: {:?}", status);
                Ok(Some(status.clone()))
            }
        };

        match result {
            Ok(Some(status)) => AttrResp::Status(status).to_tlv(&TagType::Anonymous, tw),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub async fn read(&mut self, attr: &AttrDetails, tw: &mut WriteBuf<'_>) -> Result<(), Error> {
        self.context
            .handler()
            .read(
                ReadContextInstance::new(self.exchange, &self.context, attr),
                ReadReplyInstance::new(attr, tw),
            )
            .await
    }

    pub async fn process_write(
        &mut self,
        item: &Result<(AttrDetails, TLVElement<'_>), AttrStatus>,
        tw: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let tail = tw.get_tail();

        let result = self.do_process_write(item, &mut *tw).await;

        if result.is_err() {
            // If there was an error, rewind to the tail so we don't write any data.
            tw.rewind_to(tail);
        }

        result
    }

    async fn do_process_write(
        &mut self,
        item: &Result<(AttrDetails, TLVElement<'_>), AttrStatus>,
        tw: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let result = match item {
            Ok((attr, data)) => {
                let pos = tw.get_tail();

                let result = self.write(attr, data).await;

                match result {
                    Ok(()) => {
                        // A write that was accepted by the cluster handler
                        // counts as an attribute change for subscription
                        // reporting purposes. Notify generically here so that
                        // cluster handlers do not each need to call
                        // `notify_attr_changed` from every attribute setter.
                        self.context.notify_attr_changed(
                            attr.endpoint_id,
                            attr.cluster_id,
                            attr.attr_id,
                        );
                        Ok(attr.status(IMStatusCode::Success))
                    }
                    Err(err) if err.code() != ErrorCode::NoSpace => {
                        error!("Error writing attribute: {}", err);

                        tw.rewind_to(pos);

                        Ok(attr.status(err.into()))
                    }
                    Err(err) => Err(err),
                }
            }
            Err(status) => {
                error!("Error processing attribute write: {:?}", status);
                Ok(Some(status.clone()))
            }
        };

        match result {
            Ok(Some(status)) => status.to_tlv(&TagType::Anonymous, tw),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub async fn write(&mut self, attr: &AttrDetails, data: &TLVElement<'_>) -> Result<(), Error> {
        self.context
            .handler()
            .write(WriteContextInstance::new(
                self.exchange,
                &self.context,
                attr,
                data,
            ))
            .await
    }

    pub async fn process_invoke(
        &mut self,
        item: &Result<(CmdDetails, TLVElement<'_>), CmdStatus>,
        tw: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let tail = tw.get_tail();

        let result = self.do_process_invoke(item, &mut *tw).await;

        if result.is_err() {
            // If there was an error, rewind to the tail so we don't write any data.
            tw.rewind_to(tail);
        }

        result
    }

    async fn do_process_invoke(
        &mut self,
        item: &Result<(CmdDetails, TLVElement<'_>), CmdStatus>,
        tw: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let result = match item {
            Ok((cmd, data)) => {
                let pos = tw.get_tail();

                let result = self.invoke(cmd, data, &mut *tw).await;

                match result {
                    Ok(()) => {
                        if pos == tw.get_tail() {
                            Ok(cmd.status(IMStatusCode::Success))
                        } else {
                            Ok(None)
                        }
                    }
                    Err(err) if err.code() != ErrorCode::NoSpace => {
                        error!("Error invoking command: {}", err);

                        tw.rewind_to(pos);

                        Ok(cmd.status(err.into()))
                    }
                    Err(err) => Err(err),
                }
            }
            Err(status) => {
                error!("Error processing command: {:?}", status);
                Ok(Some(status.clone()))
            }
        };

        match result {
            Ok(Some(status)) => CmdResp::Status(status).to_tlv(&TagType::Anonymous, tw),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub async fn invoke(
        &mut self,
        cmd: &CmdDetails,
        data: &TLVElement<'_>,
        tw: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        self.context
            .handler()
            .invoke(
                InvokeContextInstance::new(self.exchange, &self.context, cmd, data),
                InvokeReplyInstance::new(cmd, tw),
            )
            .await
    }
}
