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

use core::future::Future;

use crate::dm::{AsyncHandler, IMBuffer};
use crate::error::{Error, ErrorCode};
use crate::im::{
    AttrDataTag, AttrPath, AttrResp, AttrRespTag, AttrStatus, CmdDataTag, CmdPath, CmdResp,
    CmdRespTag, CmdStatus, IMStatusCode,
};
use crate::tlv::{TLVElement, TLVTag, TLVWrite, TagType, ToTLV};
use crate::transport::exchange::Exchange;
use crate::utils::storage::pooled::BufferAccess;

use super::{
    AttrDetails, ChangeNotify, CmdDetails, InvokeContextInstance, ReadContextInstance,
    WriteContextInstance,
};

// A type for writing the outcome of an attribute-read or command-invoke operation.
pub trait Reply {
    /// The tag to use if writing the data "manually" by using the `writer` method.
    const TAG: TagType;

    /// Set the TLV value of the reply and complete.
    fn set<T: ToTLV>(self, value: T) -> Result<(), Error>;

    /// Return the tag to use if writing the TLV reply data in smaller chunks by using the `writer` method
    /// (as opposed to just calling `set`).
    /// A convenience method to avoid using the `Self::TAG` directly.
    fn tag(&self) -> &'static TagType {
        &Self::TAG
    }

    /// Remove everything written via the `writer` method since the last call to `reset`.
    fn reset(&mut self);

    /// Return a TLV writer to write the TLV reply data manually.
    fn writer(&mut self) -> impl TLVWrite + '_;

    /// Complete the manual TLV write of the reply.
    fn complete(self) -> Result<(), Error>;
}

/// A trait for encoding the attribute value for an attribute read operation.
pub trait ReadReply {
    /// Return the reply data writer for an attribute, if the given `dataver` is still the latest
    /// cluster dataver.
    fn with_dataver(self, dataver: u32) -> Result<Option<impl Reply>, Error>;
}

/// A trait for encoding the result from a command invoke operation.
pub trait InvokeReply {
    /// Return the reply data writer for a command with the provided Command ID.
    fn with_command(self, cmd: u32) -> Result<impl Reply, Error>;
}

pub struct HandlerInvoker<'a, 'b, D, B> {
    exchange: &'b mut Exchange<'a>,
    handler: D,
    buffers: B,
}

impl<'a, 'b, D, B> HandlerInvoker<'a, 'b, D, B>
where
    D: AsyncHandler,
    B: BufferAccess<IMBuffer>,
{
    pub const fn new(exchange: &'b mut Exchange<'a>, handler: D, buffers: B) -> Self {
        Self {
            exchange,
            handler,
            buffers,
        }
    }

    pub fn exchange(&mut self) -> &mut Exchange<'a> {
        self.exchange
    }

    pub async fn process_read<T: TLVWrite>(
        &mut self,
        item: &Result<AttrDetails<'_>, AttrStatus>,
        mut tw: T,
    ) -> Result<(), Error> {
        let tail = tw.get_tail();

        let result = self.do_process_read(item, &mut tw).await;

        if result.is_err() {
            // If there was an error, rewind to the tail so we don't write any data.
            tw.rewind_to(tail);
        }

        result
    }

    async fn do_process_read<T: TLVWrite>(
        &mut self,
        item: &Result<AttrDetails<'_>, AttrStatus>,
        mut tw: T,
    ) -> Result<(), Error> {
        let result = match item {
            Ok(attr) => {
                let pos = tw.get_tail();

                let result = self.read(attr, &mut tw).await;

                match result {
                    Ok(()) => Ok(None),
                    Err(e) if e.code() != ErrorCode::NoSpace => {
                        error!("Error reading attribute: {:?}", e);

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

    pub fn read<'t, T: TLVWrite + 't>(
        &'t mut self,
        attr: &'t AttrDetails<'_>,
        tw: T,
    ) -> impl Future<Output = Result<(), Error>> + 't {
        self.handler.read(
            ReadContextInstance::new(self.exchange, &self.handler, &self.buffers, attr),
            ReadReplyInstance::new(attr, tw),
        )
    }

    pub async fn process_write<T: TLVWrite>(
        &mut self,
        item: &Result<(AttrDetails<'_>, TLVElement<'_>), AttrStatus>,
        mut tw: T,
        notify: &dyn ChangeNotify,
    ) -> Result<(), Error> {
        let tail = tw.get_tail();

        let result = self.do_process_write(item, &mut tw, notify).await;

        if result.is_err() {
            // If there was an error, rewind to the tail so we don't write any data.
            tw.rewind_to(tail);
        }

        result
    }

    async fn do_process_write<T: TLVWrite>(
        &mut self,
        item: &Result<(AttrDetails<'_>, TLVElement<'_>), AttrStatus>,
        mut tw: T,
        notify: &dyn ChangeNotify,
    ) -> Result<(), Error> {
        let result = match item {
            Ok((attr, data)) => {
                let pos = tw.get_tail();

                let result = self.write(attr, data, notify).await;

                match result {
                    Ok(()) => Ok(attr.status(IMStatusCode::Success)),
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

    pub fn write<'t>(
        &'t mut self,
        attr: &'t AttrDetails<'_>,
        data: &'t TLVElement<'_>,
        notify: &'t dyn ChangeNotify,
    ) -> impl Future<Output = Result<(), Error>> + 't {
        self.handler.write(WriteContextInstance::new(
            self.exchange,
            &self.handler,
            &self.buffers,
            attr,
            data,
            notify,
        ))
    }

    pub async fn process_invoke<T: TLVWrite>(
        &mut self,
        item: &Result<(CmdDetails<'_>, TLVElement<'_>), CmdStatus>,
        mut tw: T,
        notify: &dyn ChangeNotify,
    ) -> Result<(), Error> {
        let tail = tw.get_tail();

        let result = self.do_process_invoke(item, &mut tw, notify).await;

        if result.is_err() {
            // If there was an error, rewind to the tail so we don't write any data.
            tw.rewind_to(tail);
        }

        result
    }

    async fn do_process_invoke<T: TLVWrite>(
        &mut self,
        item: &Result<(CmdDetails<'_>, TLVElement<'_>), CmdStatus>,
        mut tw: T,
        notify: &dyn ChangeNotify,
    ) -> Result<(), Error> {
        let result = match item {
            Ok((cmd, data)) => {
                let pos = tw.get_tail();

                let result = self.invoke(cmd, data, &mut tw, notify).await;

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

    pub fn invoke<'t, T: TLVWrite + 't>(
        &'t mut self,
        cmd: &'t CmdDetails<'_>,
        data: &'t TLVElement<'_>,
        tw: T,
        notify: &'t dyn ChangeNotify,
    ) -> impl Future<Output = Result<(), Error>> + 't {
        self.handler.invoke(
            InvokeContextInstance::new(
                self.exchange,
                &self.handler,
                &self.buffers,
                cmd,
                data,
                notify,
            ),
            InvokeReplyInstance::new(cmd, tw),
        )
    }
}

/// A concrete implementation of the `ReadReply` trait for encoding attribute data.
pub struct ReadReplyInstance<T> {
    dataver_filter: Option<u32>,
    path: AttrPath,
    tw: T,
}

impl<T> ReadReplyInstance<T>
where
    T: TLVWrite,
{
    pub fn new(attr: &AttrDetails, tw: T) -> Self {
        Self {
            dataver_filter: attr.dataver,
            path: attr.reply_path(),
            tw,
        }
    }
}

impl<T> ReadReply for ReadReplyInstance<T>
where
    T: TLVWrite,
{
    fn with_dataver(self, dataver: u32) -> Result<Option<impl Reply>, Error> {
        if self
            .dataver_filter
            .map(|dataver_filter| dataver_filter != dataver)
            .unwrap_or(true)
        {
            let mut writer = AttrReadReplyInstance::new(self.tw);
            let mut tw = writer.writer();

            tw.start_struct(&TLVTag::Anonymous)?;
            tw.start_struct(&TLVTag::Context(AttrRespTag::Data as _))?;
            tw.u32(&TLVTag::Context(AttrDataTag::DataVer as _), dataver)?;
            self.path
                .to_tlv(&TagType::Context(AttrDataTag::Path as _), tw)?;

            Ok(Some(writer))
        } else {
            Ok(None)
        }
    }
}

/// A concrete implementation of the `Reply` trait for writing a reply to an attribute read operation.
pub(crate) struct AttrReadReplyInstance<T>
where
    T: TLVWrite,
{
    anchor: T::Position,
    tw: T,
}

impl<T> AttrReadReplyInstance<T>
where
    T: TLVWrite,
{
    pub(crate) const TAG: TLVTag = TLVTag::Context(AttrDataTag::Data as _);

    fn new(tw: T) -> Self {
        Self {
            anchor: tw.get_tail(),
            tw,
        }
    }
}

impl<T> Reply for AttrReadReplyInstance<T>
where
    T: TLVWrite,
{
    const TAG: TagType = Self::TAG;

    fn set<P: ToTLV>(mut self, value: P) -> Result<(), Error> {
        value.to_tlv(&Self::TAG, &mut self.tw)?;
        self.complete()
    }

    fn complete(mut self) -> Result<(), Error> {
        self.tw.end_container()?;
        self.tw.end_container()?;

        Ok(())
    }

    fn writer(&mut self) -> impl TLVWrite + '_ {
        &mut self.tw
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}

/// A concrete implementation of the `InvokeReply` trait for encoding command data.
pub struct InvokeReplyInstance<T> {
    path: CmdPath,
    tw: T,
}

impl<T> InvokeReplyInstance<T>
where
    T: TLVWrite,
{
    pub const fn new(cmd: &CmdDetails, tw: T) -> Self {
        Self {
            path: cmd.reply_path(),
            tw,
        }
    }
}

impl<T> InvokeReply for InvokeReplyInstance<T>
where
    T: TLVWrite,
{
    fn with_command(mut self, cmd: u32) -> Result<impl Reply, Error> {
        let mut writer = CmdInvokeReplyInstance::new(self.tw);
        let mut tw = writer.writer();

        tw.start_struct(&TLVTag::Anonymous)?;
        tw.start_struct(&TLVTag::Context(CmdRespTag::Cmd as _))?;

        self.path.cmd = Some(cmd as _);
        self.path
            .to_tlv(&TagType::Context(CmdDataTag::Path as _), tw)?;

        Ok(writer)
    }
}

/// A concrete implementation of the `Reply` trait for writing the reply of a command invocation.
struct CmdInvokeReplyInstance<T>
where
    T: TLVWrite,
{
    anchor: T::Position,
    tw: T,
}

impl<T> CmdInvokeReplyInstance<T>
where
    T: TLVWrite,
{
    const TAG: TagType = TagType::Context(CmdDataTag::Data as _);

    fn new(tw: T) -> Self {
        Self {
            anchor: tw.get_tail(),
            tw,
        }
    }
}

impl<T> Reply for CmdInvokeReplyInstance<T>
where
    T: TLVWrite,
{
    const TAG: TagType = Self::TAG;

    fn set<P: ToTLV>(mut self, value: P) -> Result<(), Error> {
        value.to_tlv(&Self::TAG, &mut self.tw)?;
        self.complete()
    }

    fn complete(mut self) -> Result<(), Error> {
        self.tw.end_container()?;
        self.tw.end_container()?;

        Ok(())
    }

    fn writer(&mut self) -> impl TLVWrite + '_ {
        &mut self.tw
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}
