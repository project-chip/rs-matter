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

use crate::dm::IMBuffer;
use crate::error::{Error, ErrorCode};
use crate::im::{
    AttrDataTag, AttrPath, AttrResp, AttrRespTag, AttrStatus, CmdDataTag, CmdPath, CmdResp,
    CmdRespTag, CmdStatus, IMStatusCode,
};
use crate::tlv::{TLVElement, TLVTag, TLVWrite, TLVWriter, TagType, ToTLV};
use crate::transport::exchange::Exchange;
use crate::utils::storage::pooled::BufferAccess;

use super::{
    AttrDetails, ChangeNotify, CmdDetails, DataModelHandler, InvokeContextInstance,
    ReadContextInstance, WriteContextInstance,
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

/// A concrete implementation of the `ReadReply` trait for encoding attribute data.
pub(crate) struct ReadReplyInstance<'a, 'b, 'c> {
    dataver_filter: Option<u32>,
    path: AttrPath,
    tw: &'a mut TLVWriter<'b, 'c>,
}

impl<'a, 'b, 'c> ReadReplyInstance<'a, 'b, 'c> {
    pub(crate) async fn handle_read<T: DataModelHandler, B: BufferAccess<IMBuffer>>(
        exchange: &Exchange<'_>,
        item: &Result<AttrDetails<'_>, AttrStatus>,
        handler: T,
        buffers: B,
        tw: &mut TLVWriter<'_, '_>,
    ) -> Result<bool, Error> {
        let status = match item {
            Ok(attr) => {
                let encoder = ReadReplyInstance::new(attr, tw);

                let result = handler
                    .read(
                        ReadContextInstance::new(exchange, &handler, buffers, attr),
                        encoder,
                    )
                    .await;
                match result {
                    Ok(()) => None,
                    Err(e) => {
                        if e.code() == ErrorCode::NoSpace {
                            return Ok(false);
                        } else {
                            error!("Error reading attribute: {}", e);
                            attr.status(e.into())?
                        }
                    }
                }
            }
            Err(status) => Some(status.clone()),
        };

        if let Some(status) = status {
            AttrResp::Status(status).to_tlv(&TagType::Anonymous, tw)?;
        }

        Ok(true)
    }

    pub(crate) async fn handle_write<T: DataModelHandler, B: BufferAccess<IMBuffer>>(
        exchange: &Exchange<'_>,
        item: &Result<(AttrDetails<'_>, TLVElement<'_>), AttrStatus>,
        handler: T,
        buffers: B,
        tw: &mut TLVWriter<'_, '_>,
        notify: &dyn ChangeNotify,
    ) -> Result<(), Error> {
        let status = match item {
            Ok((attr, data)) => {
                let result = handler
                    .write(WriteContextInstance::new(
                        exchange, &handler, buffers, attr, data, notify,
                    ))
                    .await;
                match result {
                    Ok(()) => attr.status(IMStatusCode::Success)?,
                    Err(error) => {
                        error!("Error writing attribute: {}", error);
                        attr.status(error.into())?
                    }
                }
            }
            Err(status) => Some(status.clone()),
        };

        if let Some(status) = status {
            status.to_tlv(&TagType::Anonymous, tw)?;
        }

        Ok(())
    }

    pub(crate) fn new(attr: &AttrDetails, tw: &'a mut TLVWriter<'b, 'c>) -> Self {
        Self {
            dataver_filter: attr.dataver,
            path: attr.path(),
            tw,
        }
    }
}

impl<'a, 'b, 'c> ReadReply for ReadReplyInstance<'a, 'b, 'c> {
    fn with_dataver(self, dataver: u32) -> Result<Option<impl Reply>, Error> {
        if self
            .dataver_filter
            .map(|dataver_filter| dataver_filter != dataver)
            .unwrap_or(true)
        {
            let mut writer = AttrReplyInstance::new(self.tw);
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

/// A concrete implementation of the `Reply` trait for returning attribute data.
pub(crate) struct AttrReplyInstance<'a, 'b, 'c> {
    tw: &'a mut TLVWriter<'b, 'c>,
    anchor: usize,
    completed: bool,
}

impl<'a, 'b, 'c> AttrReplyInstance<'a, 'b, 'c> {
    pub const TAG: TLVTag = TLVTag::Context(AttrDataTag::Data as _);

    fn new(tw: &'a mut TLVWriter<'b, 'c>) -> Self {
        let anchor = tw.get_tail();

        Self {
            tw,
            anchor,
            completed: false,
        }
    }
}

impl<'a, 'b, 'c> Reply for AttrReplyInstance<'a, 'b, 'c> {
    const TAG: TagType = Self::TAG;

    fn set<T: ToTLV>(mut self, value: T) -> Result<(), Error> {
        value.to_tlv(&Self::TAG, &mut self.tw)?;
        self.complete()
    }

    fn complete(mut self) -> Result<(), Error> {
        self.tw.end_container()?;
        self.tw.end_container()?;

        self.completed = true;

        Ok(())
    }

    fn writer(&mut self) -> impl TLVWrite + '_ {
        &mut self.tw
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}

impl Drop for AttrReplyInstance<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.reset();
        }
    }
}

#[derive(Default)]
pub(crate) struct CmdDataTracker {
    skip_status: bool,
}

impl CmdDataTracker {
    pub const fn new() -> Self {
        Self { skip_status: false }
    }

    pub(crate) fn complete(&mut self) {
        self.skip_status = true;
    }

    pub fn needs_status(&self) -> bool {
        !self.skip_status
    }
}

/// A concrete implementation of the `InvokeReply` trait for encoding command data.
pub(crate) struct InvokeReplyInstance<'a, 'b, 'c> {
    tracker: &'a mut CmdDataTracker,
    path: CmdPath,
    tw: &'a mut TLVWriter<'b, 'c>,
}

impl<'a, 'b, 'c> InvokeReplyInstance<'a, 'b, 'c> {
    pub(crate) async fn handle<T: DataModelHandler, B: BufferAccess<IMBuffer>>(
        item: &Result<(CmdDetails<'_>, TLVElement<'_>), CmdStatus>,
        handler: T,
        buffers: B,
        tw: &mut TLVWriter<'_, '_>,
        exchange: &Exchange<'_>,
        notify: &dyn ChangeNotify,
    ) -> Result<(), Error> {
        let status = match item {
            Ok((cmd, data)) => {
                let mut tracker = CmdDataTracker::new();
                let encoder = InvokeReplyInstance::new(cmd, &mut tracker, tw);

                let result = handler
                    .invoke(
                        InvokeContextInstance::new(exchange, &handler, buffers, cmd, data, notify),
                        encoder,
                    )
                    .await;
                match result {
                    Ok(()) => cmd.success(&tracker),
                    Err(error) => {
                        error!("Error invoking command: {}", error);
                        cmd.status(error.into())
                    }
                }
            }
            Err(status) => {
                error!("Error invoking command: {:?}", status);
                Some(status.clone())
            }
        };

        if let Some(status) = status {
            CmdResp::Status(status).to_tlv(&TagType::Anonymous, tw)?;
        }

        Ok(())
    }

    pub fn new(
        cmd: &CmdDetails,
        tracker: &'a mut CmdDataTracker,
        tw: &'a mut TLVWriter<'b, 'c>,
    ) -> Self {
        Self {
            tracker,
            path: cmd.path(),
            tw,
        }
    }
}

impl<'a, 'b, 'c> InvokeReply for InvokeReplyInstance<'a, 'b, 'c> {
    fn with_command(mut self, cmd: u32) -> Result<impl Reply, Error> {
        let mut writer = CmdReplyInstance::new(self.tracker, self.tw);
        let mut tw = writer.writer();

        tw.start_struct(&TLVTag::Anonymous)?;
        tw.start_struct(&TLVTag::Context(CmdRespTag::Cmd as _))?;

        self.path.path.leaf = Some(cmd as _);
        self.path
            .to_tlv(&TagType::Context(CmdDataTag::Path as _), tw)?;

        Ok(writer)
    }
}

/// A concrete implementation of the `Reply` trait for writing command data.
pub(crate) struct CmdReplyInstance<'a, 'b, 'c> {
    tracker: &'a mut CmdDataTracker,
    tw: &'a mut TLVWriter<'b, 'c>,
    anchor: usize,
    completed: bool,
}

impl<'a, 'b, 'c> CmdReplyInstance<'a, 'b, 'c> {
    pub const TAG: TagType = TagType::Context(CmdDataTag::Data as _);

    fn new(tracker: &'a mut CmdDataTracker, tw: &'a mut TLVWriter<'b, 'c>) -> Self {
        let anchor = tw.get_tail();

        Self {
            tracker,
            tw,
            anchor,
            completed: false,
        }
    }
}

impl<'a, 'b, 'c> Reply for CmdReplyInstance<'a, 'b, 'c> {
    const TAG: TagType = Self::TAG;

    fn set<T: ToTLV>(mut self, value: T) -> Result<(), Error> {
        value.to_tlv(&Self::TAG, &mut self.tw)?;
        self.complete()
    }

    fn complete(mut self) -> Result<(), Error> {
        self.tw.end_container()?;
        self.tw.end_container()?;

        self.completed = true;
        self.tracker.complete();

        Ok(())
    }

    fn writer(&mut self) -> impl TLVWrite + '_ {
        &mut self.tw
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}

impl Drop for CmdReplyInstance<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.reset();
        }
    }
}
