/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

use crate::error::Error;
use crate::im::encoding::{AttrDataTag, AttrPath, AttrRespTag, CmdDataTag, CmdPath, CmdRespTag};
use crate::tlv::{TLVTag, TLVWrite, TagType, ToTLV};

use super::{AttrDetails, CmdDetails};

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
    fn writer(&mut self) -> impl TLVWrite + Send + '_;

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
    T: TLVWrite + Send,
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
    T: TLVWrite + Send,
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

    fn writer(&mut self) -> impl TLVWrite + Send + '_ {
        &mut self.tw
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}

/// A concrete implementation of the `InvokeReply` trait for encoding command data.
pub struct InvokeReplyInstance<T> {
    path: CmdPath,
    command_ref: Option<u16>,
    tw: T,
}

impl<T> InvokeReplyInstance<T>
where
    T: TLVWrite,
{
    pub const fn new(cmd: &CmdDetails, tw: T) -> Self {
        Self {
            path: cmd.reply_path(),
            command_ref: cmd.command_ref,
            tw,
        }
    }
}

impl<T> InvokeReply for InvokeReplyInstance<T>
where
    T: TLVWrite + Send,
{
    fn with_command(mut self, cmd: u32) -> Result<impl Reply, Error> {
        let mut writer = CmdInvokeReplyInstance::new(self.tw, self.command_ref);
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
    command_ref: Option<u16>,
    tw: T,
}

impl<T> CmdInvokeReplyInstance<T>
where
    T: TLVWrite,
{
    const TAG: TagType = TagType::Context(CmdDataTag::Data as _);

    fn new(tw: T, command_ref: Option<u16>) -> Self {
        Self {
            anchor: tw.get_tail(),
            command_ref,
            tw,
        }
    }
}

impl<T> Reply for CmdInvokeReplyInstance<T>
where
    T: TLVWrite + Send,
{
    const TAG: TagType = Self::TAG;

    fn set<P: ToTLV>(mut self, value: P) -> Result<(), Error> {
        value.to_tlv(&Self::TAG, &mut self.tw)?;
        self.complete()
    }

    fn complete(mut self) -> Result<(), Error> {
        if let Some(command_ref) = self.command_ref {
            self.tw
                .u16(&TLVTag::Context(CmdDataTag::CommandRef as _), command_ref)?;
        }

        self.tw.end_container()?;
        self.tw.end_container()?;

        Ok(())
    }

    fn writer(&mut self) -> impl TLVWrite + Send + '_ {
        &mut self.tw
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}
