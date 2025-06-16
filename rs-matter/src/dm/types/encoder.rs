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

use core::fmt::Debug;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::im::core::IMStatusCode;
use crate::im::messages::ib::{
    AttrPath, AttrResp, AttrStatus, CmdDataTag, CmdPath, CmdResp, CmdRespTag, CmdStatus,
};
use crate::tlv::TLVTag;
use crate::transport::exchange::Exchange;
use crate::{
    error::{Error, ErrorCode},
    im::messages::ib::{AttrDataTag, AttrRespTag},
    tlv::{FromTLV, TLVElement, TLVWrite, TLVWriter, TagType, ToTLV},
};

use super::{
    AttrDetails, ChangeNotify, CmdDetails, DataModelHandler, InvokeContext, ReadContext,
    WriteContext,
};

pub struct AttrDataEncoder<'a, 'b, 'c> {
    dataver_filter: Option<u32>,
    path: AttrPath,
    tw: &'a mut TLVWriter<'b, 'c>,
}

impl<'a, 'b, 'c> AttrDataEncoder<'a, 'b, 'c> {
    pub async fn handle_read<T: DataModelHandler>(
        exchange: &Exchange<'_>,
        item: &Result<AttrDetails<'_>, AttrStatus>,
        handler: &T,
        tw: &mut TLVWriter<'_, '_>,
    ) -> Result<bool, Error> {
        let status = match item {
            Ok(attr) => {
                let encoder = AttrDataEncoder::new(attr, tw);

                let result = handler
                    .read(&ReadContext::new(exchange, attr), encoder)
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

    pub(crate) async fn handle_write<T: DataModelHandler>(
        exchange: &Exchange<'_>,
        item: &Result<(AttrDetails<'_>, TLVElement<'_>), AttrStatus>,
        handler: &T,
        tw: &mut TLVWriter<'_, '_>,
        notify: &dyn ChangeNotify,
    ) -> Result<(), Error> {
        let status = match item {
            Ok((attr, data)) => {
                let result = handler
                    .write(&WriteContext::new(exchange, attr, data, notify))
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

    pub fn new(attr: &AttrDetails, tw: &'a mut TLVWriter<'b, 'c>) -> Self {
        Self {
            dataver_filter: attr.dataver,
            path: attr.path(),
            tw,
        }
    }

    pub fn with_dataver(self, dataver: u32) -> Result<Option<AttrDataWriter<'a, 'b, 'c>>, Error> {
        if self
            .dataver_filter
            .map(|dataver_filter| dataver_filter != dataver)
            .unwrap_or(true)
        {
            let mut writer = AttrDataWriter::new(self.tw);

            writer.start_struct(&TLVTag::Anonymous)?;
            writer.start_struct(&TLVTag::Context(AttrRespTag::Data as _))?;
            writer.u32(&TLVTag::Context(AttrDataTag::DataVer as _), dataver)?;
            self.path
                .to_tlv(&TagType::Context(AttrDataTag::Path as _), &mut *writer)?;

            Ok(Some(writer))
        } else {
            Ok(None)
        }
    }
}

pub struct AttrDataWriter<'a, 'b, 'c> {
    tw: &'a mut TLVWriter<'b, 'c>,
    anchor: usize,
    completed: bool,
}

impl<'a, 'b, 'c> AttrDataWriter<'a, 'b, 'c> {
    pub const TAG: TLVTag = TLVTag::Context(AttrDataTag::Data as _);

    fn new(tw: &'a mut TLVWriter<'b, 'c>) -> Self {
        let anchor = tw.get_tail();

        Self {
            tw,
            anchor,
            completed: false,
        }
    }

    pub fn set<T: ToTLV>(mut self, value: T) -> Result<(), Error> {
        value.to_tlv(&Self::TAG, &mut self.tw)?;
        self.complete()
    }

    pub fn complete(mut self) -> Result<(), Error> {
        self.tw.end_container()?;
        self.tw.end_container()?;

        self.completed = true;

        Ok(())
    }

    pub fn writer(&mut self) -> &mut TLVWriter<'b, 'c> {
        self.tw
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}

impl Drop for AttrDataWriter<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.reset();
        }
    }
}

impl<'b, 'c> Deref for AttrDataWriter<'_, 'b, 'c> {
    type Target = TLVWriter<'b, 'c>;

    fn deref(&self) -> &Self::Target {
        self.tw
    }
}

impl DerefMut for AttrDataWriter<'_, '_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.tw
    }
}

#[derive(Default)]
pub struct CmdDataTracker {
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

pub struct CmdDataEncoder<'a, 'b, 'c> {
    tracker: &'a mut CmdDataTracker,
    path: CmdPath,
    tw: &'a mut TLVWriter<'b, 'c>,
}

impl<'a, 'b, 'c> CmdDataEncoder<'a, 'b, 'c> {
    pub(crate) async fn handle<T: DataModelHandler>(
        item: &Result<(CmdDetails<'_>, TLVElement<'_>), CmdStatus>,
        handler: &T,
        tw: &mut TLVWriter<'_, '_>,
        exchange: &Exchange<'_>,
        notify: &dyn ChangeNotify,
    ) -> Result<(), Error> {
        let status = match item {
            Ok((cmd, data)) => {
                let mut tracker = CmdDataTracker::new();
                let encoder = CmdDataEncoder::new(cmd, &mut tracker, tw);

                let result = handler
                    .invoke(&InvokeContext::new(exchange, cmd, data, notify), encoder)
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

    pub fn with_command(mut self, cmd: u32) -> Result<CmdDataWriter<'a, 'b, 'c>, Error> {
        let mut writer = CmdDataWriter::new(self.tracker, self.tw);

        writer.start_struct(&TLVTag::Anonymous)?;
        writer.start_struct(&TLVTag::Context(CmdRespTag::Cmd as _))?;

        self.path.path.leaf = Some(cmd as _);
        self.path
            .to_tlv(&TagType::Context(CmdDataTag::Path as _), &mut *writer)?;

        Ok(writer)
    }
}

pub struct CmdDataWriter<'a, 'b, 'c> {
    tracker: &'a mut CmdDataTracker,
    tw: &'a mut TLVWriter<'b, 'c>,
    anchor: usize,
    completed: bool,
}

impl<'a, 'b, 'c> CmdDataWriter<'a, 'b, 'c> {
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

    pub fn set<T: ToTLV>(mut self, value: T) -> Result<(), Error> {
        value.to_tlv(&Self::TAG, &mut self.tw)?;
        self.complete()
    }

    pub fn complete(mut self) -> Result<(), Error> {
        self.tw.end_container()?;
        self.tw.end_container()?;

        self.completed = true;
        self.tracker.complete();

        Ok(())
    }

    pub fn writer(&mut self) -> &mut TLVWriter<'b, 'c> {
        self.tw
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}

impl Drop for CmdDataWriter<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.reset();
        }
    }
}

impl<'b, 'c> Deref for CmdDataWriter<'_, 'b, 'c> {
    type Target = TLVWriter<'b, 'c>;

    fn deref(&self) -> &Self::Target {
        self.tw
    }
}

impl DerefMut for CmdDataWriter<'_, '_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.tw
    }
}

#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttrType<T>(PhantomData<fn() -> T>);

impl<T> AttrType<T> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }

    pub fn encode(&self, writer: AttrDataWriter, value: T) -> Result<(), Error>
    where
        T: ToTLV,
    {
        writer.set(value)
    }

    pub fn decode<'a>(&self, data: &'a TLVElement) -> Result<T, Error>
    where
        T: FromTLV<'a>,
    {
        T::from_tlv(data)
    }
}

impl<T> Default for AttrType<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttrUtfType;

impl AttrUtfType {
    pub const fn new() -> Self {
        Self
    }

    pub fn encode(&self, writer: AttrDataWriter, value: &str) -> Result<(), Error> {
        writer.set(value)
    }

    pub fn decode<'a>(&self, data: &TLVElement<'a>) -> Result<&'a str, IMStatusCode> {
        data.utf8().map_err(|_| IMStatusCode::InvalidDataType)
    }
}
