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

use core::fmt::{Debug, Formatter};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::interaction_model::core::{IMStatusCode, Transaction};
use crate::interaction_model::messages::ib::{
    AttrPath, AttrResp, AttrStatus, CmdDataTag, CmdPath, CmdStatus, InvResp, InvRespTag,
};
use crate::interaction_model::messages::GenericPath;
use crate::tlv::UtfStr;
use crate::{
    error::{Error, ErrorCode},
    interaction_model::messages::ib::{AttrDataTag, AttrRespTag},
    tlv::{FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
};
use log::error;

use super::{AttrDetails, CmdDetails, Handler};

// TODO: Should this return an IMStatusCode Error? But if yes, the higher layer
// may have already started encoding the 'success' headers, we might not want to manage
// the tw.rewind() in that case, if we add this support
pub type EncodeValueGen<'a> = &'a dyn Fn(TagType, &mut TLVWriter);

#[derive(Copy, Clone)]
/// A structure for encoding various types of values
pub enum EncodeValue<'a> {
    /// This indicates a value that is dynamically generated. This variant
    /// is typically used in the transmit/to-tlv path where we want to encode a value at
    /// run time
    Closure(EncodeValueGen<'a>),
    /// This indicates a value that is in the TLVElement form. this variant is
    /// typically used in the receive/from-tlv path where we don't want to decode the
    /// full value but it can be done at the time of its usage
    Tlv(TLVElement<'a>),
    /// This indicates a static value. This variant is typically used in the transmit/
    /// to-tlv path
    Value(&'a dyn ToTLV),
}

impl<'a> EncodeValue<'a> {
    pub fn unwrap_tlv(self) -> Option<TLVElement<'a>> {
        match self {
            EncodeValue::Tlv(t) => Some(t),
            _ => None,
        }
    }
}

impl<'a> PartialEq for EncodeValue<'a> {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            EncodeValue::Closure(_) => {
                error!("PartialEq not yet supported");
                false
            }
            EncodeValue::Tlv(a) => {
                if let EncodeValue::Tlv(b) = *other {
                    a == b
                } else {
                    false
                }
            }
            // Just claim false for now
            EncodeValue::Value(_) => {
                error!("PartialEq not yet supported");
                false
            }
        }
    }
}

impl<'a> Debug for EncodeValue<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match *self {
            EncodeValue::Closure(_) => write!(f, "Contains closure"),
            EncodeValue::Tlv(t) => write!(f, "{:?}", t),
            EncodeValue::Value(_) => write!(f, "Contains EncodeValue"),
        }?;
        Ok(())
    }
}

impl<'a> ToTLV for EncodeValue<'a> {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        match self {
            EncodeValue::Closure(f) => {
                (f)(tag_type, tw);
                Ok(())
            }
            EncodeValue::Tlv(_) => panic!("This looks invalid"),
            EncodeValue::Value(v) => v.to_tlv(tw, tag_type),
        }
    }
}

impl<'a> FromTLV<'a> for EncodeValue<'a> {
    fn from_tlv(data: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(EncodeValue::Tlv(*data))
    }
}

pub struct AttrDataEncoder<'a, 'b, 'c> {
    dataver_filter: Option<u32>,
    path: AttrPath,
    tw: &'a mut TLVWriter<'b, 'c>,
}

impl<'a, 'b, 'c> AttrDataEncoder<'a, 'b, 'c> {
    pub fn handle_read<T: Handler>(
        item: Result<AttrDetails, AttrStatus>,
        handler: &T,
        tw: &mut TLVWriter,
    ) -> Result<Option<GenericPath>, Error> {
        let status = match item {
            Ok(attr) => {
                let encoder = AttrDataEncoder::new(&attr, tw);

                match handler.read(&attr, encoder) {
                    Ok(()) => None,
                    Err(e) => {
                        if e.code() == ErrorCode::NoSpace {
                            return Ok(Some(attr.path().to_gp()));
                        } else {
                            attr.status(e.into())?
                        }
                    }
                }
            }
            Err(status) => Some(status),
        };

        if let Some(status) = status {
            AttrResp::Status(status).to_tlv(tw, TagType::Anonymous)?;
        }

        Ok(None)
    }

    pub fn handle_write<T: Handler>(
        item: Result<(AttrDetails, TLVElement), AttrStatus>,
        handler: &mut T,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        let status = match item {
            Ok((attr, data)) => match handler.write(&attr, AttrData::new(attr.dataver, &data)) {
                Ok(()) => attr.status(IMStatusCode::Success)?,
                Err(error) => attr.status(error.into())?,
            },
            Err(status) => Some(status),
        };

        if let Some(status) = status {
            status.to_tlv(tw, TagType::Anonymous)?;
        }

        Ok(())
    }

    #[cfg(feature = "nightly")]
    pub async fn handle_read_async<T: super::asynch::AsyncHandler>(
        item: Result<AttrDetails<'_>, AttrStatus>,
        handler: &T,
        tw: &mut TLVWriter<'_, '_>,
    ) -> Result<Option<GenericPath>, Error> {
        let status = match item {
            Ok(attr) => {
                let encoder = AttrDataEncoder::new(&attr, tw);

                match handler.read(&attr, encoder).await {
                    Ok(()) => None,
                    Err(e) => {
                        if e.code() == ErrorCode::NoSpace {
                            return Ok(Some(attr.path().to_gp()));
                        } else {
                            attr.status(e.into())?
                        }
                    }
                }
            }
            Err(status) => Some(status),
        };

        if let Some(status) = status {
            AttrResp::Status(status).to_tlv(tw, TagType::Anonymous)?;
        }

        Ok(None)
    }

    #[cfg(feature = "nightly")]
    pub async fn handle_write_async<T: super::asynch::AsyncHandler>(
        item: Result<(AttrDetails<'_>, TLVElement<'_>), AttrStatus>,
        handler: &mut T,
        tw: &mut TLVWriter<'_, '_>,
    ) -> Result<(), Error> {
        let status = match item {
            Ok((attr, data)) => match handler
                .write(&attr, AttrData::new(attr.dataver, &data))
                .await
            {
                Ok(()) => attr.status(IMStatusCode::Success)?,
                Err(error) => attr.status(error.into())?,
            },
            Err(status) => Some(status),
        };

        if let Some(status) = status {
            AttrResp::Status(status).to_tlv(tw, TagType::Anonymous)?;
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

            writer.start_struct(TagType::Anonymous)?;
            writer.start_struct(TagType::Context(AttrRespTag::Data as _))?;
            writer.u32(TagType::Context(AttrDataTag::DataVer as _), dataver)?;
            self.path
                .to_tlv(&mut writer, TagType::Context(AttrDataTag::Path as _))?;

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
    pub const TAG: TagType = TagType::Context(AttrDataTag::Data as _);

    fn new(tw: &'a mut TLVWriter<'b, 'c>) -> Self {
        let anchor = tw.get_tail();

        Self {
            tw,
            anchor,
            completed: false,
        }
    }

    pub fn set<T: ToTLV>(self, value: T) -> Result<(), Error> {
        value.to_tlv(self.tw, Self::TAG)?;
        self.complete()
    }

    pub fn complete(mut self) -> Result<(), Error> {
        self.tw.end_container()?;
        self.tw.end_container()?;

        self.completed = true;

        Ok(())
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}

impl<'a, 'b, 'c> Drop for AttrDataWriter<'a, 'b, 'c> {
    fn drop(&mut self) {
        if !self.completed {
            self.reset();
        }
    }
}

impl<'a, 'b, 'c> Deref for AttrDataWriter<'a, 'b, 'c> {
    type Target = TLVWriter<'b, 'c>;

    fn deref(&self) -> &Self::Target {
        self.tw
    }
}

impl<'a, 'b, 'c> DerefMut for AttrDataWriter<'a, 'b, 'c> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.tw
    }
}

pub struct AttrData<'a> {
    for_dataver: Option<u32>,
    data: &'a TLVElement<'a>,
}

impl<'a> AttrData<'a> {
    pub fn new(for_dataver: Option<u32>, data: &'a TLVElement<'a>) -> Self {
        Self { for_dataver, data }
    }

    pub fn with_dataver(self, dataver: u32) -> Result<&'a TLVElement<'a>, Error> {
        if let Some(req_dataver) = self.for_dataver {
            if req_dataver != dataver {
                Err(ErrorCode::DataVersionMismatch)?;
            }
        }

        Ok(self.data)
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
    pub fn handle<T: Handler>(
        item: Result<(CmdDetails, TLVElement), CmdStatus>,
        handler: &mut T,
        transaction: &mut Transaction,
        tw: &mut TLVWriter,
    ) -> Result<(), Error> {
        let status = match item {
            Ok((cmd, data)) => {
                let mut tracker = CmdDataTracker::new();
                let encoder = CmdDataEncoder::new(&cmd, &mut tracker, tw);

                match handler.invoke(transaction, &cmd, &data, encoder) {
                    Ok(()) => cmd.success(&tracker),
                    Err(error) => {
                        error!("Error invoking command: {}", error);
                        cmd.status(error.into())
                    }
                }
            }
            Err(status) => {
                error!("Error invoking command: {:?}", status);
                Some(status)
            }
        };

        if let Some(status) = status {
            InvResp::Status(status).to_tlv(tw, TagType::Anonymous)?;
        }

        Ok(())
    }

    #[cfg(feature = "nightly")]
    pub async fn handle_async<T: super::asynch::AsyncHandler>(
        item: Result<(CmdDetails<'_>, TLVElement<'_>), CmdStatus>,
        handler: &mut T,
        transaction: &mut Transaction<'_, '_>,
        tw: &mut TLVWriter<'_, '_>,
    ) -> Result<(), Error> {
        let status = match item {
            Ok((cmd, data)) => {
                let mut tracker = CmdDataTracker::new();
                let encoder = CmdDataEncoder::new(&cmd, &mut tracker, tw);

                match handler.invoke(transaction, &cmd, &data, encoder).await {
                    Ok(()) => cmd.success(&tracker),
                    Err(error) => cmd.status(error.into()),
                }
            }
            Err(status) => Some(status),
        };

        if let Some(status) = status {
            InvResp::Status(status).to_tlv(tw, TagType::Anonymous)?;
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

    pub fn with_command(mut self, cmd: u16) -> Result<CmdDataWriter<'a, 'b, 'c>, Error> {
        let mut writer = CmdDataWriter::new(self.tracker, self.tw);

        writer.start_struct(TagType::Anonymous)?;
        writer.start_struct(TagType::Context(InvRespTag::Cmd as _))?;

        self.path.path.leaf = Some(cmd as _);
        self.path
            .to_tlv(&mut writer, TagType::Context(CmdDataTag::Path as _))?;

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

    pub fn set<T: ToTLV>(self, value: T) -> Result<(), Error> {
        value.to_tlv(self.tw, Self::TAG)?;
        self.complete()
    }

    pub fn complete(mut self) -> Result<(), Error> {
        self.tw.end_container()?;
        self.tw.end_container()?;

        self.completed = true;
        self.tracker.complete();

        Ok(())
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}

impl<'a, 'b, 'c> Drop for CmdDataWriter<'a, 'b, 'c> {
    fn drop(&mut self) {
        if !self.completed {
            self.reset();
        }
    }
}

impl<'a, 'b, 'c> Deref for CmdDataWriter<'a, 'b, 'c> {
    type Target = TLVWriter<'b, 'c>;

    fn deref(&self) -> &Self::Target {
        self.tw
    }
}

impl<'a, 'b, 'c> DerefMut for CmdDataWriter<'a, 'b, 'c> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.tw
    }
}

#[derive(Copy, Clone, Debug)]
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
pub struct AttrUtfType;

impl AttrUtfType {
    pub const fn new() -> Self {
        Self
    }

    pub fn encode(&self, writer: AttrDataWriter, value: &str) -> Result<(), Error> {
        writer.set(UtfStr::new(value.as_bytes()))
    }

    pub fn decode<'a>(&self, data: &'a TLVElement) -> Result<&'a str, IMStatusCode> {
        data.str().map_err(|_| IMStatusCode::InvalidDataType)
    }
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! attribute_enum {
    ($en:ty) => {
        impl core::convert::TryFrom<$crate::data_model::objects::AttrId> for $en {
            type Error = $crate::error::Error;

            fn try_from(id: $crate::data_model::objects::AttrId) -> Result<Self, Self::Error> {
                <$en>::from_repr(id)
                    .ok_or_else(|| $crate::error::ErrorCode::AttributeNotFound.into())
            }
        }
    };
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! command_enum {
    ($en:ty) => {
        impl core::convert::TryFrom<$crate::data_model::objects::CmdId> for $en {
            type Error = $crate::error::Error;

            fn try_from(id: $crate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
                <$en>::from_repr(id).ok_or_else(|| $crate::error::ErrorCode::CommandNotFound.into())
            }
        }
    };
}
