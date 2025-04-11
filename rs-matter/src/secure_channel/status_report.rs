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

use num_derive::FromPrimitive;

use crate::{
    error::{Error, ErrorCode},
    utils::storage::{ParseBuf, WriteBuf},
};

#[allow(dead_code)]
#[derive(FromPrimitive, PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GeneralCode {
    Success = 0,
    Failure = 1,
    BadPrecondition = 2,
    OutOfRange = 3,
    BadRequest = 4,
    Unsupported = 5,
    Unexpected = 6,
    ResourceExhausted = 7,
    Busy = 8,
    Timeout = 9,
    Continue = 10,
    Aborted = 11,
    InvalidArgument = 12,
    NotFound = 13,
    AlreadyExists = 14,
    PermissionDenied = 15,
    DataLoss = 16,
}

/// Represents a Status Report message, as per "Appendix D: Status Report Messages" of the Matter Spec.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StatusReport<'a> {
    pub general_code: GeneralCode,
    pub proto_id: u32,
    pub proto_code: u16,
    pub proto_data: &'a [u8],
}

impl<'a> StatusReport<'a> {
    pub fn read(pb: &'a mut ParseBuf) -> Result<Self, Error> {
        Ok(Self {
            general_code: num::FromPrimitive::from_u16(pb.le_u16()?)
                .ok_or(ErrorCode::InvalidOpcode)?,
            proto_id: pb.le_u32()?,
            proto_code: pb.le_u16()?,
            proto_data: pb.as_slice(),
        })
    }

    pub fn write(&self, wb: &mut WriteBuf) -> Result<(), Error> {
        wb.le_u16(self.general_code as u16)?;
        wb.le_u32(self.proto_id)?;
        wb.le_u16(self.proto_code)?;
        wb.copy_from_slice(self.proto_data)?;

        Ok(())
    }
}
