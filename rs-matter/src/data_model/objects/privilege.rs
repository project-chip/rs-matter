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
    error::{Error, ErrorCode},
    tlv::{FromTLV, TLVElement, TLVTag, TLVWrite, ToTLV, TLV},
};
use log::error;

use bitflags::bitflags;

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Privilege: u8 {
        const V = 0x01;
        const O = 0x02;
        const M = 0x04;
        const A = 0x08;

        const VIEW = Self::V.bits();
        const OPERATE = Self::V.bits() | Self::O.bits();
        const MANAGE = Self::V.bits() | Self::O.bits() | Self::M.bits();
        const ADMIN = Self::V.bits() | Self::O.bits() | Self::M.bits() | Self::A.bits();
    }
}

impl Privilege {
    pub fn raw_value(&self) -> u8 {
        if self.contains(Privilege::ADMIN) {
            5
        } else if self.contains(Privilege::OPERATE) {
            4
        } else if self.contains(Privilege::MANAGE) {
            3
        } else if self.contains(Privilege::VIEW) {
            1
        } else {
            0
        }
    }
}

impl FromTLV<'_> for Privilege {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error>
    where
        Self: Sized,
    {
        match t.u32()? {
            1 => Ok(Privilege::VIEW),
            2 => {
                error!("ProxyView privilege not yet supporteds");
                Err(ErrorCode::Invalid.into())
            }
            3 => Ok(Privilege::OPERATE),
            4 => Ok(Privilege::MANAGE),
            5 => Ok(Privilege::ADMIN),
            _ => Err(ErrorCode::Invalid.into()),
        }
    }
}

impl ToTLV for Privilege {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.u8(tag, self.raw_value())
    }

    fn tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<TLV, Error>> {
        TLV::u8(tag, self.raw_value()).into_tlv_iter()
    }
}
