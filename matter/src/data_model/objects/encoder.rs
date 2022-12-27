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

use std::fmt::{Debug, Formatter};

use crate::{
    error::Error,
    interaction_model::core::IMStatusCode,
    tlv::{FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
};
use log::error;

// TODO: Should this return an IMStatusCode Error? But if yes, the higher layer
// may have already started encoding the 'success' headers, we might not to manage
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
    Value(&'a (dyn ToTLV)),
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
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
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
            EncodeValue::Tlv(_) => (panic!("This looks invalid")),
            EncodeValue::Value(v) => v.to_tlv(tw, tag_type),
        }
    }
}

impl<'a> FromTLV<'a> for EncodeValue<'a> {
    fn from_tlv(data: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(EncodeValue::Tlv(*data))
    }
}

/// An object that can encode EncodeValue into the necessary hierarchical structure
/// as expected by the Interaction Model
pub trait Encoder {
    /// Encode a given value
    fn encode(&mut self, value: EncodeValue);
    /// Encode a status report
    fn encode_status(&mut self, status: IMStatusCode, cluster_status: u16);
}
