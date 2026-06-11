/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

//! Implementation of the Bulk Data Exchange (BDX) protocol, as per the Matter Spec.
//!
//! BDX runs as its own protocol (proto ID `0x0002`) inside ordinary Matter exchanges,
//! alongside Secure Channel ([`crate::sc`]) and the Interaction Model ([`crate::im`]).
//! Unlike most Matter messages, BDX messages are NOT TLV-encoded - they use a bespoke,
//! little-endian binary layout (only the trailing `Metadata` blob is TLV).

use num_derive::FromPrimitive;

use crate::sc::{GeneralCode, StatusReport};
use crate::transport::exchange::MessageMeta;

pub use block::*;
pub use init::*;

mod block;
mod init;

/// BDX Protocol ID, as per the Matter Core Spec.
pub const PROTO_ID_BDX: u16 = 0x02;

/// The BDX protocol version is pinned to 0 per 11.22.5.1 in Matter Core Spec
/// (a bit hidden, it's in the first paragraph about the PTC field)
pub const BDX_VERSION: u8 = 0;

/// BDX message opcodes, as per the Matter Core Spec, 11.22.3.1
#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OpCode {
    SendInit = 0x01,
    SendAccept = 0x02,
    ReceiveInit = 0x04,
    ReceiveAccept = 0x05,
    BlockQuery = 0x10,
    Block = 0x11,
    BlockEOF = 0x12,
    BlockAck = 0x13,
    BlockAckEOF = 0x14,
    BlockQueryWithSkip = 0x15,
}

impl OpCode {
    pub fn meta(&self) -> MessageMeta {
        MessageMeta {
            proto_id: PROTO_ID_BDX,
            proto_opcode: *self as u8,
            // All BDX messages are sent over the reliable (MRP) exchange.
            reliable: true,
        }
    }

    /// BDX messages use a bespoke binary encoding rather than a TLV envelope;
    /// Done like this to be consistent with im.rs and sc.rs.
    pub fn is_tlv(&self) -> bool {
        false
    }
}

impl From<OpCode> for MessageMeta {
    fn from(op: OpCode) -> Self {
        op.meta()
    }
}

/// An enumeration of all possible error codes that can be returned by the BDX protocol.
#[derive(FromPrimitive, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BdxStatusCode {
    LengthTooLarge = 0x0012,
    LengthTooShort = 0x0013,
    LengthMismatch = 0x0014,
    LengthRequired = 0x0015,
    BadMessageContents = 0x0016,
    BadBlockCounter = 0x0017,
    UnexpectedMessage = 0x0018,
    ResponderBusy = 0x0019,
    TransferFailedUnknownError = 0x001F,
    TransferMethodNotSupported = 0x0050,
    FileDesignatorUnknown = 0x0051,
    StartOffsetNotSupported = 0x0052,
    VersionNotSupported = 0x0053,
    Unknown = 0x005F,
}

impl BdxStatusCode {
    /// Build the `StatusReport` that carries this BDX status code.
    pub fn as_report(&self) -> StatusReport<'static> {
        StatusReport {
            // BDX `StatusReport` always denote a failure, see 11.22.3.2 in Core Spec
            general_code: GeneralCode::Failure,
            proto_id: PROTO_ID_BDX as u32,
            proto_code: *self as u16,
            proto_data: &[],
        }
    }
}