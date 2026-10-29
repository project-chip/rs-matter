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

//! The identifiers of the Bulk Data Exchange (BDX) protocol. The protocol itself
//! is in `rs-matter-bdx`, which re-exports these.
//!
//! They are here because the transport logs the opcodes of the messages it
//! handles, like it does for the other protocols. A `rs-matter-bdx-core` crate would
//! contain only these.

use num_derive::FromPrimitive;

use crate::exchange::MessageMeta;

/// The Matter protocol id for BDX.
pub const PROTO_ID_BDX: u16 = 0x0002;

/// The BDX protocol message opcodes.
#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum OpCode {
    /// Initiator wants to be the Sender (upload).
    SendInit = 0x01,
    /// Responder accepts a `SendInit`.
    SendAccept = 0x02,
    /// Initiator wants to be the Receiver (download).
    ReceiveInit = 0x04,
    /// Responder accepts a `ReceiveInit`.
    ReceiveAccept = 0x05,
    /// Driving Receiver requests the next block.
    BlockQuery = 0x10,
    /// A block of data.
    Block = 0x11,
    /// The final block of a transfer (may be empty).
    BlockEof = 0x12,
    /// Acknowledges a received `Block`.
    BlockAck = 0x13,
    /// Acknowledges a received `BlockEof`; ends the session.
    BlockAckEof = 0x14,
    /// Like `BlockQuery`, but advances the sender's cursor first.
    BlockQueryWithSkip = 0x15,
}

impl OpCode {
    /// The [`MessageMeta`] for this opcode. All BDX messages are reliable: BDX
    /// runs only over reliable transports and uses MRP over UDP.
    pub fn meta(self) -> MessageMeta {
        MessageMeta {
            proto_id: PROTO_ID_BDX,
            proto_opcode: self as u8,
            reliable: true,
        }
    }
}

impl From<OpCode> for MessageMeta {
    fn from(op: OpCode) -> Self {
        op.meta()
    }
}
