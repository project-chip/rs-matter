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

//! Negotiation and framing helpers shared by the [`read`](super::read) and
//! [`write`](super::write) submodules: classifying incoming messages, sending
//! `*Init`/`*Accept`/`StatusReport` messages, and awaiting them. The parent
//! `bdx` module only declares this module; it does not use it directly.

use super::*;

/// Map the meta + payload of a freshly received transfer message to a BDX
/// opcode. A Secure Channel `StatusReport` means the peer aborted the transfer
/// (mapped to an error); anything else is a protocol violation.
pub(super) fn classify(meta: &MessageMeta, payload: &[u8]) -> Result<OpCode, Error> {
    if meta.proto_id == PROTO_ID_BDX {
        return opcode(meta).ok_or_else(|| ErrorCode::InvalidOpcode.into());
    }

    if meta.proto_id == sc::PROTO_ID_SECURE_CHANNEL
        && meta.proto_opcode == sc::OpCode::StatusReport as u8
    {
        // A `StatusReport` ends the transfer. Its message header is always
        // Secure-Channel framed (Matter Core spec, Appendix D.2); a BDX-level
        // abort additionally names the BDX protocol in the report *body* (per the
        // BDX spec). Inspect the body for diagnostics - the outcome (abort) is the
        // same regardless of what it carries.
        let mut rb = ReadBuf::new(payload);
        match StatusReport::read(&mut rb) {
            Ok(report) if report.proto_id == PROTO_ID_BDX as u32 => {
                error!(
                    "BDX: peer aborted the transfer (BDX status 0x{:04x})",
                    report.proto_code
                );
            }
            Ok(report) => {
                error!(
                    "BDX: transfer ended by a non-BDX StatusReport (protocol 0x{:08x}, code 0x{:04x})",
                    report.proto_id, report.proto_code
                );
            }
            Err(_) => {
                error!("BDX: peer aborted the transfer with a malformed StatusReport");
            }
        }

        return Err(ErrorCode::Invalid.into());
    }

    Err(ErrorCode::InvalidProto.into())
}

/// Send a BDX failure `StatusReport` (a Secure Channel `StatusReport` naming the
/// BDX protocol).
pub(super) async fn send_status_report(
    exchange: &mut Exchange<'_>,
    status: BdxStatus,
) -> Result<(), Error> {
    exchange
        .send_with(|_, wb| {
            status.as_report().write(wb)?;
            Ok(Some(sc::OpCode::StatusReport.meta()))
        })
        .await
}

/// Send a BDX failure `StatusReport` and return an error, aborting the transfer.
pub(super) async fn abort<T>(exchange: &mut Exchange<'_>, status: BdxStatus) -> Result<T, Error> {
    warn!("BDX: aborting the transfer ({:?})", status);

    send_status_report(exchange, status).await?;

    Err(ErrorCode::Invalid.into())
}

/// Build the streaming `*Init` proposal (both drive modes, indefinite length).
/// `max_block_size` is the largest block this node is willing to handle.
pub(super) async fn send_init(
    exchange: &mut Exchange<'_>,
    opcode: OpCode,
    max_block_size: u16,
    file_designator: &[u8],
) -> Result<(), Error> {
    let init = TransferInit {
        transfer_control: TransferControl {
            version: BDX_VERSION,
            sender_drive: true,
            receiver_drive: true,
            async_mode: false,
        },
        range_control: RangeControl::default(),
        max_block_size,
        start_offset: 0,
        length: 0,
        file_designator,
        metadata: &[],
    };

    exchange
        .send_with(|_, wb| {
            init.write(wb)?;
            Ok(Some(opcode.into()))
        })
        .await
}

/// Send a streaming `*Accept` selecting the transfer control + block size, and
/// (for a `ReceiveAccept`) advertising the definite `length` if known.
pub(super) async fn send_accept(
    exchange: &mut Exchange<'_>,
    receive: bool,
    transfer_control: TransferControl,
    max_block_size: u16,
    length: Option<u64>,
) -> Result<(), Error> {
    let accept = TransferAccept {
        receive,
        transfer_control,
        // Only a `ReceiveAccept` carries range control + length.
        range_control: RangeControl {
            def_len: receive && length.is_some(),
            start_offset: false,
            wide_range: length.is_some_and(|len| len > u32::MAX as u64),
        },
        max_block_size,
        length: length.unwrap_or(0),
        metadata: &[],
    };

    let opcode = if receive {
        OpCode::ReceiveAccept
    } else {
        OpCode::SendAccept
    };

    exchange
        .send_with(|_, wb| {
            accept.write(wb)?;
            Ok(Some(opcode.into()))
        })
        .await
}

/// Await the `*Accept` and return the negotiated transfer control, block size,
/// and definite length (if any), or `None` if no drive mode was selected.
pub(super) async fn recv_accept(
    exchange: &mut Exchange<'_>,
    receive: bool,
) -> Result<Option<(TransferControl, u16, Option<u64>)>, Error> {
    let expected = if receive {
        OpCode::ReceiveAccept
    } else {
        OpCode::SendAccept
    };

    enum Outcome {
        Ok(TransferControl, u16, Option<u64>),
        NoMethod,
        Unexpected,
        Aborted(Error),
    }

    exchange.recv_fetch().await?;
    let meta = exchange.rx()?.meta();
    let outcome = {
        let payload = exchange.rx()?.payload();
        match classify(&meta, payload) {
            Ok(op) if op == expected => {
                let accept = TransferAccept::parse(receive, payload)?;
                let tc = accept.transfer_control;
                if tc.sender_drive || tc.receiver_drive {
                    let length = (accept.range_control.def_len && accept.length > 0)
                        .then_some(accept.length);
                    Outcome::Ok(tc, accept.max_block_size, length)
                } else {
                    Outcome::NoMethod
                }
            }
            Ok(_) => Outcome::Unexpected,
            Err(e) => Outcome::Aborted(e),
        }
    };

    exchange.rx_done()?;

    match outcome {
        Outcome::Ok(tc, mbs, length) => Ok(Some((tc, mbs, length))),
        Outcome::NoMethod => Ok(None),
        Outcome::Unexpected => abort(exchange, BdxStatus::UnexpectedMessage).await,
        Outcome::Aborted(e) => Err(e),
    }
}

/// Await the opening `*Init` and *keep it held* in the exchange RX buffer (so the
/// file designator can be borrowed via [`held_fd`]). Returns the proposed
/// transfer control, block size, and definite length (if any). The caller is
/// responsible for eventually releasing the held message (`rx_done`).
pub(super) async fn recv_init_hold(
    exchange: &mut Exchange<'_>,
    expected: OpCode,
) -> Result<(TransferControl, u16, Option<u64>), Error> {
    enum Outcome {
        Ok(TransferControl, u16, Option<u64>),
        Unexpected,
        Aborted(Error),
    }

    exchange.recv_fetch().await?;
    let meta = exchange.rx()?.meta();
    let outcome = {
        let payload = exchange.rx()?.payload();
        match classify(&meta, payload) {
            Ok(op) if op == expected => {
                let init = TransferInit::parse(payload)?;
                let length = (init.range_control.def_len && init.length > 0).then_some(init.length);
                Outcome::Ok(init.transfer_control, init.max_block_size, length)
            }
            Ok(_) => Outcome::Unexpected,
            Err(e) => Outcome::Aborted(e),
        }
    };

    match outcome {
        // Leave the `*Init` held in RX; `held_fd` borrows its file designator.
        Outcome::Ok(tc, pmbs, length) => Ok((tc, pmbs, length)),
        Outcome::Unexpected => {
            exchange.rx_done()?;
            abort(exchange, BdxStatus::UnexpectedMessage).await
        }
        Outcome::Aborted(e) => {
            exchange.rx_done()?;
            Err(e)
        }
    }
}

/// Borrow the file designator of the `*Init` currently held in the exchange RX
/// buffer (see [`recv_init_hold`]). Empty if nothing valid is held.
pub(super) fn held_fd<'x>(exchange: &'x Exchange<'_>) -> &'x [u8] {
    exchange
        .rx()
        .ok()
        .and_then(|rx| TransferInit::parse(rx.payload()).ok())
        .map(|init| init.file_designator)
        .unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_bdx_opcodes() {
        // BDX opcodes ignore the payload.
        assert_eq!(classify(&OpCode::Block.meta(), &[]).unwrap(), OpCode::Block);
        assert_eq!(
            classify(&OpCode::ReceiveInit.meta(), &[]).unwrap(),
            OpCode::ReceiveInit
        );
    }

    #[test]
    fn classify_rejects_status_report() {
        // A Secure Channel `StatusReport` means the peer aborted.
        let meta = MessageMeta::new(
            sc::PROTO_ID_SECURE_CHANNEL,
            sc::OpCode::StatusReport as u8,
            true,
        );

        // A well-formed BDX-scoped status report body.
        let mut buf = [0u8; 16];
        let mut wb = WriteBuf::new(&mut buf);
        BdxStatus::TransferFailedUnknownError
            .as_report()
            .write(&mut wb)
            .unwrap();
        assert!(classify(&meta, wb.as_slice()).is_err());

        // A malformed/empty body still aborts the transfer.
        assert!(classify(&meta, &[]).is_err());
    }

    #[test]
    fn classify_rejects_other_protocols() {
        assert!(classify(&MessageMeta::new(0x99, 0x01, true), &[]).is_err());
    }

    #[test]
    fn classify_rejects_unknown_bdx_opcode() {
        assert!(classify(&MessageMeta::new(PROTO_ID_BDX, 0x7f, true), &[]).is_err());
    }
}
