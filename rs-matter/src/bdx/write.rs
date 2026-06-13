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

//! The *send* side of the BDX streaming engine: the [`BdxWriter`] handle and the
//! two ways to obtain one - [`BdxPush`] (initiate an upload) and
//! [`BdxPullResponder`] (respond to a peer's download).

use super::nego::*;
use super::*;

/// A writer over a BDX transfer - the Sender side.
///
/// Obtained from [`Exchange::push`](BdxPush::push) on the initiating side, or
/// from [`BdxPullResponder::reply`] on the responding side. [`write`](Self::write)
/// stages and sends the data, driving the protocol as needed;
/// [`finish`](Self::finish) flushes the final block and completes the transfer.
/// It also implements [`embedded_io_async::Write`] (delegating to the inherent
/// `write`).
///
/// The caller supplies the staging buffer `buf`, which doubles as the upper bound
/// on the block size (so there is no hidden, MCU-unfriendly internal allocation).
/// It must be non-empty.
pub struct BdxWriter<'a, 'b> {
    exchange: Exchange<'a>,
    drive: Drive,
    /// The caller-provided staging buffer. At most `max_block_size` of its bytes
    /// hold the block currently being assembled.
    buf: &'b mut [u8],
    max_block_size: usize,
    /// Driver: the counter for the next block to send. Follower: the expected
    /// counter of the next `BlockQuery`.
    counter: u32,
    block_len: usize,
}

impl<'a, 'b> BdxWriter<'a, 'b> {
    pub(super) fn new(
        exchange: Exchange<'a>,
        drive: Drive,
        buf: &'b mut [u8],
        max_block_size: u16,
    ) -> Self {
        // We can never stage more than the buffer holds; negotiation already
        // bounded `max_block_size`, but clamp defensively.
        let max_block_size = (max_block_size as usize).min(buf.len());

        Self {
            exchange,
            drive,
            buf,
            max_block_size,
            counter: 0,
            block_len: 0,
        }
    }

    /// Stage and send `data`, returning the number of bytes accepted (`< data.len()`
    /// only when the current block fills; call again with the remainder).
    ///
    /// This is also the [`embedded_io_async::Write`] implementation; the inherent
    /// method is kept so callers need not import the trait.
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        if data.is_empty() {
            return Ok(0);
        }

        let space = self.max_block_size - self.block_len;
        let n = space.min(data.len());
        self.buf[self.block_len..self.block_len + n].copy_from_slice(&data[..n]);
        self.block_len += n;

        if self.block_len == self.max_block_size {
            self.send_block(false).await?;
        }

        Ok(n)
    }

    /// Flush the final (possibly empty) block and complete the transfer.
    pub async fn finish(mut self) -> Result<(), Error> {
        self.send_block(true).await?;

        self.exchange.acknowledge().await
    }

    /// Send the staged bytes as one block, driving/awaiting acknowledgement per
    /// the negotiated drive mode.
    async fn send_block(&mut self, is_eof: bool) -> Result<(), Error> {
        let counter = self.counter;

        if matches!(self.drive, Drive::Follower) {
            // Receiver-driven: wait to be asked for this block.
            self.recv_control(OpCode::BlockQuery, counter).await?;
        }

        let opcode = if is_eof {
            OpCode::BlockEof
        } else {
            OpCode::Block
        };
        let len = self.block_len;
        {
            let data = &self.buf[..len];
            self.exchange
                .send_with(|_, wb| {
                    Block {
                        block_counter: counter,
                        data,
                    }
                    .write(wb)?;
                    Ok(Some(opcode.into()))
                })
                .await?;
        }
        self.block_len = 0;

        if matches!(self.drive, Drive::Driver) {
            let ack = if is_eof {
                OpCode::BlockAckEof
            } else {
                OpCode::BlockAck
            };
            self.recv_control(ack, counter).await?;
        } else if is_eof {
            // Receiver-driven: the receiver acknowledges the final block.
            self.recv_control(OpCode::BlockAckEof, counter).await?;
        }

        self.counter = self.counter.wrapping_add(1);

        Ok(())
    }

    /// Await a specific counter-only control message and validate its counter.
    async fn recv_control(&mut self, expected: OpCode, expected_counter: u32) -> Result<(), Error> {
        enum Outcome {
            Ok,
            BadCounter,
            Unexpected,
            Aborted(Error),
        }

        self.exchange.recv_fetch().await?;
        let meta = self.exchange.rx()?.meta();
        let outcome = {
            let payload = self.exchange.rx()?.payload();
            match classify(&meta) {
                Ok(op) if op == expected => {
                    if BlockQuery::parse(payload)?.block_counter == expected_counter {
                        Outcome::Ok
                    } else {
                        Outcome::BadCounter
                    }
                }
                Ok(_) => Outcome::Unexpected,
                Err(e) => Outcome::Aborted(e),
            }
        };

        self.exchange.rx_done()?;

        match outcome {
            Outcome::Ok => Ok(()),
            Outcome::BadCounter => abort(&mut self.exchange, BdxStatus::BadBlockCounter).await,
            Outcome::Unexpected => abort(&mut self.exchange, BdxStatus::UnexpectedMessage).await,
            Outcome::Aborted(e) => Err(e),
        }
    }
}

impl embedded_io_async::ErrorType for BdxWriter<'_, '_> {
    type Error = Error;
}

impl embedded_io_async::Write for BdxWriter<'_, '_> {
    async fn write(&mut self, data: &[u8]) -> Result<usize, Self::Error> {
        BdxWriter::write(self, data).await
    }

    /// Send any staged-but-unsent bytes as a (non-final) block.
    async fn flush(&mut self) -> Result<(), Self::Error> {
        if self.block_len > 0 {
            self.send_block(false).await?;
        }

        Ok(())
    }
}

/// An extension trait for initiating a BDX *upload*: `push` makes this node the
/// (typically driving) Sender and returns a [`BdxWriter`].
pub trait BdxPush<'a> {
    /// Initiate a BDX upload of `file_designator`, negotiate the transfer, and
    /// return a writer ready to stream the data. `buf` is the (non-empty) staging
    /// buffer the writer assembles blocks in; its length bounds the block size.
    async fn push<'b>(
        self,
        buf: &'b mut [u8],
        file_designator: &[u8],
    ) -> Result<BdxWriter<'a, 'b>, Error>;
}

impl<'a> BdxPush<'a> for Exchange<'a> {
    async fn push<'b>(
        mut self,
        buf: &'b mut [u8],
        file_designator: &[u8],
    ) -> Result<BdxWriter<'a, 'b>, Error> {
        // We can never send a block larger than our staging buffer or our TX buffer.
        let pmbs = buf.len().min(MAX_TX_BLOCK_SIZE as usize) as u16;
        send_init(&mut self, OpCode::SendInit, pmbs, file_designator).await?;

        match recv_accept(&mut self, false).await? {
            // We are the sender: we drive iff sender-drive was selected.
            Some((tc, mbs, _length)) => {
                let drive = if tc.sender_drive {
                    Drive::Driver
                } else {
                    Drive::Follower
                };
                Ok(BdxWriter::new(self, drive, buf, mbs))
            }
            None => abort(&mut self, BdxStatus::TransferMethodNotSupported).await,
        }
    }
}

/// The responding side of a [`pull`](super::BdxPull::pull): a peer requested a
/// download (sent a `ReceiveInit`), so this node becomes the Sender. Inspect the
/// request via [`fd`](Self::fd), then [`reply`](Self::reply) to obtain a
/// [`BdxWriter`], or [`reject`](Self::reject) it.
pub struct BdxPullResponder<'a> {
    exchange: Exchange<'a>,
    transfer_control: TransferControl,
    max_block_size: u16,
}

impl<'a> BdxPullResponder<'a> {
    /// Receive the incoming `ReceiveInit` on `exchange`, holding it until
    /// [`reply`](Self::reply)/[`reject`](Self::reject).
    pub async fn accept(mut exchange: Exchange<'a>) -> Result<Self, Error> {
        let (transfer_control, max_block_size, _length) =
            recv_init_hold(&mut exchange, OpCode::ReceiveInit).await?;

        Ok(Self {
            exchange,
            transfer_control,
            max_block_size,
        })
    }

    /// The file designator the initiator requested (borrowed from the held init).
    pub fn fd(&self) -> &[u8] {
        held_fd(&self.exchange)
    }

    /// Accept the transfer and start sending, staging blocks in the (non-empty)
    /// caller-provided buffer `buf` (its length bounds the block size). `length`
    /// advertises a definite transfer length (enabling the receiver's progress
    /// reporting) when known.
    pub async fn reply<'b>(
        mut self,
        buf: &'b mut [u8],
        length: Option<u64>,
    ) -> Result<BdxWriter<'a, 'b>, Error> {
        // Prefer to let the initiating receiver drive (its `BdxReader` is the
        // "driving receiver"); otherwise drive ourselves.
        let tc = self.transfer_control;
        let drive = if tc.receiver_drive {
            Drive::Follower
        } else if tc.sender_drive {
            Drive::Driver
        } else {
            self.exchange.rx_done()?;
            return abort(&mut self.exchange, BdxStatus::TransferMethodNotSupported).await;
        };

        // Cap the receiver's proposed block size by our staging buffer and TX buffer.
        let cap = buf.len().min(MAX_TX_BLOCK_SIZE as usize) as u16;
        let mbs = self.max_block_size.clamp(1, cap);

        self.exchange.rx_done()?;

        send_accept(
            &mut self.exchange,
            true,
            TransferControl::select(drive == Drive::Driver),
            mbs,
            length,
        )
        .await?;

        Ok(BdxWriter::new(self.exchange, drive, buf, mbs))
    }

    /// Reject the transfer with the given status (e.g. `FileDesignatorUnknown`).
    pub async fn reject(mut self, status: BdxStatus) -> Result<(), Error> {
        self.exchange.rx_done()?;
        send_status_report(&mut self.exchange, status).await
    }
}
