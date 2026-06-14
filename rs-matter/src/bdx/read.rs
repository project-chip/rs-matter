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

//! The *receive* side of the BDX streaming engine: the [`BdxReader`] handle and
//! the two ways to obtain one - [`BdxPull`] (initiate a download) and
//! [`BdxPushResponder`] (respond to a peer's upload).

use super::nego::*;
use super::*;

/// A reader over a BDX transfer - the Receiver side.
///
/// Obtained from [`Exchange::pull`](BdxPull::pull) on the initiating side, or
/// from [`BdxPushResponder::reply`] on the responding side. [`read`](Self::read)
/// drives the protocol as needed and copies the next bytes of the transfer into
/// the caller's buffer, returning `0` at the end of the transfer. It also
/// implements [`embedded_io_async::Read`] (delegating to the inherent method).
pub struct BdxReader<'a> {
    exchange: Exchange<'a>,
    drive: Drive,
    /// The negotiated definite length of the transfer, if the sender committed
    /// to one.
    len: Option<u64>,
    /// Driver: the counter to put in the next `BlockQuery`. Follower: the
    /// expected counter of the next incoming block.
    counter: u32,
    /// The counter of the block currently held in the exchange RX buffer.
    held_counter: u32,
    /// Whether the held block is the final (`BlockEof`) block.
    held_eof: bool,
    /// How many bytes of the held block's data have been consumed.
    block_pos: usize,
    /// Whether a (partially consumed) block is held in the exchange RX buffer.
    holding: bool,
    /// Whether the transfer has completed.
    finished: bool,
}

impl<'a> BdxReader<'a> {
    pub(super) const fn new(exchange: Exchange<'a>, drive: Drive, len: Option<u64>) -> Self {
        Self {
            exchange,
            drive,
            len,
            counter: 0,
            held_counter: 0,
            held_eof: false,
            block_pos: 0,
            holding: false,
            finished: false,
        }
    }

    /// The total length of the transfer in bytes, if the sender committed to a
    /// definite length during negotiation (`None` for an indefinite transfer).
    #[allow(clippy::len_without_is_empty)] // A transfer length, not a collection count.
    pub fn len(&self) -> Option<u64> {
        self.len
    }

    /// Read the next bytes of the transfer into `buf`, returning the number of
    /// bytes read. Returns `0` once the whole transfer has been received.
    ///
    /// This is also the [`embedded_io_async::Read`] implementation; the inherent
    /// method is kept so callers need not import the trait.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            if self.finished {
                return Ok(0);
            }

            if self.holding {
                // Serve from the block held in the exchange RX buffer.
                let n = {
                    let payload = self.exchange.rx()?.payload();
                    let data = &payload[BLOCK_HEADER_LEN..];
                    if self.block_pos < data.len() {
                        let remaining = &data[self.block_pos..];
                        let n = remaining.len().min(buf.len());
                        buf[..n].copy_from_slice(&remaining[..n]);
                        Some(n)
                    } else {
                        None
                    }
                };

                if let Some(n) = n {
                    self.block_pos += n;
                    return Ok(n);
                }

                // The held block is fully consumed - acknowledge / advance.
                self.release_block().await?;
                continue;
            }

            // Nothing held and not finished: fetch the next block.
            self.receive_block().await?;
        }
    }

    /// Obtain the next block, holding it in the exchange RX buffer.
    async fn receive_block(&mut self) -> Result<(), Error> {
        enum Outcome {
            Ok(bool),
            BadCounter,
            Unexpected,
            Aborted(Error),
        }

        if matches!(self.drive, Drive::Driver) {
            // Request the next block (this also acknowledges the previous one).
            self.send_control(OpCode::BlockQuery, self.counter).await?;
        }

        self.exchange.recv_fetch().await?;
        let meta = self.exchange.rx()?.meta();
        let outcome = {
            let payload = self.exchange.rx()?.payload();
            match classify(&meta, payload) {
                Ok(op) if matches!(op, OpCode::Block | OpCode::BlockEof) => {
                    let block = Block::parse(payload)?;
                    if block.block_counter != self.counter {
                        Outcome::BadCounter
                    } else {
                        Outcome::Ok(op == OpCode::BlockEof)
                    }
                }
                Ok(_) => Outcome::Unexpected,
                Err(e) => Outcome::Aborted(e),
            }
        };

        match outcome {
            Outcome::Ok(is_eof) => {
                // Keep the block held; `read` serves its data directly from RX.
                self.held_counter = self.counter;
                self.held_eof = is_eof;
                self.counter = self.counter.wrapping_add(1);
                self.block_pos = 0;
                self.holding = true;
                Ok(())
            }
            Outcome::BadCounter => {
                self.exchange.rx_done()?;
                abort(&mut self.exchange, BdxStatus::BadBlockCounter).await
            }
            Outcome::Unexpected => {
                self.exchange.rx_done()?;
                abort(&mut self.exchange, BdxStatus::UnexpectedMessage).await
            }
            Outcome::Aborted(e) => {
                self.exchange.rx_done()?;
                Err(e)
            }
        }
    }

    /// Acknowledge the consumed block and release the RX buffer, finalizing the
    /// transfer if it was the last block.
    async fn release_block(&mut self) -> Result<(), Error> {
        let counter = self.held_counter;

        if self.held_eof {
            self.send_control(OpCode::BlockAckEof, counter).await?;
            self.exchange.rx_done()?;
            self.exchange.acknowledge().await?;
            self.finished = true;
        } else if matches!(self.drive, Drive::Follower) {
            // Sender-driven: acknowledge so the next block is sent.
            self.send_control(OpCode::BlockAck, counter).await?;
            self.exchange.rx_done()?;
        } else {
            // Receiver-driven: the next `BlockQuery` is the acknowledgement.
            self.exchange.rx_done()?;
        }

        self.holding = false;

        Ok(())
    }

    /// Send a counter-only control message (`BlockQuery`/`BlockAck`/`BlockAckEof`).
    async fn send_control(&mut self, opcode: OpCode, counter: u32) -> Result<(), Error> {
        self.exchange
            .send_with(|_, wb| {
                BlockQuery {
                    block_counter: counter,
                }
                .write(wb)?;
                Ok(Some(opcode.into()))
            })
            .await
    }
}

impl embedded_io_async::ErrorType for BdxReader<'_> {
    type Error = Error;
}

impl embedded_io_async::Read for BdxReader<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        BdxReader::read(self, buf).await
    }
}

/// An extension trait for initiating a BDX *download*: `pull` makes this node the
/// (typically driving) Receiver and returns a [`BdxReader`].
pub trait BdxPull<'a> {
    /// Initiate a BDX download of `file_designator`, negotiate the transfer, and
    /// return a reader positioned at the start of the data.
    async fn pull(self, file_designator: &[u8]) -> Result<BdxReader<'a>, Error>;
}

impl<'a> BdxPull<'a> for Exchange<'a> {
    async fn pull(mut self, file_designator: &[u8]) -> Result<BdxReader<'a>, Error> {
        // We stream blocks straight out of the exchange RX buffer, so we propose
        // the largest block that buffer can hold.
        send_init(
            &mut self,
            OpCode::ReceiveInit,
            MAX_RX_BLOCK_SIZE,
            file_designator,
        )
        .await?;

        match recv_accept(&mut self, true).await? {
            // We are the receiver: we drive iff receiver-drive was selected.
            Some((tc, _mbs, length)) => {
                let drive = if tc.receiver_drive {
                    Drive::Driver
                } else {
                    Drive::Follower
                };
                Ok(BdxReader::new(self, drive, length))
            }
            None => abort(&mut self, BdxStatus::TransferMethodNotSupported).await,
        }
    }
}

/// The responding side of a [`push`](super::BdxPush::push): a peer requested an
/// upload (sent a `SendInit`), so this node becomes the Receiver. Inspect the
/// request via [`fd`](Self::fd)/[`len`](Self::len), then [`reply`](Self::reply)
/// to obtain a [`BdxReader`], or [`reject`](Self::reject) it.
pub struct BdxPushResponder<'a> {
    exchange: Exchange<'a>,
    transfer_control: TransferControl,
    max_block_size: u16,
    length: Option<u64>,
}

impl<'a> BdxPushResponder<'a> {
    /// Receive the incoming `SendInit` on `exchange`, holding it until
    /// [`reply`](Self::reply)/[`reject`](Self::reject).
    pub async fn accept(mut exchange: Exchange<'a>) -> Result<Self, Error> {
        let (transfer_control, max_block_size, length) =
            recv_init_hold(&mut exchange, OpCode::SendInit).await?;

        Ok(Self {
            exchange,
            transfer_control,
            max_block_size,
            length,
        })
    }

    /// The file designator the initiator is sending (borrowed from the held init).
    pub fn fd(&self) -> &[u8] {
        held_fd(&self.exchange)
    }

    /// The definite length the initiator committed to, if any.
    #[allow(clippy::len_without_is_empty)] // A transfer length, not a collection count.
    pub fn len(&self) -> Option<u64> {
        self.length
    }

    /// Accept the transfer and start receiving, returning a [`BdxReader`].
    pub async fn reply(mut self) -> Result<BdxReader<'a>, Error> {
        // Prefer to let the initiating sender drive (its `BdxWriter` is the
        // "driving sender"); otherwise drive ourselves.
        let tc = self.transfer_control;
        let drive = if tc.sender_drive {
            Drive::Follower
        } else if tc.receiver_drive {
            Drive::Driver
        } else {
            self.exchange.rx_done()?;
            return abort(&mut self.exchange, BdxStatus::TransferMethodNotSupported).await;
        };

        // Cap the sender's proposed block size by what our RX buffer can hold.
        let mbs = self.max_block_size.clamp(1, MAX_RX_BLOCK_SIZE);
        let length = self.length;

        self.exchange.rx_done()?;

        // A `SendAccept` carries no length; the receiver learned it from the `SendInit`.
        send_accept(
            &mut self.exchange,
            false,
            TransferControl::select(drive == Drive::Follower),
            mbs,
            None,
        )
        .await?;

        Ok(BdxReader::new(self.exchange, drive, length))
    }

    /// Reject the transfer with the given status.
    pub async fn reject(mut self, status: BdxStatus) -> Result<(), Error> {
        self.exchange.rx_done()?;
        send_status_report(&mut self.exchange, status).await
    }
}
