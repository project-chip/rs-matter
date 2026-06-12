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

//! End-to-end tests of the BDX engine over a real CASE-secured exchange, each
//! transferring a multi-block image and asserting it arrives byte-for-byte:
//!
//! - the `serve`/`download` sink/source engine, and
//! - the streaming `BdxReader`/`BdxWriter` (`pull`/`push` + `accept`).

#![cfg(all(feature = "std", feature = "async-io"))]

#[allow(dead_code)]
mod common;

use core::future::Future;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use rs_matter::bdx::{self, BdxPull, BdxPush, BdxReader, BdxSink, BdxSource, BdxWriter};
use rs_matter::error::Error;
use rs_matter::respond::ExchangeHandler;
use rs_matter::sc::OpCode as ScOpCode;
use rs_matter::transport::exchange::Exchange;
use rs_matter::utils::select::Coalesce;

use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

const FILE_DESIGNATOR: &[u8] = b"firmware.ota";
const IMAGE_LEN: usize = 5000;
const BLOCK_SIZE: u16 = 256;

fn test_image() -> Vec<u8> {
    (0..IMAGE_LEN).map(|i| (i % 251) as u8).collect()
}

/// A BDX source serving a fixed in-memory image.
struct TestSource {
    image: Vec<u8>,
}

impl BdxSource for TestSource {
    fn begin(&mut self, file_designator: &[u8]) -> Result<(), Error> {
        assert_eq!(file_designator, FILE_DESIGNATOR);
        Ok(())
    }

    fn size(&self) -> Option<u64> {
        Some(self.image.len() as u64)
    }

    async fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let offset = offset as usize;
        if offset >= self.image.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.image.len() - offset);
        buf[..n].copy_from_slice(&self.image[offset..offset + n]);
        Ok(n)
    }
}

/// Device-side exchange handler that serves the image over BDX.
struct ServeHandler {
    image: Vec<u8>,
}

impl ExchangeHandler for ServeHandler {
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let mut block_buf = [0u8; BLOCK_SIZE as usize];
        let mut source = TestSource {
            image: self.image.clone(),
        };

        let sent = bdx::serve(exchange, &mut block_buf, &mut source).await?;
        assert_eq!(sent as usize, IMAGE_LEN);

        Ok(())
    }
}

/// A BDX sink collecting the downloaded bytes (asserting in-order, contiguous).
#[derive(Default)]
struct TestSink {
    received: Vec<u8>,
}

impl BdxSink for TestSink {
    async fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        assert_eq!(offset as usize, self.received.len(), "out-of-order block");
        self.received.extend_from_slice(data);
        Ok(())
    }
}

/// Download a multi-block image over BDX (over a CASE session) and assert it
/// round-trips intact.
#[test]
fn test_bdx_download_over_case() {
    init_env_logger();

    let runner = new_default_runner();
    let image = test_image();
    let handler = ServeHandler {
        image: image.clone(),
    };

    futures_lite::future::block_on(async {
        select(
            // Device side: drives both transports + a BDX serve responder.
            runner.run_responder(handler),
            // Controller side: open an exchange over the CASE session and download.
            async {
                let mut exchange = runner.initiate_exchange().await?;
                let mut sink = TestSink::default();

                let result = select(
                    core::pin::pin!(bdx::download(
                        &mut exchange,
                        FILE_DESIGNATOR,
                        BLOCK_SIZE,
                        &mut sink
                    )),
                    core::pin::pin!(Timer::after(Duration::from_secs(30))),
                )
                .await;

                let total = match result {
                    Either::First(r) => r?,
                    Either::Second(_) => panic!("Timeout waiting for BDX download to complete"),
                };

                assert_eq!(total as usize, image.len());
                assert_eq!(sink.received, image);

                Ok(())
            },
        )
        .coalesce()
        .await
        .unwrap();
    });
}

// ---- Streaming API (`BdxReader` / `BdxWriter`) ----

/// Fail (rather than hang) if a streaming operation doesn't make progress.
async fn with_timeout<F, T>(fut: F) -> Result<T, Error>
where
    F: Future<Output = Result<T, Error>>,
{
    match select(
        core::pin::pin!(fut),
        core::pin::pin!(Timer::after(Duration::from_secs(30))),
    )
    .await
    {
        Either::First(r) => r,
        Either::Second(()) => panic!("BDX streaming operation timed out"),
    }
}

/// Read a whole transfer via `BdxReader`, using a deliberately non-block-aligned
/// buffer to exercise partial-block and cross-block reads.
async fn read_all(reader: &mut BdxReader<'_>) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut buf = [0u8; 300];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// Write a whole buffer via `BdxWriter`, in non-block-aligned chunks (and
/// honoring the partial-accept return of `write`).
async fn write_all(writer: &mut BdxWriter<'_>, mut data: &[u8]) -> Result<(), Error> {
    while !data.is_empty() {
        let n = writer.write(data).await?;
        assert!(n > 0);
        data = &data[n..];
    }
    Ok(())
}

/// Transfer sizes that bracket the streaming block size (1024 B): empty,
/// sub-block, exactly one/two blocks, and the off-by-one neighbours, where the
/// block-buffering and final-`BlockEof` logic is most likely to break.
const STREAM_SIZES: &[usize] = &[0, 1, 1023, 1024, 1025, 2048, 5000];

fn image_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// `pull`: the initiator drives as the Receiver (`BdxReader`), the responder
/// follows as the Sender (`BdxWriter::accept`). Exercises a driving reader and a
/// following writer, across [`STREAM_SIZES`] back-to-back on one session.
#[test]
fn test_bdx_pull_streaming() {
    init_env_logger();

    let runner = new_default_runner();
    let images: Vec<Vec<u8>> = STREAM_SIZES.iter().map(|&n| image_of(n)).collect();

    futures_lite::future::block_on(async {
        // Responder: stream each image as a following sender.
        let device = async {
            for image in &images {
                let exchange = Exchange::accept(&runner.matter).await?;
                let mut writer = BdxWriter::accept(exchange).await?;
                write_all(&mut writer, image).await?;
                writer.finish().await?;
            }
            Ok::<_, Error>(())
        };

        // Initiator: pull and read each transfer, asserting it round-trips.
        let initiator = async {
            for image in &images {
                let exchange = runner.initiate_exchange().await?;
                let mut reader = exchange.pull(FILE_DESIGNATOR).await?;
                let received = with_timeout(read_all(&mut reader)).await?;
                assert_eq!(&received, image, "pull size {}", image.len());
            }
            Ok::<_, Error>(())
        };

        select(runner.run_device(device), initiator)
            .coalesce()
            .await
            .unwrap();
    });
}

/// `push`: the initiator drives as the Sender (`BdxWriter`), the responder
/// follows as the Receiver (`BdxReader::accept`). Exercises a driving writer and
/// a following reader, across [`STREAM_SIZES`] back-to-back on one session.
#[test]
fn test_bdx_push_streaming() {
    init_env_logger();

    let runner = new_default_runner();
    let images: Vec<Vec<u8>> = STREAM_SIZES.iter().map(|&n| image_of(n)).collect();

    futures_lite::future::block_on(async {
        // Responder: read each transfer as a following receiver and assert it.
        let device = async {
            for image in &images {
                let exchange = Exchange::accept(&runner.matter).await?;
                let mut reader = BdxReader::accept(exchange).await?;
                let received = read_all(&mut reader).await?;
                assert_eq!(&received, image, "push size {}", image.len());
            }
            Ok::<_, Error>(())
        };

        // Initiator: push and write each image.
        let initiator = async {
            for image in &images {
                let exchange = runner.initiate_exchange().await?;
                let mut writer = exchange.push(FILE_DESIGNATOR).await?;
                with_timeout(async {
                    write_all(&mut writer, image).await?;
                    writer.finish().await
                })
                .await?;
            }
            Ok::<_, Error>(())
        };

        select(runner.run_device(device), initiator)
            .coalesce()
            .await
            .unwrap();
    });
}

// ---- Abort / error paths (raw "misbehaving" responders) ----

/// Send a BDX failure `StatusReport` (a Secure Channel `StatusReport` whose
/// payload names the BDX protocol).
async fn send_bdx_status(exchange: &mut Exchange<'_>, status: bdx::BdxStatus) -> Result<(), Error> {
    exchange
        .send_with(|_, wb| {
            status.as_report().write(wb)?;
            Ok(Some(ScOpCode::StatusReport.meta()))
        })
        .await
}

/// A responder that rejects the transfer at negotiation: it consumes the opening
/// `*Init` and replies with a `StatusReport` instead of an `*Accept`.
struct RejectInitHandler;

impl ExchangeHandler for RejectInitHandler {
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        exchange.recv_fetch().await?;
        exchange.rx_done()?;
        send_bdx_status(exchange, bdx::BdxStatus::FileDesignatorUnknown).await
    }
}

/// `pull` must surface an error when the responder rejects the transfer with a
/// `StatusReport` during negotiation.
#[test]
fn test_bdx_pull_rejected_at_negotiation() {
    init_env_logger();

    let runner = new_default_runner();

    futures_lite::future::block_on(async {
        select(runner.run_responder(RejectInitHandler), async {
            let exchange = runner.initiate_exchange().await?;
            let result =
                with_timeout(async { exchange.pull(FILE_DESIGNATOR).await.map(|_| ()) }).await;
            assert!(result.is_err(), "pull must fail when the peer rejects it");
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

/// A responder that accepts a pull, sends one block, then aborts mid-stream with
/// a `StatusReport` instead of the next block.
struct AbortMidStreamHandler;

impl ExchangeHandler for AbortMidStreamHandler {
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        // Accept the ReceiveInit as a (driving) sender.
        exchange.recv_fetch().await?;
        exchange.rx_done()?;
        exchange
            .send_with(|_, wb| {
                bdx::TransferAccept {
                    receive: true,
                    transfer_control: bdx::TransferControl {
                        version: bdx::BDX_VERSION,
                        sender_drive: true,
                        receiver_drive: false,
                        async_mode: false,
                    },
                    range_control: bdx::RangeControl::default(),
                    max_block_size: 256,
                    length: 0,
                    metadata: &[],
                }
                .write(wb)?;
                Ok(Some(bdx::OpCode::ReceiveAccept.into()))
            })
            .await?;

        // Send the first block...
        exchange
            .send_with(|_, wb| {
                bdx::Block {
                    block_counter: 0,
                    data: b"abcd",
                }
                .write(wb)?;
                Ok(Some(bdx::OpCode::Block.into()))
            })
            .await?;

        // ...consume its BlockAck, then abort instead of sending the next block.
        exchange.recv_fetch().await?;
        exchange.rx_done()?;
        send_bdx_status(exchange, bdx::BdxStatus::TransferFailedUnknownError).await
    }
}

/// `BdxReader::read` must surface an error when the sender aborts mid-stream
/// (after a valid block has already been delivered).
#[test]
fn test_bdx_read_aborted_mid_stream() {
    init_env_logger();

    let runner = new_default_runner();

    futures_lite::future::block_on(async {
        select(runner.run_responder(AbortMidStreamHandler), async {
            let exchange = runner.initiate_exchange().await?;
            let mut reader = exchange.pull(FILE_DESIGNATOR).await?;

            with_timeout(async {
                let mut buf = [0u8; 64];

                // The first block arrives intact.
                let n = reader.read(&mut buf).await?;
                assert_eq!(&buf[..n], b"abcd");

                // The next read acknowledges block 0, then hits the abort.
                assert!(
                    reader.read(&mut buf).await.is_err(),
                    "read must fail after a mid-stream abort"
                );

                Ok::<_, Error>(())
            })
            .await
        })
        .coalesce()
        .await
        .unwrap();
    });
}
