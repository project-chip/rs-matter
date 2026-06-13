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
use core::sync::atomic::{AtomicUsize, Ordering};

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use rs_matter::bdx::{
    self, Bdx, BdxPull, BdxPullResponder, BdxPush, BdxPushResponder, BdxReader, BdxServer,
    BdxWriter, ChainedBdxServer, EmptyBdxServer,
};
use rs_matter::error::Error;
use rs_matter::respond::ExchangeHandler;
use rs_matter::sc::OpCode as ScOpCode;
use rs_matter::transport::exchange::Exchange;
use rs_matter::utils::select::Coalesce;

use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

const FILE_DESIGNATOR: &[u8] = b"firmware.ota";

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
async fn write_all(writer: &mut BdxWriter<'_, '_>, mut data: &[u8]) -> Result<(), Error> {
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

/// Responder for the pull test: serves the next image (one per accepted
/// exchange) via [`BdxPullResponder`], advertising a definite length.
struct PullResponder<'a> {
    images: &'a [Vec<u8>],
    next: AtomicUsize,
}

impl ExchangeHandler for PullResponder<'_> {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let image = &self.images[self.next.fetch_add(1, Ordering::Relaxed)];
        let responder = BdxPullResponder::accept(exchange).await?;
        assert_eq!(responder.fd(), FILE_DESIGNATOR);
        let mut wbuf = [0u8; 1024];
        let mut writer = responder.reply(&mut wbuf, Some(image.len() as u64)).await?;
        write_all(&mut writer, image).await?;
        writer.finish().await
    }
}

/// `pull`: the initiator drives as the Receiver (`BdxReader`), the responder
/// follows as the Sender (`BdxPullResponder` -> `BdxWriter`). Exercises a driving
/// reader and a following writer, across [`STREAM_SIZES`] back-to-back on one
/// session.
#[test]
fn test_bdx_pull_streaming() {
    init_env_logger();

    let runner = new_default_runner();
    let images: Vec<Vec<u8>> = STREAM_SIZES.iter().map(|&n| image_of(n)).collect();
    let responder = PullResponder {
        images: &images,
        next: AtomicUsize::new(0),
    };

    futures_lite::future::block_on(async {
        select(runner.run_responder(responder), async {
            for image in &images {
                let exchange = runner.initiate_exchange().await?;
                let mut reader = exchange.pull(FILE_DESIGNATOR).await?;
                let received = with_timeout(read_all(&mut reader)).await?;
                assert_eq!(&received, image, "pull size {}", image.len());
            }
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

/// Responder for the push test: reads the next image (one per accepted exchange)
/// via [`BdxPushResponder`] and asserts it.
struct PushResponder<'a> {
    images: &'a [Vec<u8>],
    next: AtomicUsize,
}

impl ExchangeHandler for PushResponder<'_> {
    async fn handle(&self, exchange: Exchange<'_>) -> Result<(), Error> {
        let image = &self.images[self.next.fetch_add(1, Ordering::Relaxed)];
        let responder = BdxPushResponder::accept(exchange).await?;
        assert_eq!(responder.fd(), FILE_DESIGNATOR);
        let mut reader = responder.reply().await?;
        let received = read_all(&mut reader).await?;
        assert_eq!(&received, image, "push size {}", image.len());
        Ok(())
    }
}

/// `push`: the initiator drives as the Sender (`BdxWriter`), the responder
/// follows as the Receiver (`BdxPushResponder` -> `BdxReader`). Exercises a
/// driving writer and a following reader, across [`STREAM_SIZES`] back-to-back on
/// one session.
#[test]
fn test_bdx_push_streaming() {
    init_env_logger();

    let runner = new_default_runner();
    let images: Vec<Vec<u8>> = STREAM_SIZES.iter().map(|&n| image_of(n)).collect();
    let responder = PushResponder {
        images: &images,
        next: AtomicUsize::new(0),
    };

    futures_lite::future::block_on(async {
        select(runner.run_responder(responder), async {
            for image in &images {
                let exchange = runner.initiate_exchange().await?;
                let mut wbuf = [0u8; 1024];
                let mut writer = exchange.push(&mut wbuf, FILE_DESIGNATOR).await?;
                with_timeout(async {
                    write_all(&mut writer, image).await?;
                    writer.finish().await
                })
                .await?;
            }
            Ok::<_, Error>(())
        })
        .coalesce()
        .await
        .unwrap();
    });
}

// ---- Server routing (`Bdx` / `BdxServer`) ----

const SERVE_FD: &[u8] = b"download.img";
const PROCESS_FD: &[u8] = b"upload.log";

/// A [`BdxServer`] that *serves* (sends) a single image on [`SERVE_FD`].
struct ImageServer {
    image: Vec<u8>,
}

impl BdxServer for ImageServer {
    fn serves(&self, fd: &[u8]) -> bool {
        fd == SERVE_FD
    }

    async fn serve(&self, responder: BdxPullResponder<'_>) -> Result<(), Error> {
        let mut wbuf = [0u8; 512];
        let mut writer = responder
            .reply(&mut wbuf, Some(self.image.len() as u64))
            .await?;
        write_all(&mut writer, &self.image).await?;
        writer.finish().await
    }
}

/// A [`BdxServer`] that *processes* (receives) a single upload on [`PROCESS_FD`],
/// asserting the bytes it receives.
struct LogSink {
    expected: Vec<u8>,
}

impl BdxServer for LogSink {
    fn processes(&self, fd: &[u8]) -> bool {
        fd == PROCESS_FD
    }

    async fn process(&self, responder: BdxPushResponder<'_>) -> Result<(), Error> {
        let mut reader = responder.reply().await?;
        let received = read_all(&mut reader).await?;
        assert_eq!(received, self.expected, "processed upload mismatch");

        Ok(())
    }
}

/// A single [`Bdx`] handler fronts two services on `PROTO_ID_BDX`, dispatched by
/// file designator and direction: a download routes to the (sending) image
/// server, an upload to the (receiving) log sink, and an unknown designator is
/// rejected by the chain terminator.
#[test]
fn test_bdx_server_routing() {
    init_env_logger();

    let runner = new_default_runner();

    let download = image_of(2500);
    let upload = image_of(1500);

    let server = ChainedBdxServer::new(
        ImageServer {
            image: download.clone(),
        },
        ChainedBdxServer::new(
            LogSink {
                expected: upload.clone(),
            },
            EmptyBdxServer,
        ),
    );
    let bdx = Bdx::new(server);

    futures_lite::future::block_on(async {
        select(runner.run_responder(bdx), async {
            // A download routes to the image server.
            let exchange = runner.initiate_exchange().await?;
            let mut reader = exchange.pull(SERVE_FD).await?;
            let received = with_timeout(read_all(&mut reader)).await?;
            assert_eq!(received, download);

            // An upload routes to the log sink (which asserts the payload).
            let exchange = runner.initiate_exchange().await?;
            let mut wbuf = [0u8; 512];
            let mut writer = exchange.push(&mut wbuf, PROCESS_FD).await?;
            with_timeout(async {
                write_all(&mut writer, &upload).await?;
                writer.finish().await
            })
            .await?;

            // An unknown designator is rejected by the chain terminator.
            let exchange = runner.initiate_exchange().await?;
            let result =
                with_timeout(async { exchange.pull(b"unknown.bin").await.map(|_| ()) }).await;
            assert!(result.is_err(), "unknown file designator must be rejected");

            Ok::<_, Error>(())
        })
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
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        exchange.recv_fetch().await?;
        exchange.rx_done()?;
        send_bdx_status(&mut exchange, bdx::BdxStatus::FileDesignatorUnknown).await
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
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
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
        send_bdx_status(&mut exchange, bdx::BdxStatus::TransferFailedUnknownError).await
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
