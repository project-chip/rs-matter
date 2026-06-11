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

//! End-to-end test of the BDX transfer engine: a `serve` (Sender/Responder)
//! and a `download` (Receiver/Initiator) running against each other over a real
//! CASE-secured exchange, transferring a multi-block image and asserting it
//! arrives byte-for-byte.

#![cfg(all(feature = "std", feature = "async-io"))]

#[allow(dead_code)]
mod common;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use rs_matter::bdx::{self, BdxSink, BdxSource};
use rs_matter::error::Error;
use rs_matter::respond::ExchangeHandler;
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
