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

//! End-to-end test for the *controller* side of the Diagnostic Logs cluster: a
//! device pushes a log over BDX and the controller receives it via
//! [`DiagLogsBdxHandler`] (the [`BdxHandler`](rs_matter::bdx::BdxHandler) an
//! application chains into its responder), pulling the bytes from the
//! [`BdxReader`] handed to its [`DiagLogsReceiver`].
//!
//! The device/controller node roles are mirrored relative to real life (here the
//! test driver uploads and the tested responder receives), which is all that is
//! needed to exercise the controller's receive handler - the full
//! request-then-push flow against the *server* side is covered by the CHIP
//! `TestDiagnosticLogs` integration suite.

#![cfg(all(feature = "std", feature = "async-io"))]

#[allow(dead_code)]
mod common;

use core::cell::RefCell;
use core::future::Future;
use core::pin::pin;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use rs_matter::bdx::{Bdx, BdxReader, BdxUploadInitiator, BdxWriter};
use rs_matter::dm::clusters::diag_logs::client::{DiagLogsBdxHandler, DiagLogsReceiver};
use rs_matter::error::Error;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::sync::Notification;

use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

/// The file designator the device names for the log transfer (the controller
/// echoes the one it asked for in `RetrieveLogsRequest`).
const FILE_DESIGNATOR: &[u8] = b"diag-log";

/// Log sizes that bracket the BDX block size (1024 B): empty, exactly one block,
/// and a multi-block transfer.
const LOG_SIZES: &[usize] = &[0, 1024, 5000];

fn log_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Fail (rather than hang) if the transfer doesn't make progress.
async fn with_timeout<F, T>(fut: F) -> Result<T, Error>
where
    F: Future<Output = Result<T, Error>>,
{
    match select(pin!(fut), pin!(Timer::after(Duration::from_secs(30)))).await {
        Either::First(r) => r,
        Either::Second(()) => panic!("BDX transfer timed out"),
    }
}

/// Write a whole buffer via `BdxWriter`, honoring partial-accept.
async fn write_all(writer: &mut BdxWriter<'_, '_>, mut data: &[u8]) -> Result<(), Error> {
    while !data.is_empty() {
        let n = writer.write(data).await?;
        assert!(n > 0);
        data = &data[n..];
    }
    Ok(())
}

/// A [`DiagLogsReceiver`] that collects each pushed log into memory (the
/// "store it however you like" the controller side leaves to the application -
/// here, just a buffer), signalling completion so the test can assert.
struct CollectingReceiver {
    fd: RefCell<Vec<u8>>,
    data: RefCell<Vec<u8>>,
    done: Notification,
}

impl CollectingReceiver {
    fn new() -> Self {
        Self {
            fd: RefCell::new(Vec::new()),
            data: RefCell::new(Vec::new()),
            done: Notification::new(),
        }
    }

    fn reset(&self) {
        self.fd.borrow_mut().clear();
        self.data.borrow_mut().clear();
    }
}

impl DiagLogsReceiver for CollectingReceiver {
    async fn receive(
        &self,
        file_designator: &[u8],
        reader: &mut BdxReader<'_>,
    ) -> Result<(), Error> {
        self.fd.borrow_mut().extend_from_slice(file_designator);

        // Pull the bytes ourselves (a deliberately non-block-aligned buffer to
        // exercise partial-block / cross-block reads).
        let mut buf = [0u8; 300];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            self.data.borrow_mut().extend_from_slice(&buf[..n]);
        }

        self.done.notify();

        Ok(())
    }
}

/// The device uploads a log over BDX; the controller's [`DiagLogsBdxHandler`]
/// accepts it and hands the reader to our [`DiagLogsReceiver`], which pulls
/// the bytes. Verifies the file designator and the exact content across empty,
/// single-block, and multi-block transfers on one session.
#[test]
fn diag_logs_bdx_receive() {
    init_env_logger();

    let runner = new_default_runner();
    let receiver = CollectingReceiver::new();

    // The controller's responder: just the Diagnostic Logs BDX receiver.
    let handler = Bdx::new(DiagLogsBdxHandler::new(&receiver));

    futures_lite::future::block_on(async {
        select(runner.run_responder(handler), async {
            for &size in LOG_SIZES {
                receiver.reset();

                let log = log_of(size);

                // Stand in for the device pushing the log over BDX.
                let exchange = runner.initiate_exchange().await?;
                let mut wbuf = [0u8; 1024];
                let mut writer = exchange.upload(&mut wbuf, FILE_DESIGNATOR, None).await?;
                with_timeout(async {
                    write_all(&mut writer, &log).await?;
                    writer.finish().await
                })
                .await?;

                // Wait for the receiver to drain the transfer, then check it.
                receiver.done.wait().await;
                assert_eq!(&*receiver.data.borrow(), &log, "log size {size}");
                assert_eq!(&*receiver.fd.borrow(), FILE_DESIGNATOR);
            }

            Ok::<_, Error>(())
        })
        .coalesce()
        .await
    })
    .unwrap();
}
