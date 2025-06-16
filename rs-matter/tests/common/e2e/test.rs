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

use embassy_futures::block_on;
use embassy_futures::select::select;

use embassy_time::{Duration, Timer};

use rs_matter::dm::objects::{AsyncHandler, AsyncMetadata};
use rs_matter::error::Error;
use rs_matter::transport::exchange::{Exchange, MessageMeta};
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::WriteBuf;

use super::E2eRunner;

/// Represents an E2E test.
pub trait E2eTest {
    /// Prepare the input message for the test.
    fn fill_input(&self, message_buf: &mut WriteBuf) -> Result<MessageMeta, Error>;

    /// Validate the message returned by the remote peer.
    fn validate_result(&self, meta: MessageMeta, message: &[u8]) -> Result<(), Error>;

    /// Optionally return a delay in milliseconds to wait after receiving the message by the remote peer.
    fn delay(&self) -> Option<u64> {
        None
    }
}

impl E2eTest for &dyn E2eTest {
    fn fill_input(&self, message_buf: &mut WriteBuf) -> Result<MessageMeta, Error> {
        (*self).fill_input(message_buf)
    }

    fn validate_result(&self, meta: MessageMeta, message: &[u8]) -> Result<(), Error> {
        (*self).validate_result(meta, message)
    }

    fn delay(&self) -> Option<u64> {
        (*self).delay()
    }
}

impl E2eRunner {
    /// Run the provided test with the given handler and wait with blocking
    /// until the test completes or fails.
    pub fn test_one<H, T>(&self, handler: H, test: T)
    where
        H: AsyncHandler + AsyncMetadata,
        T: E2eTest,
    {
        self.test_all(handler, core::iter::once(test))
    }

    /// Run the provided tests with the given handler and wait with blocking
    /// until all tests complete or the first one fails.
    pub fn test_all<H, I, T>(&self, handler: H, tests: I)
    where
        H: AsyncHandler + AsyncMetadata,
        I: IntoIterator<Item = T>,
        T: E2eTest,
    {
        block_on(
            select(self.run(handler), async move {
                let mut exchange = self.initiate_exchange().await?;

                for test in tests {
                    Self::execute_test(&mut exchange, test).await?;
                }

                exchange.acknowledge().await?;

                Ok(())
            })
            .coalesce(),
        )
        .unwrap()
    }

    /// Execute the test via the provided exchange.
    pub async fn execute_test<T>(exchange: &mut Exchange<'_>, test: T) -> Result<(), Error>
    where
        T: E2eTest,
    {
        exchange
            .send_with(|_, wb| {
                let meta = test.fill_input(wb)?;

                Ok(Some(meta))
            })
            .await?;

        {
            // In a separate block so that the RX message is dropped before we start waiting

            let rx = exchange.recv().await?;

            test.validate_result(rx.meta(), rx.payload())?;
        }

        let delay = test.delay().unwrap_or(0);
        if delay > 0 {
            Timer::after(Duration::from_millis(delay as _)).await;
        }

        Ok(())
    }
}
