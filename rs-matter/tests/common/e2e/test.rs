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

use rs_matter::crypto::Crypto;
use rs_matter::dm::{AsyncHandler, AsyncMetadata};
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

    /// Optionally set up the test, allows you to emit events into the system-under-test
    fn setup(&self) -> Result<(), Error> {
        Ok(())
    }

    /// Determine if the "direction" of the messages: Do we send our fill_input message first and then
    /// expect a reply, or do we wait for a message we assert on with validate_result and then respond?
    fn direction(&self) -> E2eTestDirection {
        E2eTestDirection::ClientInitiated
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

    fn setup(&self) -> Result<(), Error> {
        (*self).setup()
    }

    fn direction(&self) -> E2eTestDirection {
        (*self).direction()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum E2eTestDirection {
    /// Default - "driving" side sends a message and then validates response
    ClientInitiated,
    /// Wait for server to send a message, then respond with fill_input
    ServerInitiated,
}

impl<C: Crypto> E2eRunner<C> {
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
                    self.execute_test(&mut exchange, test).await?;
                    exchange.acknowledge().await?;
                }

                exchange.acknowledge().await?;

                Ok(())
            })
            .coalesce(),
        )
        .unwrap()
    }

    /// Execute the test via the provided exchange.
    pub async fn execute_test<T>(&self, exchange: &mut Exchange<'_>, test: T) -> Result<(), Error>
    where
        T: E2eTest,
    {
        test.setup()?;
        match test.direction() {
            E2eTestDirection::ClientInitiated => {
                self.execute_client_part_of_test(exchange, &test).await?;
                self.execute_server_part_of_test(exchange, &test).await?;
            }
            E2eTestDirection::ServerInitiated => {
                let mut peer_exchange = Exchange::accept(self.matter_client()).await?;
                self.execute_server_part_of_test(&mut peer_exchange, &test)
                    .await?;
                self.execute_client_part_of_test(&mut peer_exchange, &test)
                    .await?;
                peer_exchange.acknowledge().await?;
            }
        }

        let delay = test.delay().unwrap_or(0);
        if delay > 0 {
            Timer::after(Duration::from_millis(delay as _)).await;
        }
        Ok(())
    }

    async fn execute_client_part_of_test<T>(
        &self,
        exchange: &mut Exchange<'_>,
        test: &T,
    ) -> Result<(), Error>
    where
        T: E2eTest,
    {
        exchange
            .send_with(|_, wb| {
                let meta = test.fill_input(wb)?;

                Ok(Some(meta))
            })
            .await?;
        Ok(())
    }

    async fn execute_server_part_of_test<T>(
        &self,
        exchange: &mut Exchange<'_>,
        test: &T,
    ) -> Result<(), Error>
    where
        T: E2eTest,
    {
        let rx = exchange.recv().await?;
        test.validate_result(rx.meta(), rx.payload())
    }
}
