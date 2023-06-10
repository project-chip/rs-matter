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

use core::sync::atomic::{AtomicU32, Ordering};

use super::objects::*;
use crate::{
    alloc,
    error::*,
    interaction_model::core::Interaction,
    transport::{exchange::Exchange, packet::Packet},
};

// TODO: For now...
static SUBS_ID: AtomicU32 = AtomicU32::new(1);

pub struct DataModel<T>(T);

impl<T> DataModel<T> {
    pub fn new(handler: T) -> Self {
        Self(handler)
    }

    pub async fn handle<'r, 'p>(
        &self,
        exchange: &'r mut Exchange<'_>,
        rx: &'r mut Packet<'p>,
        tx: &'r mut Packet<'p>,
        rx_status: &'r mut Packet<'p>,
    ) -> Result<(), Error>
    where
        T: DataModelHandler,
    {
        let timeout = Interaction::timeout(exchange, rx, tx).await?;

        let mut interaction = alloc!(Interaction::new(
            exchange,
            rx,
            tx,
            rx_status,
            || SUBS_ID.fetch_add(1, Ordering::SeqCst),
            timeout,
        )?);

        #[cfg(feature = "alloc")]
        let interaction = &mut *interaction;

        #[cfg(not(feature = "alloc"))]
        let interaction = &mut interaction;

        #[cfg(feature = "nightly")]
        let metadata = self.0.lock().await;

        #[cfg(not(feature = "nightly"))]
        let metadata = self.0.lock();

        if interaction.start().await? {
            match interaction {
                Interaction::Read {
                    req,
                    ref mut driver,
                } => {
                    let accessor = driver.accessor()?;

                    'outer: for item in metadata.node().read(req, None, &accessor) {
                        while !AttrDataEncoder::handle_read(&item, &self.0, &mut driver.writer()?)
                            .await?
                        {
                            if !driver.send_chunk(req).await? {
                                break 'outer;
                            }
                        }
                    }

                    driver.complete(req).await?;
                }
                Interaction::Write {
                    req,
                    ref mut driver,
                } => {
                    let accessor = driver.accessor()?;

                    for item in metadata.node().write(req, &accessor) {
                        AttrDataEncoder::handle_write(&item, &self.0, &mut driver.writer()?)
                            .await?;
                    }

                    driver.complete(req).await?;
                }
                Interaction::Invoke {
                    req,
                    ref mut driver,
                } => {
                    let accessor = driver.accessor()?;

                    for item in metadata.node().invoke(req, &accessor) {
                        let (mut tw, exchange) = driver.writer_exchange()?;

                        CmdDataEncoder::handle(&item, &self.0, &mut tw, exchange).await?;
                    }

                    driver.complete(req).await?;
                }
                Interaction::Subscribe {
                    req,
                    ref mut driver,
                } => {
                    let accessor = driver.accessor()?;

                    'outer: for item in metadata.node().subscribing_read(req, None, &accessor) {
                        while !AttrDataEncoder::handle_read(&item, &self.0, &mut driver.writer()?)
                            .await?
                        {
                            if !driver.send_chunk(req).await? {
                                break 'outer;
                            }
                        }
                    }

                    driver.complete(req).await?;
                }
            }
        }

        Ok(())
    }
}
