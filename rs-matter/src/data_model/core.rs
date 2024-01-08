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

use portable_atomic::{AtomicU32, Ordering};

use super::objects::*;
use crate::{
    alloc,
    error::*,
    interaction_model::core::Interaction,
    transport::{exchange::Exchange, packet::Packet},
};

// TODO: For now...
static SUBS_ID: AtomicU32 = AtomicU32::new(1);

/// The Maximum number of expanded writer request per transaction
///
/// The write requests are first wildcard-expanded, and these many number of
/// write requests per-transaction will be supported.
pub const MAX_WRITE_ATTRS_IN_ONE_TRANS: usize = 7;

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

        let metadata = self.0.lock().await;

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
                    // The spec expects that a single write request like DeleteList + AddItem
                    // should cause all ACLs of that fabric to be deleted and the new one to be added (Case 1).
                    //
                    // This is in conflict with the immediate-effect expectation of ACL: an ACL
                    // write should instantaneously update the ACL so that immediate next WriteAttribute
                    // *in the same WriteRequest* should see that effect (Case 2).
                    //
                    // As with the C++ SDK, here we do all the ACLs checks first, before any write begins.
                    // Thus we support the Case1 by doing this. It does come at the cost of maintaining an
                    // additional list of expanded write requests as we start processing those.
                    let node = metadata.node();
                    let write_attrs: heapless::Vec<_, MAX_WRITE_ATTRS_IN_ONE_TRANS> =
                        node.write(req, &accessor).collect();

                    for item in write_attrs {
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
