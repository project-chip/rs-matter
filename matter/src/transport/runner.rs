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

use core::{mem::MaybeUninit, pin::pin};

use crate::{
    alloc,
    data_model::{core::DataModel, objects::DataModelHandler},
    interaction_model::core::PROTO_ID_INTERACTION_MODEL,
    transport::network::{Address, IpAddr, Ipv6Addr, SocketAddr},
    CommissioningData, Matter,
};
use embassy_futures::select::{select, select3, select_slice, Either};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
use log::{error, info, warn};

use crate::{
    error::Error,
    secure_channel::{common::PROTO_ID_SECURE_CHANNEL, core::SecureChannel},
    transport::packet::{Packet, MAX_RX_BUF_SIZE},
    utils::select::EitherUnwrap,
};

use super::{
    core::Transport,
    exchange::{ExchangeCtr, Notification, MAX_EXCHANGES},
    packet::{MAX_RX_STATUS_BUF_SIZE, MAX_TX_BUF_SIZE},
    pipe::{Chunk, Pipe},
    udp::UdpListener,
};

pub type TxBuf = MaybeUninit<[u8; MAX_TX_BUF_SIZE]>;
pub type RxBuf = MaybeUninit<[u8; MAX_RX_BUF_SIZE]>;
type SxBuf = MaybeUninit<[u8; MAX_RX_STATUS_BUF_SIZE]>;

struct PacketPools {
    tx: [TxBuf; MAX_EXCHANGES],
    rx: [RxBuf; MAX_EXCHANGES],
    sx: [SxBuf; MAX_EXCHANGES],
}

impl PacketPools {
    const TX_ELEM: TxBuf = MaybeUninit::uninit();
    const RX_ELEM: RxBuf = MaybeUninit::uninit();
    const SX_ELEM: SxBuf = MaybeUninit::uninit();

    const TX_INIT: [TxBuf; MAX_EXCHANGES] = [Self::TX_ELEM; MAX_EXCHANGES];
    const RX_INIT: [RxBuf; MAX_EXCHANGES] = [Self::RX_ELEM; MAX_EXCHANGES];
    const SX_INIT: [SxBuf; MAX_EXCHANGES] = [Self::SX_ELEM; MAX_EXCHANGES];

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            tx: Self::TX_INIT,
            rx: Self::RX_INIT,
            sx: Self::SX_INIT,
        }
    }
}

/// This struct implements an executor-agnostic option to run the Matter transport stack end-to-end.
///
/// Since it is not possible to use executor tasks spawning in an executor-agnostic way (yet),
/// the async loops are arranged as one giant future. Therefore, the cost is a slightly slower execution
/// due to the generated future being relatively big and deeply nested.
///
/// Users are free to implement their own async execution loop, by utilizing the `Transport`
/// struct directly with their async executor of choice.
pub struct TransportRunner<'a> {
    transport: Transport<'a>,
    pools: PacketPools,
}

impl<'a> TransportRunner<'a> {
    #[inline(always)]
    pub fn new(matter: &'a Matter<'a>) -> Self {
        Self::wrap(Transport::new(matter))
    }

    #[inline(always)]
    pub const fn wrap(transport: Transport<'a>) -> Self {
        Self {
            transport,
            pools: PacketPools::new(),
        }
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    pub async fn run_udp<H>(
        &mut self,
        tx_buf: &mut TxBuf,
        rx_buf: &mut RxBuf,
        dev_comm: CommissioningData,
        handler: &H,
    ) -> Result<(), Error>
    where
        H: DataModelHandler,
    {
        let udp = UdpListener::new(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            self.transport.matter().port,
        ))
        .await?;

        let tx_pipe = Pipe::new(unsafe { tx_buf.assume_init_mut() });
        let rx_pipe = Pipe::new(unsafe { rx_buf.assume_init_mut() });

        let tx_pipe = &tx_pipe;
        let rx_pipe = &rx_pipe;
        let udp = &udp;

        let mut tx = pin!(async move {
            loop {
                {
                    let mut data = tx_pipe.data.lock().await;

                    if let Some(chunk) = data.chunk {
                        udp.send(chunk.addr.unwrap_udp(), &data.buf[chunk.start..chunk.end])
                            .await?;
                        data.chunk = None;
                        tx_pipe.data_consumed_notification.signal(());
                    }
                }

                tx_pipe.data_supplied_notification.wait().await;
            }
        });

        let mut rx = pin!(async move {
            loop {
                {
                    let mut data = rx_pipe.data.lock().await;

                    if data.chunk.is_none() {
                        let (len, addr) = udp.recv(data.buf).await?;

                        data.chunk = Some(Chunk {
                            start: 0,
                            end: len,
                            addr: Address::Udp(addr),
                        });
                        rx_pipe.data_supplied_notification.signal(());
                    }
                }

                rx_pipe.data_consumed_notification.wait().await;
            }
        });

        let mut run = pin!(async move { self.run(tx_pipe, rx_pipe, dev_comm, handler).await });

        select3(&mut tx, &mut rx, &mut run).await.unwrap()
    }

    pub async fn run<H>(
        &mut self,
        tx_pipe: &Pipe<'_>,
        rx_pipe: &Pipe<'_>,
        dev_comm: CommissioningData,
        handler: &H,
    ) -> Result<(), Error>
    where
        H: DataModelHandler,
    {
        info!("Running Matter transport");

        let buf = unsafe { self.pools.rx[0].assume_init_mut() };

        if self.transport.matter().start_comissioning(dev_comm, buf)? {
            info!("Comissioning started");
        }

        let construction_notification = Notification::new();

        let mut rx = pin!(Self::handle_rx(
            &self.transport,
            &mut self.pools,
            rx_pipe,
            &construction_notification,
            handler
        ));
        let mut tx = pin!(Self::handle_tx(&self.transport, tx_pipe));

        select(&mut rx, &mut tx).await.unwrap()
    }

    async fn handle_rx<H>(
        transport: &Transport<'_>,
        pools: &mut PacketPools,
        rx_pipe: &Pipe<'_>,
        construction_notification: &Notification,
        handler: &H,
    ) -> Result<(), Error>
    where
        H: DataModelHandler,
    {
        info!("Creating queue for {} exchanges", 1);

        let channel = Channel::<NoopRawMutex, _, 1>::new();

        info!("Creating {} handlers", MAX_EXCHANGES);
        let mut handlers = heapless::Vec::<_, MAX_EXCHANGES>::new();

        info!("Handlers size: {}", core::mem::size_of_val(&handlers));

        let pools = &mut *pools as *mut _;

        for index in 0..MAX_EXCHANGES {
            let channel = &channel;
            let handler_id = index;

            handlers
                .push(async move {
                    loop {
                        let exchange_ctr: ExchangeCtr<'_> = channel.recv().await;

                        info!(
                            "Handler {}: Got exchange {:?}",
                            handler_id,
                            exchange_ctr.id()
                        );

                        let result = Self::handle_exchange(
                            transport,
                            pools,
                            handler_id,
                            exchange_ctr,
                            handler,
                        )
                        .await;

                        if let Err(err) = result {
                            warn!(
                                "Handler {}: Exchange closed because of error: {:?}",
                                handler_id, err
                            );
                        } else {
                            info!("Handler {}: Exchange completed", handler_id);
                        }
                    }
                })
                .map_err(|_| ())
                .unwrap();
        }

        let mut rx = pin!(async {
            loop {
                info!("Transport: waiting for incoming packets");

                {
                    let mut data = rx_pipe.data.lock().await;

                    if let Some(chunk) = data.chunk {
                        let mut rx = alloc!(Packet::new_rx(&mut data.buf[chunk.start..chunk.end]));
                        rx.peer = chunk.addr;

                        if let Some(exchange_ctr) =
                            transport.process_rx(construction_notification, &mut rx)?
                        {
                            let exchange_id = exchange_ctr.id().clone();

                            info!("Transport: got new exchange: {:?}", exchange_id);

                            channel.send(exchange_ctr).await;
                            info!("Transport: exchange sent");

                            transport
                                .wait_construction(construction_notification, &rx, &exchange_id)
                                .await?;

                            info!("Transport: exchange started");
                        }

                        data.chunk = None;
                        rx_pipe.data_consumed_notification.signal(());
                    }
                }

                rx_pipe.data_supplied_notification.wait().await
            }

            #[allow(unreachable_code)]
            Ok::<_, Error>(())
        });

        let result = select(&mut rx, select_slice(&mut handlers)).await;

        if let Either::First(result) = result {
            if let Err(e) = &result {
                error!("Exitting RX loop due to an error: {:?}", e);
            }

            result?;
        }

        Ok(())
    }

    async fn handle_tx(transport: &Transport<'_>, tx_pipe: &Pipe<'_>) -> Result<(), Error> {
        loop {
            loop {
                {
                    let mut data = tx_pipe.data.lock().await;

                    if data.chunk.is_none() {
                        let mut tx = alloc!(Packet::new_tx(data.buf));

                        if transport.pull_tx(&mut tx).await? {
                            data.chunk = Some(Chunk {
                                start: tx.get_writebuf()?.get_start(),
                                end: tx.get_writebuf()?.get_tail(),
                                addr: tx.peer,
                            });
                            tx_pipe.data_supplied_notification.signal(());
                        } else {
                            break;
                        }
                    }
                }

                tx_pipe.data_consumed_notification.wait().await;
            }

            transport.wait_tx().await?;
        }
    }

    #[cfg_attr(feature = "nightly", allow(clippy::await_holding_refcell_ref))] // Fine because of the async mutex
    async fn handle_exchange<H>(
        transport: &Transport<'_>,
        pools: *mut PacketPools,
        handler_id: usize,
        exchange_ctr: ExchangeCtr<'_>,
        handler: &H,
    ) -> Result<(), Error>
    where
        H: DataModelHandler,
    {
        let pools = unsafe { pools.as_mut() }.unwrap();

        let tx_buf = unsafe { pools.tx[handler_id].assume_init_mut() };
        let rx_buf = unsafe { pools.rx[handler_id].assume_init_mut() };
        let rx_status_buf = unsafe { pools.sx[handler_id].assume_init_mut() };

        let mut rx = alloc!(Packet::new_rx(rx_buf.as_mut()));
        let mut tx = alloc!(Packet::new_tx(tx_buf.as_mut()));

        let mut exchange = alloc!(exchange_ctr.get(&mut rx).await?);

        match rx.get_proto_id() {
            PROTO_ID_SECURE_CHANNEL => {
                let sc = SecureChannel::new(transport.matter());

                sc.handle(&mut exchange, &mut rx, &mut tx).await?;

                transport.matter().notify_changed();
            }
            PROTO_ID_INTERACTION_MODEL => {
                let dm = DataModel::new(handler);

                let mut rx_status = alloc!(Packet::new_rx(rx_status_buf));

                dm.handle(&mut exchange, &mut rx, &mut tx, &mut rx_status)
                    .await?;

                transport.matter().notify_changed();
            }
            other => {
                error!("Unknown Proto-ID: {}", other);
            }
        }

        Ok(())
    }
}
