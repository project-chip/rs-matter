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

use embassy_futures::select::{select, select_slice, Either};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};

use log::{error, info};

use crate::{data_model::objects::DataModelHandler, CommissioningData, Matter};
use crate::{error::Error, transport::packet::MAX_RX_BUF_SIZE, utils::select::EitherUnwrap};

use super::{
    core::Transport,
    exchange::{Notification, MAX_EXCHANGES},
    packet::{MAX_RX_STATUS_BUF_SIZE, MAX_TX_BUF_SIZE},
    pipe::{Chunk, Pipe},
};

type TxBuf = MaybeUninit<[u8; MAX_TX_BUF_SIZE]>;
type RxBuf = MaybeUninit<[u8; MAX_RX_BUF_SIZE]>;
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

#[cfg(any(feature = "std", feature = "embassy-net"))]
pub struct AllUdpBuffers {
    transport: TransportUdpBuffers,
    mdns: crate::mdns::MdnsUdpBuffers,
}

#[cfg(any(feature = "std", feature = "embassy-net"))]
impl AllUdpBuffers {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            transport: TransportUdpBuffers::new(),
            mdns: crate::mdns::MdnsUdpBuffers::new(),
        }
    }
}

#[cfg(any(feature = "std", feature = "embassy-net"))]
pub struct TransportUdpBuffers {
    udp: crate::transport::udp::UdpBuffers,
    tx_buf: TxBuf,
    rx_buf: RxBuf,
}

#[cfg(any(feature = "std", feature = "embassy-net"))]
impl TransportUdpBuffers {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            udp: crate::transport::udp::UdpBuffers::new(),
            tx_buf: core::mem::MaybeUninit::uninit(),
            rx_buf: core::mem::MaybeUninit::uninit(),
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

    #[cfg(any(feature = "std", feature = "embassy-net"))]
    pub async fn run_udp_all<D, H>(
        &mut self,
        stack: &crate::transport::network::NetworkStack<D>,
        mdns: &crate::mdns::MdnsService<'_>,
        buffers: &mut AllUdpBuffers,
        dev_comm: CommissioningData,
        handler: &H,
    ) -> Result<(), Error>
    where
        D: crate::transport::network::NetworkStackDriver,
        H: DataModelHandler,
    {
        let mut mdns_runner = crate::mdns::MdnsRunner::new(mdns);

        let mut mdns = pin!(mdns_runner.run_udp(stack, &mut buffers.mdns));
        let mut transport = pin!(self.run_udp(stack, &mut buffers.transport, dev_comm, handler));

        embassy_futures::select::select(&mut mdns, &mut transport)
            .await
            .unwrap()
    }

    #[cfg(any(feature = "std", feature = "embassy-net"))]
    pub async fn run_udp<D, H>(
        &mut self,
        stack: &crate::transport::network::NetworkStack<D>,
        buffers: &mut TransportUdpBuffers,
        dev_comm: CommissioningData,
        handler: &H,
    ) -> Result<(), Error>
    where
        D: crate::transport::network::NetworkStackDriver,
        H: DataModelHandler,
    {
        let udp = crate::transport::udp::UdpListener::new(
            stack,
            crate::transport::network::SocketAddr::new(
                crate::transport::network::IpAddr::V6(
                    crate::transport::network::Ipv6Addr::UNSPECIFIED,
                ),
                self.transport.matter().port,
            ),
            &mut buffers.udp,
        )
        .await?;

        let tx_pipe = Pipe::new(unsafe { buffers.tx_buf.assume_init_mut() });
        let rx_pipe = Pipe::new(unsafe { buffers.rx_buf.assume_init_mut() });

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
                            addr: crate::transport::network::Address::Udp(addr),
                        });
                        rx_pipe.data_supplied_notification.signal(());
                    }
                }

                rx_pipe.data_consumed_notification.wait().await;
            }
        });

        let mut run = pin!(async move { self.run(tx_pipe, rx_pipe, dev_comm, handler).await });

        embassy_futures::select::select3(&mut tx, &mut rx, &mut run)
            .await
            .unwrap()
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
        let mut tx = pin!(self.transport.handle_tx(tx_pipe));

        select(&mut rx, &mut tx).await.unwrap()
    }

    #[inline(always)]
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

        // Unsafely allow mutable aliasing in the packet pools by different indices
        let pools: *mut PacketPools = pools;

        for index in 0..MAX_EXCHANGES {
            let channel = &channel;
            let handler_id = index;

            let pools = unsafe { pools.as_mut() }.unwrap();

            let tx_buf = unsafe { pools.tx[handler_id].assume_init_mut() };
            let rx_buf = unsafe { pools.rx[handler_id].assume_init_mut() };
            let sx_buf = unsafe { pools.sx[handler_id].assume_init_mut() };

            handlers
                .push(
                    transport
                        .exchange_handler(tx_buf, rx_buf, sx_buf, handler_id, channel, handler),
                )
                .map_err(|_| ())
                .unwrap();
        }

        let mut rx =
            pin!(transport.handle_rx_multiplex(rx_pipe, &construction_notification, &channel));

        let result = select(&mut rx, select_slice(&mut handlers)).await;

        if let Either::First(result) = result {
            if let Err(e) = &result {
                error!("Exitting RX loop due to an error: {:?}", e);
            }

            result?;
        }

        Ok(())
    }
}
