use core::{cell::RefCell, pin::pin};

use domain::base::name::FromStrError;
use domain::base::{octets::ParseError, ShortBuf};
use embassy_futures::select::select;
use embassy_time::{Duration, Timer};
use log::info;

use crate::data_model::cluster_basic_information::BasicInfoConfig;
use crate::error::{Error, ErrorCode};
use crate::transport::network::{Address, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use crate::transport::pipe::{Chunk, Pipe};
use crate::utils::select::{EitherUnwrap, Notification};

use super::{
    proto::{Host, Services},
    Service, ServiceMode,
};

const IP_BROADCAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const IPV6_BROADCAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

const PORT: u16 = 5353;

pub struct MdnsService<'a> {
    host: Host<'a>,
    #[allow(unused)]
    interface: u32,
    dev_det: &'a BasicInfoConfig<'a>,
    matter_port: u16,
    services: RefCell<heapless::Vec<(heapless::String<40>, ServiceMode), 4>>,
    notification: Notification,
}

impl<'a> MdnsService<'a> {
    #[inline(always)]
    pub const fn new(
        id: u16,
        hostname: &'a str,
        ip: [u8; 4],
        ipv6: Option<[u8; 16]>,
        interface: u32,
        dev_det: &'a BasicInfoConfig<'a>,
        matter_port: u16,
    ) -> Self {
        Self {
            host: Host {
                id,
                hostname,
                ip,
                ipv6,
            },
            interface,
            dev_det,
            matter_port,
            services: RefCell::new(heapless::Vec::new()),
            notification: Notification::new(),
        }
    }

    pub fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        let mut services = self.services.borrow_mut();

        services.retain(|(name, _)| name != service);
        services
            .push((service.into(), mode))
            .map_err(|_| ErrorCode::NoSpace)?;

        self.notification.signal(());

        Ok(())
    }

    pub fn remove(&self, service: &str) -> Result<(), Error> {
        let mut services = self.services.borrow_mut();

        services.retain(|(name, _)| name != service);

        Ok(())
    }

    pub fn for_each<F>(&self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(&Service) -> Result<(), Error>,
    {
        let services = self.services.borrow();

        for (service, mode) in &*services {
            mode.service(self.dev_det, self.matter_port, service, |service| {
                callback(service)
            })?;
        }

        Ok(())
    }
}

#[cfg(any(feature = "std", feature = "embassy-net"))]
pub struct MdnsUdpBuffers {
    udp: crate::transport::udp::UdpBuffers,
    tx_buf: core::mem::MaybeUninit<[u8; crate::transport::packet::MAX_TX_BUF_SIZE]>,
    rx_buf: core::mem::MaybeUninit<[u8; crate::transport::packet::MAX_RX_BUF_SIZE]>,
}

#[cfg(any(feature = "std", feature = "embassy-net"))]
impl MdnsUdpBuffers {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            udp: crate::transport::udp::UdpBuffers::new(),
            tx_buf: core::mem::MaybeUninit::uninit(),
            rx_buf: core::mem::MaybeUninit::uninit(),
        }
    }
}

pub struct MdnsRunner<'a>(&'a MdnsService<'a>);

impl<'a> MdnsRunner<'a> {
    pub const fn new(mdns: &'a MdnsService<'a>) -> Self {
        Self(mdns)
    }

    #[cfg(any(feature = "std", feature = "embassy-net"))]
    pub async fn run_udp<D>(
        &mut self,
        stack: &crate::transport::network::NetworkStack<D>,
        buffers: &mut MdnsUdpBuffers,
    ) -> Result<(), Error>
    where
        D: crate::transport::network::NetworkStackMulticastDriver
            + crate::transport::network::NetworkStackDriver
            + 'static,
    {
        let mut udp = crate::transport::udp::UdpListener::new(
            stack,
            crate::transport::network::SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), PORT),
            &mut buffers.udp,
        )
        .await?;

        udp.join_multicast_v6(IPV6_BROADCAST_ADDR, self.0.interface)?;
        udp.join_multicast_v4(
            IP_BROADCAST_ADDR,
            crate::transport::network::Ipv4Addr::from(self.0.host.ip),
        )?;

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
                            addr: Address::Udp(addr),
                        });
                        rx_pipe.data_supplied_notification.signal(());
                    }
                }

                rx_pipe.data_consumed_notification.wait().await;
            }
        });

        let mut run = pin!(async move { self.run(tx_pipe, rx_pipe).await });

        embassy_futures::select::select3(&mut tx, &mut rx, &mut run)
            .await
            .unwrap()
    }

    pub async fn run(&self, tx_pipe: &Pipe<'_>, rx_pipe: &Pipe<'_>) -> Result<(), Error> {
        let mut broadcast = pin!(self.broadcast(tx_pipe));
        let mut respond = pin!(self.respond(rx_pipe, tx_pipe));

        select(&mut broadcast, &mut respond).await.unwrap()
    }

    #[allow(clippy::await_holding_refcell_ref)]
    async fn broadcast(&self, tx_pipe: &Pipe<'_>) -> Result<(), Error> {
        loop {
            select(
                self.0.notification.wait(),
                Timer::after(Duration::from_secs(30)),
            )
            .await;

            for addr in [
                IpAddr::V4(IP_BROADCAST_ADDR),
                IpAddr::V6(IPV6_BROADCAST_ADDR),
            ] {
                loop {
                    let sent = {
                        let mut data = tx_pipe.data.lock().await;

                        if data.chunk.is_none() {
                            let len = self.0.host.broadcast(&self.0, data.buf, 60)?;

                            if len > 0 {
                                info!("Broadasting mDNS entry to {}:{}", addr, PORT);

                                data.chunk = Some(Chunk {
                                    start: 0,
                                    end: len,
                                    addr: Address::Udp(SocketAddr::new(addr, PORT)),
                                });

                                tx_pipe.data_supplied_notification.signal(());
                            }

                            true
                        } else {
                            false
                        }
                    };

                    if sent {
                        break;
                    } else {
                        tx_pipe.data_consumed_notification.wait().await;
                    }
                }
            }
        }
    }

    #[allow(clippy::await_holding_refcell_ref)]
    async fn respond(&self, rx_pipe: &Pipe<'_>, tx_pipe: &Pipe<'_>) -> Result<(), Error> {
        loop {
            {
                let mut rx_data = rx_pipe.data.lock().await;

                if let Some(rx_chunk) = rx_data.chunk {
                    let data = &rx_data.buf[rx_chunk.start..rx_chunk.end];

                    loop {
                        let sent = {
                            let mut tx_data = tx_pipe.data.lock().await;

                            if tx_data.chunk.is_none() {
                                let len = self.0.host.respond(&self.0, data, tx_data.buf, 60)?;

                                if len > 0 {
                                    info!("Replying to mDNS query from {}", rx_chunk.addr);

                                    tx_data.chunk = Some(Chunk {
                                        start: 0,
                                        end: len,
                                        addr: rx_chunk.addr,
                                    });

                                    tx_pipe.data_supplied_notification.signal(());
                                }

                                true
                            } else {
                                false
                            }
                        };

                        if sent {
                            break;
                        } else {
                            tx_pipe.data_consumed_notification.wait().await;
                        }
                    }

                    // info!("Got mDNS query");

                    rx_data.chunk = None;
                    rx_pipe.data_consumed_notification.signal(());
                }
            }

            rx_pipe.data_supplied_notification.wait().await;
        }
    }
}

impl<'a> Services for MdnsService<'a> {
    type Error = crate::error::Error;

    fn for_each<F>(&self, callback: F) -> Result<(), Error>
    where
        F: FnMut(&Service) -> Result<(), Error>,
    {
        MdnsService::for_each(self, callback)
    }
}

impl<'a> super::Mdns for MdnsService<'a> {
    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        MdnsService::add(self, service, mode)
    }

    fn remove(&self, service: &str) -> Result<(), Error> {
        MdnsService::remove(self, service)
    }
}

impl From<ShortBuf> for Error {
    fn from(_e: ShortBuf) -> Self {
        Self::new(ErrorCode::NoSpace)
    }
}

impl From<ParseError> for Error {
    fn from(_e: ParseError) -> Self {
        Self::new(ErrorCode::MdnsError)
    }
}

impl From<FromStrError> for Error {
    fn from(_e: FromStrError) -> Self {
        Self::new(ErrorCode::MdnsError)
    }
}