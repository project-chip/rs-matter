use core::net::IpAddr;
use core::pin::pin;

use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Timer};

use log::{info, warn};

use crate::data_model::cluster_basic_information::BasicInfoConfig;
use crate::error::{Error, ErrorCode};
use crate::transport::network::{
    Address, Ipv4Addr, Ipv6Addr, NetworkReceive, NetworkSend, SocketAddr, SocketAddrV4,
    SocketAddrV6,
};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::rand::Rand;
use crate::utils::select::Coalesce;
use crate::utils::storage::pooled::BufferAccess;
use crate::utils::sync::Notification;

use super::{Service, ServiceMode};

use self::proto::Services;

pub use proto::Host;

#[path = "proto.rs"]
mod proto;

pub const MDNS_SOCKET_BIND_ADDR: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0));

pub const MDNS_IPV6_BROADCAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);
pub const MDNS_IPV4_BROADCAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

pub const MDNS_PORT: u16 = 5353;

pub struct MdnsImpl<'a> {
    dev_det: &'a BasicInfoConfig<'a>,
    matter_port: u16,
    services: RefCell<crate::utils::storage::Vec<(heapless::String<40>, ServiceMode), 4>>,
    notification: Notification<NoopRawMutex>,
}

impl<'a> MdnsImpl<'a> {
    #[inline(always)]
    pub const fn new(dev_det: &'a BasicInfoConfig<'a>, matter_port: u16) -> Self {
        Self {
            dev_det,
            matter_port,
            services: RefCell::new(crate::utils::storage::Vec::new()),
            notification: Notification::new(),
        }
    }

    pub fn init(dev_det: &'a BasicInfoConfig<'a>, matter_port: u16) -> impl Init<Self> {
        init!(Self {
            dev_det,
            matter_port,
            services <- RefCell::init(crate::utils::storage::Vec::init()),
            notification: Notification::new(),
        })
    }

    pub fn reset(&self) {
        self.services.borrow_mut().clear();
    }

    pub fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        let mut services = self.services.borrow_mut();

        services.retain(|(name, _)| name != service);
        services
            .push((service.try_into().unwrap(), mode))
            .map_err(|_| ErrorCode::NoSpace)?;

        self.notification.notify();

        Ok(())
    }

    pub fn remove(&self, service: &str) -> Result<(), Error> {
        let mut services = self.services.borrow_mut();

        services.retain(|(name, _)| name != service);

        self.notification.notify();

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

    #[allow(clippy::too_many_arguments)]
    pub async fn run<S, R, SB, RB>(
        &self,
        send: S,
        recv: R,
        tx_buf: SB,
        rx_buf: RB,
        host: &Host<'_>,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
        rand: Rand,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
        SB: BufferAccess<[u8]>,
        RB: BufferAccess<[u8]>,
    {
        let send = Mutex::<NoopRawMutex, _>::new(send);

        let mut broadcast =
            pin!(self.broadcast(&send, &tx_buf, host, ipv4_interface, ipv6_interface));
        let mut respond = pin!(self.respond(
            &send,
            recv,
            &tx_buf,
            &rx_buf,
            host,
            ipv4_interface,
            ipv6_interface,
            rand
        ));

        select(&mut broadcast, &mut respond).coalesce().await
    }

    async fn broadcast<S, B>(
        &self,
        send: &Mutex<impl RawMutex, S>,
        buffer: B,
        host: &Host<'_>,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        B: BufferAccess<[u8]>,
    {
        loop {
            let mut notification = pin!(self.notification.wait());
            let mut timeout = pin!(Timer::after(Duration::from_secs(30)));

            select(&mut notification, &mut timeout).await;

            for addr in Iterator::chain(
                ipv4_interface
                    .map(|_| SocketAddr::V4(SocketAddrV4::new(MDNS_IPV4_BROADCAST_ADDR, MDNS_PORT)))
                    .into_iter(),
                ipv6_interface
                    .map(|interface| {
                        SocketAddr::V6(SocketAddrV6::new(
                            MDNS_IPV6_BROADCAST_ADDR,
                            MDNS_PORT,
                            0,
                            interface,
                        ))
                    })
                    .into_iter(),
            ) {
                let mut buf = buffer.get().await.ok_or(ErrorCode::NoSpace)?;
                let mut send = send.lock().await;

                let len = host.broadcast(self, &mut buf, 60)?;

                if len > 0 {
                    info!("Broadcasting mDNS entry to {addr}");
                    send.send_to(&buf[..len], Address::Udp(addr)).await?;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn respond<S, R, SB, RB>(
        &self,
        send: &Mutex<impl RawMutex, S>,
        mut recv: R,
        tx_buf: SB,
        rx_buf: RB,
        host: &Host<'_>,
        ipv4_interface: Option<Ipv4Addr>,
        ipv6_interface: Option<u32>,
        rand: Rand,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
        SB: BufferAccess<[u8]>,
        RB: BufferAccess<[u8]>,
    {
        loop {
            recv.wait_available().await?;

            {
                let mut rx = rx_buf.get().await.ok_or(ErrorCode::NoSpace)?;
                let (len, addr) = recv.recv_from(&mut rx).await?;

                let mut tx = tx_buf.get().await.ok_or(ErrorCode::NoSpace)?;
                let mut send = send.lock().await;

                let (len, delay) = match host.respond(self, &rx[..len], &mut tx, 60) {
                    Ok((len, delay)) => (len, delay),
                    Err(err) => {
                        warn!("mDNS protocol error {err} while replying to {addr}");
                        continue;
                    }
                };

                if len > 0 {
                    let ipv4 = addr
                        .udp()
                        .map(|addr| matches!(addr.ip(), IpAddr::V4(_)))
                        .unwrap_or(true);

                    let reply_addr = if ipv4 {
                        ipv4_interface.map(|_| {
                            SocketAddr::V4(SocketAddrV4::new(MDNS_IPV4_BROADCAST_ADDR, MDNS_PORT))
                        })
                    } else {
                        ipv6_interface.map(|interface| {
                            SocketAddr::V6(SocketAddrV6::new(
                                MDNS_IPV6_BROADCAST_ADDR,
                                MDNS_PORT,
                                0,
                                interface,
                            ))
                        })
                    };

                    if let Some(reply_addr) = reply_addr {
                        if delay {
                            let mut b = [0];
                            rand(&mut b);

                            // Generate a delay between 20 and 120 ms, as per spec
                            let delay_ms = 20 + (b[0] as u32 * 100 / 256);

                            info!("Replying to mDNS query from {addr} on {reply_addr}, delay {delay_ms}ms");
                            Timer::after(Duration::from_millis(delay_ms as _)).await;
                        } else {
                            info!("Replying to mDNS query from {addr} on {reply_addr}");
                        }

                        send.send_to(&tx[..len], Address::Udp(reply_addr)).await?;
                    } else {
                        info!("Cannot reply to mDNS query from {addr}: no suitable broadcast address found");
                    }
                }
            }
        }
    }
}

impl<'a> Services for MdnsImpl<'a> {
    fn for_each<F>(&self, callback: F) -> Result<(), Error>
    where
        F: FnMut(&Service) -> Result<(), Error>,
    {
        MdnsImpl::for_each(self, callback)
    }
}
