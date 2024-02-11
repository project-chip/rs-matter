use core::{cell::RefCell, pin::pin};

use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Timer};
use log::{info, warn};

use crate::data_model::cluster_basic_information::BasicInfoConfig;
use crate::error::{Error, ErrorCode};
use crate::transport::network::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpBuffers, UdpReceive, UdpSend,
};
use crate::utils::select::{EitherUnwrap, Notification};

use super::{
    proto::{Host, Services},
    Service, ServiceMode,
};

pub const MDNS_SOCKET_BIND_ADDR: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0));

pub const MDNS_IPV6_BROADCAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);
pub const MDNS_IPV4_BROADCAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

pub const MDNS_PORT: u16 = 5353;

pub struct MdnsService<'a> {
    host: Host<'a>,
    #[allow(unused)]
    interface: Option<u32>,
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
        ipv6: Option<([u8; 16], u32)>,
        dev_det: &'a BasicInfoConfig<'a>,
        matter_port: u16,
    ) -> Self {
        Self {
            host: Host {
                id,
                hostname,
                ip,
                ipv6: if let Some((ipv6, _)) = ipv6 {
                    Some(ipv6)
                } else {
                    None
                },
            },
            interface: if let Some((_, interface)) = ipv6 {
                Some(interface)
            } else {
                None
            },
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
            .push((service.try_into().unwrap(), mode))
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

    pub async fn run<S, R>(
        &self,
        send: S,
        recv: R,
        udp_buffers: &mut UdpBuffers,
    ) -> Result<(), Error>
    where
        S: UdpSend,
        R: UdpReceive,
    {
        let (send_buf, recv_buf) = udp_buffers.split();

        let send = Mutex::<NoopRawMutex, _>::new((send, send_buf));

        let mut broadcast = pin!(self.broadcast(&send));
        let mut respond = pin!(self.respond(recv, recv_buf, &send));

        select(&mut broadcast, &mut respond).await.unwrap()
    }

    async fn broadcast<S>(&self, send: &Mutex<impl RawMutex, (S, &mut [u8])>) -> Result<(), Error>
    where
        S: UdpSend,
    {
        loop {
            select(
                self.notification.wait(),
                Timer::after(Duration::from_secs(30)),
            )
            .await;

            for addr in core::iter::once(SocketAddr::V4(SocketAddrV4::new(
                MDNS_IPV4_BROADCAST_ADDR,
                MDNS_PORT,
            )))
            .chain(
                self.interface
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
                let mut guard = send.lock().await;
                let (send, send_buf) = &mut *guard;

                let len = self.host.broadcast(self, send_buf, 60)?;

                if len > 0 {
                    info!("Broadcasting mDNS entry to {addr}");
                    send.send_to(&send_buf[..len], addr).await?;
                }
            }
        }
    }

    async fn respond<S, R>(
        &self,
        mut recv: R,
        recv_buf: &mut [u8],
        send: &Mutex<impl RawMutex, (S, &mut [u8])>,
    ) -> Result<(), Error>
    where
        S: UdpSend,
        R: UdpReceive,
    {
        loop {
            let (len, addr) = recv.recv_from(recv_buf).await?;

            let mut guard = send.lock().await;
            let (send, send_buf) = &mut *guard;

            let len = match self.host.respond(self, &recv_buf[..len], send_buf, 60) {
                Ok(len) => len,
                Err(err) => match err.code() {
                    ErrorCode::MdnsError => {
                        warn!("Got invalid message from {addr}, skipping");
                        continue;
                    }
                    other => Err(other)?,
                },
            };

            if len > 0 {
                info!("Replying to mDNS query from {}", addr);

                send.send_to(&send_buf[..len], addr).await?;
            }
        }
    }
}

impl<'a> Services for MdnsService<'a> {
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
