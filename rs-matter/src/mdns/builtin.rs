use core::{cell::RefCell, pin::pin};

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
use crate::utils::{
    buf::BufferAccess,
    select::{EitherUnwrap, Notification},
};

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
    services: RefCell<heapless::Vec<(heapless::String<40>, ServiceMode), 4>>,
    notification: Notification,
}

impl<'a> MdnsImpl<'a> {
    #[inline(always)]
    pub const fn new(dev_det: &'a BasicInfoConfig<'a>, matter_port: u16) -> Self {
        Self {
            dev_det,
            matter_port,
            services: RefCell::new(heapless::Vec::new()),
            notification: Notification::new(),
        }
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

        self.notification.signal(());

        Ok(())
    }

    pub fn remove(&self, service: &str) -> Result<(), Error> {
        let mut services = self.services.borrow_mut();

        services.retain(|(name, _)| name != service);

        self.notification.signal(());

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

    pub async fn run<S, R, SB, RB>(
        &self,
        send: S,
        recv: R,
        tx_buf: SB,
        rx_buf: RB,
        host: Host<'_>,
        interface: Option<u32>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
        SB: BufferAccess,
        RB: BufferAccess,
    {
        let send = Mutex::<NoopRawMutex, _>::new(send);

        let mut broadcast = pin!(self.broadcast(&send, &tx_buf, &host, interface));
        let mut respond = pin!(self.respond(&send, recv, &tx_buf, &rx_buf, &host, interface));

        select(&mut broadcast, &mut respond).await.unwrap()
    }

    async fn broadcast<S, B>(
        &self,
        send: &Mutex<impl RawMutex, S>,
        buffer: B,
        host: &Host<'_>,
        interface: Option<u32>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        B: BufferAccess,
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
                interface
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
                let mut buf = buffer.get().await;
                let mut send = send.lock().await;

                let len = host.broadcast(self, &mut buf, 60)?;

                if len > 0 {
                    info!("Broadcasting mDNS entry to {addr}");
                    send.send_to(&buf[..len], Address::Udp(addr)).await?;
                }
            }
        }
    }

    async fn respond<S, R, SB, RB>(
        &self,
        send: &Mutex<impl RawMutex, S>,
        mut recv: R,
        tx_buf: SB,
        rx_buf: RB,
        host: &Host<'_>,
        _interface: Option<u32>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
        SB: BufferAccess,
        RB: BufferAccess,
    {
        loop {
            recv.wait_available().await?;

            {
                let mut rx = rx_buf.get().await;
                let (len, addr) = recv.recv_from(&mut rx).await?;

                let mut tx = tx_buf.get().await;
                let mut send = send.lock().await;

                let len = match host.respond(self, &rx[..len], &mut tx, 60) {
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

                    send.send_to(&tx[..len], addr).await?;
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
