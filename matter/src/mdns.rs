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

use core::fmt::Write;

use crate::error::Error;

pub trait Mdns {
    fn add(
        &self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
        service_subtypes: &[&str],
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error>;

    fn remove(&self, name: &str, service: &str, protocol: &str, port: u16) -> Result<(), Error>;
}

impl<T> Mdns for &mut T
where
    T: Mdns,
{
    fn add(
        &self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
        service_subtypes: &[&str],
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        (**self).add(name, service, protocol, port, service_subtypes, txt_kvs)
    }

    fn remove(&self, name: &str, service: &str, protocol: &str, port: u16) -> Result<(), Error> {
        (**self).remove(name, service, protocol, port)
    }
}

impl<T> Mdns for &T
where
    T: Mdns,
{
    fn add(
        &self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
        service_subtypes: &[&str],
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        (**self).add(name, service, protocol, port, service_subtypes, txt_kvs)
    }

    fn remove(&self, name: &str, service: &str, protocol: &str, port: u16) -> Result<(), Error> {
        (**self).remove(name, service, protocol, port)
    }
}

#[cfg(all(feature = "std", feature = "astro-dnssd"))]
pub type DefaultMdns = astro::Mdns;

#[cfg(all(feature = "std", feature = "astro-dnssd"))]
pub type DefaultMdnsRunner<'a> = astro::MdnsRunner<'a>;

#[cfg(not(all(feature = "std", feature = "astro-dnssd")))]
pub type DefaultMdns<'a> = builtin::Mdns<'a>;

#[cfg(not(all(feature = "std", feature = "astro-dnssd")))]
pub type DefaultMdnsRunner<'a> = builtin::MdnsRunner<'a>;

pub struct DummyMdns;

impl Mdns for DummyMdns {
    fn add(
        &self,
        _name: &str,
        _service: &str,
        _protocol: &str,
        _port: u16,
        _service_subtypes: &[&str],
        _txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        Ok(())
    }

    fn remove(
        &self,
        _name: &str,
        _service: &str,
        _protocol: &str,
        _port: u16,
    ) -> Result<(), Error> {
        Ok(())
    }
}

pub enum ServiceMode {
    /// The commissioned state
    Commissioned,
    /// The commissionable state with the discriminator that should be used
    Commissionable(u16),
}

/// The mDNS service handler
pub struct MdnsMgr<'a> {
    /// Vendor ID
    vid: u16,
    /// Product ID
    pid: u16,
    /// Device name
    device_name: &'a str,
    /// Matter port
    matter_port: u16,
    /// mDns service
    pub(crate) mdns: &'a dyn Mdns,
}

impl<'a> MdnsMgr<'a> {
    #[inline(always)]
    pub fn new(
        vid: u16,
        pid: u16,
        device_name: &'a str,
        matter_port: u16,
        mdns: &'a dyn Mdns,
    ) -> Self {
        Self {
            vid,
            pid,
            device_name,
            matter_port,
            mdns,
        }
    }

    /// Publish an mDNS service
    /// name - is the service name (comma separated subtypes may follow)
    /// mode - the current service mode
    #[allow(clippy::needless_pass_by_value)]
    pub fn publish_service(&self, name: &str, mode: ServiceMode) -> Result<(), Error> {
        match mode {
            ServiceMode::Commissioned => {
                self.mdns
                    .add(name, "_matter", "_tcp", self.matter_port, &[], &[])
            }
            ServiceMode::Commissionable(discriminator) => {
                let discriminator_str = Self::get_discriminator_str(discriminator);
                let vp = self.get_vp();

                let txt_kvs = [
                    ("D", discriminator_str.as_str()),
                    ("CM", "1"),
                    ("DN", self.device_name),
                    ("VP", &vp),
                    ("SII", "5000"), /* Sleepy Idle Interval */
                    ("SAI", "300"),  /* Sleepy Active Interval */
                    ("PH", "33"),    /* Pairing Hint */
                    ("PI", ""),      /* Pairing Instruction */
                ];

                self.mdns.add(
                    name,
                    "_matterc",
                    "_udp",
                    self.matter_port,
                    &[
                        &self.get_long_service_subtype(discriminator),
                        &self.get_short_service_type(discriminator),
                    ],
                    &txt_kvs,
                )
            }
        }
    }

    pub fn unpublish_service(&self, name: &str, mode: ServiceMode) -> Result<(), Error> {
        match mode {
            ServiceMode::Commissioned => {
                self.mdns.remove(name, "_matter", "_tcp", self.matter_port)
            }
            ServiceMode::Commissionable(_) => {
                self.mdns.remove(name, "_matterc", "_udp", self.matter_port)
            }
        }
    }

    fn get_long_service_subtype(&self, discriminator: u16) -> heapless::String<32> {
        let mut serv_type = heapless::String::new();
        write!(&mut serv_type, "_L{}", discriminator).unwrap();

        serv_type
    }

    fn get_short_service_type(&self, discriminator: u16) -> heapless::String<32> {
        let short = Self::compute_short_discriminator(discriminator);

        let mut serv_type = heapless::String::new();
        write!(&mut serv_type, "_S{}", short).unwrap();

        serv_type
    }

    fn get_discriminator_str(discriminator: u16) -> heapless::String<5> {
        discriminator.into()
    }

    fn get_vp(&self) -> heapless::String<11> {
        let mut vp = heapless::String::new();

        write!(&mut vp, "{}+{}", self.vid, self.pid).unwrap();

        vp
    }

    fn compute_short_discriminator(discriminator: u16) -> u16 {
        const SHORT_DISCRIMINATOR_MASK: u16 = 0xF00;
        const SHORT_DISCRIMINATOR_SHIFT: u16 = 8;

        (discriminator & SHORT_DISCRIMINATOR_MASK) >> SHORT_DISCRIMINATOR_SHIFT
    }
}

pub mod builtin {
    use core::cell::RefCell;
    use core::fmt::Write;
    use core::mem::MaybeUninit;
    use core::pin::pin;
    use core::str::FromStr;

    use domain::base::header::Flags;
    use domain::base::iana::Class;
    use domain::base::octets::{Octets256, Octets64, OctetsBuilder};
    use domain::base::{Dname, MessageBuilder, Record, ShortBuf};
    use domain::rdata::{Aaaa, Ptr, Srv, Txt, A};
    use embassy_futures::select::{select, select3};
    use embassy_time::{Duration, Timer};
    use log::info;

    use crate::error::{Error, ErrorCode};
    use crate::transport::network::{Address, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use crate::transport::packet::{MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE};
    use crate::transport::pipe::{Chunk, Pipe};
    use crate::transport::udp::UdpListener;
    use crate::utils::select::{EitherUnwrap, Notification};

    const IP_BROADCAST_ADDRS: [(IpAddr, u16); 2] = [
        (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353),
        (
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb)),
            5353,
        ),
    ];

    const IP_BIND_ADDR: (IpAddr, u16) = (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 5353);

    type MdnsTxBuf = MaybeUninit<[u8; MAX_TX_BUF_SIZE]>;
    type MdnsRxBuf = MaybeUninit<[u8; MAX_RX_BUF_SIZE]>;

    #[allow(clippy::too_many_arguments)]
    pub fn create_record(
        id: u16,
        hostname: &str,
        ip: [u8; 4],
        ipv6: Option<[u8; 16]>,

        ttl_sec: u32,

        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
        service_subtypes: &[&str],
        txt_kvs: &[(&str, &str)],

        buffer: &mut [u8],
    ) -> Result<usize, ShortBuf> {
        let target = domain::base::octets::Octets2048::new();
        let message = MessageBuilder::from_target(target)?;

        let mut message = message.answer();

        let mut ptr_str = heapless::String::<40>::new();
        write!(ptr_str, "{}.{}.local", service, protocol).unwrap();

        let mut dname = heapless::String::<60>::new();
        write!(dname, "{}.{}.{}.local", name, service, protocol).unwrap();

        let mut hname = heapless::String::<40>::new();
        write!(hname, "{}.local", hostname).unwrap();

        let ptr: Dname<Octets64> = Dname::from_str(&ptr_str).unwrap();
        let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
            Dname::from_str("_services._dns-sd._udp.local").unwrap(),
            Class::In,
            ttl_sec,
            Ptr::new(ptr),
        );
        message.push(record)?;

        let t: Dname<Octets64> = Dname::from_str(&dname).unwrap();
        let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
            Dname::from_str(&ptr_str).unwrap(),
            Class::In,
            ttl_sec,
            Ptr::new(t),
        );
        message.push(record)?;

        for sub_srv in service_subtypes {
            let mut ptr_str = heapless::String::<40>::new();
            write!(ptr_str, "{}._sub.{}.{}.local", sub_srv, service, protocol).unwrap();

            let ptr: Dname<Octets64> = Dname::from_str(&ptr_str).unwrap();
            let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
                Dname::from_str("_services._dns-sd._udp.local").unwrap(),
                Class::In,
                ttl_sec,
                Ptr::new(ptr),
            );
            message.push(record)?;

            let t: Dname<Octets64> = Dname::from_str(&dname).unwrap();
            let record: Record<Dname<Octets64>, Ptr<_>> = Record::new(
                Dname::from_str(&ptr_str).unwrap(),
                Class::In,
                ttl_sec,
                Ptr::new(t),
            );
            message.push(record)?;
        }

        let target: Dname<Octets64> = Dname::from_str(&hname).unwrap();
        let record: Record<Dname<Octets64>, Srv<_>> = Record::new(
            Dname::from_str(&dname).unwrap(),
            Class::In,
            ttl_sec,
            Srv::new(0, 0, port, target),
        );
        message.push(record)?;

        // only way I found to create multiple parts in a Txt
        // each slice is the length and then the data
        let mut octets = Octets256::new();
        //octets.append_slice(&[1u8, b'X']).unwrap();
        //octets.append_slice(&[2u8, b'A', b'B']).unwrap();
        //octets.append_slice(&[0u8]).unwrap();
        for (k, v) in txt_kvs {
            octets
                .append_slice(&[(k.len() + v.len() + 1) as u8])
                .unwrap();
            octets.append_slice(k.as_bytes()).unwrap();
            octets.append_slice(&[b'=']).unwrap();
            octets.append_slice(v.as_bytes()).unwrap();
        }

        let txt = Txt::from_octets(&mut octets).unwrap();

        let record: Record<Dname<Octets64>, Txt<_>> =
            Record::new(Dname::from_str(&dname).unwrap(), Class::In, ttl_sec, txt);
        message.push(record)?;

        let record: Record<Dname<Octets64>, A> = Record::new(
            Dname::from_str(&hname).unwrap(),
            Class::In,
            ttl_sec,
            A::from_octets(ip[0], ip[1], ip[2], ip[3]),
        );
        message.push(record)?;

        if let Some(ipv6) = ipv6 {
            let record: Record<Dname<Octets64>, Aaaa> = Record::new(
                Dname::from_str(&hname).unwrap(),
                Class::In,
                ttl_sec,
                Aaaa::new(ipv6.into()),
            );
            message.push(record)?;
        }

        let headerb = message.header_mut();
        headerb.set_id(id);
        headerb.set_opcode(domain::base::iana::Opcode::Query);
        headerb.set_rcode(domain::base::iana::Rcode::NoError);

        let mut flags = Flags::new();
        flags.qr = true;
        flags.aa = true;
        headerb.set_flags(flags);

        let target = message.finish();

        buffer[..target.len()].copy_from_slice(target.as_ref());

        Ok(target.len())
    }

    #[derive(Debug, Clone)]
    struct MdnsEntry {
        key: heapless::String<64>,
        record: heapless::Vec<u8, 1024>,
    }

    impl MdnsEntry {
        #[inline(always)]
        const fn new(key: heapless::String<64>) -> Self {
            Self {
                key,
                record: heapless::Vec::new(),
            }
        }
    }

    pub struct Mdns<'a> {
        id: u16,
        hostname: &'a str,
        ip: [u8; 4],
        ipv6: Option<[u8; 16]>,
        entries: RefCell<heapless::Vec<MdnsEntry, 4>>,
        notification: Notification,
    }

    impl<'a> Mdns<'a> {
        #[inline(always)]
        pub const fn new(id: u16, hostname: &'a str, ip: [u8; 4], ipv6: Option<[u8; 16]>) -> Self {
            Self {
                id,
                hostname,
                ip,
                ipv6,
                entries: RefCell::new(heapless::Vec::new()),
                notification: Notification::new(),
            }
        }

        pub fn add(
            &self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
            service_subtypes: &[&str],
            txt_kvs: &[(&str, &str)],
        ) -> Result<(), Error> {
            info!(
                "Registering mDNS service {}/{}.{} [{:?}]/{}, keys [{:?}]",
                name, service, protocol, service_subtypes, port, txt_kvs
            );

            let key = self.key(name, service, protocol, port);

            let mut entries = self.entries.borrow_mut();

            entries.retain(|entry| entry.key != key);
            entries
                .push(MdnsEntry::new(key))
                .map_err(|_| ErrorCode::NoSpace)?;

            let entry = entries.iter_mut().last().unwrap();
            entry
                .record
                .resize(1024, 0)
                .map_err(|_| ErrorCode::NoSpace)
                .unwrap();

            match create_record(
                self.id,
                self.hostname,
                self.ip,
                self.ipv6,
                60, /*ttl_sec*/
                name,
                service,
                protocol,
                port,
                service_subtypes,
                txt_kvs,
                &mut entry.record,
            ) {
                Ok(len) => entry.record.truncate(len),
                Err(_) => {
                    entries.pop();
                    Err(ErrorCode::NoSpace)?;
                }
            }

            self.notification.signal(());

            Ok(())
        }

        pub fn remove(
            &self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
        ) -> Result<(), Error> {
            info!(
                "Deregistering mDNS service {}/{}.{}/{}",
                name, service, protocol, port
            );

            let key = self.key(name, service, protocol, port);

            let mut entries = self.entries.borrow_mut();

            let old_len = entries.len();

            entries.retain(|entry| entry.key != key);

            if entries.len() != old_len {
                self.notification.signal(());
            }

            Ok(())
        }

        fn key(
            &self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
        ) -> heapless::String<64> {
            let mut key = heapless::String::new();

            write!(&mut key, "{name}.{service}.{protocol}.{port}").unwrap();

            key
        }
    }

    pub struct MdnsRunner<'a>(&'a Mdns<'a>);

    impl<'a> MdnsRunner<'a> {
        pub const fn new(mdns: &'a Mdns<'a>) -> Self {
            Self(mdns)
        }

        pub async fn run_udp(&mut self) -> Result<(), Error> {
            let mut tx_buf = MdnsTxBuf::uninit();
            let mut rx_buf = MdnsRxBuf::uninit();

            let tx_buf = &mut tx_buf;
            let rx_buf = &mut rx_buf;

            let tx_pipe = Pipe::new(unsafe { tx_buf.assume_init_mut() });
            let rx_pipe = Pipe::new(unsafe { rx_buf.assume_init_mut() });

            let tx_pipe = &tx_pipe;
            let rx_pipe = &rx_pipe;

            let udp = UdpListener::new(SocketAddr::new(IP_BIND_ADDR.0, IP_BIND_ADDR.1)).await?;
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

            select3(&mut tx, &mut rx, &mut run).await.unwrap()
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

                let mut index = 0;

                'outer: loop {
                    for (addr, port) in IP_BROADCAST_ADDRS {
                        loop {
                            {
                                let mut data = tx_pipe.data.lock().await;

                                if data.chunk.is_none() {
                                    let entries = self.0.entries.borrow();
                                    let entry = entries.get(index);

                                    if let Some(entry) = entry {
                                        info!(
                                            "Broadasting mDNS entry {} on {}:{}",
                                            &entry.key, addr, port
                                        );

                                        let len = entry.record.len();
                                        data.buf[..len].copy_from_slice(&entry.record);
                                        drop(entries);

                                        data.chunk = Some(Chunk {
                                            start: 0,
                                            end: len,
                                            addr: Address::Udp(SocketAddr::new(addr, port)),
                                        });

                                        tx_pipe.data_supplied_notification.signal(());
                                    } else {
                                        break 'outer;
                                    }

                                    break;
                                }
                            }

                            tx_pipe.data_consumed_notification.wait().await;
                        }
                    }

                    index += 1;
                }
            }
        }

        #[allow(clippy::await_holding_refcell_ref)]
        async fn respond(&self, rx_pipe: &Pipe<'_>, _tx_pipe: &Pipe<'_>) -> Result<(), Error> {
            loop {
                {
                    let mut data = rx_pipe.data.lock().await;

                    if let Some(_chunk) = data.chunk {
                        // TODO: Process the incoming packed and only answer what we are being queried about

                        data.chunk = None;
                        rx_pipe.data_consumed_notification.signal(());

                        self.0.notification.signal(());
                    }
                }

                rx_pipe.data_supplied_notification.wait().await;
            }
        }
    }

    impl<'a, 'b> super::Mdns for Mdns<'a> {
        fn add(
            &self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
            service_subtypes: &[&str],
            txt_kvs: &[(&str, &str)],
        ) -> Result<(), Error> {
            Mdns::add(
                self,
                name,
                service,
                protocol,
                port,
                service_subtypes,
                txt_kvs,
            )
        }

        fn remove(
            &self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
        ) -> Result<(), Error> {
            Mdns::remove(self, name, service, protocol, port)
        }
    }
}

#[cfg(all(feature = "std", feature = "astro-dnssd"))]
pub mod astro {
    use core::cell::RefCell;
    use std::collections::HashMap;

    use crate::{
        error::{Error, ErrorCode},
        transport::pipe::Pipe,
    };
    use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};
    use log::info;

    #[derive(Debug, Clone, Eq, PartialEq, Hash)]
    struct ServiceId {
        name: String,
        service: String,
        protocol: String,
        port: u16,
    }

    pub struct Mdns {
        services: RefCell<HashMap<ServiceId, RegisteredDnsService>>,
    }

    impl Mdns {
        pub fn new(_id: u16, _hostname: &str, _ip: [u8; 4], _ipv6: Option<[u8; 16]>) -> Self {
            Self::native_new()
        }

        pub fn native_new() -> Self {
            Self {
                services: RefCell::new(HashMap::new()),
            }
        }

        pub fn add(
            &self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
            service_subtypes: &[&str],
            txt_kvs: &[(&str, &str)],
        ) -> Result<(), Error> {
            info!(
                "Registering mDNS service {}/{}.{} [{:?}]/{}",
                name, service, protocol, service_subtypes, port
            );

            let _ = self.remove(name, service, protocol, port);

            let composite_service_type = if !service_subtypes.is_empty() {
                format!("{}.{},{}", service, protocol, service_subtypes.join(","))
            } else {
                format!("{}.{}", service, protocol)
            };

            let mut builder = DNSServiceBuilder::new(&composite_service_type, port).with_name(name);

            for kvs in txt_kvs {
                info!("mDNS TXT key {} val {}", kvs.0, kvs.1);
                builder = builder.with_key_value(kvs.0.to_string(), kvs.1.to_string());
            }

            let svc = builder.register().map_err(|_| ErrorCode::MdnsError)?;

            self.services.borrow_mut().insert(
                ServiceId {
                    name: name.into(),
                    service: service.into(),
                    protocol: protocol.into(),
                    port,
                },
                svc,
            );

            Ok(())
        }

        pub fn remove(
            &self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
        ) -> Result<(), Error> {
            let id = ServiceId {
                name: name.into(),
                service: service.into(),
                protocol: protocol.into(),
                port,
            };

            if self.services.borrow_mut().remove(&id).is_some() {
                info!(
                    "Deregistering mDNS service {}/{}.{}/{}",
                    name, service, protocol, port
                );
            }

            Ok(())
        }
    }

    pub struct MdnsRunner<'a>(&'a Mdns);

    impl<'a> MdnsRunner<'a> {
        pub const fn new(mdns: &'a Mdns) -> Self {
            Self(mdns)
        }

        pub async fn run_udp(&mut self) -> Result<(), Error> {
            core::future::pending::<Result<(), Error>>().await
        }

        pub async fn run(&self, _tx_pipe: &Pipe<'_>, _rx_pipe: &Pipe<'_>) -> Result<(), Error> {
            core::future::pending::<Result<(), Error>>().await
        }
    }

    impl super::Mdns for Mdns {
        fn add(
            &self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
            service_subtypes: &[&str],
            txt_kvs: &[(&str, &str)],
        ) -> Result<(), Error> {
            Mdns::add(
                self,
                name,
                service,
                protocol,
                port,
                service_subtypes,
                txt_kvs,
            )
        }

        fn remove(
            &self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
        ) -> Result<(), Error> {
            Mdns::remove(self, name, service, protocol, port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_compute_short_discriminator() {
        let discriminator: u16 = 0b0000_1111_0000_0000;
        let short = MdnsMgr::compute_short_discriminator(discriminator);
        assert_eq!(short, 0b1111);

        let discriminator: u16 = 840;
        let short = MdnsMgr::compute_short_discriminator(discriminator);
        assert_eq!(short, 3);
    }
}
