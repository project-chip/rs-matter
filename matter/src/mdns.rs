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
        &mut self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
        service_subtypes: &[&str],
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error>;

    fn remove(&mut self, name: &str, service: &str, protocol: &str, port: u16)
        -> Result<(), Error>;
}

impl<T> Mdns for &mut T
where
    T: Mdns,
{
    fn add(
        &mut self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
        service_subtypes: &[&str],
        txt_kvs: &[(&str, &str)],
    ) -> Result<(), Error> {
        (**self).add(name, service, protocol, port, service_subtypes, txt_kvs)
    }

    fn remove(
        &mut self,
        name: &str,
        service: &str,
        protocol: &str,
        port: u16,
    ) -> Result<(), Error> {
        (**self).remove(name, service, protocol, port)
    }
}

pub struct DummyMdns;

impl Mdns for DummyMdns {
    fn add(
        &mut self,
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
        &mut self,
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
    device_name: heapless::String<32>,
    /// Matter port
    matter_port: u16,
    /// mDns service
    mdns: &'a mut dyn Mdns,
}

impl<'a> MdnsMgr<'a> {
    #[inline(always)]
    pub fn new(
        vid: u16,
        pid: u16,
        device_name: &str,
        matter_port: u16,
        mdns: &'a mut dyn Mdns,
    ) -> Self {
        Self {
            vid,
            pid,
            device_name: device_name.chars().take(32).collect(),
            matter_port,
            mdns,
        }
    }

    /// Publish an mDNS service
    /// name - is the service name (comma separated subtypes may follow)
    /// mode - the current service mode
    #[allow(clippy::needless_pass_by_value)]
    pub fn publish_service(&mut self, name: &str, mode: ServiceMode) -> Result<(), Error> {
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
                    ("DN", self.device_name.as_str()),
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

    pub fn unpublish_service(&mut self, name: &str, mode: ServiceMode) -> Result<(), Error> {
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
    use core::pin::pin;
    use core::str::FromStr;

    use domain::base::header::Flags;
    use domain::base::iana::Class;
    use domain::base::octets::{Octets256, Octets64, OctetsBuilder};
    use domain::base::{Dname, MessageBuilder, Record, ShortBuf};
    use domain::rdata::{Aaaa, Ptr, Srv, Txt, A};
    use embassy_futures::select::select;
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embassy_time::{Duration, Timer};
    use log::info;

    use crate::error::{Error, ErrorCode};
    use crate::transport::network::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use crate::transport::udp::UdpListener;
    use crate::utils::select::EitherUnwrap;

    const IP_BROADCAST_ADDRS: [SocketAddr; 2] = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353),
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb)),
            5353,
        ),
    ];

    const IP_BIND_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 5353);

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

    pub type Notification = embassy_sync::signal::Signal<NoopRawMutex, ()>;

    #[derive(Debug, Clone)]
    struct MdnsEntry {
        key: heapless::String<64>,
        record: heapless::Vec<u8, 1024>,
    }

    impl MdnsEntry {
        #[inline(always)]
        const fn new() -> Self {
            Self {
                key: heapless::String::new(),
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
        udp: RefCell<Option<UdpListener>>,
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
                udp: RefCell::new(None),
            }
        }

        pub fn split(&mut self) -> (MdnsApi<'_, 'a>, MdnsRunner<'_, 'a>) {
            (MdnsApi(&*self), MdnsRunner(&*self))
        }

        async fn bind(&self) -> Result<(), Error> {
            if self.udp.borrow().is_none() {
                *self.udp.borrow_mut() = Some(UdpListener::new(IP_BIND_ADDR).await?);
            }

            Ok(())
        }

        pub fn close(&mut self) {
            *self.udp.borrow_mut() = None;
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

    pub struct MdnsApi<'a, 'b>(&'a Mdns<'b>);

    impl<'a, 'b> MdnsApi<'a, 'b> {
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

            let key = self.0.key(name, service, protocol, port);

            let mut entries = self.0.entries.borrow_mut();

            entries.retain(|entry| entry.key != key);
            entries
                .push(MdnsEntry::new())
                .map_err(|_| ErrorCode::NoSpace)?;

            let entry = entries.iter_mut().last().unwrap();
            entry
                .record
                .resize(1024, 0)
                .map_err(|_| ErrorCode::NoSpace)
                .unwrap();

            match create_record(
                self.0.id,
                self.0.hostname,
                self.0.ip,
                self.0.ipv6,
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

            self.0.notification.signal(());

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

            let key = self.0.key(name, service, protocol, port);

            let mut entries = self.0.entries.borrow_mut();

            let old_len = entries.len();

            entries.retain(|entry| entry.key != key);

            if entries.len() != old_len {
                self.0.notification.signal(());
            }

            Ok(())
        }
    }

    pub struct MdnsRunner<'a, 'b>(&'a Mdns<'b>);

    impl<'a, 'b> MdnsRunner<'a, 'b> {
        pub async fn run(&mut self) -> Result<(), Error> {
            let mut broadcast = pin!(self.broadcast());
            let mut respond = pin!(self.respond());

            select(&mut broadcast, &mut respond).await.unwrap()
        }

        async fn broadcast(&self) -> Result<(), Error> {
            loop {
                select(
                    self.0.notification.wait(),
                    Timer::after(Duration::from_secs(30)),
                )
                .await;

                let mut index = 0;

                while let Some(entry) = self
                    .0
                    .entries
                    .borrow()
                    .get(index)
                    .map(|entry| entry.clone())
                {
                    info!("Broadasting mDNS entry {}", &entry.key);

                    self.0.bind().await?;

                    let udp = self.0.udp.borrow();
                    let udp = udp.as_ref().unwrap();

                    for addr in IP_BROADCAST_ADDRS {
                        udp.send(addr, &entry.record).await?;
                    }

                    index += 1;
                }
            }
        }

        async fn respond(&self) -> Result<(), Error> {
            loop {
                let mut buf = [0; 1580];

                let udp = self.0.udp.borrow();
                let udp = udp.as_ref().unwrap();

                let (_len, _addr) = udp.recv(&mut buf).await?;

                info!("Received UDP packet");

                // TODO: Process the incoming packed and only answer what we are being queried about

                self.0.notification.signal(());
            }
        }
    }

    impl<'a, 'b> super::Mdns for MdnsApi<'a, 'b> {
        fn add(
            &mut self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
            service_subtypes: &[&str],
            txt_kvs: &[(&str, &str)],
        ) -> Result<(), Error> {
            MdnsApi::add(
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
            &mut self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
        ) -> Result<(), Error> {
            MdnsApi::remove(self, name, service, protocol, port)
        }
    }
}

#[cfg(all(feature = "std", feature = "astro-dnssd"))]
pub mod astro {
    use std::collections::HashMap;

    use super::Mdns;
    use crate::error::{Error, ErrorCode};
    use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};
    use log::info;

    #[derive(Debug, Clone, Eq, PartialEq, Hash)]
    pub struct ServiceId {
        name: String,
        service: String,
        protocol: String,
        port: u16,
    }

    pub struct AstroMdns {
        services: HashMap<ServiceId, RegisteredDnsService>,
    }

    impl AstroMdns {
        pub fn new() -> Result<Self, Error> {
            Ok(Self {
                services: HashMap::new(),
            })
        }

        pub fn add(
            &mut self,
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

            self.services.insert(
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
            &mut self,
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

            if self.services.remove(&id).is_some() {
                info!(
                    "Deregistering mDNS service {}/{}.{}/{}",
                    name, service, protocol, port
                );
            }

            Ok(())
        }
    }

    impl Mdns for AstroMdns {
        fn add(
            &mut self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
            service_subtypes: &[&str],
            txt_kvs: &[(&str, &str)],
        ) -> Result<(), Error> {
            AstroMdns::add(
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
            &mut self,
            name: &str,
            service: &str,
            protocol: &str,
            port: u16,
        ) -> Result<(), Error> {
            AstroMdns::remove(self, name, service, protocol, port)
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
