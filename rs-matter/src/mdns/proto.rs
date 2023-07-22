use core::fmt::Write;
use core::str::FromStr;

use domain::{
    base::{
        header::Flags,
        iana::Class,
        message_builder::AnswerBuilder,
        name::FromStrError,
        octets::{Octets256, Octets64, OctetsBuilder, ParseError},
        Dname, Message, MessageBuilder, Record, Rtype, ShortBuf, ToDname,
    },
    rdata::{Aaaa, Ptr, Srv, Txt, A},
};
use log::trace;

pub trait Services {
    type Error: From<ShortBuf> + From<ParseError> + From<FromStrError>;

    fn for_each<F>(&self, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Service) -> Result<(), Self::Error>;
}

impl<T> Services for &mut T
where
    T: Services,
{
    type Error = T::Error;

    fn for_each<F>(&self, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Service) -> Result<(), Self::Error>,
    {
        (**self).for_each(callback)
    }
}

impl<T> Services for &T
where
    T: Services,
{
    type Error = T::Error;

    fn for_each<F>(&self, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Service) -> Result<(), Self::Error>,
    {
        (**self).for_each(callback)
    }
}

pub struct Host<'a> {
    pub id: u16,
    pub hostname: &'a str,
    pub ip: [u8; 4],
    pub ipv6: Option<[u8; 16]>,
}

impl<'a> Host<'a> {
    pub fn broadcast<T: Services>(
        &self,
        services: T,
        buf: &mut [u8],
        ttl_sec: u32,
    ) -> Result<usize, T::Error> {
        let buf = Buf(buf, 0);

        let message = MessageBuilder::from_target(buf)?;

        let mut answer = message.answer();

        self.set_broadcast(services, &mut answer, ttl_sec)?;

        let buf = answer.finish();

        Ok(buf.1)
    }

    pub fn respond<T: Services>(
        &self,
        services: T,
        data: &[u8],
        buf: &mut [u8],
        ttl_sec: u32,
    ) -> Result<usize, T::Error> {
        let buf = Buf(buf, 0);

        let message = MessageBuilder::from_target(buf)?;

        let mut answer = message.answer();

        if self.set_response(data, services, &mut answer, ttl_sec)? {
            let buf = answer.finish();

            Ok(buf.1)
        } else {
            Ok(0)
        }
    }

    fn set_broadcast<T, F>(
        &self,
        services: F,
        answer: &mut AnswerBuilder<T>,
        ttl_sec: u32,
    ) -> Result<(), F::Error>
    where
        T: OctetsBuilder + AsMut<[u8]>,
        F: Services,
    {
        self.set_header(answer);

        self.add_ipv4(answer, ttl_sec)?;
        self.add_ipv6(answer, ttl_sec)?;

        services.for_each(|service| {
            service.add_service(answer, self.hostname, ttl_sec)?;
            service.add_service_type(answer, ttl_sec)?;
            service.add_service_subtypes(answer, ttl_sec)?;
            service.add_txt(answer, ttl_sec)?;

            Ok(())
        })?;

        Ok(())
    }

    fn set_response<T, F>(
        &self,
        data: &[u8],
        services: F,
        answer: &mut AnswerBuilder<T>,
        ttl_sec: u32,
    ) -> Result<bool, F::Error>
    where
        T: OctetsBuilder + AsMut<[u8]>,
        F: Services,
    {
        self.set_header(answer);

        let message = Message::from_octets(data)?;

        let mut replied = false;

        for question in message.question() {
            trace!("Handling question {:?}", question);

            let question = question?;

            match question.qtype() {
                Rtype::A
                    if question
                        .qname()
                        .name_eq(&Host::host_fqdn(self.hostname, true)?) =>
                {
                    self.add_ipv4(answer, ttl_sec)?;
                    replied = true;
                }
                Rtype::Aaaa
                    if question
                        .qname()
                        .name_eq(&Host::host_fqdn(self.hostname, true)?) =>
                {
                    self.add_ipv6(answer, ttl_sec)?;
                    replied = true;
                }
                Rtype::Srv => {
                    services.for_each(|service| {
                        if question.qname().name_eq(&service.service_fqdn(true)?) {
                            self.add_ipv4(answer, ttl_sec)?;
                            self.add_ipv6(answer, ttl_sec)?;
                            service.add_service(answer, self.hostname, ttl_sec)?;
                            replied = true;
                        }

                        Ok(())
                    })?;
                }
                Rtype::Ptr => {
                    services.for_each(|service| {
                        if question.qname().name_eq(&Service::dns_sd_fqdn(true)?) {
                            service.add_service_type(answer, ttl_sec)?;
                            replied = true;
                        } else if question.qname().name_eq(&service.service_type_fqdn(true)?) {
                            // TODO
                            self.add_ipv4(answer, ttl_sec)?;
                            self.add_ipv6(answer, ttl_sec)?;
                            service.add_service(answer, self.hostname, ttl_sec)?;
                            service.add_service_type(answer, ttl_sec)?;
                            service.add_service_subtypes(answer, ttl_sec)?;
                            service.add_txt(answer, ttl_sec)?;
                            replied = true;
                        }

                        Ok(())
                    })?;
                }
                Rtype::Txt => {
                    services.for_each(|service| {
                        if question.qname().name_eq(&service.service_fqdn(true)?) {
                            service.add_txt(answer, ttl_sec)?;
                            replied = true;
                        }

                        Ok(())
                    })?;
                }
                Rtype::Any => {
                    // A / AAAA
                    if question
                        .qname()
                        .name_eq(&Host::host_fqdn(self.hostname, true)?)
                    {
                        self.add_ipv4(answer, ttl_sec)?;
                        self.add_ipv6(answer, ttl_sec)?;
                        replied = true;
                    }

                    // PTR
                    services.for_each(|service| {
                        if question.qname().name_eq(&Service::dns_sd_fqdn(true)?) {
                            service.add_service_type(answer, ttl_sec)?;
                            replied = true;
                        } else if question.qname().name_eq(&service.service_type_fqdn(true)?) {
                            // TODO
                            self.add_ipv4(answer, ttl_sec)?;
                            self.add_ipv6(answer, ttl_sec)?;
                            service.add_service(answer, self.hostname, ttl_sec)?;
                            service.add_service_type(answer, ttl_sec)?;
                            service.add_service_subtypes(answer, ttl_sec)?;
                            service.add_txt(answer, ttl_sec)?;
                            replied = true;
                        }

                        Ok(())
                    })?;

                    // SRV
                    services.for_each(|service| {
                        if question.qname().name_eq(&service.service_fqdn(true)?) {
                            self.add_ipv4(answer, ttl_sec)?;
                            self.add_ipv6(answer, ttl_sec)?;
                            service.add_service(answer, self.hostname, ttl_sec)?;
                            replied = true;
                        }

                        Ok(())
                    })?;
                }
                _ => (),
            }
        }

        Ok(replied)
    }

    fn set_header<T: OctetsBuilder + AsMut<[u8]>>(&self, answer: &mut AnswerBuilder<T>) {
        let header = answer.header_mut();
        header.set_id(self.id);
        header.set_opcode(domain::base::iana::Opcode::Query);
        header.set_rcode(domain::base::iana::Rcode::NoError);

        let mut flags = Flags::new();
        flags.qr = true;
        flags.aa = true;
        header.set_flags(flags);
    }

    fn add_ipv4<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        answer: &mut AnswerBuilder<T>,
        ttl_sec: u32,
    ) -> Result<(), ShortBuf> {
        answer.push(Record::<Dname<Octets64>, A>::new(
            Self::host_fqdn(self.hostname, false).unwrap(),
            Class::In,
            ttl_sec,
            A::from_octets(self.ip[0], self.ip[1], self.ip[2], self.ip[3]),
        ))
    }

    fn add_ipv6<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        answer: &mut AnswerBuilder<T>,
        ttl_sec: u32,
    ) -> Result<(), ShortBuf> {
        if let Some(ip) = &self.ipv6 {
            answer.push(Record::<Dname<Octets64>, Aaaa>::new(
                Self::host_fqdn(self.hostname, false).unwrap(),
                Class::In,
                ttl_sec,
                Aaaa::new((*ip).into()),
            ))
        } else {
            Ok(())
        }
    }

    fn host_fqdn(hostname: &str, suffix: bool) -> Result<Dname<Octets64>, FromStrError> {
        let suffix = if suffix { "." } else { "" };

        let mut host_fqdn = heapless::String::<60>::new();
        write!(host_fqdn, "{}.local{}", hostname, suffix,).unwrap();

        Dname::from_str(&host_fqdn)
    }
}

pub struct Service<'a> {
    pub name: &'a str,
    pub service: &'a str,
    pub protocol: &'a str,
    pub port: u16,
    pub service_subtypes: &'a [&'a str],
    pub txt_kvs: &'a [(&'a str, &'a str)],
}

impl<'a> Service<'a> {
    fn add_service<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        answer: &mut AnswerBuilder<T>,
        hostname: &str,
        ttl_sec: u32,
    ) -> Result<(), ShortBuf> {
        answer.push(Record::<Dname<Octets64>, Srv<_>>::new(
            self.service_fqdn(false).unwrap(),
            Class::In,
            ttl_sec,
            Srv::new(0, 0, self.port, Host::host_fqdn(hostname, false).unwrap()),
        ))
    }

    fn add_service_type<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        answer: &mut AnswerBuilder<T>,
        ttl_sec: u32,
    ) -> Result<(), ShortBuf> {
        answer.push(Record::<Dname<Octets64>, Ptr<_>>::new(
            Self::dns_sd_fqdn(false).unwrap(),
            Class::In,
            ttl_sec,
            Ptr::new(self.service_type_fqdn(false).unwrap()),
        ))?;

        answer.push(Record::<Dname<Octets64>, Ptr<_>>::new(
            self.service_type_fqdn(false).unwrap(),
            Class::In,
            ttl_sec,
            Ptr::new(self.service_fqdn(false).unwrap()),
        ))
    }

    fn add_service_subtypes<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        answer: &mut AnswerBuilder<T>,
        ttl_sec: u32,
    ) -> Result<(), ShortBuf> {
        for service_subtype in self.service_subtypes {
            self.add_service_subtype(answer, service_subtype, ttl_sec)?;
        }

        Ok(())
    }

    fn add_service_subtype<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        answer: &mut AnswerBuilder<T>,
        service_subtype: &str,
        ttl_sec: u32,
    ) -> Result<(), ShortBuf> {
        answer.push(Record::<Dname<Octets64>, Ptr<_>>::new(
            Self::dns_sd_fqdn(false).unwrap(),
            Class::In,
            ttl_sec,
            Ptr::new(self.service_subtype_fqdn(service_subtype, false).unwrap()),
        ))?;

        answer.push(Record::<Dname<Octets64>, Ptr<_>>::new(
            self.service_subtype_fqdn(service_subtype, false).unwrap(),
            Class::In,
            ttl_sec,
            Ptr::new(self.service_fqdn(false).unwrap()),
        ))
    }

    fn add_txt<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        answer: &mut AnswerBuilder<T>,
        ttl_sec: u32,
    ) -> Result<(), ShortBuf> {
        // only way I found to create multiple parts in a Txt
        // each slice is the length and then the data
        let mut octets = Octets256::new();
        //octets.append_slice(&[1u8, b'X'])?;
        //octets.append_slice(&[2u8, b'A', b'B'])?;
        //octets.append_slice(&[0u8])?;
        for (k, v) in self.txt_kvs {
            octets.append_slice(&[(k.len() + v.len() + 1) as u8])?;
            octets.append_slice(k.as_bytes())?;
            octets.append_slice(&[b'='])?;
            octets.append_slice(v.as_bytes())?;
        }

        let txt = Txt::from_octets(&mut octets).unwrap();

        answer.push(Record::<Dname<Octets64>, Txt<_>>::new(
            self.service_fqdn(false).unwrap(),
            Class::In,
            ttl_sec,
            txt,
        ))
    }

    fn service_fqdn(&self, suffix: bool) -> Result<Dname<Octets64>, FromStrError> {
        let suffix = if suffix { "." } else { "" };

        let mut service_fqdn = heapless::String::<60>::new();
        write!(
            service_fqdn,
            "{}.{}.{}.local{}",
            self.name, self.service, self.protocol, suffix,
        )
        .unwrap();

        Dname::from_str(&service_fqdn)
    }

    fn service_type_fqdn(&self, suffix: bool) -> Result<Dname<Octets64>, FromStrError> {
        let suffix = if suffix { "." } else { "" };

        let mut service_type_fqdn = heapless::String::<60>::new();
        write!(
            service_type_fqdn,
            "{}.{}.local{}",
            self.service, self.protocol, suffix,
        )
        .unwrap();

        Dname::from_str(&service_type_fqdn)
    }

    fn service_subtype_fqdn(
        &self,
        service_subtype: &str,
        suffix: bool,
    ) -> Result<Dname<Octets64>, FromStrError> {
        let suffix = if suffix { "." } else { "" };

        let mut service_subtype_fqdn = heapless::String::<40>::new();
        write!(
            service_subtype_fqdn,
            "{}._sub.{}.{}.local{}",
            service_subtype, self.service, self.protocol, suffix,
        )
        .unwrap();

        Dname::from_str(&service_subtype_fqdn)
    }

    fn dns_sd_fqdn(suffix: bool) -> Result<Dname<Octets64>, FromStrError> {
        if suffix {
            Dname::from_str("_services._dns-sd._udp.local.")
        } else {
            Dname::from_str("_services._dns-sd._udp.local")
        }
    }
}

struct Buf<'a>(pub &'a mut [u8], pub usize);

impl<'a> OctetsBuilder for Buf<'a> {
    type Octets = Self;

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        if self.1 + slice.len() <= self.0.len() {
            let end = self.1 + slice.len();
            self.0[self.1..end].copy_from_slice(slice);
            self.1 = end;

            Ok(())
        } else {
            Err(ShortBuf)
        }
    }

    fn truncate(&mut self, len: usize) {
        self.1 = len;
    }

    fn freeze(self) -> Self::Octets {
        self
    }

    fn len(&self) -> usize {
        self.1
    }

    fn is_empty(&self) -> bool {
        self.1 == 0
    }
}

impl<'a> AsMut<[u8]> for Buf<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..self.1]
    }
}
