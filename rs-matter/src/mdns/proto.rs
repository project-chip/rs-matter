use core::fmt::Write;
use core::net::{Ipv4Addr, Ipv6Addr};

use domain::base::header::Flags;
use domain::base::iana::{Class, Opcode, Rcode};
use domain::base::message::ShortMessage;
use domain::base::message_builder::{AdditionalBuilder, AnswerBuilder, PushError};
use domain::base::name::FromStrError;
use domain::base::wire::{Composer, ParseError};
use domain::base::{Message, MessageBuilder, Name, RecordSectionBuilder, Rtype, ToName};
use domain::dep::octseq::Truncate;
use domain::dep::octseq::{OctetsBuilder, ShortBuf};
use domain::rdata::{Aaaa, Ptr, Srv, Txt, A};

use crate::error::{Error, ErrorCode};
use crate::utils::bitflags::bitflags;

use super::Service;

/// Internet DNS class with the "Cache Flush" bit set.
/// See https://datatracker.ietf.org/doc/html/rfc6762#section-10.2 for details.
fn dns_class_with_flush(dns_class: Class) -> Class {
    const RESOURCE_RECORD_CACHE_FLUSH_BIT: u16 = 0x8000;
    Class::from_int(u16::from(dns_class) | RESOURCE_RECORD_CACHE_FLUSH_BIT)
}

impl From<ShortBuf> for Error {
    fn from(_: ShortBuf) -> Self {
        Self::new(ErrorCode::NoSpace)
    }
}

impl From<PushError> for Error {
    fn from(_: PushError) -> Self {
        Self::new(ErrorCode::NoSpace)
    }
}

impl From<FromStrError> for Error {
    fn from(_: FromStrError) -> Self {
        Self::new(ErrorCode::MdnsError)
    }
}

impl From<ShortMessage> for Error {
    fn from(_: ShortMessage) -> Self {
        Self::new(ErrorCode::MdnsError)
    }
}

impl From<ParseError> for Error {
    fn from(_: ParseError) -> Self {
        Self::new(ErrorCode::MdnsError)
    }
}

pub trait Services {
    fn for_each<F>(&self, callback: F) -> Result<(), Error>
    where
        F: FnMut(&Service) -> Result<(), Error>;
}

impl<T> Services for &mut T
where
    T: Services,
{
    fn for_each<F>(&self, callback: F) -> Result<(), Error>
    where
        F: FnMut(&Service) -> Result<(), Error>,
    {
        (**self).for_each(callback)
    }
}

impl<T> Services for &T
where
    T: Services,
{
    fn for_each<F>(&self, callback: F) -> Result<(), Error>
    where
        F: FnMut(&Service) -> Result<(), Error>,
    {
        (**self).for_each(callback)
    }
}

// What additional data to be set in the mDNS reply
bitflags! {
    #[repr(transparent)]
    #[derive(Default)]
    #[cfg_attr(not(feature = "defmt"), derive(Debug, Copy, Clone, Eq, PartialEq, Hash))]
    pub struct AdditionalData: u8 {
        const IPS = 0x01;
        const SRV = 0x02;
        const TXT = 0x04;
    }
}

pub struct Host<'a> {
    pub id: u16,
    pub hostname: &'a str,
    pub ip: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}

impl Host<'_> {
    /// Broadcast an mDNS packet with the host and its services
    ///
    /// Should be done pro-actively every time there is a change in the host
    /// data itself, or in the data of one of its services
    pub fn broadcast<T: Services>(
        &self,
        services: T,
        buf: &mut [u8],
        ttl_sec: u32,
    ) -> Result<usize, Error> {
        let buf = Buf(buf, 0);

        let message = MessageBuilder::from_target(buf)?;

        let mut answer = message.answer();

        self.set_answer_header(&mut answer);

        self.add_ipv4(&mut answer, ttl_sec)?;
        self.add_ipv6(&mut answer, ttl_sec)?;

        services.for_each(|service| {
            service.add_service(&mut answer, self.hostname, ttl_sec)?;
            service.add_service_type(&mut answer, ttl_sec)?;
            service.add_dns_sd_service_type(&mut answer, ttl_sec)?;

            // TODO: Apple commissioning - since Apple commissions > 1 fabric
            // we are overflowing the DNS broadcast record.
            // Temporarily comment out a few records to make it work.

            //service.add_service_subtypes(&mut answer, ttl_sec)?;
            //service.add_dns_sd_service_subtypes(&mut answer, ttl_sec)?;
            //service.add_txt(&mut answer, ttl_sec)?;

            Ok(())
        })?;

        let buf = answer.finish();

        Ok(buf.1)
    }

    /// Respond to an mDNS packet as long as it contains at least one question
    /// which is applicable to the hoswt and its services
    ///
    /// Returns the number of bytes written to the buffer and a boolean indicating
    /// whether the response should be delayed by a random interval of 20 - 120ms,
    /// as per the mDNS spec
    pub fn respond<T: Services>(
        &self,
        services: T,
        data: &[u8],
        buf: &mut [u8],
        ttl_sec: u32,
    ) -> Result<(usize, bool), Error> {
        let buf = Buf(buf, 0);

        let message = MessageBuilder::from_target(buf)?;

        let mut answer = message.answer();
        let mut ad = AdditionalData::empty();
        let mut delay = false;

        if self.answer(data, &services, &mut answer, &mut ad, &mut delay, ttl_sec)? {
            let mut additional = answer.additional();

            self.additional(ad, &services, &mut additional, ttl_sec)?;

            let buf = additional.finish();

            Ok((buf.1, delay))
        } else {
            Ok((0, false))
        }
    }

    /// Generate answers for queries in the message which are applicable to the host and
    /// the services registered in it
    ///
    /// Returns true if any answers were generated
    ///
    /// Updates the `AdditionalData` parameter with indications of what additional data
    /// to be set in the "additional data" DNS record
    ///
    /// Updates the `delay` parameter to indicate if the reply should be delayed to avoid
    /// collissions with other mDNS responders
    #[allow(clippy::too_many_arguments)]
    fn answer<T, F>(
        &self,
        data: &[u8],
        services: F,
        answer: &mut AnswerBuilder<T>,
        ad: &mut AdditionalData,
        delay: &mut bool,
        ttl_sec: u32,
    ) -> Result<bool, Error>
    where
        T: Composer,
        F: Services,
    {
        self.set_answer_header(answer);

        let message = Message::from_octets(data)?;

        let mut replied = false;

        for question in message.question() {
            trace!("Handling question {:?}", question);

            let question = question?;

            replied |= self.answer_one(
                question.qname(),
                question.qtype(),
                &services,
                answer,
                ad,
                delay,
                ttl_sec,
            )?;
        }

        Ok(replied)
    }

    /// Generate additional data records as indicated in the `AdditionalData` parameter
    ///
    /// Note that we are not 100% compliant with the spec, because for efficiency purposes
    /// (to avoid extra allocations) we are putting more data in the additional data section
    /// than strictly needed (i.e. we answer with _all_ SRV and _all_ TXT records for _all_
    /// registered services, even when we get a query for a specific service).
    ///
    /// Given that the additional data section is optional and provisional, this is not expected
    /// to be an issue.
    fn additional<T, F>(
        &self,
        ad: AdditionalData,
        services: F,
        additional: &mut AdditionalBuilder<T>,
        ttl_sec: u32,
    ) -> Result<bool, Error>
    where
        T: Composer,
        F: Services,
    {
        let mut replied = false;

        if ad.contains(AdditionalData::IPS) {
            self.add_ipv4(additional, ttl_sec)?;
            self.add_ipv6(additional, ttl_sec)?;
            replied = true;
        }

        if ad.contains(AdditionalData::SRV) {
            services.for_each(|service| {
                service.add_service(additional, self.hostname, ttl_sec)?;
                replied = true;

                Ok(())
            })?;
        }

        if ad.contains(AdditionalData::TXT) {
            services.for_each(|service| {
                service.add_txt(additional, ttl_sec)?;
                replied = true;

                Ok(())
            })?;
        }

        Ok(replied)
    }

    /// Append the answer to a specific question in the message as long as the host can
    /// answer that question
    ///
    /// Updates the `AdditionalData` parameter with information what additional data to be
    /// set in the "additional data" DNS record
    ///
    /// Updates the `delay` parameter to indicate if the reply should be delayed
    /// (i.e. when answering DNS-SD queries with the DNS-SD FQDN
    /// to avoid collissions with other mDNS responders)
    #[allow(clippy::too_many_arguments)]
    fn answer_one<N, F, R, T>(
        &self,
        name: N,
        rtype: Rtype,
        services: F,
        answer: &mut R,
        ad: &mut AdditionalData,
        delay: &mut bool,
        ttl_sec: u32,
    ) -> Result<bool, Error>
    where
        N: ToName,
        F: Services,
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        if matches!(rtype, Rtype::ANY) {
            let mut replied = false;

            replied |=
                self.answer_simple(&name, Rtype::A, &services, answer, ad, delay, ttl_sec)?;
            replied |=
                self.answer_simple(&name, Rtype::AAAA, &services, answer, ad, delay, ttl_sec)?;
            replied |=
                self.answer_simple(&name, Rtype::PTR, &services, answer, ad, delay, ttl_sec)?;
            replied |=
                self.answer_simple(&name, Rtype::SRV, &services, answer, ad, delay, ttl_sec)?;
            replied |=
                self.answer_simple(&name, Rtype::TXT, services, answer, ad, delay, ttl_sec)?;

            Ok(replied)
        } else {
            self.answer_simple(name, rtype, services, answer, ad, delay, ttl_sec)
        }
    }

    /// Same as `answer_question` but does not answer questions of type "Any"
    #[allow(clippy::too_many_arguments)]
    fn answer_simple<N, F, R, T>(
        &self,
        name: N,
        rtype: Rtype,
        services: F,
        answer: &mut R,
        ad: &mut AdditionalData,
        delay: &mut bool,
        ttl_sec: u32,
    ) -> Result<bool, Error>
    where
        N: ToName,
        F: Services,
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        let mut replied = false;

        match rtype {
            Rtype::A if name.name_eq(&Host::host_fqdn(self.hostname, true)?) => {
                self.add_ipv4(answer, ttl_sec)?;
                replied = true;
            }
            Rtype::AAAA if name.name_eq(&Host::host_fqdn(self.hostname, true)?) => {
                self.add_ipv6(answer, ttl_sec)?;
                replied = true;
            }
            Rtype::SRV => {
                services.for_each(|service| {
                    if name.name_eq(&service.service_fqdn(true)?) {
                        service.add_service(answer, self.hostname, ttl_sec)?;
                        *ad |= AdditionalData::IPS;
                        replied = true;
                    }

                    Ok(())
                })?;
            }
            Rtype::PTR => {
                services.for_each(|service| {
                    if name.name_eq(&Service::dns_sd_fqdn(true)?) {
                        service.add_dns_sd_service_type(answer, ttl_sec)?;
                        service.add_dns_sd_service_subtypes(answer, ttl_sec)?;
                        *ad |= AdditionalData::SRV;
                        *ad |= AdditionalData::TXT;
                        *delay = true; // As we reply to a shared resource question, hence we need to avoid collissions
                        replied = true;
                    } else if name.name_eq(&service.service_type_fqdn(true)?) {
                        service.add_service(answer, self.hostname, ttl_sec)?;
                        *ad |= AdditionalData::SRV;
                        *ad |= AdditionalData::TXT;
                        replied = true;
                    } else {
                        for subtype in service.service_subtypes {
                            if name.name_eq(&service.service_subtype_fqdn(subtype, true)?) {
                                service.add_service_subtype(answer, subtype, ttl_sec)?;
                                replied = true;
                                *ad |= AdditionalData::SRV;
                                *ad |= AdditionalData::TXT;
                                break;
                            }
                        }
                    }

                    Ok(())
                })?;
            }
            Rtype::TXT => {
                services.for_each(|service| {
                    if name.name_eq(&service.service_fqdn(true)?) {
                        service.add_txt(answer, ttl_sec)?;
                        replied = true;
                    }

                    Ok(())
                })?;
            }
            _ => (),
        }

        Ok(replied)
    }

    fn set_answer_header<T: Composer>(&self, answer: &mut AnswerBuilder<T>) {
        let header = answer.header_mut();
        header.set_id(self.id);
        header.set_opcode(Opcode::QUERY);
        header.set_rcode(Rcode::NOERROR);

        let mut flags = Flags::new();
        flags.qr = true;
        flags.aa = true;
        header.set_flags(flags);
    }

    fn add_ipv4<R, T>(&self, answer: &mut R, ttl_sec: u32) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        if !self.ip.is_unspecified() {
            let octets = self.ip.octets();

            answer.push((
                Self::host_fqdn(self.hostname, false).unwrap(),
                dns_class_with_flush(Class::IN),
                ttl_sec,
                A::from_octets(octets[0], octets[1], octets[2], octets[3]),
            ))?;
        }

        Ok(())
    }

    fn add_ipv6<R, T>(&self, answer: &mut R, ttl_sec: u32) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        if !self.ipv6.is_unspecified() {
            answer.push((
                Self::host_fqdn(self.hostname, false).unwrap(),
                dns_class_with_flush(Class::IN),
                ttl_sec,
                Aaaa::new(self.ipv6.octets().into()),
            ))?;
        }

        Ok(())
    }

    fn host_fqdn(hostname: &str, suffix: bool) -> Result<impl ToName, FromStrError> {
        let suffix = if suffix { "." } else { "" };

        let mut host_fqdn = heapless::String::<60>::new();
        write!(host_fqdn, "{}.local{}", hostname, suffix,).unwrap();

        Name::<heapless::Vec<u8, 64>>::from_chars(host_fqdn.chars())
    }
}

impl Service<'_> {
    fn add_service<R, T>(
        &self,
        answer: &mut R,
        hostname: &str,
        ttl_sec: u32,
    ) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        answer.push((
            self.service_fqdn(false).unwrap(),
            dns_class_with_flush(Class::IN),
            ttl_sec,
            Srv::new(0, 0, self.port, Host::host_fqdn(hostname, false).unwrap()),
        ))
    }

    fn add_service_type<R, T>(&self, answer: &mut R, ttl_sec: u32) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        answer.push((
            self.service_type_fqdn(false).unwrap(),
            Class::IN,
            ttl_sec,
            Ptr::new(self.service_fqdn(false).unwrap()),
        ))
    }

    fn add_dns_sd_service_type<R, T>(&self, answer: &mut R, ttl_sec: u32) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        answer.push((
            Self::dns_sd_fqdn(false).unwrap(),
            dns_class_with_flush(Class::IN),
            ttl_sec,
            Ptr::new(self.service_type_fqdn(false).unwrap()),
        ))
    }

    #[allow(unused)]
    fn add_service_subtypes<R, T>(&self, answer: &mut R, ttl_sec: u32) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        for service_subtype in self.service_subtypes {
            self.add_service_subtype(answer, service_subtype, ttl_sec)?;
        }

        Ok(())
    }

    fn add_dns_sd_service_subtypes<R, T>(
        &self,
        answer: &mut R,
        ttl_sec: u32,
    ) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        for service_subtype in self.service_subtypes {
            self.add_dns_sd_service_subtype(answer, service_subtype, ttl_sec)?;
        }

        Ok(())
    }

    fn add_service_subtype<R, T>(
        &self,
        answer: &mut R,
        service_subtype: &str,
        ttl_sec: u32,
    ) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        // Don't set the flush-bit when sending this PTR record, as we're not the
        // authority of dns_sd_fqdn: there may be answers from other devices on
        // the network as well.
        answer.push((
            self.service_subtype_fqdn(service_subtype, false).unwrap(),
            Class::IN,
            ttl_sec,
            Ptr::new(self.service_fqdn(false).unwrap()),
        ))
    }

    fn add_dns_sd_service_subtype<R, T>(
        &self,
        answer: &mut R,
        service_subtype: &str,
        ttl_sec: u32,
    ) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        answer.push((
            Self::dns_sd_fqdn(false).unwrap(),
            Class::IN,
            ttl_sec,
            Ptr::new(self.service_subtype_fqdn(service_subtype, false).unwrap()),
        ))
    }

    fn add_txt<R, T>(&self, answer: &mut R, ttl_sec: u32) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<T>,
        T: Composer,
    {
        if self.txt_kvs.is_empty() {
            let txt = Txt::from_octets(&[0]).unwrap();

            answer.push((self.service_fqdn(false).unwrap(), Class::IN, ttl_sec, txt))
        } else {
            let mut octets = heapless::Vec::<_, 256>::new();

            // only way I found to create multiple parts in a Txt
            // each slice is the length and then the data
            for (k, v) in self.txt_kvs {
                octets.append_slice(&[(k.len() + v.len() + 1) as u8])?;
                octets.append_slice(k.as_bytes())?;
                octets.append_slice(b"=")?;
                octets.append_slice(v.as_bytes())?;
            }

            let txt = Txt::from_octets(&octets).unwrap();

            answer.push((
                self.service_fqdn(false).unwrap(),
                dns_class_with_flush(Class::IN),
                ttl_sec,
                txt,
            ))
        }
    }

    fn service_fqdn(&self, suffix: bool) -> Result<impl ToName, FromStrError> {
        let suffix = if suffix { "." } else { "" };

        let mut service_fqdn = heapless::String::<60>::new();
        write!(
            service_fqdn,
            "{}.{}.{}.local{}",
            self.name, self.service, self.protocol, suffix,
        )
        .unwrap();

        Name::<heapless::Vec<u8, 64>>::from_chars(service_fqdn.chars())
    }

    fn service_type_fqdn(&self, suffix: bool) -> Result<impl ToName, FromStrError> {
        let suffix = if suffix { "." } else { "" };

        let mut service_type_fqdn = heapless::String::<60>::new();
        write!(
            service_type_fqdn,
            "{}.{}.local{}",
            self.service, self.protocol, suffix,
        )
        .unwrap();

        Name::<heapless::Vec<u8, 64>>::from_chars(service_type_fqdn.chars())
    }

    fn service_subtype_fqdn(
        &self,
        service_subtype: &str,
        suffix: bool,
    ) -> Result<impl ToName, FromStrError> {
        let suffix = if suffix { "." } else { "" };

        let mut service_subtype_fqdn = heapless::String::<40>::new();
        write!(
            service_subtype_fqdn,
            "{}._sub.{}.{}.local{}",
            service_subtype, self.service, self.protocol, suffix,
        )
        .unwrap();

        Name::<heapless::Vec<u8, 64>>::from_chars(service_subtype_fqdn.chars())
    }

    fn dns_sd_fqdn(suffix: bool) -> Result<impl ToName, FromStrError> {
        Name::<heapless::Vec<u8, 64>>::from_chars(
            if suffix {
                "_services._dns-sd._udp.local."
            } else {
                "_services._dns-sd._udp.local"
            }
            .chars(),
        )
    }
}

struct Buf<'a>(pub &'a mut [u8], pub usize);

impl Composer for Buf<'_> {}

impl OctetsBuilder for Buf<'_> {
    type AppendError = ShortBuf;

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), Self::AppendError> {
        if self.1 + slice.len() <= self.0.len() {
            let end = self.1 + slice.len();
            self.0[self.1..end].copy_from_slice(slice);
            self.1 = end;

            Ok(())
        } else {
            Err(ShortBuf)
        }
    }
}

impl Truncate for Buf<'_> {
    fn truncate(&mut self, len: usize) {
        self.1 = len;
    }
}

impl AsMut<[u8]> for Buf<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..self.1]
    }
}

impl AsRef<[u8]> for Buf<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..self.1]
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use domain::base::header::Flags;
    use domain::base::iana::{Class, Opcode, Rcode};
    use domain::base::{Message, MessageBuilder, Name, RecordSection, Rtype, ToName};
    use domain::rdata::AllRecordData;

    use crate::error::Error;
    use crate::mdns::Service;

    use super::{Buf, Host, Services};

    static TEST_HOST_ONLY: TestRun = TestRun {
        host: Host {
            id: 0,
            hostname: "foo",
            ip: Ipv4Addr::new(192, 168, 0, 1),
            ipv6: Ipv6Addr::UNSPECIFIED,
        },
        services: &[],

        tests: &[
            // No questions - no answers
            (&[], &[], &[]),
            // Other domain - no answers
            (
                &[Question {
                    name: "foo1.local",
                    qtype: Rtype::A,
                }],
                &[],
                &[],
            ),
            // Our domain
            (
                &[Question {
                    name: "foo.local",
                    qtype: Rtype::A,
                }],
                &[Answer {
                    owner: "foo.local",
                    details: AnswerDetails::A(Ipv4Addr::new(192, 168, 0, 1)),
                }],
                &[],
            ),
            // ipv6 - no answer (TODO: We should return negative answer here in future)
            (
                &[Question {
                    name: "foo.local",
                    qtype: Rtype::AAAA,
                }],
                &[],
                &[],
            ),
        ],
    };

    static TEST_SERVICES: TestRun = TestRun {
        host: Host {
            id: 1,
            hostname: "foo",
            ip: Ipv4Addr::new(192, 168, 0, 1),
            ipv6: Ipv6Addr::new(0xfb, 0, 0, 0, 0, 0, 0, 1),
        },
        services: &[
            Service {
                name: "bar",
                service: "_matterc",
                protocol: "_udp",
                port: 1234,
                service_subtypes: &["L", "R"],
                txt_kvs: &[("a", "b"), ("c", "d")],
            },
            Service {
                name: "ddd",
                service: "_matter",
                protocol: "_tcp",
                port: 1235,
                service_subtypes: &[],
                txt_kvs: &[],
            },
        ],

        tests: &[
            // No questions - no answers
            (&[], &[], &[]),
            // Other domain - no answers
            (
                &[Question {
                    name: "foo1.local",
                    qtype: Rtype::A,
                }],
                &[],
                &[],
            ),
            // SRV - no answer
            (
                &[Question {
                    name: "foo.bar.local",
                    qtype: Rtype::SRV,
                }],
                &[],
                &[],
            ),
            // SRV - Answer
            (
                &[Question {
                    name: "bar._matterc._udp.local",
                    qtype: Rtype::SRV,
                }],
                &[Answer {
                    owner: "bar._matterc._udp.local",
                    details: AnswerDetails::Srv {
                        port: 1234,
                        target: "foo.local",
                    },
                }],
                &[
                    Answer {
                        owner: "foo.local",
                        details: AnswerDetails::A(Ipv4Addr::new(192, 168, 0, 1)),
                    },
                    Answer {
                        owner: "foo.local",
                        details: AnswerDetails::Aaaa(Ipv6Addr::new(0xfb, 0, 0, 0, 0, 0, 0, 1)),
                    },
                ],
            ),
            // PTR
            (
                &[Question {
                    name: "_services._dns-sd._udp.local",
                    qtype: Rtype::PTR,
                }],
                &[
                    Answer {
                        owner: "_services._dns-sd._udp.local",
                        details: AnswerDetails::Ptr("_matterc._udp.local"),
                    },
                    Answer {
                        owner: "_services._dns-sd._udp.local",
                        details: AnswerDetails::Ptr("L._sub._matterc._udp.local"),
                    },
                    Answer {
                        owner: "_services._dns-sd._udp.local",
                        details: AnswerDetails::Ptr("R._sub._matterc._udp.local"),
                    },
                    Answer {
                        owner: "_services._dns-sd._udp.local",
                        details: AnswerDetails::Ptr("_matter._tcp.local"),
                    },
                ],
                &[
                    Answer {
                        owner: "bar._matterc._udp.local",
                        details: AnswerDetails::Srv {
                            port: 1234,
                            target: "foo.local",
                        },
                    },
                    Answer {
                        owner: "ddd._matter._tcp.local",
                        details: AnswerDetails::Srv {
                            port: 1235,
                            target: "foo.local",
                        },
                    },
                    Answer {
                        owner: "bar._matterc._udp.local",
                        details: AnswerDetails::Txt(&[("a", "b"), ("c", "d")]),
                    },
                    Answer {
                        owner: "ddd._matter._tcp.local",
                        details: AnswerDetails::Txt(&[]),
                    },
                ],
            ),
        ],
    };

    #[test]
    fn test_host_only() {
        TEST_HOST_ONLY.run();
    }

    #[test]
    fn test_services() {
        TEST_SERVICES.run();
    }

    struct TestRun<'a> {
        host: Host<'a>,
        services: &'a [Service<'a>],

        tests: &'a [(&'a [Question<'a>], &'a [Answer<'a>], &'a [Answer<'a>])],
    }

    impl TestRun<'_> {
        fn run(&self) {
            let mut buf1 = [0; 1500];
            let mut buf2 = [0; 1500];

            for (questions, expected_answers, expected_additional) in self.tests {
                let data = Question::prep(&mut buf1, self.host.id, questions);

                let (len, _) = self
                    .host
                    .respond(self.services, data, &mut buf2, 0)
                    .unwrap();

                if len > 0 {
                    Answer::validate(
                        &buf2[..len],
                        self.host.id,
                        expected_answers,
                        expected_additional,
                    );
                } else {
                    assert!(expected_answers.is_empty());
                    assert!(expected_additional.is_empty());
                }
            }
        }
    }

    #[derive(Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    struct Question<'a> {
        name: &'a str,
        #[cfg_attr(feature = "defmt", defmt(Display2Format))]
        qtype: Rtype,
    }

    impl Question<'_> {
        fn prep<'b>(buf: &'b mut [u8], id: u16, questions: &[Question]) -> &'b [u8] {
            let message = MessageBuilder::from_target(Buf(buf, 0)).unwrap();

            let mut qb = message.question();

            let header = qb.header_mut();
            header.set_id(id);
            header.set_opcode(Opcode::QUERY);
            header.set_rcode(Rcode::NOERROR);

            let mut flags = Flags::new();
            flags.qr = false;
            flags.aa = true;
            header.set_flags(flags);

            for question in questions {
                let dname =
                    Name::<heapless::Vec<u8, 64>>::from_chars(question.name.chars()).unwrap();

                qb.push((dname, question.qtype, Class::IN)).unwrap();
            }

            let len = qb.finish().as_ref().len();

            &buf[..len]
        }
    }

    #[derive(Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    enum AnswerDetails<'a> {
        A(#[cfg_attr(feature = "defmt", defmt(Display2Format))] Ipv4Addr),
        Aaaa(#[cfg_attr(feature = "defmt", defmt(Display2Format))] Ipv6Addr),
        Srv { port: u16, target: &'a str },
        Ptr(&'a str),
        Txt(&'a [(&'a str, &'a str)]),
    }

    #[derive(Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    struct Answer<'a> {
        owner: &'a str,
        details: AnswerDetails<'a>,
    }

    impl Answer<'_> {
        fn validate(
            data: &[u8],
            expected_id: u16,
            expected_answers: &[Answer],
            expected_additional: &[Answer],
        ) {
            let message = Message::from_octets(data).unwrap();

            let header = message.header();
            ::core::assert_eq!(header.id(), expected_id);
            ::core::assert_eq!(header.opcode(), Opcode::QUERY);
            ::core::assert_eq!(header.rcode(), Rcode::NOERROR);

            Answer::validate_section(&message.answer().unwrap(), expected_answers);
            Answer::validate_section(&message.additional().unwrap(), expected_additional);
        }

        fn validate_section(section: &RecordSection<&[u8]>, expected_answers: &[Answer]) {
            let mut answers = section.peekable();
            let mut expectations = expected_answers.iter().peekable();

            while answers.peek().is_some() && expectations.peek().is_some() {
                let answer = answers
                    .next()
                    .unwrap()
                    .unwrap()
                    .to_any_record::<AllRecordData<_, _>>()
                    .unwrap();

                let expected = expectations.next().unwrap();

                assert!(
                    answer.owner().name_eq(
                        &Name::<heapless::Vec<u8, 64>>::from_chars(expected.owner.chars()).unwrap()
                    ),
                    "OWNER {} (answer) != {} (expected)",
                    display2format!(answer.owner()),
                    expected.owner
                );

                match (answer.data(), &expected.details) {
                    (AllRecordData::A(a), AnswerDetails::A(ip)) => {
                        ::core::assert_eq!(Ipv4Addr::from(a.addr().octets()), *ip);
                    }
                    (AllRecordData::Aaaa(a), AnswerDetails::Aaaa(ip)) => {
                        ::core::assert_eq!(Ipv6Addr::from(a.addr().octets()), *ip);
                    }
                    (AllRecordData::Srv(s), AnswerDetails::Srv { port, target }) => {
                        assert_eq!(s.port(), *port);
                        assert!(
                            s.target().name_eq(
                                &Name::<heapless::Vec<u8, 64>>::from_chars(target.chars()).unwrap()
                            ),
                            "SRV {} (answer) != {} (expected)",
                            display2format!(s.target()),
                            target
                        );
                    }
                    (AllRecordData::Ptr(p), AnswerDetails::Ptr(name)) => {
                        assert!(
                            p.ptrdname().name_eq(
                                &Name::<heapless::Vec<u8, 64>>::from_chars(name.chars()).unwrap()
                            ),
                            "PTR {} (answer) != {} (expected)",
                            display2format!(p.ptrdname()),
                            name,
                        );
                    }
                    (AllRecordData::Txt(txt), AnswerDetails::Txt(kvs)) => {
                        use core::fmt::Write;

                        let mut txt = txt.iter().peekable();
                        let mut kvs = kvs.iter().peekable();

                        while txt.peek().is_some() && kvs.peek().is_some() {
                            let t = txt.next().unwrap();

                            if t.is_empty() || t.len() == 1 && t[0] == 0 {
                                continue;
                            }

                            let (k, v) = kvs.next().unwrap();

                            let mut str = heapless::Vec::<u8, 256>::new();
                            write!(&mut str, "{k}={v}").unwrap();

                            assert_eq!(t, str);
                        }

                        for t in txt {
                            if !t.is_empty() {
                                panic!("Unexpected TXT string {:?} for {}", t, expected.owner);
                            }
                        }

                        if let Some((k, v)) = kvs.next() {
                            panic!("Missing TXT string {}={} for {}", k, v, expected.owner);
                        }
                    }
                    other => panic!("Unexpected record type: {:?}", debug2format!(other)),
                }
            }

            if let Some(answer) = answers.next() {
                let answer = answer
                    .unwrap()
                    .to_any_record::<AllRecordData<_, _>>()
                    .unwrap();

                panic!("Unexpected answer {:?}", debug2format!(answer));
            }

            if let Some(expected) = expectations.next() {
                panic!("Missing answer {:?}", expected);
            }
        }
    }

    impl<'a> Services for &'a [Service<'a>] {
        fn for_each<F>(&self, mut callback: F) -> Result<(), Error>
        where
            F: FnMut(&Service) -> Result<(), Error>,
        {
            for service in self.iter() {
                callback(service)?;
            }

            Ok(())
        }
    }
}
