/*
 *
 *    Copyright (c) 2023-2026 Project CHIP Authors
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

use core::net::{Ipv4Addr, Ipv6Addr};

use domain::base::header::Flags;
use domain::base::iana::{Class, Opcode, Rcode};
use domain::base::message::ShortMessage;
use domain::base::message_builder::{AdditionalBuilder, AnswerBuilder, PushError};
use domain::base::name::FromStrError;
use domain::base::wire::{Composer, ParseError};
use domain::base::{Message, MessageBuilder, RecordSectionBuilder, Rtype, ToName};
use domain::dep::octseq::ShortBuf;
use domain::rdata::{Aaaa, Ptr, Srv, A};

use crate::error::{Error, ErrorCode};
use crate::transport::network::mdns::builtin::types::{Buf, NameSlice, Txt};
use crate::utils::bitflags::bitflags;

use super::Service;

impl From<ShortBuf> for Error {
    fn from(_: ShortBuf) -> Self {
        Self::new(ErrorCode::BufferTooSmall)
    }
}

impl From<PushError> for Error {
    fn from(_: PushError) -> Self {
        Self::new(ErrorCode::BufferTooSmall)
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
    pub hostname: &'a str,
    pub ip: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}

/// How a response prepared by [`Host::respond`] should be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RespondMode {
    /// No applicable question was found in the query; nothing should be sent.
    Skip,
    /// Send the prepared response via multicast.
    Multicast {
        /// Whether to apply a random 20-120 ms delay before sending
        /// (RFC 6762 §6 — collision avoidance for shared-resource responses).
        delay: bool,
    },
    /// Send the prepared response via unicast back to the query source.
    ///
    /// Used for legacy unicast resolvers (RFC 6762 §6.7), where the query
    /// arrived from a UDP source port other than the mDNS port (5353).
    Unicast,
}

impl Host<'_> {
    /// Broadcast an mDNS packet with the host and its services
    ///
    /// Should be done pro-actively every time there is a change in the host
    /// data itself, or in the data of one of its services.
    ///
    /// Per RFC 6762 §18.1 the message ID for unsolicited multicast responses
    /// is set to zero; per §10.2 records that we are authoritative for carry
    /// the cache-flush bit.
    pub fn broadcast<'a, S, T>(
        &self,
        service: &Service<'a, S, T>,
        buf: &mut [u8],
        host_ttl_sec: u32,
        service_ttl_sec: u32,
    ) -> Result<usize, Error>
    where
        S: Iterator<Item = &'a str> + Clone,
        T: Iterator<Item = (&'a str, &'a str)> + Clone,
    {
        let buf = Buf::new(buf);

        let message = MessageBuilder::from_target(buf)?;

        let mut answer = message.answer();

        Self::set_answer_header(&mut answer, 0);

        let flush = true;

        self.add_ipv4(&mut answer, host_ttl_sec, flush)?;
        self.add_ipv6(&mut answer, host_ttl_sec, flush)?;

        service.add_service(&mut answer, self.hostname, service_ttl_sec, flush)?;
        service.add_service_type(&mut answer, service_ttl_sec)?;
        service.add_dns_sd_service_type(&mut answer, host_ttl_sec)?;

        for subtype in service.service_subtypes.clone() {
            service.add_service_subtype(&mut answer, subtype, service_ttl_sec)?;
        }

        service.add_txt(&mut answer, service_ttl_sec, flush)?;

        let buf = answer.finish();

        Ok(buf.1)
    }

    /// Respond to an mDNS query message.
    ///
    /// Returns the number of bytes written into `buf` and a [`RespondMode`]
    /// indicating how the caller should send the response (or skip it).
    ///
    /// `legacy_unicast` should be set by the caller when the query arrived
    /// from a UDP source port other than 5353 — i.e. from a legacy unicast
    /// resolver (RFC 6762 §6.7). In that case the response:
    /// - echoes the query's question section
    /// - reuses the query's transaction ID
    /// - caps record TTLs to 10 seconds
    /// - omits the cache-flush bit on records we are authoritative for
    /// - is sent unicast back to the query source.
    ///
    /// For multicast queries the response uses ID 0 (RFC 6762 §18.1), full
    /// TTLs, and the cache-flush bit on authoritative records.
    pub fn respond<'a, S, T>(
        &self,
        service: &Service<'a, S, T>,
        data: &[u8],
        buf: &mut [u8],
        ttl_sec: u32,
        legacy_unicast: bool,
    ) -> Result<(usize, RespondMode), Error>
    where
        S: Iterator<Item = &'a str> + Clone,
        T: Iterator<Item = (&'a str, &'a str)> + Clone,
    {
        let message_in = Message::from_octets(data)?;

        // Only respond to queries (QR bit = 0); ignore responses from other mDNS responders.
        if message_in.header().flags().qr {
            return Ok((0, RespondMode::Skip));
        }

        let buf = Buf::new(buf);
        let builder = MessageBuilder::from_target(buf)?;

        // Cap TTLs at 10s for legacy unicast (RFC 6762 §6.7).
        let effective_ttl = if legacy_unicast {
            ttl_sec.min(10)
        } else {
            ttl_sec
        };
        // Suppress the cache-flush bit for legacy responses (RFC 6762 §10.2 / §6.7).
        let flush = !legacy_unicast;

        // For legacy responses: echo the original question section and reuse
        // the query's transaction ID. For multicast responses: skip questions
        // and use ID 0.
        let (mut answer, response_id) = if legacy_unicast {
            let mut qb = builder.question();
            for question in message_in.question() {
                let q = question?;
                qb.push((q.qname(), q.qtype(), q.qclass()))?;
            }
            (qb.answer(), message_in.header().id())
        } else {
            (builder.answer(), 0)
        };

        Self::set_answer_header(&mut answer, response_id);

        let mut ad = AdditionalData::empty();
        let mut delay = false;

        if !self.answer(
            service,
            &message_in,
            &mut answer,
            &mut ad,
            &mut delay,
            effective_ttl,
            flush,
        )? {
            return Ok((0, RespondMode::Skip));
        }

        let mut additional = answer.additional();
        self.additional(service, ad, &mut additional, effective_ttl, flush)?;

        let len = additional.finish().1;

        let mode = if legacy_unicast {
            RespondMode::Unicast
        } else {
            RespondMode::Multicast { delay }
        };

        Ok((len, mode))
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
    fn answer<'a, S, T, C>(
        &self,
        service: &Service<'a, S, T>,
        message: &Message<&[u8]>,
        answer: &mut AnswerBuilder<C>,
        ad: &mut AdditionalData,
        delay: &mut bool,
        ttl_sec: u32,
        flush: bool,
    ) -> Result<bool, Error>
    where
        S: Iterator<Item = &'a str> + Clone,
        T: Iterator<Item = (&'a str, &'a str)> + Clone,
        C: Composer,
    {
        let mut replied = false;

        for question in message.question() {
            trace!("Handling question {:?}", debug2format!(question));

            let question = question?;

            replied |= self.answer_one(
                question.qname(),
                question.qtype(),
                service,
                answer,
                ad,
                delay,
                ttl_sec,
                flush,
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
    fn additional<'a, S, T, C>(
        &self,
        service: &Service<'a, S, T>,
        ad: AdditionalData,
        additional: &mut AdditionalBuilder<C>,
        ttl_sec: u32,
        flush: bool,
    ) -> Result<bool, Error>
    where
        S: Iterator<Item = &'a str> + Clone,
        T: Iterator<Item = (&'a str, &'a str)> + Clone,
        C: Composer,
    {
        let mut replied = false;

        if ad.contains(AdditionalData::IPS) {
            self.add_ipv4(additional, ttl_sec, flush)?;
            self.add_ipv6(additional, ttl_sec, flush)?;
            replied = true;
        }

        if ad.contains(AdditionalData::SRV) {
            service.add_service(additional, self.hostname, ttl_sec, flush)?;
            replied = true;
        }

        if ad.contains(AdditionalData::TXT) {
            service.add_txt(additional, ttl_sec, flush)?;
            replied = true;
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
    fn answer_one<'a, N, R, S, T, C>(
        &self,
        name: N,
        rtype: Rtype,
        service: &Service<'a, S, T>,
        answer: &mut R,
        ad: &mut AdditionalData,
        delay: &mut bool,
        ttl_sec: u32,
        flush: bool,
    ) -> Result<bool, Error>
    where
        N: ToName,
        R: RecordSectionBuilder<C>,
        S: Iterator<Item = &'a str> + Clone,
        T: Iterator<Item = (&'a str, &'a str)> + Clone,
        C: Composer,
    {
        if matches!(rtype, Rtype::ANY) {
            let mut replied = false;

            replied |=
                self.answer_simple(&name, Rtype::A, service, answer, ad, delay, ttl_sec, flush)?;
            replied |= self.answer_simple(
                &name,
                Rtype::AAAA,
                service,
                answer,
                ad,
                delay,
                ttl_sec,
                flush,
            )?;
            replied |= self.answer_simple(
                &name,
                Rtype::PTR,
                service,
                answer,
                ad,
                delay,
                ttl_sec,
                flush,
            )?;
            replied |= self.answer_simple(
                &name,
                Rtype::SRV,
                service,
                answer,
                ad,
                delay,
                ttl_sec,
                flush,
            )?;
            replied |= self.answer_simple(
                &name,
                Rtype::TXT,
                service,
                answer,
                ad,
                delay,
                ttl_sec,
                flush,
            )?;

            Ok(replied)
        } else {
            self.answer_simple(name, rtype, service, answer, ad, delay, ttl_sec, flush)
        }
    }

    /// Same as `answer_question` but does not answer questions of type "Any"
    #[allow(clippy::too_many_arguments)]
    fn answer_simple<'a, N, R, S, T, C>(
        &self,
        name: N,
        rtype: Rtype,
        service: &Service<'a, S, T>,
        answer: &mut R,
        ad: &mut AdditionalData,
        delay: &mut bool,
        ttl_sec: u32,
        flush: bool,
    ) -> Result<bool, Error>
    where
        N: ToName,
        R: RecordSectionBuilder<C>,
        S: Iterator<Item = &'a str> + Clone,
        T: Iterator<Item = (&'a str, &'a str)> + Clone,
        C: Composer,
    {
        let mut replied = false;

        match rtype {
            Rtype::A if name.name_eq(&Host::host_fqdn(self.hostname)) => {
                self.add_ipv4(answer, ttl_sec, flush)?;
                replied = true;
            }
            Rtype::AAAA if name.name_eq(&Host::host_fqdn(self.hostname)) => {
                self.add_ipv6(answer, ttl_sec, flush)?;
                replied = true;
            }
            Rtype::SRV if name.name_eq(&service.service_fqdn()) => {
                service.add_service(answer, self.hostname, ttl_sec, flush)?;
                *ad |= AdditionalData::IPS;
                replied = true;
            }
            Rtype::PTR => {
                if name.name_eq(&Service::<S, T>::dns_sd_fqdn()) {
                    service.add_dns_sd_service_type(answer, ttl_sec)?;
                    service.add_dns_sd_service_subtypes(answer, ttl_sec)?;
                    *ad |= AdditionalData::IPS | AdditionalData::SRV | AdditionalData::TXT;
                    *delay = true; // As we reply to a shared resource question, hence we need to avoid collissions
                    replied = true;
                } else if name.name_eq(&service.service_type_fqdn()) {
                    service.add_service_type(answer, ttl_sec)?;
                    *ad |= AdditionalData::IPS | AdditionalData::SRV | AdditionalData::TXT;
                    replied = true;
                } else {
                    for subtype in service.service_subtypes.clone() {
                        if name.name_eq(&service.service_subtype_fqdn(subtype)) {
                            service.add_service_subtype(answer, subtype, ttl_sec)?;
                            replied = true;
                            *ad |= AdditionalData::IPS | AdditionalData::SRV | AdditionalData::TXT;
                            break;
                        }
                    }
                }
            }
            Rtype::TXT if name.name_eq(&service.service_fqdn()) => {
                service.add_txt(answer, ttl_sec, flush)?;
                replied = true;
            }
            _ => (),
        }

        Ok(replied)
    }

    fn set_answer_header<T: Composer>(answer: &mut AnswerBuilder<T>, id: u16) {
        let header = answer.header_mut();
        header.set_id(id);
        header.set_opcode(Opcode::QUERY);
        header.set_rcode(Rcode::NOERROR);

        let mut flags = Flags::new();
        flags.qr = true;
        flags.aa = true;
        header.set_flags(flags);
    }

    fn add_ipv4<R, C>(&self, answer: &mut R, ttl_sec: u32, flush: bool) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<C>,
        C: Composer,
    {
        if !self.ip.is_unspecified() {
            let octets = self.ip.octets();

            answer.push((
                Self::host_fqdn(self.hostname),
                Self::auth_class(flush),
                ttl_sec,
                A::from_octets(octets[0], octets[1], octets[2], octets[3]),
            ))?;
        }

        Ok(())
    }

    fn add_ipv6<R, C>(&self, answer: &mut R, ttl_sec: u32, flush: bool) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<C>,
        C: Composer,
    {
        if !self.ipv6.is_unspecified() {
            answer.push((
                Self::host_fqdn(self.hostname),
                Self::auth_class(flush),
                ttl_sec,
                Aaaa::new(self.ipv6.octets().into()),
            ))?;
        }

        Ok(())
    }

    const fn host_fqdn(hostname: &str) -> impl ToName + '_ {
        NameSlice::new([hostname, "local"])
    }

    /// Class to use for records we are authoritative for.
    ///
    /// `flush=true` sets the cache-flush bit (RFC 6762 §10.2). `flush=false`
    /// returns plain `IN` — used for legacy unicast responses (RFC 6762 §6.7),
    /// where setting the cache-flush bit is forbidden.
    fn auth_class(flush: bool) -> Class {
        if flush {
            // Internet DNS class with the "Cache Flush" bit set.
            // See https://datatracker.ietf.org/doc/html/rfc6762#section-10.2 for details.
            const RESOURCE_RECORD_CACHE_FLUSH_BIT: u16 = 0x8000;
            Class::from_int(u16::from(Class::IN) | RESOURCE_RECORD_CACHE_FLUSH_BIT)
        } else {
            Class::IN
        }
    }
}

impl<'a, S, T> Service<'a, S, T>
where
    S: Iterator<Item = &'a str> + Clone,
    T: Iterator<Item = (&'a str, &'a str)> + Clone,
{
    fn add_service<R, C>(
        &self,
        answer: &mut R,
        hostname: &str,
        ttl_sec: u32,
        flush: bool,
    ) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<C>,
        C: Composer,
    {
        answer.push((
            self.service_fqdn(),
            Host::auth_class(flush),
            ttl_sec,
            Srv::new(0, 0, self.port, Host::host_fqdn(hostname)),
        ))
    }

    fn add_service_type<R, C>(&self, answer: &mut R, ttl_sec: u32) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<C>,
        C: Composer,
    {
        answer.push((
            self.service_type_fqdn(),
            Class::IN,
            ttl_sec,
            Ptr::new(self.service_fqdn()),
        ))
    }

    fn add_dns_sd_service_type<R, C>(&self, answer: &mut R, ttl_sec: u32) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<C>,
        C: Composer,
    {
        // Don't set the flush-bit when sending this PTR record, as we're not the
        // authority of dns_sd_fqdn: there may be answers from other devices on
        // the network as well.
        answer.push((
            Self::dns_sd_fqdn(),
            Class::IN,
            ttl_sec,
            Ptr::new(self.service_type_fqdn()),
        ))
    }

    #[allow(unused)]
    fn add_service_subtypes<R, C>(&self, answer: &mut R, ttl_sec: u32) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<C>,
        C: Composer,
    {
        for service_subtype in self.service_subtypes.clone() {
            self.add_service_subtype(answer, service_subtype, ttl_sec)?;
        }

        Ok(())
    }

    fn add_dns_sd_service_subtypes<R, C>(
        &self,
        answer: &mut R,
        ttl_sec: u32,
    ) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<C>,
        C: Composer,
    {
        for service_subtype in self.service_subtypes.clone() {
            self.add_dns_sd_service_subtype(answer, service_subtype, ttl_sec)?;
        }

        Ok(())
    }

    fn add_service_subtype<R, C>(
        &self,
        answer: &mut R,
        service_subtype: &str,
        ttl_sec: u32,
    ) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<C>,
        C: Composer,
    {
        // Don't set the flush-bit when sending this PTR record, as we're not the
        // authority of dns_sd_fqdn: there may be answers from other devices on
        // the network as well.
        answer.push((
            self.service_subtype_fqdn(service_subtype),
            Class::IN,
            ttl_sec,
            Ptr::new(self.service_fqdn()),
        ))
    }

    fn add_dns_sd_service_subtype<R, C>(
        &self,
        answer: &mut R,
        service_subtype: &str,
        ttl_sec: u32,
    ) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<C>,
        C: Composer,
    {
        answer.push((
            Self::dns_sd_fqdn(),
            Class::IN,
            ttl_sec,
            Ptr::new(self.service_subtype_fqdn(service_subtype)),
        ))
    }

    fn add_txt<R, C>(&self, answer: &mut R, ttl_sec: u32, flush: bool) -> Result<(), PushError>
    where
        R: RecordSectionBuilder<C>,
        C: Composer,
    {
        answer.push((
            self.service_fqdn(),
            Host::auth_class(flush),
            ttl_sec,
            Txt::new(self.txt_kvs.clone()),
        ))
    }

    const fn service_fqdn(&self) -> impl ToName + '_ {
        NameSlice::new([self.name, self.service, self.protocol, "local"])
    }

    const fn service_type_fqdn(&self) -> impl ToName + '_ {
        NameSlice::new([self.service, self.protocol, "local"])
    }

    const fn service_subtype_fqdn<'b>(&'b self, service_subtype: &'b str) -> impl ToName + 'b {
        NameSlice::new([
            service_subtype,
            "_sub",
            self.service,
            self.protocol,
            "local",
        ])
    }

    const fn dns_sd_fqdn() -> impl ToName {
        NameSlice::new(["_services", "_dns-sd", "_udp", "local"])
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use domain::base::header::Flags;
    use domain::base::iana::{Class, Opcode, Rcode};
    use domain::base::{Message, MessageBuilder, Name, ParsedRecord, Rtype, ToName};
    use domain::rdata::AllRecordData;

    use crate::transport::network::mdns::builtin::types::Buf;
    use crate::transport::network::mdns::Service;

    use super::Host;

    /// A test fixture for a service, holding subtypes and TXT records as slices.
    /// At "use" time, converted to a `Service` with iterator-typed fields.
    struct TestService<'a> {
        name: &'a str,
        service: &'a str,
        protocol: &'a str,
        service_protocol: &'a str,
        port: u16,
        service_subtypes: &'a [&'a str],
        txt_kvs: &'a [(&'a str, &'a str)],
    }

    impl<'a> TestService<'a> {
        fn as_service(
            &self,
        ) -> Service<
            'a,
            impl Iterator<Item = &'a str> + Clone + '_,
            impl Iterator<Item = (&'a str, &'a str)> + Clone + '_,
        > {
            Service {
                name: self.name,
                service: self.service,
                protocol: self.protocol,
                service_protocol: self.service_protocol,
                port: self.port,
                service_subtypes: self.service_subtypes.iter().copied(),
                txt_kvs: self.txt_kvs.iter().copied(),
            }
        }
    }

    static TEST_HOST_ONLY: TestRun = TestRun {
        host: Host {
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
            hostname: "foo",
            ip: Ipv4Addr::new(192, 168, 0, 1),
            ipv6: Ipv6Addr::new(0xfb, 0, 0, 0, 0, 0, 0, 1),
        },
        services: &[
            TestService {
                name: "bar",
                service: "_matterc",
                protocol: "_udp",
                service_protocol: "_matterc._udp",
                port: 1234,
                service_subtypes: &["L", "R"],
                txt_kvs: &[("a", "b"), ("c", "d")],
            },
            TestService {
                name: "ddd",
                service: "_matter",
                protocol: "_tcp",
                service_protocol: "_matter._tcp",
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
                // Per-service responses: each service emits its own packet, so
                // host A/AAAA additionals repeat per service.
                &[
                    // Service 1 (bar._matterc._udp): A, AAAA, SRV, TXT
                    Answer {
                        owner: "foo.local",
                        details: AnswerDetails::A(Ipv4Addr::new(192, 168, 0, 1)),
                    },
                    Answer {
                        owner: "foo.local",
                        details: AnswerDetails::Aaaa(Ipv6Addr::new(0xfb, 0, 0, 0, 0, 0, 0, 1)),
                    },
                    Answer {
                        owner: "bar._matterc._udp.local",
                        details: AnswerDetails::Srv {
                            port: 1234,
                            target: "foo.local",
                        },
                    },
                    Answer {
                        owner: "bar._matterc._udp.local",
                        details: AnswerDetails::Txt(&[("a", "b"), ("c", "d")]),
                    },
                    // Service 2 (ddd._matter._tcp): A, AAAA, SRV, TXT
                    Answer {
                        owner: "foo.local",
                        details: AnswerDetails::A(Ipv4Addr::new(192, 168, 0, 1)),
                    },
                    Answer {
                        owner: "foo.local",
                        details: AnswerDetails::Aaaa(Ipv6Addr::new(0xfb, 0, 0, 0, 0, 0, 0, 1)),
                    },
                    Answer {
                        owner: "ddd._matter._tcp.local",
                        details: AnswerDetails::Srv {
                            port: 1235,
                            target: "foo.local",
                        },
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

    #[test]
    fn test_ptr_service_type_query() {
        // Test that a PTR query for a service type FQDN (e.g., _matterc._udp.local)
        // returns PTR records pointing to service instances (not SRV records)
        let host = Host {
            hostname: "foo",
            ip: Ipv4Addr::new(192, 168, 0, 1),
            ipv6: Ipv6Addr::new(0xfb, 0, 0, 0, 0, 0, 0, 1),
        };

        let services: &[TestService<'_>] = &[TestService {
            name: "bar",
            service: "_matterc",
            protocol: "_udp",
            service_protocol: "_matterc._udp",
            port: 1234,
            service_subtypes: &["_L1234", "_S3"],
            txt_kvs: &[("D", "1234"), ("CM", "1")],
        }];

        let run = TestRun {
            host,
            services,
            tests: &[(
                &[Question {
                    name: "_matterc._udp.local",
                    qtype: Rtype::PTR,
                }],
                // Answer should be PTR records, not SRV
                &[Answer {
                    owner: "_matterc._udp.local",
                    details: AnswerDetails::Ptr("bar._matterc._udp.local"),
                }],
                // Additional should include IPS, SRV and TXT
                &[
                    Answer {
                        owner: "foo.local",
                        details: AnswerDetails::A(Ipv4Addr::new(192, 168, 0, 1)),
                    },
                    Answer {
                        owner: "foo.local",
                        details: AnswerDetails::Aaaa(Ipv6Addr::new(0xfb, 0, 0, 0, 0, 0, 0, 1)),
                    },
                    Answer {
                        owner: "bar._matterc._udp.local",
                        details: AnswerDetails::Srv {
                            port: 1234,
                            target: "foo.local",
                        },
                    },
                    Answer {
                        owner: "bar._matterc._udp.local",
                        details: AnswerDetails::Txt(&[("D", "1234"), ("CM", "1")]),
                    },
                ],
            )],
        };

        run.run();
    }

    #[test]
    fn test_response_ignored() {
        // Test that mDNS responses (QR=1) are not replied to
        let host = Host {
            hostname: "foo",
            ip: Ipv4Addr::new(192, 168, 0, 1),
            ipv6: Ipv6Addr::UNSPECIFIED,
        };

        let test_service = TestService {
            name: "bar",
            service: "_matterc",
            protocol: "_udp",
            service_protocol: "_matterc._udp",
            port: 1234,
            service_subtypes: &[],
            txt_kvs: &[],
        };
        let service = test_service.as_service();

        // Build a response message (QR=1) with a question that would normally match
        let mut buf1 = [0; 1500];
        let message = unwrap!(
            MessageBuilder::from_target(Buf::new(&mut buf1)),
            "Failed to create message builder"
        );
        let mut qb = message.question();
        let header = qb.header_mut();
        header.set_id(3);
        header.set_opcode(Opcode::QUERY);
        header.set_rcode(Rcode::NOERROR);

        let mut flags = Flags::new();
        flags.qr = true; // This is a RESPONSE, not a query
        flags.aa = true;
        header.set_flags(flags);

        let dname = unwrap!(
            Name::<heapless::Vec<u8, 64>>::from_chars("foo.local".chars()),
            "Failed to convert question name"
        );
        unwrap!(
            qb.push((dname, Rtype::A, Class::IN)),
            "Failed to push question"
        );

        let len = qb.finish().as_ref().len();
        let data = &buf1[..len];

        let mut buf2 = [0; 1500];
        let (response_len, mode) = unwrap!(host.respond(&service, data, &mut buf2, 0, false));

        // Should produce no response since QR=1
        assert_eq!(response_len, 0, "mDNS response should be ignored (QR=1)");
        assert_eq!(mode, super::RespondMode::Skip);
    }

    /// RFC 6762 §6.7: legacy unicast resolver — query from non-5353 source port.
    /// Response must echo the question section, reuse the query's transaction ID,
    /// cap TTLs at 10s, omit the cache-flush bit, and indicate Unicast mode.
    #[test]
    fn test_legacy_unicast_response() {
        use domain::base::Question as DnsQuestion;
        use domain::rdata::AllRecordData;

        let host = Host {
            hostname: "foo",
            ip: Ipv4Addr::new(192, 168, 0, 1),
            ipv6: Ipv6Addr::UNSPECIFIED,
        };

        let test_service = TestService {
            name: "bar",
            service: "_matterc",
            protocol: "_udp",
            service_protocol: "_matterc._udp",
            port: 1234,
            service_subtypes: &[],
            txt_kvs: &[],
        };
        let service = test_service.as_service();

        // Build a legacy-style query: id=0xBEEF, single A question for foo.local.
        let query_id: u16 = 0xBEEF;
        let mut qbuf = [0u8; 1500];
        let qmsg = unwrap!(MessageBuilder::from_target(Buf::new(&mut qbuf)));
        let mut qb = qmsg.question();
        let qheader = qb.header_mut();
        qheader.set_id(query_id);
        qheader.set_opcode(Opcode::QUERY);
        let mut qflags = Flags::new();
        qflags.qr = false;
        qheader.set_flags(qflags);
        let qname = unwrap!(Name::<heapless::Vec<u8, 64>>::from_chars(
            "foo.local".chars()
        ));
        unwrap!(qb.push((qname, Rtype::A, Class::IN)));
        let qlen = qb.finish().as_ref().len();
        let query = &qbuf[..qlen];

        // Use a generous source TTL to verify the cap kicks in.
        let mut rbuf = [0u8; 1500];
        let (rlen, mode) = unwrap!(host.respond(&service, query, &mut rbuf, 600, true));

        assert!(rlen > 0, "expected a response");
        assert_eq!(mode, super::RespondMode::Unicast);

        let response = unwrap!(Message::from_octets(&rbuf[..rlen]));

        // Header: same id as query, QR=1, AA=1.
        let h = response.header();
        assert_eq!(h.id(), query_id, "legacy response must echo query id");
        assert!(h.flags().qr);
        assert!(h.flags().aa);

        // Question section must be echoed.
        let mut questions = response.question();
        let q: DnsQuestion<_> = unwrap!(unwrap!(questions.next(), "missing echoed question"));
        assert_eq!(q.qtype(), Rtype::A);
        assert!(q
            .qname()
            .name_eq(&unwrap!(Name::<heapless::Vec<u8, 64>>::from_chars(
                "foo.local".chars()
            ))));
        assert!(questions.next().is_none(), "exactly one echoed question");

        // Answer: A record for foo.local, TTL capped at 10, no cache-flush bit.
        let mut answers = unwrap!(response.answer());
        let answer = unwrap!(unwrap!(answers.next(), "missing answer"))
            .to_any_record::<AllRecordData<_, _>>()
            .unwrap();
        assert_eq!(
            answer.ttl().as_secs(),
            10,
            "legacy TTL must be capped at 10s"
        );
        assert_eq!(
            u16::from(answer.class()) & 0x8000,
            0,
            "legacy responses must NOT set the cache-flush bit"
        );
        match answer.data() {
            AllRecordData::A(a) => {
                assert_eq!(
                    Ipv4Addr::from(a.addr().octets()),
                    Ipv4Addr::new(192, 168, 0, 1)
                );
            }
            other => panic!("expected A record, got {:?}", debug2format!(&other)),
        }
        assert!(answers.next().is_none());
    }

    struct TestRun<'a> {
        host: Host<'a>,
        services: &'a [TestService<'a>],
        tests: &'a [(&'a [Question<'a>], &'a [Answer<'a>], &'a [Answer<'a>])],
    }

    impl TestRun<'_> {
        fn run(&self) {
            let mut query_buf = [0; 1500];

            // One response buffer per service (per the new "one UDP packet per service" design).
            // Pre-allocate so we can keep all responses alive for combined validation.
            let mut response_bufs: std::vec::Vec<[u8; 1500]> =
                self.services.iter().map(|_| [0u8; 1500]).collect();
            // If there are zero services, we still need at least one slot for the host-only case.
            if response_bufs.is_empty() {
                response_bufs.push([0; 1500]);
            }

            for (questions, expected_answers, expected_additional) in self.tests {
                // Multicast queries always carry ID 0 (RFC 6762 §18.1).
                let query = Question::prep(&mut query_buf, 0, questions);

                let mut response_lens: std::vec::Vec<usize> = std::vec::Vec::new();

                if self.services.is_empty() {
                    // Host-only path: still need to call `respond` once with a synthetic empty service
                    // so the host machinery has a chance to answer A/AAAA queries.
                    let synthetic = TestService {
                        name: "",
                        service: "_unused",
                        protocol: "_udp",
                        service_protocol: "_unused._udp",
                        port: 0,
                        service_subtypes: &[],
                        txt_kvs: &[],
                    };
                    let service = synthetic.as_service();
                    let (len, _) = unwrap!(self.host.respond(
                        &service,
                        query,
                        &mut response_bufs[0],
                        0,
                        false
                    ));
                    response_lens.push(len);
                } else {
                    for (i, ts) in self.services.iter().enumerate() {
                        let service = ts.as_service();
                        let (len, _) = unwrap!(self.host.respond(
                            &service,
                            query,
                            &mut response_bufs[i],
                            0,
                            false,
                        ));
                        response_lens.push(len);
                    }
                }

                let messages: std::vec::Vec<&[u8]> = response_lens
                    .iter()
                    .zip(response_bufs.iter())
                    .filter_map(|(&len, buf)| if len > 0 { Some(&buf[..len]) } else { None })
                    .collect();

                if messages.is_empty() {
                    assert!(
                        expected_answers.is_empty(),
                        "No responses but expected answers: {:?}",
                        expected_answers
                    );
                    assert!(
                        expected_additional.is_empty(),
                        "No responses but expected additional: {:?}",
                        expected_additional
                    );
                } else {
                    // Multicast responses always carry ID 0 (RFC 6762 §18.1).
                    Answer::validate_all(&messages, 0, expected_answers, expected_additional);
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
            let message = unwrap!(
                MessageBuilder::from_target(Buf::new(buf)),
                "Failed to create message builder"
            );

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
                let dname = unwrap!(
                    Name::<heapless::Vec<u8, 64>>::from_chars(question.name.chars()),
                    "Failed to convert question name"
                );

                unwrap!(
                    qb.push((dname, question.qtype, Class::IN)),
                    "Failed to push question"
                );
            }

            let len = qb.finish().as_ref().len();

            &buf[..len]
        }
    }

    #[derive(Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    enum AnswerDetails<'a> {
        A(Ipv4Addr),
        Aaaa(Ipv6Addr),
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
        /// Validate that the records produced by responding to a query — possibly spread
        /// across multiple per-service mDNS response packets — match the expected lists.
        fn validate_all(
            messages: &[&[u8]],
            expected_id: u16,
            expected_answers: &[Answer],
            expected_additional: &[Answer],
        ) {
            let mut answer_idx = 0;
            let mut additional_idx = 0;

            for data in messages {
                let message = unwrap!(
                    Message::from_octets(*data),
                    "Failed to convert data to message"
                );

                let header = message.header();
                ::core::assert_eq!(header.id(), expected_id);
                ::core::assert_eq!(header.opcode(), Opcode::QUERY);
                ::core::assert_eq!(header.rcode(), Rcode::NOERROR);

                Answer::validate_section_records(
                    message.answer().unwrap().into_iter(),
                    expected_answers,
                    &mut answer_idx,
                );
                Answer::validate_section_records(
                    message.additional().unwrap().into_iter(),
                    expected_additional,
                    &mut additional_idx,
                );
            }

            if answer_idx < expected_answers.len() {
                panic!("Missing answer {:?}", expected_answers[answer_idx]);
            }
            if additional_idx < expected_additional.len() {
                panic!(
                    "Missing additional {:?}",
                    expected_additional[additional_idx]
                );
            }
        }

        fn validate_section_records<'b, I>(
            records: I,
            expected_answers: &[Answer],
            expected_idx: &mut usize,
        ) where
            I: IntoIterator<
                Item = Result<ParsedRecord<'b, &'b [u8]>, domain::base::wire::ParseError>,
            >,
        {
            for answer_res in records {
                let answer = answer_res
                    .unwrap()
                    .to_any_record::<AllRecordData<_, _>>()
                    .unwrap();

                if *expected_idx >= expected_answers.len() {
                    panic!("Unexpected answer {:?}", debug2format!(&answer));
                }

                let expected = &expected_answers[*expected_idx];
                *expected_idx += 1;

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
                    other => panic!("Unexpected record type: {:?}", debug2format!(&other)),
                }
            }
        }
    }
}
