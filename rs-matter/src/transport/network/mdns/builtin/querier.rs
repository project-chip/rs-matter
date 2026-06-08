/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! mDNS query construction and response parsing for discovering Matter devices.
//!
//! This module is stateless: [`build_query`] turns a service type / instance
//! name into an outgoing mDNS query, and [`parse_into_answer`] turns a single
//! incoming mDNS response packet into a borrowed [`MdnsAnswer`] view that is
//! handed to a caller-supplied callback. Neither accumulates discovered devices
//! - that is left entirely to the caller, keeping discovery allocation-free.

use core::fmt::Write;

use domain::base::header::Flags;
use domain::base::iana::{Class, Opcode, Rcode, Rtype};
use domain::base::message_builder::MessageBuilder;
use domain::base::{Message, Name};
use domain::rdata::{Aaaa, Ptr, Srv, Txt, A};

use crate::error::Error;
use crate::transport::network::mdns::builtin::types::Buf;
use crate::transport::network::mdns::{score_ip_address, MdnsAnswer};
use crate::transport::network::{IpAddr, Ipv4Addr};

/// The maximum number of TXT key/value pairs surfaced per answer.
///
/// Matter commissionable records define ~10 TXT keys; 16 leaves headroom.
const MAX_TXT_KVS: usize = 16;

/// Build an mDNS browse query: a PTR question against a service type
/// (e.g. `_matterc._udp.local` or a subtype like `_L840._sub._matterc._udp.local`).
pub fn build_browse_query(service_type: &str, buf: &mut [u8]) -> Result<usize, Error> {
    build_query(service_type, Rtype::PTR, buf)
}

/// Build an mDNS resolve query: an `ANY` question against a specific instance
/// name (e.g. `ABCD1234._matterc._udp.local`), which compliant responders answer
/// with the instance's SRV/TXT records (plus A/AAAA in the additional section).
pub fn build_resolve_query(instance_name: &str, buf: &mut [u8]) -> Result<usize, Error> {
    build_query(instance_name, Rtype::ANY, buf)
}

/// Build an mDNS query for a given name and record type.
///
/// The query deliberately does *not* set the QU (unicast-response) bit, so
/// responders multicast their replies.
fn build_query(name: &str, rtype: Rtype, buf: &mut [u8]) -> Result<usize, Error> {
    let buf = Buf::new(buf);
    let message = MessageBuilder::from_target(buf)?;

    let mut question = message.question();

    let header = question.header_mut();
    header.set_id(0); // mDNS queries use ID 0
    header.set_opcode(Opcode::QUERY);
    header.set_rcode(Rcode::NOERROR);

    let mut flags = Flags::new();
    flags.qr = false; // This is a query
    header.set_flags(flags);

    let name = Name::<heapless::Vec<u8, 128>>::from_chars(name.chars())?;
    question.push((&name, rtype, Class::IN))?;

    let buf = question.finish();
    Ok(buf.1)
}

/// Check if two domain names match (case-insensitively, ignoring a trailing dot).
fn names_match(name1: &str, name2: &str) -> bool {
    name1
        .trim_end_matches('.')
        .eq_ignore_ascii_case(name2.trim_end_matches('.'))
}

/// Parse a single mDNS response packet and, if it describes a Matter service
/// instance, invoke `on_answer` with a borrowed [`MdnsAnswer`] view assembled
/// from *this packet only*.
///
/// `AD` bounds the number of addresses surfaced per answer (scratch size).
///
/// Non-responses (QR=0 queries) and packets without an instance name are
/// silently ignored. Records split across multiple packets are not merged -
/// see [`MdnsAnswer`] for the rationale.
pub fn parse_into_answer<const AD: usize, F>(data: &[u8], mut on_answer: F) -> Result<(), Error>
where
    F: FnMut(&MdnsAnswer<'_>),
{
    let message = Message::from_octets(data)?;

    // Only process responses (QR=1); ignore queries from other nodes.
    if !message.header().flags().qr {
        return Ok(());
    }

    // Scratch buffers, owned by this frame and borrowed by the emitted
    // `MdnsAnswer`. TXT pairs are assembled last (below) so their borrow into
    // the message stays alive for the duration of the `on_answer` call.
    let mut instance = heapless::String::<128>::new();
    let mut hostname = heapless::String::<128>::new();
    let mut addrs = heapless::Vec::<IpAddr, AD>::new();
    let mut port: Option<u16> = None;
    let mut have_srv = false;
    let mut have_ptr = false;

    // Pass 1: collect the instance name, and the SRV (port + target hostname).
    // The SRV owner is the instance name for both browse and resolve responses;
    // for browse-only responses (PTR but no SRV) we fall back to the PTR target.
    for section in [message.answer(), message.additional()] {
        let Ok(section) = section else { continue };

        for record in section {
            let Ok(record) = record else { continue };

            if let Ok(Some(srv)) = record.to_record::<Srv<_>>() {
                instance.clear();
                write_unwrap!(&mut instance, "{}", record.owner());
                hostname.clear();
                write_unwrap!(&mut hostname, "{}", srv.data().target());
                port = Some(srv.data().port());
                have_srv = true;
            } else if let Ok(Some(ptr)) = record.to_record::<Ptr<_>>() {
                if !have_srv && !have_ptr {
                    instance.clear();
                    write_unwrap!(&mut instance, "{}", ptr.data().ptrdname());
                    have_ptr = true;
                }
            }
        }
    }

    // Normalize: drop any trailing dot from the rendered names.
    trim_trailing_dot(&mut instance);
    trim_trailing_dot(&mut hostname);

    if instance.is_empty() {
        // Nothing resolvable in this packet.
        return Ok(());
    }

    // Pass 2: collect A/AAAA addresses for the SRV target hostname. We need a
    // second pass because A/AAAA records may precede the SRV in the packet.
    if !hostname.is_empty() {
        for section in [message.answer(), message.additional()] {
            let Ok(section) = section else { continue };

            for record in section {
                let Ok(record) = record else { continue };

                let mut owner = heapless::String::<128>::new();
                write_unwrap!(&mut owner, "{}", record.owner());

                if !names_match(&owner, &hostname) {
                    continue;
                }

                if let Ok(Some(a)) = record.to_record::<A>() {
                    push_addr(
                        &mut addrs,
                        IpAddr::V4(Ipv4Addr::from(a.data().addr().octets())),
                    );
                } else if let Ok(Some(aaaa)) = record.to_record::<Aaaa>() {
                    push_addr(
                        &mut addrs,
                        IpAddr::V6(core::net::Ipv6Addr::from(aaaa.data().addr().octets())),
                    );
                }
            }
        }
    }

    // Pass 3: find the TXT record for this instance and, while its borrow into
    // the message is still live, assemble the key/value pairs and emit the
    // answer. Keeping this inside the record's scope avoids holding a borrow of
    // the parsed message across iterations.
    for section in [message.answer(), message.additional()] {
        let Ok(section) = section else { continue };

        for record in section {
            let Ok(record) = record else { continue };

            let Ok(Some(txt)) = record.to_record::<Txt<_>>() else {
                continue;
            };

            let mut owner = heapless::String::<128>::new();
            write_unwrap!(&mut owner, "{}", record.owner());
            if !names_match(&owner, &instance) {
                continue;
            }

            let mut txt_pairs = heapless::Vec::<(&str, &str), MAX_TXT_KVS>::new();
            collect_txt(txt.data(), &mut txt_pairs);

            emit(
                &instance,
                &hostname,
                port,
                &addrs,
                &txt_pairs,
                &mut on_answer,
            );
            return Ok(());
        }
    }

    // No TXT record present: emit with empty TXT.
    emit(&instance, &hostname, port, &addrs, &[], &mut on_answer);

    Ok(())
}

/// Build an [`MdnsAnswer`] from the assembled parts and hand it to `on_answer`.
fn emit<F>(
    instance: &str,
    hostname: &str,
    port: Option<u16>,
    addrs: &[IpAddr],
    txt: &[(&str, &str)],
    on_answer: &mut F,
) where
    F: FnMut(&MdnsAnswer<'_>),
{
    let answer = MdnsAnswer {
        instance_name: instance,
        hostname: (!hostname.is_empty()).then_some(hostname),
        port,
        addrs,
        txt,
    };

    on_answer(&answer);
}

/// Strip a single trailing dot (the DNS root label) from a rendered name.
fn trim_trailing_dot(s: &mut heapless::String<128>) {
    if s.ends_with('.') {
        s.pop();
    }
}

/// Split a TXT record into key/value `&str` pairs, borrowing the record bytes.
fn collect_txt<'a>(
    txt: &'a Txt<&'a [u8]>,
    out: &mut heapless::Vec<(&'a str, &'a str), MAX_TXT_KVS>,
) {
    for item in txt.iter() {
        let Some(eq_pos) = item.iter().position(|&b| b == b'=') else {
            continue;
        };

        let (key, value) = (&item[..eq_pos], &item[eq_pos + 1..]);

        if let (Ok(key), Ok(value)) = (core::str::from_utf8(key), core::str::from_utf8(value)) {
            let _ = out.push((key, value));
        }
    }
}

/// Insert an address into `addrs`, deduplicated and kept sorted by descending
/// priority (see [`score_ip_address`]).
fn push_addr<const AD: usize>(addrs: &mut heapless::Vec<IpAddr, AD>, addr: IpAddr) {
    if addrs.contains(&addr) {
        return;
    }

    let score = score_ip_address(&addr);
    let pos = addrs
        .iter()
        .position(|a| score_ip_address(a) < score)
        .unwrap_or(addrs.len());

    if pos < AD {
        if addrs.len() >= AD {
            addrs.pop();
        }
        unwrap!(addrs.insert(pos, addr));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::transport::network::mdns::builtin::proto::Host;
    use crate::transport::network::mdns::Service;
    use crate::transport::network::Ipv6Addr;

    use domain::base::Message;

    const MAX_ADDRESSES_PER_DEVICE: usize = 4;

    fn host() -> Host<'static> {
        Host {
            hostname: "myhost",
            ip: Ipv4Addr::new(192, 168, 1, 5),
            ipv6: Ipv6Addr::UNSPECIFIED,
        }
    }

    /// Build a real commissionable response packet via `Host::broadcast`.
    fn commissionable_response(buf: &mut [u8], subtypes: &[&str]) -> usize {
        let service = Service {
            name: "ABCD1234",
            service: "_matterc",
            protocol: "_udp",
            service_protocol: "_matterc._udp",
            port: 5540,
            service_subtypes: subtypes.iter().copied(),
            txt_kvs: [("D", "1234"), ("VP", "65521+32769")].into_iter(),
        };

        host().broadcast(&service, buf, 60, 60).unwrap()
    }

    #[test]
    fn names_match_basic() {
        assert!(names_match("example.local", "example.local."));
        assert!(names_match("Example.Local.", "example.local"));
        assert!(!names_match("device1.local", "device2.local"));
        assert!(!names_match("device", "device.local"));
        assert!(names_match(
            "abcd1234._matterc._udp.local",
            "ABCD1234._MATTERC._UDP.LOCAL."
        ));
    }

    #[test]
    fn build_query_is_a_query() {
        let mut buf = [0u8; 512];
        let len = build_browse_query("_matterc._udp.local", &mut buf).unwrap();
        assert!(len > 0);

        let message = Message::from_octets(&buf[..len]).unwrap();
        assert!(!message.header().flags().qr); // a query, not a response
        assert_eq!(message.header().opcode(), Opcode::QUERY);
    }

    #[test]
    fn ignores_queries() {
        // A query packet (QR=0) must yield no answers.
        let mut buf = [0u8; 512];
        let len = build_browse_query("_matterc._udp.local", &mut buf).unwrap();

        let mut called = false;
        parse_into_answer::<MAX_ADDRESSES_PER_DEVICE, _>(&buf[..len], |_| called = true).unwrap();
        assert!(!called);
    }

    #[test]
    fn parses_full_response() {
        let mut buf = [0u8; 1024];
        let len = commissionable_response(&mut buf, &["_L1234", "_S3", "_CM"]);

        let mut seen = 0;
        parse_into_answer::<MAX_ADDRESSES_PER_DEVICE, _>(&buf[..len], |answer| {
            seen += 1;
            assert!(names_match(
                answer.instance_name,
                "ABCD1234._matterc._udp.local"
            ));
            assert_eq!(answer.port, Some(5540));
            assert!(names_match(answer.hostname.unwrap(), "myhost.local"));
            assert!(answer
                .addrs
                .contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))));

            // TXT round-trips into a DiscoveredDevice via the caller-side helper.
            let mut device = crate::transport::network::mdns::DiscoveredDevice::<
                MAX_ADDRESSES_PER_DEVICE,
            >::new();
            for (k, v) in answer.txt {
                device.set_txt_value(k, v);
            }
            assert_eq!(device.discriminator, 1234);
            assert_eq!(device.vendor_id, 65521);
            assert_eq!(device.product_id, 32769);
        })
        .unwrap();

        assert_eq!(seen, 1);
    }

    #[test]
    fn parses_response_without_txt() {
        // A response carrying SRV/A but no TXT yields an answer with empty TXT;
        // a caller filtering on discriminator would reject it. Documents the
        // intended "no cross-packet merge" gap.
        let mut buf = [0u8; 1024];
        let service = Service {
            name: "ABCD1234",
            service: "_matterc",
            protocol: "_udp",
            service_protocol: "_matterc._udp",
            port: 5540,
            service_subtypes: core::iter::empty(),
            txt_kvs: core::iter::empty::<(&str, &str)>(),
        };
        // Note: broadcast always appends an (empty) TXT record; to exercise the
        // "no usable TXT" path we assert the parsed pairs are empty instead.
        let len = host().broadcast(&service, &mut buf, 60, 60).unwrap();

        let mut seen = 0;
        parse_into_answer::<MAX_ADDRESSES_PER_DEVICE, _>(&buf[..len], |answer| {
            seen += 1;
            assert_eq!(answer.port, Some(5540));
            assert!(answer.txt.is_empty());
        })
        .unwrap();

        assert_eq!(seen, 1);
    }
}
