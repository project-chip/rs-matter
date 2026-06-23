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
//! incoming mDNS response packet into a borrowed [`MdnsRemoteService`] view that is
//! handed to a caller-supplied callback. Neither accumulates discovered devices
//! - that is left entirely to the caller, keeping discovery allocation-free.

use domain::base::header::Flags;
use domain::base::iana::{Class, Opcode, Rcode, Rtype};
use domain::base::message_builder::MessageBuilder;
use domain::base::{Message, ParsedName, ToName, UnknownRecordData};
use domain::rdata::{Aaaa, Ptr, Srv, A};

use crate::error::Error;
use crate::transport::network::mdns::builtin::types::Buf;
use crate::transport::network::mdns::MdnsRemoteService;
use crate::transport::network::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Build an mDNS browse query: a PTR question against a service type
/// (e.g. `_matterc._udp.local` or a subtype like `_L840._sub._matterc._udp.local`).
///
/// `name` is any [`ToName`] - the builtin passes a [`NameSlice`] built straight
/// from labels, so no name buffer is allocated or re-parsed.
///
/// [`NameSlice`]: crate::transport::network::mdns::builtin::types::NameSlice
pub fn build_browse_query(name: impl ToName, buf: &mut [u8]) -> Result<usize, Error> {
    build_query(name, Rtype::PTR, buf)
}

/// Build an mDNS resolve query: an `ANY` question against a specific instance
/// name (e.g. `ABCD1234._matterc._udp.local`), which compliant responders answer
/// with the instance's SRV/TXT records (plus A/AAAA in the additional section).
///
/// `name` is any [`ToName`] (see [`build_browse_query`]).
pub fn build_resolve_query(name: impl ToName, buf: &mut [u8]) -> Result<usize, Error> {
    build_query(name, Rtype::ANY, buf)
}

/// Build an mDNS query for a given name and record type.
///
/// The query deliberately does *not* set the QU (unicast-response) bit, so
/// responders multicast their replies. The name is composed straight into the
/// message buffer (no intermediate name buffer).
fn build_query(name: impl ToName, rtype: Rtype, buf: &mut [u8]) -> Result<usize, Error> {
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

    question.push((name, rtype, Class::IN))?;

    let buf = question.finish();
    Ok(buf.1)
}

/// A lazy iterator over the A/AAAA addresses of a parsed mDNS answer.
///
/// Re-walks the packet's answer + additional sections on each step, yielding the
/// address of every A/AAAA record whose owner matches the SRV target hostname -
/// so no address buffer is ever materialized. Addresses come out in packet
/// order; callers that want the "best" address score them (see
/// [`score_ip_address`](crate::transport::network::mdns::score_ip_address)).
#[derive(Debug, Clone, Copy)]
pub struct MdnsAddrs<'a> {
    msg: Message<&'a [u8]>,
    /// The SRV target hostname to correlate A/AAAA records against, or `None`
    /// (e.g. a PTR-only answer) - in which case no address is ever yielded.
    target: Option<ParsedName<&'a [u8]>>,
    /// How many matching addresses have already been yielded (re-walk cursor).
    yielded: usize,
}

impl Iterator for MdnsAddrs<'_> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        let target = self.target?;

        let mut seen = 0;
        for section in [self.msg.answer(), self.msg.additional()] {
            let Ok(section) = section else { continue };

            for record in section {
                let Ok(record) = record else { continue };

                if record.owner() != target {
                    continue;
                }

                let addr = if let Ok(Some(rec)) = record.to_record::<A>() {
                    IpAddr::V4(Ipv4Addr::from(rec.data().addr().octets()))
                } else if let Ok(Some(rec)) = record.to_record::<Aaaa>() {
                    IpAddr::V6(Ipv6Addr::from(rec.data().addr().octets()))
                } else {
                    continue;
                };

                if seen == self.yielded {
                    self.yielded += 1;
                    return Some(addr);
                }
                seen += 1;
            }
        }

        None
    }
}

/// A lazy iterator over the `key=value` TXT pairs of a parsed mDNS answer.
///
/// Borrows the TXT record's raw rdata directly out of the receive buffer and
/// splits it into character strings (then each on its first `=`) on the fly - so
/// no TXT buffer is materialized and there is no upper bound on the pair count.
/// Entries that aren't valid UTF-8 or lack a `=` are skipped.
#[derive(Debug, Clone, Copy)]
pub struct MdnsTxt<'a> {
    /// Raw TXT rdata: a sequence of length-prefixed character strings.
    data: &'a [u8],
    pos: usize,
}

impl<'a> MdnsTxt<'a> {
    /// An empty TXT iterator (for answers carrying no TXT record).
    const fn empty() -> Self {
        Self { data: &[], pos: 0 }
    }

    /// Wrap raw TXT rdata (a sequence of length-prefixed character strings).
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> Iterator for MdnsTxt<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<(&'a str, &'a str)> {
        while self.pos < self.data.len() {
            let len = self.data[self.pos] as usize;
            let start = self.pos + 1;
            let end = (start + len).min(self.data.len());
            self.pos = end;

            if let Ok(s) = core::str::from_utf8(&self.data[start..end]) {
                if let Some(eq) = s.find('=') {
                    return Some((&s[..eq], &s[eq + 1..]));
                }
            }
        }

        None
    }
}

/// Parse a single mDNS response packet into a lazy [`MdnsRemoteService`] view
/// assembled from *this packet only*, or `None` if the packet is a query (QR=0)
/// or carries no resolvable instance name.
///
/// The returned view borrows the packet buffer and materializes nothing: its
/// `addrs`/`txt` walk the records on demand (see [`MdnsAddrs`] / [`MdnsTxt`]).
/// Records split across multiple packets are not merged - see
/// [`MdnsRemoteService`] for the rationale.
///
/// `ipv6_scope` is the interface index the builtin backend listens on (its
/// configured `ipv6_interface`); it is stamped onto the result as the IPv6
/// scope id so a link-local (`fe80::`) AAAA record becomes routable. It is the
/// only interface the builtin mDNS sends/receives on, so any link-local result
/// is necessarily reachable through it. `None` (no specific interface) maps to
/// the unscoped sentinel `0`.
#[allow(clippy::type_complexity)]
pub fn parse_into_answer(
    data: &[u8],
    ipv6_scope: Option<u32>,
) -> Result<Option<MdnsRemoteService<ParsedName<&[u8]>, MdnsAddrs<'_>, MdnsTxt<'_>>>, Error> {
    let msg = Message::from_octets(data)?;

    // Only process responses (QR=1); ignore queries from other nodes.
    if !msg.header().flags().qr {
        return Ok(None);
    }

    // Pass 1: the instance name + SRV (port + target hostname). The SRV owner is
    // the instance name for both browse and resolve responses; for browse-only
    // responses (PTR but no SRV) we fall back to the PTR target.
    let mut instance: Option<ParsedName<&[u8]>> = None;
    let mut hostname: Option<ParsedName<&[u8]>> = None;
    let mut port: Option<u16> = None;
    let mut have_srv = false;

    for section in [msg.answer(), msg.additional()] {
        let Ok(section) = section else { continue };

        for record in section {
            let Ok(record) = record else { continue };

            if let Ok(Some(rec)) = record.to_record::<Srv<_>>() {
                instance = Some(*rec.owner());
                hostname = Some(*rec.data().target());
                port = Some(rec.data().port());
                have_srv = true;
            } else if !have_srv && instance.is_none() {
                if let Ok(Some(rec)) = record.to_record::<Ptr<_>>() {
                    instance = Some(*rec.data().ptrdname());
                }
            }
        }
    }

    let Some(instance) = instance else {
        // Nothing resolvable in this packet.
        return Ok(None);
    };

    // The TXT record for this instance, kept as raw rdata to be split lazily.
    let mut txt = MdnsTxt::empty();
    'txt: for section in [msg.answer(), msg.additional()] {
        let Ok(section) = section else { continue };

        for record in section {
            let Ok(record) = record else { continue };

            if record.rtype() != Rtype::TXT || record.owner() != instance {
                continue;
            }

            if let Ok(Some(rec)) = record.to_record::<UnknownRecordData<_>>() {
                // Copy the `&'a` rdata slice out by pattern (an explicit `*`
                // would reborrow it to the temporary record's shorter lifetime).
                let &data = rec.data().data();
                txt = MdnsTxt::new(data);
            }
            break 'txt;
        }
    }

    Ok(Some(MdnsRemoteService {
        instance_name: instance,
        port,
        addrs: MdnsAddrs {
            msg,
            target: hostname,
            yielded: 0,
        },
        txt,
        // The builtin backend listens on a single configured interface, so a
        // link-local AAAA result is reachable through it: stamp that interface
        // index as the IPv6 scope id (`0` = unscoped, when none was configured).
        scope_id: ipv6_scope.unwrap_or(0),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::fmt::Write as _;

    use crate::transport::network::mdns::builtin::respond::Host;
    use crate::transport::network::mdns::builtin::types::NameSlice;
    use crate::transport::network::mdns::MdnsLocalService;
    use crate::transport::network::Ipv6Addr;

    use domain::base::Message;

    /// Render a parsed instance name to a `String` for comparison.
    fn name_str(name: ParsedName<&[u8]>) -> heapless::String<64> {
        let mut s = heapless::String::new();
        write!(s, "{}", name).unwrap();
        while s.ends_with('.') {
            s.pop();
        }
        s
    }

    fn host() -> Host<'static> {
        Host {
            hostname: "myhost",
            ip: Ipv4Addr::new(192, 168, 1, 5),
            ipv6: Ipv6Addr::UNSPECIFIED,
        }
    }

    /// Build a real commissionable response packet via `Host::broadcast`.
    fn commissionable_response(buf: &mut [u8], subtypes: &[&str]) -> usize {
        let service = MdnsLocalService {
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
    fn build_query_is_a_query() {
        let mut buf = [0u8; 512];
        let len =
            build_browse_query(NameSlice::new(["_matterc", "_udp", "local"]), &mut buf).unwrap();
        assert!(len > 0);

        let message = Message::from_octets(&buf[..len]).unwrap();
        assert!(!message.header().flags().qr); // a query, not a response
        assert_eq!(message.header().opcode(), Opcode::QUERY);
    }

    #[test]
    fn ignores_queries() {
        // A query packet (QR=0) must yield no answer.
        let mut buf = [0u8; 512];
        let len =
            build_browse_query(NameSlice::new(["_matterc", "_udp", "local"]), &mut buf).unwrap();

        assert!(parse_into_answer(&buf[..len], None).unwrap().is_none());
    }

    #[test]
    fn parses_full_response() {
        let mut buf = [0u8; 1024];
        let len = commissionable_response(&mut buf, &["_L1234", "_S3", "_CM"]);

        // A configured IPv6 interface index is threaded through as the scope id.
        let answer = parse_into_answer(&buf[..len], Some(7)).unwrap().unwrap();
        assert_eq!(answer.scope_id, 7);

        assert_eq!(
            name_str(answer.instance_name).as_str(),
            "ABCD1234._matterc._udp.local"
        );
        assert_eq!(answer.port, Some(5540));
        assert!(answer
            .addrs
            .clone()
            .any(|a| a == IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))));

        // The parsed TXT records filter correctly via CommissionableFilter.
        let filter = crate::transport::network::mdns::CommissionableFilter {
            discriminator: Some(1234),
            vendor_id: Some(65521),
            product_id: Some(32769),
            ..Default::default()
        };
        assert!(filter.matches(&answer));
    }

    #[test]
    fn parses_response_without_txt() {
        // A response carrying SRV/A but no usable TXT yields an answer whose TXT
        // iterator is empty; a caller filtering on discriminator would reject it.
        // Documents the intended "no cross-packet merge" gap.
        let mut buf = [0u8; 1024];
        let service = MdnsLocalService {
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

        // No interface configured → unscoped (scope id 0).
        let answer = parse_into_answer(&buf[..len], None).unwrap().unwrap();

        assert_eq!(answer.port, Some(5540));
        assert_eq!(answer.scope_id, 0);
        assert_eq!(answer.txt.count(), 0);
    }
}
