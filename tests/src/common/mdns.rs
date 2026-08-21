/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

//! A module containing the mDNS code used in the examples

use rs_matter::transport::network::mdns::{DottedName, MdnsRemoteService};
use rs_matter::transport::network::{IpAddr, MatterRemoteService, SocketAddrV6};
use rs_matter::Matter;
use rs_matter::{crypto::Crypto, error::Error};

use socket2::{Domain, Protocol, Socket, Type};

#[allow(unused)]
pub async fn run_mdns<C: Crypto>(matter: &Matter<'_>, crypto: C) -> Result<(), Error> {
    #[cfg(feature = "astro-dnssd")]
    rs_matter::transport::network::mdns::astro::AstroMdns::new()
        .run(matter)
        .await?;

    #[cfg(all(feature = "zeroconf", not(feature = "astro-dnssd")))]
    rs_matter::transport::network::mdns::zeroconf::ZeroconfMdns::new()
        .run(matter)
        .await?;

    #[cfg(all(
        feature = "resolve",
        not(any(feature = "zeroconf", feature = "astro-dnssd"))
    ))]
    rs_matter::transport::network::mdns::resolve::ResolveMdns::new(
        rs_matter::utils::zbus::Connection::system().await.unwrap(),
    )
    .run(matter)
    .await?;

    #[cfg(all(
        feature = "avahi",
        not(any(feature = "resolve", feature = "zeroconf", feature = "astro-dnssd"))
    ))]
    rs_matter::transport::network::mdns::avahi::AvahiMdns::new(
        rs_matter::utils::zbus::Connection::system().await.unwrap(),
    )
    .run(matter)
    .await?;

    #[cfg(not(any(
        feature = "avahi",
        feature = "resolve",
        feature = "zeroconf",
        feature = "astro-dnssd"
    )))]
    run_builtin_mdns(matter, crypto).await?;

    Ok(())
}

#[allow(unused)]
async fn run_builtin_mdns<C: Crypto>(matter: &Matter<'_>, crypto: C) -> Result<(), Error> {
    use std::net::UdpSocket;

    use log::{debug, error, info, warn};

    use rs_matter::transport::network::{Ipv4Addr, Ipv6Addr};

    // NOTE:
    // Replace with your own network initialization for e.g. `no_std` environments.
    //
    // Uses the cross-platform `if-addrs` crate to enumerate interfaces so the
    // examples work on Linux, macOS and Windows.
    #[inline(never)]
    fn initialize_network() -> Result<(Ipv4Addr, Vec<Ipv6Addr>, u32), Error> {
        use rs_matter::error::ErrorCode;

        let all = if_addrs::get_if_addrs().map_err(|_| ErrorCode::StdIoError)?;
        debug!("Available network interfaces: {:?}", all);

        // A quick and dirty way to pick the interface we want: find one that
        // has both an IPv6 address AND a non-loopback IPv4 address assigned.
        // Prefer link-local (fe80::/10) IPv6 addresses — most likely that's
        // the "real" LAN interface we need, as opposed to all the
        // docker/libvirt/virtual interfaces that might be present on the
        // machine and which typically are IPv4-only.
        //
        // On Windows the `if_addrs` crate may omit link-local IPv6 addresses,
        // so we fall back to accepting any non-loopback IPv6 address paired
        // with an IPv4 address on the same interface.
        let find_ipv6_candidate = |ipv6_filter: fn(std::net::Ipv6Addr) -> bool| {
            all.iter()
                .filter(|ia| !ia.is_loopback())
                .filter_map(|ia| match ia.addr {
                    if_addrs::IfAddr::V6(ref v6) if ipv6_filter(v6.ip) => {
                        Some((ia.name.clone(), v6.ip, ia.index.unwrap_or(0)))
                    }
                    _ => None,
                })
                .find_map(|(iname, ipv6, index)| {
                    all.iter()
                        .filter(|ia2| ia2.name == iname)
                        .find_map(|ia2| match ia2.addr {
                            if_addrs::IfAddr::V4(ref v4) => {
                                Some((iname.clone(), v4.ip, ipv6, index))
                            }
                            _ => None,
                        })
                })
        };

        // Last-resort fallback trying to find the ethernet interface even if it doesn't have an IPv6 address assigned.
        let find_fallback_candidate = || {
            all.iter()
                .filter(|ia| !ia.is_loopback())
                .filter(|ia| ia.name.starts_with("eth") || ia.name.starts_with("eno"))
                .map(|ia| match ia.addr {
                    if_addrs::IfAddr::V4(ref v4) => (
                        ia.name.clone(),
                        v4.ip,
                        std::net::Ipv6Addr::UNSPECIFIED,
                        ia.index.unwrap_or(0),
                    ),
                    if_addrs::IfAddr::V6(ref v6) => (
                        ia.name.clone(),
                        std::net::Ipv4Addr::UNSPECIFIED,
                        v6.ip,
                        ia.index.unwrap_or(0),
                    ),
                })
                .next()
        };

        // Prefer an interface with a link-local IPv6 address
        let candidate = find_ipv6_candidate(|ip| ip.is_unicast_link_local())
            // otherwise accept any non-loopback IPv6 address
            .or_else(|| find_ipv6_candidate(|_| true))
            // otherwise do one last fallback: accept an interface named "eth*" or "eno*" with a non-loopback IPv4 address
            // even if it doesn't have an IPv6 address assigned.
            //
            // This is a common scenario in VMs and containers where the host might not provide an IPv6 address - including GH actions.
            .or_else(|| {
                warn!("No network interface with a suitable IPv6 address found");
                find_fallback_candidate()
            })
            .ok_or_else(|| {
                error!("Cannot find network interface suitable for mDNS broadcasting");
                ErrorCode::StdIoError
            })?;

        let (iname, ip, ipv6, index) = candidate;

        // Advertise *every* IPv6 address configured on the chosen interface, not
        // only the one that got the interface selected. A node has to publish an
        // AAAA record for each address it accepts Matter messages on; publishing
        // only the link-local one leaves it unreachable to any peer that learns
        // of it across a subnet boundary (an mDNS reflector, or the DNS-SD proxy
        // of a Thread border router), because the relayed record then carries
        // nothing routable.
        let mut ipv6_addrs: Vec<Ipv6Addr> = Vec::new();

        if !ipv6.is_unspecified() {
            ipv6_addrs.push(ipv6.octets().into());
        }

        for ia in all.iter().filter(|ia| ia.name == iname) {
            if let if_addrs::IfAddr::V6(ref v6) = ia.addr {
                let addr: Ipv6Addr = v6.ip.octets().into();

                if !v6.ip.is_loopback() && !ipv6_addrs.contains(&addr) {
                    ipv6_addrs.push(addr);
                }
            }
        }

        info!("Will use network interface {iname} with {ip} / {ipv6_addrs:?} for mDNS");

        Ok((ip.octets().into(), ipv6_addrs, index))
    }

    let (ipv4_addr, ipv6_addrs, interface) = initialize_network()?;

    use rs_matter::transport::network::mdns::builtin::{BuiltinMdns, Host};
    use rs_matter::transport::network::mdns::{
        MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR, MDNS_SOCKET_DEFAULT_BIND_ADDR,
    };

    // NOTE:
    // When using a custom UDP stack (e.g. for `no_std` environments), replace with a UDP socket bind + multicast join for your custom UDP stack
    // The returned socket should be splittable into two halves, where each half implements `UdpSend` and `UdpReceive` respectively
    let mut socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_only_v6(false)?;
    socket.bind(&MDNS_SOCKET_DEFAULT_BIND_ADDR.into())?;
    let socket = async_io::Async::<UdpSocket>::new_nonblocking(socket.into())?;

    socket
        .get_ref()
        .join_multicast_v6(&MDNS_IPV6_BROADCAST_ADDR, interface)?;
    socket
        .get_ref()
        .join_multicast_v4(&MDNS_IPV4_BROADCAST_ADDR, &ipv4_addr)?;

    BuiltinMdns::new()
        .run(
            &socket,
            &socket,
            &Host {
                hostname: "001122334455", //"rs-matter-demo",
                ip: ipv4_addr,
                ipv6: &ipv6_addrs,
            },
            Some(ipv4_addr),
            Some(interface),
            matter,
            crypto,
        )
        .await
}

/// Answer operational mDNS resolve requests from a fixed `node_id -> address`
/// table, standing in for a real mDNS backend.
///
/// Tests drive commissioning phase 2 (and anything else that resolves a peer)
/// against devices at addresses they already know, but the production code path
/// deliberately goes through discovery rather than taking a known address. This
/// closes that gap without binding port 5353 on a real interface, which would
/// make the tests depend on the host's network and on no other responder
/// running.
///
/// Never returns - run it concurrently with whatever drives the resolves, e.g.
/// `select(work, stub_mdns_resolver(matter, &table))`.
#[allow(unused)]
pub async fn stub_mdns_resolver(matter: &Matter<'_>, table: &[(u64, SocketAddrV6)]) -> ! {
    stub_mdns_resolver_txt(matter, table, "").await
}

/// [`stub_mdns_resolver`], additionally advertising a `T` TXT value.
///
/// `T` is the TCP-support bitmap (bit 1 = client, bit 2 = server), so `"6"`
/// makes the stubbed peer look TCP-capable and `""` omits the key entirely, as a
/// node without TCP support does. It gates whether a
/// [`TransportPreference::LargePayload`](rs_matter::transport::TransportPreference)
/// request is allowed to establish over TCP.
#[allow(unused)]
pub async fn stub_mdns_resolver_txt(
    matter: &Matter<'_>,
    table: &[(u64, SocketAddrV6)],
    tcp: &str,
) -> ! {
    loop {
        let service = matter.transport().wait_mdns_resolve_request().await;

        let MatterRemoteService::Operational { node_id, .. } = &service else {
            continue;
        };

        let Some((_, sock)) = table.iter().find(|(id, _)| id == node_id) else {
            continue;
        };

        let mut name = heapless::String::<128>::new();
        service.instance_name(&mut name);

        matter.transport().try_deposit_mdns_resolve(
            &MdnsRemoteService {
                instance_name: DottedName(name.as_str()),
                port: Some(sock.port()),
                addrs: core::iter::once(IpAddr::V6(*sock.ip())),
                txt: (!tcp.is_empty()).then_some(("T", tcp)).into_iter(),
                scope_id: 0,
            },
            &[],
        );
    }
}
