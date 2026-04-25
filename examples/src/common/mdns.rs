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

//! A module containing the mDNS code used in the examples

use rs_matter::Matter;
use rs_matter::{crypto::Crypto, error::Error};

use socket2::{Domain, Protocol, Socket, Type};

#[allow(unused)]
pub async fn run_mdns<C: Crypto>(matter: &Matter<'_>, crypto: C) -> Result<(), Error> {
    #[cfg(feature = "astro-dnssd")]
    rs_matter::transport::network::mdns::astro::AstroMdnsResponder::new(matter)
        .run()
        .await?;

    #[cfg(all(feature = "zeroconf", not(feature = "astro-dnssd")))]
    rs_matter::transport::network::mdns::zeroconf::ZeroconfMdnsResponder::new(matter)
        .run()
        .await?;

    #[cfg(all(
        feature = "resolve",
        not(any(feature = "zeroconf", feature = "astro-dnssd"))
    ))]
    rs_matter::transport::network::mdns::resolve::ResolveMdnsResponder::new(matter)
        .run(&rs_matter::utils::zbus::Connection::system().await.unwrap())
        .await?;

    #[cfg(all(
        feature = "avahi",
        not(any(feature = "resolve", feature = "zeroconf", feature = "astro-dnssd"))
    ))]
    rs_matter::transport::network::mdns::avahi::AvahiMdnsResponder::new(matter)
        .run(&rs_matter::utils::zbus::Connection::system().await.unwrap())
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

    use log::info;

    use rs_matter::transport::network::{Ipv4Addr, Ipv6Addr};

    // NOTE:
    // Replace with your own network initialization for e.g. `no_std` environments.
    //
    // Uses the cross-platform `if-addrs` crate to enumerate interfaces so the
    // examples work on Linux, macOS and Windows.
    #[inline(never)]
    fn initialize_network() -> Result<(Ipv4Addr, Ipv6Addr, u32), Error> {
        use log::error;
        use rs_matter::error::ErrorCode;

        let all = if_addrs::get_if_addrs().map_err(|_| ErrorCode::StdIoError)?;

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
        let find_candidate = |ipv6_filter: fn(std::net::Ipv6Addr) -> bool| {
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

        // Prefer an interface with a link-local IPv6 address …
        let candidate = find_candidate(|ip| (ip.segments()[0] & 0xffc0) == 0xfe80)
            // … otherwise accept any non-loopback IPv6 address
            .or_else(|| find_candidate(|_| true))
            .ok_or_else(|| {
                error!("Cannot find network interface suitable for mDNS broadcasting");
                ErrorCode::StdIoError
            })?;

        let (iname, ip, ipv6, index) = candidate;

        info!("Will use network interface {iname} with {ip}/{ipv6} for mDNS");

        Ok((ip.octets().into(), ipv6.octets().into(), index))
    }

    let (ipv4_addr, ipv6_addr, interface) = initialize_network()?;

    use rs_matter::transport::network::mdns::builtin::{BuiltinMdnsResponder, Host};
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

    BuiltinMdnsResponder::new(matter, crypto)
        .run(
            &socket,
            &socket,
            &Host {
                id: 0,
                hostname: "001122334455", //"rs-matter-demo",
                ip: ipv4_addr,
                ipv6: ipv6_addr,
            },
            Some(ipv4_addr),
            Some(interface),
        )
        .await
}
