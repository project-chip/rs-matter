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

//! mDNS responder helpers for integration tests.
//!
//! Mirrors `examples/src/common/mdns.rs` with two additions needed when device
//! and controller share the same host (as in in-process tests):
//!
//! - `SO_REUSEPORT`: lets both the device's mDNS socket and the controller's
//!   discovery socket bind to port 5353 simultaneously.
//! - Multicast loopback (`IP_MULTICAST_LOOP` / `IPV6_MULTICAST_LOOP`): ensures
//!   multicast packets sent by the device are received by the controller on the
//!   same host.

use rs_matter::Matter;
use rs_matter::{crypto::Crypto, error::Error};

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

    // Both `avahi` and `resolve` modules are compiled under the single `zbus`
    // feature (there are no separate `avahi`/`resolve` features in rs-matter).
    // Avahi is the better default: systemd-resolved requires extra daemon
    // configuration while Avahi runs out-of-the-box on most Linux distros.
    #[cfg(all(
        feature = "zbus",
        not(any(feature = "zeroconf", feature = "astro-dnssd"))
    ))]
    rs_matter::transport::network::mdns::avahi::AvahiMdnsResponder::new(matter)
        .run(&rs_matter::utils::zbus::Connection::system().await.unwrap())
        .await?;

    #[cfg(not(any(feature = "zbus", feature = "zeroconf", feature = "astro-dnssd")))]
    run_builtin_mdns(matter, crypto).await?;

    Ok(())
}

#[allow(unused)]
async fn run_builtin_mdns<C: Crypto>(matter: &Matter<'_>, crypto: C) -> Result<(), Error> {
    use std::net::UdpSocket;

    use log::info;
    use socket2::{Domain, Protocol, Socket, Type};

    use rs_matter::transport::network::{Ipv4Addr, Ipv6Addr};

    #[inline(never)]
    fn initialize_network() -> Result<(Ipv4Addr, Ipv6Addr, u32), Error> {
        use log::error;
        use nix::{net::if_::InterfaceFlags, sys::socket::SockaddrIn6};
        use rs_matter::error::ErrorCode;

        let interfaces = || {
            nix::ifaddrs::getifaddrs().unwrap().filter(|ia| {
                ia.flags
                    .contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_BROADCAST)
                    && !ia
                        .flags
                        .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
            })
        };

        let (iname, ip, ipv6) = interfaces()
            .filter_map(|ia| {
                ia.address
                    .and_then(|addr| addr.as_sockaddr_in6().map(SockaddrIn6::ip))
                    .map(|ipv6| (ia.interface_name, ipv6))
            })
            .filter_map(|(iname, ipv6)| {
                interfaces()
                    .filter(|ia2| ia2.interface_name == iname)
                    .find_map(|ia2| {
                        ia2.address
                            .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip().into()))
                            .map(|ip: std::net::Ipv4Addr| (iname.clone(), ip, ipv6))
                    })
            })
            .next()
            .ok_or_else(|| {
                error!("Cannot find network interface suitable for mDNS broadcasting");
                ErrorCode::StdIoError
            })?;

        info!("Will use network interface {iname} with {ip}/{ipv6} for mDNS");

        Ok((ip.octets().into(), ipv6.octets().into(), 0 as _))
    }

    let (ipv4_addr, ipv6_addr, interface) = initialize_network()?;

    use rs_matter::transport::network::mdns::builtin::{BuiltinMdnsResponder, Host};
    use rs_matter::transport::network::mdns::{
        MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR, MDNS_SOCKET_DEFAULT_BIND_ADDR,
    };

    let mut socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    // SO_REUSEPORT: allows the controller's discovery socket to also bind to
    // port 5353 when device and controller run in the same process.
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_only_v6(false)?;
    // Multicast loopback: ensures the device's mDNS advertisements are
    // received by the controller socket on the same host.
    socket.set_multicast_loop_v4(true)?;
    socket.set_multicast_loop_v6(true)?;
    socket.bind(&MDNS_SOCKET_DEFAULT_BIND_ADDR.into())?;
    let socket = async_io::Async::<UdpSocket>::new_nonblocking(socket.into())?;

    socket
        .get_ref()
        .join_multicast_v6(&MDNS_IPV6_BROADCAST_ADDR, interface)?;
    socket
        .get_ref()
        .join_multicast_v4(&MDNS_IPV4_BROADCAST_ADDR, &ipv4_addr)?;

    BuiltinMdnsResponder::new()
        .run(
            &socket,
            &socket,
            &Host {
                hostname: "rs-matter-test",
                ip: ipv4_addr,
                ipv6: ipv6_addr,
            },
            Some(ipv4_addr),
            Some(interface),
            matter,
            crypto,
        )
        .await
}
