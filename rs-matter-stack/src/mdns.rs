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

use core::future::Future;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use rs_matter_crypto::Crypto;
use rs_matter_node::Matter;
use rs_matter_transport::network::mdns::builtin::BuiltinMdns;
use rs_matter_utils::error::Error;
use rs_matter_utils::storage::String;
use rs_matter_utils::sync::MaybeSend;

use crate::net::{NetSocket, NetStack};

/// The maximum number of IPv6 addresses of the operational network interface
/// that the stack tracks and advertises over mDNS.
///
/// The link-local address, a global unicast one and a unique local one - the set
/// a commissioner needs to reach the node whichever of the three it is on - plus
/// one spare. Anything beyond the limit is not advertised (with a warning).
pub const MAX_NETIF_IPV6_ADDRS: usize = 4;

/// A trait for running an mDNS responder.
pub trait Mdns: MaybeSend {
    /// Run the mDNS responder with the given network stack, MAC address, IPv4 and IPv6 addresses, and interface index.
    ///
    /// NOTE: This trait might change once `rs-matter` starts supporting mDNS resolvers
    ///
    /// # Arguments
    /// - `matter`: A reference to the `Matter` instance.
    /// - `crypto`: An object implementing the `Crypto` trait for cryptographic operations.
    /// - `net_stack`: The network stack for binding the UDP socket of the responder.
    /// - `mac`: The MAC address of the host, used to generate the hostname.
    /// - `ipv4`: The IPv4 address of the host, or `Ipv4Addr::UNSPECIFIED` for none.
    /// - `ipv6`: All IPv6 addresses of the host on the operational network interface -
    ///   a link-local one and, where the network provides on-link prefixes, one or more
    ///   routable (GUA / ULA) ones - as commissioners pick whichever of them they can reach.
    /// - `interface`: The interface index for the host, used for IPv6 multicast.
    #[allow(clippy::too_many_arguments)]
    fn run<C, S>(
        &mut self,
        matter: &Matter<'_>,
        crypto: &C,
        net_stack: &S,
        mac: &[u8],
        ipv4: Ipv4Addr,
        ipv6: &[Ipv6Addr],
        interface: u32,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        C: Crypto,
        S: NetStack;
}

impl<T> Mdns for &mut T
where
    T: Mdns,
{
    fn run<C, S>(
        &mut self,
        matter: &Matter<'_>,
        crypto: &C,
        net_stack: &S,
        mac: &[u8],
        ipv4: Ipv4Addr,
        ipv6: &[Ipv6Addr],
        interface: u32,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        C: Crypto,
        S: NetStack,
    {
        (*self).run(matter, crypto, net_stack, mac, ipv4, ipv6, interface)
    }
}

impl Mdns for BuiltinMdns {
    async fn run<C, S>(
        &mut self,
        matter: &Matter<'_>,
        crypto: &C,
        net_stack: &S,
        mac: &[u8],
        ipv4: Ipv4Addr,
        ipv6: &[Ipv6Addr],
        interface: u32,
    ) -> Result<(), Error>
    where
        C: Crypto,
        S: NetStack,
    {
        use core::fmt::Write as _;

        use rs_matter_transport::network::mdns::builtin::Host;
        use rs_matter_transport::network::mdns::{
            MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR, MDNS_PORT,
        };
        use rs_matter_transport::network::NetworkMulticast;

        let mut socket = net_stack
            .bind(
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0)),
                ipv4,
                interface,
            )
            .await?;

        let (send, recv, mut multicast) = socket.split();

        multicast.join(IpAddr::V4(MDNS_IPV4_BROADCAST_ADDR)).await?;
        multicast.join(IpAddr::V6(MDNS_IPV6_BROADCAST_ADDR)).await?;

        let mut hostname = String::<16>::new();
        if mac.len() == 6 {
            write_unwrap!(
                hostname,
                "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
        } else if mac.len() == 8 {
            write_unwrap!(
                hostname,
                "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5],
                mac[6],
                mac[7]
            );
        } else {
            panic!("Invalid MAC address length: should be 6 or 8 bytes");
        }

        BuiltinMdns::run(
            self,
            send,
            recv,
            &Host {
                hostname: &hostname,
                ip: ipv4,
                ipv6,
            },
            Some(ipv4),
            Some(interface),
            matter,
            crypto,
        )
        .await
    }
}

#[cfg(feature = "zbus")]
impl Mdns for rs_matter_transport::network::mdns::avahi::AvahiMdns {
    fn run<C, S>(
        &mut self,
        matter: &Matter<'_>,
        _crypto: &C,
        _net_stack: &S,
        _mac: &[u8],
        _ipv4: Ipv4Addr,
        _ipv6: &[Ipv6Addr],
        _interface: u32,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        C: Crypto,
        S: NetStack,
    {
        Self::run(self, matter)
    }
}

#[cfg(feature = "zbus")]
impl Mdns for rs_matter_transport::network::mdns::resolve::ResolveMdns {
    fn run<C, S>(
        &mut self,
        matter: &Matter<'_>,
        _crypto: &C,
        _net_stack: &S,
        _mac: &[u8],
        _ipv4: Ipv4Addr,
        _ipv6: &[Ipv6Addr],
        _interface: u32,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        C: Crypto,
        S: NetStack,
    {
        Self::run(self, matter)
    }
}

#[cfg(feature = "zeroconf")]
impl Mdns for rs_matter_transport::network::mdns::zeroconf::ZeroconfMdns {
    fn run<C, S>(
        &mut self,
        matter: &Matter<'_>,
        _crypto: &C,
        _net_stack: &S,
        _mac: &[u8],
        _ipv4: Ipv4Addr,
        _ipv6: &[Ipv6Addr],
        _interface: u32,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        C: Crypto,
        S: NetStack,
    {
        Self::run(self, matter)
    }
}

/// An mDNS responder for Matter using the `astro-dnssd` crate.
#[cfg(feature = "astro-dnssd")]
impl Mdns for rs_matter_transport::network::mdns::astro::AstroMdns {
    async fn run<C, S>(
        &mut self,
        matter: &Matter<'_>,
        _crypto: &C,
        _net_stack: &S,
        _mac: &[u8],
        _ipv4: Ipv4Addr,
        _ipv6: &[Ipv6Addr],
        _interface: u32,
    ) -> Result<(), Error>
    where
        C: Crypto,
        S: NetStack,
    {
        Self::run(self, matter).await
    }
}
