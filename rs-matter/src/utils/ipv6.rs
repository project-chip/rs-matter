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

use core::net::Ipv6Addr;

/// Create a link-local IPv6 address from a MAC address.
///
/// Note that this function does not perform any SLAAC-related operations
/// like checking whether the generated address is already in use.
pub fn create_link_local_ipv6(mac: &[u8; 6]) -> Ipv6Addr {
    Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        u16::from_be_bytes([mac[0] ^ 0x02, mac[1]]),
        u16::from_be_bytes([mac[2], 0xff]),
        u16::from_be_bytes([0xfe, mac[3]]),
        u16::from_be_bytes([mac[4], mac[5]]),
    )
}

/// Compute the Matter IPv6 multicast address for a given fabric and group.
///
/// Per Matter Core Specification Section 4.3.1 and RFC 3306:
/// - Network prefix (bytes 4-11): 0xFD + upper 56 bits of fabric_id
/// - Group ID (bytes 12-15): lower 8 bits of fabric_id + 0x00 + group_id
pub fn compute_group_multicast_addr(fabric_id: u64, group_id: u16) -> Ipv6Addr {
    let prefix = 0xfd00_0000_0000_0000_u64 | ((fabric_id >> 8) & 0x00ff_ffff_ffff_ffff);
    let group32 = ((fabric_id as u32) << 24) | group_id as u32;

    let mut octets = [0u8; 16];
    octets[0] = 0xff;
    octets[1] = 0x35; // flags=0x3 (transient), scope=0x5 (site-local)
    octets[2] = 0x00; // reserved
    octets[3] = 0x40; // plen = 64
    octets[4..12].copy_from_slice(&prefix.to_be_bytes());
    octets[12..16].copy_from_slice(&group32.to_be_bytes());

    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::alloc::string::ToString;

    extern crate alloc;

    #[test]
    fn test_compute_group_multicast_addr() {
        // fabric_id = 0x0001_0002_0003_0004, group_id = 0x0001
        let addr = compute_group_multicast_addr(0x0001_0002_0003_0004, 0x0001);
        let octets = addr.octets();
        assert_eq!(octets[0], 0xff);
        assert_eq!(octets[1], 0x35);
        assert_eq!(octets[2], 0x00);
        assert_eq!(octets[3], 0x40);
        // prefix: 0xFD + upper 56 bits of fabric_id (0x00_0100_0200_0300)
        // => 0xFD00_0100_0200_0300
        assert_eq!(&octets[4..12], &0xfd00_0100_0200_0300_u64.to_be_bytes());
        // group32: lower 8 bits of fabric_id (0x04) << 24 | 0x0001
        // => 0x04000001
        assert_eq!(&octets[12..16], &0x04000001_u32.to_be_bytes());
    }

    #[test]
    fn test_create_link_local_ipv6() {
        let mac = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let ipv6 = create_link_local_ipv6(&mac);
        assert_eq!(ipv6.to_string(), "fe80::1034:56ff:fe78:9abc");

        let mac2 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ipv6_2 = create_link_local_ipv6(&mac2);
        assert_eq!(ipv6_2.to_string(), "fe80::211:22ff:fe33:4455");

        let mac3 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let ipv6_3 = create_link_local_ipv6(&mac3);
        assert_eq!(ipv6_3.to_string(), "fe80::302:3ff:fe04:506");
    }
}
