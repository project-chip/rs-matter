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

//! Arbitrary bytes as an mDNS message: a query to the responder of a node, which
//! any host on the network can send, and a response to the browser of a controller.

#![no_main]

use core::net::{Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;

use rs_matter_transport::network::mdns::builtin::{parse_into_answer, Host};
use rs_matter_transport::network::mdns::MdnsLocalService;

const IPV6: [Ipv6Addr; 1] = [Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)];

fuzz_target!(|data: &[u8]| {
    let host = Host {
        hostname: "001122334455",
        ip: Ipv4Addr::new(192, 168, 0, 2),
        ipv6: &IPV6,
    };

    let service = MdnsLocalService {
        name: "0011223344556677",
        service: "_matterc",
        protocol: "_udp",
        service_protocol: "_matterc._udp",
        port: 5540,
        service_subtypes: ["_L3840", "_S15", "_CM"].into_iter(),
        txt_kvs: [("D", "3840"), ("CM", "1")].into_iter(),
    };

    let mut buf = [0; 1500];
    let _ = host.respond(&service, data, &mut buf, 120, false);
    let _ = host.respond(&service, data, &mut buf, 120, true);

    if let Ok(Some(answer)) = parse_into_answer(data, Some(1)) {
        let _ = format!("{}", answer.instance_name);
        answer.addrs.for_each(drop);
        answer.txt.for_each(drop);
    }
});
