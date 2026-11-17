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

//! Operational TCP stack abstractions for embedded and host network stacks.

pub use crate::net::{NetTcp, NetTcpStack};
pub use rs_matter_transport::network::tcp::{
    NoTcp, TcpConfig, TcpKeepAlive, TcpNetwork, TcpNetworkBuffers, TcpNetworkRead,
    TcpNetworkSocket, TcpNetworkSockets, TcpNetworkWrite,
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[test]
    fn no_tcp_stack_returns_no_network_interface() {
        futures_lite::future::block_on(async {
            let stack = NoTcp;
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5540));
            let result = NetTcpStack::bind(&stack, addr).await;
            assert!(result.is_err());
        });
    }
}
