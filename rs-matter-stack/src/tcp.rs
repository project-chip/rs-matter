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

use core::future::Future;
use core::net::SocketAddr;

pub use rs_matter_transport::network::tcp::{
    NetTcpListener, NetTcpSocket, NoTcp, TcpConfig, TcpServer,
};
use rs_matter_utils::error::Error;
use rs_matter_utils::sync::{MaybeSend, MaybeSendSync};

/// A network stack capable of binding an operational TCP server.
pub trait TcpStack: MaybeSendSync {
    /// The TCP listener returned by [`Self::bind`].
    type Listener: NetTcpListener;

    /// Bind a TCP listener to the specified address and return a bounded [`TcpServer`].
    fn bind(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpServer<Self::Listener>, Error>> + MaybeSend;
}

impl<T: TcpStack> TcpStack for &T {
    type Listener = T::Listener;

    fn bind(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpServer<Self::Listener>, Error>> + MaybeSend {
        (*self).bind(addr)
    }
}

impl TcpStack for NoTcp {
    type Listener = NoTcp;

    fn bind(
        &self,
        _addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpServer<Self::Listener>, Error>> + MaybeSend {
        core::future::ready(Err(
            rs_matter_utils::error::ErrorCode::NoNetworkInterface.into()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn no_tcp_stack_returns_no_network_interface() {
        futures_lite::future::block_on(async {
            let stack = NoTcp;
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5540));
            let result = TcpStack::bind(&stack, addr).await;
            assert!(result.is_err());
        });
    }
}
