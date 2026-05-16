/*
 *
 *    Copyright (c) 2023-2026 Project CHIP Authors
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

use rand_core::RngCore;

use crate::handler_chain_type;

use super::clusters::acl::{self, AclHandler, ClusterHandler as _};
use super::clusters::adm_comm::{self, AdminCommHandler, ClusterHandler as _};
use super::clusters::basic_info::{self, BasicInfoHandler, ClusterHandler as _};
use super::clusters::desc::{self, ClusterHandler as _, DescHandler};
use super::clusters::eth_diag::{self, ClusterHandler as _, EthDiagHandler};
use super::clusters::gen_comm::{self, ClusterHandler as _, CommPolicy, GenCommHandler};
use super::clusters::gen_diag::{self, ClusterHandler as _, GenDiag, GenDiagHandler, NetifDiag};
use super::clusters::grp_key_mgmt::{self, ClusterHandler as _, GrpKeyMgmtHandler};
use super::clusters::net_comm::{
    self, ClusterAsyncHandler as _, NetCommHandler, NetCtl, NetCtlStatus,
};
use super::clusters::noc::{self, ClusterHandler as _, NocHandler};
use super::clusters::sw_diag::{self, ClusterHandler as _, SwDiagHandler};
use super::clusters::thread_diag::{self, ClusterHandler as _, ThreadDiag, ThreadDiagHandler};
use super::clusters::wifi_diag::{self, ClusterHandler as _, WifiDiag, WifiDiagHandler};
use super::networks::eth::EthNetCtl;
use super::types::{Async, ChainedHandler, Dataver, EndptId, EpClMatcher};

/// A macro to generate the meta-data for the root endpoint (Endpoint 0).
///
/// Valid arguments:
/// - `sys` - includes all system model clusters EXCEPT the concrete Network Diagnostics cluster (i.e. Ethernet, Thread or Wifi).
///   Typically, you would prefer to use `eth`, `wifi` or `thread` instead of `sys`, which do include the appropriate
///   Network Diagnostics cluster based on the network type.
/// - `eth` - includes all system model clusters + the Ethernet Network Diagnostics cluster.
/// - `wifi` - includes all system model clusters + the Wi-Fi Network Diagnostics cluster.
/// - `thread` - includes all system model clusters + the Thread Network Diagnostics cluster.
///
/// The Groups cluster is intentionally not part of any of these presets — it
/// is not a Root Node device-type cluster and has no defined behavior on the
/// root endpoint. Add `GroupsHandler::CLUSTER` to the application endpoint(s)
/// where group-addressed traffic is actually meaningful.
#[allow(unused_macros)]
#[macro_export]
macro_rules! root_endpoint {
    ($t:ident) => {
        $crate::dm::Endpoint {
            id: $crate::dm::endpoints::ROOT_ENDPOINT_ID,
            device_types: $crate::devices!($crate::dm::devices::DEV_TYPE_ROOT_NODE),
            clusters: $crate::clusters!($t;),
            client_clusters: &[],
        }
    }
}

/// A type alias for the handler chain returned by `with_eth_sys()`.
pub type EthSysHandler<'a, H> = handler_chain_type!(
    EpClMatcher => Async<eth_diag::HandlerAdaptor<EthDiagHandler>>
    | SysHandler<'a, EthNetCtl, H>
);

/// A type alias for the handler chain returned by `with_wifi_sys()`.
pub type WifiSysHandler<'a, T, H> = handler_chain_type!(
    EpClMatcher => Async<wifi_diag::HandlerAdaptor<WifiDiagHandler<'a>>>
    | SysHandler<'a, T, H>
);

/// A type alias for the handler chain returned by `with_thread_sys()`.
pub type ThreadSysHandler<'a, T, H> = handler_chain_type!(
    EpClMatcher => Async<thread_diag::HandlerAdaptor<ThreadDiagHandler<'a>>>
    | SysHandler<'a, T, H>
);

/// A type alias for the handler chain returned by `with_sys()`.
pub type SysHandler<'a, T, H> = handler_chain_type!(
    EpClMatcher => Async<desc::HandlerAdaptor<DescHandler<'a>>>,
    EpClMatcher => Async<basic_info::HandlerAdaptor<BasicInfoHandler>>,
    EpClMatcher => Async<gen_comm::HandlerAdaptor<GenCommHandler<'a>>>,
    EpClMatcher => Async<adm_comm::HandlerAdaptor<AdminCommHandler>>,
    EpClMatcher => Async<noc::HandlerAdaptor<NocHandler>>,
    EpClMatcher => Async<acl::HandlerAdaptor<acl::AclHandler>>,
    EpClMatcher => Async<grp_key_mgmt::HandlerAdaptor<GrpKeyMgmtHandler>>,
    EpClMatcher => Async<sw_diag::HandlerAdaptor<SwDiagHandler>>,
    EpClMatcher => Async<gen_diag::HandlerAdaptor<GenDiagHandler<'a>>>,
    EpClMatcher => net_comm::HandlerAsyncAdaptor<NetCommHandler<T>>
    | H
);

/// The ID of the root endpoint (Endpoint 0)
pub const ROOT_ENDPOINT_ID: EndptId = 0;

/// Decorate the provided `handler` with the system model handlers installed on the root endpoint (Endpoint 0).
/// Use this decorator for devices that use Ethernet as the Matter Operational Network.
///
/// # Arguments:
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `rand`: A random number generator.
/// - `handler`: The handler to be decorated with the system model and Ethernet Network Diagnostics handlers
pub fn with_eth_sys<'a, R: RngCore, H>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    mut rand: R,
    handler: H,
) -> EthSysHandler<'a, H> {
    ChainedHandler::new(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(EthDiagHandler::CLUSTER.id)),
        Async(EthDiagHandler::new(Dataver::new_rand(&mut rand)).adapt()),
        with_sys(comm_policy, gen_diag, netif_diag, EthNetCtl, rand, handler),
    )
}

/// Decorate the provided `handler` with the system model handlers installed on the root endpoint (Endpoint 0).
/// Use this decorator for devices that use Wifi as the Matter Operational Network.
///
/// # Arguments:
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `wifi_diag`: The `WifiDiag` implementation.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
/// - `handler`: The handler to be decorated with the system model and Wifi Network Diagnostics handlers
pub fn with_wifi_sys<'a, R: RngCore, T, H>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    wifi_diag: &'a dyn WifiDiag,
    net_ctl: T,
    mut rand: R,
    handler: H,
) -> WifiSysHandler<'a, T, H>
where
    T: NetCtl + NetCtlStatus,
{
    ChainedHandler::new(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(WifiDiagHandler::CLUSTER.id)),
        Async(WifiDiagHandler::new(Dataver::new_rand(&mut rand), wifi_diag).adapt()),
        with_sys(comm_policy, gen_diag, netif_diag, net_ctl, rand, handler),
    )
}

/// Decorate the provided `handler` with the system model handlers installed on the root endpoint (Endpoint 0).
/// Use this decorator for devices that use Thread as the Matter Operational Network.
///
/// # Arguments:
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `thread_diag`: The `ThreadDiag` implementation.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
/// - `handler`: The handler to be decorated with the system model and Thread Network Diagnostics handlers
pub fn with_thread_sys<'a, R: RngCore, T, H>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    thread_diag: &'a dyn ThreadDiag,
    net_ctl: T,
    mut rand: R,
    handler: H,
) -> ThreadSysHandler<'a, T, H>
where
    T: NetCtl + NetCtlStatus,
{
    ChainedHandler::new(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(ThreadDiagHandler::CLUSTER.id)),
        Async(ThreadDiagHandler::new(Dataver::new_rand(&mut rand), thread_diag).adapt()),
        with_sys(comm_policy, gen_diag, netif_diag, net_ctl, rand, handler),
    )
}

/// Decorate the provided `handler` with the system model handlers installed on the root endpoint (Endpoint 0).
/// Note that this decoration does not include the Network Diagnostic handler, which is dependent on
/// the network type and thus is not included in this function.
///
/// Use `with_eth_sys()`, `with_wifi_sys()` or `with_thread_sys()` instead to get the appropriate Network Diagnostic handler included in the decoration.
///
/// # Arguments:
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `networks`: The `Networks` implementation.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
fn with_sys<'a, R: RngCore, T, H>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    net_ctl: T,
    mut rand: R,
    handler: H,
) -> SysHandler<'a, T, H>
where
    T: NetCtl + NetCtlStatus,
{
    ChainedHandler::new(
        EpClMatcher::new(
            Some(ROOT_ENDPOINT_ID),
            Some(NetCommHandler::<T>::CLUSTER.id),
        ),
        NetCommHandler::new(Dataver::new_rand(&mut rand), net_ctl).adapt(),
        handler,
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GenDiagHandler::CLUSTER.id)),
        Async(GenDiagHandler::new(Dataver::new_rand(&mut rand), gen_diag, netif_diag).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(SwDiagHandler::CLUSTER.id)),
        Async(SwDiagHandler::new(Dataver::new_rand(&mut rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GrpKeyMgmtHandler::CLUSTER.id)),
        Async(GrpKeyMgmtHandler::new(Dataver::new_rand(&mut rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(AclHandler::CLUSTER.id)),
        Async(AclHandler::new(Dataver::new_rand(&mut rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(NocHandler::CLUSTER.id)),
        Async(NocHandler::new(Dataver::new_rand(&mut rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(AdminCommHandler::CLUSTER.id)),
        Async(AdminCommHandler::new(Dataver::new_rand(&mut rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GenCommHandler::CLUSTER.id)),
        Async(GenCommHandler::new(Dataver::new_rand(&mut rand), comm_policy).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(BasicInfoHandler::CLUSTER.id)),
        Async(BasicInfoHandler::new(Dataver::new_rand(&mut rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(DescHandler::CLUSTER.id)),
        Async(DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
    )
}
