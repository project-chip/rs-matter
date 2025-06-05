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

use crate::handler_chain_type;
use crate::utils::rand::Rand;

use super::basic_info::{self, BasicInfoHandler, ClusterHandler as _};
use super::networks::eth::{EthNetCtl, EthNetwork};
use super::objects::{Async, ChainedHandler, Dataver, Endpoint, EndptId, EpClMatcher};
use super::sdm::adm_comm::{self, AdminCommHandler, ClusterHandler as _};
use super::sdm::eth_diag::{self, ClusterHandler as _, EthDiagHandler};
use super::sdm::gen_comm::{self, ClusterHandler as _, CommPolicy, GenCommHandler};
use super::sdm::gen_diag::{self, ClusterHandler as _, GenDiag, GenDiagHandler, NetifDiag};
use super::sdm::grp_key_mgmt::{self, ClusterHandler as _, GrpKeyMgmtHandler};
use super::sdm::net_comm::{
    self, ClusterAsyncHandler as _, NetCommHandler, NetCtl, NetCtlStatus, NetworkType, Networks,
};
use super::sdm::noc::{self, ClusterHandler as _, NocHandler};
use super::sdm::thread_diag::{self, ClusterHandler as _, ThreadDiag, ThreadDiagHandler};
use super::sdm::wifi_diag::{self, ClusterHandler as _, WifiDiag, WifiDiagHandler};
use super::system_model::acl::{self, AclHandler, ClusterHandler as _};
use super::system_model::desc::{self, ClusterHandler as _, DescHandler};

/// A utility function to create a root (Endpoint 0) object using the requested operational network type.
pub const fn root_endpoint(net_type: NetworkType) -> Endpoint<'static> {
    Endpoint {
        id: ROOT_ENDPOINT_ID,
        device_types: &[super::device_types::DEV_TYPE_ROOT_NODE],
        clusters: net_type.root_clusters(),
    }
}

/// A type alias for the handler chain returned by `with_eth()`.
pub type EthHandler<'a, H> = NetHandler<
    'a,
    net_comm::HandlerAsyncAdaptor<NetCommHandler<'a, EthNetCtl>>,
    Async<eth_diag::HandlerAdaptor<EthDiagHandler>>,
    H,
>;

/// A type alias for the handler chain returned by `with_wifi()`.
pub type WifiHandler<'a, T, H> = NetHandler<
    'a,
    net_comm::HandlerAsyncAdaptor<NetCommHandler<'a, T>>,
    Async<wifi_diag::HandlerAdaptor<WifiDiagHandler<'a>>>,
    H,
>;

/// A type alias for the handler chain returned by `with_thread()`.
pub type ThreadHandler<'a, T, H> = NetHandler<
    'a,
    net_comm::HandlerAsyncAdaptor<NetCommHandler<'a, T>>,
    Async<thread_diag::HandlerAdaptor<ThreadDiagHandler<'a>>>,
    H,
>;

pub type NetHandler<'a, NETCOMM, NETDIAG, H> = handler_chain_type!(
    EpClMatcher => NETCOMM,
    EpClMatcher => NETDIAG,
    EpClMatcher => Async<gen_diag::HandlerAdaptor<GenDiagHandler<'a>>>
    | H
);

/// A type alias for the handler chain returned by `with_sys()`.
pub type SysHandler<'a, H> = handler_chain_type!(
    EpClMatcher => Async<desc::HandlerAdaptor<DescHandler<'a>>>,
    EpClMatcher => Async<basic_info::HandlerAdaptor<BasicInfoHandler>>,
    EpClMatcher => Async<gen_comm::HandlerAdaptor<GenCommHandler<'a>>>,
    EpClMatcher => Async<adm_comm::HandlerAdaptor<AdminCommHandler>>,
    EpClMatcher => Async<noc::HandlerAdaptor<NocHandler>>,
    EpClMatcher => Async<acl::HandlerAdaptor<acl::AclHandler>>,
    EpClMatcher => Async<grp_key_mgmt::HandlerAdaptor<GrpKeyMgmtHandler>>
    | H
);

/// The ID of the root endpoint (Endpoint 0)
pub const ROOT_ENDPOINT_ID: EndptId = 0;

/// Decorates the provided `handler` with the system model networking handlers necessary for operating
/// with Ethernet networks, installed on the root endpoint (0).
///
/// The following handlers are added:
/// - `GenDiagHandler`
/// - `EthDiagHandler`
/// - `NetCommHandler`
///
/// # Arguments:
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
/// - `handler`: The handler to be decorated.
pub fn with_eth<'a, H>(
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    rand: Rand,
    handler: H,
) -> EthHandler<'a, H> {
    const NETWORK: EthNetwork<'static> = EthNetwork::new("eth");

    ChainedHandler::new(
        EpClMatcher::new(ROOT_ENDPOINT_ID, GenDiagHandler::CLUSTER.id),
        Async(GenDiagHandler::new(Dataver::new_rand(rand), gen_diag, netif_diag).adapt()),
        handler,
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, EthDiagHandler::CLUSTER.id),
        Async(EthDiagHandler::new(Dataver::new_rand(rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, NetCommHandler::<EthNetCtl>::CLUSTER.id),
        NetCommHandler::new(Dataver::new_rand(rand), &NETWORK, EthNetCtl).adapt(),
    )
}

/// Decorates the provided `handler` with the system model networking handlers necessary for operating
/// with Wifi networks, installed on the root endpoint (0).
///
/// The following handlers are added:
/// - `GenDiagHandler`
/// - `WifiDiagHandler`
/// - `NetCommHandler`
///
/// # Arguments:
/// - `gen_diag`: The `GenDiag` implementation.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `networks`: The `Networks` implementation.
/// - `rand`: A random number generator.
/// - `handler`: The handler to be decorated.
pub fn with_wifi<'a, T, H>(
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    net_ctl: &'a T,
    networks: &'a dyn Networks,
    rand: Rand,
    handler: H,
) -> WifiHandler<'a, &'a T, H>
where
    T: NetCtl + NetCtlStatus + WifiDiag,
{
    ChainedHandler::new(
        EpClMatcher::new(ROOT_ENDPOINT_ID, GenDiagHandler::CLUSTER.id),
        Async(GenDiagHandler::new(Dataver::new_rand(rand), gen_diag, netif_diag).adapt()),
        handler,
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, WifiDiagHandler::CLUSTER.id),
        Async(WifiDiagHandler::new(Dataver::new_rand(rand), net_ctl).adapt()),
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, NetCommHandler::<T>::CLUSTER.id),
        NetCommHandler::new(Dataver::new_rand(rand), networks, net_ctl).adapt(),
    )
}

/// Decorates the provided `handler` with the system model networking handlers necessary for operating
/// with Thread networks, installed on the root endpoint (0).
///
/// The following handlers are added:
/// - `GenDiagHandler`
/// - `ThreadDiagHandler`
/// - `NetCommHandler`
///
/// # Arguments:
/// - `gen_diag`: The `GenDiag` implementation.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `networks`: The `Networks` implementation.
/// - `rand`: A random number generator.
pub fn with_thread<'a, T, H>(
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    net_ctl: &'a T,
    networks: &'a dyn Networks,
    rand: Rand,
    handler: H,
) -> ThreadHandler<'a, &'a T, H>
where
    T: NetCtl + NetCtlStatus + ThreadDiag,
{
    ChainedHandler::new(
        EpClMatcher::new(ROOT_ENDPOINT_ID, GenDiagHandler::CLUSTER.id),
        Async(GenDiagHandler::new(Dataver::new_rand(rand), gen_diag, netif_diag).adapt()),
        handler,
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, ThreadDiagHandler::CLUSTER.id),
        Async(ThreadDiagHandler::new(Dataver::new_rand(rand), net_ctl).adapt()),
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, NetCommHandler::<T>::CLUSTER.id),
        NetCommHandler::new(Dataver::new_rand(rand), networks, net_ctl).adapt(),
    )
}

/// Decorates the provided `handler` with the system model handlers installed on the root endpoint (0).
///
/// All system model handlers are added except for the following ones, which are network-specific:
/// - `GenDiagHandler`
/// - `EthDiagHandler`/`WifiDiagHandler`/`ThreadDiagHandler`
/// - `NetCommHandler`
///
/// # Arguments:
/// - `comm_policy`: The commissioning policy to be used for the `GenCommHandler`.
/// - `rand`: A random number generator.
/// - `handler`: The handler to be decorated.
pub fn with_sys<'a, H>(
    comm_policy: &'a dyn CommPolicy,
    rand: Rand,
    handler: H,
) -> SysHandler<'a, H> {
    ChainedHandler::new(
        EpClMatcher::new(ROOT_ENDPOINT_ID, GrpKeyMgmtHandler::CLUSTER.id),
        Async(GrpKeyMgmtHandler::new(Dataver::new_rand(rand)).adapt()),
        handler,
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, AclHandler::CLUSTER.id),
        Async(AclHandler::new(Dataver::new_rand(rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, NocHandler::CLUSTER.id),
        Async(NocHandler::new(Dataver::new_rand(rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, AdminCommHandler::CLUSTER.id),
        Async(AdminCommHandler::new(Dataver::new_rand(rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, GenCommHandler::CLUSTER.id),
        Async(GenCommHandler::new(Dataver::new_rand(rand), comm_policy).adapt()),
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, BasicInfoHandler::CLUSTER.id),
        Async(BasicInfoHandler::new(Dataver::new_rand(rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(ROOT_ENDPOINT_ID, DescHandler::CLUSTER.id),
        Async(DescHandler::new(Dataver::new_rand(rand)).adapt()),
    )
}
