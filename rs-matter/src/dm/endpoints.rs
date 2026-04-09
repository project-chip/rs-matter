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

use rand_core::RngCore;

use crate::dm::clusters::net_comm::SharedNetworks;
use crate::dm::networks::eth::{EthNetCtl, EthNetwork};
use crate::{devices, handler_chain_type};

use super::clusters::acl::{self, AclHandler, ClusterHandler as _};
use super::clusters::adm_comm::{self, AdminCommHandler, ClusterHandler as _};
use super::clusters::basic_info::{self, BasicInfoHandler, ClusterHandler as _};
use super::clusters::desc::{self, ClusterHandler as _, DescHandler};
use super::clusters::eth_diag::{self, ClusterHandler as _, EthDiagHandler};
use super::clusters::gen_comm::{self, ClusterHandler as _, CommPolicy, GenCommHandler};
use super::clusters::gen_diag::{self, ClusterHandler as _, GenDiag, GenDiagHandler, NetifDiag};
use super::clusters::groups::{self, ClusterHandler as _, GroupsHandler};
use super::clusters::grp_key_mgmt::{self, ClusterHandler as _, GrpKeyMgmtHandler};
use super::clusters::net_comm::{
    self, ClusterAsyncHandler as _, NetCommHandler, NetCtl, NetCtlStatus, NetworkType,
    NetworksAccess,
};
use super::clusters::noc::{self, ClusterHandler as _, NocHandler};
use super::clusters::thread_diag::{self, ClusterHandler as _, ThreadDiag, ThreadDiagHandler};
use super::clusters::wifi_diag::{self, ClusterHandler as _, WifiDiag, WifiDiagHandler};
use super::types::{Async, ChainedHandler, Dataver, Endpoint, EndptId, EpClMatcher};

/// A utility function to create a root (Endpoint 0) object using the requested operational network type.
pub const fn root_endpoint(net_type: NetworkType) -> Endpoint<'static> {
    Endpoint {
        id: ROOT_ENDPOINT_ID,
        device_types: devices!(super::devices::DEV_TYPE_ROOT_NODE),
        clusters: net_type.root_clusters(),
    }
}

/// A type alias for the handler chain returned by `with_eth()`.
pub type EthHandler<'a, H> = SysHandler<'a, SharedNetworks<EthNetwork<'static>>, EthNetCtl, H>;

/// A type alias for the handler chain returned by `with_sys()`.
pub type SysHandler<'a, N, T, H> = handler_chain_type!(
    EpClMatcher => Async<desc::HandlerAdaptor<DescHandler<'a>>>,
    EpClMatcher => Async<basic_info::HandlerAdaptor<BasicInfoHandler>>,
    EpClMatcher => Async<gen_comm::HandlerAdaptor<GenCommHandler<'a>>>,
    EpClMatcher => Async<adm_comm::HandlerAdaptor<AdminCommHandler>>,
    EpClMatcher => Async<noc::HandlerAdaptor<NocHandler>>,
    EpClMatcher => Async<acl::HandlerAdaptor<acl::AclHandler>>,
    EpClMatcher => Async<grp_key_mgmt::HandlerAdaptor<GrpKeyMgmtHandler>>,
    EpClMatcher => Async<groups::HandlerAdaptor<GroupsHandler>>,
    EpClMatcher => Async<gen_diag::HandlerAdaptor<GenDiagHandler<'a>>>,
    EpClMatcher => Async<eth_diag::HandlerAdaptor<EthDiagHandler>>,
    EpClMatcher => Async<wifi_diag::HandlerAdaptor<WifiDiagHandler<'a>>>,
    EpClMatcher => Async<thread_diag::HandlerAdaptor<ThreadDiagHandler<'a>>>,
    EpClMatcher => net_comm::HandlerAsyncAdaptor<NetCommHandler<N, T>>
    | H
);

/// The ID of the root endpoint (Endpoint 0)
pub const ROOT_ENDPOINT_ID: EndptId = 0;

/// A shortcut for `with_sys` for Ethernet-based devices.
pub fn with_eth<'a, R: RngCore, H>(
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    rand: R,
    handler: H,
) -> EthHandler<'a, H> {
    with_sys(
        &false,
        gen_diag,
        netif_diag,
        &(), // No Wifi diagnostics
        &(), // No Thread diagnostics
        SharedNetworks::new(EthNetwork::new_default()),
        EthNetCtl,
        rand,
        handler,
    )
}

/// Decorate the provided `handler` with the system model networking handlers installed on the root endpoint (0).
///
/// # Arguments:
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `wifi_diag`: The `WifiDiag` implementation. Not necessary (provide `&()`) if not operating with Wifi networks.
/// - `thread_diag`: The `ThreadDiag` implementation. Not necessary (provide `&()`) if not operating with Thread networks.
/// - `networks`: The `Networks` implementation.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
pub fn with_sys<'a, R: RngCore, N, T, H>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    wifi_diag: &'a dyn WifiDiag,
    thread_diag: &'a dyn ThreadDiag,
    networks: N,
    net_ctl: T,
    mut rand: R,
    handler: H,
) -> SysHandler<'a, N, T, H>
where
    N: NetworksAccess,
    T: NetCtl + NetCtlStatus,
{
    ChainedHandler::new(
        EpClMatcher::new(
            Some(ROOT_ENDPOINT_ID),
            Some(NetCommHandler::<N, T>::CLUSTER.id),
        ),
        NetCommHandler::new(Dataver::new_rand(&mut rand), networks, net_ctl).adapt(),
        handler,
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(ThreadDiagHandler::CLUSTER.id)),
        Async(ThreadDiagHandler::new(Dataver::new_rand(&mut rand), thread_diag).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(WifiDiagHandler::CLUSTER.id)),
        Async(WifiDiagHandler::new(Dataver::new_rand(&mut rand), wifi_diag).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(EthDiagHandler::CLUSTER.id)),
        Async(EthDiagHandler::new(Dataver::new_rand(&mut rand)).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GenDiagHandler::CLUSTER.id)),
        Async(GenDiagHandler::new(Dataver::new_rand(&mut rand), gen_diag, netif_diag).adapt()),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GroupsHandler::CLUSTER.id)),
        Async(GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
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
