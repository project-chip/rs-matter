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

use crate::utils::rand::Rand;
use crate::{devices, handler_chain_type};

use super::clusters::acl::{self, AclHandler, ClusterHandler as _};
use super::clusters::adm_comm::{self, AdminCommHandler, ClusterHandler as _};
use super::clusters::basic_info::{self, BasicInfoHandler, ClusterHandler as _};
use super::clusters::desc::{self, ClusterHandler as _, DescHandler};
use super::clusters::eth_diag::{self, ClusterHandler as _, EthDiagHandler};
use super::clusters::gen_comm::{self, ClusterHandler as _, CommPolicy, GenCommHandler};
use super::clusters::gen_diag::{self, ClusterHandler as _, GenDiag, GenDiagHandler, NetifDiag};
use super::clusters::grp_key_mgmt::{self, ClusterHandler as _, GrpKeyMgmtHandler};
use super::clusters::net_comm::{
    self, ClusterHandler as _, NetCommHandler, NetCtl, NetCtlStatus, NetworkType, Networks,
};
use super::clusters::noc::{self, ClusterHandler as _, NocHandler};
use super::clusters::thread_diag::{self, ClusterHandler as _, ThreadDiag, ThreadDiagHandler};
use super::clusters::wifi_diag::{self, ClusterHandler as _, WifiDiag, WifiDiagHandler};
use super::networks::eth::{EthNetCtl, EthNetwork};
use super::types::{ChainedHandler, Dataver, Endpoint, EndptId, EpClMatcher};

/// A utility function to create a root (Endpoint 0) object using the requested operational network type.
pub const fn root_endpoint(net_type: NetworkType) -> Endpoint<'static> {
    Endpoint {
        id: ROOT_ENDPOINT_ID,
        device_types: devices!(super::devices::DEV_TYPE_ROOT_NODE),
        clusters: net_type.root_clusters(),
    }
}

/// A type alias for the handler chain returned by `with_eth()`.
pub type EthHandler<'a, H> = NetHandler<
    'a,
    net_comm::HandlerAdaptor<NetCommHandler<'a, EthNetCtl>>,
    eth_diag::HandlerAdaptor<EthDiagHandler>,
    H,
>;

/// A type alias for the handler chain returned by `with_wifi()`.
pub type WifiHandler<'a, T, H> = NetHandler<
    'a,
    net_comm::HandlerAdaptor<NetCommHandler<'a, T>>,
    wifi_diag::HandlerAdaptor<WifiDiagHandler<'a>>,
    H,
>;

/// A type alias for the handler chain returned by `with_thread()`.
pub type ThreadHandler<'a, T, H> = NetHandler<
    'a,
    net_comm::HandlerAdaptor<NetCommHandler<'a, T>>,
    thread_diag::HandlerAdaptor<ThreadDiagHandler<'a>>,
    H,
>;

pub type NetHandler<'a, NETCOMM, NETDIAG, H> = handler_chain_type!(
    EpClMatcher => NETCOMM,
    EpClMatcher => NETDIAG,
    EpClMatcher => gen_diag::HandlerAdaptor<GenDiagHandler<'a>>
    | H
);

/// A type alias for the handler chain returned by `with_sys()`.
pub type SysHandler<'a, H> = handler_chain_type!(
    EpClMatcher => desc::HandlerAdaptor<DescHandler<'a>>,
    EpClMatcher => basic_info::HandlerAdaptor<BasicInfoHandler>,
    EpClMatcher => gen_comm::HandlerAdaptor<GenCommHandler<'a>>,
    EpClMatcher => adm_comm::HandlerAdaptor<AdminCommHandler>,
    EpClMatcher => noc::HandlerAdaptor<NocHandler>,
    EpClMatcher => acl::HandlerAdaptor<acl::AclHandler>,
    EpClMatcher => grp_key_mgmt::HandlerAdaptor<GrpKeyMgmtHandler>
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
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GenDiagHandler::CLUSTER.id)),
        GenDiagHandler::new(Dataver::new_rand(rand), gen_diag, netif_diag).adapt(),
        handler,
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(EthDiagHandler::CLUSTER.id)),
        EthDiagHandler::new(Dataver::new_rand(rand)).adapt(),
    )
    .chain(
        EpClMatcher::new(
            Some(ROOT_ENDPOINT_ID),
            Some(NetCommHandler::<EthNetCtl>::CLUSTER.id),
        ),
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
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GenDiagHandler::CLUSTER.id)),
        GenDiagHandler::new(Dataver::new_rand(rand), gen_diag, netif_diag).adapt(),
        handler,
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(WifiDiagHandler::CLUSTER.id)),
        WifiDiagHandler::new(Dataver::new_rand(rand), net_ctl).adapt(),
    )
    .chain(
        EpClMatcher::new(
            Some(ROOT_ENDPOINT_ID),
            Some(NetCommHandler::<T>::CLUSTER.id),
        ),
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
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GenDiagHandler::CLUSTER.id)),
        GenDiagHandler::new(Dataver::new_rand(rand), gen_diag, netif_diag).adapt(),
        handler,
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(ThreadDiagHandler::CLUSTER.id)),
        ThreadDiagHandler::new(Dataver::new_rand(rand), net_ctl).adapt(),
    )
    .chain(
        EpClMatcher::new(
            Some(ROOT_ENDPOINT_ID),
            Some(NetCommHandler::<T>::CLUSTER.id),
        ),
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
pub fn with_sys<H>(comm_policy: &dyn CommPolicy, rand: Rand, handler: H) -> SysHandler<'_, H> {
    ChainedHandler::new(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GrpKeyMgmtHandler::CLUSTER.id)),
        GrpKeyMgmtHandler::new(Dataver::new_rand(rand)).adapt(),
        handler,
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(AclHandler::CLUSTER.id)),
        AclHandler::new(Dataver::new_rand(rand)).adapt(),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(NocHandler::CLUSTER.id)),
        NocHandler::new(Dataver::new_rand(rand)).adapt(),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(AdminCommHandler::CLUSTER.id)),
        AdminCommHandler::new(Dataver::new_rand(rand)).adapt(),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GenCommHandler::CLUSTER.id)),
        GenCommHandler::new(Dataver::new_rand(rand), comm_policy).adapt(),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(BasicInfoHandler::CLUSTER.id)),
        BasicInfoHandler::new(Dataver::new_rand(rand)).adapt(),
    )
    .chain(
        EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(DescHandler::CLUSTER.id)),
        DescHandler::new(Dataver::new_rand(rand)).adapt(),
    )
}
