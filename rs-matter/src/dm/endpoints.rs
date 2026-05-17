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

use crate::dm::{ClusterId, EmptyHandler};
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
use super::clusters::sw_diag::{self, ClusterHandler as _, SwDiag, SwDiagHandler};
use super::clusters::thread_diag::{self, ClusterHandler as _, ThreadDiag, ThreadDiagHandler};
use super::clusters::time_sync::{self, ClusterHandler as _, TimeSync, TimeSyncHandler};
use super::clusters::wifi_diag::{self, ClusterHandler as _, WifiDiag, WifiDiagHandler};
use super::networks::eth::EthNetCtl;
use super::types::{Async, ChainedHandler, Dataver, EndptId, EpClMatcher};

/// A macro to generate the meta-data for the root endpoint (Endpoint 0).
///
/// Net-type token (pick one): `sys`, `eth`, `wifi`, `thread` — same meaning
/// as the corresponding tokens on the [`crate::clusters!`] macro.
///
/// Optional cluster-shape modifiers (in order):
/// - `sw_diag(heap | watermarks | thread, …)` — shapes the Software
///   Diagnostics cluster.
/// - `time_sync(time_zone | ntp_client | ntp_server | time_sync_client, …)` —
///   shapes the Time Synchronization cluster.
///
/// See the [`crate::clusters!`] docs for the token semantics.
///
/// The Groups cluster is intentionally not part of any of these presets — it
/// is not a Root Node device-type cluster and has no defined behavior on the
/// root endpoint. Add `GroupsHandler::CLUSTER` to the application endpoint(s)
/// where group-addressed traffic is actually meaningful.
#[allow(unused_macros)]
#[macro_export]
macro_rules! root_endpoint {
    ($t:ident
        $(, sw_diag($($sw_opt:ident),* $(,)?))?
        $(, time_sync($($ts_opt:ident),* $(,)?))?
    ) => {
        $crate::dm::Endpoint {
            id: $crate::dm::endpoints::ROOT_ENDPOINT_ID,
            device_types: $crate::devices!($crate::dm::devices::DEV_TYPE_ROOT_NODE),
            clusters: $crate::clusters!(
                $t
                $(, sw_diag($($sw_opt),*))?
                $(, time_sync($($ts_opt),*))?
                ;
            ),
            client_clusters: &[],
        }
    }
}

/// A type alias for the handler chain returned by `with_eth_sys()`.
pub type EthSysHandler<'a> = SysHandler<'a, EthNetCtl, eth_diag::HandlerAdaptor<EthDiagHandler>>;

/// A type alias for the handler chain returned by `with_wifi_sys()`.
pub type WifiSysHandler<'a, T> = SysHandler<'a, T, wifi_diag::HandlerAdaptor<WifiDiagHandler<'a>>>;

/// A type alias for the handler chain returned by `with_thread_sys()`.
pub type ThreadSysHandler<'a, T> =
    SysHandler<'a, T, thread_diag::HandlerAdaptor<ThreadDiagHandler<'a>>>;

/// A type alias for the handler chain returned by `with_sys()`.
pub type SysHandler<'a, T, N> = handler_chain_type!(
    EpClMatcher => net_comm::HandlerAsyncAdaptor<NetCommHandler<T>>
    | Async<handler_chain_type!(
        EpClMatcher => desc::HandlerAdaptor<DescHandler<'a>>,
        EpClMatcher => basic_info::HandlerAdaptor<BasicInfoHandler>,
        EpClMatcher => gen_comm::HandlerAdaptor<GenCommHandler<'a>>,
        EpClMatcher => adm_comm::HandlerAdaptor<AdminCommHandler>,
        EpClMatcher => noc::HandlerAdaptor<NocHandler>,
        EpClMatcher => acl::HandlerAdaptor<acl::AclHandler>,
        EpClMatcher => grp_key_mgmt::HandlerAdaptor<GrpKeyMgmtHandler>,
        EpClMatcher => sw_diag::HandlerAdaptor<SwDiagHandler<'a>>,
        EpClMatcher => time_sync::HandlerAdaptor<TimeSyncHandler<'a>>,
        EpClMatcher => gen_diag::HandlerAdaptor<GenDiagHandler<'a>>,
        EpClMatcher => N
    )>
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
/// - `time_sync`: The `TimeSync` implementation (pass `&()` for the
///   no-op default: `UTCTime = Null`, `Granularity = NoTime`,
///   `TimeSource = None`).
/// - `sw_diag`: The `SwDiag` implementation (pass `&()` for the
///   no-op default: heap counters report `0`).
/// - `rand`: A random number generator.
/// - `handler`: The handler to be decorated with the system model and Ethernet Network Diagnostics handlers
#[allow(clippy::too_many_arguments)]
pub fn with_eth_sys<'a, R: RngCore>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    time_sync: &'a dyn TimeSync,
    sw_diag: &'a dyn SwDiag,
    mut rand: R,
) -> EthSysHandler<'a> {
    with_sys(
        comm_policy,
        gen_diag,
        netif_diag,
        time_sync,
        sw_diag,
        EthNetCtl,
        EthDiagHandler::CLUSTER.id,
        EthDiagHandler::new(Dataver::new_rand(&mut rand)).adapt(),
        rand,
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
/// - `time_sync`: The `TimeSync` implementation (pass `&()` for the no-op default).
/// - `sw_diag`: The `SwDiag` implementation (pass `&()` for the no-op default).
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
/// - `handler`: The handler to be decorated with the system model and Wifi Network Diagnostics handlers
#[allow(clippy::too_many_arguments)]
pub fn with_wifi_sys<'a, R: RngCore, T>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    wifi_diag: &'a dyn WifiDiag,
    time_sync: &'a dyn TimeSync,
    sw_diag: &'a dyn SwDiag,
    net_ctl: T,
    mut rand: R,
) -> WifiSysHandler<'a, T>
where
    T: NetCtl + NetCtlStatus,
{
    with_sys(
        comm_policy,
        gen_diag,
        netif_diag,
        time_sync,
        sw_diag,
        net_ctl,
        WifiDiagHandler::CLUSTER.id,
        WifiDiagHandler::new(Dataver::new_rand(&mut rand), wifi_diag).adapt(),
        rand,
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
/// - `time_sync`: The `TimeSync` implementation (pass `&()` for the no-op default).
/// - `sw_diag`: The `SwDiag` implementation (pass `&()` for the no-op default).
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
/// - `handler`: The handler to be decorated with the system model and Thread Network Diagnostics handlers
#[allow(clippy::too_many_arguments)]
pub fn with_thread_sys<'a, R: RngCore, T>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    thread_diag: &'a dyn ThreadDiag,
    time_sync: &'a dyn TimeSync,
    sw_diag: &'a dyn SwDiag,
    net_ctl: T,
    mut rand: R,
) -> ThreadSysHandler<'a, T>
where
    T: NetCtl + NetCtlStatus,
{
    with_sys(
        comm_policy,
        gen_diag,
        netif_diag,
        time_sync,
        sw_diag,
        net_ctl,
        ThreadDiagHandler::CLUSTER.id,
        ThreadDiagHandler::new(Dataver::new_rand(&mut rand), thread_diag).adapt(),
        rand,
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
fn with_sys<'a, R: RngCore, T, N>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    time_sync: &'a dyn TimeSync,
    sw_diag: &'a dyn SwDiag,
    net_ctl: T,
    netw_diag_cluster_id: ClusterId,
    netw_diag: N,
    mut rand: R,
) -> SysHandler<'a, T, N>
where
    T: NetCtl + NetCtlStatus,
{
    ChainedHandler::new(
        EpClMatcher::new(
            Some(ROOT_ENDPOINT_ID),
            Some(NetCommHandler::<T>::CLUSTER.id),
        ),
        NetCommHandler::new(Dataver::new_rand(&mut rand), net_ctl).adapt(),
        Async(
            ChainedHandler::new(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(netw_diag_cluster_id)),
                netw_diag,
                EmptyHandler,
            )
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GenDiagHandler::CLUSTER.id)),
                GenDiagHandler::new(Dataver::new_rand(&mut rand), gen_diag, netif_diag).adapt(),
            )
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(TimeSyncHandler::CLUSTER.id)),
                TimeSyncHandler::new(Dataver::new_rand(&mut rand), time_sync).adapt(),
            )
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(SwDiagHandler::CLUSTER.id)),
                SwDiagHandler::new(Dataver::new_rand(&mut rand), sw_diag).adapt(),
            )
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GrpKeyMgmtHandler::CLUSTER.id)),
                GrpKeyMgmtHandler::new(Dataver::new_rand(&mut rand)).adapt(),
            )
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(AclHandler::CLUSTER.id)),
                AclHandler::new(Dataver::new_rand(&mut rand)).adapt(),
            )
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(NocHandler::CLUSTER.id)),
                NocHandler::new(Dataver::new_rand(&mut rand)).adapt(),
            )
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(AdminCommHandler::CLUSTER.id)),
                AdminCommHandler::new(Dataver::new_rand(&mut rand)).adapt(),
            )
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(GenCommHandler::CLUSTER.id)),
                GenCommHandler::new(Dataver::new_rand(&mut rand), comm_policy).adapt(),
            )
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(BasicInfoHandler::CLUSTER.id)),
                BasicInfoHandler::new(Dataver::new_rand(&mut rand)).adapt(),
            )
            .chain(
                EpClMatcher::new(Some(ROOT_ENDPOINT_ID), Some(DescHandler::CLUSTER.id)),
                DescHandler::new(Dataver::new_rand(&mut rand)).adapt(),
            ),
        ),
    )
}
