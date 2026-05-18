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

/// A type alias for the handler chain returned by `eth_sys_handler()`.
pub type EthSysHandler<'a> = SysHandler<'a, EthNetCtl, eth_diag::HandlerAdaptor<EthDiagHandler>>;

/// A type alias for the handler chain returned by `wifi_sys_handler()`.
pub type WifiSysHandler<'a, T> = SysHandler<'a, T, wifi_diag::HandlerAdaptor<WifiDiagHandler<'a>>>;

/// A type alias for the handler chain returned by `thread_sys_handler()`.
pub type ThreadSysHandler<'a, T> =
    SysHandler<'a, T, thread_diag::HandlerAdaptor<ThreadDiagHandler<'a>>>;

/// A type alias for the handler chain returned by `sys_handler()`.
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

/// Return a system handler for the root endpoint (Endpoint 0).
/// Use this handler for devices that use Ethernet as the Matter Operational Network.
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
#[allow(clippy::too_many_arguments)]
pub fn eth_sys_handler<'a, R: RngCore>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    time_sync: &'a dyn TimeSync,
    sw_diag: &'a dyn SwDiag,
    mut rand: R,
) -> EthSysHandler<'a> {
    sys_handler(
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

/// Return a system handler for the root endpoint (Endpoint 0).
/// Use this handler for devices that use Wifi as the Matter Operational Network.
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
#[allow(clippy::too_many_arguments)]
pub fn wifi_sys_handler<'a, R: RngCore, T>(
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
    sys_handler(
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

/// Return a system handler for the root endpoint (Endpoint 0).
/// Use this handler for devices that use Thread as the Matter Operational Network.
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
#[allow(clippy::too_many_arguments)]
pub fn thread_sys_handler<'a, R: RngCore, T>(
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
    sys_handler(
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

/// Return a system handler for the root endpoint (Endpoint 0).
/// Note that this handler does not include the Network Diagnostic handler, which is dependent on
/// the network type and thus is not included in this function.
///
/// Use `eth_sys_handler()`, `wifi_sys_handler()` or `thread_sys_handler()` instead to get the appropriate
/// Network Diagnostic handler included in the handler.
///
/// # Arguments:
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `networks`: The `Networks` implementation.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
fn sys_handler<'a, R: RngCore, T, N>(
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

// ---- Sys-handler builders ----------------------------------------------------
//
// Thin builders over the `eth_sys_handler` / `wifi_sys_handler` /
// `thread_sys_handler` free fns: each cluster-data hook is a setter, unset
// ones fall back to the canonical no-op default (`&true` for `CommPolicy`,
// `&()` for every other trait — `bool: CommPolicy` and `(): GenDiag` /
// `NetifDiag` / `TimeSync` / `SwDiag` are already impls in the crate). New
// hooks can be added later by extending one struct + adding a setter, with
// no churn on existing call sites.

/// Builder for an Ethernet root-endpoint system handler.
///
/// Unset hooks fall back to no-op defaults: `&true` for `CommPolicy`
/// (commissioning open / allowed) and `&()` for every other trait
/// (reports nothing / no-op).
///
/// ```ignore
/// let h = EthSysHandlerBuilder::new()
///     .gen_diag(&my_gen_diag)
///     .netif_diag(&SysNetifs)
///     .build(rand);
/// ```
pub struct EthSysHandlerBuilder<'a> {
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    time_sync: &'a dyn TimeSync,
    sw_diag: &'a dyn SwDiag,
}

impl<'a> EthSysHandlerBuilder<'a> {
    /// Create a builder with all hooks defaulted to their no-op providers.
    pub const fn new() -> Self {
        Self {
            comm_policy: &true,
            gen_diag: &(),
            netif_diag: &(),
            time_sync: &(),
            sw_diag: &(),
        }
    }

    /// Set the `CommPolicy` hook (commissioning window policy).
    pub const fn comm_policy(mut self, comm_policy: &'a dyn CommPolicy) -> Self {
        self.comm_policy = comm_policy;
        self
    }

    /// Set the `GenDiag` hook (General Diagnostics data provider).
    pub const fn gen_diag(mut self, gen_diag: &'a dyn GenDiag) -> Self {
        self.gen_diag = gen_diag;
        self
    }

    /// Set the `NetifDiag` hook (network-interface enumeration).
    pub const fn netif_diag(mut self, netif_diag: &'a dyn NetifDiag) -> Self {
        self.netif_diag = netif_diag;
        self
    }

    /// Set the `TimeSync` hook (Time Synchronization data provider).
    pub const fn time_sync(mut self, time_sync: &'a dyn TimeSync) -> Self {
        self.time_sync = time_sync;
        self
    }

    /// Set the `SwDiag` hook (Software Diagnostics data provider).
    pub const fn sw_diag(mut self, sw_diag: &'a dyn SwDiag) -> Self {
        self.sw_diag = sw_diag;
        self
    }

    /// Build the Ethernet system handler.
    pub fn build<R: RngCore>(self, rand: R) -> EthSysHandler<'a> {
        eth_sys_handler(
            self.comm_policy,
            self.gen_diag,
            self.netif_diag,
            self.time_sync,
            self.sw_diag,
            rand,
        )
    }
}

impl Default for EthSysHandlerBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for a Wi-Fi root-endpoint system handler.
///
/// `net_ctl` and `wifi_diag` are required (no sensible default) and supplied
/// to [`Self::new`]; everything else falls back to no-op defaults.
pub struct WifiSysHandlerBuilder<'a, T> {
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    wifi_diag: &'a dyn WifiDiag,
    time_sync: &'a dyn TimeSync,
    sw_diag: &'a dyn SwDiag,
    net_ctl: T,
}

impl<'a, T> WifiSysHandlerBuilder<'a, T>
where
    T: NetCtl + NetCtlStatus,
{
    /// Create a builder. `net_ctl` and `wifi_diag` are required; every other
    /// hook defaults to a no-op provider.
    pub const fn new(net_ctl: T, wifi_diag: &'a dyn WifiDiag) -> Self {
        Self {
            comm_policy: &true,
            gen_diag: &(),
            netif_diag: &(),
            wifi_diag,
            time_sync: &(),
            sw_diag: &(),
            net_ctl,
        }
    }

    /// Set the `CommPolicy` hook.
    pub const fn comm_policy(mut self, comm_policy: &'a dyn CommPolicy) -> Self {
        self.comm_policy = comm_policy;
        self
    }

    /// Set the `GenDiag` hook.
    pub const fn gen_diag(mut self, gen_diag: &'a dyn GenDiag) -> Self {
        self.gen_diag = gen_diag;
        self
    }

    /// Set the `NetifDiag` hook.
    pub const fn netif_diag(mut self, netif_diag: &'a dyn NetifDiag) -> Self {
        self.netif_diag = netif_diag;
        self
    }

    /// Set the `TimeSync` hook.
    pub const fn time_sync(mut self, time_sync: &'a dyn TimeSync) -> Self {
        self.time_sync = time_sync;
        self
    }

    /// Set the `SwDiag` hook.
    pub const fn sw_diag(mut self, sw_diag: &'a dyn SwDiag) -> Self {
        self.sw_diag = sw_diag;
        self
    }

    /// Build the Wi-Fi system handler.
    pub fn build<R: RngCore>(self, rand: R) -> WifiSysHandler<'a, T> {
        wifi_sys_handler(
            self.comm_policy,
            self.gen_diag,
            self.netif_diag,
            self.wifi_diag,
            self.time_sync,
            self.sw_diag,
            self.net_ctl,
            rand,
        )
    }
}

/// Builder for a Thread root-endpoint system handler.
///
/// `net_ctl` and `thread_diag` are required (no sensible default) and supplied
/// to [`Self::new`]; everything else falls back to no-op defaults.
pub struct ThreadSysHandlerBuilder<'a, T> {
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    thread_diag: &'a dyn ThreadDiag,
    time_sync: &'a dyn TimeSync,
    sw_diag: &'a dyn SwDiag,
    net_ctl: T,
}

impl<'a, T> ThreadSysHandlerBuilder<'a, T>
where
    T: NetCtl + NetCtlStatus,
{
    /// Create a builder. `net_ctl` and `thread_diag` are required; every
    /// other hook defaults to a no-op provider.
    pub const fn new(net_ctl: T, thread_diag: &'a dyn ThreadDiag) -> Self {
        Self {
            comm_policy: &true,
            gen_diag: &(),
            netif_diag: &(),
            thread_diag,
            time_sync: &(),
            sw_diag: &(),
            net_ctl,
        }
    }

    /// Set the `CommPolicy` hook.
    pub const fn comm_policy(mut self, comm_policy: &'a dyn CommPolicy) -> Self {
        self.comm_policy = comm_policy;
        self
    }

    /// Set the `GenDiag` hook.
    pub const fn gen_diag(mut self, gen_diag: &'a dyn GenDiag) -> Self {
        self.gen_diag = gen_diag;
        self
    }

    /// Set the `NetifDiag` hook.
    pub const fn netif_diag(mut self, netif_diag: &'a dyn NetifDiag) -> Self {
        self.netif_diag = netif_diag;
        self
    }

    /// Set the `TimeSync` hook.
    pub const fn time_sync(mut self, time_sync: &'a dyn TimeSync) -> Self {
        self.time_sync = time_sync;
        self
    }

    /// Set the `SwDiag` hook.
    pub const fn sw_diag(mut self, sw_diag: &'a dyn SwDiag) -> Self {
        self.sw_diag = sw_diag;
        self
    }

    /// Build the Thread system handler.
    pub fn build<R: RngCore>(self, rand: R) -> ThreadSysHandler<'a, T> {
        thread_sys_handler(
            self.comm_policy,
            self.gen_diag,
            self.netif_diag,
            self.thread_diag,
            self.time_sync,
            self.sw_diag,
            self.net_ctl,
            rand,
        )
    }
}
