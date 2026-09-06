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

//! Handler chains for the root endpoint (Endpoint 0).
//!
//! The mandatory system clusters of the root endpoint come in two groups:
//!
//! - The clusters that do not depend on the operational network: Descriptor,
//!   Basic Information, Administrator Commissioning, Operational Credentials,
//!   Access Control, Group Key Management, Software Diagnostics and Time
//!   Synchronization. [`root_handler`] returns a chain with all of them.
//!
//! - The operational network clusters: Network Commissioning, General
//!   Commissioning, General Diagnostics and the network-type diagnostics cluster
//!   (Ethernet, Wifi or Thread). Their inputs are the network controller, the
//!   network interface and the commissioning policy. [`eth_net_handler`],
//!   [`wifi_net_handler`] and [`thread_net_handler`] return a chain with these,
//!   chained on top of a caller-provided handler.
//!
//! [`eth_sys_handler`], [`wifi_sys_handler`] and [`thread_sys_handler`] combine
//! the two groups into a single chain for the whole root endpoint. Use the split
//! form when the two groups have different lifetimes or owners - as with a
//! non-concurrent commissioning flow, where the network clusters are re-created
//! on every BLE to Wifi/Thread handover while the rest of the root endpoint
//! stays - or when extra clusters need to be chained into the root endpoint
//! next to the system ones.
//!
//! The root endpoint metadata is the same in all cases: [`root_endpoint!`] lists
//! all clusters, as the Descriptor cluster and the Interaction Model dispatch
//! are driven by the metadata rather than by the shape of the handler chain.

use rand_core::Rng;

use crate::dm::{EmptyHandler, FnMatcher};
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
use super::clusters::time_sync::{self, ClusterHandler as _, TimeSyncHandler};
use super::clusters::wifi_diag::{
    self, AlwaysConnected, ClusterHandler as _, WifiDiag, WifiDiagHandler, WirelessDiag,
};
use super::networks::eth::EthNetCtl;
use super::types::{Async, ChainedHandler, Dataver, EndptId};

/// A macro to generate the meta-data for the root endpoint (Endpoint 0).
///
/// Net-type token (pick one): `sys`, `eth`, `wifi`, `thread` — same meaning
/// as the corresponding tokens on the [`crate::clusters!`] macro.
///
/// Optional cluster-shape modifiers (in order):
/// - `acl(aux)` — makes the Access Control cluster advertise the provisional
///   `AUXILIARY` feature and `AuxiliaryACL` attribute (e.g. for nodes hosting
///   the Groupcast cluster).
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
        $(, acl($($acl_opt:ident),* $(,)?))?
        $(, sw_diag($($sw_opt:ident),* $(,)?))?
        $(, time_sync($($ts_opt:ident),* $(,)?))?
    ) => {
        $crate::dm::Endpoint {
            id: $crate::dm::endpoints::ROOT_ENDPOINT_ID,
            device_types: $crate::devices!($crate::dm::devices::DEV_TYPE_ROOT_NODE),
            clusters: $crate::clusters!(
                $t
                $(, acl($($acl_opt),*))?
                $(, sw_diag($($sw_opt),*))?
                $(, time_sync($($ts_opt),*))?
                ;
            ),
            client_clusters: &[],
            unique_id: None,
            semantic_tags: &[],
        }
    }
}

/// The ID of the root endpoint (Endpoint 0)
pub const ROOT_ENDPOINT_ID: EndptId = 0;

/// A type alias for the handler chain returned by `root_handler()`:
/// the root endpoint system clusters that do not depend on the operational network.
///
/// A non-async chain; wrap it in `Async` to chain it with async handlers.
/// `T` is the handler at the end of the chain.
pub type RootHandler<'a, T = EmptyHandler> = handler_chain_type!(
    FnMatcher => desc::HandlerAdaptor<DescHandler<'a>>,
    FnMatcher => basic_info::HandlerAdaptor<BasicInfoHandler>,
    FnMatcher => adm_comm::HandlerAdaptor<AdminCommHandler>,
    FnMatcher => noc::HandlerAdaptor<NocHandler>,
    FnMatcher => acl::HandlerAdaptor<AclHandler>,
    FnMatcher => grp_key_mgmt::HandlerAdaptor<GrpKeyMgmtHandler>,
    FnMatcher => sw_diag::HandlerAdaptor<SwDiagHandler<'a>>,
    FnMatcher => time_sync::HandlerAdaptor<TimeSyncHandler<'a>>
    | T
);

/// A type alias for the non-async operational network clusters of the root endpoint:
/// General Commissioning, General Diagnostics and the network-type diagnostics
/// cluster `N`, on top of the handler `T`.
///
/// The three are kept in one non-async chain behind a single `Async` wrapper
/// (see `NetHandler` and `SysHandler`), so that the async-to-sync adaptation
/// is monomorphized once rather than once per cluster.
pub type OperNetHandler<'a, N, T = EmptyHandler> = handler_chain_type!(
    FnMatcher => gen_comm::HandlerAdaptor<GenCommHandler<'a>>,
    FnMatcher => gen_diag::HandlerAdaptor<GenDiagHandler<'a>>,
    FnMatcher => N
    | T
);

/// A type alias for the handler chain returned by `eth_net_handler()`.
pub type EthNetHandler<'a, H> =
    NetHandler<'a, EthNetCtl<'a>, eth_diag::HandlerAdaptor<EthDiagHandler>, H>;

/// A type alias for the handler chain returned by `wifi_net_handler()`.
pub type WifiNetHandler<'a, T, H> =
    NetHandler<'a, T, wifi_diag::HandlerAdaptor<WifiDiagHandler<'a>>, H>;

/// A type alias for the handler chain returned by `thread_net_handler()`.
pub type ThreadNetHandler<'a, T, H> =
    NetHandler<'a, T, thread_diag::HandlerAdaptor<ThreadDiagHandler<'a>>, H>;

/// A type alias for the handler chain returned by `net_handler()`:
/// the operational network clusters of the root endpoint, on top of the handler `H`,
/// which receives everything the network clusters do not match.
pub type NetHandler<'a, T, N, H> = handler_chain_type!(
    FnMatcher => net_comm::HandlerAsyncAdaptor<NetCommHandler<'a, T>>,
    FnMatcher => Async<OperNetHandler<'a, N>>
    | H
);

/// A type alias for the handler chain returned by `eth_sys_handler()`.
pub type EthSysHandler<'a> =
    SysHandler<'a, EthNetCtl<'a>, eth_diag::HandlerAdaptor<EthDiagHandler>>;

/// A type alias for the handler chain returned by `wifi_sys_handler()`.
pub type WifiSysHandler<'a, T> = SysHandler<'a, T, wifi_diag::HandlerAdaptor<WifiDiagHandler<'a>>>;

/// A type alias for the handler chain returned by `thread_sys_handler()`.
pub type ThreadSysHandler<'a, T> =
    SysHandler<'a, T, thread_diag::HandlerAdaptor<ThreadDiagHandler<'a>>>;

/// A type alias for the handler chain returned by `sys_handler()`:
/// all system clusters of the root endpoint.
pub type SysHandler<'a, T, N> = handler_chain_type!(
    FnMatcher => net_comm::HandlerAsyncAdaptor<NetCommHandler<'a, T>>
    | Async<OperNetHandler<'a, N, RootHandler<'a>>>
);

/// Return a handler for the root endpoint system clusters that do not depend on the
/// operational network: Descriptor, Basic Information, Administrator Commissioning,
/// Operational Credentials, Access Control, Group Key Management, Software Diagnostics
/// and Time Synchronization.
///
/// Chain the operational network clusters on top of it with `eth_net_handler()`,
/// `wifi_net_handler()` or `thread_net_handler()`, or use `eth_sys_handler()` & co.
/// for a chain with all root endpoint system clusters.
///
/// # Arguments:
/// - `sw_diag`: The `SwDiag` implementation (pass `&()` for the
///   no-op default: heap counters report `0`).
/// - `rand`: A random number generator.
pub fn root_handler<'a, R: Rng>(sw_diag: &'a dyn SwDiag, rand: R) -> RootHandler<'a> {
    root_handler_chained(sw_diag, EmptyHandler, rand)
}

/// Return a handler for the root endpoint operational network clusters,
/// chained on top of `next`.
/// Use this handler for devices that use Ethernet as the Matter Operational Network.
///
/// # Arguments:
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `next`: The handler to chain on top of; receives everything not matched here.
/// - `rand`: A random number generator.
pub fn eth_net_handler<'a, R: Rng, H>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    next: H,
    mut rand: R,
) -> EthNetHandler<'a, H> {
    net_handler(
        comm_policy,
        gen_diag,
        netif_diag,
        EthNetCtl::new_default(),
        &AlwaysConnected,
        |e, c| {
            e == ROOT_ENDPOINT_ID
                && (c == GenCommHandler::CLUSTER.id
                    || c == GenDiagHandler::CLUSTER.id
                    || c == EthDiagHandler::CLUSTER.id)
        },
        EthDiagHandler::new(Dataver::new_rand(&mut rand)).adapt(),
        next,
        rand,
    )
}

/// Return a handler for the root endpoint operational network clusters,
/// chained on top of `next`.
/// Use this handler for devices that use Wifi as the Matter Operational Network.
///
/// # Arguments:
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `wifi_diag`: The `WifiDiag` implementation.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `next`: The handler to chain on top of; receives everything not matched here.
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
pub fn wifi_net_handler<'a, R: Rng, T, H>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    wifi_diag: &'a dyn WifiDiag,
    net_ctl: T,
    next: H,
    mut rand: R,
) -> WifiNetHandler<'a, T, H>
where
    T: NetCtl + NetCtlStatus,
{
    net_handler(
        comm_policy,
        gen_diag,
        netif_diag,
        net_ctl,
        wifi_diag,
        |e, c| {
            e == ROOT_ENDPOINT_ID
                && (c == GenCommHandler::CLUSTER.id
                    || c == GenDiagHandler::CLUSTER.id
                    || c == WifiDiagHandler::CLUSTER.id)
        },
        WifiDiagHandler::new(Dataver::new_rand(&mut rand), wifi_diag).adapt(),
        next,
        rand,
    )
}

/// Return a handler for the root endpoint operational network clusters,
/// chained on top of `next`.
/// Use this handler for devices that use Thread as the Matter Operational Network.
///
/// # Arguments:
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `thread_diag`: The `ThreadDiag` implementation.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `next`: The handler to chain on top of; receives everything not matched here.
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
pub fn thread_net_handler<'a, R: Rng, T, H>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    thread_diag: &'a dyn ThreadDiag,
    net_ctl: T,
    next: H,
    mut rand: R,
) -> ThreadNetHandler<'a, T, H>
where
    T: NetCtl + NetCtlStatus,
{
    net_handler(
        comm_policy,
        gen_diag,
        netif_diag,
        net_ctl,
        thread_diag,
        |e, c| {
            e == ROOT_ENDPOINT_ID
                && (c == GenCommHandler::CLUSTER.id
                    || c == GenDiagHandler::CLUSTER.id
                    || c == ThreadDiagHandler::CLUSTER.id)
        },
        ThreadDiagHandler::new(Dataver::new_rand(&mut rand), thread_diag).adapt(),
        next,
        rand,
    )
}

/// Return a system handler for the root endpoint (Endpoint 0).
/// Use this handler for devices that use Ethernet as the Matter Operational Network.
///
/// # Arguments:
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `sw_diag`: The `SwDiag` implementation (pass `&()` for the
///   no-op default: heap counters report `0`).
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
pub fn eth_sys_handler<'a, R: Rng>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    sw_diag: &'a dyn SwDiag,
    mut rand: R,
) -> EthSysHandler<'a> {
    sys_handler(
        comm_policy,
        gen_diag,
        netif_diag,
        sw_diag,
        EthNetCtl::new_default(),
        &AlwaysConnected,
        |e, c| e == ROOT_ENDPOINT_ID && c == EthDiagHandler::CLUSTER.id,
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
/// - `sw_diag`: The `SwDiag` implementation (pass `&()` for the no-op default).
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
pub fn wifi_sys_handler<'a, R: Rng, T>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    wifi_diag: &'a dyn WifiDiag,
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
        sw_diag,
        net_ctl,
        wifi_diag,
        |e, c| e == ROOT_ENDPOINT_ID && c == WifiDiagHandler::CLUSTER.id,
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
/// - `sw_diag`: The `SwDiag` implementation (pass `&()` for the no-op default).
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
pub fn thread_sys_handler<'a, R: Rng, T>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    thread_diag: &'a dyn ThreadDiag,
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
        sw_diag,
        net_ctl,
        thread_diag,
        |e, c| e == ROOT_ENDPOINT_ID && c == ThreadDiagHandler::CLUSTER.id,
        ThreadDiagHandler::new(Dataver::new_rand(&mut rand), thread_diag).adapt(),
        rand,
    )
}

/// The `root_handler()` chain on top of `next`.
fn root_handler_chained<'a, R: Rng, T>(
    sw_diag: &'a dyn SwDiag,
    next: T,
    mut rand: R,
) -> RootHandler<'a, T> {
    ChainedHandler::new(
        |e, c| e == ROOT_ENDPOINT_ID && c == TimeSyncHandler::CLUSTER.id,
        TimeSyncHandler::new(Dataver::new_rand(&mut rand)).adapt(),
        next,
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == SwDiagHandler::CLUSTER.id,
        SwDiagHandler::new(Dataver::new_rand(&mut rand), sw_diag).adapt(),
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == GrpKeyMgmtHandler::CLUSTER.id,
        GrpKeyMgmtHandler::new(Dataver::new_rand(&mut rand)).adapt(),
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == AclHandler::CLUSTER.id,
        AclHandler::new(Dataver::new_rand(&mut rand)).adapt(),
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == NocHandler::CLUSTER.id,
        NocHandler::new(Dataver::new_rand(&mut rand)).adapt(),
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == AdminCommHandler::CLUSTER.id,
        AdminCommHandler::new(Dataver::new_rand(&mut rand)).adapt(),
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == BasicInfoHandler::CLUSTER.id,
        BasicInfoHandler::new(Dataver::new_rand(&mut rand)).adapt(),
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == DescHandler::CLUSTER.id,
        DescHandler::new(Dataver::new_rand(&mut rand)).adapt(),
    )
}

/// The non-async operational network clusters on top of `next`.
///
/// `netw_diag_matcher` is the matcher of the network diagnostics link, which sits
/// at the bottom of the chain, right above `next`.
#[allow(clippy::too_many_arguments)]
fn oper_net_handler<'a, R: Rng, N, T>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    netw_diag_matcher: FnMatcher,
    netw_diag: N,
    next: T,
    mut rand: R,
) -> OperNetHandler<'a, N, T> {
    ChainedHandler::new(netw_diag_matcher, netw_diag, next)
        .chain(
            |e, c| e == ROOT_ENDPOINT_ID && c == GenDiagHandler::CLUSTER.id,
            GenDiagHandler::new(Dataver::new_rand(&mut rand), gen_diag, netif_diag).adapt(),
        )
        .chain(
            |e, c| e == ROOT_ENDPOINT_ID && c == GenCommHandler::CLUSTER.id,
            GenCommHandler::new(Dataver::new_rand(&mut rand), comm_policy).adapt(),
        )
}

/// Return a handler for the root endpoint operational network clusters,
/// chained on top of `next`.
///
/// Use `eth_net_handler()`, `wifi_net_handler()` or `thread_net_handler()` instead to get the
/// appropriate Network Diagnostic handler included in the handler.
///
/// # Arguments:
/// - `net_matcher`: A matcher for exactly the General Commissioning, General Diagnostics and
///   `netw_diag` clusters on the root endpoint. It guards the `Async` sub-chain with the three,
///   and - as the network diagnostics link is at the bottom of that sub-chain - also serves
///   as the matcher of that link.
#[allow(clippy::too_many_arguments)]
fn net_handler<'a, R: Rng, T, N, H>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    net_ctl: T,
    wireless_diag: &'a dyn WirelessDiag,
    net_matcher: FnMatcher,
    netw_diag: N,
    next: H,
    mut rand: R,
) -> NetHandler<'a, T, N, H>
where
    T: NetCtl + NetCtlStatus,
{
    ChainedHandler::new(
        |e, c| e == ROOT_ENDPOINT_ID && c == NetCommHandler::<T>::CLUSTER.id,
        NetCommHandler::new(Dataver::new_rand(&mut rand), net_ctl, wireless_diag).adapt(),
        ChainedHandler::new(
            net_matcher,
            Async(oper_net_handler(
                comm_policy,
                gen_diag,
                netif_diag,
                net_matcher,
                netw_diag,
                EmptyHandler,
                &mut rand,
            )),
            next,
        ),
    )
}

/// Return a system handler for the root endpoint (Endpoint 0) with all system clusters.
///
/// Use `eth_sys_handler()`, `wifi_sys_handler()` or `thread_sys_handler()` instead to get the
/// appropriate Network Diagnostic handler included in the handler.
#[allow(clippy::too_many_arguments)]
fn sys_handler<'a, R: Rng, T, N>(
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    sw_diag: &'a dyn SwDiag,
    net_ctl: T,
    wireless_diag: &'a dyn WirelessDiag,
    netw_diag_matcher: FnMatcher,
    netw_diag: N,
    mut rand: R,
) -> SysHandler<'a, T, N>
where
    T: NetCtl + NetCtlStatus,
{
    ChainedHandler::new(
        |e, c| e == ROOT_ENDPOINT_ID && c == NetCommHandler::<T>::CLUSTER.id,
        NetCommHandler::new(Dataver::new_rand(&mut rand), net_ctl, wireless_diag).adapt(),
        Async(oper_net_handler(
            comm_policy,
            gen_diag,
            netif_diag,
            netw_diag_matcher,
            netw_diag,
            root_handler_chained(sw_diag, EmptyHandler, &mut rand),
            &mut rand,
        )),
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
    sw_diag: &'a dyn SwDiag,
}

impl Default for EthSysHandlerBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> EthSysHandlerBuilder<'a> {
    /// Create a builder. Every hook defaults to a no-op provider.
    pub const fn new() -> Self {
        Self {
            comm_policy: &true,
            gen_diag: &(),
            netif_diag: &(),
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

    /// Set the `SwDiag` hook (Software Diagnostics data provider).
    pub const fn sw_diag(mut self, sw_diag: &'a dyn SwDiag) -> Self {
        self.sw_diag = sw_diag;
        self
    }

    /// Build the Ethernet system handler.
    pub fn build<R: Rng>(self, rand: R) -> EthSysHandler<'a> {
        eth_sys_handler(
            self.comm_policy,
            self.gen_diag,
            self.netif_diag,
            self.sw_diag,
            rand,
        )
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
    sw_diag: &'a dyn SwDiag,
    net_ctl: T,
}

impl<'a, T> WifiSysHandlerBuilder<'a, T>
where
    T: NetCtl + NetCtlStatus,
{
    /// Create a builder. `net_ctl` and `wifi_diag` are required;
    /// every other hook defaults to a no-op provider.
    pub const fn new(net_ctl: T, wifi_diag: &'a dyn WifiDiag) -> Self {
        Self {
            comm_policy: &true,
            gen_diag: &(),
            netif_diag: &(),
            wifi_diag,
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

    /// Set the `SwDiag` hook.
    pub const fn sw_diag(mut self, sw_diag: &'a dyn SwDiag) -> Self {
        self.sw_diag = sw_diag;
        self
    }

    /// Build the Wi-Fi system handler.
    pub fn build<R: Rng>(self, rand: R) -> WifiSysHandler<'a, T> {
        wifi_sys_handler(
            self.comm_policy,
            self.gen_diag,
            self.netif_diag,
            self.wifi_diag,
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
    sw_diag: &'a dyn SwDiag,
    net_ctl: T,
}

impl<'a, T> ThreadSysHandlerBuilder<'a, T>
where
    T: NetCtl + NetCtlStatus,
{
    /// Create a builder. `net_ctl` and `thread_diag` are required;
    /// every other hook defaults to a no-op provider.
    pub const fn new(net_ctl: T, thread_diag: &'a dyn ThreadDiag) -> Self {
        Self {
            comm_policy: &true,
            gen_diag: &(),
            netif_diag: &(),
            thread_diag,
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

    /// Set the `SwDiag` hook.
    pub const fn sw_diag(mut self, sw_diag: &'a dyn SwDiag) -> Self {
        self.sw_diag = sw_diag;
        self
    }

    /// Build the Thread system handler.
    pub fn build<R: Rng>(self, rand: R) -> ThreadSysHandler<'a, T> {
        thread_sys_handler(
            self.comm_policy,
            self.gen_diag,
            self.netif_diag,
            self.thread_diag,
            self.sw_diag,
            self.net_ctl,
            rand,
        )
    }
}
