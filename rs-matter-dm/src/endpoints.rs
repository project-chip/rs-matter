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
use crate::{handler_chain_type, Matter};

use crate::dm::clusters::acl::{self, AclHandler, ClusterHandler as _};
use crate::dm::clusters::adm_comm::{self, AdminCommHandler, ClusterHandler as _};
use crate::dm::clusters::basic_info::{self, BasicInfoHandler, ClusterHandler as _};
use crate::dm::clusters::desc::{self, ClusterHandler as _, DescHandler};
use crate::dm::clusters::eth_diag::{self, ClusterHandler as _, EthDiag, EthDiagHandler};
use crate::dm::clusters::gen_comm::{self, ClusterHandler as _, CommPolicy, GenCommHandler};
use crate::dm::clusters::gen_diag::{
    self, ClusterHandler as _, GenDiag, GenDiagHandler, NetifDiag,
};
use crate::dm::clusters::grp_key_mgmt::{self, ClusterHandler as _, GrpKeyMgmtHandler};
use crate::dm::clusters::net_comm::{
    self, ClusterAsyncHandler as _, NetCommHandler, NetCtl, NetCtlStatus, Networks,
};
use crate::dm::clusters::noc::{self, ClusterHandler as _, NocHandler};
use crate::dm::clusters::sw_diag::{self, ClusterHandler as _, SwDiag, SwDiagHandler};
use crate::dm::clusters::thread_diag::{self, ClusterHandler as _, ThreadDiag, ThreadDiagHandler};
use crate::dm::clusters::time_sync::{self, ClusterHandler as _, TimeSyncHandler};
use crate::dm::clusters::wifi_diag::{
    self, AlwaysConnected, ClusterHandler as _, WifiDiag, WifiDiagHandler, WirelessDiag,
};
use crate::dm::networks::eth::{EthNetCtl, EthNetwork};
use crate::dm::networks::NetChangeNotif;
use crate::dm::{Async, ChainedHandler, Dataver};
use crate::persist::NETWORKS_KEY;

/// A macro to generate the clusters' meta-data for an endpoint.
///
/// Net-type tokens (pick exactly one):
/// - `sys;` - all system model clusters except the concrete Network Diagnostics
///   cluster. Usually you want `eth;` / `wifi;` / `thread;` instead.
/// - `eth;` / `wifi;` / `thread;` - same as `sys;` plus the matching Network
///   Diagnostics cluster.
///
/// Optional cluster-shape modifiers — supply zero or more, in the order
/// shown, after the net-type token:
/// - `sw_diag(heap | watermarks | thread, …)` - shape the Software Diagnostics
///   cluster's advertised attribute/command surface. Tokens map to
///   [`crate::dm::clusters::sw_diag::Options`]: `heap` → `HEAP`,
///   `watermarks` → `WATERMARKS` (claims the Matter `WATERMARKS` feature and
///   implies `HEAP`), `thread` → `THREAD` (advertises `ThreadMetrics`; unrelated
///   to the Thread network protocol).
/// - `time_sync(time_zone | ntp_client | ntp_server | time_sync_client, …)` -
///   shape the Time Synchronization cluster. Tokens map 1:1 to
///   [`crate::dm::clusters::time_sync::Options`] and to the matching Matter
///   features (`TIME_ZONE`, `NTP_CLIENT`, `NTP_SERVER`, `TIME_SYNC_CLIENT`).
///
/// - `eth_diag(phy_rate | full_duplex | carrier_detect | time_since_reset | packet_counts |
///   error_counts, …)` - `eth;` only; shape the Ethernet Network Diagnostics cluster. Tokens map
///   1:1 to [`crate::dm::clusters::eth_diag::Options`]; `packet_counts` and `error_counts` claim
///   the Matter `PKTCNT` and `ERRCNT` features.
/// - `thread_diag(error_counts | mle_counts | mac_counts | active_timestamp | pending_timestamp |
///   delay, …)` - `thread;` only; shape the Thread Network Diagnostics cluster. Tokens map 1:1 to
///   [`crate::dm::clusters::thread_diag::Options`]; the `*_counts` ones claim the Matter
///   `ERRCNT`, `MLECNT` and `MACCNT` features.
/// - `wifi_diag(error_counts | packet_counts | current_max_rate, …)` - `wifi;` only; shape the
///   Wi-Fi Network Diagnostics cluster. Tokens map 1:1 to
///   [`crate::dm::clusters::wifi_diag::Options`]; the `*_counts` ones claim the Matter `ERRCNT`
///   and `PKTCNT` features.
///
/// Omitting a modifier advertises the corresponding cluster's empty-options
/// shape (required globals + always-on attributes, no features, no commands).
///
/// Trailing positional arguments are additional `Cluster<'static>` literals
/// merged into the slice — e.g. `clusters!(eth, sw_diag(heap); my_cluster)`.
///
/// The Groups cluster is intentionally *not* included in any of these presets:
/// Root Node (Matter Device Library) does not list Groups, and Groups
/// (Matter Application Cluster Specification) is scoped to per-endpoint
/// group membership which has no defined behavior on the Root Node. Wire
/// `GroupsHandler::CLUSTER` onto the application endpoint(s) where it actually
/// has meaning instead.
#[allow(unused_macros)]
#[macro_export]
macro_rules! clusters {
    (sys
        $(, acl($($acl_opt:ident),* $(,)?))?
        $(, sw_diag($($sw_opt:ident),* $(,)?))?
        $(, time_sync($($ts_opt:ident),* $(,)?))?
        ; $($cluster:expr $(,)?)*
    ) => {
        $crate::clusters!(
            <$crate::dm::clusters::desc::DescHandler as $crate::dm::clusters::desc::ClusterHandler>::CLUSTER,
            $crate::__acl_cluster!( $($($acl_opt),*)? ),
            <$crate::dm::clusters::basic_info::BasicInfoHandler as $crate::dm::clusters::basic_info::ClusterHandler>::CLUSTER,
            <$crate::dm::clusters::gen_comm::GenCommHandler as $crate::dm::clusters::gen_comm::ClusterHandler>::CLUSTER,
            <$crate::dm::clusters::gen_diag::GenDiagHandler as $crate::dm::clusters::gen_diag::ClusterHandler>::CLUSTER,
            $crate::dm::clusters::sw_diag::cluster(
                $crate::__sw_diag_options!( $($($sw_opt),*)? )
            ),
            $crate::dm::clusters::time_sync::cluster::<{
                $crate::__time_sync_options!( $($($ts_opt),*)? ).bits()
            }>(),
            <$crate::dm::clusters::adm_comm::AdminCommHandler as $crate::dm::clusters::adm_comm::ClusterHandler>::CLUSTER,
            <$crate::dm::clusters::noc::NocHandler as $crate::dm::clusters::noc::ClusterHandler>::CLUSTER,
            <$crate::dm::clusters::grp_key_mgmt::GrpKeyMgmtHandler as $crate::dm::clusters::grp_key_mgmt::ClusterHandler>::CLUSTER,
            $($cluster,)*
        )
    };
    (eth
        $(, acl($($acl_opt:ident),* $(,)?))?
        $(, sw_diag($($sw_opt:ident),* $(,)?))?
        $(, time_sync($($ts_opt:ident),* $(,)?))?
        $(, eth_diag($($ed_opt:ident),* $(,)?))?
        ; $($cluster:expr $(,)?)*
    ) => {
        $crate::clusters!(
            sys
            $(, acl($($acl_opt),*))?
            $(, sw_diag($($sw_opt),*))?
            $(, time_sync($($ts_opt),*))?
            ;
            $crate::dm::clusters::net_comm::NetworkType::Ethernet.cluster(),
            $crate::dm::clusters::eth_diag::cluster::<{
                $crate::__eth_diag_options!( $($($ed_opt),*)? ).bits()
            }>(),
            $($cluster,)*
        )
    };
    (thread
        $(, acl($($acl_opt:ident),* $(,)?))?
        $(, sw_diag($($sw_opt:ident),* $(,)?))?
        $(, time_sync($($ts_opt:ident),* $(,)?))?
        $(, thread_diag($($td_opt:ident),* $(,)?))?
        ; $($cluster:expr $(,)?)*
    ) => {
        $crate::clusters!(
            sys
            $(, acl($($acl_opt),*))?
            $(, sw_diag($($sw_opt),*))?
            $(, time_sync($($ts_opt),*))?
            ;
            $crate::dm::clusters::net_comm::NetworkType::Thread.cluster(),
            $crate::dm::clusters::thread_diag::cluster::<{
                $crate::__thread_diag_options!( $($($td_opt),*)? ).bits()
            }>(),
            $($cluster,)*
        )
    };
    (wifi
        $(, acl($($acl_opt:ident),* $(,)?))?
        $(, sw_diag($($sw_opt:ident),* $(,)?))?
        $(, time_sync($($ts_opt:ident),* $(,)?))?
        $(, wifi_diag($($wd_opt:ident),* $(,)?))?
        ; $($cluster:expr $(,)?)*
    ) => {
        $crate::clusters!(
            sys
            $(, acl($($acl_opt),*))?
            $(, sw_diag($($sw_opt),*))?
            $(, time_sync($($ts_opt),*))?
            ;
            $crate::dm::clusters::net_comm::NetworkType::Wifi.cluster(),
            $crate::dm::clusters::wifi_diag::cluster::<{
                $crate::__wifi_diag_options!( $($($wd_opt),*)? ).bits()
            }>(),
            $($cluster,)*
        )
    };
    ($($cluster:expr $(,)?)*) => {
        &[
            $($cluster,)*
        ]
    }
}

/// Internal helper: map the `acl(...)` option token to the matching Access
/// Control cluster metadata: no token → the default
/// [`crate::dm::clusters::acl::AclHandler::CLUSTER`]; `aux` →
/// [`crate::dm::clusters::acl::CLUSTER_AUX`] (advertising the provisional
/// `AUXILIARY` feature and `AuxiliaryACL` attribute, e.g. for nodes hosting
/// the Groupcast cluster).
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __acl_cluster {
    () => {
        <$crate::dm::clusters::acl::AclHandler as $crate::dm::clusters::acl::ClusterHandler>::CLUSTER
    };
    (aux) => {
        $crate::dm::clusters::acl::CLUSTER_AUX
    };
}

/// Internal helper: turn a comma-separated list of `sw_diag(...)` lowercase
/// tokens into the corresponding [`crate::dm::clusters::sw_diag::Options`]
/// bitset value. `heap` → `HEAP`, `watermarks` → `WATERMARKS`, `thread`
/// → `THREAD`.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __sw_diag_options {
    () => { $crate::dm::clusters::sw_diag::Options::empty() };
    ($($opt:ident),+ $(,)?) => {
        $crate::dm::clusters::sw_diag::Options::empty()
            $(.union($crate::__sw_diag_option_bit!($opt)))+
    };
}

/// Internal helper: map one lowercase `sw_diag(...)` token to the matching
/// [`crate::dm::clusters::sw_diag::Options`] constant.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __sw_diag_option_bit {
    (heap) => {
        $crate::dm::clusters::sw_diag::Options::HEAP
    };
    (watermarks) => {
        $crate::dm::clusters::sw_diag::Options::WATERMARKS
    };
    (thread) => {
        $crate::dm::clusters::sw_diag::Options::THREAD
    };
}

/// Internal helper: turn a comma-separated list of `eth_diag(...)` lowercase
/// tokens into the corresponding [`crate::dm::clusters::eth_diag::Options`]
/// bitset value.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __eth_diag_options {
    () => { $crate::dm::clusters::eth_diag::Options::empty() };
    ($($opt:ident),+ $(,)?) => {
        $crate::dm::clusters::eth_diag::Options::empty()
            $(.union($crate::__eth_diag_option_bit!($opt)))+
    };
}

/// Internal helper: map one lowercase `eth_diag(...)` token to the matching
/// [`crate::dm::clusters::eth_diag::Options`] constant.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __eth_diag_option_bit {
    (phy_rate) => {
        $crate::dm::clusters::eth_diag::Options::PHY_RATE
    };
    (full_duplex) => {
        $crate::dm::clusters::eth_diag::Options::FULL_DUPLEX
    };
    (carrier_detect) => {
        $crate::dm::clusters::eth_diag::Options::CARRIER_DETECT
    };
    (time_since_reset) => {
        $crate::dm::clusters::eth_diag::Options::TIME_SINCE_RESET
    };
    (packet_counts) => {
        $crate::dm::clusters::eth_diag::Options::PACKET_COUNTS
    };
    (error_counts) => {
        $crate::dm::clusters::eth_diag::Options::ERROR_COUNTS
    };
}

/// Internal helper: turn a comma-separated list of `thread_diag(...)` lowercase
/// tokens into the corresponding [`crate::dm::clusters::thread_diag::Options`]
/// bitset value.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __thread_diag_options {
    () => { $crate::dm::clusters::thread_diag::Options::empty() };
    ($($opt:ident),+ $(,)?) => {
        $crate::dm::clusters::thread_diag::Options::empty()
            $(.union($crate::__thread_diag_option_bit!($opt)))+
    };
}

/// Internal helper: map one lowercase `thread_diag(...)` token to the matching
/// [`crate::dm::clusters::thread_diag::Options`] constant.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __thread_diag_option_bit {
    (error_counts) => {
        $crate::dm::clusters::thread_diag::Options::ERROR_COUNTS
    };
    (mle_counts) => {
        $crate::dm::clusters::thread_diag::Options::MLE_COUNTS
    };
    (mac_counts) => {
        $crate::dm::clusters::thread_diag::Options::MAC_COUNTS
    };
    (active_timestamp) => {
        $crate::dm::clusters::thread_diag::Options::ACTIVE_TIMESTAMP
    };
    (pending_timestamp) => {
        $crate::dm::clusters::thread_diag::Options::PENDING_TIMESTAMP
    };
    (delay) => {
        $crate::dm::clusters::thread_diag::Options::DELAY
    };
}

/// Internal helper: turn a comma-separated list of `wifi_diag(...)` lowercase
/// tokens into the corresponding [`crate::dm::clusters::wifi_diag::Options`]
/// bitset value.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __wifi_diag_options {
    () => { $crate::dm::clusters::wifi_diag::Options::empty() };
    ($($opt:ident),+ $(,)?) => {
        $crate::dm::clusters::wifi_diag::Options::empty()
            $(.union($crate::__wifi_diag_option_bit!($opt)))+
    };
}

/// Internal helper: map one lowercase `wifi_diag(...)` token to the matching
/// [`crate::dm::clusters::wifi_diag::Options`] constant.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __wifi_diag_option_bit {
    (error_counts) => {
        $crate::dm::clusters::wifi_diag::Options::ERROR_COUNTS
    };
    (packet_counts) => {
        $crate::dm::clusters::wifi_diag::Options::PACKET_COUNTS
    };
    (current_max_rate) => {
        $crate::dm::clusters::wifi_diag::Options::CURRENT_MAX_RATE
    };
}

/// Internal helper: turn a comma-separated list of `time_sync(...)` lowercase
/// tokens into the corresponding [`crate::dm::clusters::time_sync::Options`]
/// bitset value. Tokens map 1:1 to the matching Matter features.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __time_sync_options {
    () => { $crate::dm::clusters::time_sync::Options::empty() };
    ($($opt:ident),+ $(,)?) => {
        $crate::dm::clusters::time_sync::Options::empty()
            $(.union($crate::__time_sync_option_bit!($opt)))+
    };
}

/// Internal helper: map one lowercase `time_sync(...)` token to the matching
/// [`crate::dm::clusters::time_sync::Options`] constant.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __time_sync_option_bit {
    (time_zone) => {
        $crate::dm::clusters::time_sync::Options::TIME_ZONE
    };
    (ntp_client) => {
        $crate::dm::clusters::time_sync::Options::NTP_CLIENT
    };
    (ntp_server) => {
        $crate::dm::clusters::time_sync::Options::NTP_SERVER
    };
    (time_sync_client) => {
        $crate::dm::clusters::time_sync::Options::TIME_SYNC_CLIENT
    };
}

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
/// - `eth_diag(phy_rate | full_duplex | carrier_detect | time_since_reset | packet_counts |
///   error_counts, …)` — `eth` only; shapes the Ethernet Network Diagnostics cluster.
/// - `thread_diag(error_counts | mle_counts | mac_counts | active_timestamp | pending_timestamp |
///   delay, …)` — `thread` only; shapes the Thread Network Diagnostics cluster.
/// - `wifi_diag(error_counts | packet_counts | current_max_rate, …)` — `wifi` only; shapes the
///   Wi-Fi Network Diagnostics cluster.
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
        $(, eth_diag($($ed_opt:ident),* $(,)?))?
        $(, thread_diag($($td_opt:ident),* $(,)?))?
        $(, wifi_diag($($wd_opt:ident),* $(,)?))?
    ) => {
        $crate::dm::Endpoint {
            id: $crate::dm::endpoints::ROOT_ENDPOINT_ID,
            device_types: $crate::devices!($crate::dm::devices::DEV_TYPE_ROOT_NODE),
            clusters: $crate::clusters!(
                $t
                $(, acl($($acl_opt),*))?
                $(, sw_diag($($sw_opt),*))?
                $(, time_sync($($ts_opt),*))?
                $(, eth_diag($($ed_opt),*))?
                $(, thread_diag($($td_opt),*))?
                $(, wifi_diag($($wd_opt),*))?
                ;
            ),
            client_clusters: &[],
            unique_id: None,
            semantic_tags: &[],
        }
    }
}

pub use crate::dm::ROOT_ENDPOINT_ID;

/// A type alias for the handler chain returned by `root_handler()`:
/// the root endpoint system clusters that do not depend on the operational network.
///
/// A non-async chain; wrap it in `Async` to chain it with async handlers.
/// `T` is the handler at the end of the chain.
pub type RootHandler<'a, T = EmptyHandler> = handler_chain_type!(
    FnMatcher => desc::HandlerAdaptor<DescHandler<'a>>,
    FnMatcher => basic_info::HandlerAdaptor<BasicInfoHandler<'a>>,
    FnMatcher => adm_comm::HandlerAdaptor<AdminCommHandler<'a>>,
    FnMatcher => noc::HandlerAdaptor<NocHandler<'a>>,
    FnMatcher => acl::HandlerAdaptor<AclHandler<'a>>,
    FnMatcher => grp_key_mgmt::HandlerAdaptor<GrpKeyMgmtHandler<'a>>,
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
pub type EthNetHandler<'a, H> = NetHandler<
    'a,
    EthNetwork<'static>,
    EthNetCtl<'a>,
    eth_diag::HandlerAdaptor<EthDiagHandler<'a>>,
    H,
>;

/// A type alias for the handler chain returned by `wifi_net_handler()`.
pub type WifiNetHandler<'a, S, T, H> =
    NetHandler<'a, S, T, wifi_diag::HandlerAdaptor<WifiDiagHandler<'a>>, H>;

/// A type alias for the handler chain returned by `thread_net_handler()`.
pub type ThreadNetHandler<'a, S, T, H> =
    NetHandler<'a, S, T, thread_diag::HandlerAdaptor<ThreadDiagHandler<'a>>, H>;

/// A type alias for the handler chain returned by `net_handler()`:
/// the operational network clusters of the root endpoint, on top of the handler `H`,
/// which receives everything the network clusters do not match.
///
/// `S` is the networks store of the primary network interface.
pub type NetHandler<'a, S, T, N, H> = handler_chain_type!(
    FnMatcher => net_comm::HandlerAsyncAdaptor<NetCommHandler<'a, S, T>>,
    FnMatcher => Async<OperNetHandler<'a, N>>
    | H
);

/// A type alias for the handler chain returned by `eth_sys_handler()`.
pub type EthSysHandler<'a> = SysHandler<
    'a,
    EthNetwork<'static>,
    EthNetCtl<'a>,
    eth_diag::HandlerAdaptor<EthDiagHandler<'a>>,
>;

/// A type alias for the handler chain returned by `wifi_sys_handler()`.
pub type WifiSysHandler<'a, S, T> =
    SysHandler<'a, S, T, wifi_diag::HandlerAdaptor<WifiDiagHandler<'a>>>;

/// A type alias for the handler chain returned by `thread_sys_handler()`.
pub type ThreadSysHandler<'a, S, T> =
    SysHandler<'a, S, T, thread_diag::HandlerAdaptor<ThreadDiagHandler<'a>>>;

/// A type alias for the handler chain returned by `sys_handler()`:
/// all system clusters of the root endpoint.
///
/// `S` is the networks store of the primary network interface.
pub type SysHandler<'a, S, T, N> = handler_chain_type!(
    FnMatcher => net_comm::HandlerAsyncAdaptor<NetCommHandler<'a, S, T>>
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
/// - `matter`: The `Matter` instance the clusters serve.
/// - `sw_diag`: The `SwDiag` implementation (pass `&()` for the
///   no-op default: heap counters report `0`).
/// - `rand`: A random number generator.
pub fn root_handler<'a, R: Rng>(
    matter: &'a Matter<'a>,
    sw_diag: &'a dyn SwDiag,
    rand: R,
) -> RootHandler<'a> {
    root_handler_chained(matter, sw_diag, EmptyHandler, rand)
}

/// Return a handler for the root endpoint operational network clusters,
/// chained on top of `next`.
/// Use this handler for devices that use Ethernet as the Matter Operational Network.
///
/// # Arguments:
/// - `matter`: The `Matter` instance the clusters serve.
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `eth_diag`: The `EthDiag` implementation (pass `&()` if it has nothing to report).
/// - `next`: The handler to chain on top of; receives everything not matched here.
/// - `rand`: A random number generator.
pub fn eth_net_handler<'a, R: Rng, H>(
    matter: &'a Matter<'a>,
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    eth_diag: &'a dyn EthDiag,
    next: H,
    mut rand: R,
) -> EthNetHandler<'a, H> {
    net_handler(
        matter,
        comm_policy,
        gen_diag,
        netif_diag,
        EthNetwork::new_default(),
        EthNetCtl::new_default(),
        &AlwaysConnected,
        |e, c| {
            e == ROOT_ENDPOINT_ID
                && (c == GenCommHandler::CLUSTER.id
                    || c == GenDiagHandler::CLUSTER.id
                    || c == EthDiagHandler::CLUSTER.id)
        },
        EthDiagHandler::new(Dataver::new_rand(&mut rand), eth_diag).adapt(),
        next,
        rand,
    )
}

/// Return a handler for the root endpoint operational network clusters,
/// chained on top of `next`.
/// Use this handler for devices that use Wifi as the Matter Operational Network.
///
/// # Arguments:
/// - `matter`: The `Matter` instance the clusters serve.
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `wifi_diag`: The `WifiDiag` implementation.
/// - `networks`: The networks store of the Wifi interface: by value, or a `&mut`
///   to a store living elsewhere.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `next`: The handler to chain on top of; receives everything not matched here.
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
pub fn wifi_net_handler<'a, R: Rng, S, T, H>(
    matter: &'a Matter<'a>,
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    wifi_diag: &'a dyn WifiDiag,
    networks: S,
    net_ctl: T,
    next: H,
    mut rand: R,
) -> WifiNetHandler<'a, S, T, H>
where
    S: Networks,
    T: NetCtl + NetCtlStatus + WirelessDiag + NetChangeNotif,
{
    net_handler(
        matter,
        comm_policy,
        gen_diag,
        netif_diag,
        networks,
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
/// - `matter`: The `Matter` instance the clusters serve.
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `thread_diag`: The `ThreadDiag` implementation.
/// - `networks`: The networks store of the Thread interface: by value, or a `&mut`
///   to a store living elsewhere.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `next`: The handler to chain on top of; receives everything not matched here.
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
pub fn thread_net_handler<'a, R: Rng, S, T, H>(
    matter: &'a Matter<'a>,
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    thread_diag: &'a dyn ThreadDiag,
    networks: S,
    net_ctl: T,
    next: H,
    mut rand: R,
) -> ThreadNetHandler<'a, S, T, H>
where
    S: Networks,
    T: NetCtl + NetCtlStatus + WirelessDiag + NetChangeNotif,
{
    net_handler(
        matter,
        comm_policy,
        gen_diag,
        netif_diag,
        networks,
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
/// - `matter`: The `Matter` instance the clusters serve.
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `eth_diag`: The `EthDiag` implementation (pass `&()` if it has nothing to report).
/// - `sw_diag`: The `SwDiag` implementation (pass `&()` for the
///   no-op default: heap counters report `0`).
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
pub fn eth_sys_handler<'a, R: Rng>(
    matter: &'a Matter<'a>,
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    eth_diag: &'a dyn EthDiag,
    sw_diag: &'a dyn SwDiag,
    mut rand: R,
) -> EthSysHandler<'a> {
    sys_handler(
        matter,
        comm_policy,
        gen_diag,
        netif_diag,
        sw_diag,
        EthNetwork::new_default(),
        EthNetCtl::new_default(),
        &AlwaysConnected,
        |e, c| e == ROOT_ENDPOINT_ID && c == EthDiagHandler::CLUSTER.id,
        EthDiagHandler::new(Dataver::new_rand(&mut rand), eth_diag).adapt(),
        rand,
    )
}

/// Return a system handler for the root endpoint (Endpoint 0).
/// Use this handler for devices that use Wifi as the Matter Operational Network.
///
/// # Arguments:
/// - `matter`: The `Matter` instance the clusters serve.
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `wifi_diag`: The `WifiDiag` implementation.
/// - `sw_diag`: The `SwDiag` implementation (pass `&()` for the no-op default).
/// - `networks`: The networks store of the Wifi interface: by value, or a `&mut`
///   to a store living elsewhere.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
pub fn wifi_sys_handler<'a, R: Rng, S, T>(
    matter: &'a Matter<'a>,
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    wifi_diag: &'a dyn WifiDiag,
    sw_diag: &'a dyn SwDiag,
    networks: S,
    net_ctl: T,
    mut rand: R,
) -> WifiSysHandler<'a, S, T>
where
    S: Networks,
    T: NetCtl + NetCtlStatus + WirelessDiag + NetChangeNotif,
{
    sys_handler(
        matter,
        comm_policy,
        gen_diag,
        netif_diag,
        sw_diag,
        networks,
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
/// - `matter`: The `Matter` instance the clusters serve.
/// - `comm_policy`: The `CommPolicy` implementation.
/// - `gen_diag`: The `GenDiag` implementation.
/// - `netif_diag`: The `NetifDiag` implementation.
/// - `thread_diag`: The `ThreadDiag` implementation.
/// - `sw_diag`: The `SwDiag` implementation (pass `&()` for the no-op default).
/// - `networks`: The networks store of the Thread interface: by value, or a `&mut`
///   to a store living elsewhere.
/// - `net_ctl`: The `NetCtl` implementation.
/// - `rand`: A random number generator.
#[allow(clippy::too_many_arguments)]
pub fn thread_sys_handler<'a, R: Rng, S, T>(
    matter: &'a Matter<'a>,
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    thread_diag: &'a dyn ThreadDiag,
    sw_diag: &'a dyn SwDiag,
    networks: S,
    net_ctl: T,
    mut rand: R,
) -> ThreadSysHandler<'a, S, T>
where
    S: Networks,
    T: NetCtl + NetCtlStatus + WirelessDiag + NetChangeNotif,
{
    sys_handler(
        matter,
        comm_policy,
        gen_diag,
        netif_diag,
        sw_diag,
        networks,
        net_ctl,
        thread_diag,
        |e, c| e == ROOT_ENDPOINT_ID && c == ThreadDiagHandler::CLUSTER.id,
        ThreadDiagHandler::new(Dataver::new_rand(&mut rand), thread_diag).adapt(),
        rand,
    )
}

/// The `root_handler()` chain on top of `next`.
fn root_handler_chained<'a, R: Rng, T>(
    matter: &'a Matter<'a>,
    sw_diag: &'a dyn SwDiag,
    next: T,
    mut rand: R,
) -> RootHandler<'a, T> {
    ChainedHandler::new(
        |e, c| e == ROOT_ENDPOINT_ID && c == TimeSyncHandler::CLUSTER.id,
        TimeSyncHandler::new(Dataver::new_rand(&mut rand), matter).adapt(),
        next,
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == SwDiagHandler::CLUSTER.id,
        SwDiagHandler::new(Dataver::new_rand(&mut rand), sw_diag).adapt(),
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == GrpKeyMgmtHandler::CLUSTER.id,
        GrpKeyMgmtHandler::new(Dataver::new_rand(&mut rand), matter).adapt(),
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == AclHandler::CLUSTER.id,
        AclHandler::new(Dataver::new_rand(&mut rand), matter).adapt(),
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == NocHandler::CLUSTER.id,
        NocHandler::new(Dataver::new_rand(&mut rand), matter).adapt(),
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == AdminCommHandler::CLUSTER.id,
        AdminCommHandler::new(Dataver::new_rand(&mut rand), matter).adapt(),
    )
    .chain(
        |e, c| e == ROOT_ENDPOINT_ID && c == BasicInfoHandler::CLUSTER.id,
        BasicInfoHandler::new(Dataver::new_rand(&mut rand), matter).adapt(),
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
    matter: &'a Matter<'a>,
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
            GenDiagHandler::new(Dataver::new_rand(&mut rand), matter, gen_diag, netif_diag).adapt(),
        )
        .chain(
            |e, c| e == ROOT_ENDPOINT_ID && c == GenCommHandler::CLUSTER.id,
            GenCommHandler::new(Dataver::new_rand(&mut rand), matter, comm_policy).adapt(),
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
fn net_handler<'a, R: Rng, S, T, N, H>(
    matter: &'a Matter<'a>,
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    networks: S,
    net_ctl: T,
    wireless_diag: &'a dyn WirelessDiag,
    net_matcher: FnMatcher,
    netw_diag: N,
    next: H,
    mut rand: R,
) -> NetHandler<'a, S, T, N, H>
where
    S: Networks,
    T: NetCtl + NetCtlStatus + WirelessDiag + NetChangeNotif,
{
    ChainedHandler::new(
        |e, c| e == ROOT_ENDPOINT_ID && c == NetCommHandler::<S, T>::CLUSTER.id,
        NetCommHandler::new(
            Dataver::new_rand(&mut rand),
            matter,
            ROOT_ENDPOINT_ID,
            networks,
            NETWORKS_KEY,
            net_ctl,
            wireless_diag,
        )
        .adapt(),
        ChainedHandler::new(
            net_matcher,
            Async(oper_net_handler(
                matter,
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
fn sys_handler<'a, R: Rng, S, T, N>(
    matter: &'a Matter<'a>,
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    sw_diag: &'a dyn SwDiag,
    networks: S,
    net_ctl: T,
    wireless_diag: &'a dyn WirelessDiag,
    netw_diag_matcher: FnMatcher,
    netw_diag: N,
    mut rand: R,
) -> SysHandler<'a, S, T, N>
where
    S: Networks,
    T: NetCtl + NetCtlStatus + WirelessDiag + NetChangeNotif,
{
    ChainedHandler::new(
        |e, c| e == ROOT_ENDPOINT_ID && c == NetCommHandler::<S, T>::CLUSTER.id,
        NetCommHandler::new(
            Dataver::new_rand(&mut rand),
            matter,
            ROOT_ENDPOINT_ID,
            networks,
            NETWORKS_KEY,
            net_ctl,
            wireless_diag,
        )
        .adapt(),
        Async(oper_net_handler(
            matter,
            comm_policy,
            gen_diag,
            netif_diag,
            netw_diag_matcher,
            netw_diag,
            root_handler_chained(matter, sw_diag, EmptyHandler, &mut rand),
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
// `NetifDiag` / `EthDiag` / `TimeSync` / `SwDiag` are already impls in the crate). New
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
    eth_diag: &'a dyn EthDiag,
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
            eth_diag: &(),
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

    /// Set the `EthDiag` hook (Ethernet Network Diagnostics data provider).
    pub const fn eth_diag(mut self, eth_diag: &'a dyn EthDiag) -> Self {
        self.eth_diag = eth_diag;
        self
    }

    /// Set the `SwDiag` hook (Software Diagnostics data provider).
    pub const fn sw_diag(mut self, sw_diag: &'a dyn SwDiag) -> Self {
        self.sw_diag = sw_diag;
        self
    }

    /// Build the Ethernet system handler, serving `matter`.
    pub fn build<R: Rng>(self, matter: &'a Matter<'a>, rand: R) -> EthSysHandler<'a> {
        eth_sys_handler(
            matter,
            self.comm_policy,
            self.gen_diag,
            self.netif_diag,
            self.eth_diag,
            self.sw_diag,
            rand,
        )
    }
}

/// Builder for a Wi-Fi root-endpoint system handler.
///
/// `networks`, `net_ctl` and `wifi_diag` are required (no sensible default) and
/// supplied to [`Self::new`]; everything else falls back to no-op defaults.
pub struct WifiSysHandlerBuilder<'a, S, T> {
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    wifi_diag: &'a dyn WifiDiag,
    sw_diag: &'a dyn SwDiag,
    networks: S,
    net_ctl: T,
}

impl<'a, S, T> WifiSysHandlerBuilder<'a, S, T>
where
    S: Networks,
    T: NetCtl + NetCtlStatus + WirelessDiag + NetChangeNotif,
{
    /// Create a builder. `networks`, `net_ctl` and `wifi_diag` are required;
    /// every other hook defaults to a no-op provider.
    pub const fn new(networks: S, net_ctl: T, wifi_diag: &'a dyn WifiDiag) -> Self {
        Self {
            comm_policy: &true,
            gen_diag: &(),
            netif_diag: &(),
            wifi_diag,
            sw_diag: &(),
            networks,
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

    /// Build the Wi-Fi system handler, serving `matter`.
    pub fn build<R: Rng>(self, matter: &'a Matter<'a>, rand: R) -> WifiSysHandler<'a, S, T> {
        wifi_sys_handler(
            matter,
            self.comm_policy,
            self.gen_diag,
            self.netif_diag,
            self.wifi_diag,
            self.sw_diag,
            self.networks,
            self.net_ctl,
            rand,
        )
    }
}

/// Builder for a Thread root-endpoint system handler.
///
/// `networks`, `net_ctl` and `thread_diag` are required (no sensible default) and
/// supplied to [`Self::new`]; everything else falls back to no-op defaults.
pub struct ThreadSysHandlerBuilder<'a, S, T> {
    comm_policy: &'a dyn CommPolicy,
    gen_diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
    thread_diag: &'a dyn ThreadDiag,
    sw_diag: &'a dyn SwDiag,
    networks: S,
    net_ctl: T,
}

impl<'a, S, T> ThreadSysHandlerBuilder<'a, S, T>
where
    S: Networks,
    T: NetCtl + NetCtlStatus + WirelessDiag + NetChangeNotif,
{
    /// Create a builder. `networks`, `net_ctl` and `thread_diag` are required;
    /// every other hook defaults to a no-op provider.
    pub const fn new(networks: S, net_ctl: T, thread_diag: &'a dyn ThreadDiag) -> Self {
        Self {
            comm_policy: &true,
            gen_diag: &(),
            netif_diag: &(),
            thread_diag,
            sw_diag: &(),
            networks,
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

    /// Build the Thread system handler, serving `matter`.
    pub fn build<R: Rng>(self, matter: &'a Matter<'a>, rand: R) -> ThreadSysHandler<'a, S, T> {
        thread_sys_handler(
            matter,
            self.comm_policy,
            self.gen_diag,
            self.netif_diag,
            self.thread_diag,
            self.sw_diag,
            self.networks,
            self.net_ctl,
            rand,
        )
    }
}
