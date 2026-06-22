/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

//! The Interaction Model as defined by the Matter Core spec: the interactions
//! (Read, Subscribe/Report, Write, Invoke, Timed) and their TLV-serde encoding
//! types, plus the engine - [`InteractionModel`] - that drives those
//! interactions against a [`crate::dm`] data model.
//!
//! It also contains a requestor-side IM client ([`client`]) and a very simple
//! responder - [`busy`] - which always returns a busy status code to all
//! incoming IM requests.

use core::num::NonZeroU8;
use core::pin::pin;

use embassy_futures::select::{select3, select4};
use embassy_time::{Instant, Timer};

use crate::acl::Accessor;
use crate::crypto::Crypto;
use crate::dm::clusters::net_comm::{
    NetCtl, NetworkType, Networks, NetworksAccess, SharedNetworks,
};
use crate::dm::clusters::wifi_diag::WirelessDiag;
use crate::dm::networks::eth::EthNetwork;
use crate::dm::networks::wireless::{NoopWirelessNetCtl, WirelessMgr, MAX_CREDS_SIZE};
use crate::dm::networks::NetChangeNotif;
use crate::dm::{
    AsyncHandler, AttrChangeNotifier, AttrDetails, Attribute, DataModel, EventEmitter,
    HandlerContext, MatchContextInstance, Metadata,
};
use crate::error::{Error, ErrorCode};
use crate::im::events::{EventReader, EventTLVWrite, Events, DEFAULT_MAX_EVENTS_BUF_SIZE};
use crate::im::invoker::HandlerInvoker;
use crate::im::subscriptions::{
    ReportContext, Subscriptions, SubscriptionsBuffers, DEFAULT_MAX_SUBSCRIPTIONS,
};
use crate::persist::{KvBlobStoreAccess, NETWORKS_KEY};
use crate::respond::ExchangeHandler;
use crate::tlv::{get_root_node_struct, FromTLV, Nullable, TLVElement, TLVTag, TLVWrite, ToTLV};
use crate::transport::exchange::{Exchange, ExchangeId, MAX_EXCHANGE_TX_BUF_SIZE};
use crate::utils::init::{init, Init};
use crate::utils::select::Coalesce;
use crate::utils::storage::pooled::Buffers;
use crate::utils::storage::WriteBuf;
use crate::Matter;

pub use encoding::*;
pub use expand::{expand_invoke, expand_read, expand_write};

pub mod busy;
pub mod client;
pub mod encoding;
pub mod events;
pub mod expand;
pub mod invoker;
pub mod subscriptions;

/// An `ExchangeHandler` implementation capable of handling responder exchanges for the Interaction Model protocol.
/// The mutable, owned-together state a [`InteractionModel`] operates on: the
/// subscriptions table, the events queue and the network store.
///
/// Allocating these as a single value (rather than three separate locals wired
/// up by hand at every call site) is the whole point: construct one
/// `InteractionModelState`, then hand a reference to it to [`InteractionModel::new`]. Each of
/// the three pieces keeps its own lock internally (the proven multi-lock model);
/// folding them behind a single mutex is a possible later refinement.
///
/// `N` is the (raw) [`Networks`] implementation — e.g.
/// [`EthNetwork`](crate::dm::networks::eth::EthNetwork) or
/// [`WirelessNetworks`](crate::dm::networks::wireless::WirelessNetworks); it is
/// wrapped internally in a [`SharedNetworks`] so the data model and (later) the
/// wireless manager can share it. `NS`/`NE` bound the subscription table and the
/// event-buffer size and default to [`DEFAULT_MAX_SUBSCRIPTIONS`] /
/// [`DEFAULT_MAX_EVENTS_BUF_SIZE`].
pub struct InteractionModelState<
    N,
    const NS: usize = DEFAULT_MAX_SUBSCRIPTIONS,
    const NE: usize = DEFAULT_MAX_EVENTS_BUF_SIZE,
> {
    subscriptions: Subscriptions<NS>,
    events: Events<NE>,
    networks: SharedNetworks<N>,
}

impl<N, const NS: usize, const NE: usize> InteractionModelState<N, NS, NE> {
    /// Create a new state instance backed by the given (raw) [`Networks`] store.
    pub const fn new(networks: N) -> Self {
        Self {
            subscriptions: Subscriptions::new(),
            events: Events::new(),
            networks: SharedNetworks::new(networks),
        }
    }

    /// Return an in-place initializer for the state (for large `NE`, to
    /// avoid a big temporary on the stack).
    pub fn init(networks: impl Init<N>) -> impl Init<Self> {
        init!(Self {
            subscriptions <- Subscriptions::init(),
            events <- Events::init(),
            networks <- SharedNetworks::init(networks),
        })
    }

    /// Reset this state's persisted contents to factory defaults - the
    /// events-queue epoch and the network store - removing both from `kv` using
    /// the scratch buffer provided by `kv`. Call once during a factory reset,
    /// with exclusive (`&mut`) access (i.e. before the state is shared with a
    /// [`InteractionModel`]).
    pub async fn reset_persist<K>(&mut self, kv: K) -> Result<(), Error>
    where
        K: KvBlobStoreAccess,
        N: Networks,
    {
        // We hold `&mut self`, so borrow the pieces directly - no locking.
        let Self {
            events, networks, ..
        } = self;

        let events = events.inner_mut();
        let networks = networks.get_mut().get_mut();

        kv.access(|store, buf| {
            // The event-number epoch.
            events.reset_persist(&mut *store, buf)?;

            // The network store.
            networks.reset()?;
            store.remove(NETWORKS_KEY, buf)?;

            Ok(())
        })
    }

    /// Re-hydrate this state's persisted contents - the events-queue epoch (so
    /// event numbers are not reused across reboots) and the network store - using
    /// the scratch buffer provided by `kv`. Call once at startup, before the
    /// state is shared with a [`InteractionModel`].
    pub async fn load_persist<K>(&mut self, kv: K) -> Result<(), Error>
    where
        K: KvBlobStoreAccess,
        N: Networks,
    {
        // We hold `&mut self`, so borrow the pieces directly - no locking
        // (the inner mutexes are only needed for shared, runtime access).
        let Self {
            events, networks, ..
        } = self;

        let events = events.inner_mut();
        let networks = networks.get_mut().get_mut();

        // The KV ops are sync, so do them all inside a single `access` closure.
        kv.access(|store, buf| {
            // The event-number epoch.
            events.load_persist(&mut *store, buf)?;

            // The network store.
            networks.reset()?;
            if let Some(data) = store.load(NETWORKS_KEY, buf)? {
                networks.load(data)?;
            }

            Ok(())
        })
    }

    /// The subscriptions table.
    pub const fn subscriptions(&self) -> &Subscriptions<NS> {
        &self.subscriptions
    }

    /// The events queue.
    pub const fn events(&self) -> &Events<NE> {
        &self.events
    }

    /// The network store (wrapped for shared, change-notifying access).
    pub const fn networks(&self) -> &SharedNetworks<N> {
        &self.networks
    }
}

/// The implementation needs a `DataModel` instance to interact with the underlying clusters of the data model.
///
/// `NC` is the network controller type driving the (optional) wireless connection
/// manager from [`InteractionModel::run`]. It defaults to [`NoopWirelessNetCtl`], which is
/// the right choice for Ethernet (and what the convenience [`InteractionModel::new`]
/// constructor wires up); wireless devices pass a real controller via
/// [`InteractionModel::new_with_net_ctl`].
pub struct InteractionModel<
    'a,
    C,
    B,
    T,
    K,
    N,
    NC = NoopWirelessNetCtl,
    const NS: usize = DEFAULT_MAX_SUBSCRIPTIONS,
    const NE: usize = DEFAULT_MAX_EVENTS_BUF_SIZE,
> where
    B: Buffers<IMBuffer>,
{
    matter: &'a Matter<'a>,
    crypto: C,
    buffers: &'a B,
    kv: K,
    net_ctl: NC,
    subscriptions_buffers: SubscriptionsBuffers<'a, B, NS>,
    state: &'a InteractionModelState<N, NS, NE>,
    handler: T,
}

/// A [`InteractionModelState`] for an Ethernet device: its network store is a fixed
/// [`EthNetwork`], so call sites need only the (defaulted) subscription/event
/// sizes. Pairs with [`EthInteractionModel`].
pub type EthInteractionModelState<
    const NS: usize = DEFAULT_MAX_SUBSCRIPTIONS,
    const NE: usize = DEFAULT_MAX_EVENTS_BUF_SIZE,
> = InteractionModelState<EthNetwork<'static>, NS, NE>;

/// A [`InteractionModel`] for an Ethernet device (network store fixed to [`EthNetwork`]),
/// so the `N` generic disappears from call sites. Pairs with [`EthInteractionModelState`].
pub type EthInteractionModel<
    'a,
    C,
    B,
    T,
    K,
    NC = NoopWirelessNetCtl,
    const NS: usize = DEFAULT_MAX_SUBSCRIPTIONS,
    const NE: usize = DEFAULT_MAX_EVENTS_BUF_SIZE,
> = InteractionModel<'a, C, B, T, K, EthNetwork<'static>, NC, NS, NE>;

/// A [`InteractionModelState`] for a wireless device, parameterized by the concrete
/// wireless network store `N` (e.g. `WifiNetworks<3>` or a Thread store). Pairs
/// with [`WirelessInteractionModel`].
pub type WirelessInteractionModelState<
    N,
    const NS: usize = DEFAULT_MAX_SUBSCRIPTIONS,
    const NE: usize = DEFAULT_MAX_EVENTS_BUF_SIZE,
> = InteractionModelState<N, NS, NE>;

/// A [`InteractionModel`] for a wireless device (network store `N`, network controller
/// `NC`). Pairs with [`WirelessInteractionModelState`].
pub type WirelessInteractionModel<
    'a,
    C,
    B,
    T,
    K,
    N,
    NC,
    const NS: usize = DEFAULT_MAX_SUBSCRIPTIONS,
    const NE: usize = DEFAULT_MAX_EVENTS_BUF_SIZE,
> = InteractionModel<'a, C, B, T, K, N, NC, NS, NE>;

impl<'a, C, B, T, K, N, const NS: usize, const NE: usize>
    InteractionModel<'a, C, B, T, K, N, NoopWirelessNetCtl, NS, NE>
where
    C: Crypto,
    B: Buffers<IMBuffer>,
    T: DataModel,
    K: KvBlobStoreAccess,
    N: Networks,
{
    /// Create the data model for a device that does not need an operational
    /// wireless connection manager (typically an Ethernet device).
    ///
    /// This is a convenience wrapper around [`InteractionModel::new_with_net_ctl`] that
    /// fixes the network controller to an inert [`NoopWirelessNetCtl`], so
    /// [`InteractionModel::run`]'s connection-management branch stays dormant.
    ///
    /// # Arguments
    /// - `matter` - a reference to the `Matter` instance
    /// - `buffers` - a reference to an implementation of `Buffers<IMBuffer>` which is used for allocating RX and TX buffers on the fly, when necessary
    /// - `handler` - an instance of type `T` which implements the `DataModel` trait. This instance is used for interacting with the underlying
    ///   clusters of the data model. Note that the expectations is for the user to provide a handler that handles the Matter system clusters
    ///   as well (Endpoint 0), possibly by decorating her own clusters with the `rs_matter::dm::root_endpoint::with_` methods
    /// - `kv` - an instance of type `K` which implements the `KvBlobStoreAccess` trait
    ///   (obtain one via [`Matter::kv`]). This instance is used for interacting with the key-value blob store.
    /// - `state` - a reference to the [`InteractionModelState`] holding the subscriptions table, the
    ///   events queue and the network store (the latter parameterized by the `Networks`
    ///   implementation `N`).
    #[inline(always)]
    pub fn new(
        matter: &'a Matter<'a>,
        crypto: C,
        buffers: &'a B,
        handler: T,
        kv: K,
        state: &'a InteractionModelState<N, NS, NE>,
    ) -> Self {
        Self::new_with_net_ctl(
            matter,
            crypto,
            buffers,
            handler,
            kv,
            NoopWirelessNetCtl::new(NetworkType::Ethernet),
            state,
        )
    }
}

impl<'a, C, B, T, K, N, NC, const NS: usize, const NE: usize>
    InteractionModel<'a, C, B, T, K, N, NC, NS, NE>
where
    C: Crypto,
    B: Buffers<IMBuffer>,
    T: DataModel,
    K: KvBlobStoreAccess,
    N: Networks,
{
    /// Create the data model with an explicit network controller `net_ctl`.
    ///
    /// Use this for wireless devices: `net_ctl` drives the operational connection
    /// manager run from [`InteractionModel::run`] (and is typically the same controller
    /// instance also wired into the `NetworkCommissioning` cluster handler). For
    /// Ethernet devices prefer the [`InteractionModel::new`] convenience constructor.
    ///
    /// # Arguments
    /// - `matter` - a reference to the `Matter` instance
    /// - `buffers` - a reference to an implementation of `Buffers<IMBuffer>` which is used for allocating RX and TX buffers on the fly, when necessary
    /// - `handler` - an instance of type `T` which implements the `DataModel` trait. This instance is used for interacting with the underlying
    ///   clusters of the data model. Note that the expectations is for the user to provide a handler that handles the Matter system clusters
    ///   as well (Endpoint 0), possibly by decorating her own clusters with the `rs_matter::dm::root_endpoint::with_` methods
    /// - `kv` - an instance of type `K` which implements the `KvBlobStoreAccess` trait
    ///   (obtain one via [`Matter::kv`]). This instance is used for interacting with the key-value blob store.
    /// - `net_ctl` - the network controller (`NetCtl` + `WirelessDiag` + `NetChangeNotif`) used by
    ///   the operational wireless connection manager driven from [`InteractionModel::run`].
    /// - `state` - a reference to the [`InteractionModelState`] holding the subscriptions table, the
    ///   events queue and the network store (the latter parameterized by the `Networks`
    ///   implementation `N`).
    #[inline(always)]
    pub fn new_with_net_ctl(
        matter: &'a Matter<'a>,
        crypto: C,
        buffers: &'a B,
        handler: T,
        kv: K,
        net_ctl: NC,
        state: &'a InteractionModelState<N, NS, NE>,
    ) -> Self {
        state.subscriptions.clear();

        Self {
            matter,
            crypto,
            buffers,
            kv,
            net_ctl,
            subscriptions_buffers: SubscriptionsBuffers::new(),
            state,
            handler,
        }
    }

    /// Get a reference to the `Matter` instance this data model is associated with.
    pub const fn matter(&self) -> &'a Matter<'a> {
        self.matter
    }

    pub const fn crypto(&self) -> &C {
        &self.crypto
    }

    /// Open the basic commissioning window.
    ///
    /// Equivalent to [`Matter::open_basic_comm_window`] but additionally
    /// bumps the data version of the `AdministratorCommissioning`
    /// cluster on the root endpoint and routes the change to
    /// subscribers — both happen automatically because this `InteractionModel`
    /// is itself the [`AttrChangeNotifier`] passed down.
    ///
    /// Prefer this entry point over the `Matter` one for any code path
    /// that has a `InteractionModel` available; `Matter::open_basic_comm_window`
    /// is the building block we delegate to and does not bump dataver
    /// (see its docs).
    pub fn open_basic_comm_window(&self, timeout_secs: u16) -> Result<(), Error> {
        self.matter
            .open_basic_comm_window(timeout_secs, &self.crypto, self)
    }

    /// Close the active commissioning window.
    ///
    /// Equivalent to [`Matter::close_comm_window`] but additionally
    /// bumps the `AdministratorCommissioning` dataver and routes
    /// subscribers via this `InteractionModel`'s [`AttrChangeNotifier`]. See
    /// `open_basic_comm_window` for the rationale.
    pub fn close_comm_window(&self) -> Result<bool, Error> {
        self.matter.close_comm_window(self)
    }

    /// Bump `BasicInformation::ConfigurationVersion` by one, persist
    /// the new value, and notify subscribers (which also bumps the
    /// `BasicInformation` cluster's dataver via this `InteractionModel`'s
    /// [`AttrChangeNotifier`]).
    ///
    /// Per Matter Core Spec, callers MUST invoke this
    /// whenever the node's exposed fixed-quality surface changes —
    /// typically after a firmware update that adds or removes
    /// functionality, after an internal reconfiguration that changes
    /// any `F`-quality attribute (Descriptor::ServerList,
    /// PartsList, …), or (for bridges) after a bridged node is added
    /// or removed. It is not invoked automatically by `rs-matter`
    /// because the library has no way to know about an application's
    /// reconfiguration events.
    ///
    /// Returns the new `ConfigurationVersion` value.
    pub fn bump_configuration_version(&self) -> Result<u32, Error> {
        // Delegate to `Matter::bump_configuration_version` for the
        // in-memory bump + persist; pass `self` as the
        // `AttrChangeNotifier` so the cluster's `Dataver` is bumped
        // too (the `Matter`-level call by itself only routes
        // subscribers and persists).
        self.matter.bump_configuration_version(&self.kv, self)
    }

    /// Run the Data Model instance.
    ///
    /// This drives the IM timeout checks, the data-model handler's own background
    /// job, the subscriptions reporting loop, and - for wireless devices - the
    /// operational connection manager (inert for Ethernet, where `net_ctl` is a
    /// [`NoopWirelessNetCtl`]).
    pub async fn run(&self) -> Result<(), Error>
    where
        NC: NetCtl + WirelessDiag + NetChangeNotif,
    {
        let mut timeouts = pin!(self.run_timeout_checks());
        let mut handler = pin!(self.handler.run(self));
        let mut subs = pin!(self.process_subscriptions(self.matter));
        let mut net = pin!(self.run_net_mgr());

        select4(&mut timeouts, &mut handler, &mut subs, &mut net)
            .coalesce()
            .await
    }

    /// Drive the operational wireless connection manager.
    ///
    /// For Ethernet devices (`net_ctl.net_type() == NetworkType::Ethernet`) there
    /// is nothing to manage, so this future simply pends forever. For wireless
    /// devices it runs a [`WirelessMgr`] over the network store, cycling through
    /// the registered networks and (re)connecting as needed once commissioned.
    async fn run_net_mgr(&self) -> Result<(), Error>
    where
        NC: NetCtl + WirelessDiag + NetChangeNotif,
    {
        if self.net_ctl.net_type() == NetworkType::Ethernet {
            // Nothing to manage for a wired device - just pend forever.
            return core::future::pending().await;
        }

        let mut buf = [0u8; MAX_CREDS_SIZE];
        let mut mgr = WirelessMgr::new(self.state.networks(), &self.net_ctl, &mut buf);

        mgr.run().await
    }

    /// Perform a single, one-shot connect to the wireless network with the given
    /// ID, immediately and regardless of the commissioning status.
    ///
    /// This drives the same [`WirelessMgr`] used by [`InteractionModel::run`]
    /// (over this model's network controller and the network store owned by its
    /// [`InteractionModelState`]), but calls [`WirelessMgr::connect_once`] rather
    /// than the operational loop. It exists so a stack performing **non-concurrent**
    /// (BLE-only) commissioning can replay the deferred `ConnectNetwork` once the
    /// operational radio is up but before commissioning completes - without having
    /// to own a `WirelessMgr` (or the networks) itself.
    pub async fn connect_once(&self, network_id: &[u8]) -> Result<(), Error>
    where
        NC: NetCtl + WirelessDiag + NetChangeNotif,
    {
        let mut buf = [0u8; MAX_CREDS_SIZE];
        let mut mgr = WirelessMgr::new(self.state.networks(), &self.net_ctl, &mut buf);

        mgr.connect_once(network_id).await
    }

    async fn run_timeout_checks(&self) -> Result<(), Error> {
        const CHECK_INTERVAL_SECS: u64 = 1;

        loop {
            Timer::after_secs(CHECK_INTERVAL_SECS).await;

            self.check_timeouts(None)?;
        }
    }

    fn check_timeouts(&self, exch_id: Option<ExchangeId>) -> Result<(), Error> {
        let mut notify_mdns = || self.matter.transport().notify_mdns_changed();
        let mut notify_change =
            |endpt_id, clust_id| self.notify_cluster_changed(endpt_id, clust_id);

        self.matter.with_state(|state| {
            let expire_sess_id = exch_id.and_then(|exch_id| {
                state
                    .sessions
                    .get(exch_id.session_id())
                    .map(|sess| sess.id())
            });

            // Disarm the failsafe on timeout
            state.failsafe.check_failsafe_timeout(
                &mut state.fabrics,
                &mut state.sessions,
                &self.state.networks,
                &self.kv,
                expire_sess_id,
                &mut notify_mdns,
                &mut notify_change,
            )?;

            // Close the commissioning window on timeout
            state
                .pase
                .check_comm_window_timeout(&mut notify_mdns, &mut notify_change)?;

            Ok(())
        })
    }

    /// Answer a responding exchange using the `DataModel` instance wrapped by this exchange handler.
    pub async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let fetch_meta = |exchange: &mut Exchange| {
            let meta = exchange.rx()?.meta();
            if meta.proto_id != PROTO_ID_INTERACTION_MODEL {
                Err(ErrorCode::InvalidProto)?;
            }

            Result::<_, Error>::Ok(meta)
        };

        if exchange.rx().is_err() {
            exchange.recv_fetch().await?;
        }

        let is_groupcast = exchange.is_groupcast()?;

        let mut meta = fetch_meta(exchange)?;

        let timeout_instant = if !is_groupcast && meta.opcode::<OpCode>()? == OpCode::TimedRequest {
            let timeout = self.timed(exchange).await?;

            exchange.recv_fetch().await?;
            meta = fetch_meta(exchange)?;

            Some(timeout)
        } else {
            None
        };

        self.check_timeouts(Some(exchange.id()))?;

        // TODO: Handle the cases where we receive a timeout request
        // before read and subscribe. This is probably not allowed.

        match meta.opcode::<OpCode>()? {
            OpCode::ReadRequest if is_groupcast => {
                error!("Received a groupcast message for opcode: ReadRequest")
            }
            OpCode::ReadRequest if !is_groupcast => self.read(exchange).await?,
            OpCode::WriteRequest => self.write(exchange, timeout_instant, is_groupcast).await?,
            OpCode::InvokeRequest => self.invoke(exchange, timeout_instant, is_groupcast).await?,
            OpCode::SubscribeRequest if is_groupcast => {
                error!("Received a groupcast message for opcode: SubscribeRequest")
            }
            OpCode::SubscribeRequest if !is_groupcast => self.subscribe(exchange).await?,
            OpCode::TimedRequest if !is_groupcast => {
                Self::send_status(exchange, IMStatusCode::InvalidAction).await?
            }
            _ if is_groupcast => {
                // Silently drop unsupported opcodes for group messages
            }
            opcode => {
                error!("Invalid opcode: {:?}", opcode);
                Err(ErrorCode::InvalidOpcode)?
            }
        }

        if !is_groupcast {
            exchange.acknowledge().await?;
        }

        Ok(())
    }

    /// Respond to a `ReadReq` request.
    async fn read(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let Some((mut tx, rx)) = self.buffers(exchange).await? else {
            return Ok(());
        };

        let read_req = ReadReq::new(TLVElement::new(&rx));
        debug!("IM: Read request: {:?}", read_req);

        if let Err(err) = Self::validate_read(&read_req) {
            error!("Invalid read request: {:?}", err);
            return Self::send_status(exchange, err.code().into()).await;
        }

        let req = ReportDataReq::Read(&read_req);

        let mut wb = WriteBuf::new(&mut tx);

        // Honor the `fabricFiltered` flag on the originating Read request.
        // When set, fabric-sensitive events emitted on other fabrics are
        // dropped before they reach the wire (Matter Core spec).
        let fabric_filtered = req.fabric_filtered().unwrap_or(true);

        let mut resp = ReportDataResponder::new(
            &req,
            None,
            HandlerInvoker::new(exchange, self),
            EventReader::new(0, u64::MAX, fabric_filtered),
            &self.state.events,
        );

        resp.respond(&mut wb, true, true, &self.handler, |_, _, _| true)
            .await?;

        Ok(())
    }

    /// Validate a `ReadReq` request prior to processing.
    fn validate_read(req: &ReadReq<'_>) -> Result<(), Error> {
        if let Some(attr_requests) = req.attr_requests()? {
            for attr_req in attr_requests {
                Self::validate_attr_wildcard_path(&attr_req?)?;
            }
        }

        Ok(())
    }

    /// Per-spec validation of an `AttrPath` that may contain wildcards.
    ///
    /// Per Matter spec, when a path uses a wildcard cluster
    /// but specifies a concrete attribute id, that attribute id must be a
    /// global (system) attribute. Any other combination must be rejected with
    /// `INVALID_ACTION`.
    fn validate_attr_wildcard_path(path: &AttrPath) -> Result<(), Error> {
        if path.cluster.is_none() {
            if let Some(attr_id) = path.attr {
                if !Attribute::is_system_attr(attr_id) {
                    return Err(ErrorCode::InvalidAction.into());
                }
            }
        }

        Ok(())
    }

    /// Respond to a `WriteReq` request.
    ///
    /// Arguments:
    /// - `exchange` - the exchange to respond to
    /// - `timeout_instant` - an optional timeout instant, if the request is a timed request
    async fn write(
        &self,
        exchange: &mut Exchange<'_>,
        timeout_instant: Option<Instant>,
        is_groupcast: bool,
    ) -> Result<(), Error> {
        while exchange.rx().is_ok() {
            // Loop while there are more write request chunks to process

            let Some((mut tx, rx)) = self.buffers(exchange).await? else {
                break;
            };

            let req = WriteReq::new(TLVElement::new(&rx));
            debug!("IM: Write request: {:?}", req);

            let timed = req.timed_request()?;

            if self.timed_out(exchange, timeout_instant, timed).await? {
                break;
            }

            let mut wb = WriteBuf::new(&mut tx);

            let mut resp = WriteResponder::new(&req, HandlerInvoker::new(exchange, self));

            resp.respond(&mut wb, &self.handler, is_groupcast).await?;

            if req.more_chunks()? {
                // This write request is just one of the chunks, so we need to wait and process
                // the next chunk as well
                exchange.recv_fetch().await?;
            }
        }

        Ok(())
    }

    /// Respond to an `InvokeReq` request.
    ///
    /// Arguments:
    /// - `exchange` - the exchange to respond to
    /// - `timeout_instant` - an optional timeout instant, if the request is a timed request
    async fn invoke(
        &self,
        exchange: &mut Exchange<'_>,
        timeout_instant: Option<Instant>,
        is_groupcast: bool,
    ) -> Result<(), Error> {
        let Some((mut tx, rx)) = self.buffers(exchange).await? else {
            return Ok(());
        };

        let req = InvReq::new(TLVElement::new(&rx));
        debug!("IM: Invoke request: {:?}", req);

        let timed = req.timed_request()?;

        if self.timed_out(exchange, timeout_instant, timed).await? {
            return Ok(());
        }

        let max_paths = exchange.matter().dev_det().max_paths_per_invoke as usize;

        if let Some(reqs) = req.inv_requests()? {
            let mut count = 0;
            for r in &reqs {
                let _ = r?;
                count += 1;
            }

            if count > max_paths {
                return Self::send_status(exchange, IMStatusCode::InvalidAction).await;
            }

            // Per Matter Core spec: when an `InvokeRequestMessage`
            // carries multiple `CommandDataIB` entries, each MUST include a unique
            // `CommandRef` and the request paths SHALL be unique. `count` is bounded
            // by `max_paths_per_invoke` (typically a single-digit number), so the
            // O(n²) pairwise check below is cheaper than allocating buffers.
            if count > 1 {
                for (i, req_i) in reqs.iter().enumerate() {
                    let req_i = req_i?;
                    if req_i.command_ref.is_none() {
                        return Self::send_status(exchange, IMStatusCode::InvalidAction).await;
                    }
                    for req_j in reqs.iter().skip(i + 1) {
                        let req_j = req_j?;
                        if req_i.path == req_j.path || req_i.command_ref == req_j.command_ref {
                            return Self::send_status(exchange, IMStatusCode::InvalidAction).await;
                        }
                    }
                }
            }
        }

        let mut wb = WriteBuf::new(&mut tx);

        let mut resp = InvokeResponder::new(&req, HandlerInvoker::new(exchange, self));

        resp.respond(&mut wb, &self.handler, is_groupcast).await
    }

    /// Respond to a `SubscribeReq` request by priming the subscription (i.e. doing an initial data report)
    /// and if the priming is successful, sending a `SubscribeResp` response to the peer and registering
    /// the subscription details in the `Subscriptions` instance.
    async fn subscribe(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let Some((mut tx, rx)) = self.buffers(exchange).await? else {
            return Ok(());
        };

        let req = SubscribeReq::new(TLVElement::new(&rx));
        debug!("IM: Subscribe request: {:?}", req);

        let accessor = exchange.accessor()?;

        if let Err(err) = self.validate_subscribe(&req, &accessor) {
            error!("Invalid subscribe request: {:?}", err);
            return Self::send_status(exchange, err.code().into()).await;
        }

        let (fab_idx, peer_node_id) = exchange.with_state(|state| {
            let sess = exchange.id().session(&mut state.sessions);

            let fab_idx = NonZeroU8::new(sess.get_local_fabric_idx()).ok_or(ErrorCode::Invalid)?;
            let peer_node_id = sess.get_peer_node_id().ok_or(ErrorCode::Invalid)?;

            Ok((fab_idx, peer_node_id))
        })?;

        if !req.keep_subs()? {
            self.state
                .subscriptions
                .remove(&self.subscriptions_buffers, |sub| {
                    (sub.ids().fab_idx == fab_idx && sub.ids().peer_node_id == peer_node_id)
                        .then_some("new subscription request")
                });
        }

        let max_int_secs = core::cmp::max(req.max_int_ceil()?, 40); // Say we need at least 4 secs for potential latencies
        let min_int_secs = req.min_int_floor()?;

        let now = Instant::now();

        let Some(mut rctx) = self.state.subscriptions.add(
            now,
            fab_idx,
            peer_node_id,
            exchange.id().session_id(),
            min_int_secs,
            max_int_secs,
            self.state.events.watermark(),
            rx,
            &self.subscriptions_buffers,
        ) else {
            return Self::send_status(exchange, IMStatusCode::ResourceExhausted).await;
        };

        let primed = self.report_data(&mut rctx, &mut tx, exchange, true).await?;

        if primed {
            exchange
                .send_with(|_, wb| {
                    SubscribeResp::write(wb, rctx.subscription().ids().id, max_int_secs)?;
                    Ok(Some(OpCode::SubscribeResponse.into()))
                })
                .await?;

            rctx.set_keep();

            info!("Subscription {:?} primed", rctx.subscription().ids());

            // Commit the subscription into the table now (its `report_complete`
            // runs on `Drop`) and then wake the reporter so it can account for
            // the new subscription's deadline.
            drop(rctx);
            self.state.subscriptions.notification.notify();
        }

        Ok(())
    }

    /// Validates the subscription request
    fn validate_subscribe(
        &self,
        req: &SubscribeReq<'_>,
        accessor: &Accessor<'_>,
    ) -> Result<(), Error> {
        // As per spec, we need to validate that the subscription request
        // contains existing endpoints, clusters and attributes, and if not
        // we should (a bit surprisingly) return InvalidAction

        self.handler.access(|node| {
            let mut has_attrs = false;
            let mut has_events = false;

            if let Some(attr_requests) = req.attr_requests()? {
                has_attrs = true;

                for attr_req in attr_requests {
                    let path = attr_req?;

                    if path.is_wildcard() {
                        Self::validate_attr_wildcard_path(&path)?;

                        if !node.has_accessible_attr(&path, accessor) {
                            return Err(ErrorCode::InvalidAction.into());
                        }
                    } else {
                        node.validate_attr_path(&path, false, false, accessor)
                            .map_err(|_| ErrorCode::InvalidAction)?;
                    }
                }
            }

            if let Some(event_reqs) = req.event_requests()? {
                has_events = true;

                for event_req in event_reqs {
                    let path = event_req?;

                    if !path.is_wildcard() {
                        node.validate_event_path(&path, accessor)
                            .map_err(|_| ErrorCode::InvalidAction)?;
                    }
                }
            }

            if !has_attrs && !has_events {
                // Empty subscribe requests are not allowed either
                return Err(ErrorCode::InvalidAction.into());
            }

            Ok(())
        })
    }

    /// Process all valid subscriptions in an endless loop, checking for changes
    /// and reporting them to the peers.
    async fn process_subscriptions(&self, matter: &Matter<'_>) -> Result<(), Error> {
        loop {
            // Sleep until the soonest subscription deadline: the end of a
            // `min_int` quiet period for a subscription holding back a change,
            // or the chosen liveness wake point. A change, event, removal, a torn
            // down session, or a newly accepted subscription (the accept path
            // notifies) all wake the loop early. With no subscription there is
            // no deadline, so just wait to be notified.
            let mut notification = pin!(self.state.subscriptions.notification.wait());
            let mut session_removed = pin!(matter.transport().wait_session_removed());

            // With no subscription (or none primed) the deadline is `Instant::MAX`,
            // so the timer effectively never fires and the loop just waits to be
            // notified.
            let deadline = self
                .state
                .subscriptions
                .next_report_at(self.state.events.watermark(), &self.subscriptions_buffers);
            let mut timeout = pin!(Timer::at(deadline));

            select3(&mut notification, &mut timeout, &mut session_removed).await;

            let now = Instant::now();

            // First remove all expired or no-longer valid subscriptions

            loop {
                let removed_any =
                    self.state
                        .subscriptions
                        .remove(&self.subscriptions_buffers, |sub| {
                            if sub.is_expired(now) {
                                return Some("expired");
                            }

                            matter.with_state(|state| {
                                if state.fabrics.get(sub.ids().fab_idx).is_none() {
                                    return Some("fabric removed");
                                }

                                // The session the subscription was accepted on was
                                // torn down (eviction, explicit close, peer-side
                                // CASE re-handshake, ...). Per Matter spec
                                // subscriptions are scoped to the session they
                                // were established on, and the publisher can no
                                // longer route reports to the subscriber. Drop
                                // immediately rather than waiting for `max_int`
                                // to expire and time-out the send.
                                if state.sessions.get(sub.session_id()).is_none() {
                                    return Some("session removed");
                                }

                                None
                            })
                        });

                if !removed_any {
                    break;
                }
            }

            // Now report while there are subscriptions which are due for reporting

            let event_numbers_watermark = self.state.events.watermark();

            loop {
                let Some(mut rctx) = self.state.subscriptions.report(
                    now,
                    event_numbers_watermark,
                    &self.subscriptions_buffers,
                ) else {
                    break;
                };

                let result = self.process_subscription(matter, &mut rctx).await;

                match result {
                    Ok(true) => rctx.set_keep(),
                    Ok(false) => (),
                    Err(e) => error!(
                        "Error processing subscription {:?}: {:?}",
                        rctx.subscription().ids(),
                        e
                    ),
                }
            }

            // Periodically trim changed-attr entries that have been reported by every
            // subscription, so the table does not accumulate stale promoted wildcards.
            self.state.subscriptions.purge_reported_changes();
        }
    }

    /// Process one valid subscription, reporting the data to the peer.
    ///
    /// Arguments:
    /// - `matter` - a reference to the `Matter` instance
    /// - `fabric_idx` - the fabric index of the peer
    /// - `peer_node_id` - the node ID of the peer
    /// - `session_id` - the session ID of the peer, if any
    /// - `sub` - the received and saved data for the subscription, when the subscription was primed
    /// - `min_event_number` - the subscription's current event watermark; updated
    ///   in place as events are emitted so the caller can persist it
    /// - `ctx` - the report context for this subscription
    #[allow(clippy::too_many_arguments)]
    async fn process_subscription(
        &self,
        matter: &Matter<'_>,
        rctx: &mut ReportContext<'_, '_, B, NS>,
    ) -> Result<bool, Error> {
        let mut exchange =
            Exchange::initiate_for_session(matter, rctx.subscription().session_id())?;

        if let Some(mut tx) = self.buffers.get().await {
            // Always safe as `IMBuffer` is defined to be `MAX_EXCHANGE_RX_BUF_SIZE`, which is bigger than `MAX_EXCHANGE_TX_BUF_SIZE`
            unwrap!(tx.resize_default(MAX_EXCHANGE_TX_BUF_SIZE));

            let primed = self
                .report_data(rctx, &mut tx, &mut exchange, false)
                .await?;

            exchange.acknowledge().await?;

            Ok(primed)
        } else {
            error!(
                "No TX buffer available for processing subscription {:?}",
                rctx.subscription().ids(),
            );

            Ok(false)
        }
    }

    /// Process a `TimedReq` request, which is used to set a timeout for the following Write/Invoke request.
    async fn timed(&self, exchange: &mut Exchange<'_>) -> Result<Instant, Error> {
        let req = TimedReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;
        debug!("IM: Timed request: {:?}", req);

        let timeout_instant = req.timeout_instant();

        Self::send_status(exchange, IMStatusCode::Success).await?;

        Ok(timeout_instant)
    }

    /// A utility to check whether a timed request has timed out, and if so, send a timeout status response
    async fn timed_out(
        &self,
        exchange: &mut Exchange<'_>,
        timeout_instant: Option<Instant>,
        timed_req: bool,
    ) -> Result<bool, Error> {
        let status = {
            if timed_req != timeout_instant.is_some() {
                Some(IMStatusCode::TimedRequestMisMatch)
            } else if timeout_instant
                .map(|timeout_instant| Instant::now() > timeout_instant)
                .unwrap_or(false)
            {
                Some(IMStatusCode::Timeout)
            } else {
                None
            }
        };

        if let Some(status) = status {
            Self::send_status(exchange, status).await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// A utility to respond with a `ReportData` response to a subscription request, which is used to report data to the peer.
    ///
    /// Arguments:
    /// - `id` - the subscription ID
    /// - `fabric_idx` - the fabric index of the peer
    /// - `peer_node_id` - the node ID of the peer
    /// - `min_event_number` - the minimum event number to report
    /// - `rx` - the received data for the subscription, when the subscription was primed
    /// - `tx` - the TX buffer to write the response to
    /// - `exchange` - the exchange to respond to
    /// - `with_dataver` - whether to include the data version in the response
    #[allow(clippy::too_many_arguments)]
    async fn report_data(
        &self,
        rctx: &mut ReportContext<'_, '_, B, NS>,
        tx: &mut [u8],
        exchange: &mut Exchange<'_>,
        with_dataver: bool,
    ) -> Result<bool, Error>
    where
        T: DataModel,
    {
        let mut wb = WriteBuf::new(tx);

        let sub_req = SubscribeReq::new(TLVElement::new(rctx.rx()));
        let req = if with_dataver {
            ReportDataReq::Subscribe(&sub_req)
        } else {
            ReportDataReq::SubscribeReport(&sub_req)
        };

        // Honor the `fabricFiltered` flag on the originating Subscribe request.
        // When set, fabric-sensitive events emitted on other fabrics are
        // dropped before they reach the wire (Matter Core spec).
        let fabric_filtered = req.fabric_filtered().unwrap_or(true);

        let mut resp = ReportDataResponder::new(
            &req,
            Some(rctx.subscription().ids().id),
            HandlerInvoker::new(exchange, self),
            EventReader::new(
                rctx.max_seen_event_number(),
                rctx.next_max_seen_event_number(),
                fabric_filtered,
            ),
            &self.state.events,
        );

        let sub_valid = resp
            .respond(
                &mut wb,
                false,
                rctx.should_send_if_empty(),
                &self.handler,
                |e, c, a| rctx.should_report_attr(e, c, a),
            )
            .await?;

        if !sub_valid {
            warn!(
                "Subscription {:?} removed during reporting",
                rctx.subscription().ids()
            );
        }

        Ok(sub_valid)
    }

    /// A utility to fetch a pair of TX/RX buffers for processing an Interaction Model request.
    ///
    /// If there are no free buffers available, this method will send a `Busy` status response to the peer.
    ///
    /// Upon returning:
    /// - The RX buffer will contain the payload of the received Interaction Model request
    /// - The TX buffer will be resized to `MAX_EXCHANGE_TX_BUF_SIZE` and will be ready to be written to
    ///
    /// Returns:
    /// - `Ok(Some((tx, rx)))` - if both TX and RX buffers are available
    /// - `Ok(None)` - if no buffers are available, and a `Busy` status response has been sent
    /// - `Err(Error)` - if an error occurred while fetching the buffers or sending the status response
    async fn buffers(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> Result<Option<(B::Buffer<'a>, B::Buffer<'a>)>, Error> {
        if let Some(tx) = self.tx_buffer(exchange).await? {
            if let Some(rx) = self.rx_buffer(exchange).await? {
                return Ok(Some((tx, rx)));
            }
        }

        Ok(None)
    }

    /// A utility to fetch a RX buffer for processing an Interaction Model request.
    ///
    /// If there are no free buffers available, this method will send a `Busy` status response to the peer.
    ///
    /// Upon returning, the RX buffer will contain the payload of the received Interaction Model request.
    ///
    /// Returns:
    /// - `Ok(Some(rx))` - if a RX buffer is available
    /// - `Ok(None)` - if no RX buffer is available, and a `Busy` status response has been sent
    /// - `Err(Error)` - if an error occurred while fetching the buffer or sending the status response
    async fn rx_buffer(&self, exchange: &mut Exchange<'_>) -> Result<Option<B::Buffer<'a>>, Error> {
        if let Some(mut buffer) = self.buffer(exchange).await? {
            let rx = exchange.rx()?;

            buffer.clear();

            // Safe to unwrap, as `IMBuffer` is defined to be `MAX_EXCHANGE_RX_BUF_SIZE`, i.e. it cannot be overflown
            // by the payload of the received exchange.
            unwrap!(buffer.extend_from_slice(rx.payload()));

            exchange.rx_done()?;

            Ok(Some(buffer))
        } else {
            Ok(None)
        }
    }

    /// A utility to fetch a TX buffer for processing an Interaction Model request.
    ///
    /// If there are no free buffers available, this method will send a `Busy` status response to the peer.
    ///
    /// Upon returning, the TX buffer will be resized to `MAX_EXCHANGE_TX_BUF_SIZE` and will be ready to be written to.
    ///
    /// Returns:
    /// - `Ok(Some(tx))` - if a TX buffer is available
    /// - `Ok(None)` - if no TX buffer is available, and a `Busy` status response has been sent
    /// - `Err(Error)` - if an error occurred while fetching the buffer or sending the status response
    async fn tx_buffer(&self, exchange: &mut Exchange<'_>) -> Result<Option<B::Buffer<'a>>, Error> {
        if let Some(mut buffer) = self.buffer(exchange).await? {
            // Always safe as `IMBuffer` is defined to be `MAX_EXCHANGE_RX_BUF_SIZE`, which is bigger than `MAX_EXCHANGE_TX_BUF_SIZE`
            unwrap!(buffer.resize_default(MAX_EXCHANGE_TX_BUF_SIZE));

            Ok(Some(buffer))
        } else {
            Ok(None)
        }
    }

    /// A utility to fetch a buffer for processing an Interaction Model request.
    ///
    /// If there are no free buffers available, this method will send a `Busy` status response to the peer.
    ///
    /// Upon returning, the buffer will be UNINITIALIZED. I.e. it is up to the user to resize it appropriately
    /// if it is to be used for sending a response, or to fill it with data, if it is to be used for receiving data.
    ///
    /// Returns:
    /// - `Ok(Some(buffer))` - if a buffer is available
    /// - `Ok(None)` - if no buffer is available, and a `Busy` status response has been sent
    /// - `Err(Error)` - if an error occurred while fetching the buffer or sending the status response
    async fn buffer(&self, exchange: &mut Exchange<'_>) -> Result<Option<B::Buffer<'a>>, Error> {
        if let Some(buffer) = self.buffers.get().await {
            Ok(Some(buffer))
        } else {
            Self::send_status(exchange, IMStatusCode::Busy).await?;

            Ok(None)
        }
    }

    /// A utility to send a status response to the peer.
    async fn send_status(exchange: &mut Exchange<'_>, status: IMStatusCode) -> Result<(), Error> {
        exchange
            .send_with(|_, wb| {
                StatusResp::write(wb, status)?;

                Ok(Some(OpCode::StatusResponse.into()))
            })
            .await
    }
}

impl<C, B, T, K, N, NC, const NS: usize, const NE: usize> ExchangeHandler
    for InteractionModel<'_, C, B, T, K, N, NC, NS, NE>
where
    C: Crypto,
    B: Buffers<IMBuffer>,
    T: DataModel,
    K: KvBlobStoreAccess,
    N: Networks,
{
    async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        InteractionModel::handle(self, &mut exchange).await
    }
}

impl<C, B, T, K, N, NC, const NS: usize, const NE: usize> HandlerContext
    for InteractionModel<'_, C, B, T, K, N, NC, NS, NE>
where
    C: Crypto,
    B: Buffers<IMBuffer>,
    T: DataModel,
    K: KvBlobStoreAccess,
    N: Networks,
{
    fn matter(&self) -> &Matter<'_> {
        self.matter
    }

    fn crypto(&self) -> impl Crypto + '_ {
        &self.crypto
    }

    fn kv(&self) -> impl KvBlobStoreAccess + '_ {
        &self.kv
    }

    fn networks(&self) -> impl NetworksAccess + '_ {
        &self.state.networks
    }

    fn metadata(&self) -> impl Metadata + '_ {
        &self.handler
    }

    fn handler(&self) -> impl AsyncHandler + '_ {
        &self.handler
    }

    fn buffers(&self) -> impl Buffers<IMBuffer> + '_ {
        self.buffers
    }
}

impl<C, B, T, K, N, NC, const NS: usize, const NE: usize> AttrChangeNotifier
    for InteractionModel<'_, C, B, T, K, N, NC, NS, NE>
where
    C: Crypto,
    B: Buffers<IMBuffer>,
    T: DataModel,
    K: KvBlobStoreAccess,
    N: Networks,
{
    fn notify_attr_changed(&self, endpoint_id: EndptId, cluster_id: ClusterId, attr_id: AttrId) {
        self.handler.bump_dataver(MatchContextInstance::new(
            Some(endpoint_id),
            Some(cluster_id),
        ));
        self.state
            .subscriptions
            .notify_attr_changed(endpoint_id, cluster_id, attr_id);
    }

    fn notify_cluster_changed(&self, endpoint_id: EndptId, cluster_id: ClusterId) {
        self.handler.bump_dataver(MatchContextInstance::new(
            Some(endpoint_id),
            Some(cluster_id),
        ));
        self.state
            .subscriptions
            .notify_cluster_changed(endpoint_id, cluster_id);
    }

    fn notify_endpoint_changed(&self, endpoint_id: EndptId) {
        self.handler
            .bump_dataver(MatchContextInstance::new(Some(endpoint_id), None));
        self.state
            .subscriptions
            .notify_endpoint_changed(endpoint_id)
    }

    fn notify_all_changed(&self) {
        self.handler
            .bump_dataver(MatchContextInstance::new(None, None));
        self.state.subscriptions.notify_all_changed()
    }
}

impl<C, B, T, K, N, NC, const NS: usize, const NE: usize> EventEmitter
    for InteractionModel<'_, C, B, T, K, N, NC, NS, NE>
where
    C: Crypto,
    B: Buffers<IMBuffer>,
    T: DataModel,
    K: KvBlobStoreAccess,
    N: Networks,
{
    fn emit_event<F>(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        event_id: EventId,
        priority: EventPriority,
        f: F,
    ) -> Result<u64, Error>
    where
        F: FnOnce(EventTLVWrite<'_>) -> Result<(), Error>,
    {
        let event_number =
            self.state
                .events
                .push(endpoint_id, cluster_id, event_id, priority, &self.kv, f)?;

        self.state
            .subscriptions
            .notify_event_emitted(endpoint_id, cluster_id, event_id);

        Ok(event_number)
    }
}

pub enum RespondOutcome {
    Accepted,
    Rejected,
    Empty,
}

/// This type responds with a `ReportData` response to all of:
/// - A `ReadReq`
/// - A `SubscribeReq`
/// - A `SubscribeReportReq` (i.e. once a valid recorded subscription is detected as in a need to be reported on)
///
/// The responder handles chunking as needed. I.e. if reported data is too large to fit into a single
/// Matter message, it will send the data in multiple chunks (i.e. with multiple Matter messages), waiting for
/// a `Success` response from the peer after each chunk, and then continuing to send the next chunk until all data is sent.
struct ReportDataResponder<'a, 'b, 'c, const NE: usize, C> {
    req: &'a ReportDataReq<'a>,
    subscription_id: Option<u32>,
    invoker: HandlerInvoker<'b, 'c, C>,
    event_reader: EventReader,
    events: &'a Events<NE>,
}

impl<'a, 'b, 'c, const NE: usize, C> ReportDataResponder<'a, 'b, 'c, NE, C>
where
    C: HandlerContext,
{
    // This is the amount of space we reserve for the structure/array closing TLVs
    // to be attached towards the end of long reads
    const LONG_READS_TLV_RESERVE_SIZE: usize = 24;

    /// Create a new `ReportDataResponder`.
    const fn new(
        req: &'a ReportDataReq<'a>,
        subscription_id: Option<u32>,
        invoker: HandlerInvoker<'b, 'c, C>,
        event_reader: EventReader,
        events: &'a Events<NE>,
    ) -> Self {
        Self {
            req,
            subscription_id,
            invoker,
            event_reader,
            events,
        }
    }

    /// Respond to the request with a `ReportData` response, possibly with more than one
    /// chunk if the data is too large to fit into a single Matter message.
    ///
    /// Arguments:
    /// - `wb` - the buffer to use while sending the response
    /// - `suppress_last_resp` - whether to suppress the response from the peer. When multiple Matter messages are
    ///   being sent due to chunking, this is valid for the last chunk only, as the others - by necessity need to have a
    ///   status response by the other peer
    async fn respond<M, F>(
        &mut self,
        wb: &mut WriteBuf<'_>,
        suppress_last_resp: bool,
        send_if_empty: bool,
        metadata: M,
        mut filter: F,
    ) -> Result<bool, Error>
    where
        M: Metadata,
        F: FnMut(EndptId, ClusterId, u32) -> bool,
    {
        let mut empty = true;

        self.start_reply(wb)?;

        if !self
            .report_attributes(wb, &mut empty, &metadata, &mut filter)
            .await?
        {
            return Ok(false);
        }

        if !self.report_events(wb, &mut empty, &metadata).await? {
            return Ok(false);
        }

        if send_if_empty || !empty {
            self.send(ReportDataChunkState::Done, suppress_last_resp, wb)
                .await
        } else {
            debug!("No data to report, skipping sending ReportData response");

            Ok(true)
        }
    }

    async fn report_attributes<M, F>(
        &mut self,
        wb: &mut WriteBuf<'_>,
        empty: &mut bool,
        metadata: M,
        mut filter: F,
    ) -> Result<bool, Error>
    where
        M: Metadata,
        F: FnMut(EndptId, ClusterId, u32) -> bool,
    {
        let accessor = self.invoker.exchange().accessor()?;

        if self.req.attr_requests()?.is_some() {
            wb.start_array(&TLVTag::Context(ReportDataRespTag::AttributeReports as u8))?;

            for item in expand_read(&metadata, self.req, &accessor, &mut filter)? {
                let item = item?;

                *empty = false;

                loop {
                    let result = self.invoker.process_read(&item, &mut *wb).await;

                    match result {
                        Ok(()) => break,
                        Err(err) if err.code() == ErrorCode::NoSpace => {
                            let array_attr = item.as_ref().ok().filter(|attr| {
                                attr.list_index.is_none()
                                    // The whole attribute is requested
                                    // Check if it is an array, and if so, send it as individual items instead
                                    && attr.array
                            });

                            if let Some(array_attr) = array_attr {
                                if self.send_array_items(array_attr, wb).await? {
                                    break;
                                } else {
                                    return Ok(false);
                                }
                            } else {
                                debug!("<<< No TX space, chunking >>>");
                                if !self
                                    .send(ReportDataChunkState::ChunkingAttributes, false, wb)
                                    .await?
                                {
                                    return Ok(false);
                                }
                            }
                        }
                        Err(err) => Err(err)?,
                    }
                }
            }

            wb.end_container()?;
        }

        Ok(true)
    }

    async fn report_events<M>(
        &mut self,
        wb: &mut WriteBuf<'_>,
        empty: &mut bool,
        metadata: M,
    ) -> Result<bool, Error>
    where
        M: Metadata,
    {
        let accessor = self.invoker.exchange().accessor()?;

        if let Some(event_reqs) = self.req.event_requests()? {
            wb.start_array(&TLVTag::Context(ReportDataRespTag::EventReports as _))?;

            // Validate concrete event paths against node metadata
            // and emit EventStatusIB for non-wildcard paths that don't match
            for event_req in event_reqs.iter() {
                let path = event_req?;

                if !path.is_wildcard() {
                    if let Err(status) =
                        metadata.access(|node| node.validate_event_path(&path, &accessor))
                    {
                        if matches!(status, IMStatusCode::UnsupportedEvent) {
                            // Event does not exist on this endpoint
                            // TODO: Look at TestEventsById.yaml
                            // Seems we should not error out in that case?
                            continue;
                        }

                        *empty = false;

                        let resp = EventResp::Status(EventStatus::new(path, status, None));

                        let mut result = resp.to_tlv(&TLVTag::Anonymous, &mut *wb);

                        if let Err(e) = &result {
                            if e.code() == ErrorCode::NoSpace {
                                debug!("<<< No TX space, chunking >>>");
                                if !self
                                    .send(ReportDataChunkState::ChunkingEvents, false, &mut *wb)
                                    .await?
                                {
                                    return Ok(false);
                                }

                                result = resp.to_tlv(&TLVTag::Anonymous, &mut *wb);
                            }
                        }

                        result?;
                    }
                }
            }

            let event_filters = self.req.event_filters()?;

            loop {
                let finished = self.events.fetch(|events| {
                    metadata.access(|node| {
                        for event in events {
                            let result = self.event_reader.process_read(
                                event,
                                &event_reqs,
                                &event_filters,
                                node,
                                &accessor,
                                &mut *wb,
                            );

                            if let Err(e) = &result {
                                if e.code() == ErrorCode::NoSpace {
                                    return Ok::<_, Error>(false);
                                }
                            }

                            if result? {
                                *empty = false;
                            }
                        }

                        Ok(true)
                    })
                })?;

                if finished {
                    break;
                }

                debug!("<<< No TX space, chunking >>>");
                if !self
                    .send(ReportDataChunkState::ChunkingEvents, false, wb)
                    .await?
                {
                    return Ok(false);
                }
            }

            wb.end_container()?;
        }

        Ok(true)
    }

    /// Send the items of an array attribute one by one, until the end of the array is reached.
    ///
    /// The data is potentially sent in multiple chunks if it cannot fit into a single Matter message.
    ///
    /// Arguments:
    /// - `attr` - the array attribute to send the items of
    /// - `wb` - the buffer to use while sending the items
    async fn send_array_items(
        &mut self,
        attr: &AttrDetails,
        wb: &mut WriteBuf<'_>,
    ) -> Result<bool, Error> {
        let mut attr = attr.clone();

        // First generate an empty array
        let mut list_index = None;
        attr.list_chunked = true;
        attr.list_index = Some(Nullable::new(list_index));

        loop {
            let pos = wb.get_tail();

            let result = self.invoker.read(&attr, &mut *wb).await;

            if result.is_err() {
                // If we got an error, we rewind to the position before the read
                // and handle it accordingly
                wb.rewind_to(pos);
            }

            match result {
                Ok(()) => {
                    // The empty array payload was sent
                    // Now iterate over the array and send each item one by one as separate payload

                    let new_list_index = if let Some(list_index) = list_index {
                        list_index + 1
                    } else {
                        0
                    };

                    list_index = Some(new_list_index);
                    attr.list_index = Some(Nullable::some(new_list_index));
                }
                Err(err) if err.code() == ErrorCode::NoSpace => {
                    debug!("<<< No TX space, chunking >>>");
                    if !self
                        .send(ReportDataChunkState::ChunkingAttributes, false, wb)
                        .await?
                    {
                        return Ok(false);
                    }
                }
                Err(err) if err.code() == ErrorCode::ConstraintError => break, // Got to the end of the array
                Err(err) => Err(err)?,
            }
        }

        Ok(true)
    }

    /// Send the reply to the peer, potentially opening another reply.
    ///
    /// Arguments:
    /// - `state`: tracks chunking state - are we just sending a chunk packet or are we done and wrapping up?
    /// - `suppress_last_resp`: whether to suppress the response from the peer, this is ignored if state is != Done
    /// - `wb`: the buffer containing the reply. Once the reply is sent, the buffer is re-initialized for a new reply if `more_chunks` is `true`
    async fn send(
        &mut self,
        state: ReportDataChunkState,
        suppress_last_resp: bool,
        wb: &mut WriteBuf<'_>,
    ) -> Result<bool, Error> {
        self.end_reply(state, suppress_last_resp, wb)?;

        self.invoker
            .exchange()
            .send(OpCode::ReportData, wb.as_slice())
            .await?;

        let cont = match state {
            ReportDataChunkState::ChunkingAttributes => {
                let cont = self.recv_status_success().await?;
                self.start_reply(wb)?;
                wb.start_array(&TLVTag::Context(ReportDataRespTag::AttributeReports as u8))?;
                cont
            }
            ReportDataChunkState::ChunkingEvents => {
                let cont = self.recv_status_success().await?;
                self.start_reply(wb)?;
                wb.start_array(&TLVTag::Context(ReportDataRespTag::EventReports as u8))?;
                cont
            }
            ReportDataChunkState::Done => {
                if !suppress_last_resp {
                    self.recv_status_success().await?
                } else {
                    false
                }
            }
        };

        Ok(cont)
    }

    /// Receive a status response from the peer
    ///
    /// If the response is not a status response, the method will fail with an `Invalid` error.
    ///
    /// Return `Ok(true)` if the response is a success response, `Ok(false)` if the response is not a success response.
    async fn recv_status_success(&mut self) -> Result<bool, Error> {
        let rx = self.invoker.exchange().recv().await?;
        let opcode = rx.meta().proto_opcode;

        if opcode != OpCode::StatusResponse as u8 {
            warn!(
                "Got opcode {:02x}, while expecting status code {:02x}",
                opcode,
                OpCode::StatusResponse as u8
            );

            return Err(ErrorCode::Invalid.into());
        }

        let resp = StatusResp::from_tlv(&get_root_node_struct(rx.payload())?)?;

        if resp.status == IMStatusCode::Success {
            Ok(true)
        } else {
            warn!(
                "Got status response {:?}, aborting interaction",
                resp.status
            );

            drop(rx);

            self.invoker.exchange().acknowledge().await?;

            Ok(false)
        }
    }

    /// Start a reply by initializing the `WriteBuf` and writing the initial TLVs.
    fn start_reply(&self, wb: &mut WriteBuf<'_>) -> Result<(), Error> {
        wb.reset();
        wb.shrink(Self::LONG_READS_TLV_RESERVE_SIZE)?;

        wb.start_struct(&TLVTag::Anonymous)?;

        if let Some(subscription_id) = self.subscription_id {
            assert!(matches!(
                self.req,
                ReportDataReq::Subscribe(_) | ReportDataReq::SubscribeReport(_)
            ));
            wb.u32(
                &TLVTag::Context(ReportDataRespTag::SubscriptionId as u8),
                subscription_id,
            )?;
        } else {
            assert!(matches!(self.req, ReportDataReq::Read(_)));
        }

        Ok(())
    }

    /// End a reply by writing the closing TLVs and potentially indicating that there are more chunks to send.
    fn end_reply(
        &self,
        state: ReportDataChunkState,
        suppress_resp: bool,
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        wb.expand(Self::LONG_READS_TLV_RESERVE_SIZE)?;

        match state {
            ReportDataChunkState::ChunkingAttributes | ReportDataChunkState::ChunkingEvents => {
                wb.end_container()?;
                wb.bool(
                    &TLVTag::Context(ReportDataRespTag::MoreChunkedMsgs as u8),
                    true,
                )?;
            }
            ReportDataChunkState::Done => {
                if suppress_resp {
                    wb.bool(
                        &TLVTag::Context(ReportDataRespTag::SupressResponse as u8),
                        true,
                    )?;
                }
            }
        };

        // InteractionModelRevision is mandatory in all IM messages from
        // Matter 1.0 onward (TLV tag 0xFF). matter.js validates this
        // strictly and refuses to commission devices that omit it; the
        // reference chip-tool happens to tolerate the absence.
        wb.u8(
            &TLVTag::Context(crate::im::encoding::IM_REVISION_TAG),
            IM_REVISION,
        )?;

        wb.end_container()?;

        Ok(())
    }
}

/// Used to avoid duplicating the chunking logic for events and attributes; they both
/// share the same write path when the current packet fills up, and use this to determine
/// which field they should be setting up an array in for more output in the next packet
#[derive(Clone, Copy)]
enum ReportDataChunkState {
    ChunkingAttributes,
    ChunkingEvents,
    Done,
}

/// This type responds to a `WriteReq` by invoking the
/// corresponding handlers for each write attribute in the request.
///
/// The responser assumes that all response data can fit in a single Matter message,
/// which is a fair assumption and as per the Matter spec, in that the response of a
/// write request is always shorter than the write request itself, so given that the
/// write request fits in a single Matter message, the write reponse should as well.
///
/// With that said, the write request might itself be just one out of many chunks that
/// the other peers is sending, but processing all of those chunks is not done here,
/// but is rather - a responsibility of the caller who should call in a loop `WriteResponder::respond`
/// for all the chunks of the write request, until the `WriteReq::more_chunks()` returns `false`.
struct WriteResponder<'a, 'b, 'c, C> {
    req: &'a WriteReq<'a>,
    invoker: HandlerInvoker<'b, 'c, C>,
}

impl<'a, 'b, 'c, C> WriteResponder<'a, 'b, 'c, C>
where
    C: HandlerContext,
{
    /// Create a new `WriteResponder`.
    const fn new(req: &'a WriteReq<'a>, invoker: HandlerInvoker<'b, 'c, C>) -> Self {
        Self { req, invoker }
    }

    /// Respond to the write request by processing each write attribute in the request
    /// and sending a response back.
    async fn respond<M>(
        &mut self,
        wb: &mut WriteBuf<'_>,
        metadata: M,
        suppress_resp: bool,
    ) -> Result<(), Error>
    where
        M: Metadata,
    {
        let accessor = self.invoker.exchange().accessor()?;

        wb.reset();

        wb.start_struct(&TLVTag::Anonymous)?;
        wb.start_array(&TLVTag::Context(WriteRespTag::WriteResponses as u8))?;

        for item in expand_write(metadata, self.req, &accessor)? {
            self.invoker.process_write(&item?, &mut *wb).await?;
        }

        if suppress_resp {
            return Ok(());
        }

        wb.end_container()?;
        // Mandatory `interactionModelRevision` (tag 0xFF); see note in
        // the ReportData emitter above.
        wb.u8(
            &TLVTag::Context(crate::im::encoding::IM_REVISION_TAG),
            IM_REVISION,
        )?;
        wb.end_container()?;

        self.invoker
            .exchange()
            .send(OpCode::WriteResponse, wb.as_slice())
            .await
    }
}

/// This type responds to an `InvRequest` by invoking the
/// corresponding handlers for each command in the invoke request.
///
/// NOTE: In future, this responder should support chunking in that
/// if the reply to all the commands in the invoke request is too large to fit
/// into a single Matter message, it should send the response in multiple chunks.
///
/// The simplest strategy for chunking would be to simply - and unconditionally - send each individual
/// command response in a separate Matter message, i.e. if the invoke request contains 3 commands,
/// the responder will send 3 Matter messages, each containing a single command response.
struct InvokeResponder<'a, 'b, 'c, C> {
    req: &'a InvReq<'a>,
    invoker: HandlerInvoker<'b, 'c, C>,
}

impl<'a, 'b, 'c, C> InvokeResponder<'a, 'b, 'c, C>
where
    C: HandlerContext,
{
    /// Create a new `InvokeResponder`.
    const fn new(req: &'a InvReq<'a>, invoker: HandlerInvoker<'b, 'c, C>) -> Self {
        Self { req, invoker }
    }

    /// Respond to the invoke request by processing each command in the request
    /// and sending one or more reponses back.
    async fn respond<M>(
        &mut self,
        wb: &mut WriteBuf<'_>,
        metadata: M,
        suppress_resp: bool,
    ) -> Result<(), Error>
    where
        M: Metadata,
    {
        wb.reset();

        wb.start_struct(&TLVTag::Anonymous)?;

        // Suppress Response -> TODO: Need to revisit this for cases where we send a command back
        wb.bool(
            &TLVTag::Context(InvRespTag::SupressResponse as u8),
            suppress_resp,
        )?;

        let has_requests = self.req.inv_requests()?.is_some();

        if has_requests {
            wb.start_array(&TLVTag::Context(InvRespTag::InvokeResponses as u8))?;
        }

        let accessor = self.invoker.exchange().accessor()?;

        for item in expand_invoke(metadata, self.req, &accessor)? {
            self.invoker.process_invoke(&item?, &mut *wb).await?;
        }

        if suppress_resp {
            return Ok(());
        }

        if has_requests {
            wb.end_container()?;
        }

        // Mandatory `interactionModelRevision` (tag 0xFF) at the end of
        // every IM message — see the matching note in the ReportData
        // emitter above.
        wb.u8(
            &TLVTag::Context(crate::im::encoding::IM_REVISION_TAG),
            IM_REVISION,
        )?;
        wb.end_container()?;

        self.invoker
            .exchange()
            .send(OpCode::InvokeResponse, wb.as_slice())
            .await?;

        Ok(())
    }
}
