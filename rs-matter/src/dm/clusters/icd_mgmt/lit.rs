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

//! The Long Idle Time (LIT) layer of an ICD: the client registrations, the
//! Check-In counter and sender, and the ICD Management cluster serving them.

use core::num::NonZeroU8;
use core::pin::pin;

use embassy_futures::select::{select, Either};
use embassy_time::{with_timeout, Duration};

use crate::acl::AccessReq;
use crate::crypto::{CanonAeadKey, Crypto, Rng};
use crate::dm::endpoints::ROOT_ENDPOINT_ID;
use crate::dm::{
    Access, ArrayAttributeRead, Cluster, Dataver, HandlerContext, InvokeContext, LifecycleOp,
    ReadContext,
};
use crate::error::{Error, ErrorCode};
use crate::fabric::MAX_FABRICS;
use crate::im::encoding::GenericPath;
use crate::im::ImStats;
use crate::persist::{
    KvBlobStore, KvBlobStoreAccess, Persist, ICD_CHECK_IN_COUNTER_KEY, ICD_REGISTERED_CLIENTS_KEY,
};
use crate::sc::checkin::{CheckIn, CheckInCounter};
use crate::tlv::{FromTLV, TLVBuilderParent, TLVElement, ToTLV};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;
use crate::with;
use crate::Matter;

use super::*;

/// The maximum number of clients that can register per fabric — the value
/// reported by the cluster's `ClientsSupportedPerFabric` attribute.
///
/// The spec floor is 1; two (matching CHIP's default) covers a fabric whose
/// ecosystem monitors the device from more than one client. Raise it if a
/// fabric needs still more independent Check-In clients.
pub const CLIENTS_PER_FABRIC: usize = 2;

/// The total capacity of the registration store, across all fabrics.
pub const MAX_REGISTERED_CLIENTS: usize = CLIENTS_PER_FABRIC * MAX_FABRICS;

/// How long one Check-In send (mDNS resolution included) may take before it is
/// abandoned, so that a client that cannot be resolved does not keep the device
/// awake.
const CHECK_IN_TIMEOUT: Duration = Duration::from_secs(5);

/// The buffer for one Check-In message: nonce + counter + MIC plus the
/// 2-byte `ActiveModeThreshold` application data, rounded up.
const CHECK_IN_BUF_LEN: usize = 64;

/// A single client registration (one entry of the `RegisteredClients` list).
///
/// Fabric-scoped: an entry belongs to the fabric it was registered on and is
/// only ever matched, replaced or removed within that fabric.
#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MonitoringRegistration {
    /// The fabric this registration belongs to.
    pub fab_idx: NonZeroU8,
    /// The node to which Check-In messages are sent.
    pub check_in_node_id: u64,
    /// The subject whose active subscription suppresses Check-Ins for this entry.
    pub monitored_subject: u64,
    /// The client's type (permanent or ephemeral).
    pub client_type: ClientTypeEnum,
    /// The shared symmetric key used to encrypt this client's Check-In messages.
    ///
    /// Write-only from the outside: it is provided at registration and used to
    /// build Check-In messages, but never read back as an attribute.
    pub key: CanonAeadKey,
}

/// The outcome of checking a presented verification key against a stored
/// registration, used to gate non-administrator register/unregister requests.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyVerdict {
    /// No registration exists for the given `(fabric, node)`.
    NotFound,
    /// A registration exists and the presented key matches its stored key.
    Match,
    /// A registration exists but the presented key is absent or does not match.
    Mismatch,
}

/// The interior, mutable LIT state guarded by a single lock: the
/// registrations, the Check-In counter and what the operating mode follows.
struct LitState {
    /// The registered Check-In clients (persisted).
    clients: Vec<MonitoringRegistration, MAX_REGISTERED_CLIENTS>,
    /// The Check-In counter.
    counter: CheckInCounter,
    /// Whether the application requires SIT operation even with registered
    /// clients (the Dynamic SIT/LIT feature).
    sit_required: bool,
}

impl LitState {
    const fn new(counter: CheckInCounter) -> Self {
        Self {
            clients: Vec::new(),
            counter,
            sit_required: false,
        }
    }

    fn init(counter: CheckInCounter) -> impl Init<Self> {
        init!(Self {
            clients <- Vec::init(),
            counter: counter,
            sit_required: false,
        })
    }

    /// A LIT-capable ICD operates as a LIT once a client has registered with
    /// it - unless the application requires SIT operation.
    fn operating_mode(&self) -> OperatingModeEnum {
        if self.clients.is_empty() || self.sit_required {
            OperatingModeEnum::SIT
        } else {
            OperatingModeEnum::LIT
        }
    }
}

/// A Long Idle Time (LIT) capable ICD: the power mode state machine ([`Icd`])
/// plus the client registrations, the Check-In counter and the Check-In
/// sender.
///
/// It operates as a SIT until a client registers for Check-Ins with it, and as
/// a LIT from then on - as the spec requires ("A commissioned LIT ICD SHALL
/// operate as a SIT ICD if it doesn't have at least one registration") - or
/// as a SIT for as long as the application requires it
/// ([`set_sit_required`](Self::set_sit_required)).
///
/// The application owns one instance and lends it to its
/// [`LitIcdMgmtHandler`]; its network driver and its sleep logic follow the
/// power mode state machine, [`icd`](Self::icd).
pub struct LitIcd {
    icd: Icd,
    state: Mutex<RefCell<LitState>>,
    /// Signalled whenever the operating mode changed.
    /// Single waiter: the handler's `run` hook, which re-advertises it.
    mode_changed: Notification,
}

impl LitIcd {
    /// Create the LIT state from the Check-In counter's persistence epoch, the
    /// mode timings and the slow polling interval to use while operating as a
    /// SIT.
    ///
    /// `epoch` is how far ahead of the live counter the persisted boundary is
    /// kept - i.e. how many Check-Ins may be sent between two flash writes, and
    /// equally how far the counter jumps forward across a restart. It must be
    /// non-zero.
    ///
    /// `sit_slow_poll_ms` is the slow polling interval while operating as a
    /// SIT, whenever the configured one (`BasicInfoConfig::sii`, the LIT idle
    /// interval) is longer; also the `SII` the device then advertises. Until a
    /// client registers, somebody is typically waiting to reach the device: the
    /// commissioner about to register, or a controller that does not know about
    /// LIT at all. Polling faster here costs little and makes the device
    /// correspondingly quicker to reach. In range `1..=`[`SIT_SLOW_POLL_MAX_MS`],
    /// the most a SIT may go unreachable for.
    ///
    /// # Panics
    ///
    /// Panics if `epoch` is zero, or if `sit_slow_poll_ms` is zero or exceeds
    /// [`SIT_SLOW_POLL_MAX_MS`].
    pub const fn new(epoch: u32, mode: IcdModeConfig, sit_slow_poll_ms: u32) -> Self {
        Self {
            icd: Icd::with_sit_slow_poll(mode, sit_slow_poll_ms),
            state: Mutex::new(RefCell::new(LitState::new(CheckInCounter::new(0, epoch)))),
            mode_changed: Notification::new(),
        }
    }

    /// An in-place initializer, mirroring [`Self::new`]. Prefer this over `new`
    /// to avoid the registration array transiting the stack.
    ///
    /// # Panics
    ///
    /// Panics if `epoch` is zero, or if `sit_slow_poll_ms` is zero or exceeds
    /// [`SIT_SLOW_POLL_MAX_MS`].
    pub fn init(epoch: u32, mode: IcdModeConfig, sit_slow_poll_ms: u32) -> impl Init<Self> {
        init!(Self {
            icd <- Icd::init_with_sit_slow_poll(mode, sit_slow_poll_ms),
            state <- Mutex::init(RefCell::init(LitState::init(CheckInCounter::new(0, epoch)))),
            mode_changed <- Notification::init(),
        })
    }

    /// The power mode state machine, for the network driver and the
    /// application's sleep logic to follow.
    pub const fn icd(&self) -> &Icd {
        &self.icd
    }

    /// Require SIT operation even while clients are registered, or lift that
    /// requirement.
    ///
    /// This is the Dynamic SIT/LIT feature - e.g. a device that stays
    /// responsive as a SIT while it is line-powered, and saves its battery as a
    /// LIT otherwise. A device using it must claim the feature, i.e. serve
    /// [`LitIcdMgmtHandler::CLUSTER_DSLS`].
    pub fn set_sit_required(&self, required: bool) {
        self.update(|s| s.sit_required = required);
    }

    /// Mutate the LIT state, and have the operating mode follow it.
    fn update<R>(&self, f: impl FnOnce(&mut LitState) -> R) -> R {
        let (result, mode) = self.state.lock(|s| {
            let mut s = s.borrow_mut();

            let result = f(&mut s);

            (result, s.operating_mode())
        });

        if mode != self.icd.operating_mode() {
            self.icd.set_operating_mode(mode);
            self.mode_changed.notify();
        }

        result
    }

    /// Re-seed the Check-In counter from `start`, keeping the epoch this
    /// `LitIcd` was constructed with, and return the boundary that must be
    /// persisted.
    fn reseed_counter(&self, start: u32) -> u32 {
        self.state.lock(|s| {
            let mut s = s.borrow_mut();

            let epoch = s.counter.epoch();
            s.counter = CheckInCounter::new(start, epoch);

            s.counter.persist_value()
        })
    }

    /// Draw a fresh random Check-In counter start.
    fn random_counter_start<C: Crypto>(crypto: C) -> Result<u32, Error> {
        let mut bytes = [0; 4];
        crypto.rand()?.fill_bytes(&mut bytes);

        Ok(u32::from_le_bytes(bytes))
    }

    // --- Registrations ---

    /// The total number of registrations across all fabrics.
    #[cfg(test)]
    fn registrations_len(&self) -> usize {
        self.state.lock(|s| s.borrow().clients.len())
    }

    /// The number of registrations on `fab_idx`.
    #[cfg(test)]
    fn fabric_registrations_len(&self, fab_idx: NonZeroU8) -> usize {
        self.state.lock(|s| {
            s.borrow()
                .clients
                .iter()
                .filter(|c| c.fab_idx == fab_idx)
                .count()
        })
    }

    /// Register a client, or update the existing registration with the same
    /// `(fab_idx, check_in_node_id)`.
    ///
    /// Returns `Err(ResourceExhausted)` if a *new* entry would exceed the
    /// per-fabric limit ([`CLIENTS_PER_FABRIC`]).
    fn register(&self, registration: MonitoringRegistration) -> Result<(), Error> {
        self.update(|s| {
            let clients = &mut s.clients;

            if let Some(existing) = clients.iter_mut().find(|c| {
                c.fab_idx == registration.fab_idx
                    && c.check_in_node_id == registration.check_in_node_id
            }) {
                *existing = registration;
            } else {
                if clients
                    .iter()
                    .filter(|c| c.fab_idx == registration.fab_idx)
                    .count()
                    >= CLIENTS_PER_FABRIC
                {
                    Err(ErrorCode::ResourceExhausted)?;
                }

                clients
                    .push(registration)
                    .map_err(|_| ErrorCode::ResourceExhausted)?;
            }

            Ok(())
        })
    }

    /// Remove the registration for `(fab_idx, check_in_node_id)`.
    ///
    /// Returns `Err(NotFound)` if there is no such registration.
    fn unregister(&self, fab_idx: NonZeroU8, check_in_node_id: u64) -> Result<(), Error> {
        let removed = self.update(|s| {
            let before = s.clients.len();
            s.clients
                .retain(|c| !(c.fab_idx == fab_idx && c.check_in_node_id == check_in_node_id));

            s.clients.len() != before
        });

        if !removed {
            Err(ErrorCode::NotFound)?;
        }

        Ok(())
    }

    /// Check a presented verification `key` against the stored registration for
    /// `(fab_idx, check_in_node_id)`.
    ///
    /// Non-administrator clients may only modify or remove an entry they own,
    /// proven by re-presenting the same key the entry was registered with. A
    /// missing or wrong key yields [`KeyVerdict::Mismatch`].
    fn verify_key(
        &self,
        fab_idx: NonZeroU8,
        check_in_node_id: u64,
        key: Option<&[u8]>,
    ) -> KeyVerdict {
        self.state.lock(|s| {
            let state = s.borrow();
            let Some(entry) = state
                .clients
                .iter()
                .find(|c| c.fab_idx == fab_idx && c.check_in_node_id == check_in_node_id)
            else {
                return KeyVerdict::NotFound;
            };

            match key {
                Some(key) if key == entry.key.access() => KeyVerdict::Match,
                _ => KeyVerdict::Mismatch,
            }
        })
    }

    /// Drop every registration belonging to `fab_idx`.
    ///
    /// Call when a fabric is removed. Returns whether anything was removed.
    fn remove_fabric(&self, fab_idx: NonZeroU8) -> bool {
        self.update(|s| {
            let before = s.clients.len();
            s.clients.retain(|c| c.fab_idx != fab_idx);

            s.clients.len() != before
        })
    }

    /// Run `f` with the registrations while the lock is held.
    ///
    /// The closure runs under the lock, so it must not re-enter the ICD state and
    /// must not `.await`.
    fn with_registrations<R>(&self, f: impl FnOnce(&[MonitoringRegistration]) -> R) -> R {
        self.state.lock(|s| f(&s.borrow().clients))
    }

    /// Persist the current registrations to `ctx.kv()`.
    fn store_registrations<C: HandlerContext>(&self, ctx: &C) -> Result<(), Error> {
        let mut persist = Persist::new(ctx.kv());

        self.state
            .lock(|s| persist.store_tlv(ICD_REGISTERED_CLIENTS_KEY, &s.borrow().clients))?;

        persist.run()
    }

    // --- Check-In counter ---

    /// The counter value the next Check-In message will use (a peek).
    fn next_counter(&self) -> u32 {
        self.state.lock(|s| s.borrow().counter.next())
    }

    /// Advance the Check-In counter after sending, persisting to `kv` when a new
    /// epoch boundary is crossed.
    ///
    /// Call once per Check-In *batch* (all messages in the batch used the same
    /// [`next_counter`](Self::next_counter) value).
    fn advance_counter<S: KvBlobStore>(&self, mut kv: S, buf: &mut [u8]) -> Result<(), Error> {
        let to_persist = self.state.lock(|s| s.borrow_mut().counter.advance());

        if let Some(value) = to_persist {
            kv.store(ICD_CHECK_IN_COUNTER_KEY, &value.to_le_bytes(), buf)?;
        }

        Ok(())
    }

    /// Jump the Check-In counter forward by `delta` (wrapping). Used to
    /// invalidate outstanding counter values in one step; the new value is
    /// visible immediately as the `ICDCounter` attribute.
    ///
    /// Returns `true` if the jump moved the persist boundary, in which case
    /// [`persist_counter`](Self::persist_counter) must run before the device
    /// restarts (defer it if the caller has no storage access here).
    #[must_use = "a moved boundary must be persisted via persist_counter"]
    pub fn invalidate_counter(&self, delta: u32) -> bool {
        self.state
            .lock(|s| s.borrow_mut().counter.advance_by(delta))
            .is_some()
    }

    /// Persist the current Check-In counter boundary to `kv`.
    pub fn persist_counter<S: KvBlobStore>(&self, mut kv: S, buf: &mut [u8]) -> Result<(), Error> {
        let value = self.state.lock(|s| s.borrow().counter.persist_value());
        kv.store(ICD_CHECK_IN_COUNTER_KEY, &value.to_le_bytes(), buf)
    }

    /// Re-hydrate the LIT state from `kv` - the registrations and the Check-In
    /// counter boundary.
    ///
    /// Driven by [`LifecycleOp::Startup`], before the data model starts
    /// serving operations and before any Check-In is sent.
    ///
    /// The counter's epoch comes from the counter the application supplied at
    /// construction, so the persisted blob only has to carry the boundary. The
    /// new boundary is written straight back: [`CheckInCounter::new`] resumes
    /// *at* the stored value, so the values this run may use (`start + 1 ..=
    /// start + epoch`) are only guaranteed unique once `start + epoch` is
    /// durable. A crash before the next boundary crossing would otherwise
    /// reload `start` and hand out the same values a second time.
    fn load_persist<S: KvBlobStore, C: Crypto>(
        &self,
        crypto: C,
        mut kv: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let clients = match kv.load(ICD_REGISTERED_CLIENTS_KEY, buf)? {
            Some(data) => Vec::from_tlv(&TLVElement::new(data))?,
            None => Vec::new(),
        };

        self.update(|s| s.clients = clients);

        let start = match kv.load(ICD_CHECK_IN_COUNTER_KEY, buf)? {
            Some(data) => u32::from_le_bytes(data.try_into().map_err(|_| ErrorCode::Invalid)?),
            // First boot (or a cleared store): start somewhere random rather
            // than at a fixed value every device shares.
            None => Self::random_counter_start(crypto)?,
        };

        let boundary = self.reseed_counter(start);

        kv.store(ICD_CHECK_IN_COUNTER_KEY, &boundary.to_le_bytes(), buf)
    }

    /// Reset the LIT state to factory defaults and remove both persisted blobs
    /// (the registrations and the Check-In counter boundary) from `kv`.
    ///
    /// Driven by [`LifecycleOp::FactoryReset`].
    ///
    /// The counter is re-seeded from a fresh random value, the same way a first
    /// boot seeds it - the device is starting a new life, and every key the old
    /// counter was used with is gone along with the registrations. The new
    /// value is left unpersisted: whichever comes first, the next boundary
    /// crossing or the next startup, writes one.
    fn reset_persist<S: KvBlobStore, C: Crypto>(
        &self,
        crypto: C,
        mut kv: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.update(|s| s.clients.clear());

        kv.remove(ICD_REGISTERED_CLIENTS_KEY, buf)?;
        kv.remove(ICD_CHECK_IN_COUNTER_KEY, buf)?;

        self.reseed_counter(Self::random_counter_start(crypto)?);

        Ok(())
    }

    // --- Sending Check-In messages ---

    /// Send a Check-In message to the registered client `(fab_idx, node_id)`,
    /// using the given counter value.
    ///
    /// A per-client convenience over [`CheckIn::send_to`]; it looks up the
    /// client's key and sends with the ICD application data (the
    /// `ActiveModeThreshold`). It does *not* advance the counter — the caller
    /// owns that so a batch can share one value.
    ///
    /// Requires a running mDNS responder to service the address resolve.
    async fn send_one_check_in<C: Crypto>(
        &self,
        matter: &Matter<'_>,
        crypto: C,
        fab_idx: NonZeroU8,
        node_id: u64,
        counter: u32,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        // Copy the key out under the lock, then send outside it (sending is
        // `async`; the lock is not held across the `await`).
        let key = self
            .state
            .lock(|s| {
                s.borrow()
                    .clients
                    .iter()
                    .find(|c| c.fab_idx == fab_idx && c.check_in_node_id == node_id)
                    .map(|c| c.key.clone())
            })
            .ok_or(ErrorCode::NotFound)?;

        let app_data = self.icd.mode.active_mode_threshold_ms.to_le_bytes();

        CheckIn::new(key.reference())
            .send_to(matter, crypto, fab_idx, node_id, counter, &app_data, buf)
            .await
    }
}

impl CheckIns for LitIcd {
    const LIT: bool = true;

    /// Send a Check-In to every registered client whose monitored subject has
    /// no live subscription, then advance (and, on an epoch boundary, persist)
    /// the Check-In counter.
    ///
    /// Best-effort per client, with a timeout per send so that an unresolvable
    /// client cannot keep the device awake; only a counter persistence failure
    /// is an error.
    async fn send_check_ins(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        let stats = ctx.im_stats();

        let mut targets: Vec<(NonZeroU8, u64), MAX_REGISTERED_CLIENTS> = Vec::new();

        self.with_registrations(|registrations| {
            for r in registrations {
                // A CAT-valued monitored subject won't match here (we compare
                // against subscriber node ids), so such a client is treated as
                // unsubscribed and always nudged.
                if stats.has_subscription_for(r.fab_idx, r.monitored_subject) {
                    continue;
                }

                // Capacity matches the registration store, so this cannot fail.
                let _ = targets.push((r.fab_idx, r.check_in_node_id));
            }
        });

        if targets.is_empty() {
            return Ok(());
        }

        let matter = ctx.matter();
        let crypto = ctx.crypto();
        let counter = self.next_counter();
        let mut buf = [0; CHECK_IN_BUF_LEN];

        for (fab_idx, node_id) in &targets {
            info!("ICD: Check-In to fabric {} node {:#x}", fab_idx, node_id);

            let send =
                self.send_one_check_in(matter, &crypto, *fab_idx, *node_id, counter, &mut buf);

            match with_timeout(CHECK_IN_TIMEOUT, send).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => warn!(
                    "ICD: Check-In to fabric {} node {:#x} failed: {:?}",
                    fab_idx, node_id, err
                ),
                Err(_) => warn!(
                    "ICD: Check-In to fabric {} node {:#x} timed out",
                    fab_idx, node_id
                ),
            }
        }

        // All messages of the batch shared `counter`; advance once.
        ctx.kv()
            .access(|store, kv_buf| self.advance_counter(store, kv_buf))
    }
}

/// The ICD Management cluster handler of a Long Idle Time (LIT) capable
/// device.
///
/// Backed by a [`LitIcd`]: the registration commands mutate its store, the ICD
/// Counter reported to clients comes from its counter, and its `run` hook
/// drives the power mode state machine, sends the Check-Ins and keeps the
/// operating mode advertised over DNS-SD.
///
/// Serves the Check-In Protocol, Long Idle Time and User Active Mode Trigger
/// features ([`CLUSTER`](ClusterHandler::CLUSTER)), and the Dynamic SIT/LIT
/// one on top with [`CLUSTER_DSLS`](Self::CLUSTER_DSLS).
pub struct LitIcdMgmtHandler<'a> {
    dataver: Dataver,
    lit: &'a LitIcd,
}

impl<'a> LitIcdMgmtHandler<'a> {
    /// The cluster metadata of a device that also claims the Dynamic SIT/LIT
    /// feature: one that may require SIT operation while clients are
    /// registered ([`LitIcd::set_sit_required`]).
    pub const CLUSTER_DSLS: Cluster<'static> = Self::cluster(
        Feature::CHECK_IN_PROTOCOL_SUPPORT
            .union(Feature::LONG_IDLE_TIME_SUPPORT)
            .union(Feature::USER_ACTIVE_MODE_TRIGGER)
            .union(Feature::DYNAMIC_SIT_LIT_SUPPORT),
    );

    /// The cluster metadata for `features`. CIP makes the registration
    /// attributes and commands and `MaximumCheckInBackoff` mandatory; LITS
    /// makes `OperatingMode` and `StayActiveRequest` mandatory; UAT makes
    /// `UserActiveModeTriggerHint` mandatory; DSLS adds only its feature bit.
    const fn cluster(features: Feature) -> Cluster<'static> {
        FULL_CLUSTER
            .with_features(features.bits())
            .with_attrs(with!(required;
            AttributeId::RegisteredClients
                | AttributeId::ICDCounter
                | AttributeId::ClientsSupportedPerFabric
                | AttributeId::MaximumCheckInBackOff
                | AttributeId::OperatingMode
                | AttributeId::UserActiveModeTriggerHint
                | AttributeId::UserActiveModeTriggerInstruction))
    }

    /// Create a handler backed by the shared [`LitIcd`] state.
    pub const fn new(dataver: Dataver, lit: &'a LitIcd) -> Self {
        Self { dataver, lit }
    }

    /// Adapt this handler to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    /// The accessing fabric of the current command.
    fn cmd_fabric(ctx: &impl InvokeContext) -> Result<NonZeroU8, Error> {
        ctx.accessor()?.fab_idx()
    }

    /// Whether the caller holds Administer privilege on this command's path.
    ///
    /// Administrators may register/unregister any client; everyone else must
    /// prove ownership of an existing entry with its verification key.
    fn caller_is_admin(ctx: &impl InvokeContext) -> Result<bool, Error> {
        let accessor = ctx.accessor()?;
        let cmd = ctx.cmd();
        let path = GenericPath::new(
            Some(cmd.endpoint_id),
            Some(cmd.cluster_id),
            Some(cmd.cmd_id),
        );

        let mut req = AccessReq::new(&accessor, path, Access::WRITE, &[]);
        req.set_target_perms(Access::WRITE | Access::NEED_ADMIN);

        Ok(req.allow())
    }

    /// Publish the current operating mode (and the slow poll it implies) to
    /// the mDNS layer.
    fn sync_icd_mode(&self, ctx: &impl HandlerContext) {
        self.lit.icd.publish_advertisement(ctx.matter());
    }

    /// The `RegisterClient` command, minus the logging of its outcome.
    fn register_client<P: TLVBuilderParent>(
        &self,
        ctx: &impl InvokeContext,
        request: RegisterClientRequest<'_>,
        response: RegisterClientResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::cmd_fabric(ctx)?;
        let node_id = request.check_in_node_id()?;

        info!(
            "ICD: RegisterClient from fabric {} for check-in node {:#x}",
            fab_idx, node_id
        );

        // A non-administrator replacing an existing entry must present its
        // verification key. A new entry (NotFound) needs no key.
        if !Self::caller_is_admin(ctx)? {
            let presented = request.verification_key()?.map(|k| k.0);
            if self.lit.verify_key(fab_idx, node_id, presented) == KeyVerdict::Mismatch {
                warn!(
                    "ICD: fabric {} check-in node {:#x}: verification key mismatch",
                    fab_idx, node_id
                );
                Err(ErrorCode::Failure)?;
            }
        }

        let key = request.key()?;

        self.lit.register(MonitoringRegistration {
            fab_idx,
            check_in_node_id: node_id,
            monitored_subject: request.monitored_subject()?,
            // An out-of-range client type or wrong-length key is a constraint
            // violation, not a generic failure.
            client_type: request
                .client_type()
                .map_err(|_| ErrorCode::ConstraintError)?,
            key: key.0.try_into().map_err(|_| ErrorCode::ConstraintError)?,
        })?;

        self.lit.store_registrations(ctx)?;
        ctx.notify_own_cluster_changed();

        info!(
            "ICD: registered fabric {} check-in node {:#x}",
            fab_idx, node_id
        );

        // The client stores this as its starting Check-In counter reference.
        response.icd_counter(self.lit.next_counter())?.end()
    }

    /// The `UnregisterClient` command, minus the logging of its outcome.
    fn unregister_client(
        &self,
        ctx: &impl InvokeContext,
        request: UnregisterClientRequest<'_>,
    ) -> Result<(), Error> {
        let fab_idx = Self::cmd_fabric(ctx)?;
        let node_id = request.check_in_node_id()?;

        info!(
            "ICD: UnregisterClient from fabric {} for check-in node {:#x}",
            fab_idx, node_id
        );

        // A non-administrator must prove ownership with the verification key
        // before the entry is removed; a missing entry is `NotFound` regardless.
        if !Self::caller_is_admin(ctx)? {
            let presented = request.verification_key()?.map(|k| k.0);
            match self.lit.verify_key(fab_idx, node_id, presented) {
                KeyVerdict::NotFound => Err(ErrorCode::NotFound)?,
                KeyVerdict::Mismatch => {
                    warn!(
                        "ICD: fabric {} check-in node {:#x}: verification key mismatch",
                        fab_idx, node_id
                    );
                    Err(ErrorCode::Failure)?
                }
                KeyVerdict::Match => {}
            }
        }

        // A missing registration fails here for an administrator too, and is
        // logged, like every failure, by the caller.
        self.lit.unregister(fab_idx, node_id)?;

        self.lit.store_registrations(ctx)?;
        ctx.notify_own_cluster_changed();

        info!(
            "ICD: unregistered fabric {} check-in node {:#x}",
            fab_idx, node_id
        );

        Ok(())
    }
}

impl ClusterHandler for LitIcdMgmtHandler<'_> {
    const CLUSTER: Cluster<'static> = Self::cluster(
        Feature::CHECK_IN_PROTOCOL_SUPPORT
            .union(Feature::LONG_IDLE_TIME_SUPPORT)
            .union(Feature::USER_ACTIVE_MODE_TRIGGER),
    );

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        match op {
            LifecycleOp::Startup => {
                ctx.kv()
                    .access(|store, buf| self.lit.load_persist(ctx.crypto(), store, buf))?;

                // Advertise the operating mode from the reloaded registration
                // set right away, so a client registered before the reboot
                // keeps the device advertising as LIT.
                self.sync_icd_mode(&ctx);

                Ok(())
            }
            LifecycleOp::FactoryReset => {
                ctx.kv()
                    .access(|store, buf| self.lit.reset_persist(ctx.crypto(), store, buf))?;

                // Every registration is gone, so the device drops back to SIT.
                self.sync_icd_mode(&ctx);

                Ok(())
            }
            LifecycleOp::FabricRemoval { fab_idx } => {
                // Dropping the last registration flips the operating mode to
                // SIT, which `run` announces.
                if self.lit.remove_fabric(fab_idx) {
                    self.lit.store_registrations(&ctx)?;
                }

                Ok(())
            }
        }
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        let mut power_mode = pin!(self.lit.icd.run(&ctx, self.lit));

        // Every operating mode change - a registration, the last one gone, the
        // application requiring SIT operation - is a global (not fabric-scoped)
        // observable: the mDNS layer and the subscribers learn about it. ICD
        // Management is a root-node cluster, hence the fixed endpoint.
        let mut operating_mode = pin!(async {
            loop {
                self.lit.mode_changed.wait().await;

                self.sync_icd_mode(&ctx);
                ctx.notify_attr_changed(
                    ROOT_ENDPOINT_ID,
                    Self::CLUSTER.id,
                    AttributeId::OperatingMode as _,
                );
            }
        });

        match select(&mut power_mode, &mut operating_mode).await {
            Either::First(result) => result,
            Either::Second(_) => unreachable!(),
        }
    }

    fn idle_mode_duration(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.lit.icd.mode.idle_mode_duration_s)
    }

    fn active_mode_duration(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.lit.icd.mode.active_mode_duration_ms)
    }

    fn active_mode_threshold(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.lit.icd.mode.active_mode_threshold_ms)
    }

    fn clients_supported_per_fabric(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(CLIENTS_PER_FABRIC as u16)
    }

    // The lower bound of the allowed range: this device does not back its
    // Check-Ins off, so its maximum equals its idle-mode duration.
    fn maximum_check_in_back_off(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.lit.icd.mode.idle_mode_duration_s)
    }

    fn operating_mode(&self, _ctx: impl ReadContext) -> Result<OperatingModeEnum, Error> {
        Ok(self.lit.icd.operating_mode())
    }

    fn user_active_mode_trigger_hint(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<UserActiveModeTriggerBitmap, Error> {
        Ok(UserActiveModeTriggerBitmap::from_bits_truncate(
            self.lit.icd.mode.user_active_mode_trigger_hint,
        ))
    }

    fn user_active_mode_trigger_instruction<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: crate::tlv::Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.lit.icd.mode.user_active_mode_trigger_instruction)
    }

    fn icd_counter(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.lit.next_counter())
    }

    fn registered_clients<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            MonitoringRegistrationStructArrayBuilder<P>,
            MonitoringRegistrationStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        let attr = ctx.attr();
        let fab_filter = attr
            .fab_filter
            .then(|| NonZeroU8::new(attr.fab_idx).ok_or(ErrorCode::UnsupportedAccess))
            .transpose()?;

        self.lit.with_registrations(|clients| {
            let mut iter = clients
                .iter()
                .filter(|c| fab_filter.is_none_or(|f| c.fab_idx == f));

            match builder {
                ArrayAttributeRead::ReadAll(mut array) => {
                    for c in iter {
                        array = array
                            .push()?
                            .check_in_node_id(Some(c.check_in_node_id))?
                            .monitored_subject(Some(c.monitored_subject))?
                            .client_type(Some(c.client_type))?
                            .fabric_index(Some(c.fab_idx.get()))?
                            .end()?;
                    }
                    array.end()
                }
                ArrayAttributeRead::ReadOne(index, item) => {
                    let Some(c) = iter.nth(index as usize) else {
                        return Err(ErrorCode::ConstraintError.into());
                    };
                    item.check_in_node_id(Some(c.check_in_node_id))?
                        .monitored_subject(Some(c.monitored_subject))?
                        .client_type(Some(c.client_type))?
                        .fabric_index(Some(c.fab_idx.get()))?
                        .end()
                }
                ArrayAttributeRead::ReadNone(array) => array.end(),
            }
        })
    }

    fn handle_register_client<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: RegisterClientRequest<'_>,
        response: RegisterClientResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Logged before anything can fail, so that a request which arrived
        // and failed is never mistaken for one that never arrived.
        info!("ICD: RegisterClient received");

        self.register_client(&ctx, request, response)
            .inspect_err(|err| warn!("ICD: RegisterClient failed: {:?}", err))
    }

    fn handle_unregister_client(
        &self,
        ctx: impl InvokeContext,
        request: UnregisterClientRequest<'_>,
    ) -> Result<(), Error> {
        info!("ICD: UnregisterClient received");

        self.unregister_client(&ctx, request)
            .inspect_err(|err| warn!("ICD: UnregisterClient failed: {:?}", err))
    }

    fn handle_stay_active_request<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        request: StayActiveRequestRequest<'_>,
        response: StayActiveResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Honor at most the maximum guaranteed stay-active duration, then extend
        // the deadline and report the actual resulting remaining time (which may
        // be longer if a prior request already extended further).
        let requested = request.stay_active_duration()?.min(STAY_ACTIVE_MAX_MS);
        let promised = self.lit.icd.stay_active(requested);

        info!(
            "ICD: StayActiveRequest for {} ms, promised {} ms",
            requested, promised
        );

        response.promised_active_duration(promised)?.end()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::crypto::test_only_crypto;

    use super::super::tests::{force_idle, mode, notified};
    use super::*;

    fn fab(i: u8) -> NonZeroU8 {
        NonZeroU8::new(i).unwrap()
    }

    fn reg(fab: u8, node: u64) -> MonitoringRegistration {
        MonitoringRegistration {
            fab_idx: NonZeroU8::new(fab).unwrap(),
            check_in_node_id: node,
            monitored_subject: node,
            client_type: ClientTypeEnum::Permanent,
            key: CanonAeadKey::new(),
        }
    }

    fn lit() -> LitIcd {
        LitIcd::new(10, mode(), SIT_SLOW_POLL_MAX_MS)
    }

    /// Collect the node ids of the registrations matching `fab_filter`.
    fn nodes(lit: &LitIcd, fab_filter: Option<NonZeroU8>) -> alloc::vec::Vec<u64> {
        lit.with_registrations(|clients| {
            clients
                .iter()
                .filter(|c| fab_filter.is_none_or(|f| c.fab_idx == f))
                .map(|c| c.check_in_node_id)
                .collect()
        })
    }

    #[test]
    #[should_panic]
    fn a_sit_poll_above_the_maximum_is_rejected() {
        LitIcd::new(10, mode(), SIT_SLOW_POLL_MAX_MS + 1);
    }

    #[test]
    fn registrations_signal_the_network_driver_only_on_a_sit_lit_flip() {
        let lit = lit();
        let icd = lit.icd();

        // SIT -> LIT
        lit.register(reg(1, 100)).unwrap();
        assert!(notified(&icd.net_changed));
        assert!(notified(&lit.mode_changed));
        assert!(!notified(&icd.power_changed));

        // Still LIT: another client, and an update of the first one.
        lit.register(reg(1, 101)).unwrap();
        lit.register(reg(1, 100)).unwrap();
        assert!(!notified(&icd.net_changed));
        assert!(!notified(&lit.mode_changed));

        // Still LIT.
        lit.unregister(fab(1), 101).unwrap();
        assert!(!notified(&icd.net_changed));

        // LIT -> SIT
        lit.unregister(fab(1), 100).unwrap();
        assert!(notified(&icd.net_changed));
        assert!(notified(&lit.mode_changed));
        assert!(!notified(&icd.power_changed));

        // The same over a fabric removal.
        lit.register(reg(2, 200)).unwrap();
        assert!(notified(&icd.net_changed));
        assert!(lit.remove_fabric(fab(2)));
        assert!(notified(&icd.net_changed));
        assert!(!lit.remove_fabric(fab(2)));
        assert!(!notified(&icd.net_changed));
    }

    #[test]
    fn register_adds_and_updates() {
        let lit = lit();

        lit.register(reg(1, 100)).unwrap();
        assert_eq!(lit.registrations_len(), 1);
        assert_eq!(lit.fabric_registrations_len(fab(1)), 1);

        // Same (fabric, node) -> update in place, not a second entry.
        let mut updated = reg(1, 100);
        updated.monitored_subject = 999;
        lit.register(updated).unwrap();
        assert_eq!(lit.registrations_len(), 1);
        let subject = lit.with_registrations(|c| c[0].monitored_subject);
        assert_eq!(subject, 999);
    }

    #[test]
    fn per_fabric_limit_is_enforced_independently() {
        let lit = lit();

        // Fill fabric 1 up to the per-fabric limit.
        for i in 0..CLIENTS_PER_FABRIC {
            lit.register(reg(1, 100 + i as u64)).unwrap();
        }
        assert_eq!(lit.fabric_registrations_len(fab(1)), CLIENTS_PER_FABRIC);

        // One more distinct client on fabric 1 exceeds the limit...
        assert!(lit
            .register(reg(1, 100 + CLIENTS_PER_FABRIC as u64))
            .is_err());
        assert_eq!(lit.fabric_registrations_len(fab(1)), CLIENTS_PER_FABRIC);

        // ...updating an existing fabric-1 client still works...
        lit.register(reg(1, 100)).unwrap();
        assert_eq!(lit.fabric_registrations_len(fab(1)), CLIENTS_PER_FABRIC);

        // ...and fabric 2 has its own independent budget.
        lit.register(reg(2, 200)).unwrap();
        assert_eq!(lit.fabric_registrations_len(fab(2)), 1);
    }

    #[test]
    fn unregister_and_remove_fabric() {
        let lit = lit();
        lit.register(reg(1, 100)).unwrap();
        lit.register(reg(2, 200)).unwrap();

        assert!(lit.unregister(fab(1), 999).is_err()); // no such node
        lit.unregister(fab(1), 100).unwrap();
        assert_eq!(lit.registrations_len(), 1);

        // Removing a fabric drops only its entries.
        assert!(lit.remove_fabric(fab(2)));
        assert_eq!(lit.registrations_len(), 0);
        assert!(!lit.remove_fabric(fab(2))); // nothing left
    }

    #[test]
    fn operating_mode_follows_the_registration_set() {
        let lit = lit();
        let icd = lit.icd();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::SIT);

        lit.register(reg(1, 100)).unwrap();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::LIT);

        lit.register(reg(1, 101)).unwrap();
        lit.unregister(fab(1), 100).unwrap();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::LIT);

        lit.unregister(fab(1), 101).unwrap();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::SIT);
    }

    /// Dynamic SIT/LIT: the application may require SIT operation even while
    /// clients are registered.
    #[test]
    fn required_sit_operation_overrides_the_registrations() {
        let lit = lit();
        let icd = lit.icd();

        icd.set_poll_intervals(300, 900_000);
        force_idle(icd);

        lit.register(reg(1, 100)).unwrap();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::LIT);
        assert_eq!(icd.net_params().poll_interval_ms, 900_000);
        assert!(notified(&lit.mode_changed));

        lit.set_sit_required(true);
        assert_eq!(icd.operating_mode(), OperatingModeEnum::SIT);
        assert_eq!(icd.net_params().poll_interval_ms, SIT_SLOW_POLL_MAX_MS);
        assert!(notified(&lit.mode_changed));

        // The registrations stay, and a new one does not flip the mode.
        lit.register(reg(1, 101)).unwrap();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::SIT);
        assert_eq!(lit.registrations_len(), 2);

        lit.set_sit_required(false);
        assert_eq!(icd.operating_mode(), OperatingModeEnum::LIT);
        assert!(notified(&lit.mode_changed));
    }

    #[test]
    fn verify_key_matches_only_the_stored_key() {
        let lit = lit();

        let mut r = reg(1, 100);
        let stored = [7u8; 16];
        r.key.try_load_from_slice(&stored).unwrap();
        lit.register(r).unwrap();

        // Unknown node.
        assert_eq!(
            lit.verify_key(fab(1), 999, Some(&stored)),
            KeyVerdict::NotFound
        );
        // Right node, wrong fabric.
        assert_eq!(
            lit.verify_key(fab(2), 100, Some(&stored)),
            KeyVerdict::NotFound
        );
        // Correct key.
        assert_eq!(
            lit.verify_key(fab(1), 100, Some(&stored)),
            KeyVerdict::Match
        );
        // Wrong key and absent key both mismatch.
        assert_eq!(
            lit.verify_key(fab(1), 100, Some(&[0u8; 16])),
            KeyVerdict::Mismatch
        );
        assert_eq!(lit.verify_key(fab(1), 100, None), KeyVerdict::Mismatch);
    }

    #[test]
    fn with_registrations_honors_the_fabric_filter() {
        let lit = lit();
        lit.register(reg(1, 100)).unwrap();
        lit.register(reg(2, 200)).unwrap();

        let mut all = nodes(&lit, None);
        all.sort_unstable();
        assert_eq!(all, [100, 200]);

        assert_eq!(nodes(&lit, Some(fab(1))), [100]);
    }

    /// A key-aware in-memory store. The LIT state spans two keys
    /// (registrations and the Check-In counter), so a single-slot stub would
    /// hand one key's blob back for the other.
    #[derive(Default)]
    struct MemKv {
        entries: alloc::vec::Vec<(u16, alloc::vec::Vec<u8>)>,
    }

    impl MemKv {
        fn get(&self, key: u16) -> Option<&[u8]> {
            self.entries
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.as_slice())
        }
    }

    impl KvBlobStore for &mut MemKv {
        fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
            let Some(v) = self.get(key) else {
                return Ok(None);
            };

            buf[..v.len()].copy_from_slice(v);

            Ok(Some(&buf[..v.len()]))
        }

        fn store(&mut self, key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
            self.entries.retain(|(k, _)| *k != key);
            self.entries.push((key, data.to_vec()));

            Ok(())
        }

        fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), Error> {
            self.entries.retain(|(k, _)| *k != key);

            Ok(())
        }
    }

    #[test]
    fn counter_persists_at_boundary_and_resumes_across_restart() {
        const EPOCH: u32 = 10;
        let mut kv = MemKv::default();
        let mut buf = [0u8; 16];

        // Session 1: counter starts at 100, boundary at 110.
        let lit = LitIcd::new(EPOCH, mode(), SIT_SLOW_POLL_MAX_MS);
        // Session 1 seeds at 100 the way `load_persist` would from a stored
        // boundary, so the expectations below stay readable.
        lit.reseed_counter(100);

        // Peeks are stable; advancing before the boundary writes nothing.
        assert_eq!(lit.next_counter(), 101);
        for _ in 0..9 {
            lit.advance_counter(&mut kv, &mut buf).unwrap();
        }
        assert_eq!(
            kv.get(ICD_CHECK_IN_COUNTER_KEY),
            None,
            "no persist before the boundary"
        );

        // Crossing the boundary persists the next one (120).
        let last_used = lit.next_counter();
        lit.advance_counter(&mut kv, &mut buf).unwrap();
        assert_eq!(last_used, 110);
        assert!(
            kv.get(ICD_CHECK_IN_COUNTER_KEY).is_some(),
            "boundary crossing must persist"
        );

        // Session 2 (a restart): a fresh LitIcd whose counter resumes from the
        // persisted boundary. Every value it hands out is past session 1's.
        // The epoch comes from the counter this `LitIcd` was built with, not
        // from the blob.
        let lit2 = LitIcd::new(EPOCH, mode(), SIT_SLOW_POLL_MAX_MS);
        lit2.load_persist(test_only_crypto(), &mut kv, &mut buf)
            .unwrap();
        assert!(lit2.next_counter() > last_used);

        // Re-hydrating must itself persist the boundary it resumes from, or a
        // crash before the next crossing would hand out these values twice.
        let boundary = u32::from_le_bytes(
            kv.get(ICD_CHECK_IN_COUNTER_KEY)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert!(boundary >= lit2.next_counter() + EPOCH - 1);

        // Session 3 (a second restart, no traffic in session 2): still strictly
        // past every value session 2 could have used.
        let lit3 = LitIcd::new(EPOCH, mode(), SIT_SLOW_POLL_MAX_MS);
        lit3.load_persist(test_only_crypto(), &mut kv, &mut buf)
            .unwrap();
        assert!(lit3.next_counter() > lit2.next_counter() + EPOCH - 1);
    }

    #[test]
    fn first_boot_seeds_the_counter_and_persists_a_boundary() {
        const EPOCH: u32 = 10;
        let mut kv = MemKv::default();
        let mut buf = [0u8; 256];

        // Nothing stored: the counter is seeded from a random start, and the
        // boundary it resumes from must be durable before any Check-In goes out.
        let lit = LitIcd::new(EPOCH, mode(), SIT_SLOW_POLL_MAX_MS);
        lit.load_persist(test_only_crypto(), &mut kv, &mut buf)
            .unwrap();

        let boundary = u32::from_le_bytes(
            kv.get(ICD_CHECK_IN_COUNTER_KEY)
                .expect("a first boot must persist a boundary")
                .try_into()
                .unwrap(),
        );

        // `next()` peeks at start + 1 and the boundary sits at start + EPOCH.
        assert_eq!(boundary, lit.next_counter().wrapping_add(EPOCH - 1));
    }

    #[test]
    fn factory_reset_clears_registrations_and_both_keys() {
        let mut kv = MemKv::default();
        let mut buf = [0u8; 256];

        let lit = lit();

        lit.register(reg(1, 0x1234)).unwrap();
        assert_eq!(lit.icd().operating_mode(), OperatingModeEnum::LIT);

        // Seed both persisted blobs the way a running node would.
        (&mut kv)
            .store(ICD_REGISTERED_CLIENTS_KEY, b"whatever", &mut buf)
            .unwrap();
        (&mut kv)
            .store(ICD_CHECK_IN_COUNTER_KEY, &110u32.to_le_bytes(), &mut buf)
            .unwrap();

        let before_reset = lit.next_counter();

        lit.reset_persist(test_only_crypto(), &mut kv, &mut buf)
            .unwrap();

        assert_eq!(lit.registrations_len(), 0);
        assert_eq!(lit.icd().operating_mode(), OperatingModeEnum::SIT);
        assert_eq!(kv.get(ICD_REGISTERED_CLIENTS_KEY), None);
        assert_eq!(kv.get(ICD_CHECK_IN_COUNTER_KEY), None);

        // The counter is re-seeded rather than left where it was, so the next
        // boot does not resume the decommissioned device's sequence.
        assert_ne!(lit.next_counter(), before_reset);
    }
}
