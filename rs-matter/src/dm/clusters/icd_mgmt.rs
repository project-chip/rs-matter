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

//! The ICD Management cluster and Check-In sender.
//!
//! An Intermittently Connected Device (ICD) hosts this cluster so clients can
//! register to receive Check-In notifications when their subscription is lost.
//!
//! - [`Icd`] is the shared state (registrations + Check-In counter +
//!   stay-active deadline) the application owns and lends to the handler and the
//!   sender.
//! - [`IcdMgmtHandler`] is the cluster handler (registration commands + the
//!   Check-In-relevant attributes), layered on an [`Icd`].
//! - [`Icd::send_check_in`] sends a Check-In to every registered client whose
//!   subscription is lost; [`Icd::send_one_check_in`] targets a single client.
//!   Both resolve the address over mDNS and send sessionlessly. The application
//!   drives them when it decides clients should be nudged.

use core::num::NonZeroU8;

use embassy_time::{Duration, Instant};

use crate::acl::AccessReq;
use crate::crypto::{CanonAeadKey, Crypto};
use crate::dm::{
    Access, ArrayAttributeRead, Cluster, Dataver, HandlerContext, InvokeContext, ReadContext,
};
use crate::error::{Error, ErrorCode};
use crate::fabric::MAX_FABRICS;
use crate::im::encoding::GenericPath;
use crate::persist::{KvBlobStore, Persist, ICD_REGISTERED_CLIENTS_KEY};
use crate::sc::checkin::{CheckIn, CheckInCounter};
use crate::tlv::{FromTLV, TLVBuilderParent, TLVElement, ToTLV};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;
use crate::with;
use crate::Matter;

pub use crate::dm::clusters::decl::icd_management::*;

/// The maximum number of clients that can register per fabric — the value
/// reported by the cluster's `ClientsSupportedPerFabric` attribute.
///
/// The spec floor is 1; two (matching CHIP's default) covers a fabric whose
/// ecosystem monitors the device from more than one client. Raise it if a
/// fabric needs still more independent Check-In clients.
pub const CLIENTS_PER_FABRIC: usize = 2;

/// The total capacity of the registration store, across all fabrics.
pub const MAX_REGISTERED_CLIENTS: usize = CLIENTS_PER_FABRIC * MAX_FABRICS;

/// The maximum stay-active duration (milliseconds) a `StayActiveRequest` will be
/// honored for — the "guaranteed" duration the device must be able to grant. A
/// request longer than this is clamped to it (though the *promised* remaining
/// time may still be longer if the deadline was already further out).
pub const STAY_ACTIVE_MAX_MS: u32 = 30_000;

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

/// The timing parameters an ICD advertises through the cluster's mandatory
/// mode-duration / threshold attributes.
///
/// These describe the device's own power-management behavior; the application
/// supplies them.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IcdModeConfig {
    /// Maximum time (seconds) the device may stay in idle mode. Must not be
    /// smaller than `active_mode_duration_ms` converted to seconds.
    pub idle_mode_duration_s: u32,
    /// Minimum time (milliseconds) the device stays active after leaving idle.
    pub active_mode_duration_ms: u32,
    /// Minimum time (milliseconds) the device stays active after network
    /// activity. Also the ICD Check-In application data.
    pub active_mode_threshold_ms: u16,
    /// The `UserActiveModeTriggerHint` bitmap: how a user can return the device
    /// to active mode. `0` means no trigger advertised.
    pub user_active_mode_trigger_hint: u32,
    /// The `UserActiveModeTriggerInstruction` string paired with the hint (empty
    /// when the hint needs no free-form instruction). Must be `<= 128` bytes.
    pub user_active_mode_trigger_instruction: &'static str,
}

/// The interior, mutable ICD state guarded by a single lock: the registrations,
/// the Check-In counter, and the stay-active deadline. These are always touched
/// together, so one lock keeps them consistent and cheap.
struct IcdState {
    /// The registered Check-In clients (persisted).
    clients: Vec<MonitoringRegistration, MAX_REGISTERED_CLIENTS>,
    /// The Check-In counter.
    counter: CheckInCounter,
    /// The instant until which a `StayActiveRequest` has asked this device to
    /// stay active, or `None` if no request is outstanding.
    stay_active_until: Option<Instant>,
}

impl IcdState {
    fn init(counter: CheckInCounter) -> impl Init<Self> {
        init!(Self {
            clients <- Vec::init(),
            counter: counter,
            stay_active_until: None,
        })
    }
}

/// The shared ICD state.
///
/// The cluster handler ([`IcdMgmtHandler`]) and the Check-In sender both operate
/// on one instance the application owns and lends to each: the handler mutates
/// the registrations and reads the counter; the sender reads the registrations
/// and advances the counter. All of it lives behind a single lock.
///
/// Two [`Notification`]s (outside the lock) let the application react: the
/// registration set changing ([`wait_registrations_changed`](Self::wait_registrations_changed))
/// and the stay-active deadline being extended ([`wait_active_extended`](Self::wait_active_extended)).
pub struct Icd {
    state: Mutex<RefCell<IcdState>>,
    /// The advertised mode timings; `active_mode_threshold_ms` is also the
    /// Check-In application data.
    mode: IcdModeConfig,
    /// Signalled whenever the registration set changes.
    registrations_changed: Notification,
    /// Signalled whenever the stay-active deadline is extended.
    active_extended: Notification,
}

impl Icd {
    /// Create the ICD state from a starting Check-In counter and mode timings.
    ///
    /// `counter` should be constructed from the persisted counter value (or a
    /// random one on first use); persist [`CheckInCounter::persist_value`] right
    /// after, as its docs describe.
    pub const fn new(counter: CheckInCounter, mode: IcdModeConfig) -> Self {
        Self {
            state: Mutex::new(RefCell::new(IcdState {
                clients: Vec::new(),
                counter,
                stay_active_until: None,
            })),
            mode,
            registrations_changed: Notification::new(),
            active_extended: Notification::new(),
        }
    }

    /// An in-place initializer, mirroring [`Self::new`]. Prefer this over `new`
    /// to avoid the registration array transiting the stack.
    pub fn init(counter: CheckInCounter, mode: IcdModeConfig) -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(IcdState::init(counter))),
            mode: mode,
            registrations_changed <- Notification::init(),
            active_extended <- Notification::init(),
        })
    }

    /// The mode timings this ICD advertises.
    pub fn mode(&self) -> IcdModeConfig {
        self.mode
    }

    // --- Registrations ---

    /// The total number of registrations across all fabrics.
    pub fn registrations_len(&self) -> usize {
        self.state.lock(|s| s.borrow().clients.len())
    }

    /// Whether there are no registrations.
    pub fn registrations_is_empty(&self) -> bool {
        self.registrations_len() == 0
    }

    /// The current operating mode: `LIT` while any client is registered,
    /// otherwise `SIT`.
    ///
    /// This is the value of the `OperatingMode` attribute and of the `ICD`
    /// operational DNS-SD TXT key. It changes only when the registration set
    /// transitions empty↔non-empty, so
    /// [`wait_registrations_changed`](Self::wait_registrations_changed) is the
    /// signal to re-read it (e.g. to re-advertise mDNS).
    pub fn operating_mode(&self) -> OperatingModeEnum {
        if self.registrations_is_empty() {
            OperatingModeEnum::SIT
        } else {
            OperatingModeEnum::LIT
        }
    }

    /// The number of registrations on `fab_idx`.
    pub fn fabric_registrations_len(&self, fab_idx: NonZeroU8) -> usize {
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
    pub fn register(&self, registration: MonitoringRegistration) -> Result<(), Error> {
        self.state.lock(|s| -> Result<(), Error> {
            let clients = &mut s.borrow_mut().clients;

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
        })?;

        self.registrations_changed.notify();

        Ok(())
    }

    /// Remove the registration for `(fab_idx, check_in_node_id)`.
    ///
    /// Returns `Err(NotFound)` if there is no such registration.
    pub fn unregister(&self, fab_idx: NonZeroU8, check_in_node_id: u64) -> Result<(), Error> {
        let removed = self.state.lock(|s| {
            let clients = &mut s.borrow_mut().clients;
            let before = clients.len();
            clients.retain(|c| !(c.fab_idx == fab_idx && c.check_in_node_id == check_in_node_id));
            clients.len() != before
        });

        if !removed {
            Err(ErrorCode::NotFound)?;
        }

        self.registrations_changed.notify();

        Ok(())
    }

    /// Check a presented verification `key` against the stored registration for
    /// `(fab_idx, check_in_node_id)`.
    ///
    /// Non-administrator clients may only modify or remove an entry they own,
    /// proven by re-presenting the same key the entry was registered with. A
    /// missing or wrong key yields [`KeyVerdict::Mismatch`].
    pub fn verify_key(
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
    pub fn remove_fabric(&self, fab_idx: NonZeroU8) -> bool {
        let removed = self.state.lock(|s| {
            let clients = &mut s.borrow_mut().clients;
            let before = clients.len();
            clients.retain(|c| c.fab_idx != fab_idx);
            clients.len() != before
        });

        if removed {
            self.registrations_changed.notify();
        }

        removed
    }

    /// Run `f` with the registrations while the lock is held.
    ///
    /// The closure runs under the lock, so it must not re-enter the ICD state and
    /// must not `.await`.
    pub fn with_registrations<R>(&self, f: impl FnOnce(&[MonitoringRegistration]) -> R) -> R {
        self.state.lock(|s| f(&s.borrow().clients))
    }

    /// Wait until the set of registrations changes.
    pub async fn wait_registrations_changed(&self) {
        self.registrations_changed.wait().await;
    }

    /// Re-hydrate the registrations from `kv`. Call once at startup, before
    /// exposing the data model.
    pub fn load_registrations<S: KvBlobStore>(
        &self,
        mut kv: S,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let clients = match kv.load(ICD_REGISTERED_CLIENTS_KEY, buf)? {
            Some(data) => Vec::from_tlv(&TLVElement::new(data))?,
            None => Vec::new(),
        };

        self.state.lock(|s| s.borrow_mut().clients = clients);

        Ok(())
    }

    /// Persist the current registrations to `ctx.kv()`.
    pub fn store_registrations<C: HandlerContext>(&self, ctx: &C) -> Result<(), Error> {
        let mut persist = Persist::new(ctx.kv());

        self.state
            .lock(|s| persist.store_tlv(ICD_REGISTERED_CLIENTS_KEY, &s.borrow().clients))?;

        persist.run()
    }

    // --- Stay-active deadline ---

    /// The instant until which a client has asked this device to stay active via
    /// `StayActiveRequest`, or `None` if no such request is outstanding.
    ///
    /// NOTE: this reflects *only* the `StayActiveRequest`-driven deadline. A real
    /// ICD stays active for other reasons too — a baseline period after waking
    /// (`ActiveModeDuration`) and a top-up after each message
    /// (`ActiveModeThreshold`). Those depend on the device's own power state, so
    /// they are the firmware's concern: combine this deadline with your own when
    /// deciding whether it is safe to sleep.
    pub fn active_until(&self) -> Option<Instant> {
        self.state.lock(|s| s.borrow().stay_active_until)
    }

    /// Wait until [`active_until`](Self::active_until) is extended by a new
    /// `StayActiveRequest`, so a sleep loop can re-read the deadline.
    pub async fn wait_active_extended(&self) {
        self.active_extended.wait().await;
    }

    /// Extend the stay-active deadline by `duration_ms` from now, returning the
    /// resulting remaining active time in milliseconds.
    ///
    /// The deadline only ever moves later: `deadline = max(deadline, now + d)`.
    /// So the returned value can exceed `duration_ms` if an earlier request
    /// already extended further — it is the *actual* remaining time, which is
    /// what the `StayActiveResponse` promises.
    fn extend_active(&self, duration_ms: u32) -> u32 {
        let now = Instant::now();
        let requested = now.saturating_add(Duration::from_millis(duration_ms as u64));

        let deadline = self.state.lock(|s| {
            let stay = &mut s.borrow_mut().stay_active_until;
            let deadline = stay.map_or(requested, |current| current.max(requested));
            *stay = Some(deadline);
            deadline
        });

        self.active_extended.notify();

        // Remaining time to the deadline (0 if it somehow already passed).
        deadline.saturating_duration_since(now).as_millis() as u32
    }

    // --- Check-In counter ---

    /// The counter value the next Check-In message will use (a peek).
    pub fn next_counter(&self) -> u32 {
        self.state.lock(|s| s.borrow().counter.next())
    }

    /// Advance the Check-In counter after sending, persisting to `kv` when a new
    /// epoch boundary is crossed.
    ///
    /// Call once per Check-In *batch* (all messages in the batch used the same
    /// [`next_counter`](Self::next_counter) value).
    pub fn advance_counter<S: KvBlobStore>(&self, mut kv: S, buf: &mut [u8]) -> Result<(), Error> {
        let to_persist = self.state.lock(|s| s.borrow_mut().counter.advance());

        if let Some(value) = to_persist {
            kv.store(
                crate::persist::ICD_CHECK_IN_COUNTER_KEY,
                &value.to_le_bytes(),
                buf,
            )?;
        }

        Ok(())
    }

    /// Jump the Check-In counter forward by `delta` (wrapping). Used to
    /// invalidate outstanding counter values in one step; the new value is
    /// visible immediately via [`next_counter`](Self::next_counter).
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
        kv.store(
            crate::persist::ICD_CHECK_IN_COUNTER_KEY,
            &value.to_le_bytes(),
            buf,
        )
    }

    /// Load the persisted Check-In counter epoch and reset the counter to resume
    /// from it. Call once at startup, before any Check-In is sent.
    pub fn load_counter<S: KvBlobStore>(
        &self,
        mut kv: S,
        epoch: u32,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        let start = match kv.load(crate::persist::ICD_CHECK_IN_COUNTER_KEY, buf)? {
            Some(data) => u32::from_le_bytes(data.try_into().map_err(|_| ErrorCode::Invalid)?),
            // No persisted value yet: the caller's initial (random) counter stands.
            None => return Ok(()),
        };

        self.state
            .lock(|s| s.borrow_mut().counter = CheckInCounter::new(start, epoch));

        Ok(())
    }

    // --- Sending Check-In messages ---

    /// Send a Check-In message to the registered client `(fab_idx, node_id)`,
    /// using the given counter value.
    ///
    /// A per-client convenience over [`CheckIn::send_to`]; it looks up the
    /// client's key and sends with the ICD application data (the
    /// `ActiveModeThreshold`). It does *not* advance the counter — the caller
    /// owns that so a batch can share one value (see [`send_check_in`](Self::send_check_in)).
    ///
    /// Requires a running mDNS responder to service the address resolve.
    pub async fn send_one_check_in<C: Crypto>(
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

        let app_data = self.mode.active_mode_threshold_ms.to_le_bytes();

        CheckIn::new(key.reference())
            .send_to(matter, crypto, fab_idx, node_id, counter, &app_data, buf)
            .await
    }

    /// Send a Check-In message to every registered client whose monitored
    /// subject has **no active subscription** — the clients that have lost touch
    /// and need a nudge.
    ///
    /// All messages in the batch share one counter value; the counter is advanced
    /// and persisted once at the end. Errors sending to individual clients are
    /// swallowed (best-effort) so one unreachable client does not block the rest;
    /// only a counter-persist failure is returned.
    ///
    /// Requires a running mDNS responder to service the address resolves.
    pub async fn send_check_in<C: Crypto, const NS: usize>(
        &self,
        matter: &Matter<'_>,
        crypto: C,
        subscriptions: &crate::im::subscriptions::Subscriptions<NS>,
        kv: impl KvBlobStore,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        // Snapshot the eligible clients under the lock — sending is `async`, so
        // neither the ICD nor the subscriptions lock may be held across an
        // `await`. The subscription-liveness check is a quick locked lookup.
        let mut targets: Vec<(NonZeroU8, u64, CanonAeadKey), MAX_REGISTERED_CLIENTS> = Vec::new();

        let counter = self.state.lock(|s| {
            let state = s.borrow();
            for c in &state.clients {
                // A CAT-valued monitored subject won't match here (we compare
                // against subscriber node ids), so such a client is treated as
                // unsubscribed and always nudged.
                if subscriptions.has_subscription_for(c.fab_idx, c.monitored_subject) {
                    continue;
                }
                // Capacity matches the client list, so this cannot overflow.
                let _ = targets.push((c.fab_idx, c.check_in_node_id, c.key.clone()));
            }
            state.counter.next()
        });

        if targets.is_empty() {
            return Ok(());
        }

        let app_data = self.mode.active_mode_threshold_ms.to_le_bytes();

        for (fab_idx, node_id, key) in &targets {
            // Best-effort: keep sending to the rest even if one fails to resolve.
            let _ = CheckIn::new(key.reference())
                .send_to(matter, &crypto, *fab_idx, *node_id, counter, &app_data, buf)
                .await;
        }

        self.advance_counter(kv, buf)
    }
}

/// The server-side handler for the ICD Management cluster.
///
/// Backed by the shared [`Icd`] state: the registration commands mutate its
/// store, and the ICD Counter reported to clients comes from its counter. Only
/// the Check-In Protocol subset is implemented — the mode-duration / threshold
/// attributes plus the `RegisteredClients` / `ICDCounter` /
/// `ClientsSupportedPerFabric` attributes and the `RegisterClient` /
/// `UnregisterClient` / `StayActiveRequest` commands.
pub struct IcdMgmtHandler<'a> {
    dataver: Dataver,
    icd: &'a Icd,
}

impl<'a> IcdMgmtHandler<'a> {
    /// Create a handler backed by the shared [`Icd`] state.
    pub const fn new(dataver: Dataver, icd: &'a Icd) -> Self {
        Self { dataver, icd }
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

    /// Publish the current operating mode to the mDNS layer. This handler serves
    /// the LITS feature, so the device is always ICD-capable — the mode flips
    /// between SIT and LIT as the registration set empties and fills.
    fn sync_icd_mode(&self, ctx: &impl InvokeContext) {
        ctx.matter().set_icd_mode(Some(self.icd.operating_mode()));
    }
}

impl ClusterHandler for IcdMgmtHandler<'_> {
    // We claim the full ICD feature set: Check-In Protocol, Long-Idle-Time,
    // User-Active-Mode-Trigger and Dynamic-SIT-LIT. CIP makes the registration
    // attributes/commands and MaximumCheckInBackoff mandatory; LITS makes
    // OperatingMode and StayActiveRequest mandatory; UAT makes
    // UserActiveModeTriggerHint mandatory; DSLS (which is exactly our
    // registration-driven SIT/LIT switching) adds only its feature bit.
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_features(
            Feature::CHECK_IN_PROTOCOL_SUPPORT
                .union(Feature::LONG_IDLE_TIME_SUPPORT)
                .union(Feature::USER_ACTIVE_MODE_TRIGGER)
                .union(Feature::DYNAMIC_SIT_LIT_SUPPORT)
                .bits(),
        )
        .with_attrs(with!(required;
            AttributeId::RegisteredClients
                | AttributeId::ICDCounter
                | AttributeId::ClientsSupportedPerFabric
                | AttributeId::MaximumCheckInBackOff
                | AttributeId::OperatingMode
                | AttributeId::UserActiveModeTriggerHint
                | AttributeId::UserActiveModeTriggerInstruction));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn idle_mode_duration(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.icd.mode.idle_mode_duration_s)
    }

    fn active_mode_duration(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.icd.mode.active_mode_duration_ms)
    }

    fn active_mode_threshold(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.icd.mode.active_mode_threshold_ms)
    }

    fn clients_supported_per_fabric(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(CLIENTS_PER_FABRIC as u16)
    }

    // The lower bound of the allowed range: this device does not back its
    // Check-Ins off, so its maximum equals its idle-mode duration.
    fn maximum_check_in_back_off(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.icd.mode.idle_mode_duration_s)
    }

    fn operating_mode(&self, _ctx: impl ReadContext) -> Result<OperatingModeEnum, Error> {
        Ok(self.icd.operating_mode())
    }

    fn user_active_mode_trigger_hint(
        &self,
        _ctx: impl ReadContext,
    ) -> Result<UserActiveModeTriggerBitmap, Error> {
        Ok(UserActiveModeTriggerBitmap::from_bits_truncate(
            self.icd.mode.user_active_mode_trigger_hint,
        ))
    }

    fn user_active_mode_trigger_instruction<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: crate::tlv::Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        builder.set(self.icd.mode.user_active_mode_trigger_instruction)
    }

    fn icd_counter(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.icd.next_counter())
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

        self.icd.with_registrations(|clients| {
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
        let fab_idx = Self::cmd_fabric(&ctx)?;
        let node_id = request.check_in_node_id()?;

        // A non-administrator replacing an existing entry must present its
        // verification key. A new entry (NotFound) needs no key.
        if !Self::caller_is_admin(&ctx)? {
            let presented = request.verification_key()?.map(|k| k.0);
            if self.icd.verify_key(fab_idx, node_id, presented) == KeyVerdict::Mismatch {
                Err(ErrorCode::Failure)?;
            }
        }

        let key = request.key()?;

        self.icd.register(MonitoringRegistration {
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

        self.icd.store_registrations(&ctx)?;
        ctx.notify_own_cluster_changed();
        self.sync_icd_mode(&ctx);

        // The client stores this as its starting Check-In counter reference.
        response.icd_counter(self.icd.next_counter())?.end()
    }

    fn handle_unregister_client(
        &self,
        ctx: impl InvokeContext,
        request: UnregisterClientRequest<'_>,
    ) -> Result<(), Error> {
        let fab_idx = Self::cmd_fabric(&ctx)?;
        let node_id = request.check_in_node_id()?;

        // A non-administrator must prove ownership with the verification key
        // before the entry is removed; a missing entry is `NotFound` regardless.
        if !Self::caller_is_admin(&ctx)? {
            let presented = request.verification_key()?.map(|k| k.0);
            match self.icd.verify_key(fab_idx, node_id, presented) {
                KeyVerdict::NotFound => Err(ErrorCode::NotFound)?,
                KeyVerdict::Mismatch => Err(ErrorCode::Failure)?,
                KeyVerdict::Match => {}
            }
        }

        self.icd.unregister(fab_idx, node_id)?;

        self.icd.store_registrations(&ctx)?;
        ctx.notify_own_cluster_changed();
        self.sync_icd_mode(&ctx);

        Ok(())
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
        let promised = self.icd.extend_active(requested);

        response.promised_active_duration(promised)?.end()
    }
}

#[cfg(test)]
mod tests {
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

    fn icd() -> Icd {
        Icd::new(CheckInCounter::new(0, 10), mode())
    }

    /// Collect the node ids of the registrations matching `fab_filter`.
    fn nodes(icd: &Icd, fab_filter: Option<NonZeroU8>) -> alloc::vec::Vec<u64> {
        icd.with_registrations(|clients| {
            clients
                .iter()
                .filter(|c| fab_filter.is_none_or(|f| c.fab_idx == f))
                .map(|c| c.check_in_node_id)
                .collect()
        })
    }

    #[test]
    fn register_adds_and_updates() {
        let icd = icd();

        icd.register(reg(1, 100)).unwrap();
        assert_eq!(icd.registrations_len(), 1);
        assert_eq!(icd.fabric_registrations_len(fab(1)), 1);

        // Same (fabric, node) -> update in place, not a second entry.
        let mut updated = reg(1, 100);
        updated.monitored_subject = 999;
        icd.register(updated).unwrap();
        assert_eq!(icd.registrations_len(), 1);
        let subject = icd.with_registrations(|c| c[0].monitored_subject);
        assert_eq!(subject, 999);
    }

    #[test]
    fn per_fabric_limit_is_enforced_independently() {
        let icd = icd();

        // Fill fabric 1 up to the per-fabric limit.
        for i in 0..CLIENTS_PER_FABRIC {
            icd.register(reg(1, 100 + i as u64)).unwrap();
        }
        assert_eq!(icd.fabric_registrations_len(fab(1)), CLIENTS_PER_FABRIC);

        // One more distinct client on fabric 1 exceeds the limit...
        assert!(icd
            .register(reg(1, 100 + CLIENTS_PER_FABRIC as u64))
            .is_err());
        assert_eq!(icd.fabric_registrations_len(fab(1)), CLIENTS_PER_FABRIC);

        // ...updating an existing fabric-1 client still works...
        icd.register(reg(1, 100)).unwrap();
        assert_eq!(icd.fabric_registrations_len(fab(1)), CLIENTS_PER_FABRIC);

        // ...and fabric 2 has its own independent budget.
        icd.register(reg(2, 200)).unwrap();
        assert_eq!(icd.fabric_registrations_len(fab(2)), 1);
    }

    #[test]
    fn unregister_and_remove_fabric() {
        let icd = icd();
        icd.register(reg(1, 100)).unwrap();
        icd.register(reg(2, 200)).unwrap();

        assert!(icd.unregister(fab(1), 999).is_err()); // no such node
        icd.unregister(fab(1), 100).unwrap();
        assert_eq!(icd.registrations_len(), 1);

        // Removing a fabric drops only its entries.
        assert!(icd.remove_fabric(fab(2)));
        assert!(icd.registrations_is_empty());
        assert!(!icd.remove_fabric(fab(2))); // nothing left
    }

    #[test]
    fn operating_mode_follows_the_registration_set() {
        let icd = icd();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::SIT);

        icd.register(reg(1, 100)).unwrap();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::LIT);

        icd.register(reg(1, 101)).unwrap();
        icd.unregister(fab(1), 100).unwrap();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::LIT);

        icd.unregister(fab(1), 101).unwrap();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::SIT);
    }

    #[test]
    fn verify_key_matches_only_the_stored_key() {
        let icd = icd();

        let mut r = reg(1, 100);
        let stored = [7u8; 16];
        r.key.try_load_from_slice(&stored).unwrap();
        icd.register(r).unwrap();

        // Unknown node.
        assert_eq!(
            icd.verify_key(fab(1), 999, Some(&stored)),
            KeyVerdict::NotFound
        );
        // Right node, wrong fabric.
        assert_eq!(
            icd.verify_key(fab(2), 100, Some(&stored)),
            KeyVerdict::NotFound
        );
        // Correct key.
        assert_eq!(
            icd.verify_key(fab(1), 100, Some(&stored)),
            KeyVerdict::Match
        );
        // Wrong key and absent key both mismatch.
        assert_eq!(
            icd.verify_key(fab(1), 100, Some(&[0u8; 16])),
            KeyVerdict::Mismatch
        );
        assert_eq!(icd.verify_key(fab(1), 100, None), KeyVerdict::Mismatch);
    }

    #[test]
    fn with_registrations_honors_the_fabric_filter() {
        let icd = icd();
        icd.register(reg(1, 100)).unwrap();
        icd.register(reg(2, 200)).unwrap();

        let mut all = nodes(&icd, None);
        all.sort_unstable();
        assert_eq!(all, [100, 200]);

        assert_eq!(nodes(&icd, Some(fab(1))), [100]);
    }

    /// A minimal in-memory single-key store, enough to test the counter
    /// persist/reload roundtrip.
    #[derive(Default)]
    struct MemKv {
        value: Option<alloc::vec::Vec<u8>>,
    }

    impl KvBlobStore for &mut MemKv {
        fn load<'a>(&mut self, _key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
            Ok(self.value.as_ref().map(|v| {
                buf[..v.len()].copy_from_slice(v);
                &buf[..v.len()]
            }))
        }

        fn store(&mut self, _key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), Error> {
            self.value = Some(data.to_vec());
            Ok(())
        }

        fn remove(&mut self, _key: u16, _buf: &mut [u8]) -> Result<(), Error> {
            self.value = None;
            Ok(())
        }
    }

    fn mode() -> IcdModeConfig {
        IcdModeConfig {
            idle_mode_duration_s: 60,
            active_mode_duration_ms: 300,
            active_mode_threshold_ms: 500,
            user_active_mode_trigger_hint: 0,
            user_active_mode_trigger_instruction: "",
        }
    }

    #[test]
    fn stay_active_combines_with_max_and_reports_remaining() {
        let icd = Icd::new(CheckInCounter::new(0, 10), mode());

        // No request yet: no stay-active deadline.
        assert!(icd.active_until().is_none());

        // A request sets the deadline and promises ~its duration.
        let promised = icd.extend_active(STAY_ACTIVE_MAX_MS);
        assert!(promised <= STAY_ACTIVE_MAX_MS);
        assert!(promised > STAY_ACTIVE_MAX_MS - 1_000, "promised {promised}");
        let deadline = icd.active_until().expect("deadline now set");

        // A shorter request does NOT shrink the deadline (max-combine): it still
        // promises ~the earlier, longer remaining time, not its own 1s.
        let promised2 = icd.extend_active(1_000);
        assert!(
            promised2 > 1_000,
            "shorter request must not shrink: {promised2}"
        );
        assert_eq!(icd.active_until(), Some(deadline), "deadline unchanged");

        // A longer request DOES push the deadline out.
        icd.extend_active(2 * STAY_ACTIVE_MAX_MS);
        assert!(icd.active_until().unwrap() > deadline);
    }

    #[test]
    fn stay_active_request_clamps_to_the_guaranteed_max() {
        // The clamp lives in the command handler, not `extend_active` — verify it
        // via the same `.min(STAY_ACTIVE_MAX_MS)` the handler applies.
        let icd = Icd::new(CheckInCounter::new(0, 10), mode());

        let requested = STAY_ACTIVE_MAX_MS + 5_000;
        let promised = icd.extend_active(requested.min(STAY_ACTIVE_MAX_MS));
        assert!(promised <= STAY_ACTIVE_MAX_MS, "must clamp: {promised}");
    }

    #[test]
    fn counter_persists_at_boundary_and_resumes_across_restart() {
        const EPOCH: u32 = 10;
        let mut kv = MemKv::default();
        let mut buf = [0u8; 16];

        // Session 1: counter starts at 100, boundary at 110.
        let icd = Icd::new(CheckInCounter::new(100, EPOCH), mode());

        // Peeks are stable; advancing before the boundary writes nothing.
        assert_eq!(icd.next_counter(), 101);
        for _ in 0..9 {
            icd.advance_counter(&mut kv, &mut buf).unwrap();
        }
        assert_eq!(kv.value, None, "no persist before the boundary");

        // Crossing the boundary persists the next one (120).
        let last_used = icd.next_counter();
        icd.advance_counter(&mut kv, &mut buf).unwrap();
        assert_eq!(last_used, 110);
        assert!(kv.value.is_some(), "boundary crossing must persist");

        // Session 2 (a restart): a fresh Icd whose counter resumes from the
        // persisted boundary. Every value it hands out is past session 1's.
        let icd2 = Icd::new(CheckInCounter::new(0, EPOCH), mode());
        icd2.load_counter(&mut kv, EPOCH, &mut buf).unwrap();
        assert!(icd2.next_counter() > last_used);
    }
}
