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
//! - [`Icd::run`] sends a Check-In (resolved over mDNS, sent sessionlessly) to
//!   every registered client whose subscription is lost, whenever a LIT wakes
//!   up from idle mode.
//! - [`Icd`] also runs the ICD *power mode* state machine ([`IcdPowerMode`]):
//!   active mode after boot, after network activity, on a `StayActiveRequest`,
//!   on a user trigger and while a commissioning window is open; idle mode
//!   otherwise, for at most `IdleModeDuration`. The handler's `run` hook drives
//!   it and sends the Check-Ins whenever a Long-Idle-Time ICD wakes up from idle
//!   mode. Network drivers *follow* the state machine through
//!   [`Icd::net_params`] / [`Icd::wait_net_changed`] - e.g. a Thread driver maps the
//!   polling interval onto the Sleepy End Device poll period - and the
//!   application consults [`Icd::power_mode`] / [`Icd::idle_until`] to decide
//!   whether, and how deeply, the MCU may sleep.

use core::num::NonZeroU8;

use core::pin::pin;

use embassy_futures::select::{select, select3, Either, Either3};
use embassy_time::{with_timeout, Duration, Instant, Timer};

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

/// The slowest polling interval a Short-Idle-Time ICD may use, in milliseconds
/// (`SIT_ICD_SLOW_POLL_MAX` in the spec).
///
/// A LIT-capable device without any registered Check-In client operates as SIT
/// and is capped to this as well.
pub const SIT_SLOW_POLL_MAX_MS: u32 = 15_000;

/// The fast (active mode) polling interval used when `BasicInfoConfig::sai` is
/// not set: the `SESSION_ACTIVE_INTERVAL` default.
pub const DEFAULT_FAST_POLL_MS: u32 = 300;

/// The slow (idle mode) polling interval used when `BasicInfoConfig::sii` is
/// not set.
pub const DEFAULT_SLOW_POLL_MS: u32 = SIT_SLOW_POLL_MAX_MS;

/// How long one Check-In send (mDNS resolution included) may take before it is
/// abandoned, so that a client that cannot be resolved does not keep the device
/// awake.
const CHECK_IN_TIMEOUT: Duration = Duration::from_secs(5);

/// The buffer for one Check-In message: nonce + counter + MIC plus the
/// 2-byte `ActiveModeThreshold` application data, rounded up.
const CHECK_IN_BUF_LEN: usize = 64;

/// The ICD power mode.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum IcdPowerMode {
    /// The device is responsive: it polls fast and must not sleep deeply.
    Active,
    /// The device is idle: it polls slowly and may sleep as deeply as its
    /// state permits.
    Idle,
}

/// The network-facing parameters of the ICD power state at a given moment.
///
/// Network drivers re-read this whenever [`Icd::wait_net_changed`] resolves.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IcdNetParams {
    /// The current power mode.
    pub power_mode: IcdPowerMode,
    /// The operating mode (`SIT` or `LIT`) the cluster reports.
    pub operating_mode: OperatingModeEnum,
    /// The polling interval to use right now, in milliseconds: the fast one
    /// while active, the (SIT-capped) slow one while idle.
    pub poll_interval_ms: u32,
    /// The slowest polling interval the device will ever ask for, in
    /// milliseconds. Drivers size their link keep-alives (e.g. the Thread
    /// child timeout) from it.
    pub max_poll_interval_ms: u32,
}

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
    /// The current power mode.
    power_mode: IcdPowerMode,
    /// While active: the instant the active window ends unless extended
    /// (the `StayActiveRequest` deadline is tracked separately above).
    active_until: Instant,
    /// While idle: the instant idle mode ends by itself (`IdleModeDuration`).
    idle_until: Instant,
    /// Whether a commissioning window is open, which keeps the device active.
    comm_window_open: bool,
    /// The fast (active mode) polling interval, in milliseconds.
    fast_poll_ms: u32,
    /// The configured slow (idle mode) polling interval, in milliseconds
    /// (before the SIT cap).
    slow_poll_ms: u32,
}

impl IcdState {
    const fn new(counter: CheckInCounter) -> Self {
        Self {
            clients: Vec::new(),
            counter,
            stay_active_until: None,
            power_mode: IcdPowerMode::Active,
            active_until: Instant::MIN,
            idle_until: Instant::MIN,
            comm_window_open: false,
            fast_poll_ms: DEFAULT_FAST_POLL_MS,
            slow_poll_ms: DEFAULT_SLOW_POLL_MS,
        }
    }

    fn init(counter: CheckInCounter) -> impl Init<Self> {
        init!(Self {
            clients <- Vec::init(),
            counter: counter,
            stay_active_until: None,
            power_mode: IcdPowerMode::Active,
            active_until: Instant::MIN,
            idle_until: Instant::MIN,
            comm_window_open: false,
            fast_poll_ms: DEFAULT_FAST_POLL_MS,
            slow_poll_ms: DEFAULT_SLOW_POLL_MS,
        })
    }

    fn operating_mode(&self) -> OperatingModeEnum {
        if self.clients.is_empty() {
            OperatingModeEnum::SIT
        } else {
            OperatingModeEnum::LIT
        }
    }

    /// The slow polling interval in effect: the configured one, capped for
    /// SIT operation.
    fn effective_slow_poll_ms(&self) -> u32 {
        match self.operating_mode() {
            OperatingModeEnum::SIT => self.slow_poll_ms.min(SIT_SLOW_POLL_MAX_MS),
            OperatingModeEnum::LIT => self.slow_poll_ms,
        }
    }

    fn net_params(&self) -> IcdNetParams {
        IcdNetParams {
            power_mode: self.power_mode,
            operating_mode: self.operating_mode(),
            poll_interval_ms: match self.power_mode {
                IcdPowerMode::Active => self.fast_poll_ms,
                IcdPowerMode::Idle => self.effective_slow_poll_ms(),
            },
            max_poll_interval_ms: self.slow_poll_ms,
        }
    }

    /// The deadline the active window stays open until, considering every
    /// reason to be active: the own deadline (boot, activity, nudges) and the
    /// `StayActiveRequest` one.
    fn active_deadline(&self) -> Instant {
        self.active_until
            .max(self.stay_active_until.unwrap_or(Instant::MIN))
    }

    /// Extend the active window to at least `duration` from now, entering
    /// active mode if idle.
    fn extend_active(&mut self, duration: Duration) -> ActiveExtension {
        let deadline = Instant::now() + duration;

        let mode_changed = if self.power_mode != IcdPowerMode::Active {
            self.power_mode = IcdPowerMode::Active;
            true
        } else {
            false
        };

        let deadline_moved = if deadline > self.active_until {
            self.active_until = deadline;
            true
        } else {
            false
        };

        ActiveExtension {
            mode_changed,
            deadline_moved,
        }
    }
}

/// What extending the active window ([`IcdState::extend_active`]) did.
///
/// The observers (the network driver, the application) are told about the
/// first alone - the deadline is the state machine's own business - while the
/// state machine has to re-read its state on either.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ActiveExtension {
    /// The device was idle and is active now.
    mode_changed: bool,
    /// The active deadline moved out.
    deadline_moved: bool,
}

impl ActiveExtension {
    fn any(self) -> bool {
        self.mode_changed || self.deadline_moved
    }
}

/// The shared ICD state: the registrations, the Check-In counter, the
/// `StayActiveRequest` deadline and the power mode state machine, all behind a
/// single lock.
///
/// The application owns one instance and lends it to its [`IcdMgmtHandler`]
/// (which mutates the registrations and drives the state machine from its `run`
/// hook), to its network driver (which follows [`net_params`](Self::net_params))
/// and to its own sleep logic (which consults [`power_mode`](Self::power_mode)
/// and [`idle_until`](Self::idle_until)).
pub struct Icd {
    state: Mutex<RefCell<IcdState>>,
    /// The advertised mode timings; `active_mode_threshold_ms` is also the
    /// Check-In application data.
    mode: IcdModeConfig,
    /// Signalled whenever the power mode or the net params may have changed.
    /// Single waiter: the network driver ([`wait_net_changed`](Self::wait_net_changed)).
    net_changed: Notification,
    /// Signalled whenever the power mode or the net params may have changed.
    /// Single waiter: the application ([`wait_power_changed`](Self::wait_power_changed)).
    power_changed: Notification,
    /// Signalled by the events the power mode loop has to react to.
    /// Single waiter: the loop itself.
    nudged: Notification,
}

impl Icd {
    /// Create the ICD state from the Check-In counter's persistence epoch and
    /// the mode timings.
    ///
    /// `epoch` is how far ahead of the live counter the persisted boundary is
    /// kept - i.e. how many Check-Ins may be sent between two flash writes, and
    /// equally how far the counter jumps forward across a restart. It must be
    /// non-zero.
    ///
    /// # Panics
    ///
    /// Panics if `epoch` is zero.
    pub const fn new(epoch: u32, mode: IcdModeConfig) -> Self {
        Self {
            state: Mutex::new(RefCell::new(IcdState::new(CheckInCounter::new(0, epoch)))),
            mode,
            net_changed: Notification::new(),
            power_changed: Notification::new(),
            nudged: Notification::new(),
        }
    }

    /// An in-place initializer, mirroring [`Self::new`]. Prefer this over `new`
    /// to avoid the registration array transiting the stack.
    ///
    /// # Panics
    ///
    /// Panics if `epoch` is zero.
    pub fn init(epoch: u32, mode: IcdModeConfig) -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(IcdState::init(CheckInCounter::new(0, epoch)))),
            mode: mode,
            net_changed <- Notification::init(),
            power_changed <- Notification::init(),
            nudged <- Notification::init(),
        })
    }

    /// Re-seed the Check-In counter from `start`, keeping the epoch this `Icd`
    /// was constructed with, and return the boundary that must be persisted.
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

    /// Whether there are no registrations.
    #[cfg(test)]
    fn registrations_is_empty(&self) -> bool {
        self.registrations_len() == 0
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

    /// The current operating mode: `LIT` while any client is registered,
    /// otherwise `SIT`.
    ///
    /// This is the value of the `OperatingMode` attribute and of the `ICD`
    /// operational DNS-SD TXT key. It changes only when the registration set
    /// transitions empty↔non-empty; [`wait_net_changed`](Self::wait_net_changed)
    /// resolves when it does.
    pub fn operating_mode(&self) -> OperatingModeEnum {
        self.state.lock(|s| s.borrow().operating_mode())
    }

    /// Register a client, or update the existing registration with the same
    /// `(fab_idx, check_in_node_id)`.
    ///
    /// Returns `Err(ResourceExhausted)` if a *new* entry would exceed the
    /// per-fabric limit ([`CLIENTS_PER_FABRIC`]).
    fn register(&self, registration: MonitoringRegistration) -> Result<(), Error> {
        // The first registration flips the operating mode (SIT -> LIT), which
        // the network driver follows; a further one, or an update, is nothing
        // it needs to hear about.
        let flipped = self.state.lock(|s| -> Result<bool, Error> {
            let clients = &mut s.borrow_mut().clients;

            let was_empty = clients.is_empty();

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

            Ok(was_empty)
        })?;

        if flipped {
            self.notify_net_changed();
            self.nudged.notify();
        }

        Ok(())
    }

    /// Remove the registration for `(fab_idx, check_in_node_id)`.
    ///
    /// Returns `Err(NotFound)` if there is no such registration.
    fn unregister(&self, fab_idx: NonZeroU8, check_in_node_id: u64) -> Result<(), Error> {
        let (removed, flipped) = self.state.lock(|s| {
            let clients = &mut s.borrow_mut().clients;
            let before = clients.len();
            clients.retain(|c| !(c.fab_idx == fab_idx && c.check_in_node_id == check_in_node_id));

            let removed = clients.len() != before;

            // Removing the last registration flips the operating mode (LIT -> SIT).
            (removed, removed && clients.is_empty())
        });

        if !removed {
            Err(ErrorCode::NotFound)?;
        }

        if flipped {
            self.notify_net_changed();
            self.nudged.notify();
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
        let (removed, flipped) = self.state.lock(|s| {
            let clients = &mut s.borrow_mut().clients;
            let before = clients.len();
            clients.retain(|c| c.fab_idx != fab_idx);

            let removed = clients.len() != before;

            // Removing the last registration flips the operating mode (LIT -> SIT).
            (removed, removed && clients.is_empty())
        });

        if flipped {
            self.notify_net_changed();
            self.nudged.notify();
        }

        removed
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

    // --- Stay-active deadline ---

    /// The instant until which a client has asked this device to stay active via
    /// `StayActiveRequest`, or `None` if no such request is outstanding.
    #[cfg(test)]
    fn active_until(&self) -> Option<Instant> {
        self.state.lock(|s| s.borrow().stay_active_until)
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

        let (deadline, mode_changed) = self.state.lock(|s| {
            let mut s = s.borrow_mut();

            let deadline = s
                .stay_active_until
                .map_or(requested, |current| current.max(requested));
            s.stay_active_until = Some(deadline);

            // Asked to stay active, so be active - which the device normally is
            // already, the request having arrived over the network.
            let mode_changed = if s.power_mode != IcdPowerMode::Active {
                s.power_mode = IcdPowerMode::Active;
                true
            } else {
                false
            };

            (deadline, mode_changed)
        });

        if mode_changed {
            self.notify_power_changed();
        }

        // The state machine has a new deadline to wait for either way.
        self.nudged.notify();

        // Remaining time to the deadline (0 if it somehow already passed).
        deadline.saturating_duration_since(now).as_millis() as u32
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
        kv.store(ICD_CHECK_IN_COUNTER_KEY, &value.to_le_bytes(), buf)
    }

    /// Re-hydrate the ICD state from `kv` - the registrations and the Check-In
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

        self.state.lock(|s| s.borrow_mut().clients = clients);

        let start = match kv.load(ICD_CHECK_IN_COUNTER_KEY, buf)? {
            Some(data) => u32::from_le_bytes(data.try_into().map_err(|_| ErrorCode::Invalid)?),
            // First boot (or a cleared store): start somewhere random rather
            // than at a fixed value every device shares.
            None => Self::random_counter_start(crypto)?,
        };

        let boundary = self.reseed_counter(start);

        kv.store(ICD_CHECK_IN_COUNTER_KEY, &boundary.to_le_bytes(), buf)
    }

    /// Reset the ICD state to factory defaults and remove both persisted blobs
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
        let had_registrations = self.state.lock(|s| {
            let clients = &mut s.borrow_mut().clients;

            let had = !clients.is_empty();
            clients.clear();

            had
        });

        kv.remove(ICD_REGISTERED_CLIENTS_KEY, buf)?;
        kv.remove(ICD_CHECK_IN_COUNTER_KEY, buf)?;

        self.reseed_counter(Self::random_counter_start(crypto)?);

        // Dropping the last registration flips the operating mode to SIT, which
        // the network driver follows.
        if had_registrations {
            self.notify_net_changed();
            self.nudged.notify();
        }

        Ok(())
    }

    // --- Power mode ---

    /// The current power mode.
    pub fn power_mode(&self) -> IcdPowerMode {
        self.state.lock(|s| s.borrow().power_mode)
    }

    /// The current network-facing parameters (power mode, operating mode and
    /// polling interval).
    pub fn net_params(&self) -> IcdNetParams {
        self.state.lock(|s| s.borrow().net_params())
    }

    /// While idle: the instant idle mode ends by itself (`IdleModeDuration`
    /// after it began), i.e. how long the application may sleep before the
    /// device has to be active again. `None` while active.
    ///
    /// A device that deep-sleeps and reboots on wake-up does not observe that
    /// transition; it simply comes back active. The slow polling interval
    /// still has to be honored while asleep - a Thread SED polls its parent
    /// only while awake - so such an application should not sleep longer than
    /// [`net_params`](Self::net_params)`.poll_interval_ms` either.
    pub fn idle_until(&self) -> Option<Instant> {
        self.state.lock(|s| {
            let s = s.borrow();

            matches!(s.power_mode, IcdPowerMode::Idle).then_some(s.idle_until)
        })
    }

    /// Wait until the net params changed - the power mode, the operating mode
    /// or the polling intervals - then re-read them.
    ///
    /// For the *network driver* (the one following
    /// [`net_params`](Self::net_params)): a single-waiter notification, so
    /// exactly one task should wait on it. The application has its own,
    /// [`wait_power_changed`](Self::wait_power_changed).
    pub async fn wait_net_changed(&self) {
        self.net_changed.wait().await
    }

    /// Wait until the power mode changed, then re-read it.
    ///
    /// For the *application* (the one deciding whether the MCU may sleep): a
    /// single-waiter notification, so exactly one task should wait on it -
    /// including through [`wait_idle`](Self::wait_idle) and
    /// [`wait_active`](Self::wait_active).
    pub async fn wait_power_changed(&self) {
        self.power_changed.wait().await
    }

    /// Wait until the device is in idle mode (see [`wait_power_changed`](Self::wait_power_changed)).
    pub async fn wait_idle(&self) {
        while self.power_mode() != IcdPowerMode::Idle {
            self.wait_power_changed().await;
        }
    }

    /// Wait until the device is in active mode (see [`wait_power_changed`](Self::wait_power_changed)).
    pub async fn wait_active(&self) {
        while self.power_mode() != IcdPowerMode::Active {
            self.wait_power_changed().await;
        }
    }

    /// Announce a power mode change: to the application, and to the network
    /// driver, whose net params changed with it.
    fn notify_power_changed(&self) {
        self.net_changed.notify();
        self.power_changed.notify();
    }

    /// Announce a net params change that leaves the power mode alone (the
    /// operating mode, the polling intervals): to the network driver only.
    fn notify_net_changed(&self) {
        self.net_changed.notify();
    }

    /// Note network activity: keep the device active for at least
    /// `ActiveModeThreshold`, entering active mode if it was idle.
    ///
    /// The `run` loop feeds the transport's own activity here; the application
    /// may call it as well for traffic the transport does not see.
    pub fn network_activity(&self) {
        self.extend_active_for(Duration::from_millis(
            self.mode.active_mode_threshold_ms as u64,
        ));
    }

    /// Ask the device to be active for (at least) `ActiveModeDuration` from
    /// now: on a user trigger (the `UserActiveModeTrigger` the cluster
    /// advertises), or when the application is about to send data on its own
    /// initiative.
    pub fn request_active(&self) {
        self.extend_active_for(Duration::from_millis(
            self.mode.active_mode_duration_ms as u64,
        ));
    }

    /// Ask the device to be active for (at least) `duration` from now.
    pub fn request_active_for(&self, duration: Duration) {
        self.extend_active_for(duration);
    }

    fn extend_active_for(&self, duration: Duration) {
        let extension = self.state.lock(|s| s.borrow_mut().extend_active(duration));

        // Every message received moves the deadline out, and neither the
        // network driver nor the application has anything to do about that;
        // the state machine re-arms its timer on the nudge.
        if extension.mode_changed {
            self.notify_power_changed();
        }

        if extension.any() {
            self.nudged.notify();
        }
    }

    /// Record whether a commissioning window is open: an open window means the
    /// device has to be reachable, so it (re)enters active mode and stays
    /// there until the window closes.
    fn set_comm_window_open(&self, open: bool) {
        let changed = self.state.lock(|s| {
            let mut s = s.borrow_mut();

            if s.comm_window_open == open {
                return None;
            }

            s.comm_window_open = open;

            let mode_changed = open && s.extend_active(Duration::from_millis(0)).mode_changed;

            Some(mode_changed)
        });

        if let Some(mode_changed) = changed {
            if mode_changed {
                self.notify_power_changed();
            }

            // The state machine ignores or honors the deadline depending on the window.
            self.nudged.notify();
        }
    }

    /// Set the fast (active) and slow (idle) polling intervals.
    fn set_poll_intervals(&self, fast_poll_ms: u32, slow_poll_ms: u32) {
        let changed = self.state.lock(|s| {
            let mut s = s.borrow_mut();

            let changed = s.fast_poll_ms != fast_poll_ms || s.slow_poll_ms != slow_poll_ms;

            s.fast_poll_ms = fast_poll_ms;
            s.slow_poll_ms = slow_poll_ms;

            changed
        });

        if changed {
            self.notify_net_changed();
        }
    }

    /// Run the power mode state machine. Driven by the handler's `run` hook.
    ///
    /// - takes the polling intervals from the advertised `SAI` / `SII` of the
    ///   node's `BasicInfoConfig`;
    /// - starts in active mode for `ActiveModeDuration`, as a freshly booted
    ///   ICD does, and sends the Check-Ins of a LIT right away;
    /// - feeds the transport's activity and the commissioning window state in;
    /// - expires the active window into idle mode, wakes up from idle mode
    ///   after `IdleModeDuration`, and sends the Check-Ins on every such wake-up;
    /// - sends them as well as soon as a report to a subscriber fails while the
    ///   device is active: that client may have lost its subscription, and is
    ///   better nudged now than on the next wake-up.
    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        let matter = ctx.matter();
        let transport = matter.transport();

        let dev_det = matter.dev_det();
        self.set_poll_intervals(
            dev_det.sai.unwrap_or(DEFAULT_FAST_POLL_MS),
            dev_det.sii.unwrap_or(DEFAULT_SLOW_POLL_MS),
        );

        self.set_comm_window_open(matter.comm_window_state().is_open());
        self.request_active();

        let mut activity = pin!(async {
            loop {
                transport.wait_activity().await;
                self.network_activity();
            }
        });

        let mut comm_window = pin!(async {
            loop {
                transport.wait_comm_window_changed().await;
                self.set_comm_window_open(matter.comm_window_state().is_open());
            }
        });

        let mut duty = pin!(self.run_power_mode(&ctx));

        match select3(&mut activity, &mut comm_window, &mut duty).await {
            Either3::Third(result) => result,
            _ => unreachable!(),
        }
    }

    /// The idle <-> active loop.
    async fn run_power_mode(&self, ctx: &impl HandlerContext) -> Result<(), Error> {
        let stats = ctx.im_stats();

        // A LIT that (re)starts is waking up from its sleep, as far as its
        // clients are concerned.
        self.send_check_ins(ctx).await?;

        loop {
            match self.power_mode() {
                IcdPowerMode::Active => {
                    // Stay active until the active deadline - unless a report to
                    // a subscriber fails meanwhile. That client may well have lost
                    // its subscription (it no longer counts as subscribed for the
                    // Check-In, see `ImStats::has_subscription_for`), so nudge the
                    // registered clients that lost touch right away, while awake,
                    // and stay awake long enough for them to come back.
                    if let Either::Second(()) =
                        select(self.run_active(), stats.wait_report_failed()).await
                    {
                        self.request_active();
                        self.send_check_ins(ctx).await?;
                    }
                }
                IcdPowerMode::Idle => {
                    if self.run_idle().await {
                        self.send_check_ins(ctx).await?;
                    }
                }
            }
        }
    }

    /// Stay in active mode until the active deadline passes without being
    /// extended, then switch to idle mode.
    async fn run_active(&self) {
        loop {
            let (deadline, comm_window_open) = self.state.lock(|s| {
                let s = s.borrow();

                (s.active_deadline(), s.comm_window_open)
            });

            if comm_window_open {
                // Commissionable: stay active until the window closes, whatever
                // the deadline says.
                self.nudged.wait().await;
                continue;
            }

            if let Either::Second(()) = select(Timer::at(deadline), self.nudged.wait()).await {
                // Something extended the deadline (or closed the window): re-read.
                continue;
            }

            // The deadline might have moved meanwhile, so re-check under the
            // lock before switching.
            let switched = self.state.lock(|s| {
                let mut s = s.borrow_mut();

                if s.comm_window_open || s.active_deadline() > Instant::now() {
                    return false;
                }

                s.power_mode = IcdPowerMode::Idle;
                s.idle_until =
                    Instant::now() + Duration::from_secs(self.mode.idle_mode_duration_s as u64);

                true
            });

            if switched {
                info!("ICD: idle mode");
                self.notify_power_changed();
                return;
            }
        }
    }

    /// Stay in idle mode until `IdleModeDuration` elapses (returning `true`: a
    /// wake-up on the device's own schedule) or until a nudge has switched the
    /// device to active mode already (returning `false`).
    async fn run_idle(&self) -> bool {
        loop {
            let (idle_until, power_mode) = self.state.lock(|s| {
                let s = s.borrow();

                (s.idle_until, s.power_mode)
            });

            if power_mode != IcdPowerMode::Idle {
                return false;
            }

            if let Either::Second(()) = select(Timer::at(idle_until), self.nudged.wait()).await {
                // A nudge - either it switched us to active mode (checked at
                // the top of the loop), or the operating mode changed, which
                // `changed` already announced.
                continue;
            }

            let woke = self.state.lock(|s| {
                let mut s = s.borrow_mut();

                if s.power_mode != IcdPowerMode::Idle {
                    return false;
                }

                s.power_mode = IcdPowerMode::Active;
                s.active_until = Instant::now()
                    + Duration::from_millis(self.mode.active_mode_duration_ms as u64);

                true
            });

            if woke {
                info!("ICD: active mode (idle period elapsed)");
                self.notify_power_changed();
                return true;
            }
        }
    }

    /// Send a Check-In to every registered client whose monitored subject has
    /// no live subscription, then advance (and, on an epoch boundary, persist)
    /// the Check-In counter.
    ///
    /// Best-effort per client, with a timeout per send so that an unresolvable
    /// client cannot keep the device awake; only a counter persistence failure
    /// is an error.
    async fn send_check_ins(&self, ctx: &impl HandlerContext) -> Result<(), Error> {
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

    // --- Sending Check-In messages ---

    /// Send a Check-In message to the registered client `(fab_idx, node_id)`,
    /// using the given counter value.
    ///
    /// A per-client convenience over [`CheckIn::send_to`]; it looks up the
    /// client's key and sends with the ICD application data (the
    /// `ActiveModeThreshold`). It does *not* advance the counter — the caller
    /// owns that so a batch can share one value (see `send_check_ins`).
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

        let app_data = self.mode.active_mode_threshold_ms.to_le_bytes();

        CheckIn::new(key.reference())
            .send_to(matter, crypto, fab_idx, node_id, counter, &app_data, buf)
            .await
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
    fn sync_icd_mode(&self, ctx: &impl HandlerContext) {
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

    fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        match op {
            LifecycleOp::Startup => {
                ctx.kv()
                    .access(|store, buf| self.icd.load_persist(ctx.crypto(), store, buf))?;

                // Seed the advertised operating mode from the reloaded
                // registration set, so a client registered before the reboot
                // keeps the device advertising as LIT.
                self.sync_icd_mode(&ctx);

                Ok(())
            }
            LifecycleOp::FactoryReset => {
                ctx.kv()
                    .access(|store, buf| self.icd.reset_persist(ctx.crypto(), store, buf))?;

                // Every registration is gone, so the device drops back to SIT.
                self.sync_icd_mode(&ctx);

                Ok(())
            }
            LifecycleOp::FabricRemoval { fab_idx } => {
                let mode_before = self.icd.operating_mode();

                if self.icd.remove_fabric(fab_idx) {
                    self.icd.store_registrations(&ctx)?;

                    // Dropping the last LIT registration flips the operating
                    // mode to SIT - a global (not fabric-scoped) observable,
                    // so subscribers and the mDNS layer must learn about it.
                    // ICD Management is a root-node cluster, hence the fixed
                    // endpoint.
                    if self.icd.operating_mode() != mode_before {
                        ctx.notify_attr_changed(
                            ROOT_ENDPOINT_ID,
                            Self::CLUSTER.id,
                            AttributeId::OperatingMode as _,
                        );
                    }

                    self.sync_icd_mode(&ctx);
                }

                Ok(())
            }
        }
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        self.icd.run(ctx).await
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::crypto::test_only_crypto;

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
        Icd::new(10, mode())
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

    /// Whether `notification` has been signalled since it was last waited on
    /// (consuming the signal).
    fn notified(notification: &Notification) -> bool {
        use core::future::Future;
        use core::task::{Context, Poll, Waker};

        let mut wait = core::pin::pin!(notification.wait());

        matches!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(())
        )
    }

    /// Put the device in idle mode, the way `run_active` does once the active
    /// deadline passes.
    fn go_idle(icd: &Icd) {
        icd.state.lock(|s| {
            let mut s = s.borrow_mut();

            s.power_mode = IcdPowerMode::Idle;
            s.idle_until = Instant::now() + Duration::from_secs(60);
        });
    }

    #[test]
    fn activity_signals_the_observers_only_when_it_wakes_the_device() {
        let icd = icd();

        // Active from the start: more activity moves the deadline out, which
        // is the state machine's business alone.
        icd.network_activity();
        assert!(notified(&icd.nudged));
        assert!(!notified(&icd.net_changed));
        assert!(!notified(&icd.power_changed));

        go_idle(&icd);

        icd.network_activity();
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);
        assert!(notified(&icd.nudged));
        assert!(notified(&icd.net_changed));
        assert!(notified(&icd.power_changed));
    }

    #[test]
    fn stay_active_request_wakes_an_idle_device() {
        let icd = icd();
        go_idle(&icd);

        icd.extend_active(1_000);
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);
        assert!(notified(&icd.nudged));
        assert!(notified(&icd.net_changed));
        assert!(notified(&icd.power_changed));

        // Active already: a further request only moves the deadline out.
        icd.extend_active(2_000);
        assert!(notified(&icd.nudged));
        assert!(!notified(&icd.net_changed));
        assert!(!notified(&icd.power_changed));
    }

    #[test]
    fn comm_window_signals_the_observers_only_when_it_wakes_the_device() {
        let icd = icd();

        // Active already: the window changes what the state machine does with
        // the deadline, and nothing the observers see.
        icd.set_comm_window_open(true);
        assert!(notified(&icd.nudged));
        assert!(!notified(&icd.net_changed));
        assert!(!notified(&icd.power_changed));

        // No change at all.
        icd.set_comm_window_open(true);
        assert!(!notified(&icd.nudged));

        icd.set_comm_window_open(false);
        assert!(notified(&icd.nudged));
        assert!(!notified(&icd.power_changed));

        go_idle(&icd);

        icd.set_comm_window_open(true);
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);
        assert!(notified(&icd.nudged));
        assert!(notified(&icd.net_changed));
        assert!(notified(&icd.power_changed));
    }

    #[test]
    fn registrations_signal_the_network_driver_only_on_a_sit_lit_flip() {
        let icd = icd();

        // SIT -> LIT
        icd.register(reg(1, 100)).unwrap();
        assert!(notified(&icd.net_changed));
        assert!(!notified(&icd.power_changed));

        // Still LIT: another client, and an update of the first one.
        icd.register(reg(1, 101)).unwrap();
        icd.register(reg(1, 100)).unwrap();
        assert!(!notified(&icd.net_changed));

        // Still LIT.
        icd.unregister(fab(1), 101).unwrap();
        assert!(!notified(&icd.net_changed));

        // LIT -> SIT
        icd.unregister(fab(1), 100).unwrap();
        assert!(notified(&icd.net_changed));
        assert!(!notified(&icd.power_changed));

        // The same over a fabric removal.
        icd.register(reg(2, 200)).unwrap();
        assert!(notified(&icd.net_changed));
        assert!(icd.remove_fabric(fab(2)));
        assert!(notified(&icd.net_changed));
        assert!(!icd.remove_fabric(fab(2)));
        assert!(!notified(&icd.net_changed));
    }

    #[test]
    fn poll_intervals_signal_the_network_driver_only_when_they_change() {
        let icd = icd();

        icd.set_poll_intervals(500, 20_000);
        assert!(notified(&icd.net_changed));
        assert!(!notified(&icd.power_changed));

        icd.set_poll_intervals(500, 20_000);
        assert!(!notified(&icd.net_changed));
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

    /// A key-aware in-memory store. The ICD state spans two keys
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
        let icd = Icd::new(10, mode());

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
        let icd = Icd::new(10, mode());

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
        let icd = Icd::new(EPOCH, mode());
        // Session 1 seeds at 100 the way `load_persist` would from a stored
        // boundary, so the expectations below stay readable.
        icd.reseed_counter(100);

        // Peeks are stable; advancing before the boundary writes nothing.
        assert_eq!(icd.next_counter(), 101);
        for _ in 0..9 {
            icd.advance_counter(&mut kv, &mut buf).unwrap();
        }
        assert_eq!(
            kv.get(ICD_CHECK_IN_COUNTER_KEY),
            None,
            "no persist before the boundary"
        );

        // Crossing the boundary persists the next one (120).
        let last_used = icd.next_counter();
        icd.advance_counter(&mut kv, &mut buf).unwrap();
        assert_eq!(last_used, 110);
        assert!(
            kv.get(ICD_CHECK_IN_COUNTER_KEY).is_some(),
            "boundary crossing must persist"
        );

        // Session 2 (a restart): a fresh Icd whose counter resumes from the
        // persisted boundary. Every value it hands out is past session 1's.
        // The epoch comes from the counter this `Icd` was built with, not from
        // the blob.
        let icd2 = Icd::new(EPOCH, mode());
        icd2.load_persist(test_only_crypto(), &mut kv, &mut buf)
            .unwrap();
        assert!(icd2.next_counter() > last_used);

        // Re-hydrating must itself persist the boundary it resumes from, or a
        // crash before the next crossing would hand out these values twice.
        let boundary = u32::from_le_bytes(
            kv.get(ICD_CHECK_IN_COUNTER_KEY)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert!(boundary >= icd2.next_counter() + EPOCH - 1);

        // Session 3 (a second restart, no traffic in session 2): still strictly
        // past every value session 2 could have used.
        let icd3 = Icd::new(EPOCH, mode());
        icd3.load_persist(test_only_crypto(), &mut kv, &mut buf)
            .unwrap();
        assert!(icd3.next_counter() > icd2.next_counter() + EPOCH - 1);
    }

    #[test]
    fn first_boot_seeds_the_counter_and_persists_a_boundary() {
        const EPOCH: u32 = 10;
        let mut kv = MemKv::default();
        let mut buf = [0u8; 256];

        // Nothing stored: the counter is seeded from a random start, and the
        // boundary it resumes from must be durable before any Check-In goes out.
        let icd = Icd::new(EPOCH, mode());
        icd.load_persist(test_only_crypto(), &mut kv, &mut buf)
            .unwrap();

        let boundary = u32::from_le_bytes(
            kv.get(ICD_CHECK_IN_COUNTER_KEY)
                .expect("a first boot must persist a boundary")
                .try_into()
                .unwrap(),
        );

        // `next()` peeks at start + 1 and the boundary sits at start + EPOCH.
        assert_eq!(boundary, icd.next_counter().wrapping_add(EPOCH - 1));
    }

    #[test]
    fn factory_reset_clears_registrations_and_both_keys() {
        let mut kv = MemKv::default();
        let mut buf = [0u8; 256];

        let icd = Icd::new(10, mode());

        icd.register(reg(1, 0x1234)).unwrap();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::LIT);

        // Seed both persisted blobs the way a running node would.
        (&mut kv)
            .store(ICD_REGISTERED_CLIENTS_KEY, b"whatever", &mut buf)
            .unwrap();
        (&mut kv)
            .store(ICD_CHECK_IN_COUNTER_KEY, &110u32.to_le_bytes(), &mut buf)
            .unwrap();

        let before_reset = icd.next_counter();

        icd.reset_persist(test_only_crypto(), &mut kv, &mut buf)
            .unwrap();

        assert!(icd.registrations_is_empty());
        assert_eq!(icd.operating_mode(), OperatingModeEnum::SIT);
        assert_eq!(kv.get(ICD_REGISTERED_CLIENTS_KEY), None);
        assert_eq!(kv.get(ICD_CHECK_IN_COUNTER_KEY), None);

        // The counter is re-seeded rather than left where it was, so the next
        // boot does not resume the decommissioned device's sequence.
        assert_ne!(icd.next_counter(), before_reset);
    }

    /// Put the ICD into idle mode directly, bypassing the async loop.
    fn force_idle(icd: &Icd) {
        icd.state.lock(|s| {
            let mut s = s.borrow_mut();

            s.power_mode = IcdPowerMode::Idle;
            s.idle_until = Instant::now() + Duration::from_secs(60);
        });
    }

    fn active_until(icd: &Icd) -> Instant {
        icd.state.lock(|s| s.borrow().active_until)
    }

    #[test]
    fn sit_caps_the_slow_poll_interval_until_a_client_registers() {
        let icd = icd();

        // The defaults, before `run` has read the advertised intervals.
        let params = icd.net_params();
        assert_eq!(params.power_mode, IcdPowerMode::Active);
        assert_eq!(params.operating_mode, OperatingModeEnum::SIT);
        assert_eq!(params.poll_interval_ms, DEFAULT_FAST_POLL_MS);
        assert_eq!(params.max_poll_interval_ms, DEFAULT_SLOW_POLL_MS);

        // A LIT-capable configuration: a slow poll far beyond the SIT cap.
        icd.set_poll_intervals(300, 900_000);
        force_idle(&icd);

        // No registered client -> operating as SIT -> capped while idle.
        let params = icd.net_params();
        assert_eq!(params.operating_mode, OperatingModeEnum::SIT);
        assert_eq!(params.poll_interval_ms, SIT_SLOW_POLL_MAX_MS);
        // ... but the driver still learns the slowest interval it may ever see.
        assert_eq!(params.max_poll_interval_ms, 900_000);

        // A registered client -> LIT -> the full interval.
        icd.register(reg(1, 100)).unwrap();
        let params = icd.net_params();
        assert_eq!(params.operating_mode, OperatingModeEnum::LIT);
        assert_eq!(params.poll_interval_ms, 900_000);

        // Back to SIT once it is gone.
        icd.unregister(fab(1), 100).unwrap();
        assert_eq!(icd.net_params().poll_interval_ms, SIT_SLOW_POLL_MAX_MS);

        // A slow interval within the cap is never raised to it.
        icd.set_poll_intervals(300, 5_000);
        assert_eq!(icd.net_params().poll_interval_ms, 5_000);
    }

    #[test]
    fn net_params_follow_the_power_mode() {
        let icd = icd();
        icd.set_poll_intervals(200, 10_000);

        assert_eq!(icd.power_mode(), IcdPowerMode::Active);
        assert_eq!(icd.net_params().poll_interval_ms, 200);
        assert!(icd.idle_until().is_none());

        force_idle(&icd);

        assert_eq!(icd.power_mode(), IcdPowerMode::Idle);
        assert_eq!(icd.net_params().poll_interval_ms, 10_000);
        assert!(icd.idle_until().is_some());
    }

    #[test]
    fn activity_and_requests_wake_the_device_and_extend_the_window() {
        let icd = icd();
        force_idle(&icd);

        // Network activity: active for at least `ActiveModeThreshold`.
        let before = Instant::now();
        icd.network_activity();
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);
        assert!(icd.idle_until().is_none());
        let after_activity = active_until(&icd);
        assert!(after_activity >= before + Duration::from_millis(500));

        // A user trigger: `ActiveModeDuration` (300 ms here) is *shorter* than the threshold,
        // so it must not pull the deadline back in.
        icd.request_active();
        assert_eq!(active_until(&icd), after_activity);

        // An explicit, longer request moves it out.
        icd.request_active_for(Duration::from_secs(5));
        assert!(active_until(&icd) >= before + Duration::from_secs(5));

        // A shorter one afterwards leaves it alone: the deadline only ever grows.
        let extended = active_until(&icd);
        icd.request_active_for(Duration::from_millis(1));
        assert_eq!(active_until(&icd), extended);
    }

    #[test]
    fn open_commissioning_window_wakes_the_device() {
        let icd = icd();
        force_idle(&icd);

        icd.set_comm_window_open(true);
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);

        // Closing it does not switch modes by itself; the loop lets the window expire.
        icd.set_comm_window_open(false);
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);

        // Idempotent: no state change, no spurious nudge.
        icd.set_comm_window_open(false);
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);
    }

    /// The two halves of the loop, driven in real time with short durations: the active
    /// window expires into idle mode, and the idle period expires back into active mode.
    #[test]
    fn active_window_expires_into_idle_and_idle_period_wakes_up() {
        let icd = Icd::new(
            10,
            IcdModeConfig {
                idle_mode_duration_s: 1,
                active_mode_duration_ms: 50,
                active_mode_threshold_ms: 50,
                ..mode()
            },
        );

        // Boot: active for `ActiveModeDuration`. `start` is taken before the request, as the
        // deadline is measured from the request.
        let start = Instant::now();
        icd.request_active();
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);

        embassy_futures::block_on(icd.run_active());

        assert_eq!(icd.power_mode(), IcdPowerMode::Idle);
        assert!(start.elapsed() >= Duration::from_millis(50));
        let idle_until = icd.idle_until().expect("idle");
        assert!(idle_until >= start + Duration::from_secs(1));

        // Idle mode ends by itself after `IdleModeDuration`: a scheduled wake-up.
        let woke = embassy_futures::block_on(icd.run_idle());

        assert!(woke);
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);
        assert!(Instant::now() >= idle_until);

        // A nudge during idle mode ends it early, and is *not* a scheduled wake-up.
        force_idle(&icd);
        icd.network_activity();
        let woke = embassy_futures::block_on(icd.run_idle());

        assert!(!woke);
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);
    }
}
