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

//! The ICD Management cluster, the ICD power mode state machine and the
//! Check-In sender.
//!
//! An Intermittently Connected Device (ICD) is either a Short Idle Time (SIT)
//! device - reachable within its `SESSION_IDLE_INTERVAL` at all times, at most
//! 15 s - or a Long Idle Time (LIT) capable one, which may stay unreachable for
//! up to its `IdleModeDuration` once a client has registered for Check-In
//! messages with it, and operates as a SIT until then. The two come in two
//! layers, so that a SIT-only device carries none of the LIT machinery:
//!
//! - [`Icd`] is the power mode state machine ([`IcdPowerMode`]) every ICD
//!   runs: active mode after boot, after network activity, on a user trigger,
//!   while work is in flight and while a commissioning window is open; idle
//!   mode otherwise, for at most `IdleModeDuration`. Network drivers *follow*
//!   it through [`Icd::net_params`] / [`Icd::wait_net_changed`] - e.g. a Thread
//!   driver maps the polling interval onto the Sleepy End Device poll period -
//!   and the application consults [`Icd::power_mode`] / [`Icd::idle_until`] to
//!   decide whether, and how deeply, the MCU may sleep.
//! - [`SitIcdMgmtHandler`] serves the cluster of a SIT-only device over an
//!   [`Icd`]: its mode timings, and nothing else.
//! - [`LitIcd`] adds what a LIT-capable device needs on top of an [`Icd`]: the
//!   client registrations, the Check-In counter, the Check-In sender and the
//!   SIT/LIT operating mode that follows the registrations.
//! - [`LitIcdMgmtHandler`] serves the cluster of a LIT-capable device over a
//!   [`LitIcd`]: the Check-In Protocol, Long Idle Time and User Active Mode
//!   Trigger features.

use core::future::Future;
use core::pin::pin;

use embassy_futures::select::{select, select3, Either, Either3};
use embassy_time::{Duration, Instant, Timer};

use crate::dm::HandlerContext;
use crate::error::Error;
use crate::im::ImStats;
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;
use crate::Matter;

pub use crate::dm::clusters::decl::icd_management::*;

pub use lit::*;
pub use sit::*;

mod lit;
mod sit;

/// The maximum stay-active duration (milliseconds) a `StayActiveRequest` will be
/// honored for — the "guaranteed" duration the device must be able to grant. A
/// request longer than this is clamped to it (though the *promised* remaining
/// time may still be longer if the deadline was already further out).
pub const STAY_ACTIVE_MAX_MS: u32 = 30_000;

/// The slowest polling interval a Short-Idle-Time ICD may use, in milliseconds
/// (`SIT_ICD_SLOW_POLL_MAX` in the spec).
///
/// A SIT-only device is capped to it, and so is a LIT-capable one while it
/// operates as a SIT: it then polls at the SIT slow poll it was created with
/// (see [`LitIcd::new`]), which may not exceed this.
pub const SIT_SLOW_POLL_MAX_MS: u32 = 15_000;

/// The fast (active mode) polling interval used when `BasicInfoConfig::sai` is
/// not set: the `SESSION_ACTIVE_INTERVAL` default.
pub const DEFAULT_FAST_POLL_MS: u32 = 300;

/// The slow (idle mode) polling interval used when `BasicInfoConfig::sii` is
/// not set.
pub const DEFAULT_SLOW_POLL_MS: u32 = SIT_SLOW_POLL_MAX_MS;

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
    /// The operating mode: always `SIT` for a SIT-only device; for a
    /// LIT-capable one, `LIT` while it operates as one.
    pub operating_mode: OperatingModeEnum,
    /// The polling interval to use right now, in milliseconds: the fast one
    /// while active, the (SIT-capped) slow one while idle.
    pub poll_interval_ms: u32,
    /// The slowest polling interval the device will ever ask for, in
    /// milliseconds. Drivers size their link keep-alives (e.g. the Thread
    /// child timeout) from it.
    pub max_poll_interval_ms: u32,
}

/// What an ICD advertises about itself, over DNS-SD and in the session
/// parameters of its CASE / PASE handshakes - and what its subscriptions are
/// paced by.
///
/// The ICD Management handler keeps [`Matter`](crate::Matter) supplied with it
/// (see [`Matter::icd_advertisement`](crate::Matter::icd_advertisement)); a node
/// that is not an ICD advertises none.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IcdAdvertisement {
    /// The `ActiveModeThreshold`, in milliseconds: the advertised
    /// `SESSION_ACTIVE_THRESHOLD` (`SAT` TXT key).
    pub active_threshold_ms: u16,
    /// The slow polling interval in effect, in milliseconds: what the device is
    /// reachable within while idle, so the least `SESSION_IDLE_INTERVAL`
    /// (`SII` TXT key) it may advertise.
    pub slow_poll_ms: u32,
    /// The current operating mode of a Long-Idle-Time-capable ICD: the `ICD`
    /// TXT key (`0` for `SIT`, `1` for `LIT`). `None` for a SIT-only ICD, which
    /// has no `ICD` key.
    pub operating_mode: Option<OperatingModeEnum>,
    /// The idle mode duration, in seconds. Subscriptions to the device pick
    /// their max interval from it, so that their reports wake the device no
    /// more often than idle mode ends anyway.
    pub idle_mode_duration_s: u32,
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

/// The interior, mutable power mode state, guarded by a single lock.
struct IcdState {
    /// The current operating mode. `SIT` unless a [`LitIcd`] says otherwise.
    operating_mode: OperatingModeEnum,
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
    /// The SIT cap on the slow polling interval, in milliseconds:
    /// [`SIT_SLOW_POLL_MAX_MS`], or less for a [`LitIcd`] configured so.
    sit_slow_poll_ms: u32,
}

impl IcdState {
    const fn new(sit_slow_poll_ms: u32) -> Self {
        Self {
            operating_mode: OperatingModeEnum::SIT,
            stay_active_until: None,
            power_mode: IcdPowerMode::Active,
            active_until: Instant::MIN,
            idle_until: Instant::MIN,
            comm_window_open: false,
            fast_poll_ms: DEFAULT_FAST_POLL_MS,
            slow_poll_ms: DEFAULT_SLOW_POLL_MS,
            sit_slow_poll_ms,
        }
    }

    /// The slow polling interval in effect: the configured one, capped to the
    /// SIT one while operating as a SIT.
    fn effective_slow_poll_ms(&self) -> u32 {
        match self.operating_mode {
            OperatingModeEnum::SIT => self.slow_poll_ms.min(self.sit_slow_poll_ms),
            OperatingModeEnum::LIT => self.slow_poll_ms,
        }
    }

    fn net_params(&self) -> IcdNetParams {
        IcdNetParams {
            power_mode: self.power_mode,
            operating_mode: self.operating_mode,
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

/// What a Long-Idle-Time-capable ICD adds to the power mode state machine: the
/// Check-Ins, sent whenever the device (re)starts, wakes up from idle mode on
/// its own schedule, or fails to report to a subscriber.
///
/// Implemented by `()` for a SIT-only device, which sends none. [`Icd::run`] is
/// generic over it, so a SIT-only build never references the Check-In code.
trait CheckIns {
    /// Whether this is a LIT-capable device: it sends Check-Ins, and advertises
    /// its operating mode over DNS-SD.
    const LIT: bool;

    /// Send a Check-In to every registered client that has lost touch with
    /// the device.
    fn send_check_ins(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>>;
}

impl<T: CheckIns> CheckIns for &T {
    const LIT: bool = T::LIT;

    fn send_check_ins(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> {
        T::send_check_ins(self, ctx)
    }
}

impl CheckIns for () {
    const LIT: bool = false;

    fn send_check_ins(&self, _ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> {
        core::future::ready(Ok(()))
    }
}

/// The ICD power mode state machine.
///
/// The application owns one instance - directly for a SIT-only device, or
/// inside its [`LitIcd`] for a LIT-capable one - and lends it to its ICD
/// Management handler (which drives the state machine from its `run` hook), to
/// its network driver (which follows [`net_params`](Self::net_params)) and to
/// its own sleep logic (which consults [`power_mode`](Self::power_mode) and
/// [`idle_until`](Self::idle_until)).
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
    /// Create the power mode state machine from the mode timings.
    pub const fn new(mode: IcdModeConfig) -> Self {
        Self::with_sit_slow_poll(mode, SIT_SLOW_POLL_MAX_MS)
    }

    /// An in-place initializer, mirroring [`Self::new`].
    pub fn init(mode: IcdModeConfig) -> impl Init<Self> {
        Self::init_with_sit_slow_poll(mode, SIT_SLOW_POLL_MAX_MS)
    }

    /// [`Self::new`], with the slow poll to cap to while operating as a SIT.
    ///
    /// # Panics
    ///
    /// Panics if `sit_slow_poll_ms` is zero or exceeds [`SIT_SLOW_POLL_MAX_MS`].
    const fn with_sit_slow_poll(mode: IcdModeConfig, sit_slow_poll_ms: u32) -> Self {
        Self::validate(sit_slow_poll_ms);

        Self {
            state: Mutex::new(RefCell::new(IcdState::new(sit_slow_poll_ms))),
            mode,
            net_changed: Notification::new(),
            power_changed: Notification::new(),
            nudged: Notification::new(),
        }
    }

    /// [`Self::init`], with the slow poll to cap to while operating as a SIT.
    ///
    /// # Panics
    ///
    /// Panics if `sit_slow_poll_ms` is zero or exceeds [`SIT_SLOW_POLL_MAX_MS`].
    fn init_with_sit_slow_poll(mode: IcdModeConfig, sit_slow_poll_ms: u32) -> impl Init<Self> {
        Self::validate(sit_slow_poll_ms);

        init!(Self {
            state: Mutex::new(RefCell::new(IcdState::new(sit_slow_poll_ms))),
            mode: mode,
            net_changed <- Notification::init(),
            power_changed <- Notification::init(),
            nudged <- Notification::init(),
        })
    }

    /// The configuration checks shared by the constructors.
    const fn validate(sit_slow_poll_ms: u32) {
        core::assert!(
            sit_slow_poll_ms > 0 && sit_slow_poll_ms <= SIT_SLOW_POLL_MAX_MS,
            "`sit_slow_poll_ms` must be in `1..=SIT_SLOW_POLL_MAX_MS`"
        );
    }

    /// The mode timings this device was configured with.
    pub const fn mode(&self) -> &IcdModeConfig {
        &self.mode
    }

    // --- Operating mode ---

    /// The current operating mode: always `SIT` for a SIT-only device; for a
    /// LIT-capable one, `LIT` while it operates as one (see [`LitIcd`]).
    ///
    /// [`wait_net_changed`](Self::wait_net_changed) resolves when it changes.
    pub fn operating_mode(&self) -> OperatingModeEnum {
        self.state.lock(|s| s.borrow().operating_mode)
    }

    /// Set the operating mode. Only a [`LitIcd`] ever does.
    fn set_operating_mode(&self, mode: OperatingModeEnum) {
        let changed = self.state.lock(|s| {
            let mut s = s.borrow_mut();

            let changed = s.operating_mode != mode;
            s.operating_mode = mode;

            changed
        });

        // The slow poll in effect changes with it, which the network driver
        // follows.
        if changed {
            self.notify_net_changed();
            self.nudged.notify();
        }
    }

    /// What the device advertises about itself as an ICD right now; the
    /// operating mode only if it is LIT-capable (`lit`).
    pub(crate) fn advertisement(&self, lit: bool) -> IcdAdvertisement {
        let (operating_mode, slow_poll_ms) = self.state.lock(|s| {
            let s = s.borrow();
            (s.operating_mode, s.effective_slow_poll_ms())
        });

        IcdAdvertisement {
            active_threshold_ms: self.mode.active_mode_threshold_ms,
            slow_poll_ms,
            operating_mode: lit.then_some(operating_mode),
            idle_mode_duration_s: self.mode.idle_mode_duration_s,
        }
    }

    /// Hand the current [`advertisement`](Self::advertisement) to `matter`,
    /// which re-publishes its mDNS records if it changed.
    fn publish_advertisement(&self, matter: &Matter, lit: bool) {
        matter.set_icd_advertisement(Some(self.advertisement(lit)));
    }

    // --- Stay-active deadline ---

    /// The instant until which a client has asked this device to stay active via
    /// `StayActiveRequest`, or `None` if no such request is outstanding.
    #[cfg(test)]
    fn stay_active_until(&self) -> Option<Instant> {
        self.state.lock(|s| s.borrow().stay_active_until)
    }

    /// Extend the stay-active deadline by `duration_ms` from now, returning the
    /// resulting remaining active time in milliseconds.
    ///
    /// The deadline only ever moves later: `deadline = max(deadline, now + d)`.
    /// So the returned value can exceed `duration_ms` if an earlier request
    /// already extended further — it is the *actual* remaining time, which is
    /// what the `StayActiveResponse` promises.
    fn stay_active(&self, duration_ms: u32) -> u32 {
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

    /// Run the power mode state machine. Driven by the ICD Management
    /// handler's `run` hook.
    ///
    /// - takes the polling intervals from the advertised `SAI` / `SII` of the
    ///   node's `BasicInfoConfig`, and has the node advertise its
    ///   `ActiveModeThreshold` as its `SAT`;
    /// - starts in active mode for `ActiveModeDuration`, as a freshly booted
    ///   ICD does, and sends the Check-Ins of a LIT right away;
    /// - feeds the transport's activity and the commissioning window state in;
    /// - expires the active window into idle mode - but not while an exchange
    ///   is open or the fail-safe is armed: work in flight keeps the device
    ///   active past its deadline - wakes up from idle mode after
    ///   `IdleModeDuration`, and sends the Check-Ins on every such wake-up;
    /// - sends them as well as soon as a report to a subscriber fails while the
    ///   device is active: that client may have lost its subscription, and is
    ///   better nudged now than on the next wake-up.
    async fn run<X: CheckIns>(&self, ctx: impl HandlerContext, check_ins: X) -> Result<(), Error> {
        let matter = ctx.matter();
        let transport = matter.transport();

        let dev_det = matter.dev_det();
        self.set_poll_intervals(
            dev_det.sai.unwrap_or(DEFAULT_FAST_POLL_MS),
            dev_det.sii.unwrap_or(DEFAULT_SLOW_POLL_MS),
        );

        // The slow poll in effect may have changed with them.
        self.publish_advertisement(matter, X::LIT);

        if !X::LIT && dev_det.sii.is_some_and(|sii| sii > SIT_SLOW_POLL_MAX_MS) {
            // A SIT polls at most every `SIT_SLOW_POLL_MAX_MS`, and does so
            // here too; but it advertises what it is configured with.
            warn!(
                "ICD: a SIT device advertises an SII above {} ms",
                SIT_SLOW_POLL_MAX_MS
            );
        }

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

        let mut duty = pin!(self.run_power_mode(&ctx, check_ins));

        match select3(&mut activity, &mut comm_window, &mut duty).await {
            Either3::Third(result) => result,
            _ => unreachable!(),
        }
    }

    /// The idle <-> active loop.
    async fn run_power_mode<X: CheckIns>(
        &self,
        ctx: impl HandlerContext,
        check_ins: X,
    ) -> Result<(), Error> {
        let matter = ctx.matter();
        let stats = ctx.im_stats();

        // Work in flight that keeps the device active past its deadline, as the
        // spec has it ("while there are Exchanges active, a node typically will
        // remain in Active mode"): an open exchange, or the fail-safe armed by a
        // commissioning or a network update in progress.
        let busy = || matter.is_icd_busy();

        // A LIT that (re)starts is waking up from its sleep, as far as its
        // clients are concerned.
        check_ins.send_check_ins(&ctx).await?;

        loop {
            match self.power_mode() {
                IcdPowerMode::Active if X::LIT => {
                    // Stay active until the active deadline - unless a report to
                    // a subscriber fails meanwhile. That client may well have lost
                    // its subscription (it no longer counts as subscribed for the
                    // Check-In, see `ImStats::has_subscription_for`), so nudge the
                    // registered clients that lost touch right away, while awake,
                    // and stay awake long enough for them to come back.
                    if let Either::Second(()) = select(
                        self.run_active(&busy, || stats.next_keep_alive_at()),
                        stats.wait_report_failed(),
                    )
                    .await
                    {
                        self.request_active();
                        check_ins.send_check_ins(&ctx).await?;
                    }
                }
                IcdPowerMode::Active => self.run_active(&busy, || stats.next_keep_alive_at()).await,
                IcdPowerMode::Idle => {
                    if self.run_idle().await {
                        check_ins.send_check_ins(&ctx).await?;
                    }
                }
            }
        }
    }

    /// Stay in active mode until the active deadline passes without being
    /// extended, then switch to idle mode - once `busy` no longer holds.
    ///
    /// `busy` is whatever work in flight has to keep the device active past its
    /// deadline (an open exchange, an armed fail-safe). Nothing signals the end
    /// of such work, so it is looked at again every `ActiveModeThreshold`.
    ///
    /// `next_keep_alive_at` is when the earliest subscription next needs a
    /// report to keep alive: idle mode ends by then at the latest, so that the
    /// subscriptions keep alive with the device's own wake-up rather than wake it
    /// up themselves - whatever woke the device up last.
    async fn run_active(
        &self,
        mut busy: impl FnMut() -> bool,
        next_keep_alive_at: impl Fn() -> Option<Instant>,
    ) {
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

            if busy() {
                // The deadline passed with work still in flight, which idle mode
                // would cut short: look again in a while (or at the next nudge).
                select(Timer::after(self.busy_recheck()), self.nudged.wait()).await;
                continue;
            }

            // The deadline might have moved meanwhile, so re-check under the
            // lock before switching.
            let switched = self.state.lock(|s| {
                let mut s = s.borrow_mut();

                if s.comm_window_open || s.active_deadline() > Instant::now() {
                    return false;
                }

                let now = Instant::now();
                let idle_until = now + Duration::from_secs(self.mode.idle_mode_duration_s as u64);

                s.power_mode = IcdPowerMode::Idle;
                s.idle_until = next_keep_alive_at().map_or(idle_until, |at| at.min(idle_until));

                true
            });

            if switched {
                info!("ICD: idle mode");
                self.notify_power_changed();
                return;
            }
        }
    }

    /// How long to wait before looking again at work in flight that keeps the
    /// device active past its deadline: `ActiveModeThreshold`, the granularity
    /// the device keeps its active window at anyway - floored, as a threshold of
    /// `0` is allowed and must not turn the wait into a busy loop.
    fn busy_recheck(&self) -> Duration {
        const MIN_MS: u64 = 100;

        Duration::from_millis((self.mode.active_mode_threshold_ms as u64).max(MIN_MS))
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
                // `set_operating_mode` already announced.
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
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    pub(super) fn mode() -> IcdModeConfig {
        IcdModeConfig {
            idle_mode_duration_s: 60,
            active_mode_duration_ms: 300,
            active_mode_threshold_ms: 500,
            user_active_mode_trigger_hint: 0,
            user_active_mode_trigger_instruction: "",
        }
    }

    fn icd() -> Icd {
        Icd::new(mode())
    }

    /// Whether `notification` has been signalled since it was last waited on
    /// (consuming the signal).
    pub(super) fn notified(notification: &Notification) -> bool {
        use core::future::Future;
        use core::task::{Context, Poll, Waker};

        let mut wait = core::pin::pin!(notification.wait());

        matches!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(())
        )
    }

    /// Put the device in idle mode directly, the way `run_active` does once
    /// the active deadline passes.
    pub(super) fn force_idle(icd: &Icd) {
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
    fn activity_signals_the_observers_only_when_it_wakes_the_device() {
        let icd = icd();

        // Active from the start: more activity moves the deadline out, which
        // is the state machine's business alone.
        icd.network_activity();
        assert!(notified(&icd.nudged));
        assert!(!notified(&icd.net_changed));
        assert!(!notified(&icd.power_changed));

        force_idle(&icd);

        icd.network_activity();
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);
        assert!(notified(&icd.nudged));
        assert!(notified(&icd.net_changed));
        assert!(notified(&icd.power_changed));
    }

    #[test]
    fn stay_active_request_wakes_an_idle_device() {
        let icd = icd();
        force_idle(&icd);

        icd.stay_active(1_000);
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);
        assert!(notified(&icd.nudged));
        assert!(notified(&icd.net_changed));
        assert!(notified(&icd.power_changed));

        // Active already: a further request only moves the deadline out.
        icd.stay_active(2_000);
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

        force_idle(&icd);

        icd.set_comm_window_open(true);
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);
        assert!(notified(&icd.nudged));
        assert!(notified(&icd.net_changed));
        assert!(notified(&icd.power_changed));
    }

    #[test]
    fn operating_mode_signals_the_network_driver_only_when_it_changes() {
        let icd = icd();
        assert_eq!(icd.operating_mode(), OperatingModeEnum::SIT);

        icd.set_operating_mode(OperatingModeEnum::SIT);
        assert!(!notified(&icd.net_changed));

        icd.set_operating_mode(OperatingModeEnum::LIT);
        assert!(notified(&icd.net_changed));
        assert!(!notified(&icd.power_changed));

        icd.set_operating_mode(OperatingModeEnum::LIT);
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
    fn stay_active_combines_with_max_and_reports_remaining() {
        let icd = icd();

        // No request yet: no stay-active deadline.
        assert!(icd.stay_active_until().is_none());

        // A request sets the deadline and promises ~its duration.
        let promised = icd.stay_active(STAY_ACTIVE_MAX_MS);
        assert!(promised <= STAY_ACTIVE_MAX_MS);
        assert!(promised > STAY_ACTIVE_MAX_MS - 1_000, "promised {promised}");
        let deadline = icd.stay_active_until().expect("deadline now set");

        // A shorter request does NOT shrink the deadline (max-combine): it still
        // promises ~the earlier, longer remaining time, not its own 1s.
        let promised2 = icd.stay_active(1_000);
        assert!(
            promised2 > 1_000,
            "shorter request must not shrink: {promised2}"
        );
        assert_eq!(
            icd.stay_active_until(),
            Some(deadline),
            "deadline unchanged"
        );

        // A longer request DOES push the deadline out.
        icd.stay_active(2 * STAY_ACTIVE_MAX_MS);
        assert!(icd.stay_active_until().unwrap() > deadline);
    }

    #[test]
    fn stay_active_request_clamps_to_the_guaranteed_max() {
        // The clamp lives in the command handler, not `stay_active` — verify it
        // via the same `.min(STAY_ACTIVE_MAX_MS)` the handler applies.
        let icd = icd();

        let requested = STAY_ACTIVE_MAX_MS + 5_000;
        let promised = icd.stay_active(requested.min(STAY_ACTIVE_MAX_MS));
        assert!(promised <= STAY_ACTIVE_MAX_MS, "must clamp: {promised}");
    }

    #[test]
    fn sit_caps_the_slow_poll_interval() {
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

        // Operating as SIT -> capped while idle.
        let params = icd.net_params();
        assert_eq!(params.operating_mode, OperatingModeEnum::SIT);
        assert_eq!(params.poll_interval_ms, SIT_SLOW_POLL_MAX_MS);
        // ... but the driver still learns the slowest interval it may ever see.
        assert_eq!(params.max_poll_interval_ms, 900_000);

        // Operating as LIT -> the full interval.
        icd.set_operating_mode(OperatingModeEnum::LIT);
        let params = icd.net_params();
        assert_eq!(params.operating_mode, OperatingModeEnum::LIT);
        assert_eq!(params.poll_interval_ms, 900_000);

        // Back to SIT.
        icd.set_operating_mode(OperatingModeEnum::SIT);
        assert_eq!(icd.net_params().poll_interval_ms, SIT_SLOW_POLL_MAX_MS);

        // A slow interval within the cap is never raised to it.
        icd.set_poll_intervals(300, 5_000);
        assert_eq!(icd.net_params().poll_interval_ms, 5_000);
    }

    /// A device may poll faster than the SIT maximum while operating as a SIT;
    /// the advertisement follows the poll in effect.
    #[test]
    fn a_configured_sit_poll_below_the_maximum_is_used_while_sit() {
        let icd = Icd::with_sit_slow_poll(mode(), 5_000);

        icd.set_poll_intervals(300, 900_000);
        force_idle(&icd);

        assert_eq!(icd.net_params().poll_interval_ms, 5_000);
        assert_eq!(
            icd.advertisement(true),
            IcdAdvertisement {
                active_threshold_ms: mode().active_mode_threshold_ms,
                slow_poll_ms: 5_000,
                operating_mode: Some(OperatingModeEnum::SIT),
                idle_mode_duration_s: mode().idle_mode_duration_s,
            }
        );

        icd.set_operating_mode(OperatingModeEnum::LIT);
        assert_eq!(icd.net_params().poll_interval_ms, 900_000);
        assert_eq!(
            icd.advertisement(true),
            IcdAdvertisement {
                active_threshold_ms: mode().active_mode_threshold_ms,
                slow_poll_ms: 900_000,
                operating_mode: Some(OperatingModeEnum::LIT),
                idle_mode_duration_s: mode().idle_mode_duration_s,
            }
        );

        // A SIT-only configuration polls at its own, shorter, interval.
        icd.set_operating_mode(OperatingModeEnum::SIT);
        icd.set_poll_intervals(300, 2_000);
        assert_eq!(icd.net_params().poll_interval_ms, 2_000);
        assert_eq!(icd.advertisement(true).slow_poll_ms, 2_000);

        // A SIT-only device has no operating mode to advertise.
        assert_eq!(icd.advertisement(false).operating_mode, None);
    }

    #[test]
    #[should_panic]
    fn a_sit_poll_above_the_maximum_is_rejected() {
        Icd::with_sit_slow_poll(mode(), SIT_SLOW_POLL_MAX_MS + 1);
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

    /// Idle mode ends by the earliest keep-alive of the subscriptions at the latest.
    #[test]
    fn idle_mode_ends_by_next_keep_alive() {
        let icd = Icd::new(IcdModeConfig {
            idle_mode_duration_s: 60,
            active_mode_duration_ms: 50,
            active_mode_threshold_ms: 50,
            ..mode()
        });

        icd.request_active();

        let keep_alive_at = Instant::now() + Duration::from_secs(5);
        embassy_futures::block_on(icd.run_active(|| false, || Some(keep_alive_at)));

        assert_eq!(icd.power_mode(), IcdPowerMode::Idle);
        assert_eq!(icd.idle_until(), Some(keep_alive_at));

        // A later one does not stretch idle mode beyond `IdleModeDuration`.
        icd.request_active();

        let start = Instant::now();
        embassy_futures::block_on(
            icd.run_active(|| false, || Some(start + Duration::from_secs(3600))),
        );

        let idle_until = icd.idle_until().expect("idle");
        assert!(idle_until <= Instant::now() + Duration::from_secs(60));
        assert!(idle_until >= start + Duration::from_secs(60));
    }

    /// The two halves of the loop, driven in real time with short durations: the active
    /// window expires into idle mode, and the idle period expires back into active mode.
    #[test]
    fn active_window_expires_into_idle_and_idle_period_wakes_up() {
        let icd = Icd::new(IcdModeConfig {
            idle_mode_duration_s: 1,
            active_mode_duration_ms: 50,
            active_mode_threshold_ms: 50,
            ..mode()
        });

        // Boot: active for `ActiveModeDuration`. `start` is taken before the request, as the
        // deadline is measured from the request.
        let start = Instant::now();
        icd.request_active();
        assert_eq!(icd.power_mode(), IcdPowerMode::Active);

        embassy_futures::block_on(icd.run_active(|| false, || None));

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

    /// Work in flight (an open exchange, an armed fail-safe) keeps the device
    /// active past its deadline; it goes idle once the work is done.
    #[test]
    fn work_in_flight_keeps_the_device_active_past_the_deadline() {
        use core::cell::Cell;

        let icd = Icd::new(IcdModeConfig {
            idle_mode_duration_s: 1,
            active_mode_duration_ms: 50,
            active_mode_threshold_ms: 50,
            ..mode()
        });

        let busy = Cell::new(true);

        let start = Instant::now();
        icd.request_active();

        embassy_futures::block_on(embassy_futures::join::join(
            icd.run_active(|| busy.get(), || None),
            async {
                Timer::after(Duration::from_millis(250)).await;
                busy.set(false);
            },
        ));

        // Idle only after the work ended, well past the 50 ms deadline.
        assert_eq!(icd.power_mode(), IcdPowerMode::Idle);
        assert!(start.elapsed() >= Duration::from_millis(250));
    }
}
