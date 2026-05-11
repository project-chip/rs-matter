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

//! Identify cluster handler (Matter Application Cluster spec §1.2).
//!
//! The Identify cluster lets a controller put an endpoint into an
//! identification state — typically blinking an LED, beeping, or playing a
//! lighting effect — so a human can pick out which physical device they
//! just commissioned among several visually-identical ones. It is a
//! mandatory cluster on most application device types (e.g. On/Off Light,
//! Dimmable Light, Color Temperature Light), see Matter Device Library
//! §4.1.4 for the On/Off Light requirements.
//!
//! [`IdentifyHandler`] is generic over an [`IdentifyHooks`] hardware-hook
//! trait. The library handler owns all the boring bookkeeping —
//! `IdentifyTime` storage, the deadline-driven countdown, attribute-change
//! notifications — and dispatches a single sync [`IdentifyAction`]
//! callback to the application whenever the identification state
//! transitions. Applications with real hardware just implement
//! [`IdentifyHooks::identify`] (and optionally
//! [`IdentifyHooks::identify_type`]) and let the library handle the rest;
//! applications with no hardware can use the default `()` impl and ship
//! `IdentifyHandler::new(dataver)` without further ceremony.

use core::cell::Cell;
use core::pin::pin;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Instant, Timer};

use crate::dm::types::EndptId;
use crate::dm::{
    Cluster, Dataver, Handler, HandlerContext, InvokeContext, InvokeReply, MatchContext,
    NonBlockingHandler, ReadContext, ReadReply, WriteContext,
};
use crate::error::Error;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;
use crate::with;

pub use crate::dm::clusters::decl::identify::*;

/// Cluster metadata exposed by [`IdentifyHandler`] regardless of hooks.
///
/// Equivalent to `<IdentifyHandler<H> as ClusterHandler>::CLUSTER` for
/// any `H: IdentifyHooks`, exposed here as a free constant so callers
/// don't have to spell out the generic parameter when they just want the
/// cluster ID for an `EpClMatcher` or a `clusters!(...)` literal.
pub const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

/// The kind of identification action requested by a controller, dispatched
/// by [`IdentifyHandler`] to the application's [`IdentifyHooks::identify`]
/// method. Hooks see exactly one of these per state transition.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(crate::reexport::defmt::Format))]
pub enum IdentifyAction {
    /// `IdentifyTime` write (or `Identify` command) with a non-zero
    /// duration: start (or re-arm) identifying for the supplied seconds.
    /// The handler tracks the deadline and will dispatch a follow-up
    /// [`IdentifyAction::Cancel`] action when the timer expires.
    Time(u16),
    /// `TriggerEffect` command: trigger a named effect with the supplied
    /// variant. The handler does not track effect duration — applications
    /// own the effect lifecycle from this point. The `StopEffect` /
    /// `FinishEffect` effect identifiers arrive here as
    /// [`IdentifyAction::Effect`] just like every other effect, so the
    /// application can dispatch them to the appropriate hardware sequence.
    Effect(EffectIdentifierEnum, EffectVariantEnum),
    /// Stop any in-progress identification. Dispatched on:
    /// - `IdentifyTime` write (or `Identify` command) with value `0`,
    /// - the countdown deadline being reached,
    ///
    /// **not** dispatched on a re-arm: the application instead receives a
    /// fresh [`IdentifyAction::Time`] with the new duration and can decide
    /// whether to keep its current visual pattern running or restart.
    Cancel,
}

/// Application-level hooks for the Identify cluster.
///
/// Implementations override this trait to drive their hardware (LED,
/// buzzer, display, …) in response to identify requests from a Matter
/// controller. The default `()` implementation is a no-op and is suitable
/// for headless test fixtures or applications that observe identification
/// state via attribute subscriptions instead.
pub trait IdentifyHooks {
    /// Return the kind of identification mechanism this endpoint provides.
    /// Reported as the `IdentifyType` attribute (per App Cluster spec
    /// §1.2.5.2). The default is [`IdentifyTypeEnum::None`] which means
    /// "no physical mechanism."
    fn identify_type(&self) -> IdentifyTypeEnum {
        IdentifyTypeEnum::None
    }

    /// Drive the application's identify hardware in response to a state
    /// transition. The default implementation is a no-op — useful for
    /// headless test fixtures.
    fn identify(&self, action: IdentifyAction) {
        let _ = action;
    }
}

impl IdentifyHooks for () {}

impl<T> IdentifyHooks for &T
where
    T: IdentifyHooks,
{
    fn identify_type(&self) -> IdentifyTypeEnum {
        (*self).identify_type()
    }

    fn identify(&self, action: IdentifyAction) {
        (*self).identify(action)
    }
}

/// The captured identify session. Reads of `IdentifyTime` compute
/// `duration.saturating_sub(elapsed)` from this on-demand; the run task
/// uses `endpoint_id` to target its `notify_attr_changed` at the right
/// path when the deadline expires.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(crate::reexport::defmt::Format))]
struct Session {
    /// The endpoint that requested the identify — captured at write/invoke
    /// time from the surrounding `OperationContext`, since the
    /// `HandlerContext` available in the run task does not carry it.
    endpoint_id: EndptId,
    /// The originally-requested duration in seconds. Together with `start`
    /// drives the on-demand "remaining seconds" computation.
    duration: u16,
    /// The `Instant` at which the request landed.
    start: Instant,
}

/// The handler for the Identify Matter cluster.
///
/// Per-endpoint instance: each endpoint that advertises the Identify
/// cluster must own a separate `IdentifyHandler` so countdown state and
/// attribute reports stay segregated. The endpoint ID is captured *lazily*
/// from the first write/command that lands on this instance — no
/// constructor argument required, and the same handler type can therefore
/// serve any endpoint without per-endpoint specialization.
///
/// State model: rather than physically decrement an `IdentifyTime` counter
/// at 1 Hz, the handler captures the originally-requested
/// `(endpoint_id, duration, start_instant)` when an `Identify` command (or
/// `IdentifyTime` write) arrives, and computes the *remaining* seconds
/// on-demand whenever the framework reads the attribute. This is
/// observably equivalent to a physical countdown per Matter App Cluster
/// spec §1.2.5.1 (which constrains the attribute's observable value, not
/// the implementation's internal storage), but it avoids 60 wakeups for
/// a 60-second identify — the [run task](Handler::run) only schedules a
/// single `Timer::at(deadline)` per identify cycle, fires the final-zero
/// `notify_attr_changed`, and parks. On battery-powered targets that's the
/// difference between a measurable wake-and-radio-on hit per second and a
/// non-event.
///
/// Concurrency: the session cell is wrapped in a blocking [`Mutex`] so the
/// handler is sound under a future work-stealing executor configuration of
/// rs-matter. Lock holds are bounded to a single `Cell::get` / `Cell::set`
/// each — the lock is *never* held across `.await` points.
///
/// Dataver is bumped automatically by the framework after each write/invoke
/// (via the cluster handler chain's `bump_dataver(MatchContext)`), and
/// again whenever a `notify_attr_changed` is dispatched. This handler
/// therefore never calls `self.dataver.changed()` directly — it only
/// signals attribute-changed notifications, and the framework takes care
/// of dataver progression.
///
/// # Why this implements `Handler` directly
///
/// The cluster's request dispatch (read / write / invoke) is delegated to
/// the generated `HandlerAdaptor` — see the `Handler` impl below — which
/// keeps the read/write/invoke surface as cheap sync calls (smaller
/// footprint than `ClusterAsyncHandler`'s all-async state machines). The
/// only async surface this handler exposes is the deadline-timer task in
/// `Handler::run`, which is exactly what we need.
pub struct IdentifyHandler<H = ()> {
    dataver: Dataver,
    /// `Some(session)` while identifying, `None` when idle. Reads of
    /// `IdentifyTime` compute `duration.saturating_sub(elapsed)` from the
    /// captured `(endpoint_id, duration, start_instant)` on-demand.
    session: Mutex<Cell<Option<Session>>>,
    /// Wakes the run loop on writes/commands so it can re-arm its
    /// `Timer::at(deadline)` against the new session, instead of letting
    /// the previous deadline complete with stale parameters.
    state_change: Notification,
    hooks: H,
}

impl IdentifyHandler<()> {
    /// Creates a new `IdentifyHandler` with the no-hardware default
    /// `()` hooks. Suitable for headless test fixtures.
    ///
    /// The endpoint ID is *not* a constructor argument: it is captured at
    /// the first write/command from the surrounding `OperationContext`.
    pub const fn new(dataver: Dataver) -> Self {
        Self::new_with(dataver, ())
    }
}

impl<H> IdentifyHandler<H>
where
    H: IdentifyHooks,
{
    /// Creates a new `IdentifyHandler` with application-supplied hooks.
    pub const fn new_with(dataver: Dataver, hooks: H) -> Self {
        Self {
            dataver,
            session: Mutex::new(Cell::new(None)),
            state_change: Notification::new(),
            hooks,
        }
    }

    /// Compute the current `IdentifyTime` value from the captured session,
    /// saturating at zero if the deadline has already passed (the
    /// background `run` task may not yet have observed expiry).
    fn remaining(&self) -> u16 {
        let Some(Session {
            duration, start, ..
        }) = self.session.lock(|cell| cell.get())
        else {
            return 0;
        };
        let elapsed = start.elapsed().as_secs();
        // `duration as u64` is in [0, u16::MAX]; `saturating_sub` returns a
        // value in [0, lhs]; therefore the result is in [0, u16::MAX] and
        // the narrowing cast back to `u16` is lossless.
        (duration as u64).saturating_sub(elapsed) as u16
    }

    /// Capture a new identify session (or clear the existing one),
    /// dispatch the matching [`IdentifyAction`] to the hooks, and wake the
    /// run loop so it can re-arm its deadline timer. Caller is responsible
    /// for the subsequent attribute-changed notification — the
    /// WriteContext path uses `ctx.notify_changed()` and the InvokeContext
    /// path uses `ctx.notify_own_attr_changed(...)`.
    fn set_identify_time_internal(&self, endpoint_id: EndptId, value: u16) {
        self.session.lock(|cell| {
            if value == 0 {
                cell.set(None);
            } else {
                cell.set(Some(Session {
                    endpoint_id,
                    duration: value,
                    start: Instant::now(),
                }));
            }
        });
        self.state_change.notify();
        self.hooks.identify(if value == 0 {
            IdentifyAction::Cancel
        } else {
            IdentifyAction::Time(value)
        });
    }
}

impl<H> ClusterHandler for IdentifyHandler<H>
where
    H: IdentifyHooks,
{
    // No optional features supported; default cluster metadata covers the
    // mandatory `IdentifyTime` / `IdentifyType` attributes and the
    // mandatory `Identify` / `TriggerEffect` commands. Same as the
    // module-level `identify::CLUSTER` constant — the duplication exists
    // because trait-impl associated consts can't reference free items
    // by short path inside the impl body without trips through name
    // resolution that depend on glob re-export ordering.
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn identify_time(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.remaining())
    }

    fn identify_type(&self, _ctx: impl ReadContext) -> Result<IdentifyTypeEnum, Error> {
        Ok(self.hooks.identify_type())
    }

    fn set_identify_time(&self, ctx: impl WriteContext, value: u16) -> Result<(), Error> {
        self.set_identify_time_internal(ctx.attr().endpoint_id, value);
        // The shortcut for "the attribute the framework just wrote": fans
        // out a `notify_attr_changed` for `IdentifyTime`, which
        // simultaneously triggers the `bump_dataver(MatchContext)` chain
        // and notifies any subscribers.
        ctx.notify_changed();
        Ok(())
    }

    fn handle_identify(
        &self,
        ctx: impl InvokeContext,
        request: IdentifyRequest<'_>,
    ) -> Result<(), Error> {
        let time = request.identify_time()?;
        self.set_identify_time_internal(ctx.cmd().endpoint_id, time);
        // The Identify command mutates an attribute that lives on the
        // *same* cluster as the command (App Cluster §1.2.6.1), so use the
        // `OwnAttrChangeNotifier` shortcut to notify against
        // `(ctx.cmd().endpoint_id, ctx.cmd().cluster_id, IdentifyTime)`.
        ctx.notify_own_attr_changed(AttributeId::IdentifyTime as _);
        Ok(())
    }

    fn handle_trigger_effect(
        &self,
        _ctx: impl InvokeContext,
        request: TriggerEffectRequest<'_>,
    ) -> Result<(), Error> {
        let effect = request.effect_identifier()?;
        let variant = request.effect_variant()?;
        self.hooks.identify(IdentifyAction::Effect(effect, variant));
        Ok(())
    }
}

// Implement `Handler` directly so we get to provide the `run` deadline
// task, while still delegating the read/write/invoke/bump_dataver dispatch
// to the generated `HandlerAdaptor` (which is parameterized over a
// `ClusterHandler` impl, which we provide above). The `&Self: ClusterHandler`
// blanket — generated alongside the trait — makes this delegation cheap.
impl<H> Handler for IdentifyHandler<H>
where
    H: IdentifyHooks,
{
    fn read(&self, ctx: impl ReadContext, reply: impl ReadReply) -> Result<(), Error> {
        Handler::read(&HandlerAdaptor(self), ctx, reply)
    }

    fn write(&self, ctx: impl WriteContext) -> Result<(), Error> {
        Handler::write(&HandlerAdaptor(self), ctx)
    }

    fn invoke(&self, ctx: impl InvokeContext, reply: impl InvokeReply) -> Result<(), Error> {
        Handler::invoke(&HandlerAdaptor(self), ctx, reply)
    }

    fn bump_dataver(&self, ctx: impl MatchContext) {
        Handler::bump_dataver(&HandlerAdaptor(self), ctx)
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        loop {
            let Some(Session {
                endpoint_id,
                duration,
                start,
            }) = self.session.lock(|cell| cell.get())
            else {
                // Idle: wait for a write/command to start a session.
                self.state_change.wait().await;
                continue;
            };

            // Compute the absolute deadline once and race a single timer
            // against the wakeup signal — no per-second polling, and no
            // accumulating sub-second drift across multiple ticks.
            let deadline = start + Duration::from_secs(duration as u64);

            match select(Timer::at(deadline), pin!(self.state_change.wait())).await {
                Either::First(_) => {
                    // Deadline reached: clear the session so subsequent
                    // reads of `IdentifyTime` return 0, dispatch the
                    // application-visible `Cancel` action, and notify
                    // subscribers of the final-zero transition (Q-quality
                    // reportable per App Cluster spec §1.2.5.1). The
                    // framework auto-bumps the cluster dataver through
                    // the `bump_dataver` chain as a side effect.
                    self.session.lock(|cell| cell.set(None));
                    self.hooks.identify(IdentifyAction::Cancel);
                    ctx.notify_attr_changed(
                        endpoint_id,
                        <Self as ClusterHandler>::CLUSTER.id,
                        AttributeId::IdentifyTime as _,
                    );
                }
                Either::Second(_) => {
                    // Re-armed via write/command (or cancelled with `0`);
                    // loop and re-read the session.
                }
            }
        }
    }
}

// Marker impl: the `Handler::read`/`write`/`invoke` methods above are
// fully synchronous, which lets the chain compose this handler with the
// `Async(...)` lifter (defined in `dm::types::handler`) into the rest of
// the cluster chain just like the sync `HandlerAdaptor`-based clusters.
impl<H> NonBlockingHandler for IdentifyHandler<H> where H: IdentifyHooks {}
