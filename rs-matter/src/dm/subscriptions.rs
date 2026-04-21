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

use core::num::NonZeroU8;

use embassy_time::Instant;

use crate::dm::{
    AttrChangeNotifier, AttrId, ClusterId, EndptId, EventId, EventNumber, IMBuffer, NodeId,
};
use crate::fabric::MAX_FABRICS;
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::pooled::BufferAccess;
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::{DynBase, Notification};

/// The maximum number of subscriptions that can be tracked at the same time by default.
///
/// According to the Matter spec, at least 3 subscriptions per fabric should be supported.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = MAX_FABRICS * 3;

/// The maximum number of changed-attribute entries tracked simultaneously.
///
/// When the table is full, entries are coalesced ("promoted") to coarser-grained
/// wildcards so that new changes can always be recorded.
pub const MAX_CHANGED_ATTRS: usize = 16;

// REVIEW: `SubscriptionsBuffers` is a thin wrapper around a second
// `Mutex<RefCell<Vec<..>>>` that is *always* locked in lockstep with
// `Subscriptions::state` (see `Subscriptions::with`). As long as that lock
// order is respected the pair is safe, but the two locks let someone (now or
// in the future) lock only one of them and violate the invariant that
// `subscriptions.len() == buffers.len()`. The cleanest fix is to move the
// `Vec<B::Buffer<'a>, N>` *into* `SubscriptionsInner` behind the same mutex
// so it cannot be locked independently. The current layout also forces all
// public APIs to thread an extra `&SubscriptionsBuffers` argument everywhere,
// which is why `remove` / `report` / `add` all grew a second ref parameter.
pub struct SubscriptionsBuffers<'a, B, const N: usize = DEFAULT_MAX_SUBSCRIPTIONS>
where
    B: BufferAccess<IMBuffer> + 'a,
{
    buffers: Mutex<RefCell<SubscriptionsBuffersInner<'a, B, N>>>,
}

impl<'a, B, const N: usize> Default for SubscriptionsBuffers<'a, B, N>
where
    B: BufferAccess<IMBuffer> + 'a,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, B, const N: usize> SubscriptionsBuffers<'a, B, N>
where
    B: BufferAccess<IMBuffer> + 'a,
{
    pub const fn new() -> Self {
        Self {
            buffers: Mutex::new(RefCell::new(Vec::new())),
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            buffers <- Mutex::init(RefCell::init(Vec::init())),
        })
    }

    fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut SubscriptionsBuffersInner<'a, B, N>) -> R,
    {
        self.buffers.lock(|buffers| f(&mut buffers.borrow_mut()))
    }
}

type SubscriptionsBuffersInner<'a, B, const N: usize> =
    Vec<<B as BufferAccess<IMBuffer>>::Buffer<'a>, N>;

/// A utility for tracking subscriptions accepted by the data model.
///
/// The `N` type parameter specifies the maximum number of subscriptions that can be tracked at the same time.
/// Additional subscriptions are rejected by the data model with a "resource exhausted" IM status message.
pub struct Subscriptions<const N: usize = DEFAULT_MAX_SUBSCRIPTIONS> {
    state: Mutex<RefCell<SubscriptionsInner<N>>>,
    pub(crate) notification: Notification,
}

impl<const N: usize> Subscriptions<N> {
    /// Create the instance.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(SubscriptionsInner::new())),
            notification: Notification::new(),
        }
    }

    /// Create an in-place initializer for the instance.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(SubscriptionsInner::init())),
            notification: Notification::new(),
        })
    }

    /// Notify the instance that the data of a specific attribute has changed and that it should re-evaluate the subscriptions
    /// and report on those that are interested in the changed data.
    ///
    /// This method is supposed to be called by the application code whenever it changes the data of an attribute.
    ///
    /// # Arguments
    /// - `endpoint_id`: The endpoint ID of the cluster that had changed.
    /// - `cluster_id`: The cluster ID of the cluster that had changed.
    /// - `attr_id`: The attribute ID of the attribute that changed.
    pub(crate) fn notify_attribute_changed(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        attr_id: AttrId,
    ) {
        self.state.lock(|internal| {
            internal
                .borrow_mut()
                .changed_attrs
                .record(endpoint_id, cluster_id, attr_id);
        });

        // The per-subscription decision of whether anything needs to be reported is
        // computed on-the-fly by `find_report_due` (and by the responder's filter)
        // by consulting the live `changed_attrs` table, so there is no per-sub flag
        // to flip here. We just wake the reporter task.
        self.notification.notify();
    }

    /// Record a cluster-wide change. Every attribute of `(endpoint_id,
    /// cluster_id)` is treated as changed for the purposes of subscription
    /// reporting.
    pub(crate) fn notify_cluster_attrs_changed(&self, endpoint_id: EndptId, cluster_id: ClusterId) {
        self.state.lock(|internal| {
            internal
                .borrow_mut()
                .changed_attrs
                .record_wildcard(Some(endpoint_id), Some(cluster_id));
        });

        self.notification.notify();
    }

    /// Record an endpoint-wide change. Every attribute on every cluster of
    /// `endpoint_id` is treated as changed for the purposes of subscription
    /// reporting.
    pub(crate) fn notify_endpoint_attrs_changed(&self, endpoint_id: EndptId) {
        self.state.lock(|internal| {
            internal
                .borrow_mut()
                .changed_attrs
                .record_wildcard(Some(endpoint_id), None);
        });

        self.notification.notify();
    }

    /// Record a fully-global change. Every attribute on every cluster on
    /// every endpoint is treated as changed for the purposes of subscription
    /// reporting. Intended for coarse-grained reset / restart scenarios.
    pub(crate) fn notify_all_attrs_changed(&self) {
        self.state.lock(|internal| {
            internal
                .borrow_mut()
                .changed_attrs
                .record_wildcard(None, None);
        });

        self.notification.notify();
    }

    pub fn notify_event_emitted(
        &self,
        _endpoint_id: EndptId,
        _cluster_id: ClusterId,
        _event_id: EventId,
    ) {
        // Events are filtered at report time by `min_event_number` + event path matching.
        // Whether a subscription is due to report because of new events is recomputed on
        // the fly in `find_report_due`, so here we only need to kick the reporter task.
        self.notification.notify();
    }

    pub(crate) fn clear(&self) {
        self.state.lock(|state| state.borrow_mut().clear());
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add<'a, 's, B>(
        &'s self,
        now: Instant,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
        session_id: u32,
        min_int_secs: u16,
        max_int_secs: u16,
        max_event_number: EventNumber,
        buffer: B::Buffer<'a>,
        buffers: &'s SubscriptionsBuffers<'a, B, N>,
    ) -> Option<ReportContext<'a, 's, B, N>>
    where
        B: BufferAccess<IMBuffer> + 'a,
    {
        // REVIEW: `next_max_seen_attr_change_id` is hard-coded to `0` here,
        // but the matching path in `report()` uses `changed_attrs.watermark()`.
        // For `add()` the value doesn't actually matter (the subscription is
        // freshly constructed below with `max_seen_attr_change_id =
        // changed_attrs.watermark()`, and `set_complete()` is what ultimately
        // writes this field back via `report_complete`), but the asymmetry is
        // confusing and means `set_complete()` called from the *priming*
        // report path will overwrite `max_seen_attr_change_id` with 0,
        // effectively resetting the subscription's `since` watermark to 0 on
        // its very first commit.  Changes that occurred *during* the priming
        // report will then be re-emitted in the next incremental report, but
        // changes that happened between `add()` and the start of priming will
        // be replayed twice.
        let (sub, buf, next_max_seen_attr_change_id) = self.with(buffers, |state, buffers| {
            let (sub, buf) = state.add::<B>(
                fabric_idx,
                peer_node_id,
                session_id,
                min_int_secs,
                max_int_secs,
                max_event_number,
                buffer,
                buffers,
            )?;

            // Mirror `report()`: commit the current watermark so the priming
            // report's `set_keep` does not regress the subscription's `since`
            // to 0 (which would cause every pre-`add` change to be replayed
            // on the first incremental report).
            Some((sub, buf, state.changed_attrs.watermark()))
        })?;

        Some(ReportContext {
            subscriptions: self,
            subscriptions_buffers: buffers,
            subscription: Some(sub),
            subscription_buffer: Some(buf),
            next_max_seen_attr_change_id,
            next_reported_at: now,
            keep: false,
        })
    }

    // REVIEW: a subscription that is currently being reported on has been
    // `swap_remove`d from `state.subscriptions` (see `SubscriptionsInner::report`)
    // and only lives inside its `ReportContext`. `remove` scans
    // `state.subscriptions` only, so an in-flight subscription is *invisible*
    // to `remove` and will silently survive any removal request (e.g. a
    // `keep_subs=false` Subscribe handled by another task, or a session
    // removal). It is put back verbatim by `Drop` via `report_complete`.
    // This is a correctness regression vs. the pre-refactor code and probably
    // deserves either a "pending removal" flag on `ReportContext` or holding
    // the subscription in place during reporting (e.g. with a `reporting`
    // marker) so `remove` can still act on it.
    pub(crate) fn remove<B, F>(&self, buffers: &SubscriptionsBuffers<'_, B, N>, mut f: F) -> bool
    where
        B: BufferAccess<IMBuffer>,
        F: FnMut(&Subscription) -> Option<&'static str>,
    {
        let removed = self.with(buffers, |state, buffers| {
            let mut removed = false;

            loop {
                let next = state
                    .subscriptions
                    .iter()
                    .enumerate()
                    .filter_map(|(index, subscription)| {
                        f(subscription).map(|reason| (index, subscription.ids().clone(), reason))
                    })
                    .next();

                let Some((index, ids, reason)) = next else {
                    break;
                };

                state.subscriptions.swap_remove(index);
                buffers.swap_remove(index);

                state.subscriptions_count -= 1;

                info!("Removed subscription {:?}, reason: {}", ids, reason);

                removed = true;
            }

            removed
        });

        if removed {
            self.notification.notify();
        }

        removed
    }

    pub(crate) fn report<'a, 's, B>(
        &'s self,
        now: Instant,
        max_event_number: EventNumber,
        buffers: &'s SubscriptionsBuffers<'a, B, N>,
    ) -> Option<ReportContext<'a, 's, B, N>>
    where
        B: BufferAccess<IMBuffer> + 'a,
    {
        let (sub, buf, next_max_seen_attr_change_id) = self.with(buffers, |state, buffers| {
            let (sub, buf) = state.report::<B>(now, max_event_number, buffers)?;

            Some((sub, buf, state.changed_attrs.watermark()))
        })?;

        Some(ReportContext {
            subscriptions: self,
            subscriptions_buffers: buffers,
            subscription: Some(sub),
            subscription_buffer: Some(buf),
            next_max_seen_attr_change_id,
            next_reported_at: now,
            keep: false,
        })
    }

    /// Remove entries that every subscription has already reported on.
    pub(crate) fn purge_reported_changes(&self) {
        self.state
            .lock(|state| state.borrow_mut().purge_reported_changes())
    }

    fn report_complete<'a, B>(&self, report: &mut ReportContext<'a, '_, B, N>)
    where
        B: BufferAccess<IMBuffer> + 'a,
    {
        let mut sub = unwrap!(report.subscription.take());
        let buf = unwrap!(report.subscription_buffer.take());

        sub.max_seen_attr_change_id = report.next_max_seen_attr_change_id;
        sub.reported_at = report.next_reported_at;

        let keep = report.keep;

        self.with(report.subscriptions_buffers, |state, buffers| {
            state.report_complete::<B>(sub, buf, buffers, keep)
        })
    }

    fn with<'a, B, F, R>(&self, buffers: &SubscriptionsBuffers<'a, B, N>, f: F) -> R
    where
        B: BufferAccess<IMBuffer> + 'a,
        F: FnOnce(&mut SubscriptionsInner<N>, &mut SubscriptionsBuffersInner<'a, B, N>) -> R,
    {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            buffers.with(|buffers| f(&mut state, buffers))
        })
    }
}

impl<const N: usize> Default for Subscriptions<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AttrChangeNotifier for Subscriptions<N> {
    fn notify_attr_changed(&self, endpt: EndptId, clust: ClusterId, attr: AttrId) {
        Subscriptions::<N>::notify_attribute_changed(self, endpt, clust, attr);
    }

    fn notify_cluster_changed(&self, endpt: EndptId, clust: ClusterId) {
        Subscriptions::<N>::notify_cluster_attrs_changed(self, endpt, clust);
    }

    fn notify_endpoint_changed(&self, endpt: EndptId) {
        Subscriptions::<N>::notify_endpoint_attrs_changed(self, endpt);
    }

    fn notify_all_changed(&self) {
        Subscriptions::<N>::notify_all_attrs_changed(self);
    }
}

impl<const N: usize> DynBase for Subscriptions<N> {}

struct SubscriptionsInner<const N: usize> {
    next_subscription_id: u32,
    subscriptions_count: usize,
    subscriptions: Vec<Subscription, N>,
    changed_attrs: ChangedAttributes,
}

impl<const N: usize> SubscriptionsInner<N> {
    /// Create the instance.
    #[inline(always)]
    const fn new() -> Self {
        Self {
            next_subscription_id: 1,
            subscriptions_count: 0,
            subscriptions: Vec::new(),
            changed_attrs: ChangedAttributes::new(),
        }
    }

    /// Create an in-place initializer for the instance.
    fn init() -> impl Init<Self> {
        init!(Self {
            next_subscription_id: 1,
            subscriptions_count: 0,
            subscriptions <- Vec::init(),
            changed_attrs <- ChangedAttributes::init(),
        })
    }

    fn clear(&mut self) {
        self.subscriptions.clear();
        self.subscriptions_count = 0;
    }

    /// Add a subscription with the given parameters.
    ///
    /// Returns the assigned subscription ID on success, or `None` if the subscription table is full.
    #[allow(clippy::too_many_arguments)]
    fn add<'a, B>(
        &mut self,
        fab_idx: NonZeroU8,
        peer_node_id: u64,
        session_id: u32,
        min_int_secs: u16,
        max_int_secs: u16,
        _max_event_number: EventNumber,
        buffer: B::Buffer<'a>,
        _buffers: &mut SubscriptionsBuffersInner<'a, B, N>,
    ) -> Option<(Subscription, B::Buffer<'a>)>
    where
        B: BufferAccess<IMBuffer> + 'a,
    {
        if self.subscriptions_count >= N {
            return None;
        }

        self.subscriptions_count += 1;

        let id = self.next_subscription_id;
        self.next_subscription_id += 1;

        // Start with the current watermark so that only changes happening AFTER the
        // subscription was accepted will be reported as incremental updates.
        let max_seen_attr_change_id = self.changed_attrs.watermark();

        let subscription = Subscription {
            ids: SubscriptionIds {
                id,
                fab_idx,
                peer_node_id,
            },
            session_id,
            min_int_secs,
            max_int_secs,
            reported_at: Instant::MAX,
            max_seen_attr_change_id,
            // Start at 0 so the priming report delivers every event that was
            // already in the event buffer at subscribe time. The reader will
            // advance this via `update_max_seen_event_number` once the
            // priming report has consumed the events.
            max_seen_event_number: 0,
        };

        info!("Added subscription {:?}", subscription.ids());

        Some((subscription, buffer))
    }

    /// Begin a report for the subscription with the given ID.
    ///
    /// Returns a small [`ReportContext`] capturing the subscription's current
    /// `since` watermark and the watermark to commit via [`Self::mark_reported`]
    /// on success. Unlike a snapshot, the `changed_attrs` table itself is not
    /// copied; the report uses a [`SubAttrChangeFilter`] that consults the
    /// live table one attribute at a time.
    ///
    /// `priming = true` produces a context with filtering disabled; it is
    /// used for the initial ("priming") report delivered right after a
    /// subscription is accepted.
    fn report<'a, B>(
        &mut self,
        now: Instant,
        max_event_number: EventNumber,
        buffers: &mut SubscriptionsBuffersInner<'a, B, N>,
    ) -> Option<(Subscription, B::Buffer<'a>)>
    where
        B: BufferAccess<IMBuffer> + 'a,
    {
        if let Some(index) = self.find_reportable::<B>(now, max_event_number, buffers) {
            let sub = self.subscriptions.swap_remove(index);
            let buf = buffers.swap_remove(index);

            info!("About to report on subscription {:?}", sub.ids());

            Some((sub, buf))
        } else {
            None
        }
    }

    fn report_complete<'a, B>(
        &mut self,
        sub: Subscription,
        buffer: B::Buffer<'a>,
        buffers: &mut SubscriptionsBuffersInner<'a, B, N>,
        keep: bool,
    ) where
        B: BufferAccess<IMBuffer> + 'a,
    {
        if keep {
            unwrap!(self.subscriptions.push(sub));
            unwrap!(buffers.push(buffer).map_err(|_| ()));
        } else {
            warn!("Subscription {:?} removed during reporting", sub.ids());

            self.subscriptions_count -= 1;
        }
    }

    fn find_reportable<'a, B>(
        &self,
        now: Instant,
        max_event_number: EventNumber,
        buffers: &SubscriptionsBuffersInner<'a, B, N>,
    ) -> Option<usize>
    where
        B: BufferAccess<IMBuffer> + 'a,
    {
        self.subscriptions
            .iter()
            .enumerate()
            .map(|(index, sub)| (sub, &buffers[index]))
            .position(|(sub, rx)| sub.is_reportable(now, rx, &self.changed_attrs, max_event_number))
    }

    /// Remove entries that every subscription has already reported on.
    fn purge_reported_changes(&mut self) {
        if let Some(min_seen_attr_change_id) = self
            .subscriptions
            .iter()
            .map(|s| s.max_seen_attr_change_id)
            .min()
        {
            self.changed_attrs.purge_up_to(min_seen_attr_change_id);
        } else {
            self.changed_attrs.clear();
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SubscriptionIds {
    /// The ID of the subscription. Uniquely identifies the subscription across all of them.
    pub id: u32,
    /// The fabric index of the subscriber. Used to route reports and to remove all subscriptions of a fabric when it gets removed.
    pub fab_idx: NonZeroU8,
    /// The node ID of the subscriber. Used to route reports and to remove all subscriptions of a peer when it gets removed.
    pub peer_node_id: NodeId,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Subscription {
    /// The IDs of the subscription
    ids: SubscriptionIds,
    /// The ID of the session on which the subscription was accepted. Used by
    /// the reporter task to route outgoing reports back to the exact session
    /// the subscriber established, rather than picking any secure session
    /// matching `(fab_idx, peer_node_id)` (which may not be the one the peer
    /// is actually listening on, breaking at least HomeKit and chip-tool).
    session_id: u32,
    /// The minimum interval in seconds. The subscription should not receive reports more frequently than this interval, but may receive them less frequently.
    /// We use u16 instead of embassy::Duration to save some storage
    min_int_secs: u16,
    /// The maximum interval in seconds. The subscription should receive reports at least this frequently, even if there are no changes to report (i.e. it is a liveness deadline).
    /// We use u16 instead of embassy::Duration to save some storage
    max_int_secs: u16,
    /// The timestamp of the last report sent to this subscription. Used to decide when the next report is due based on the min/max intervals.
    /// Set to `Instant::MAX` when the subscription is created to indicate that no report has been sent yet, so the first report is due immediately. After the first report, it is updated to the actual timestamp of the last report.
    reported_at: Instant,
    /// The largest attribute change ID from the [`ChangedAttributes`] table this subscription
    /// has already reported on. Entries with a larger change ID represent pending changes the subscription still needs to emit.
    max_seen_attr_change_id: u64,
    /// The largest event number this subscription has already reported on. Events with a larger event number represent pending events the subscription still needs to emit.
    max_seen_event_number: u64,
}

impl Subscription {
    pub const fn ids(&self) -> &SubscriptionIds {
        &self.ids
    }

    /// The session ID on which this subscription was accepted.
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        self.reported_at
            .checked_add(embassy_time::Duration::from_secs(self.max_int_secs as _))
            .map(|expiry| expiry <= now)
            .unwrap_or(false)
    }

    // REVIEW: `is_expired(now)` returning `true` here *prevents* the
    // subscription from being picked up for reporting. That's a correctness
    // problem: the expected flow for an expired subscription is to be removed
    // (by `Subscriptions::remove` with an `is_expired` reason — which is
    // indeed what `dm.rs` does). But if the reporter task wakes up on the
    // change notification path and races past the `remove` pass, the expired
    // subscription will be silently starved instead of being removed or
    // reported. Consider dropping the `is_expired` check here entirely — the
    // "remove expired" step in `dm.rs` is the single source of truth.
    fn is_reportable(
        &self,
        now: Instant,
        rx: &[u8],
        changed_attrs: &ChangedAttributes,
        max_event_number: EventNumber,
    ) -> bool {
        if self.is_expired(now) || !self.is_report_allowed(now) {
            return false;
        }

        self.is_report_due(now)
            || self.is_affected_by_attr_changes(rx, changed_attrs)
            || self.is_affected_by_new_events(rx, max_event_number)
    }

    fn is_report_allowed(&self, now: Instant) -> bool {
        self.reported_at
            .checked_add(embassy_time::Duration::from_secs(self.min_int_secs as _))
            .map(|next_report| next_report <= now)
            .unwrap_or(true)
    }

    fn is_report_due(&self, now: Instant) -> bool {
        self.reported_at
            .checked_add(embassy_time::Duration::from_secs(self.max_int_secs as _))
            .map(|next_report| {
                next_report <= now
                    || next_report - now
                        <= embassy_time::Duration::from_secs((self.max_int_secs / 2) as _)
            })
            .unwrap_or(true)
    }

    fn is_affected_by_attr_changes(&self, _rx: &[u8], changes: &ChangedAttributes) -> bool {
        changes.any_since(self.max_seen_attr_change_id)
    }

    fn is_affected_by_new_events(&self, _rx: &[u8], max_event_number: EventNumber) -> bool {
        self.max_seen_event_number < max_event_number
    }
}

/// A table of recently-changed attribute triples, each tagged with an
/// ever-increasing `change_id`.
///
/// Subscriptions consult this table to decide which attributes they should
/// re-emit on their next report: only attributes with a matching entry whose
/// `change_id` is strictly greater than the subscription's own watermark
/// (`last_change_id`) need to be reported.
///
/// The table has a fixed capacity of [`MAX_CHANGED_ATTRS`] entries. When it
/// fills up, existing entries are coalesced to coarser-grained wildcards
/// (`(endpoint, cluster, *)` → `(endpoint, *, *)` → `(*, *, *)`) so that a new change can always
/// be recorded. A wildcard entry over-covers and will therefore cause the
/// affected subscriptions to emit a slightly wider set of attributes on their
/// next report, but this is a bounded loss of precision that preserves
/// correctness.
pub(crate) struct ChangedAttributes {
    /// Monotonically increasing ID assigned to every recorded change.
    /// The first assigned ID is 1; `0` is reserved as the "no change seen yet"
    /// sentinel used by fresh subscriptions.
    next_change_id: u64,
    /// The actual table of recent changes, ordered from oldest to newest.
    /// The newest change has `change_id == next_change_id - 1`.
    entries: Vec<ChangedAttr, MAX_CHANGED_ATTRS>,
}

impl ChangedAttributes {
    /// Create the instance.
    #[inline(always)]
    const fn new() -> Self {
        Self {
            next_change_id: 1,
            entries: Vec::new(),
        }
    }

    /// Return an in-place initializer for the instance.
    fn init() -> impl Init<Self> {
        init!(Self {
            next_change_id: 1,
            entries <- Vec::init(),
        })
    }

    /// The largest change ID that has been assigned so far. A subscription
    /// whose max seen change ID is equal to the watermark has seen every change.
    #[inline]
    fn watermark(&self) -> u64 {
        self.next_change_id.wrapping_sub(1)
    }

    /// Record a change to the attribute triple `(endpoint, cluster, attr)`.
    /// Returns the newly assigned change ID.
    fn record(&mut self, endpoint: EndptId, cluster: ClusterId, attr: AttrId) -> u64 {
        self.record_raw(ChangedAttr::concrete(endpoint, cluster, attr, 0))
    }

    /// Record a cluster- or endpoint-wide wildcard change. `endpoint == None`
    /// together with `cluster == None` represents a global wildcard.
    /// Returns the newly assigned change ID.
    fn record_wildcard(&mut self, endpoint: Option<EndptId>, cluster: Option<ClusterId>) -> u64 {
        self.record_raw(ChangedAttr {
            endpoint,
            cluster,
            attr: None,
            change_id: 0,
        })
    }

    /// Insert `new` into the table. The caller is expected to leave `new.change_id`
    /// at any value - it is overwritten by a freshly-assigned ID.
    fn record_raw(&mut self, mut new: ChangedAttr) -> u64 {
        let change_id = self.next_change_id;
        self.next_change_id = self.next_change_id.wrapping_add(1).max(1);
        new.change_id = change_id;

        // If an existing entry already covers `new`, just refresh its change ID.
        if let Some(existing) = self.entries.iter_mut().find(|x| x.covers(&new)) {
            existing.change_id = change_id;
            return change_id;
        }

        // `new` may itself subsume existing concrete entries - drop those to
        // keep the table compact and avoid wasting slots on redundant paths.
        let mut i = 0;
        while i < self.entries.len() {
            if new.covers(&self.entries[i]) {
                self.entries.swap_remove(i);
            } else {
                i += 1;
            }
        }

        if let Err(new) = self.entries.push(new) {
            // The table is full - promote entries to coarser wildcards to free a slot.
            self.promote_and_insert(new);
        }

        change_id
    }

    /// Returns `true` if the table contains at least one entry covering
    /// `(endpoint, cluster, attr)` with `change_id > since`.
    fn contains_since(
        &self,
        endpoint: EndptId,
        cluster: ClusterId,
        attr: AttrId,
        since: u64,
    ) -> bool {
        self.entries
            .iter()
            .any(|x| x.change_id > since && x.matches(endpoint, cluster, attr))
    }

    /// Returns `true` if the table contains at least one entry with
    /// `change_id > since` (of any path).
    fn any_since(&self, since: u64) -> bool {
        self.entries.iter().any(|x| x.change_id > since)
    }

    /// Drop all entries with `change_id <= threshold`.
    fn purge_up_to(&mut self, threshold: u64) {
        if threshold == 0 {
            return;
        }

        let mut i = 0;
        while i < self.entries.len() {
            if self.entries[i].change_id <= threshold {
                self.entries.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Drop every recorded change. Used when no subscriptions exist.
    fn clear(&mut self) {
        self.entries.clear();
    }

    /// Coalesce existing entries to coarser wildcards so that `new` can be inserted.
    ///
    /// The strategy is to promote as little as possible: on each iteration we
    /// collapse the single largest collapsible group at the finest available
    /// level into one coarser wildcard entry, freeing at least one slot. Only
    /// once no fine-grained group of two or more entries exists do we escalate
    /// to the next level, and finally to a global wildcard as a last resort.
    fn promote_and_insert(&mut self, new: ChangedAttr) {
        loop {
            // If an existing (possibly just-promoted) entry already covers `new`,
            // refresh its change ID and we're done.
            if let Some(existing) = self.entries.iter_mut().find(|x| x.covers(&new)) {
                existing.change_id = new.change_id;
                return;
            }

            if self.entries.push(new.clone()).is_ok() {
                return;
            }

            // Full - promote exactly one group at the finest granularity that
            // actually yields compaction. Levels:
            // - 1: (endpoint, cluster, *)
            // - 2: (endpoint, *, *)
            if !self.promote_largest_group(1) && !self.promote_largest_group(2) {
                // No collapsible group at either level - last-ditch fallback:
                // collapse the whole table into a single global wildcard entry.
                self.entries.clear();

                unwrap!(self.entries.push(ChangedAttr {
                    endpoint: None,
                    cluster: None,
                    attr: None,
                    change_id: new.change_id,
                }));

                return;
            }
        }
    }

    /// Find the largest group of entries (>= 2) that share the same key at the
    /// given promotion level, and collapse it into one coarser wildcard entry.
    ///
    /// Returns `true` if any promotion happened.
    fn promote_largest_group(&mut self, level: u8) -> bool {
        // Pick a pivot whose group is largest.
        let mut best_pivot: Option<ChangedAttr> = None;
        let mut best_count = 1usize;

        for i in 0..self.entries.len() {
            let pivot = &self.entries[i];
            let Some(coarsened) = pivot.coarsen(level) else {
                continue;
            };

            let count = self.entries.iter().filter(|e| coarsened.covers(e)).count();
            if count > best_count {
                best_count = count;
                best_pivot = Some(pivot.clone());
            }
        }

        let Some(pivot) = best_pivot else {
            return false;
        };
        // `coarsen` already returned `Some` above for this pivot.
        let mut coarsened = pivot.coarsen(level).unwrap();

        // Remove all entries covered by `coarsened`, keeping the largest
        // change_id to preserve recency.
        let mut max_change_id = 0u64;
        let mut i = 0;
        while i < self.entries.len() {
            if coarsened.covers(&self.entries[i]) {
                if self.entries[i].change_id > max_change_id {
                    max_change_id = self.entries[i].change_id;
                }
                self.entries.swap_remove(i);
            } else {
                i += 1;
            }
        }
        coarsened.change_id = max_change_id;
        // Safe: we just removed `best_count >= 2` entries, so there is room.
        unwrap!(self.entries.push(coarsened));
        true
    }
}

/// A record of one recently changed attribute.
///
/// A `None` field acts as a wildcard. Wildcards appear only as a result of
/// "promotion" when the `changed_attrs` table becomes full and several
/// concrete entries need to be coalesced into a coarser one.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct ChangedAttr {
    endpoint: Option<EndptId>,
    cluster: Option<ClusterId>,
    attr: Option<AttrId>,
    change_id: u64,
}

impl ChangedAttr {
    const fn concrete(endpoint: EndptId, cluster: ClusterId, attr: AttrId, change_id: u64) -> Self {
        Self {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attr: Some(attr),
            change_id,
        }
    }

    /// Whether this record covers the concrete attribute triple
    /// `(endpoint, cluster, attr)`.
    fn matches(&self, endpoint: EndptId, cluster: ClusterId, attr: AttrId) -> bool {
        self.endpoint.map(|x| x == endpoint).unwrap_or(true)
            && self.cluster.map(|x| x == cluster).unwrap_or(true)
            && self.attr.map(|x| x == attr).unwrap_or(true)
    }

    /// Whether `other` is semantically covered by `self` (i.e. `self` is as
    /// coarse as or coarser than `other` on every axis).
    fn covers(&self, other: &ChangedAttr) -> bool {
        fn cov<T: Eq>(a: Option<T>, b: Option<T>) -> bool {
            match (a, b) {
                (None, _) => true,        // self wildcard covers anything
                (Some(_), None) => false, // concrete doesn't cover wildcard
                (Some(a), Some(b)) => a == b,
            }
        }
        cov(self.endpoint, other.endpoint)
            && cov(self.cluster, other.cluster)
            && cov(self.attr, other.attr)
    }

    /// Build the coarsened wildcard entry representing `pivot`'s group at the
    /// given level. Returns `None` if `pivot` cannot be promoted at that level
    /// (e.g. its endpoint is already a wildcard for level 1 or 2).
    fn coarsen(&self, level: u8) -> Option<Self> {
        let (endpoint, cluster) = match level {
            1 => (self.endpoint?, self.cluster?),
            2 => {
                return Some(Self {
                    endpoint: Some(self.endpoint?),
                    cluster: None,
                    attr: None,
                    change_id: 0,
                })
            }
            _ => unreachable!(),
        };

        Some(Self {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attr: None,
            change_id: 0,
        })
    }
}

/// Per-subscription context for an in-progress report.
pub struct ReportContext<'a, 's, B, const N: usize>
where
    B: BufferAccess<IMBuffer> + 'a,
{
    subscriptions: &'s Subscriptions<N>,
    subscriptions_buffers: &'s SubscriptionsBuffers<'a, B, N>,
    subscription: Option<Subscription>,
    subscription_buffer: Option<B::Buffer<'a>>,
    next_max_seen_attr_change_id: u64,
    next_reported_at: Instant,
    keep: bool,
}

impl<'a, 's, B, const N: usize> ReportContext<'a, 's, B, N>
where
    B: BufferAccess<IMBuffer> + 'a,
{
    pub fn subscription(&self) -> &Subscription {
        unwrap!(self.subscription.as_ref())
    }

    pub fn rx(&self) -> &[u8] {
        unwrap!(self.subscription_buffer.as_ref()).as_ref()
    }

    pub fn should_send_if_empty(&self) -> bool {
        // A fresh subscription has `reported_at == Instant::MAX`, which makes
        // `is_report_due` return `true` via its overflow-to-`unwrap_or(true)`
        // branch, so priming reports are delivered unconditionally without a
        // separate `priming` flag.
        unwrap!(self.subscription.as_ref()).is_report_due(self.next_reported_at)
    }

    pub fn should_report_attr(
        &self,
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        attr_id: AttrId,
    ) -> bool {
        let sub = self.subscription();

        // A fresh subscription (priming report) has never reported anything
        // yet; its `reported_at` sentinel doubles as the "priming" marker and
        // means every selected attribute must be delivered, regardless of
        // whether it appears in `changed_attrs`.
        if sub.reported_at == Instant::MAX {
            return true;
        }

        self.subscriptions.state.lock(|state| {
            state.borrow().changed_attrs.contains_since(
                endpoint_id,
                cluster_id,
                attr_id,
                sub.max_seen_attr_change_id,
            )
        })
    }

    pub fn max_seen_event_number(&self) -> EventNumber {
        unwrap!(self.subscription.as_ref()).max_seen_event_number
    }

    pub fn update_max_seen_event_number(&mut self, max_seen_event_number: EventNumber) {
        let sub = unwrap!(self.subscription.as_mut());

        assert!(sub.max_seen_event_number <= max_seen_event_number);
        sub.max_seen_event_number = max_seen_event_number;
    }

    pub fn set_keep(&mut self) {
        self.keep = true;
    }
}

impl<'a, 's, B, const N: usize> Drop for ReportContext<'a, 's, B, N>
where
    B: BufferAccess<IMBuffer> + 'a,
{
    fn drop(&mut self) {
        self.subscriptions.report_complete(self);
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::storage::pooled::PooledBuffers;

    use super::*;

    use embassy_time::Duration;

    type TestPool<const N: usize> = PooledBuffers<N, IMBuffer>;

    // ---------- ChangedAttributes ----------

    #[test]
    fn changed_attrs_starts_empty() {
        let attrs = ChangedAttributes::new();
        assert_eq!(attrs.watermark(), 0);
        assert!(!attrs.any_since(0));
        assert!(!attrs.contains_since(1, 2, 3, 0));
    }

    #[test]
    fn changed_attrs_record_assigns_monotonic_ids() {
        let mut attrs = ChangedAttributes::new();
        let id1 = attrs.record(1, 2, 3);
        let id2 = attrs.record(1, 2, 4);
        let id3 = attrs.record(2, 2, 3);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
        assert_eq!(attrs.watermark(), 3);
    }

    #[test]
    fn changed_attrs_contains_since_and_any_since() {
        let mut attrs = ChangedAttributes::new();
        attrs.record(1, 2, 3);
        attrs.record(1, 2, 4);

        assert!(attrs.any_since(0));
        assert!(attrs.any_since(1));
        assert!(!attrs.any_since(2));

        assert!(attrs.contains_since(1, 2, 3, 0));
        assert!(attrs.contains_since(1, 2, 4, 1));
        // After watermark 2 there are no more changes
        assert!(!attrs.contains_since(1, 2, 3, 2));
        // A never-recorded triple is not covered
        assert!(!attrs.contains_since(9, 9, 9, 0));
    }

    #[test]
    fn changed_attrs_duplicate_refreshes_change_id() {
        let mut attrs = ChangedAttributes::new();
        attrs.record(1, 2, 3);
        attrs.record(1, 2, 4);
        // Same triple as first record - should refresh, not add a new entry.
        let id3 = attrs.record(1, 2, 3);
        assert_eq!(id3, 3);
        assert_eq!(attrs.entries.len(), 2);
        // The (1, 2, 3) entry now has change_id 3, so it is visible from since=2
        assert!(attrs.contains_since(1, 2, 3, 2));
        // But it was originally at id=1, which is now lost - `since=0` still sees it
        // through the refreshed id.
        assert!(attrs.contains_since(1, 2, 3, 0));
    }

    #[test]
    fn changed_attrs_record_wildcard_cluster_covers_every_attr() {
        let mut attrs = ChangedAttributes::new();
        let id = attrs.record_wildcard(Some(7), Some(42));

        // Any concrete attribute on that (endpoint, cluster) is now covered.
        assert!(attrs.contains_since(7, 42, 0, 0));
        assert!(attrs.contains_since(7, 42, 1, 0));
        assert!(attrs.contains_since(7, 42, u32::MAX, 0));
        // Unrelated clusters / endpoints are not.
        assert!(!attrs.contains_since(7, 99, 0, 0));
        assert!(!attrs.contains_since(8, 42, 0, 0));
        assert_eq!(id, attrs.watermark());
    }

    #[test]
    fn changed_attrs_record_wildcard_endpoint_covers_every_cluster() {
        let mut attrs = ChangedAttributes::new();
        attrs.record_wildcard(Some(5), None);

        assert!(attrs.contains_since(5, 1, 1, 0));
        assert!(attrs.contains_since(5, 1000, 1000, 0));
        assert!(!attrs.contains_since(6, 1, 1, 0));
    }

    #[test]
    fn changed_attrs_record_wildcard_absorbs_existing_concrete_entries() {
        let mut attrs = ChangedAttributes::new();
        // Seed three concrete attrs on (1, 2).
        attrs.record(1, 2, 10);
        attrs.record(1, 2, 11);
        attrs.record(1, 2, 12);
        // And one concrete on a different cluster - should survive.
        attrs.record(1, 3, 20);
        assert_eq!(attrs.entries.len(), 4);

        // Recording a cluster-wide wildcard for (1, 2) must collapse the three
        // concrete (1, 2, *) entries into the single wildcard.
        attrs.record_wildcard(Some(1), Some(2));

        assert_eq!(attrs.entries.len(), 2);
        assert!(attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(1) && e.cluster == Some(2) && e.attr.is_none()));
        assert!(attrs.contains_since(1, 3, 20, 0));
    }

    #[test]
    fn changed_attrs_record_wildcard_is_refreshed_when_already_covered() {
        let mut attrs = ChangedAttributes::new();
        // Endpoint-wide wildcard covers any cluster on that endpoint.
        attrs.record_wildcard(Some(1), None);
        let before_len = attrs.entries.len();

        // A cluster-wide wildcard for the same endpoint is already covered
        // by the endpoint-wide one - it must not grow the table and must
        // refresh the existing entry's change id.
        let id = attrs.record_wildcard(Some(1), Some(2));
        assert_eq!(attrs.entries.len(), before_len);
        assert_eq!(attrs.watermark(), id);
    }

    #[test]
    fn changed_attrs_purge_up_to_removes_old_entries() {
        let mut attrs = ChangedAttributes::new();
        attrs.record(1, 2, 3); // id 1
        attrs.record(1, 2, 4); // id 2
        attrs.record(2, 2, 3); // id 3

        attrs.purge_up_to(2);

        assert!(!attrs.contains_since(1, 2, 3, 0));
        assert!(!attrs.contains_since(1, 2, 4, 0));
        assert!(attrs.contains_since(2, 2, 3, 0));

        // Purging with 0 is a no-op.
        attrs.purge_up_to(0);
        assert!(attrs.contains_since(2, 2, 3, 0));
    }

    #[test]
    fn changed_attrs_clear_empties_table_but_keeps_watermark() {
        let mut attrs = ChangedAttributes::new();
        attrs.record(1, 2, 3);
        attrs.record(1, 2, 4);
        let wm_before = attrs.watermark();
        attrs.clear();
        assert!(!attrs.any_since(0));
        // Watermark is preserved so subsequent records remain strictly monotonic.
        assert_eq!(attrs.watermark(), wm_before);
        let id = attrs.record(5, 5, 5);
        assert_eq!(id, wm_before + 1);
    }

    #[test]
    fn changed_attrs_promotion_on_overflow_same_cluster() {
        let mut attrs = ChangedAttributes::new();
        // Fill the table with distinct concrete entries on the same (endpoint, cluster).
        for attr in 0..MAX_CHANGED_ATTRS as u32 {
            attrs.record(1, 2, attr);
        }
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        // One more record must still succeed - the existing entries get promoted.
        let overflow_id = attrs.record(1, 2, 9999);
        assert_eq!(overflow_id as usize, MAX_CHANGED_ATTRS + 1);

        // The table must never overflow its capacity.
        assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);

        // Every originally-recorded concrete attribute must still be reported as
        // "changed" when queried from since=0 (possibly via a coarser wildcard).
        for attr in 0..MAX_CHANGED_ATTRS as u32 {
            assert!(
                attrs.contains_since(1, 2, attr, 0),
                "attr {} lost after promotion",
                attr
            );
        }
        assert!(attrs.contains_since(1, 2, 9999, 0));

        // The new overflow entry is visible from the previous watermark.
        assert!(attrs.contains_since(1, 2, 9999, MAX_CHANGED_ATTRS as u64));
    }

    #[test]
    fn changed_attrs_promotion_to_global_wildcard() {
        let mut attrs = ChangedAttributes::new();
        // Entries spread across many endpoints/clusters/attrs to force promotion
        // past the (endpoint, cluster, *) and (endpoint, *, *) levels.
        for i in 0..(MAX_CHANGED_ATTRS as u16 + 5) {
            attrs.record(i, i as u32, i as u32);
        }
        assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);
        // All previously-recorded triples must still report as changed.
        for i in 0..(MAX_CHANGED_ATTRS as u16 + 5) {
            assert!(attrs.contains_since(i, i as u32, i as u32, 0));
        }
        // And an arbitrary never-recorded triple may or may not be covered
        // (over-reporting is allowed), but `any_since(0)` must be true.
        assert!(attrs.any_since(0));
    }

    #[test]
    fn promotion_prefers_largest_level_1_group() {
        // 10 entries on (1, 1, *) and 5 singletons on (1, k, 0) for k=2..=6
        // (= 15 entries total). One extra record fills the table, then an
        // overflowing record forces exactly ONE level-1 promotion which must
        // collapse the big (1, 1, *) group while leaving singletons concrete.
        let mut attrs = ChangedAttributes::new();
        for attr in 0..10u32 {
            attrs.record(1, 1, attr);
        }
        for cluster in 2..=6u32 {
            attrs.record(1, cluster, 0);
        }
        // Fill exactly to capacity without overflow.
        attrs.record(1, 1, 100);
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        // Now overflow to trigger promotion.
        attrs.record(2, 2, 2);
        assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);

        // The big (1, 1, *) group became exactly one wildcard entry.
        let wild_11 = attrs
            .entries
            .iter()
            .filter(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_none())
            .count();
        assert_eq!(wild_11, 1);
        // No concrete (1, 1, _) entries survived.
        let concrete_11 = attrs
            .entries
            .iter()
            .filter(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_some())
            .count();
        assert_eq!(concrete_11, 0);
        // Singletons on (1, k, 0) for k=2..=6 remain concrete.
        for cluster in 2..=6u32 {
            let n = attrs
                .entries
                .iter()
                .filter(|e| {
                    e.endpoint == Some(1) && e.cluster == Some(cluster) && e.attr == Some(0)
                })
                .count();
            assert_eq!(n, 1, "singleton (1, {}, 0) should remain concrete", cluster);
        }
        // The new (2, 2, 2) entry is present as a concrete entry.
        assert!(attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(2) && e.cluster == Some(2) && e.attr == Some(2)));

        // All original triples still report as changed.
        for attr in 0..10u32 {
            assert!(attrs.contains_since(1, 1, attr, 0));
        }
        for cluster in 2..=6u32 {
            assert!(attrs.contains_since(1, cluster, 0, 0));
        }
        assert!(attrs.contains_since(1, 1, 100, 0));
        assert!(attrs.contains_since(2, 2, 2, 0));
    }

    #[test]
    fn promotion_is_minimal_only_one_group_collapsed_per_overflow() {
        // Two big level-1 groups of equal size. A single overflow must collapse
        // only ONE of them, not both (minimal promotion).
        let mut attrs = ChangedAttributes::new();
        // Group A: (1, 1, 0..8) = 8 entries
        for attr in 0..8u32 {
            attrs.record(1, 1, attr);
        }
        // Group B: (2, 2, 0..8) = 8 entries
        for attr in 0..8u32 {
            attrs.record(2, 2, attr);
        }
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        // Overflow with an unrelated entry.
        attrs.record(9, 9, 9);

        // Exactly one of the groups got collapsed into a wildcard.
        let a_wild = attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_none());
        let b_wild = attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(2) && e.cluster == Some(2) && e.attr.is_none());
        assert!(
            a_wild ^ b_wild,
            "expected exactly one of the groups to be collapsed (A: {}, B: {})",
            a_wild,
            b_wild
        );
        // The un-collapsed group still has all 8 concrete entries.
        let a_concrete = attrs
            .entries
            .iter()
            .filter(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_some())
            .count();
        let b_concrete = attrs
            .entries
            .iter()
            .filter(|e| e.endpoint == Some(2) && e.cluster == Some(2) && e.attr.is_some())
            .count();
        assert!(
            (a_wild && a_concrete == 0 && b_concrete == 8)
                || (b_wild && b_concrete == 0 && a_concrete == 8)
        );
    }

    #[test]
    fn promotion_falls_back_to_level_2_when_no_level_1_group() {
        // All (endpoint, cluster) pairs are unique (level-1 groups are all
        // singletons) but endpoints repeat, so level-2 groups are non-trivial.
        let mut attrs = ChangedAttributes::new();
        for cluster in 0..8u32 {
            attrs.record(1, cluster, 0);
        }
        for cluster in 0..8u32 {
            attrs.record(2, cluster, 0);
        }
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        attrs.record(3, 9, 9);
        assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);

        // No level-1 wildcard (endpoint, cluster, *) was produced.
        let lvl1_wild = attrs
            .entries
            .iter()
            .filter(|e| e.endpoint.is_some() && e.cluster.is_some() && e.attr.is_none())
            .count();
        assert_eq!(lvl1_wild, 0);
        // Exactly one level-2 wildcard on endpoint 1 or 2 was produced.
        let ep1_wild = attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(1) && e.cluster.is_none() && e.attr.is_none());
        let ep2_wild = attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(2) && e.cluster.is_none() && e.attr.is_none());
        assert!(ep1_wild ^ ep2_wild);
        // No global wildcard was produced either.
        assert!(!attrs
            .entries
            .iter()
            .any(|e| e.endpoint.is_none() && e.cluster.is_none() && e.attr.is_none()));

        // All originals still visible.
        for cluster in 0..8u32 {
            assert!(attrs.contains_since(1, cluster, 0, 0));
            assert!(attrs.contains_since(2, cluster, 0, 0));
        }
        assert!(attrs.contains_since(3, 9, 9, 0));
    }

    #[test]
    fn promotion_falls_back_to_global_only_when_no_lower_group() {
        // All-distinct endpoints AND (endpoint, cluster) pairs: no level-1 or
        // level-2 group has >=2 entries. Overflow must collapse everything to
        // a single global wildcard.
        let mut attrs = ChangedAttributes::new();
        for i in 0..MAX_CHANGED_ATTRS as u16 {
            attrs.record(i, i as u32, i as u32);
        }
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        attrs.record(100, 200, 300);
        assert_eq!(attrs.entries.len(), 1);
        let only = &attrs.entries[0];
        assert!(only.endpoint.is_none() && only.cluster.is_none() && only.attr.is_none());

        // Every previously-recorded triple is still covered.
        for i in 0..MAX_CHANGED_ATTRS as u16 {
            assert!(attrs.contains_since(i, i as u32, i as u32, 0));
        }
        assert!(attrs.contains_since(100, 200, 300, 0));
    }

    #[test]
    fn promotion_preserves_max_change_id_in_coarsened_entry() {
        // After collapsing a (1, 1, *) group, the resulting wildcard's
        // change_id must equal the max change_id of the collapsed entries.
        let mut attrs = ChangedAttributes::new();
        for attr in 0..MAX_CHANGED_ATTRS as u32 {
            attrs.record(1, 1, attr);
        }
        let max_before = attrs.watermark();

        attrs.record(2, 2, 2);
        let wild = attrs
            .entries
            .iter()
            .find(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_none())
            .expect("(1, 1, *) wildcard was produced");
        assert_eq!(wild.change_id, max_before);

        // contains_since respects that watermark exactly.
        assert!(attrs.contains_since(1, 1, 0, max_before - 1));
        assert!(!attrs.contains_since(1, 1, 0, max_before));
    }

    #[test]
    fn promotion_with_existing_wildcard_refreshes_instead_of_promoting_again() {
        // Build a state where (1, 1, *) wildcard already exists via a forced
        // promotion. Recording another (1, 1, k) must refresh that wildcard's
        // change_id without producing any new entry.
        let mut attrs = ChangedAttributes::new();
        for attr in 0..MAX_CHANGED_ATTRS as u32 {
            attrs.record(1, 1, attr);
        }
        attrs.record(2, 2, 2); // forces (1, 1, *) promotion

        // Now the table has 2 entries: (1, 1, *) and (2, 2, 2).
        assert_eq!(attrs.entries.len(), 2);
        let wm_after_promo = attrs.watermark();

        let new_id = attrs.record(1, 1, 42);
        // No new entry: still 2 entries. Wildcard's change_id advanced.
        assert_eq!(attrs.entries.len(), 2);
        assert_eq!(new_id, wm_after_promo + 1);
        let wild = attrs
            .entries
            .iter()
            .find(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_none())
            .unwrap();
        assert_eq!(wild.change_id, new_id);
    }

    #[test]
    fn promotion_capacity_invariant_under_sustained_churn() {
        // Sustained mixed churn must never let the table exceed its capacity,
        // and every freshly-recorded triple must remain visible immediately
        // after recording.
        let mut attrs = ChangedAttributes::new();
        for i in 0..1000u32 {
            let endpoint = (i % 7) as u16;
            let cluster = i % 13;
            let attr = i;
            attrs.record(endpoint, cluster, attr);
            assert!(
                attrs.entries.len() <= MAX_CHANGED_ATTRS,
                "capacity exceeded at i={}",
                i
            );
            assert!(
                attrs.contains_since(endpoint, cluster, attr, 0),
                "just-recorded triple lost at i={}",
                i
            );
        }
    }

    #[test]
    fn promotion_iterated_into_same_existing_wildcard() {
        // Once (1, 1, *) exists, repeated inserts on that group must never
        // grow the table, and never trigger further promotion.
        let mut attrs = ChangedAttributes::new();
        for attr in 0..MAX_CHANGED_ATTRS as u32 {
            attrs.record(1, 1, attr);
        }
        attrs.record(2, 2, 2); // -> [(1,1,*), (2,2,2)]
        assert_eq!(attrs.entries.len(), 2);

        for attr in 100..200u32 {
            attrs.record(1, 1, attr);
            assert_eq!(attrs.entries.len(), 2);
        }
    }

    #[test]
    fn promotion_escalates_when_level_1_group_still_insufficient() {
        // Pathological case: a single level-1 group of size 2 exists, the rest
        // are singletons. After the first overflow, that group collapses
        // (freeing 1 slot), but the table is still full once the new record
        // tries to be inserted on a fresh singleton location. Subsequent
        // overflows must escalate to level-2 / global.
        let mut attrs = ChangedAttributes::new();
        // 2 entries sharing (1, 1, *) -- a single level-1 group of size 2.
        attrs.record(1, 1, 0);
        attrs.record(1, 1, 1);
        // Fill the rest with unique (endpoint, cluster) pairs.
        for i in 0..(MAX_CHANGED_ATTRS as u16 - 2) {
            attrs.record(10 + i, 100 + i as u32, i as u32);
        }
        assert_eq!(attrs.entries.len(), MAX_CHANGED_ATTRS);

        // First overflow: the only level-1 group collapses; then the new entry
        // gets inserted.
        attrs.record(50, 50, 50);
        assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);
        // The (1, 1, *) wildcard is present.
        assert!(attrs
            .entries
            .iter()
            .any(|e| e.endpoint == Some(1) && e.cluster == Some(1) && e.attr.is_none()));

        // Keep feeding: eventually we must fall back to level-2 or global
        // without breaking correctness.
        for i in 0..200u32 {
            let endpoint = 200 + (i % 5) as u16;
            let cluster = 300 + (i % 3);
            let attr = i;
            attrs.record(endpoint, cluster, attr);
            assert!(attrs.entries.len() <= MAX_CHANGED_ATTRS);
            assert!(attrs.contains_since(endpoint, cluster, attr, 0));
        }
        // Historical triples still covered.
        assert!(attrs.contains_since(1, 1, 0, 0));
        assert!(attrs.contains_since(1, 1, 1, 0));
        assert!(attrs.contains_since(50, 50, 50, 0));
    }

    #[test]
    fn changed_attr_covers_wildcards() {
        let concrete = ChangedAttr::concrete(1, 2, 3, 1);
        let any_attr = ChangedAttr {
            endpoint: Some(1),
            cluster: Some(2),
            attr: None,
            change_id: 1,
        };
        let any_cluster = ChangedAttr {
            endpoint: Some(1),
            cluster: None,
            attr: None,
            change_id: 1,
        };
        let global = ChangedAttr {
            endpoint: None,
            cluster: None,
            attr: None,
            change_id: 1,
        };

        assert!(any_attr.covers(&concrete));
        assert!(any_cluster.covers(&concrete));
        assert!(global.covers(&concrete));
        // Concrete does not cover wildcards.
        assert!(!concrete.covers(&any_attr));
        assert!(!concrete.covers(&global));
        // Concrete matches itself.
        assert!(concrete.matches(1, 2, 3));
        assert!(!concrete.matches(1, 2, 4));
        // Wildcards match any concrete triple on the wildcarded axis.
        assert!(any_attr.matches(1, 2, 99));
        assert!(!any_attr.matches(1, 9, 99));
        assert!(global.matches(99, 99, 99));
    }

    // ---------- Subscriptions ----------

    fn fab(i: u8) -> NonZeroU8 {
        NonZeroU8::new(i).unwrap()
    }

    #[test]
    fn add_returns_monotonic_ids_and_rejects_when_full() {
        let subs: Subscriptions<2> = Subscriptions::new();
        let pool = TestPool::<3>::new(0);
        let subs_bufs: SubscriptionsBuffers<TestPool<3>, 2> = SubscriptionsBuffers::new();

        let now = Instant::now();

        let rctx1 = subs
            .add(
                now,
                fab(1),
                10,
                100,
                1,
                60,
                0,
                pool.get_immediate().unwrap(),
                &subs_bufs,
            )
            .unwrap();
        let rctx2 = subs
            .add(
                now,
                fab(1),
                10,
                100,
                1,
                60,
                0,
                pool.get_immediate().unwrap(),
                &subs_bufs,
            )
            .unwrap();
        assert_eq!(rctx1.subscription().ids().id, 1);
        assert_eq!(rctx2.subscription().ids().id, 2);

        // Third add exceeds N=2.
        assert!(subs
            .add(
                now,
                fab(1),
                10,
                100,
                1,
                60,
                0,
                pool.get_immediate().unwrap(),
                &subs_bufs
            )
            .is_none());
    }

    #[test]
    fn begin_report_snapshots_watermark_and_pending() {
        let subs: Subscriptions<2> = Subscriptions::new();
        let pool = TestPool::<3>::new(0);
        let subs_bufs: SubscriptionsBuffers<TestPool<3>, 2> = SubscriptionsBuffers::new();

        let now = Instant::now();

        subs.notify_attribute_changed(1, 2, 3);
        {
            let mut rctx = subs
                .add(
                    now,
                    fab(1),
                    10,
                    100,
                    1,
                    60,
                    0,
                    pool.get_immediate().unwrap(),
                    &subs_bufs,
                )
                .unwrap();

            // The priming report is un-filtered: every attribute is reported and
            // `should_send_if_empty` is true so that the snapshot is delivered
            // unconditionally.
            assert!(rctx.should_send_if_empty());
            assert!(rctx.should_report_attr(1, 2, 3));
            assert!(rctx.should_report_attr(42, 55555, 1234556677));

            rctx.set_keep();
        }

        // A new change bumps the watermark and becomes pending.
        subs.notify_attribute_changed(1, 2, 4);
        // `min_int` = 1s has not elapsed at `now`, so the subscription is not
        // yet report-allowed; step past it.
        let later = now + Duration::from_secs(2);
        let rctx = subs.report(later, 0, &subs_bufs).unwrap();
        assert!(!rctx.should_send_if_empty());
        // The priming commit advanced the sub's `since` past the (1, 2, 3)
        // change, so only the new (1, 2, 4) is pending.
        assert!(!rctx.should_report_attr(1, 2, 3));
        assert!(rctx.should_report_attr(1, 2, 4));
    }

    // The following tests cover the public API of `Subscriptions` /
    // `SubscriptionsBuffers` / `ReportContext` post-refactor. A few of the
    // pre-refactor tests had no meaningful successor and were deleted:
    //
    //   * `sub_attr_change_filter_honors_since_watermark` — `SubAttrChangeFilter`
    //     is now dead code (see REVIEW above); the `since`-watermark logic is
    //     already covered by `changed_attrs_contains_since_and_any_since`.
    //   * `find_report_due_events_pending_receives_subscription_watermark` —
    //     the old `events_pending` callback no longer exists; the
    //     subscription's `max_seen_event_number` is now compared directly
    //     against the `max_event_number` passed to `Subscriptions::report`.
    //   * `find_removed_session_matches_predicate` — `session_id` tracking
    //     was dropped in the refactor (see REVIEW on `SubscriptionsInner::add`).
    //     Predicate-based removal is covered by `remove_invokes_predicate_*`.

    /// Helper: add a subscription with sensible defaults and return its `ReportContext`.
    fn add_sub<'a, 's, const N: usize, const B: usize>(
        subs: &'s Subscriptions<N>,
        subs_bufs: &'s SubscriptionsBuffers<'a, TestPool<B>, N>,
        pool: &'a TestPool<B>,
        now: Instant,
        fab_idx: u8,
        peer_node_id: u64,
        min_int: u16,
        max_int: u16,
    ) -> ReportContext<'a, 's, TestPool<B>, N>
    where
        'a: 's,
    {
        subs.add(
            now,
            fab(fab_idx),
            peer_node_id,
            /* session_id */ 0,
            min_int,
            max_int,
            /* max_event_number */ 0,
            pool.get_immediate().unwrap(),
            subs_bufs,
        )
        .unwrap()
    }

    #[test]
    fn priming_report_context_is_report_due_and_keeps_sub() {
        // A subscription returned from `add` is the "priming" report: it must be
        // report-due regardless of time (so the initial report is delivered
        // unconditionally) and, when dropped with `set_keep`, must survive in
        // the subscription table for subsequent incremental reports.
        let subs: Subscriptions<1> = Subscriptions::new();
        let pool = TestPool::<2>::new(0);
        let subs_bufs: SubscriptionsBuffers<TestPool<2>, 1> = SubscriptionsBuffers::new();

        let now = Instant::now();
        {
            let mut rctx = add_sub(&subs, &subs_bufs, &pool, now, 1, 10, 1, 60);
            assert!(rctx.should_send_if_empty());
            assert_eq!(rctx.max_seen_event_number(), 0);
            rctx.set_keep();
        }

        // After priming, a zero-delta report at the same instant finds nothing
        // pending (no attr changes, no new events, min_int not elapsed).
        assert!(subs.report(now, 0, &subs_bufs).is_none());
    }

    #[test]
    fn report_without_keep_frees_the_slot() {
        // Dropping a `ReportContext` *without* `set_keep` must remove the
        // subscription from the table (and free its buffer), so a new
        // subscription can take its place up to the `N` capacity.
        let subs: Subscriptions<1> = Subscriptions::new();
        let pool = TestPool::<2>::new(0);
        let subs_bufs: SubscriptionsBuffers<TestPool<2>, 1> = SubscriptionsBuffers::new();

        let now = Instant::now();

        // Add then drop without keep.
        drop(add_sub(&subs, &subs_bufs, &pool, now, 1, 10, 1, 60));

        // The slot is free again: a second add succeeds even with N=1.
        let mut rctx = add_sub(&subs, &subs_bufs, &pool, now, 1, 11, 1, 60);
        // IDs are still strictly monotonic across add/remove cycles.
        assert_eq!(rctx.subscription().ids().id, 2);
        rctx.set_keep();
    }

    #[test]
    fn report_with_keep_advances_reported_at_and_watermark() {
        // After a "kept" report, the subscription must not be picked up again
        // at the same instant unless new changes arrive.
        let subs: Subscriptions<1> = Subscriptions::new();
        let pool = TestPool::<2>::new(0);
        let subs_bufs: SubscriptionsBuffers<TestPool<2>, 1> = SubscriptionsBuffers::new();

        let now = Instant::now();

        // Prime and keep.
        {
            let mut rctx = add_sub(&subs, &subs_bufs, &pool, now, 1, 10, 1, 60);
            rctx.set_keep();
        }

        // Record one attribute change — watermark advances to 1.
        subs.notify_attribute_changed(1, 2, 3);

        // At the same instant, min_int (1s) has NOT elapsed so the sub is not
        // report-allowed: even though there is a pending change, `report()`
        // returns None.
        assert!(subs.report(now, 0, &subs_bufs).is_none());

        // Past min_int: the pending change makes the sub reportable.
        let later = now + Duration::from_secs(2);
        {
            let mut rctx = subs.report(later, 0, &subs_bufs).unwrap();
            assert!(rctx.should_report_attr(1, 2, 3));
            // A fresh (never recorded) triple is NOT in the table and must
            // not be spuriously reported.
            assert!(!rctx.should_report_attr(9, 9, 9));
            rctx.set_keep();
        }

        // Watermark has been committed — another call at `later` with no new
        // activity finds nothing.
        assert!(subs.report(later, 0, &subs_bufs).is_none());
    }

    #[test]
    fn report_triggered_by_new_events() {
        // A bump in `max_event_number` (i.e. a newly emitted event) makes the
        // subscription reportable even without attribute changes.
        let subs: Subscriptions<1> = Subscriptions::new();
        let pool = TestPool::<2>::new(0);
        let subs_bufs: SubscriptionsBuffers<TestPool<2>, 1> = SubscriptionsBuffers::new();

        let now = Instant::now();
        {
            let mut rctx = add_sub(&subs, &subs_bufs, &pool, now, 1, 10, 1, 60);
            rctx.set_keep();
        }

        // Same instant, no new events (max_event_number = 0 same as sub's
        // max_seen), min_int not elapsed → nothing to report.
        assert!(subs.report(now, 0, &subs_bufs).is_none());

        let later = now + Duration::from_secs(2);

        // Still no new events at `later` (min_int elapsed though).
        assert!(subs.report(later, 0, &subs_bufs).is_none());

        // A new event bumps max_event_number → sub is reportable.
        {
            let mut rctx = subs.report(later, 5, &subs_bufs).unwrap();
            assert_eq!(rctx.max_seen_event_number(), 0);
            rctx.update_max_seen_event_number(5);
            assert_eq!(rctx.max_seen_event_number(), 5);
            rctx.set_keep();
        }

        // After reporting, max_event_number=5 is no longer "new" for this sub.
        assert!(subs.report(later, 5, &subs_bufs).is_none());
        // But a further bump does trigger again (past min_int is needed).
        let even_later = later + Duration::from_secs(2);
        {
            let mut rctx = subs.report(even_later, 6, &subs_bufs).unwrap();
            rctx.set_keep();
        }
    }

    #[test]
    fn report_triggered_by_liveness_deadline() {
        // With no changes at all, a subscription still becomes reportable once
        // it enters the "liveness" window (within half of `max_int` of the
        // deadline).
        let subs: Subscriptions<1> = Subscriptions::new();
        let pool = TestPool::<2>::new(0);
        let subs_bufs: SubscriptionsBuffers<TestPool<2>, 1> = SubscriptionsBuffers::new();

        let now = Instant::now();
        // max_int = 20s → half of max_int = 10s → becomes report-due at now+10s.
        {
            let mut rctx = add_sub(&subs, &subs_bufs, &pool, now, 1, 10, 1, 20);
            rctx.set_keep();
        }

        // Short of the liveness window: not due.
        let short = now + Duration::from_secs(5);
        assert!(subs.report(short, 0, &subs_bufs).is_none());

        // At the liveness window: due even without any attr/event change.
        let long = now + Duration::from_secs(11);
        {
            let mut rctx = subs.report(long, 0, &subs_bufs).unwrap();
            assert!(rctx.should_send_if_empty());
            rctx.set_keep();
        }
    }

    #[test]
    fn is_expired_uses_max_int() {
        // `Subscription::is_expired` returns true once `max_int` has elapsed
        // since the last reported_at.
        let subs: Subscriptions<1> = Subscriptions::new();
        let pool = TestPool::<2>::new(0);
        let subs_bufs: SubscriptionsBuffers<TestPool<2>, 1> = SubscriptionsBuffers::new();

        let base = Instant::now();
        {
            let mut rctx = add_sub(&subs, &subs_bufs, &pool, base, 1, 10, 1, 5);
            rctx.set_keep();
        }

        // Before max_int: not expired. Use the `remove` predicate as a probe
        // because we have no other way to observe per-sub `is_expired` through
        // the public API.
        let before = base + Duration::from_secs(2);
        assert!(!subs.remove(&subs_bufs, |sub| sub
            .is_expired(before)
            .then_some("expired")));

        // Past max_int: expired — removal fires.
        let after = base + Duration::from_secs(10);
        assert!(subs.remove(&subs_bufs, |sub| sub.is_expired(after).then_some("expired")));
    }

    #[test]
    fn remove_invokes_predicate_and_frees_slots() {
        // `Subscriptions::remove` drains every matching entry (not just one),
        // returns whether anything was removed, and frees the slots so that
        // subsequent `add` calls succeed up to the capacity `N`.
        let subs: Subscriptions<3> = Subscriptions::new();
        let pool = TestPool::<4>::new(0);
        let subs_bufs: SubscriptionsBuffers<TestPool<4>, 3> = SubscriptionsBuffers::new();

        let now = Instant::now();
        for peer in [100_u64, 101, 102] {
            let fab_idx = if peer == 102 { 2 } else { 1 };
            let mut rctx = add_sub(&subs, &subs_bufs, &pool, now, fab_idx, peer, 1, 60);
            rctx.set_keep();
        }
        // Table is full: a 4th add must be rejected.
        assert!(subs
            .add(
                now,
                fab(1),
                200,
                0,
                1,
                60,
                0,
                pool.get_immediate().unwrap(),
                &subs_bufs
            )
            .is_none());

        // Remove every fab(1) subscription (2 of them).
        let mut seen_peers: std::vec::Vec<u64> = std::vec::Vec::new();
        let removed = subs.remove(&subs_bufs, |sub| {
            if sub.ids().fab_idx == fab(1) {
                seen_peers.push(sub.ids().peer_node_id);
                Some("fabric 1 removed")
            } else {
                None
            }
        });
        assert!(removed);
        seen_peers.sort();
        assert_eq!(seen_peers, std::vec![100_u64, 101]);

        // A second identical remove is a no-op and returns false.
        assert!(!subs.remove(&subs_bufs, |sub| (sub.ids().fab_idx == fab(1))
            .then_some("fabric 1 removed")));

        // Two slots were freed: we can add two more subs.
        {
            let mut r1 = add_sub(&subs, &subs_bufs, &pool, now, 3, 300, 1, 60);
            r1.set_keep();
            let mut r2 = add_sub(&subs, &subs_bufs, &pool, now, 3, 301, 1, 60);
            r2.set_keep();
        }
        // And a third add is rejected again (back at capacity).
        assert!(subs
            .add(
                now,
                fab(3),
                302,
                0,
                1,
                60,
                0,
                pool.get_immediate().unwrap(),
                &subs_bufs
            )
            .is_none());
    }

    #[test]
    fn remove_on_empty_table_returns_false() {
        let subs: Subscriptions<2> = Subscriptions::new();
        let subs_bufs: SubscriptionsBuffers<TestPool<2>, 2> = SubscriptionsBuffers::new();
        assert!(!subs.remove(&subs_bufs, |_| Some("never called on empty")));
    }

    #[test]
    fn purge_reported_changes_keeps_entries_until_all_subs_catch_up() {
        // `purge_reported_changes` must only drop table entries every
        // subscription has already reported on: the slowest subscriber's
        // `max_seen_attr_change_id` acts as a floor.
        let subs: Subscriptions<2> = Subscriptions::new();
        let pool = TestPool::<3>::new(0);
        let subs_bufs: SubscriptionsBuffers<TestPool<3>, 2> = SubscriptionsBuffers::new();

        let base = Instant::now();

        // Two priming adds. Both start at watermark = 0 (no changes yet).
        // `ReportContext::next_max_seen_attr_change_id` is captured as 0 by
        // `add`, so dropping either rctx with keep commits max_seen = 0.
        {
            let mut r1 = add_sub(&subs, &subs_bufs, &pool, base, 1, 100, 1, 60);
            r1.set_keep();
            let mut r2 = add_sub(&subs, &subs_bufs, &pool, base, 1, 101, 1, 60);
            r2.set_keep();
        }

        // Record two changes. Watermark becomes 2.
        subs.notify_attribute_changed(1, 2, 3); // id 1
        subs.notify_attribute_changed(1, 2, 4); // id 2

        // Advance both subs to watermark 2 via two `report` + keep cycles.
        let later = base + Duration::from_secs(2);
        for _ in 0..2 {
            let mut rctx = subs.report(later, 0, &subs_bufs).unwrap();
            assert!(rctx.should_report_attr(1, 2, 3));
            assert!(rctx.should_report_attr(1, 2, 4));
            rctx.set_keep();
        }

        // Both subs have max_seen = 2; purge is safe and removes the stale
        // entries. The next report should now find nothing pending (same
        // instant, no new changes, min_int elapsed but not half of max_int).
        subs.purge_reported_changes();
        assert!(subs.report(later, 0, &subs_bufs).is_none());

        // A brand new change becomes pending again post-purge.
        subs.notify_attribute_changed(5, 6, 7);
        let even_later = later + Duration::from_secs(2);
        {
            let mut rctx = subs.report(even_later, 0, &subs_bufs).unwrap();
            assert!(rctx.should_report_attr(5, 6, 7));
            // Previously-purged entries are no longer visible through the
            // sub's filter either.
            assert!(!rctx.should_report_attr(1, 2, 3));
            rctx.set_keep();
        }
    }

    #[test]
    fn update_max_seen_event_number_is_monotonic() {
        // The setter advances the watermark but panics on regression
        // (asserted in `update_max_seen_event_number`). We only exercise the
        // monotonic-advance path here to avoid a deliberate panic in tests.
        let subs: Subscriptions<1> = Subscriptions::new();
        let pool = TestPool::<2>::new(0);
        let subs_bufs: SubscriptionsBuffers<TestPool<2>, 1> = SubscriptionsBuffers::new();

        let now = Instant::now();
        let mut rctx = add_sub(&subs, &subs_bufs, &pool, now, 1, 10, 1, 60);
        assert_eq!(rctx.max_seen_event_number(), 0);
        rctx.update_max_seen_event_number(3);
        assert_eq!(rctx.max_seen_event_number(), 3);
        rctx.update_max_seen_event_number(3); // equal is allowed
        assert_eq!(rctx.max_seen_event_number(), 3);
        rctx.update_max_seen_event_number(42);
        assert_eq!(rctx.max_seen_event_number(), 42);
    }
}
