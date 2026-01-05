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

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_time::Instant;

use crate::dm::{AttrId, ClusterId, EndptId};
use crate::fabric::MAX_FABRICS;
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;

/// The maximum number of subscriptions that can be tracked at the same time by default.
///
/// According to the Matter spec, at least 3 subscriptions per fabric should be supported.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = MAX_FABRICS * 3;

/// A type alias for `Subscriptions` with the default maximum number of subscriptions.
pub type DefaultSubscriptions = Subscriptions<DEFAULT_MAX_SUBSCRIPTIONS>;

struct Subscription {
    fabric_idx: NonZeroU8,
    peer_node_id: u64,
    session_id: Option<u32>,
    id: u32,
    // We use u16 instead of embassy::Duration to save some storage
    min_int_secs: u16,
    // Ditto
    max_int_secs: u16,
    // TODO: Change to `Option<Instant>` to avoid using `Instant::MAX` as a sentinel value
    reported_at: Instant,
    changed: bool,
}

impl Subscription {
    pub fn report_due(&self, now: Instant) -> bool {
        // Either the data for the subscription had changed and therefore we need to report,
        // or the data for the subscription had not changed yet, however the report interval is due
        self.changed && self.expired(self.min_int_secs, now)
            || self.expired(self.min_int_secs.max(self.max_int_secs / 2), now)
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        self.expired(self.max_int_secs, now)
    }

    fn expired(&self, secs: u16, now: Instant) -> bool {
        self.reported_at
            .checked_add(embassy_time::Duration::from_secs(secs as _))
            .map(|expiry| expiry <= now)
            .unwrap_or(false)
    }
}

struct SubscriptionsInner<const N: usize> {
    next_subscription_id: u32,
    subscriptions: crate::utils::storage::Vec<Subscription, N>,
}

impl<const N: usize> SubscriptionsInner<N> {
    /// Create the instance.
    #[inline(always)]
    const fn new() -> Self {
        Self {
            next_subscription_id: 1,
            subscriptions: crate::utils::storage::Vec::new(),
        }
    }

    /// Create an in-place initializer for the instance.
    fn init() -> impl Init<Self> {
        init!(Self {
            next_subscription_id: 1,
            subscriptions <- crate::utils::storage::Vec::init(),
        })
    }
}

/// A utility for tracking subscriptions accepted by the data model.
///
/// The `N` type parameter specifies the maximum number of subscriptions that can be tracked at the same time.
/// Additional subscriptions are rejected by the data model with a "resource exhausted" IM status message.
pub struct Subscriptions<const N: usize = DEFAULT_MAX_SUBSCRIPTIONS, M = NoopRawMutex>
where
    M: RawMutex,
{
    state: Mutex<M, RefCell<SubscriptionsInner<N>>>,
    pub(crate) notification: Notification<M>,
}

impl<const N: usize, M> Subscriptions<N, M>
where
    M: RawMutex,
{
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
    pub fn notify_attribute_changed(
        &self,
        _endpoint_id: EndptId,
        _cluster_id: ClusterId,
        _attr_id: AttrId,
    ) {
        // TODO: Make use of the endpoint_id, cluster_id, and attr_id parameters
        // to implement more intelligent reporting on subscriptions

        self.state.lock(|internal| {
            let subscriptions = &mut internal.borrow_mut().subscriptions;
            for sub in subscriptions.iter_mut() {
                sub.changed = true;
            }
        });

        self.notification.notify();
    }

    pub(crate) fn add(
        &self,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
        session_id: u32,
        min_int_secs: u16,
        max_int_secs: u16,
    ) -> Option<u32> {
        self.state.lock(|internal| {
            let mut state = internal.borrow_mut();
            let id = state.next_subscription_id;
            state.next_subscription_id += 1;

            state
                .subscriptions
                .push(Subscription {
                    fabric_idx,
                    peer_node_id,
                    session_id: Some(session_id),
                    id,
                    min_int_secs,
                    max_int_secs,
                    reported_at: Instant::MAX,
                    changed: false,
                })
                .map(|_| id)
                .ok()
        })
    }

    /// Mark the subscription with the given ID as reported.
    ///
    /// Will return `false` if the subscription with the given ID does no longer exist, as it might be
    /// removed by a concurrent transaction while being reported on.
    pub(crate) fn mark_reported(&self, id: u32) -> bool {
        self.state.lock(|internal| {
            let subscriptions = &mut internal.borrow_mut().subscriptions;

            if let Some(sub) = subscriptions.iter_mut().find(|sub| sub.id == id) {
                sub.reported_at = Instant::now();
                sub.changed = false;

                true
            } else {
                false
            }
        })
    }

    pub(crate) fn remove(
        &self,
        fabric_idx: Option<NonZeroU8>,
        peer_node_id: Option<u64>,
        id: Option<u32>,
    ) {
        self.state.lock(|internal| {
            let subscriptions = &mut internal.borrow_mut().subscriptions;
            while let Some(index) = subscriptions.iter().position(|sub| {
                sub.fabric_idx == fabric_idx.unwrap_or(sub.fabric_idx)
                    && sub.peer_node_id == peer_node_id.unwrap_or(sub.peer_node_id)
                    && sub.id == id.unwrap_or(sub.id)
            }) {
                subscriptions.swap_remove(index);
            }
        })
    }

    pub(crate) fn find_removed_session<F>(
        &self,
        session_removed: F,
    ) -> Option<(NonZeroU8, u64, u32, u32)>
    where
        F: Fn(u32) -> bool,
    {
        self.state.lock(|internal| {
            internal.borrow_mut().subscriptions.iter().find_map(|sub| {
                sub.session_id
                    .map(&session_removed)
                    .unwrap_or(false)
                    .then_some((
                        sub.fabric_idx,
                        sub.peer_node_id,
                        unwrap!(sub.session_id),
                        sub.id,
                    ))
            })
        })
    }

    pub(crate) fn find_expired(&self, now: Instant) -> Option<(NonZeroU8, u64, Option<u32>, u32)> {
        self.state.lock(|internal| {
            internal.borrow_mut().subscriptions.iter().find_map(|sub| {
                sub.is_expired(now).then_some((
                    sub.fabric_idx,
                    sub.peer_node_id,
                    sub.session_id,
                    sub.id,
                ))
            })
        })
    }

    /// Note that this method has a side effect:
    /// it updates the `reported_at` field of the subscription that is returned.
    pub(crate) fn find_report_due(
        &self,
        now: Instant,
    ) -> Option<(NonZeroU8, u64, Option<u32>, u32)> {
        self.state.lock(|internal| {
            internal
                .borrow_mut()
                .subscriptions
                .iter_mut()
                .find(|sub| sub.report_due(now))
                .map(|sub| {
                    sub.reported_at = now;
                    (sub.fabric_idx, sub.peer_node_id, sub.session_id, sub.id)
                })
        })
    }
}

impl<const N: usize> Default for Subscriptions<N> {
    fn default() -> Self {
        Self::new()
    }
}
