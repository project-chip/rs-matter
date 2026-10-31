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

use core::future::Future;
use core::num::NonZeroU8;

use crate::utils::sync::{MaybeSend, MaybeSendSync};
use crate::utils::timers::Instant;

use super::NodeId;

/// Resource-utilisation metrics for the node, as reported by
/// `GeneralDiagnostics::DeviceLoadStatus`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceLoad {
    /// Subscriptions currently established on the node, across all fabrics.
    pub current_subscriptions: u16,
    /// Subscriptions currently established on the fabric of the reading
    /// subject. Zero when the figures were gathered without a fabric in scope.
    pub current_subscriptions_for_fabric: u16,
    /// Subscriptions accepted since boot, including those since torn down.
    pub total_subscriptions_established: u32,
    /// Interaction Model messages sent since boot.
    pub total_im_messages_sent: u32,
    /// Interaction Model messages received since boot.
    pub total_im_messages_received: u32,
}

/// Interaction-Model state threaded down to cluster handlers via
/// [`HandlerContext::im_stats`](crate::HandlerContext::im_stats).
///
pub trait ImStats: MaybeSendSync {
    /// The node's resource-utilisation metrics, for
    /// `GeneralDiagnostics::DeviceLoadStatus`.
    ///
    /// `fab_idx` is the fabric of the reading subject, for
    /// `CurrentSubscriptionsForFabric`; pass `None` when no fabric is in scope.
    fn device_load(&self, fab_idx: Option<NonZeroU8>) -> DeviceLoad;

    /// Whether a live subscription exists on `fab_idx` whose subscriber node
    /// matches `node_id`.
    ///
    /// The ICD Management handler uses it to decide which registered Check-In
    /// clients have lost touch and need a Check-In.
    fn has_subscription_for(&self, fab_idx: NonZeroU8, node_id: NodeId) -> bool;

    /// Wait until a report to a subscriber fails to be delivered.
    ///
    /// The subscriber then no longer counts as subscribed for
    /// [`has_subscription_for`](Self::has_subscription_for), and the ICD
    /// Management handler uses this to nudge the registered clients that lost
    /// touch with a Check-In right away, while the device is still awake, rather
    /// than at its next wake-up.
    ///
    /// A single-waiter notification: exactly one task should wait on it.
    fn wait_report_failed(&self) -> impl Future<Output = ()> + MaybeSend;

    /// The earliest point at which a subscription needs a report to keep alive,
    /// or `None` without subscriptions.
    ///
    /// The ICD Management handler wakes the device up no later than this, so
    /// that the subscriptions keep alive with the device's own wake-ups rather
    /// than wake it up themselves.
    fn next_keep_alive_at(&self) -> Option<Instant>;
}

impl<T> ImStats for &T
where
    T: ImStats,
{
    fn device_load(&self, fab_idx: Option<NonZeroU8>) -> DeviceLoad {
        (**self).device_load(fab_idx)
    }

    fn has_subscription_for(&self, fab_idx: NonZeroU8, node_id: NodeId) -> bool {
        (**self).has_subscription_for(fab_idx, node_id)
    }

    async fn wait_report_failed(&self) {
        (**self).wait_report_failed().await
    }

    fn next_keep_alive_at(&self) -> Option<Instant> {
        (**self).next_keep_alive_at()
    }
}
