/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

//! A module containing various types for managing Ethernet, Thread and Wifi networks.

use core::future::Future;

pub mod eth;
#[cfg(feature = "os")]
pub mod generic;
#[cfg(all(unix, feature = "os", not(target_os = "espidf")))]
pub mod unix;
pub mod wireless;

#[cfg(all(feature = "os", not(all(unix, not(target_os = "espidf")))))]
pub use generic::GenericNetifs as SysNetifs;
/// A platform-appropriate alias for the default OS-backed `NetifDiag` /
/// `NetChangeNotif` implementation:
///
/// - On Unix (non-ESP-IDF) it resolves to [`unix::UnixNetifs`], which uses
///   `nix` and reports MAC addresses and link-local IPv6 addresses.
/// - On other platforms (notably Windows) it resolves to
///   [`generic::GenericNetifs`], a portable `if-addrs`-backed fallback that
///   does not report MAC addresses.
#[cfg(all(unix, feature = "os", not(target_os = "espidf")))]
pub use unix::UnixNetifs as SysNetifs;

/// A generic trait for network change notifications.
pub trait NetChangeNotif {
    /// Wait until a change occurs.
    async fn wait_changed(&self);
}

impl<T> NetChangeNotif for &T
where
    T: NetChangeNotif,
{
    fn wait_changed(&self) -> impl Future<Output = ()> {
        (*self).wait_changed()
    }
}

/// Polling interval used by the polling-based [`NetChangeNotif`]
/// implementations of [`unix::UnixNetifs`] and [`generic::GenericNetifs`].
#[cfg(feature = "os")]
pub const NETIF_POLL_INTERVAL: embassy_time::Duration = embassy_time::Duration::from_secs(5);

/// A polling-based [`NetChangeNotif::wait_changed`] helper that simply waits
/// for [`NETIF_POLL_INTERVAL`] and then unconditionally reports a change.
///
/// This intentionally does NOT compare interface snapshots itself, because:
/// - A snapshot-comparing helper would only observe changes that happen
///   while it is being awaited; any change occurring between two consecutive
///   `wait_changed` calls would be missed.
/// - Callers of [`NetChangeNotif`] are expected to re-read the interface
///   state after `wait_changed` returns and diff it against the previously
///   observed state, so doing the same diff inside `wait_changed` would be
///   redundant.
///
/// The trade-off is that callers will be woken up every
/// [`NETIF_POLL_INTERVAL`] even when nothing has changed; for an OS-level
/// `NetChangeNotif`, [`NETIF_POLL_INTERVAL`] should therefore be kept large
/// enough to keep that overhead negligible.
#[cfg(feature = "os")]
pub(crate) async fn poll_netifs_changed() {
    embassy_time::Timer::after(NETIF_POLL_INTERVAL).await;
}
