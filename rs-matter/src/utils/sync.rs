/*
 *
 *    Copyright (c) 2024-2026 Project CHIP Authors
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

pub use mutex::*;
pub use notification::*;
pub use signal::*;

pub mod blocking;

mod mutex;
mod notification;
mod signal;

/// A trait that all other `rs-matter` `dyn` traits should extend from.
///
/// With feature `send-sync`, this trait extends `Send + Sync`, so that all `dyn` traits are
/// `Send + Sync`, and it is implemented for every type that is `Send + Sync`.
#[cfg(feature = "send-sync")]
pub trait DynBase: Send + Sync {}

#[cfg(feature = "send-sync")]
impl<T: ?Sized + Send + Sync> DynBase for T {}

/// A trait that all other `rs-matter` `dyn` traits should extend from.
///
/// Without feature `send-sync`, this trait is empty and implemented for every type.
#[cfg(not(feature = "send-sync"))]
pub trait DynBase {}

#[cfg(not(feature = "send-sync"))]
impl<T: ?Sized> DynBase for T {}

/// A bound on the futures returned by `rs-matter` traits.
///
/// With feature `send-sync`, this trait extends `Send`, so that the futures can run on a
/// work-stealing executor, and it is implemented for every type that is `Send`.
#[cfg(feature = "send-sync")]
pub trait MaybeSend: Send {}

#[cfg(feature = "send-sync")]
impl<T: ?Sized + Send> MaybeSend for T {}

/// A bound on the futures returned by `rs-matter` traits.
///
/// Without feature `send-sync`, this trait is empty and implemented for every type.
#[cfg(not(feature = "send-sync"))]
pub trait MaybeSend {}

#[cfg(not(feature = "send-sync"))]
impl<T: ?Sized> MaybeSend for T {}

// TEMP-ASSERT-SEND: experiment only, to be removed.
pub(crate) struct TempAssertSend<F>(pub(crate) F);
unsafe impl<F> Send for TempAssertSend<F> {}
impl<F: core::future::Future> core::future::Future for TempAssertSend<F> {
    type Output = F::Output;
    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx)
    }
}
