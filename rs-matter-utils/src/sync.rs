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

/// A bound on the types that `rs-matter` shares between its futures. Most `rs-matter` traits
/// extend it.
///
/// With feature `send-sync`, this trait extends `Send + Sync`, so that these types can be shared
/// between the threads of a work-stealing executor, and it is implemented for every type that is
/// `Send + Sync`.
#[cfg(feature = "send-sync")]
pub trait MaybeSendSync: Send + Sync {}

#[cfg(feature = "send-sync")]
impl<T: ?Sized + Send + Sync> MaybeSendSync for T {}

/// A bound on the types that `rs-matter` shares between its futures. Most `rs-matter` traits
/// extend it.
///
/// Without feature `send-sync`, this trait is empty and implemented for every type.
#[cfg(not(feature = "send-sync"))]
pub trait MaybeSendSync {}

#[cfg(not(feature = "send-sync"))]
impl<T: ?Sized> MaybeSendSync for T {}

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
