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
/// With feature `sync-mutex`, this trait extends `Send + Sync`, so that all `dyn` traits are
/// `Send + Sync`, and it is implemented for every type that is `Send + Sync`.
#[cfg(feature = "sync-mutex")]
pub trait DynBase: Send + Sync {}

#[cfg(feature = "sync-mutex")]
impl<T: ?Sized + Send + Sync> DynBase for T {}

/// A trait that all other `rs-matter` `dyn` traits should extend from.
///
/// Without feature `sync-mutex`, this trait is empty and implemented for every type.
#[cfg(not(feature = "sync-mutex"))]
pub trait DynBase {}

#[cfg(not(feature = "sync-mutex"))]
impl<T: ?Sized> DynBase for T {}
