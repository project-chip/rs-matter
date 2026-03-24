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

pub use mutex::*;

mod mutex {
    //! A variation of the `embassy-sync` blocking mutex that allows in-place initialization
    //! of the mutex with `Mutex::init(..) -> impl Init<Self>`.
    //! Check `embassy_sync::blocking_mutex::Mutex` for the original implementation.

    #![allow(clippy::should_implement_trait)]

    use core::cell::UnsafeCell;

    use embassy_sync::blocking_mutex::raw::RawMutex;

    use crate::utils::{
        init::{init, Init, UnsafeCellInit},
        sync::blocking::raw::MatterRawMutex,
    };

    /// Blocking mutex (not async)
    ///
    /// Provides a blocking mutual exclusion primitive backed by an implementation of [`raw::RawMutex`].
    ///
    /// Which implementation you select depends on the context in which you're using the mutex, and you can choose which kind
    /// of interior mutability fits your use case.
    ///
    /// Use [`CriticalSectionMutex`] when data can be shared between threads and interrupts.
    ///
    /// Use [`NoopMutex`] when data is only shared between tasks running on the same executor.
    ///
    /// Use [`ThreadModeMutex`] when data is shared between tasks running on the same executor but you want a global singleton.
    ///
    /// In all cases, the blocking mutex is intended to be short lived and not held across await points.
    /// Use the async [`Mutex`](crate::mutex::Mutex) if you need a lock that is held across await points.
    pub struct Mutex<T: ?Sized, R = MatterRawMutex> {
        // NOTE: `raw` must be FIRST, so when using ThreadModeMutex the "can't drop in non-thread-mode" gets
        // to run BEFORE dropping `data`.
        raw: R,
        data: UnsafeCell<T>,
    }

    unsafe impl<T: ?Sized + Send, R: RawMutex + Send> Send for Mutex<T, R> {}
    unsafe impl<T: ?Sized + Send, R: RawMutex + Sync> Sync for Mutex<T, R> {}

    impl<T, R: RawMutex> Mutex<T, R> {
        /// Creates a new mutex in an unlocked state ready for use.
        #[inline]
        pub const fn new(val: T) -> Self {
            Self {
                raw: R::INIT,
                data: UnsafeCell::new(val),
            }
        }

        /// Creates a mutex in-place initializer in an unlocked state ready for use.
        pub fn init<I: Init<T>>(val: I) -> impl Init<Self> {
            init!(Self {
                raw: R::INIT,
                data <- UnsafeCell::init(val),
            })
        }

        /// Creates a critical section and grants temporary access to the protected data.
        pub fn lock<U>(&self, f: impl FnOnce(&T) -> U) -> U {
            self.raw.lock(|| {
                let ptr = self.data.get() as *const T;
                let inner = unsafe { &*ptr };
                f(inner)
            })
        }
    }

    impl<T, R> Mutex<T, R> {
        /// Creates a new mutex based on a pre-existing raw mutex.
        ///
        /// This allows creating a mutex in a constant context on stable Rust.
        #[inline]
        pub const fn const_new(raw_mutex: R, val: T) -> Self {
            Self {
                raw: raw_mutex,
                data: UnsafeCell::new(val),
            }
        }

        /// Consumes this mutex, returning the underlying data.
        #[inline]
        pub fn into_inner(self) -> T {
            self.data.into_inner()
        }

        /// Returns a mutable reference to the underlying data.
        ///
        /// Since this call borrows the `Mutex` mutably, no actual locking needs to
        /// take place---the mutable borrow statically guarantees no locks exist.
        #[inline]
        pub fn get_mut(&mut self) -> &mut T {
            unsafe { &mut *self.data.get() }
        }
    }
}

pub mod raw {
    /// The raw mutex used throughout the `rs-matter` codebase
    #[cfg(not(feature = "sync-mutex"))]
    pub type MatterRawMutex = embassy_sync::blocking_mutex::raw::NoopRawMutex;

    /// The raw mutex used throughout the `rs-matter` codebase
    #[cfg(all(feature = "sync-mutex", not(feature = "std")))]
    pub type MatterRawMutex = embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;

    /// The raw mutex used throughout the `rs-matter` codebase
    #[cfg(all(feature = "sync-mutex", feature = "std"))]
    pub type MatterRawMutex = StdRawMutex;

    #[cfg(feature = "std")]
    pub use std::*;

    #[cfg(feature = "std")]
    mod std {
        use embassy_sync::blocking_mutex::raw::RawMutex;

        /// An `embassy-sync` `RawMutex` implementation using `std::sync::Mutex`.
        // TODO: Upstream into `embassy-sync` itself.
        #[derive(Default)]
        pub struct StdRawMutex(std::sync::Mutex<()>);

        impl StdRawMutex {
            pub const fn new() -> Self {
                Self(std::sync::Mutex::new(()))
            }
        }

        unsafe impl RawMutex for StdRawMutex {
            #[allow(clippy::declare_interior_mutable_const)]
            const INIT: Self = StdRawMutex(std::sync::Mutex::new(()));

            fn lock<R>(&self, f: impl FnOnce() -> R) -> R {
                let _guard = unwrap!(self.0.lock(), "Mutex lock failed");

                f()
            }
        }
    }
}
