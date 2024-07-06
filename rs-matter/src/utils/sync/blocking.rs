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

    use embassy_sync::blocking_mutex::raw::{self, RawMutex};

    use crate::utils::init::{init, Init, UnsafeCellInit};

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
    pub struct Mutex<R, T: ?Sized> {
        // NOTE: `raw` must be FIRST, so when using ThreadModeMutex the "can't drop in non-thread-mode" gets
        // to run BEFORE dropping `data`.
        raw: R,
        data: UnsafeCell<T>,
    }

    unsafe impl<R: RawMutex + Send, T: ?Sized + Send> Send for Mutex<R, T> {}
    unsafe impl<R: RawMutex + Sync, T: ?Sized + Send> Sync for Mutex<R, T> {}

    impl<R: RawMutex, T> Mutex<R, T> {
        /// Creates a new mutex in an unlocked state ready for use.
        #[inline]
        pub const fn new(val: T) -> Mutex<R, T> {
            Mutex {
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

    impl<R, T> Mutex<R, T> {
        /// Creates a new mutex based on a pre-existing raw mutex.
        ///
        /// This allows creating a mutex in a constant context on stable Rust.
        #[inline]
        pub const fn const_new(raw_mutex: R, val: T) -> Mutex<R, T> {
            Mutex {
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

    /// A mutex that allows borrowing data across executors and interrupts.
    ///
    /// # Safety
    ///
    /// This mutex is safe to share between different executors and interrupts.
    pub type CriticalSectionMutex<T> = Mutex<raw::CriticalSectionRawMutex, T>;

    /// A mutex that allows borrowing data in the context of a single executor.
    ///
    /// # Safety
    ///
    /// **This Mutex is only safe within a single executor.**
    pub type NoopMutex<T> = Mutex<raw::NoopRawMutex, T>;

    impl<T> Mutex<raw::CriticalSectionRawMutex, T> {
        /// Borrows the data for the duration of the critical section
        pub fn borrow<'cs>(&'cs self, _cs: critical_section::CriticalSection<'cs>) -> &'cs T {
            let ptr = self.data.get() as *const T;
            unsafe { &*ptr }
        }
    }

    impl<T> Mutex<raw::NoopRawMutex, T> {
        /// Borrows the data
        pub fn borrow(&self) -> &T {
            let ptr = self.data.get() as *const T;
            unsafe { &*ptr }
        }
    }

    // // ThreadModeMutex does NOT use the generic mutex from above because it's special:
    // // it's Send+Sync even if T: !Send. There's no way to do that without specialization (I think?).
    // //
    // // There's still a ThreadModeRawMutex for use with the generic Mutex (handy with Channel, for example),
    // // but that will require T: Send even though it shouldn't be needed.

    // #[cfg(any(cortex_m, feature = "std"))]
    // pub use thread_mode_mutex::*;
    // #[cfg(any(cortex_m, feature = "std"))]
    // mod thread_mode_mutex {
    //     use super::*;

    //     /// A "mutex" that only allows borrowing from thread mode.
    //     ///
    //     /// # Safety
    //     ///
    //     /// **This Mutex is only safe on single-core systems.**
    //     ///
    //     /// On multi-core systems, a `ThreadModeMutex` **is not sufficient** to ensure exclusive access.
    //     pub struct ThreadModeMutex<T: ?Sized> {
    //         inner: UnsafeCell<T>,
    //     }

    //     // NOTE: ThreadModeMutex only allows borrowing from one execution context ever: thread mode.
    //     // Therefore it cannot be used to send non-sendable stuff between execution contexts, so it can
    //     // be Send+Sync even if T is not Send (unlike CriticalSectionMutex)
    //     unsafe impl<T: ?Sized> Sync for ThreadModeMutex<T> {}
    //     unsafe impl<T: ?Sized> Send for ThreadModeMutex<T> {}

    //     impl<T> ThreadModeMutex<T> {
    //         /// Creates a new mutex
    //         pub const fn new(value: T) -> Self {
    //             ThreadModeMutex {
    //                 inner: UnsafeCell::new(value),
    //             }
    //         }
    //     }

    //     impl<T: ?Sized> ThreadModeMutex<T> {
    //         /// Lock the `ThreadModeMutex`, granting access to the data.
    //         ///
    //         /// # Panics
    //         ///
    //         /// This will panic if not currently running in thread mode.
    //         pub fn lock<R>(&self, f: impl FnOnce(&T) -> R) -> R {
    //             f(self.borrow())
    //         }

    //         /// Borrows the data
    //         ///
    //         /// # Panics
    //         ///
    //         /// This will panic if not currently running in thread mode.
    //         pub fn borrow(&self) -> &T {
    //             assert!(
    //                 raw::in_thread_mode(),
    //                 "ThreadModeMutex can only be borrowed from thread mode."
    //             );
    //             unsafe { &*self.inner.get() }
    //         }
    //     }

    //     impl<T: ?Sized> Drop for ThreadModeMutex<T> {
    //         fn drop(&mut self) {
    //             // Only allow dropping from thread mode. Dropping calls drop on the inner `T`, so
    //             // `drop` needs the same guarantees as `lock`. `ThreadModeMutex<T>` is Send even if
    //             // T isn't, so without this check a user could create a ThreadModeMutex in thread mode,
    //             // send it to interrupt context and drop it there, which would "send" a T even if T is not Send.
    //             assert!(
    //                 raw::in_thread_mode(),
    //                 "ThreadModeMutex can only be dropped from thread mode."
    //             );

    //             // Drop of the inner `T` happens after this.
    //         }
    //     }
    // }
}

pub mod raw {
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
                let _guard = self.0.lock().unwrap();

                f()
            }
        }
    }
}
