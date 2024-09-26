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

use core::cell::UnsafeCell;
use core::convert::Infallible;
use core::fmt::Debug;
use core::mem::MaybeUninit;

/// Re-export `pinned-init` because its API is very unstable currently (0.0.x)
pub use pinned_init::*;

/// Convert a closure returning `Result<impl Init<T, E>, E>` into an `Init<T, E>`.
pub fn into_init<F, T, E, I: Init<T, E>>(f: F) -> impl Init<T, E>
where
    F: FnOnce() -> Result<I, E>,
{
    unsafe { init_from_closure(move |slot| f()?.__init(slot)) }
}

/// An extension trait for converting `Init<T, Infallible>` to a fallible `Init<T, E>`.
/// Useful when chaining an infallible initializer with a fallible chained initialization function.
pub trait IntoFallibleInit<T>: Init<T, Infallible> {
    /// Convert the infallible initializer to a fallible one.
    fn into_fallible<E>(self) -> impl Init<T, E> {
        unsafe {
            init_from_closure(move |slot| {
                Self::__init(self, slot).unwrap();

                Ok(())
            })
        }
    }
}

impl<T, I> IntoFallibleInit<T> for I where I: Init<T, Infallible> {}

/// An extension trait for converting `Init<T, E>` to an infallible `Init<T, Infallible>`.
/// Useful when the upstream code can **guarantee**, that there will be no errors during the initialization.
///
/// If any errors occur, the resulting infallible initializer will panic.
pub trait IntoInfallibleInit<T, E: Debug>: Init<T, E> {
    /// Convert the fallible initializer to an infallible one.
    fn into_infallible(self) -> impl Init<T> {
        unsafe {
            init_from_closure(move |slot| {
                Self::__init(self, slot).unwrap();

                Ok(())
            })
        }
    }
}

impl<T, E: Debug, I> IntoInfallibleInit<T, E> for I where I: Init<T, E> {}

/// An extension trait for updating a type using an infallible initializer.
///
/// NOTE: The initializer - besides being infallible - should **NOT** panic.
/// If the initializer does panic, the code will immediately turn any unwinding panic
/// into a program abort.
pub trait ApplyInit<T>: Init<T> {
    fn apply(self, to: &mut T) {
        let update = move || {
            let to = to as *mut T;

            unsafe {
                // We can drop in place because we are sure that the following update
                // will not fail and also it should NOT panic
                core::ptr::drop_in_place(to);

                // NOTE:
                // We just dropped the value in-place, but the compiler does not know about that!
                // From here on, if the initializer panics, the program will be in an inconsistent state,
                // as the compiler will do another drop of the value.
                //
                // Therefore, we really need to promote any unwinding panic to an abort, which is
                // the only safe way to handle this situation.

                // Unwrapping should not panic because the initializer is an infallible one
                Self::__init(self, to).unwrap();
            }
        };

        #[cfg(not(panic = "abort"))]
        {
            // In the presence of `panic_unwind`:
            //
            // Catch the panic and abort immediately, because otherwise the program will continue
            // to run in an inconsistent state due to the potential double-drop of the value on
            // panic-unwind (we already called `core::ptr::drop_in_place` but the compiler does not know that!)

            extern crate std;

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(update));

            if result.is_err() {
                log::error!(
                    "Panic detected during an infallible in-place update. Aborting the program."
                );
                std::process::abort();
            }
        }

        // `panic_abort` is active. We should be safe to call `update` directly
        #[cfg(panic = "abort")]
        update();
    }
}

impl<T, I> ApplyInit<T> for I where I: Init<T> {}

/// An extension trait for retrofitting `UnsafeCell` with an initializer.
pub trait UnsafeCellInit<T> {
    /// Create a new in-place initializer for `UnsafeCell`
    /// by using the given initializer for the value.
    fn init<I: Init<T, E>, E>(value: I) -> impl Init<Self, E>;
}

impl<T> UnsafeCellInit<T> for UnsafeCell<T> {
    fn init<I: Init<T, E>, E>(value: I) -> impl Init<Self, E> {
        unsafe {
            init_from_closure::<_, E>(move |slot: *mut Self| {
                // `slot` contains uninit memory, avoid creating a reference.
                let slot: *mut T = slot as _;

                // Initialize the value
                value.__init(slot)
            })
        }
    }
}

/// An extension trait that allows safe initialization of
/// `MaybeUninit<T>` memory.
pub trait InitMaybeUninit<T> {
    /// Initialize Self with the given in-place initializer.
    fn init_with<I: Init<T>>(&mut self, init: I) -> &mut T {
        self.try_init_with(init).unwrap()
    }

    /// Try to initialize Self with the given fallible in-place initializer.
    fn try_init_with<I: Init<T, E>, E>(&mut self, init: I) -> Result<&mut T, E>;

    /// Initialize Self with all-zeroes
    fn init_zeroed(&mut self) -> &mut T
    where
        T: Zeroable,
    {
        self.init_with(pinned_init::zeroed())
    }
}

impl<T> InitMaybeUninit<T> for MaybeUninit<T> {
    fn try_init_with<I: Init<T, E>, E>(&mut self, init: I) -> Result<&mut T, E> {
        unsafe {
            Init::<T, E>::__init(init, self.as_mut_ptr())?;

            Ok(self.assume_init_mut())
        }
    }
}
