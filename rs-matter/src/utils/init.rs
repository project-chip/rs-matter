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

use core::convert::Infallible;
use core::{cell::UnsafeCell, mem::MaybeUninit};

/// Re-export `pinned-init` because its API is very unstable currently (0.0.x)
pub use pinned_init::*;

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

/// An extension trait for re-setting an already instantiated `T` with the given initializer.
pub trait ApplyInit<T, E>: Init<T, E> {
    fn apply(self, to: &mut T) -> Result<(), E> {
        unsafe { Self::__init(self, to as *mut T) }
    }
}

impl<T, I, E> ApplyInit<T, E> for I where I: Init<T, E> {}
/// An extension trait for retrofitting `UnsafeCell` with an initializer.
pub trait UnsafeCellInit<T> {
    /// Create a new in-place initializer for `UnsafeCell`
    /// by using the given initializer for the value.
    fn init<I: Init<T>>(value: I) -> impl Init<Self>;
}

impl<T> UnsafeCellInit<T> for UnsafeCell<T> {
    fn init<I: Init<T>>(value: I) -> impl Init<Self> {
        unsafe {
            init_from_closure::<_, Infallible>(move |slot: *mut Self| {
                // `slot` contains uninit memory, avoid creating a reference.
                let slot: *mut T = slot as _;

                // Initialize the value
                value.__init(slot).unwrap();

                Ok(())
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

    fn try_init_with<I: Init<T, E>, E>(&mut self, init: I) -> Result<&mut T, E>;
}

impl<T> InitMaybeUninit<T> for MaybeUninit<T> {
    fn try_init_with<I: Init<T, E>, E>(&mut self, init: I) -> Result<&mut T, E> {
        unsafe {
            Init::<T, E>::__init(init, self.as_mut_ptr())?;

            Ok(self.assume_init_mut())
        }
    }
}
