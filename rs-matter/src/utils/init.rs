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

use core::convert::Infallible;
use core::{cell::UnsafeCell, mem::MaybeUninit};

/// Re-export `pinned-init` because its API is very unstable currently (0.0.x)
pub use pinned_init::*;
// `pinned_init::zeroed` returns a value since 0.0.10; the in-place initializer is `init_zeroed`
pub use pinned_init::init_zeroed as zeroed;

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
                unwrap!(Self::__init(self, slot));

                Ok(())
            })
        }
    }
}

impl<T, I> IntoFallibleInit<T> for I where I: Init<T, Infallible> {}

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
                unwrap!(value.__init(slot));

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
        unwrap!(self.try_init_with(init))
    }

    /// Try to initialize Self with the given fallible in-place initializer.
    fn try_init_with<I: Init<T, E>, E>(&mut self, init: I) -> Result<&mut T, E>;

    /// Initialize Self with all-zeroes
    fn init_zeroed(&mut self) -> &mut T
    where
        T: Zeroable,
    {
        self.init_with(pinned_init::init_zeroed())
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

/// A trait for types that have a canonical, stack-safe, in-place default initializer.
///
/// This is the in-place initialization analogue of `Default`: unlike `Default::default()`
/// which returns `Self` by value (potentially materializing a large value on the stack),
/// `init_default()` returns an `Init<Self>` that writes the value directly into its
/// final memory location. This is essential for large types (e.g. buffers sized in MiB)
/// whose on-stack construction would overflow the stack.
pub trait InitDefault: Sized {
    /// Returns a canonical in-place initializer for `Self`.
    fn init_default() -> impl Init<Self>;
}

#[cfg(test)]
mod tests {
    use core::cell::{Cell, UnsafeCell};
    use core::mem::MaybeUninit;

    use super::{into_init, Init, InitMaybeUninit, IntoFallibleInit, UnsafeCellInit};

    struct Droppable<'a>(&'a Cell<u32>);

    impl Drop for Droppable<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn maybe_uninit_init_with() {
        let drops = Cell::new(0);

        let mut slot = MaybeUninit::<Droppable>::uninit();
        let d = slot.init_with(Droppable(&drops));
        assert_eq!(d.0.get(), 0);

        // SAFETY: `slot` was initialized by `init_with` above
        unsafe { slot.assume_init_drop() };
        assert_eq!(drops.get(), 1);

        let mut slot = MaybeUninit::<u32>::uninit();
        assert_eq!(*slot.init_zeroed(), 0);
        assert_eq!(*slot.init_with(7), 7);
    }

    #[test]
    fn into_init_and_into_fallible() {
        let drops = Cell::new(0);

        let mut slot = MaybeUninit::<Droppable>::uninit();

        // A failing initializer reports the error and constructs nothing
        let r = slot.try_init_with(into_init(|| {
            Err::<Droppable, i32>(3).map(|d| d.into_fallible())
        }));
        assert_eq!(r.err(), Some(3));
        assert_eq!(drops.get(), 0);

        let r = slot.try_init_with(into_init(|| {
            Ok::<_, i32>(Droppable(&drops).into_fallible())
        }));
        assert!(r.is_ok());

        // SAFETY: `slot` was initialized by `try_init_with` above
        unsafe { slot.assume_init_drop() };
        assert_eq!(drops.get(), 1);

        // An unused initializer drops the value it wraps
        let init = Droppable(&drops).into_fallible::<i32>();
        drop(init);
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn unsafe_cell_init() {
        let mut slot = MaybeUninit::<UnsafeCell<u32>>::uninit();
        let cell = slot.init_with(UnsafeCell::init(42u32));
        assert_eq!(*cell.get_mut(), 42);
    }

    #[test]
    fn value_is_an_initializer() {
        fn init<T>(init: impl Init<T>) -> T {
            let mut slot = MaybeUninit::uninit();
            slot.init_with(init);

            // SAFETY: `slot` was initialized by `init_with` above
            unsafe { slot.assume_init() }
        }

        assert_eq!(init(5u8), 5);
    }
}
