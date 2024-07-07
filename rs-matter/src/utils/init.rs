use core::convert::Infallible;
use core::{cell::UnsafeCell, mem::MaybeUninit};

/// Re-export `pinned-init` because its API is very unstable currently (0.0.x)
pub use pinned_init::*;

/// A trait for retrofitting types wrapping a value with an initializer.
///
/// Types that can be retrofitted this way should be `repr(transparent)`.
pub trait ContainerInit<T> {
    /// Create a new in-place initializer for the container
    /// by using the given initializer for the value.
    fn init<I: Init<T>>(value: I) -> impl Init<Self>;
}

impl<T> ContainerInit<T> for UnsafeCell<T> {
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
    fn init_with<I: Init<T>>(&mut self, init: I) -> &mut T;
}

impl<T> InitMaybeUninit<T> for MaybeUninit<T> {
    fn init_with<I: Init<T>>(&mut self, init: I) -> &mut T {
        unsafe {
            Init::<T>::__init(init, self.as_mut_ptr()).unwrap();

            self.assume_init_mut()
        }
    }
}
