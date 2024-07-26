use core::convert::Infallible;
use core::{cell::UnsafeCell, mem::MaybeUninit};

/// Re-export `pinned-init` because its API is very unstable currently (0.0.x)
pub use pinned_init::*;

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
