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

//! A variation of the `embassy-sync` async mutex that only locks the mutex if a certain
//! condition on the content of the data holds true.
//! Check `embassy_sync::Mutex` for the original unconditional implementation.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::utils::init::{init, Init, UnsafeCellInit};

use super::signal::Signal;

/// Error returned by [`Mutex::try_lock`]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TryLockError;

/// Async mutex with conditional locking based on the data inside the mutex.
/// Check `embassy_sync::Mutex` for the original unconditional implementation.
pub struct IfMutex<M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    state: Signal<M, bool>,
    inner: UnsafeCell<T>,
}

unsafe impl<M: RawMutex + Send, T: ?Sized + Send> Send for IfMutex<M, T> {}
unsafe impl<M: RawMutex + Sync, T: ?Sized + Send> Sync for IfMutex<M, T> {}

/// Async mutex.
impl<M, T> IfMutex<M, T>
where
    M: RawMutex,
{
    /// Create a new mutex with the given value.
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Self {
            state: Signal::<M, _>::new(false),
            inner: UnsafeCell::new(value),
        }
    }

    /// Creates a mutex in-place initializer with the given value initializer.
    pub fn init<I: Init<T>>(value: I) -> impl Init<Self> {
        init!(Self {
            state: Signal::<M, _>::new(false),
            inner <- UnsafeCell::init(value),
        })
    }
}

impl<M, T> IfMutex<M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    /// Lock the mutex.
    ///
    /// This will wait for the mutex to be unlocked if it's already locked.
    pub async fn lock(&self) -> IfMutexGuard<'_, M, T> {
        self.lock_if(|_| true).await
    }

    /// Lock the mutex.
    ///
    /// This will wait for the mutex to be unlocked if it's already locked _and_ for the provided condition on the data to become true.
    pub async fn lock_if<F>(&self, f: F) -> IfMutexGuard<'_, M, T>
    where
        F: Fn(&T) -> bool,
    {
        self.state
            .wait(|locked| {
                // Safety: it is safe to access the unsafe cell data, because:
                // - nobody holds the long term (async) lock on the mutex right now (`locked == false`)
                // - we have gained the blocking short-term mutex lock
                if !*locked && f(unsafe { &*self.inner.get() }) {
                    *locked = true;

                    Some(())
                } else {
                    None
                }
            })
            .await;

        IfMutexGuard { mutex: self }
    }

    /// Waits for the mutex to become unlocked and then executes the provided closure.
    /// Will become ready only when the callback closure returns a `Some` result.
    pub async fn with<F, R>(&self, mut f: F) -> R
    where
        F: FnMut(&mut T) -> Option<R>,
    {
        let result = self
            .state
            .wait(|locked| {
                if !*locked {
                    // Safety: it is safe to access the unsafe cell data, because:
                    // - nobody holds the long term (async) lock on the mutex right now (`locked == false`)
                    // - we have gained the blocking short-term mutex lock
                    if let Some(result) = f(unsafe { &mut *self.inner.get() }) {
                        *locked = true;
                        return Some(result);
                    }
                }

                None
            })
            .await;

        // Construct and immediately drop the guard to unlock the mutex
        let _ = IfMutexGuard { mutex: self };

        result
    }

    /// Attempt to immediately lock the mutex.
    pub fn try_lock(&self) -> Result<IfMutexGuard<'_, M, T>, TryLockError> {
        self.try_lock_if(|_| true)
    }

    /// Attempt to immediately lock the mutex.
    ///
    /// If the mutex is already locked or the condition on the data is not true, this will return an error instead of waiting.
    pub fn try_lock_if<F>(&self, mut f: F) -> Result<IfMutexGuard<'_, M, T>, TryLockError>
    where
        F: FnMut(&T) -> bool,
    {
        self.state.modify(|locked| {
            if *locked {
                (false, Err(TryLockError))
            } else if f(unsafe { &*self.inner.get() }) {
                // Safety: it is safe to access the unsafe cell data, because:
                // - nobody holds the long term (async) lock on the mutex right now (`locked == false`)
                // - we have gained the blocking short-term mutex lock
                *locked = true;
                (false, Ok(()))
            } else {
                (false, Err(TryLockError))
            }
        })?;

        Ok(IfMutexGuard { mutex: self })
    }

    /// Consumes this mutex, returning the underlying data.
    pub fn into_inner(self) -> T
    where
        T: Sized,
    {
        self.inner.into_inner()
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// Since this call borrows the Mutex mutably, no actual locking needs to
    /// take place -- the mutable borrow statically guarantees no locks exist.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }
}

/// Async mutex guard.
///
/// Owning an instance of this type indicates having
/// successfully locked the mutex, and grants access to the contents.
///
/// Dropping it unlocks the mutex.
pub struct IfMutexGuard<'a, M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    mutex: &'a IfMutex<M, T>,
}

impl<M, T> Drop for IfMutexGuard<'_, M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    fn drop(&mut self) {
        self.mutex.state.modify(|locked| {
            assert!(*locked);

            *locked = false;

            (true, ())
        })
    }
}

impl<M, T> Deref for IfMutexGuard<'_, M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // Safety: the MutexGuard represents exclusive access to the contents
        // of the mutex, so it's OK to get it.
        unsafe { &*(self.mutex.inner.get() as *const T) }
    }
}

impl<M, T> DerefMut for IfMutexGuard<'_, M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Safety: the MutexGuard represents exclusive access to the contents
        // of the mutex, so it's OK to get it.
        unsafe { &mut *(self.mutex.inner.get()) }
    }
}
