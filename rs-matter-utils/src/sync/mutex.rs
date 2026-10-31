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

//! A variation of the `embassy-sync` async mutex that only locks the mutex if a certain
//! condition on the content of the data holds true.
//! Check `embassy_sync::Mutex` for the original unconditional implementation.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::init::{init, Init, UnsafeCellInit};
use crate::sync::blocking::raw::MatterRawMutex;

use super::signal::{MultiSignal, Signal};

/// Error returned by [`Mutex::try_lock`]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TryLockError;

/// Async mutex with conditional locking based on the data inside the mutex.
/// Check `embassy_sync::Mutex` for the original unconditional implementation.
///
/// An `IfMutex` keeps a single waker, so the code that uses it directly must never have
/// waiters (futures waiting for the lock or for its condition) with different wakers at
/// the same time. See [`Signal`] for why. Where such waiters are possible, use
/// [`IfMultiMutex`] instead.
pub struct IfMutex<T, M = MatterRawMutex>
where
    T: ?Sized,
    M: RawMutex,
{
    state: Signal<bool, M>,
    inner: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send, M: RawMutex + Send> Send for IfMutex<T, M> {}
unsafe impl<T: ?Sized + Send, M: RawMutex + Sync> Sync for IfMutex<T, M> {}

/// Async mutex.
impl<T, M> IfMutex<T, M>
where
    M: RawMutex,
{
    /// Create a new mutex with the given value.
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Self {
            state: Signal::new(false),
            inner: UnsafeCell::new(value),
        }
    }

    /// Creates a mutex in-place initializer with the given value initializer.
    pub fn init<I: Init<T>>(value: I) -> impl Init<Self> {
        init!(Self {
            state: Signal::new(false),
            inner <- UnsafeCell::init(value),
        })
    }
}

impl<T, M> IfMutex<T, M>
where
    T: ?Sized,
    M: RawMutex,
{
    /// Lock the mutex.
    ///
    /// This will wait for the mutex to be unlocked if it's already locked.
    pub async fn lock(&self) -> IfMutexGuard<'_, T, M> {
        self.lock_if(|_| true).await
    }

    /// Lock the mutex.
    ///
    /// This will wait for the mutex to be unlocked if it's already locked _and_ for the provided condition on the data to become true.
    pub async fn lock_if<F>(&self, f: F) -> IfMutexGuard<'_, T, M>
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

    /// Wait for the mutex to be unlocked *and* for the provided condition on the data to become true,
    /// without locking the mutex.
    pub async fn wait_until<F>(&self, f: F)
    where
        F: Fn(&T) -> bool,
    {
        self.state
            .wait(|locked| {
                if *locked {
                    return None;
                }

                // Safety: it is safe to access the unsafe cell data, because:
                // - nobody holds the long term (async) lock on the mutex right now (`locked == false`)
                // - we have gained the blocking short-term mutex lock
                let data = unsafe { &*self.inner.get() };

                f(data).then_some(())
            })
            .await;
    }

    /// Attempt to immediately lock the mutex.
    pub fn try_lock(&self) -> Result<IfMutexGuard<'_, T, M>, TryLockError> {
        self.try_lock_if(|_| true)
    }

    /// Attempt to immediately lock the mutex.
    ///
    /// If the mutex is already locked or the condition on the data is not true, this will return an error instead of waiting.
    pub fn try_lock_if<F>(&self, mut f: F) -> Result<IfMutexGuard<'_, T, M>, TryLockError>
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
pub struct IfMutexGuard<'a, T, M = MatterRawMutex>
where
    T: ?Sized,
    M: RawMutex,
{
    mutex: &'a IfMutex<T, M>,
}

impl<T, M> Drop for IfMutexGuard<'_, T, M>
where
    T: ?Sized,
    M: RawMutex,
{
    fn drop(&mut self) {
        self.mutex.state.modify(|locked| {
            assert!(*locked);

            *locked = false;

            (true, ())
        })
    }
}

impl<T, M> Deref for IfMutexGuard<'_, T, M>
where
    T: ?Sized,
    M: RawMutex,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // Safety: the MutexGuard represents exclusive access to the contents
        // of the mutex, so it's OK to get it.
        unsafe { &*(self.mutex.inner.get() as *const T) }
    }
}

impl<T, M> DerefMut for IfMutexGuard<'_, T, M>
where
    T: ?Sized,
    M: RawMutex,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Safety: the MutexGuard represents exclusive access to the contents
        // of the mutex, so it's OK to get it.
        unsafe { &mut *(self.mutex.inner.get()) }
    }
}

/// An [`IfMutex`] that any number of waiters, with different wakers, can wait on at the
/// same time.
///
/// It keeps its waiters in a [`MultiSignal`], so unlocking the mutex wakes all of them.
pub struct IfMultiMutex<T, M = MatterRawMutex>
where
    T: ?Sized,
    M: RawMutex,
{
    state: MultiSignal<bool, M>,
    inner: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send, M: RawMutex + Send> Send for IfMultiMutex<T, M> {}
unsafe impl<T: ?Sized + Send, M: RawMutex + Sync> Sync for IfMultiMutex<T, M> {}

/// Async mutex.
impl<T, M> IfMultiMutex<T, M>
where
    M: RawMutex,
{
    /// Create a new mutex with the given value.
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Self {
            state: MultiSignal::new(false),
            inner: UnsafeCell::new(value),
        }
    }

    /// Creates a mutex in-place initializer with the given value initializer.
    pub fn init<I: Init<T>>(value: I) -> impl Init<Self> {
        init!(Self {
            state: MultiSignal::new(false),
            inner <- UnsafeCell::init(value),
        })
    }
}

impl<T, M> IfMultiMutex<T, M>
where
    T: ?Sized,
    M: RawMutex,
{
    /// Lock the mutex.
    ///
    /// This will wait for the mutex to be unlocked if it's already locked.
    pub async fn lock(&self) -> IfMultiMutexGuard<'_, T, M> {
        self.lock_if(|_| true).await
    }

    /// Lock the mutex.
    ///
    /// This will wait for the mutex to be unlocked if it's already locked _and_ for the provided condition on the data to become true.
    pub async fn lock_if<F>(&self, f: F) -> IfMultiMutexGuard<'_, T, M>
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

        IfMultiMutexGuard { mutex: self }
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
        let _ = IfMultiMutexGuard { mutex: self };

        result
    }

    /// Wait for the mutex to be unlocked *and* for the provided condition on the data to become true,
    /// without locking the mutex.
    pub async fn wait_until<F>(&self, f: F)
    where
        F: Fn(&T) -> bool,
    {
        self.state
            .wait(|locked| {
                if *locked {
                    return None;
                }

                // Safety: it is safe to access the unsafe cell data, because:
                // - nobody holds the long term (async) lock on the mutex right now (`locked == false`)
                // - we have gained the blocking short-term mutex lock
                let data = unsafe { &*self.inner.get() };

                f(data).then_some(())
            })
            .await;
    }

    /// Attempt to immediately lock the mutex.
    pub fn try_lock(&self) -> Result<IfMultiMutexGuard<'_, T, M>, TryLockError> {
        self.try_lock_if(|_| true)
    }

    /// Attempt to immediately lock the mutex.
    ///
    /// If the mutex is already locked or the condition on the data is not true, this will return an error instead of waiting.
    pub fn try_lock_if<F>(&self, mut f: F) -> Result<IfMultiMutexGuard<'_, T, M>, TryLockError>
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

        Ok(IfMultiMutexGuard { mutex: self })
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

/// Async mutex guard of an [`IfMultiMutex`].
///
/// Owning an instance of this type indicates having
/// successfully locked the mutex, and grants access to the contents.
///
/// Dropping it unlocks the mutex.
pub struct IfMultiMutexGuard<'a, T, M = MatterRawMutex>
where
    T: ?Sized,
    M: RawMutex,
{
    mutex: &'a IfMultiMutex<T, M>,
}

impl<T, M> Drop for IfMultiMutexGuard<'_, T, M>
where
    T: ?Sized,
    M: RawMutex,
{
    fn drop(&mut self) {
        self.mutex.state.modify(|locked| {
            assert!(*locked);

            *locked = false;

            (true, ())
        })
    }
}

impl<T, M> Deref for IfMultiMutexGuard<'_, T, M>
where
    T: ?Sized,
    M: RawMutex,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // Safety: the MutexGuard represents exclusive access to the contents
        // of the mutex, so it's OK to get it.
        unsafe { &*(self.mutex.inner.get() as *const T) }
    }
}

impl<T, M> DerefMut for IfMultiMutexGuard<'_, T, M>
where
    T: ?Sized,
    M: RawMutex,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Safety: the MutexGuard represents exclusive access to the contents
        // of the mutex, so it's OK to get it.
        unsafe { &mut *(self.mutex.inner.get()) }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use core::future::Future;
    use core::mem::MaybeUninit;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::Wake;

    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    use futures_lite::future::{block_on, poll_once, zip};

    use crate::init::InitMaybeUninit;
    use crate::storage::Vec;

    use super::{IfMultiMutex, IfMutex, TryLockError};

    struct Counter(AtomicUsize);

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn waker() -> (Waker, Arc<Counter>) {
        let counter = Arc::new(Counter(AtomicUsize::new(0)));

        (Waker::from(counter.clone()), counter)
    }

    fn count(counter: &Counter) -> usize {
        counter.0.load(Ordering::SeqCst)
    }

    #[test]
    fn try_lock_and_guard() {
        let m = IfMutex::<_, NoopRawMutex>::new(1);

        {
            let mut g = m.try_lock().unwrap();
            assert_eq!(m.try_lock().err(), Some(TryLockError));
            assert_eq!(m.try_lock_if(|_| true).err(), Some(TryLockError));

            assert_eq!(*g, 1);
            *g += 1;
        }

        assert_eq!(*m.try_lock().unwrap(), 2);
        assert!(m.try_lock_if(|v| *v == 3).is_err());
        assert_eq!(*m.try_lock_if(|v| *v == 2).unwrap(), 2);
    }

    #[test]
    fn lock_lock_if_and_with() {
        let m = IfMutex::<_, NoopRawMutex>::new(0);

        block_on(async {
            {
                let mut g = m.lock().await;
                *g = 1;
            }

            // `lock_if` must wait until the condition holds, which the second future makes true
            let (g, ()) = zip(m.lock_if(|v| *v == 2), async {
                let mut g = m.lock().await;
                *g = 2;
            })
            .await;
            assert_eq!(*g, 2);
            drop(g);

            let r = m
                .with(|v| {
                    *v += 1;
                    Some(*v)
                })
                .await;
            assert_eq!(r, 3);
        });

        let mut m = m;
        *m.get_mut() += 1;
        assert_eq!(m.into_inner(), 4);
    }

    #[test]
    fn wait_until() {
        let m = IfMutex::<_, NoopRawMutex>::new(0);

        block_on(async {
            // `wait_until` must wait until the condition holds, and wake up once a lock holder
            // makes it hold
            let mut wait = pin!(m.wait_until(|v| *v == 1));
            assert!(poll_once(wait.as_mut()).await.is_none());

            zip(wait, async {
                *m.lock().await = 1;
            })
            .await;

            // ...without locking the mutex
            assert!(m.try_lock().is_ok());

            // It must also wait while the mutex is locked, even though the condition holds,
            // and wake up once it is unlocked
            let g = m.lock().await;
            let mut wait = pin!(m.wait_until(|v| *v == 1));
            assert!(poll_once(wait.as_mut()).await.is_none());

            zip(wait, async move { drop(g) }).await;
            assert!(m.try_lock().is_ok());
        });
    }

    #[test]
    fn init_in_place() {
        let mut slot = MaybeUninit::<IfMutex<Vec<u8, 4>, NoopRawMutex>>::uninit();
        let m = slot.init_with(IfMutex::init(Vec::init()));

        m.get_mut().push(9).unwrap();
        assert_eq!(m.try_lock().unwrap().as_slice(), &[9]);

        // SAFETY: `slot` was initialized by `init_with` above
        unsafe { slot.assume_init_drop() };
    }

    #[test]
    fn multi_lock_lock_if_with_and_wait_until() {
        let m = IfMultiMutex::<_, NoopRawMutex>::new(0);

        block_on(async {
            {
                let g = m.try_lock().unwrap();
                assert_eq!(m.try_lock().err(), Some(TryLockError));
                drop(g);
            }

            let (g, ()) = zip(m.lock_if(|v| *v == 1), async {
                *m.lock().await = 1;
            })
            .await;
            assert_eq!(*g, 1);
            drop(g);

            let r = m
                .with(|v| {
                    *v += 1;
                    Some(*v)
                })
                .await;
            assert_eq!(r, 2);

            let g = m.lock().await;
            let mut wait = pin!(m.wait_until(|v| *v == 2));
            assert!(poll_once(wait.as_mut()).await.is_none());

            zip(wait, async move { drop(g) }).await;
            assert!(m.try_lock_if(|v| *v == 2).is_ok());
        });

        let mut m = m;
        *m.get_mut() += 1;
        assert_eq!(m.into_inner(), 3);
    }

    #[test]
    fn multi_lockers_with_different_wakers() {
        let m = IfMultiMutex::<_, NoopRawMutex>::new(0);

        let (wa, ca) = waker();
        let (wb, cb) = waker();
        let mut cxa = Context::from_waker(&wa);
        let mut cxb = Context::from_waker(&wb);

        let g = m.try_lock().unwrap();

        let mut a = pin!(m.lock());
        let mut b = pin!(m.lock());

        // The lockers do not wake each other when they register
        for _ in 0..3 {
            assert!(a.as_mut().poll(&mut cxa).is_pending());
            assert!(b.as_mut().poll(&mut cxb).is_pending());
        }
        assert_eq!((count(&ca), count(&cb)), (0, 0));

        // Unlocking wakes both, and the first to poll gets the lock
        drop(g);
        assert_eq!((count(&ca), count(&cb)), (1, 1));

        let Poll::Ready(ga) = a.as_mut().poll(&mut cxa) else {
            panic!("Not locked");
        };
        assert!(b.as_mut().poll(&mut cxb).is_pending());

        drop(ga);
        assert_eq!(count(&cb), 2);
        assert!(b.as_mut().poll(&mut cxb).is_ready());
    }

    #[test]
    fn multi_init_in_place() {
        let mut slot = MaybeUninit::<IfMultiMutex<Vec<u8, 4>, NoopRawMutex>>::uninit();
        let m = slot.init_with(IfMultiMutex::init(Vec::init()));

        m.get_mut().push(9).unwrap();
        assert_eq!(m.try_lock().unwrap().as_slice(), &[9]);

        // SAFETY: `slot` was initialized by `init_with` above
        unsafe { slot.assume_init_drop() };
    }
}
