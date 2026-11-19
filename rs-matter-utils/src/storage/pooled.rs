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

use core::cell::UnsafeCell;
use core::future::Future;
use core::ops::{Deref, DerefMut};
use core::pin::pin;

use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::futures::{select, Either};
use crate::init::{init, Init, InitDefault, UnsafeCellInit};
use crate::sync::blocking::raw::MatterRawMutex;
use crate::sync::{MaybeSend, MaybeSendSync, MultiSignal};
use crate::timers::{Duration, Timer};

/// A trait for getting access to a `&mut T` buffer, potentially awaiting until a buffer becomes available.
pub trait Buffers<T>: MaybeSendSync
where
    T: ?Sized,
{
    type Buffer<'a>: DerefMut<Target = T> + MaybeSendSync
    where
        Self: 'a;

    /// Get a reference to a buffer.
    /// Might await until a buffer is available, as it might be in use by somebody else.
    ///
    /// Depending on its internal implementation details, access to a buffer might also be denied
    /// immediately, or after a certain amount of time (subject to the concrete implementation of the method).
    /// In that case, the method will return `None`.
    fn get(&self) -> impl Future<Output = Option<Self::Buffer<'_>>> + MaybeSend;

    /// Get a reference to a buffer immediately, without waiting.
    /// If no buffer is available, return `None`.
    fn get_immediate(&self) -> Option<Self::Buffer<'_>>;
}

impl<B, T> Buffers<T> for &B
where
    B: Buffers<T>,
    T: ?Sized,
{
    type Buffer<'a>
        = B::Buffer<'a>
    where
        Self: 'a;

    fn get(&self) -> impl Future<Output = Option<Self::Buffer<'_>>> {
        (*self).get()
    }

    fn get_immediate(&self) -> Option<Self::Buffer<'_>> {
        (*self).get_immediate()
    }
}

/// A trait for getting access to a byte buffer of a requested length, potentially awaiting
/// until one becomes available.
///
/// Unlike with [`Buffers`], the buffers might come in different sizes (see [`ChainedBuffers`]).
pub trait ByteBuffers: MaybeSendSync {
    type Buffer<'a>: DerefMut<Target = [u8]> + MaybeSendSync
    where
        Self: 'a;

    /// Get a buffer of exactly `len` bytes. Its contents are unspecified.
    /// Might await until a buffer is available, as it might be in use by somebody else.
    ///
    /// Returns `None` when `len` is larger than any buffer, or when access to a buffer is
    /// denied, immediately or after a certain amount of time (subject to the concrete
    /// implementation of the method).
    fn get(&self, len: usize) -> impl Future<Output = Option<Self::Buffer<'_>>> + MaybeSend;

    /// Get a buffer of exactly `len` bytes immediately, without waiting.
    /// If no such buffer is available, return `None`.
    fn get_immediate(&self, len: usize) -> Option<Self::Buffer<'_>>;
}

impl<B> ByteBuffers for &B
where
    B: ByteBuffers,
{
    type Buffer<'a>
        = B::Buffer<'a>
    where
        Self: 'a;

    fn get(&self, len: usize) -> impl Future<Output = Option<Self::Buffer<'_>>> {
        (*self).get(len)
    }

    fn get_immediate(&self, len: usize) -> Option<Self::Buffer<'_>> {
        (*self).get_immediate(len)
    }
}

/// The default number of buffers held by a [`PooledBuffers`] pool.
///
/// As many as the Interaction Model needs with four responders: two for each, and one
/// for the subscription reports.
pub const DEFAULT_BUFFER_POOL_SIZE: usize = 9;

/// A concrete implementation of `Buffers` utilizing an internal pool of buffers.
/// Accessing a buffer would fail when all buffers are still used elsewhere after a wait timeout expires.
pub struct PooledBuffers<T, const N: usize = DEFAULT_BUFFER_POOL_SIZE, M = MatterRawMutex> {
    available: MultiSignal<[bool; N], M>,
    pool: UnsafeCell<crate::storage::Vec<T, N>>,
    wait_timeout_ms: u32,
}

impl<T, const N: usize, M> PooledBuffers<T, N, M>
where
    M: RawMutex,
{
    /// Create a new instance of `PooledBuffers` with the default (zero) wait
    /// timeout, i.e. buffer access is denied immediately when none is free.
    #[inline(always)]
    pub const fn new() -> Self {
        Self::new_with_timeout(0)
    }

    /// Create a new instance of `PooledBuffers`.
    ///
    /// `wait_timeout_ms` is the maximum time to wait for a buffer to become available
    /// before returning `None`.
    #[inline(always)]
    pub const fn new_with_timeout(wait_timeout_ms: u32) -> Self {
        Self {
            available: MultiSignal::new([true; N]),
            pool: UnsafeCell::new(crate::storage::Vec::new()),
            wait_timeout_ms,
        }
    }

    /// Create an in-place initializer for `PooledBuffers` with the default (zero)
    /// wait timeout, i.e. buffer access is denied immediately when none is free.
    pub fn init() -> impl Init<Self> {
        Self::init_with_timeout(0)
    }

    /// Create an in-place initializer for `PooledBuffers`.
    ///
    /// `wait_timeout_ms` is the maximum time to wait for a buffer to become available
    /// before returning `None`.
    pub fn init_with_timeout(wait_timeout_ms: u32) -> impl Init<Self> {
        init!(Self {
            available: MultiSignal::new([true; N]),
            pool <- UnsafeCell::init(crate::storage::Vec::init()),
            wait_timeout_ms,
        })
    }

    /// Get a unique reference to the buffer at `index`.
    ///
    /// The reference is derived from a raw pointer to the pool rather than from a
    /// `&mut Vec` over the whole pool, so it does not alias (and invalidate) the
    /// references to the other buffers that are currently handed out to callers.
    ///
    /// # Safety
    ///
    /// - `index` must be less than `N` and the pool must be fully populated
    ///   (`init_buffers` must have run);
    /// - The buffer at `index` must be marked as unavailable in `self.available`,
    ///   i.e. no other `&mut T` to it may exist for the lifetime of the returned one.
    #[allow(clippy::mut_from_ref)]
    unsafe fn buffer(&self, index: usize) -> &mut T {
        // SAFETY: Per the contract of this method, the slot is initialized and no other
        // reference to it is live.
        unsafe { &mut *crate::storage::Vec::raw_as_mut_ptr(self.pool.get()).add(index) }
    }

    fn init_buffers(pool: &UnsafeCell<crate::storage::Vec<T, N>>)
    where
        T: InitDefault,
    {
        let pool = pool.get();

        // The length is read through the raw pointer rather than via a `&Vec`, because
        // a reference to the whole pool would alias (and invalidate) the `&mut T` buffers
        // already handed out to callers.
        //
        // SAFETY: `pool` points to the valid, initialized `Vec` inside the `UnsafeCell`.
        if unsafe { crate::storage::Vec::raw_len(pool) } < N {
            // Buffers are only handed out once the pool is fully populated, so while it
            // is still being filled there are no outstanding `&mut T` references and a
            // unique reference to the whole pool is sound.
            //
            // SAFETY: See above; the pool is accessed under the `available` lock.
            let buffers = unsafe { &mut *pool };

            while buffers.len() < N {
                // In-place initialization: each slot is written directly via pinned-init,
                // never materializing a full `T` value on the stack. This is essential when
                // `T` is a large buffer (e.g. 1 MiB) that would otherwise overflow the stack.
                unwrap!(buffers.push_init_unchecked(T::init_default()));
            }
        }
    }
}

impl<T, const N: usize, M> Default for PooledBuffers<T, N, M>
where
    M: RawMutex,
{
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl<T, const N: usize, M> Send for PooledBuffers<T, N, M>
where
    T: Send,
    M: RawMutex + Send,
{
}

unsafe impl<T, const N: usize, M> Sync for PooledBuffers<T, N, M>
where
    T: Send,
    M: RawMutex + Send + Sync,
{
}

impl<T, const N: usize, M> Buffers<T> for PooledBuffers<T, N, M>
where
    T: InitDefault + MaybeSendSync,
    M: RawMutex + MaybeSendSync,
{
    type Buffer<'b>
        = PooledBuffer<'b, T, N, M>
    where
        Self: 'b;

    async fn get(&self) -> Option<Self::Buffer<'_>> {
        if self.wait_timeout_ms > 0 {
            let mut wait = pin!(self.available.wait(|available| {
                // Make sure the buffers are properly sized before starting to use them
                Self::init_buffers(&self.pool);

                if let Some(index) = available.iter().position(|a| *a) {
                    available[index] = false;
                    Some(index)
                } else {
                    None
                }
            }));

            let mut timeout = pin!(Timer::after(Duration::from_millis(
                self.wait_timeout_ms as u64
            )));

            let result = select(&mut wait, &mut timeout).await;

            match result {
                Either::First(index) => {
                    // SAFETY: See `Self::buffer`.
                    let buffer = unsafe { self.buffer(index) };

                    Some(PooledBuffer {
                        index,
                        buffer,
                        access: self,
                    })
                }
                Either::Second(()) => None,
            }
        } else {
            self.get_immediate()
        }
    }

    fn get_immediate(&self) -> Option<Self::Buffer<'_>> {
        let index = self.available.modify(|available| {
            // Make sure the buffers are properly sized before starting to use them
            Self::init_buffers(&self.pool);

            if let Some(index) = available.iter().position(|a| *a) {
                available[index] = false;
                (false, Some(index))
            } else {
                (false, None)
            }
        });

        index.map(|index| {
            // SAFETY: See `Self::buffer`.
            let buffer = unsafe { self.buffer(index) };

            PooledBuffer {
                index,
                buffer,
                access: self,
            }
        })
    }
}

impl<const L: usize, const N: usize, M> ByteBuffers
    for PooledBuffers<crate::storage::Vec<u8, L>, N, M>
where
    M: RawMutex + MaybeSendSync,
{
    type Buffer<'b>
        = PooledByteBuffer<'b, L, N, M>
    where
        Self: 'b;

    async fn get(&self, len: usize) -> Option<Self::Buffer<'_>> {
        // Do not wait on a pool that can never serve the request
        if len > L || N == 0 {
            return None;
        }

        let buffer = Buffers::get(self).await?;

        Some(PooledByteBuffer::new(buffer, len))
    }

    fn get_immediate(&self, len: usize) -> Option<Self::Buffer<'_>> {
        if len > L {
            return None;
        }

        Buffers::get_immediate(self).map(|buffer| PooledByteBuffer::new(buffer, len))
    }
}

pub struct PooledBuffer<'a, T, const N: usize, M = MatterRawMutex>
where
    M: RawMutex,
{
    index: usize,
    buffer: &'a mut T,
    access: &'a PooledBuffers<T, N, M>,
}

impl<T, const N: usize, M> Drop for PooledBuffer<'_, T, N, M>
where
    M: RawMutex,
{
    fn drop(&mut self) {
        self.access.available.modify(|available| {
            available[self.index] = true;
            (true, ())
        });
    }
}

impl<T, const N: usize, M> Deref for PooledBuffer<'_, T, N, M>
where
    M: RawMutex,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.buffer.deref()
    }
}

impl<T, const N: usize, M> DerefMut for PooledBuffer<'_, T, N, M>
where
    M: RawMutex,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.deref_mut()
    }
}

/// A byte buffer of a [`PooledBuffers`] pool, as returned by [`ByteBuffers::get`].
pub struct PooledByteBuffer<'a, const L: usize, const N: usize, M = MatterRawMutex>(
    PooledBuffer<'a, crate::storage::Vec<u8, L>, N, M>,
)
where
    M: RawMutex;

impl<'a, const L: usize, const N: usize, M> PooledByteBuffer<'a, L, N, M>
where
    M: RawMutex,
{
    /// `len` must not be larger than `L`.
    fn new(mut buffer: PooledBuffer<'a, crate::storage::Vec<u8, L>, N, M>, len: usize) -> Self {
        unwrap!(buffer.resize_default(len));

        Self(buffer)
    }
}

impl<const L: usize, const N: usize, M> Deref for PooledByteBuffer<'_, L, N, M>
where
    M: RawMutex,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl<const L: usize, const N: usize, M> DerefMut for PooledByteBuffer<'_, L, N, M>
where
    M: RawMutex,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut_slice()
    }
}

/// Two [`ByteBuffers`] pools used as one: a buffer comes from the first pool when it
/// has one of the requested length, else from the second one.
///
/// Chaining pools of growing buffer sizes gives a pool with size classes, where a
/// request takes the smallest free buffer that holds it.
pub struct ChainedBuffers<F, S> {
    first: F,
    second: S,
}

impl<F, S> ChainedBuffers<F, S> {
    /// Create a new instance from the `first` and the `second` pool.
    pub const fn new(first: F, second: S) -> Self {
        Self { first, second }
    }

    /// Create an in-place initializer from the initializers of the `first` and the `second` pool.
    pub fn init<IF, IS>(first: IF, second: IS) -> impl Init<Self>
    where
        IF: Init<F>,
        IS: Init<S>,
    {
        init!(Self {
            first <- first,
            second <- second,
        })
    }
}

impl<F, S> ByteBuffers for ChainedBuffers<F, S>
where
    F: ByteBuffers,
    S: ByteBuffers,
{
    type Buffer<'a>
        = ChainedBuffer<F::Buffer<'a>, S::Buffer<'a>>
    where
        Self: 'a;

    async fn get(&self, len: usize) -> Option<Self::Buffer<'_>> {
        let mut first = pin!(self.first.get(len));
        let mut second = pin!(self.second.get(len));

        // `select` polls the first pool first, so a free buffer there wins.
        // When one pool gives up, the other one may still deliver.
        match select(&mut first, &mut second).await {
            Either::First(Some(buffer)) => Some(ChainedBuffer::First(buffer)),
            Either::First(None) => second.await.map(ChainedBuffer::Second),
            Either::Second(Some(buffer)) => Some(ChainedBuffer::Second(buffer)),
            Either::Second(None) => first.await.map(ChainedBuffer::First),
        }
    }

    fn get_immediate(&self, len: usize) -> Option<Self::Buffer<'_>> {
        self.first
            .get_immediate(len)
            .map(ChainedBuffer::First)
            .or_else(|| self.second.get_immediate(len).map(ChainedBuffer::Second))
    }
}

/// A buffer of a [`ChainedBuffers`] pool.
pub enum ChainedBuffer<F, S> {
    /// A buffer of the first pool
    First(F),
    /// A buffer of the second pool
    Second(S),
}

impl<F, S> Deref for ChainedBuffer<F, S>
where
    F: Deref<Target = [u8]>,
    S: Deref<Target = [u8]>,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::First(buffer) => buffer,
            Self::Second(buffer) => buffer,
        }
    }
}

impl<F, S> DerefMut for ChainedBuffer<F, S>
where
    F: DerefMut<Target = [u8]>,
    S: DerefMut<Target = [u8]>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::First(buffer) => buffer,
            Self::Second(buffer) => buffer,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use core::mem::MaybeUninit;

    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    use futures_lite::future::block_on;

    use crate::init::InitMaybeUninit;
    use crate::storage::Vec;

    use super::{Buffers, PooledBuffers};

    type Pool = PooledBuffers<Vec<u8, 8>, 2, NoopRawMutex>;

    #[test]
    fn get_immediate_exhausts_and_releases() {
        let pool = Pool::new();

        let mut a = pool.get_immediate().unwrap();
        let mut b = pool.get_immediate().unwrap();
        assert!(pool.get_immediate().is_none());

        // Two buffers are live at the same time: writes to one must not affect the other
        a.push(1).unwrap();
        b.push(2).unwrap();
        b.push(3).unwrap();
        assert_eq!(a.as_slice(), &[1]);
        assert_eq!(b.as_slice(), &[2, 3]);

        // Dropping a buffer returns it to the pool
        drop(a);
        let mut c = pool.get_immediate().unwrap();
        assert!(pool.get_immediate().is_none());

        c.clear();
        c.push(4).unwrap();
        assert_eq!(b.as_slice(), &[2, 3]);
        assert_eq!(c.as_slice(), &[4]);

        drop(b);
        drop(c);
        let _a = pool.get_immediate().unwrap();
        let _b = pool.get_immediate().unwrap();
        assert!(pool.get_immediate().is_none());
    }

    #[test]
    fn get_without_timeout_is_immediate() {
        let pool = Pool::new();

        block_on(async {
            let a = pool.get().await.unwrap();
            let b = pool.get().await.unwrap();
            assert!(pool.get().await.is_none());

            drop(a);
            assert!(pool.get().await.is_some());
            drop(b);
        });
    }

    #[test]
    fn get_with_timeout() {
        let pool = Pool::new_with_timeout(10);

        block_on(async {
            let a = pool.get().await.unwrap();
            let _b = pool.get().await.unwrap();

            // All buffers are taken and nobody releases one: the wait must time out
            assert!(pool.get().await.is_none());

            drop(a);
            assert!(pool.get().await.is_some());
        });
    }

    #[test]
    fn init_in_place() {
        let mut slot = MaybeUninit::<Pool>::uninit();
        let pool = slot.init_with(Pool::init());

        {
            let mut a = pool.get_immediate().unwrap();
            a.push(5).unwrap();
            assert_eq!(a.as_slice(), &[5]);
        }
        assert!(pool.get_immediate().is_some());

        // SAFETY: `slot` was initialized by `init_with` above
        unsafe { slot.assume_init_drop() };
    }

    /// `ByteBuffers` lives in a module of its own: `PooledBuffers` of byte vectors
    /// implement both traits, so method calls would be ambiguous with `Buffers` in scope
    mod bytes {
        use core::mem::MaybeUninit;

        use embassy_sync::blocking_mutex::raw::NoopRawMutex;

        use futures_lite::future::block_on;

        use crate::init::InitMaybeUninit;
        use crate::storage::Vec;

        use super::super::{ByteBuffers, ChainedBuffer, ChainedBuffers, PooledBuffers};

        type Small = PooledBuffers<Vec<u8, 4>, 1, NoopRawMutex>;
        type Large = PooledBuffers<Vec<u8, 8>, 1, NoopRawMutex>;

        #[test]
        fn pooled_buffers_have_the_requested_length() {
            let pool = PooledBuffers::<Vec<u8, 8>, 2, NoopRawMutex>::new();

            let mut a = pool.get_immediate(3).unwrap();
            assert_eq!(a.len(), 3);
            a.copy_from_slice(&[1, 2, 3]);

            // Larger than the buffers of the pool
            assert!(pool.get_immediate(9).is_none());

            let b = pool.get_immediate(8).unwrap();
            assert_eq!(b.len(), 8);
            assert!(pool.get_immediate(0).is_none());

            drop(a);
            assert!(pool.get_immediate(0).unwrap().is_empty());
        }

        #[test]
        fn chained_buffers_prefer_the_first_pool() {
            let pool = ChainedBuffers::new(Small::new(), Large::new());

            let a = pool.get_immediate(2).unwrap();
            assert!(matches!(a, ChainedBuffer::First(_)));
            assert_eq!(a.len(), 2);

            // The first pool is empty now
            let b = pool.get_immediate(2).unwrap();
            assert!(matches!(b, ChainedBuffer::Second(_)));
            assert!(pool.get_immediate(2).is_none());

            drop(a);
            drop(b);

            // Too large for the first pool
            let c = pool.get_immediate(5).unwrap();
            assert!(matches!(c, ChainedBuffer::Second(_)));
            assert!(pool.get_immediate(5).is_none());
            assert!(matches!(
                pool.get_immediate(4).unwrap(),
                ChainedBuffer::First(_)
            ));

            // Too large for both pools
            drop(c);
            assert!(pool.get_immediate(9).is_none());
        }

        #[test]
        fn chained_buffers_get() {
            let pool = ChainedBuffers::new(Small::new(), Large::new());

            block_on(async {
                let a = pool.get(4).await.unwrap();
                assert!(matches!(a, ChainedBuffer::First(_)));

                let b = pool.get(4).await.unwrap();
                assert!(matches!(b, ChainedBuffer::Second(_)));

                assert!(pool.get(4).await.is_none());

                drop(b);
                assert!(matches!(pool.get(8).await, Some(ChainedBuffer::Second(_))));
                drop(a);
            });
        }

        #[test]
        fn chained_buffers_get_with_timeout() {
            let pool =
                ChainedBuffers::new(Small::new_with_timeout(10), Large::new_with_timeout(10));

            block_on(async {
                let _a = pool.get(4).await.unwrap();

                // The first pool waits, but the second one has a free buffer
                let b = pool.get(4).await.unwrap();
                assert!(matches!(b, ChainedBuffer::Second(_)));

                // Both pools wait, and nobody releases a buffer
                assert!(pool.get(4).await.is_none());

                // The first pool cannot ever serve this, the second one times out
                assert!(pool.get(8).await.is_none());

                drop(b);
                assert!(pool.get(8).await.is_some());
            });
        }

        #[test]
        fn chained_buffers_init_in_place() {
            let mut slot = MaybeUninit::<ChainedBuffers<Small, Large>>::uninit();
            let pool = slot.init_with(ChainedBuffers::init(Small::init(), Large::init()));

            assert!(matches!(
                pool.get_immediate(1),
                Some(ChainedBuffer::First(_))
            ));

            // SAFETY: `slot` was initialized by `init_with` above
            unsafe { slot.assume_init_drop() };
        }
    }
}
