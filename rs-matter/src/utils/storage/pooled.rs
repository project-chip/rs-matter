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
use core::future::Future;
use core::ops::{Deref, DerefMut};
use core::pin::pin;

use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_time::{Duration, Timer};

use crate::utils::init::{init, Init, UnsafeCellInit};
use crate::utils::sync::Signal;

/// A trait for getting access to a `&mut T` buffer, potentially awaiting until a buffer becomes available.
pub trait BufferAccess<T>
where
    T: ?Sized,
{
    type Buffer<'a>: DerefMut<Target = T>
    where
        Self: 'a;

    /// Get a reference to a buffer.
    /// Might await until a buffer is available, as it might be in use by somebody else.
    ///
    /// Depending on its internal implementation details, access to a buffer might also be denied
    /// immediately, or after a certain amount of time (subject to the concrete implementation of the method).
    /// In that case, the method will return `None`.
    async fn get(&self) -> Option<Self::Buffer<'_>>;

    /// Get a reference to a buffer immediately, without waiting.
    /// If no buffer is available, return `None`.
    fn get_immediate(&self) -> Option<Self::Buffer<'_>>;
}

impl<B, T> BufferAccess<T> for &B
where
    B: BufferAccess<T>,
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

/// A concrete implementation of `BufferAccess` utilizing an internal pool of buffers.
/// Accessing a buffer would fail when all buffers are still used elsewhere after a wait timeout expires.
pub struct PooledBuffers<const N: usize, M, T> {
    available: Signal<M, [bool; N]>,
    pool: UnsafeCell<crate::utils::storage::Vec<T, N>>,
    wait_timeout_ms: u32,
}

impl<const N: usize, M, T> PooledBuffers<N, M, T>
where
    M: RawMutex,
{
    /// Create a new instance of `PooledBuffers`.
    ///
    /// `wait_timneout_ms` is the maximum time to wait for a buffer to become available
    /// before returning `None`.
    #[inline(always)]
    pub const fn new(wait_timeout_ms: u32) -> Self {
        Self {
            available: Signal::new([true; N]),
            pool: UnsafeCell::new(crate::utils::storage::Vec::new()),
            wait_timeout_ms,
        }
    }

    /// Create an in-place initializer for `PooledBuffers`.
    ///
    /// `wait_timneout_ms` is the maximum time to wait for a buffer to become available
    /// before returning `None`.
    pub fn init(wait_timeout_ms: u32) -> impl Init<Self> {
        init!(Self {
            available: Signal::new([true; N]),
            pool <- UnsafeCell::init(crate::utils::storage::Vec::init()),
            wait_timeout_ms,
        })
    }
}

impl<const N: usize, M, T> BufferAccess<T> for PooledBuffers<N, M, T>
where
    M: RawMutex,
    T: Default + Clone,
{
    type Buffer<'b>
        = PooledBuffer<'b, N, M, T>
    where
        Self: 'b;

    async fn get(&self) -> Option<Self::Buffer<'_>> {
        if self.wait_timeout_ms > 0 {
            let mut wait = pin!(self.available.wait(|available| {
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
                    let buffer = &mut unwrap!(unsafe { self.pool.get().as_mut() })[index];

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
            if let Some(index) = available.iter().position(|a| *a) {
                available[index] = false;
                (false, Some(index))
            } else {
                (false, None)
            }
        });

        index.map(|index| {
            let buffers = unwrap!(unsafe { self.pool.get().as_mut() });
            unwrap!(buffers.resize_default(N));

            let buffer = &mut buffers[index];

            PooledBuffer {
                index,
                buffer,
                access: self,
            }
        })
    }
}

pub struct PooledBuffer<'a, const N: usize, M, T>
where
    M: RawMutex,
{
    index: usize,
    buffer: &'a mut T,
    access: &'a PooledBuffers<N, M, T>,
}

impl<const N: usize, M, T> Drop for PooledBuffer<'_, N, M, T>
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

impl<const N: usize, M, T> Deref for PooledBuffer<'_, N, M, T>
where
    M: RawMutex,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.buffer.deref()
    }
}

impl<const N: usize, M, T> DerefMut for PooledBuffer<'_, N, M, T>
where
    M: RawMutex,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.deref_mut()
    }
}
