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

use core::ops::{Deref, DerefMut};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::{Mutex, MutexGuard};

/// A trait for concurrently accessing a &mut [u8] buffer from multiple async tasks.
pub trait BufferAccess {
    type Buffer<'a>: DerefMut<Target = [u8]>
    where
        Self: 'a;

    /// Get a reference to the buffer.
    /// Await until the buffer is available, as it might be in use by somebody else.
    async fn get(&self) -> Self::Buffer<'_>;
}

impl<T> BufferAccess for &T
where
    T: BufferAccess,
{
    type Buffer<'a> = T::Buffer<'a> where Self: 'a;

    async fn get(&self) -> Self::Buffer<'_> {
        (*self).get().await
    }
}

/// A concrete implementation of `BufferAccess` utilizing a single internal buffer.
pub struct BufferAccessImpl<const N: usize>(Mutex<NoopRawMutex, heapless::Vec<u8, N>>);

impl<const N: usize> BufferAccessImpl<N> {
    #[inline(always)]
    pub const fn new() -> Self {
        Self(Mutex::new(heapless::Vec::new()))
    }
}

impl<const N: usize> BufferAccess for BufferAccessImpl<N> {
    type Buffer<'a> = BufferImpl<'a, N> where Self: 'a;

    async fn get(&self) -> Self::Buffer<'_> {
        let mut guard = self.0.lock().await;

        guard.resize_default(N).unwrap();

        BufferImpl(guard)
    }
}

pub struct BufferImpl<'a, const N: usize>(MutexGuard<'a, NoopRawMutex, heapless::Vec<u8, N>>);

impl<'a, const N: usize> Deref for BufferImpl<'a, N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, const N: usize> DerefMut for BufferImpl<'a, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
