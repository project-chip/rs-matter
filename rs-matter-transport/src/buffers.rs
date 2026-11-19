/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! The pool of the protocol payload buffers.

use core::future::Future;

use cfg_if::cfg_if;

use crate::utils::init::{init, Init};
use crate::utils::storage::pooled::{ByteBuffers, PooledBuffers, DEFAULT_BUFFER_POOL_SIZE};
use crate::utils::storage::Vec;

use super::network;

/// The size of a [`UdpBuffer`].
pub const UDP_BUFFER_SIZE: usize = network::MAX_RX_PACKET_SIZE;

/// A protocol payload buffer which holds a UDP message.
///
/// Smaller than a [`Buffer`](crate::exchange::Buffer) only with a `large-buffers-*` feature.
pub type UdpBuffer = Vec<u8, UDP_BUFFER_SIZE>;

/// The default number of the large buffers of [`MatterBuffers`]: the TX and the RX
/// buffer of one interaction with large messages.
pub const DEFAULT_LARGE_BUFFER_POOL_SIZE: usize = 2;

/// A [`ByteBuffers`] pool pre-configured with Matter defaults: `N` [`UdpBuffer`]s
/// (by default [`DEFAULT_BUFFER_POOL_SIZE`]) and, with a `large-buffers-*` feature,
/// `NL` large [`Buffer`](crate::exchange::Buffer)s (by default
/// [`DEFAULT_LARGE_BUFFER_POOL_SIZE`]).
///
/// A request takes a UDP-sized buffer when it fits one and one is free, else a large one.
/// Only TCP exchanges ask for more than a UDP message.
pub struct MatterBuffers<
    const N: usize = DEFAULT_BUFFER_POOL_SIZE,
    const NL: usize = DEFAULT_LARGE_BUFFER_POOL_SIZE,
> {
    pools: Pools<N, NL>,
}

impl<const N: usize, const NL: usize> MatterBuffers<N, NL> {
    /// Create a new instance which denies buffer access immediately when no buffer is free.
    #[inline(always)]
    pub const fn new() -> Self {
        Self::new_with_timeout(0)
    }

    /// Create a new instance.
    ///
    /// `wait_timeout_ms` is the maximum time to wait for a buffer to become available
    /// before returning `None`.
    #[inline(always)]
    pub const fn new_with_timeout(wait_timeout_ms: u32) -> Self {
        Self {
            pools: new_pools::<N, NL>(wait_timeout_ms),
        }
    }

    /// Create an in-place initializer which denies buffer access immediately when no buffer is free.
    pub fn init() -> impl Init<Self> {
        Self::init_with_timeout(0)
    }

    /// Create an in-place initializer.
    ///
    /// `wait_timeout_ms` is the maximum time to wait for a buffer to become available
    /// before returning `None`.
    pub fn init_with_timeout(wait_timeout_ms: u32) -> impl Init<Self> {
        init!(Self {
            pools <- init_pools::<N, NL>(wait_timeout_ms),
        })
    }
}

impl<const N: usize, const NL: usize> Default for MatterBuffers<N, NL> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const NL: usize> ByteBuffers for MatterBuffers<N, NL> {
    type Buffer<'a>
        = <Pools<N, NL> as ByteBuffers>::Buffer<'a>
    where
        Self: 'a;

    fn get(&self, len: usize) -> impl Future<Output = Option<Self::Buffer<'_>>> {
        self.pools.get(len)
    }

    fn get_immediate(&self, len: usize) -> Option<Self::Buffer<'_>> {
        self.pools.get_immediate(len)
    }
}

cfg_if! {
    if #[cfg(any(
        feature = "large-buffers-1048576",
        feature = "large-buffers-524288",
        feature = "large-buffers-262144",
        feature = "large-buffers-131072",
        feature = "large-buffers-65536",
        feature = "large-buffers-32768",
        feature = "large-buffers-16384",
        feature = "large-buffers-8192",
        feature = "large-buffers-4096",
    ))] {
        use crate::utils::storage::pooled::ChainedBuffers;

        use super::exchange::Buffer;

        /// The pools of [`MatterBuffers`]: the UDP-sized buffers, then the large ones.
        type Pools<const N: usize, const NL: usize> =
            ChainedBuffers<PooledBuffers<UdpBuffer, N>, PooledBuffers<Buffer, NL>>;

        const fn new_pools<const N: usize, const NL: usize>(wait_timeout_ms: u32) -> Pools<N, NL> {
            ChainedBuffers::new(
                PooledBuffers::new_with_timeout(wait_timeout_ms),
                PooledBuffers::new_with_timeout(wait_timeout_ms),
            )
        }

        fn init_pools<const N: usize, const NL: usize>(
            wait_timeout_ms: u32,
        ) -> impl Init<Pools<N, NL>> {
            ChainedBuffers::init(
                PooledBuffers::init_with_timeout(wait_timeout_ms),
                PooledBuffers::init_with_timeout(wait_timeout_ms),
            )
        }
    } else {
        // Large messages need the `large-buffers-*` feature of this crate too,
        // not only that of `rs-matter-dm-core`
        const _: () = core::assert!(crate::dm::IM_BUFFER_SIZE == UDP_BUFFER_SIZE);

        /// The pool of [`MatterBuffers`]: only the UDP-sized buffers.
        type Pools<const N: usize, const NL: usize> = PooledBuffers<UdpBuffer, N>;

        const fn new_pools<const N: usize, const NL: usize>(wait_timeout_ms: u32) -> Pools<N, NL> {
            PooledBuffers::new_with_timeout(wait_timeout_ms)
        }

        fn init_pools<const N: usize, const NL: usize>(
            wait_timeout_ms: u32,
        ) -> impl Init<Pools<N, NL>> {
            PooledBuffers::init_with_timeout(wait_timeout_ms)
        }
    }
}
