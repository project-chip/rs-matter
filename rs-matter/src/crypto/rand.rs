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

//! Random number generation utilities.

use embassy_sync::blocking_mutex::raw::RawMutex;

use rand_core::{CryptoRng, RngCore};

use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::sync::blocking::Mutex;

/// A utility wrapping a random number generator in a mutex for shared access.
///
/// Implements the `RngCore` and `CryptoRng` traits for `&SharedRand<M, T>`, where `T` is the
/// underlying RNG type and `M` is the mutex type.
pub struct SharedRand<M: RawMutex, T> {
    shared: Mutex<M, RefCell<T>>,
}

impl<M: RawMutex, T> SharedRand<M, T> {
    /// Creates a new `SharedRand` instance wrapping the provided RNG.
    pub const fn new(rand: T) -> Self {
        Self {
            shared: Mutex::new(RefCell::new(rand)),
        }
    }

    /// Initializes a new `SharedRand` instance using the provided RNG initializer.
    pub fn init(rand: impl Init<T>) -> impl Init<Self> {
        init!(Self {
            shared <- Mutex::init(RefCell::init(rand)),
        })
    }
}

impl<M: RawMutex, T> rand_core::RngCore for &SharedRand<M, T>
where
    T: rand_core::RngCore,
{
    fn next_u32(&mut self) -> u32 {
        self.shared.lock(|rand| rand.borrow_mut().next_u32())
    }

    fn next_u64(&mut self) -> u64 {
        self.shared.lock(|rand| rand.borrow_mut().next_u64())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.shared.lock(|rand| rand.borrow_mut().fill_bytes(dest))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.shared
            .lock(|rand| rand.borrow_mut().try_fill_bytes(dest))
    }
}

impl<M: RawMutex, T> CryptoRng for &SharedRand<M, T> where T: CryptoRng {}

/// A weak random number generator intended for use in tests only.
///
/// DO NOT USE IN PRODUCTION!
pub struct WeakTestOnlyRand(u32);

impl WeakTestOnlyRand {
    /// A fixed seed for the default constructor.
    const SEED: u32 = 2463534242;

    /// Create a new `WeakTestOnlyRand` instance with a default seed.
    pub const fn new_default() -> Self {
        Self(Self::SEED)
    }

    /// Create a new `WeakTestOnlyRand` instance with the specified seed.
    pub const fn new(seed: u32) -> Self {
        Self(seed)
    }
}

impl RngCore for WeakTestOnlyRand {
    fn next_u32(&mut self) -> u32 {
        self.0 = self.0 ^ (self.0 << 13);
        self.0 = self.0 ^ (self.0 >> 17);
        self.0 = self.0 ^ (self.0 << 5);

        self.0
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        rand_core::impls::fill_bytes_via_next(self, dest);

        Ok(())
    }
}

impl CryptoRng for WeakTestOnlyRand {}
