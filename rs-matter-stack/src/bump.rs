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

//! A super-simple bump allocator that allocates off from a fixed-size array.
//!
//! While dropping the `BumpBox` boxes will call the destructor of the contained object,
//! the actual memory will be free only when the unsafe `reset` method is called.
//!
//! The primary use case of this allocator is reduction of Rust future sizes, due to
//! `rustc` not being very intelligent w.r.t. stack usage in async functions.

use core::cell::{Cell, UnsafeCell};
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::ptr::NonNull;

use rs_matter_utils::init::{init, zeroed, Init};
use rs_matter_utils::sync::blocking::Mutex;

#[macro_export]
macro_rules! alloc {
    ($bump:expr, $obj:expr) => {
        $bump.alloc_with(|| $obj, concat!(file!(), ":", line!()))
    };
}

#[macro_export]
macro_rules! pin_alloc {
    ($bump:expr, $obj:expr) => {
        $bump.pin_alloc_with(|| $obj, concat!(file!(), ":", line!()))
    };
}

/// A bump allocator that uses a provided memory chunk
pub struct Bump<const N: usize> {
    inner: Mutex<Inner<N>>,
}

impl<const N: usize> Default for Bump<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Bump<N> {
    /// Create a new bump allocator
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::new()),
        }
    }

    /// Return an initializer for a new bump allocator
    pub fn init() -> impl Init<Self> {
        init!(Self {
            inner <- Mutex::init(Inner::init()),
        })
    }

    /// Reset the allocator, making all previously allocated memory available again.
    ///
    /// # Safety
    /// This is unsafe because any previously allocated objects that are still in use
    /// will get their memory corrupted and overwritten with new objects.
    ///
    /// Make sure that NO previously allocated objects are still in use
    /// when calling this method.
    pub unsafe fn reset(&self) {
        self.inner.lock(|inner| inner.offset.set(0));
    }

    /// Allocate an object and return it pinned in a `Pin<BumpBox<T>>`
    ///
    /// # Arguments
    /// - `object`: The object to allocate
    /// - `location`: A string describing the location of the allocation, for logging purposes
    ///
    /// # Panics
    /// This function will panic if there is not enough memory left in the bump allocator
    pub fn pin_alloc<T>(&self, object: T, location: &str) -> Pin<BumpBox<'_, T>>
    where
        T: Sized,
    {
        let boxed = self.alloc(object, location);

        boxed.into_pin()
    }

    /// Allocate an object and return it in a `BumpBox<T>`
    ///
    /// Prefer `alloc_with` (or the `alloc!` macro) for anything large: the object passed
    /// here already exists on the caller's stack and is copied into the allocator memory.
    ///
    /// # Arguments
    /// - `object`: The object to allocate
    /// - `location`: A string describing the location of the allocation, for logging purposes
    ///
    /// # Panics
    /// This function will panic if there is not enough memory left in the bump allocator
    pub fn alloc<T>(&self, object: T, location: &str) -> BumpBox<'_, T>
    where
        T: Sized,
    {
        self.alloc_with(|| object, location)
    }

    /// Allocate an object constructed by `f` and return it pinned in a `Pin<BumpBox<T>>`
    ///
    /// See `alloc_with` for why construction is deferred to a closure.
    ///
    /// # Arguments
    /// - `f`: A closure constructing the object
    /// - `location`: A string describing the location of the allocation, for logging purposes
    ///
    /// # Panics
    /// This function will panic if there is not enough memory left in the bump allocator
    pub fn pin_alloc_with<T, F>(&self, f: F, location: &str) -> Pin<BumpBox<'_, T>>
    where
        T: Sized,
        F: FnOnce() -> T,
    {
        self.alloc_with(f, location).into_pin()
    }

    /// Allocate an object constructed by `f` and return it in a `BumpBox<T>`
    ///
    /// The object is constructed directly inside the allocator memory. This matters for the
    /// futures this allocator exists for: taking the future by value would first materialize
    /// it on the caller's stack (which is what the allocator is there to avoid in the first
    /// place) and only then copy it over.
    ///
    /// # Arguments
    /// - `f`: A closure constructing the object
    /// - `location`: A string describing the location of the allocation, for logging purposes
    ///
    /// # Panics
    /// This function will panic if there is not enough memory left in the bump allocator
    pub fn alloc_with<T, F>(&self, f: F, location: &str) -> BumpBox<'_, T>
    where
        T: Sized,
        F: FnOnce() -> T,
    {
        let mut slot = self.reserve::<T>(location);

        // The object is constructed here, outside of the allocator lock, so that the compiler
        // can build it straight into its slot: moved into the `lock` closure instead, it would
        // first be materialized on the stack of the caller and copied over from there.
        //
        // Safety: `reserve` handed out a properly aligned, exclusively owned slot
        unsafe {
            slot.as_mut().write(f());
        }

        BumpBox {
            ptr: slot.cast(),
            _allocator: PhantomData,
        }
    }

    /// Reserve an uninitialized, properly aligned slot for a `T`
    fn reserve<T>(&self, location: &str) -> NonNull<MaybeUninit<T>>
    where
        T: Sized,
    {
        self.inner.lock(|inner| {
            let size = core::mem::size_of::<T>();

            let offset = inner.offset.get();

            info!(
                "BUMP[{}]: {}b (U:{}b/F:{}b)",
                location,
                size,
                offset,
                N - offset
            );

            // Safety: The memory past `offset` is not referenced by any previously handed out
            // slot, so a unique slice over it does not alias with anything still in use
            let remaining = unsafe {
                core::slice::from_raw_parts_mut(
                    inner.memory.get().cast::<MaybeUninit<u8>>().add(offset),
                    N - offset,
                )
            };
            let remaining_len = remaining.len();

            let (t_buf, r_buf) = align_min::<T>(remaining, 1);

            // Safety: `align_min` returns a non-empty, aligned slice for a non-ZST
            let ptr = unsafe { NonNull::new_unchecked(t_buf.as_mut_ptr()) };

            inner.offset.set(offset + remaining_len - r_buf.len());

            ptr
        })
    }
}

/// A box-like container that uses bump allocation
pub struct BumpBox<'a, T> {
    ptr: NonNull<T>,
    _allocator: core::marker::PhantomData<&'a ()>,
}

impl<T> BumpBox<'_, T> {
    /// Convert the `BumpBox<T>` into a `Pin<BumpBox<T>>`
    pub fn into_pin(self) -> Pin<Self> {
        // It's not possible to move or replace the insides of a `Pin<Box<T>>`
        // when `T: !Unpin`, so it's safe to pin it directly without any
        // additional requirements.
        unsafe { Pin::new_unchecked(self) }
    }
}

impl<T> core::ops::Deref for BumpBox<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> core::ops::DerefMut for BumpBox<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> Unpin for BumpBox<'_, T> {}

impl<T> Drop for BumpBox<'_, T> {
    fn drop(&mut self) {
        // Safety: The pointer is valid and we own the data
        unsafe {
            self.ptr.as_ptr().drop_in_place();
        }
    }
}

/// The allocator state, only ever accessed through a shared reference.
///
/// Handed out slots stay in use across later allocations, so the allocator must never
/// create a `&mut` covering the whole arena (as e.g. a `RefCell` borrow would): that would
/// invalidate the pointers of all previously allocated `BumpBox`es under the Rust aliasing
/// rules. Instead, each allocation only ever touches the still-unused tail of the arena.
struct Inner<const N: usize> {
    memory: UnsafeCell<MaybeUninit<[u8; N]>>,
    offset: Cell<usize>,
}

impl<const N: usize> Inner<N> {
    const fn new() -> Self {
        Self {
            memory: UnsafeCell::new(MaybeUninit::uninit()),
            offset: Cell::new(0),
        }
    }

    fn init() -> impl Init<Self> {
        init!(Self {
            memory <- zeroed(),
            offset: Cell::new(0),
        })
    }
}

fn align_min<T>(
    buf: &mut [MaybeUninit<u8>],
    count: usize,
) -> (&mut [MaybeUninit<T>], &mut [MaybeUninit<u8>]) {
    if count == 0 || core::mem::size_of::<T>() == 0 {
        return (&mut [], buf);
    }

    let (t_leading_buf0, t_buf, _) = unsafe { buf.align_to_mut::<MaybeUninit<T>>() };
    if t_buf.len() < count {
        panic!("Out of bump memory");
    }

    // Shrink `t_buf` to the number of requested items (count)
    let t_buf = &mut t_buf[..count];
    let t_leading_buf0_len = t_leading_buf0.len();
    let t_buf_size = core::mem::size_of_val(t_buf);

    let (buf0, remaining_buf) = buf.split_at_mut(t_leading_buf0_len + t_buf_size);

    let (t_leading_buf, t_buf, t_remaining_buf) = unsafe { buf0.align_to_mut::<MaybeUninit<T>>() };
    assert_eq!(t_leading_buf0_len, t_leading_buf.len());
    assert_eq!(t_buf.len(), count);
    assert!(t_remaining_buf.is_empty());

    (t_buf, remaining_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUMP_SIZE: usize = 1024;
    const DEFAULT_VALUE: u32 = 0xDEADBEEF;

    #[test]
    fn test_one_concurrent_borrow() {
        let bump = Bump::<BUMP_SIZE>::new();

        for _ in 0..(BUMP_SIZE / core::mem::size_of_val(&DEFAULT_VALUE)) {
            let b1 = bump.alloc(DEFAULT_VALUE, "test1");

            assert_eq!(*b1, DEFAULT_VALUE);
        }
    }

    #[test]
    fn test_multiple_concurrent_borrow() {
        let bump = Bump::<BUMP_SIZE>::new();

        let mut all_boxes = alloc::vec::Vec::new();
        for i in 0..(BUMP_SIZE / core::mem::size_of::<usize>()) {
            all_boxes.push(alloc!(bump, i));
        }

        for (i, b) in all_boxes.into_iter().enumerate() {
            assert_eq!(*b, i);
        }
    }

    #[test]
    fn test_interleaved_mutation() {
        let bump = Bump::<BUMP_SIZE>::new();

        let mut a = bump.alloc([1u8; 3], "a");
        let mut b = bump.alloc(2u64, "b");
        a[1] = 10;
        let c = bump.alloc([3u16; 5], "c");
        *b += 1;
        a[2] = 20;

        assert_eq!(*a, [1, 10, 20]);
        assert_eq!(*b, 3);
        assert_eq!(*c, [3; 5]);

        drop(b);
        drop(a);

        let d = bump.alloc(4u32, "d");
        assert_eq!(*d, 4);
        assert_eq!(*c, [3; 5]);
    }

    #[test]
    fn test_pinned_future() {
        use core::future::Future;
        use core::task::{Context, Poll, Waker};

        let bump = Bump::<BUMP_SIZE>::new();

        let mut polls = 0;
        let mut fut = pin_alloc!(bump, async {
            let buf = [7u8; 64];
            core::future::poll_fn(|_| Poll::Ready(())).await;
            buf.iter().map(|&b| b as usize).sum::<usize>()
        });

        let mut cx = Context::from_waker(Waker::noop());
        loop {
            polls += 1;
            if let Poll::Ready(sum) = fut.as_mut().poll(&mut cx) {
                assert_eq!(sum, 7 * 64);
                break;
            }
        }
        assert_eq!(polls, 1);
    }

    #[test]
    fn test_reset_and_reuse() {
        let bump = Bump::<BUMP_SIZE>::new();

        {
            let mut b = bump.alloc([1u64; 8], "test");
            b[0] = 42;
            assert_eq!(b[0], 42);
        }

        unsafe { bump.reset() };

        let b = bump.alloc(7u8, "test");
        assert_eq!(*b, 7);
    }
}
