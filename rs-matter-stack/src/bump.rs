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
macro_rules! alloc_init {
    ($bump:expr, $init:expr) => {
        $bump.alloc_init($init, concat!(file!(), ":", line!()))
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
    // Keep out-of-line so `T` / `f()` temporaries stay in a transient stack frame
    // instead of being spilled into a caller `async fn` state machine.
    #[inline(never)]
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

    /// Allocate an object, built in its slot by the in-place initializer `init`.
    // Keep out-of-line so in-place initialization intermediates are not captured in
    // a caller `async fn` state machine.
    #[inline(never)]
    pub fn alloc_init<T, I>(&self, init: I, location: &str) -> BumpBox<'_, T>
    where
        T: Sized,
        I: Init<T>,
    {
        let slot = self.reserve::<T>(location);

        // Safety: `reserve` handed out a properly aligned, exclusively owned slot
        unsafe { init.__init(slot.as_ptr().cast::<T>()) }.unwrap_or_else(|never| match never {});

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
        self.reserve_raw(
            core::mem::size_of::<T>(),
            core::mem::align_of::<T>(),
            location,
        )
        .cast()
    }

    /// Reserve `size` uninitialized bytes, aligned to `align`
    // Not generic over the allocated type, so all allocations share one copy of this code.
    #[inline(never)]
    fn reserve_raw(&self, size: usize, align: usize, location: &str) -> NonNull<u8> {
        self.inner.lock(|inner| {
            let offset = inner.offset.get();

            info!(
                "BUMP[{}]: {}b (U:{}b/F:{}b)",
                location,
                size,
                offset,
                N - offset
            );

            if size == 0 {
                // Safety: `align` is a power of two, so it is not zero
                return unsafe { NonNull::new_unchecked(core::ptr::without_provenance_mut(align)) };
            }

            let memory = inner.memory.get().cast::<u8>();

            let start = offset + ((memory.addr() + offset).wrapping_neg() & (align - 1));
            if start > N || N - start < size {
                panic!("Out of bump memory");
            }

            inner.offset.set(start + size);

            // Safety: `start < N`, so the pointer is within the arena. The memory past `offset`
            // is not referenced by any previously handed out slot.
            unsafe { NonNull::new_unchecked(memory.add(start)) }
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

// Safety: a `BumpBox` owns its `T`, as a `Box` does
unsafe impl<T: Send> Send for BumpBox<'_, T> {}
unsafe impl<T: Sync> Sync for BumpBox<'_, T> {}

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

        let all_boxes: [_; BUMP_SIZE / core::mem::size_of::<usize>()] =
            core::array::from_fn(|i| alloc!(bump, i));

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

    #[test]
    fn test_alignment() {
        #[repr(align(64))]
        struct Aligned64([u8; 3]);

        let bump = Bump::<BUMP_SIZE>::new();

        // A single byte first, so that the slots below do not start at the arena start
        let a = bump.alloc(1u8, "a");
        let b = bump.alloc(2u64, "b");
        let c = bump.alloc(3u128, "c");
        let d = bump.alloc(Aligned64([4; 3]), "d");
        let e = bump.alloc(5u16, "e");

        let spans = [span(&*a), span(&*b), span(&*c), span(&*d), span(&*e)];
        let aligns = [
            1,
            core::mem::align_of::<u64>(),
            core::mem::align_of::<u128>(),
            64,
            core::mem::align_of::<u16>(),
        ];

        for (span, align) in spans.iter().zip(aligns) {
            assert_eq!(span.start % align, 0);
        }

        for pair in spans.windows(2) {
            assert!(pair[0].end <= pair[1].start);
        }

        assert_eq!(*a, 1);
        assert_eq!(*b, 2);
        assert_eq!(*c, 3);
        assert_eq!(d.0, [4; 3]);
        assert_eq!(*e, 5);
    }

    #[test]
    fn test_zero_sized() {
        #[repr(align(16))]
        struct Aligned16;

        let bump = Bump::<BUMP_SIZE>::new();

        for _ in 0..2 * BUMP_SIZE {
            let _unit = bump.alloc((), "unit");
            let aligned = bump.alloc(Aligned16, "aligned");
            assert_eq!(span(&*aligned).start % 16, 0);
        }

        // The zero-sized values took no space, not even for alignment padding
        let all = bump.alloc([7u8; BUMP_SIZE], "all");
        assert!(all.iter().all(|&v| v == 7));
    }

    #[test]
    fn test_exact_fit() {
        let bump = Bump::<BUMP_SIZE>::new();

        let a = bump.alloc(1u8, "a");
        let b = bump.alloc([2u8; BUMP_SIZE - 1], "b");

        assert_eq!(*a, 1);
        assert!(b.iter().all(|&v| v == 2));
    }

    #[test]
    #[should_panic(expected = "Out of bump memory")]
    fn test_out_of_memory() {
        let bump = Bump::<BUMP_SIZE>::new();

        let _a = bump.alloc(1u8, "a");
        let _b = bump.alloc([2u8; BUMP_SIZE], "b");
    }

    /// The addresses that `value` occupies
    fn span<T>(value: &T) -> core::ops::Range<usize> {
        let start = (value as *const T).addr();

        start..start + core::mem::size_of::<T>()
    }
}
