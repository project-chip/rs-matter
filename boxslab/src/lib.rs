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

use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    sync::Mutex,
};

// TODO: why is max bitmap size 64 a correct max size? Could we match
// boxslabs instead or store used/not used inside the box slabs themselves?
const MAX_BITMAP_SIZE: usize = 64;
pub struct Bitmap {
    inner: bitmaps::Bitmap<MAX_BITMAP_SIZE>,
    max_size: usize,
}

impl Bitmap {
    pub fn new(max_size: usize) -> Self {
        assert!(max_size <= MAX_BITMAP_SIZE);
        Bitmap {
            inner: bitmaps::Bitmap::new(),
            max_size,
        }
    }

    pub fn set(&mut self, index: usize) -> bool {
        assert!(index < self.max_size);
        self.inner.set(index, true)
    }

    pub fn reset(&mut self, index: usize) -> bool {
        assert!(index < self.max_size);
        self.inner.set(index, false)
    }

    pub fn first_false_index(&self) -> Option<usize> {
        match self.inner.first_false_index() {
            Some(idx) if idx < self.max_size => Some(idx),
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.first_false_index().is_none()
    }
}

#[macro_export]
macro_rules! box_slab {
    ($name:ident,$t:ty,$v:expr) => {
        use std::mem::MaybeUninit;
        use std::sync::Once;
        use $crate::{BoxSlab, Slab, SlabPool};

        pub struct $name;

        impl SlabPool for $name {
            type SlabType = $t;
            fn get_slab() -> &'static Slab<Self> {
                const MAYBE_INIT: MaybeUninit<$t> = MaybeUninit::uninit();
                static mut SLAB_POOL: [MaybeUninit<$t>; $v] = [MAYBE_INIT; $v];
                static mut SLAB_SPACE: Option<Slab<$name>> = None;
                static mut INIT: Once = Once::new();
                unsafe {
                    INIT.call_once(|| {
                        SLAB_SPACE = Some(Slab::<$name>::init(&mut SLAB_POOL, $v));
                    });
                    SLAB_SPACE.as_ref().unwrap()
                }
            }
        }
    };
}

pub trait SlabPool {
    type SlabType: 'static;
    fn get_slab() -> &'static Slab<Self>
    where
        Self: Sized;
}

pub struct Inner<T: 'static + SlabPool> {
    pool: &'static mut [MaybeUninit<T::SlabType>],
    map: Bitmap,
}

// TODO: Instead of a mutex, we should replace this with a CAS loop
pub struct Slab<T: 'static + SlabPool>(Mutex<Inner<T>>);

impl<T: SlabPool> Slab<T> {
    pub fn init(pool: &'static mut [MaybeUninit<T::SlabType>], size: usize) -> Self {
        Self(Mutex::new(Inner {
            pool,
            map: Bitmap::new(size),
        }))
    }

    pub fn try_new(new_object: T::SlabType) -> Option<BoxSlab<T>> {
        let slab = T::get_slab();
        let mut inner = slab.0.lock().unwrap();
        if let Some(index) = inner.map.first_false_index() {
            inner.map.set(index);
            inner.pool[index].write(new_object);
            let cell_ptr = unsafe { &mut *inner.pool[index].as_mut_ptr() };
            Some(BoxSlab {
                data: cell_ptr,
                index,
            })
        } else {
            None
        }
    }

    pub fn free(&self, index: usize) {
        let mut inner = self.0.lock().unwrap();
        inner.map.reset(index);
        let old_value = std::mem::replace(&mut inner.pool[index], MaybeUninit::uninit());
        let _old_value = unsafe { old_value.assume_init() };
        // This will drop the old_value
    }
}

pub struct BoxSlab<T: 'static + SlabPool> {
    // Because the data is a reference within the MaybeUninit, we don't have a mechanism
    // to go out to the MaybeUninit from this reference. Hence this index
    index: usize,
    // TODO: We should figure out a way to get rid of the index too
    data: &'static mut T::SlabType,
}

impl<T: 'static + SlabPool> Drop for BoxSlab<T> {
    fn drop(&mut self) {
        T::get_slab().free(self.index);
    }
}

impl<T: SlabPool> Deref for BoxSlab<T> {
    type Target = T::SlabType;
    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<T: SlabPool> DerefMut for BoxSlab<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use std::{ops::Deref, sync::Arc};

    pub struct Test {
        val: Arc<u32>,
    }

    box_slab!(TestSlab, Test, 3);

    #[test]
    fn simple_alloc_free() {
        {
            let a = Slab::<TestSlab>::try_new(Test { val: Arc::new(10) }).unwrap();
            assert_eq!(*a.val.deref(), 10);
            let inner = TestSlab::get_slab().0.lock().unwrap();
            assert!(!inner.map.is_empty());
        }
        // Validates that the 'Drop' got executed
        let inner = TestSlab::get_slab().0.lock().unwrap();
        assert!(inner.map.is_empty());
        println!("Box Size {}", std::mem::size_of::<Box<Test>>());
        println!("BoxSlab Size {}", std::mem::size_of::<BoxSlab<TestSlab>>());
    }

    #[test]
    fn alloc_full_block() {
        {
            let a = Slab::<TestSlab>::try_new(Test { val: Arc::new(10) }).unwrap();
            let b = Slab::<TestSlab>::try_new(Test { val: Arc::new(11) }).unwrap();
            let c = Slab::<TestSlab>::try_new(Test { val: Arc::new(12) }).unwrap();
            // Test that at overflow, we return None
            assert!(Slab::<TestSlab>::try_new(Test { val: Arc::new(13) }).is_none(),);
            assert_eq!(*b.val.deref(), 11);

            {
                let inner = TestSlab::get_slab().0.lock().unwrap();
                // Test that the bitmap is marked as full
                assert!(inner.map.is_full());
            }

            // Purposefully drop, to test that new allocation is possible
            std::mem::drop(b);
            let d = Slab::<TestSlab>::try_new(Test { val: Arc::new(21) }).unwrap();
            assert_eq!(*d.val.deref(), 21);

            // Ensure older allocations are still valid
            assert_eq!(*a.val.deref(), 10);
            assert_eq!(*c.val.deref(), 12);
        }

        // Validates that the 'Drop' got executed - test that the bitmap is empty
        let inner = TestSlab::get_slab().0.lock().unwrap();
        assert!(inner.map.is_empty());
    }

    #[test]
    fn test_drop_logic() {
        let root = Arc::new(10);
        {
            let _a = Slab::<TestSlab>::try_new(Test { val: root.clone() }).unwrap();
            let _b = Slab::<TestSlab>::try_new(Test { val: root.clone() }).unwrap();
            let _c = Slab::<TestSlab>::try_new(Test { val: root.clone() }).unwrap();
            assert_eq!(Arc::strong_count(&root), 4);
        }
        // Test that Drop was correctly called on all the members of the pool
        assert_eq!(Arc::strong_count(&root), 1);
    }
}
