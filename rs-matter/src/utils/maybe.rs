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

use core::fmt::Debug;
use core::hash::Hash;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::addr_of_mut;

use super::init;

/// Represents a type similar in spirit to the built-in `Option` type.
/// Unlike `Option` however, `Maybe` _does_ have in-place initializer support.
///
/// (In-place initializer support is impossible to provide for `Option` due to its
/// enum nature, and because it is not marked with `repr(transparent)`).
///
/// `Maybe` is convertable to and from `Option` (via the `From` / `Into` traits),
/// however these conversions are not recommended when the wrapped value is large
/// which defeats the purpose of using `Maybe` in the first place.
///
/// The canonical way to use `Maybe` with large values is to initialize it in-place with
/// one of the provided init constructors, and then use one of the `as_ref`, `as_mut`,
/// `as_deref` and `as_deref_mut` methods to access the wrapped value.
#[derive(Debug)]
pub struct Maybe<T, G = ()> {
    some: bool,
    value: MaybeUninit<T>,
    _tag: PhantomData<G>,
}

impl<T, G> Maybe<T, G> {
    /// Create a new `Maybe` value from an `Option`.
    ///
    /// Note that when the wrapped value is large, it is recommended instead to use
    /// `Maybe::init_none()` and `Maybe::init_some()` to create the `Maybe` value in-place.
    pub fn new(value: Option<T>) -> Self {
        match value {
            Some(v) => Self::some(v),
            None => Self::none(),
        }
    }

    /// Create a new, empty `Maybe` value.
    pub const fn none() -> Self {
        Self {
            some: false,
            value: MaybeUninit::uninit(),
            _tag: PhantomData,
        }
    }

    /// Create a new `Maybe` value with a wrapped value.
    pub const fn some(value: T) -> Self {
        Self {
            some: true,
            value: MaybeUninit::new(value),
            _tag: PhantomData,
        }
    }

    /// Create an in-place initializer for a `Maybe` value that is empty.
    pub fn init_none() -> impl init::Init<Self> {
        unsafe {
            init::init_from_closure(move |slot: *mut Self| {
                addr_of_mut!((*slot).some).write(false);

                Ok(())
            })
        }
    }

    /// Create an in-place initializer for a `Maybe` value that is not empty
    /// by initializing the wrapped value with the provided initializer.
    pub fn init_some<I: init::Init<T, E>, E>(value: I) -> impl init::Init<Self, E> {
        Self::init(Some(value))
    }

    /// Create an in-place initializer for a `Maybe` value that might or might
    /// not be empty.
    pub fn init<I: init::Init<T, E>, E>(value: Option<I>) -> impl init::Init<Self, E> {
        unsafe {
            init::init_from_closure(move |slot: *mut Self| {
                addr_of_mut!((*slot).some).write(value.is_some());

                if let Some(value) = value {
                    value.__init(addr_of_mut!((*slot).value) as _)?;
                }

                Ok(())
            })
        }
    }

    /// Sets the `Maybe` value to "none".
    pub fn clear(&mut self) {
        if self.some {
            unsafe {
                let slot = addr_of_mut!(*self);

                addr_of_mut!((*slot).some).write(false);

                let value = addr_of_mut!((*slot).value) as *mut T;

                core::ptr::drop_in_place(value);
            }
        }
    }

    /// Re-initialize the `Maybe` value with a new in-place initializer.
    pub fn reinit<I: init::Init<Self>>(&mut self, value: I) {
        // Unwrap is safe because the initializer is infallible
        unwrap!(Self::try_reinit(self, value));
    }

    /// Try to re-initialize the `Maybe` value with a new in-place initializer.
    ///
    /// If the re-initialization fails, the `Maybe` value is left to `none`.
    pub fn try_reinit<I: init::Init<Self, E>, E>(&mut self, value: I) -> Result<(), E> {
        self.clear();

        unsafe {
            let slot = addr_of_mut!(*self);

            value.__init(slot)
        }
    }

    /// Return a mutable reference to the wrapped value, if it exists.
    pub fn as_mut(&mut self) -> Maybe<&mut T, G> {
        if self.some {
            Maybe::some(unsafe { self.value.assume_init_mut() })
        } else {
            Maybe::none()
        }
    }

    /// Return a reference to the wrapped value, if it exists.
    pub fn as_ref(&self) -> Maybe<&T, G> {
        if self.some {
            Maybe::some(unsafe { self.value.assume_init_ref() })
        } else {
            Maybe::none()
        }
    }

    /// Return - as an `Option` - a mutable reference to the wrapped value, if it exists.
    pub fn as_opt_mut(&mut self) -> Option<&mut T> {
        if self.some {
            Some(unsafe { self.value.assume_init_mut() })
        } else {
            None
        }
    }

    /// Return - as an `Option` - a reference to the wrapped value, if it exists.
    pub fn as_opt_ref(&self) -> Option<&T> {
        if self.some {
            Some(unsafe { self.value.assume_init_ref() })
        } else {
            None
        }
    }

    /// Derefs the wrapped value, if it exists.
    pub fn as_deref(&self) -> Maybe<&T::Target, G>
    where
        T: Deref,
    {
        match self.as_opt_ref() {
            Some(t) => Maybe::some(t.deref()),
            None => Maybe::none(),
        }
    }

    /// Derefs mutably the wrapped value, if it exists.
    pub fn as_deref_mut(&mut self) -> Maybe<&mut T::Target, G>
    where
        T: DerefMut,
    {
        match self.as_opt_mut() {
            Some(t) => Maybe::some(t.deref_mut()),
            None => Maybe::none(),
        }
    }

    /// Derefs - as an `Option` - the wrapped value, if it exists.
    pub fn as_opt_deref(&self) -> Option<&T::Target>
    where
        T: Deref,
    {
        match self.as_opt_ref() {
            Some(t) => Some(t.deref()),
            None => None,
        }
    }

    /// Derefs - as an `Option` - mutably the wrapped value, if it exists.
    pub fn as_opt_deref_mut(&mut self) -> Option<&mut T::Target>
    where
        T: DerefMut,
    {
        match self.as_opt_mut() {
            Some(t) => Some(t.deref_mut()),
            None => None,
        }
    }

    /// Consume the `Maybe` value and return the wrapped value, if it exists.
    ///
    /// Note that this method is not efficient when the wrapped value is large
    /// (might result in big stack memory usage due to moves), hence its usage
    /// is not recommended when the wrapped value is large.
    pub fn into_option(mut self) -> Option<T> {
        if !self.some {
            return None;
        }

        Some(unsafe {
            let slot = addr_of_mut!(self);

            let ret = core::ptr::read(addr_of_mut!((*slot).value) as *mut _);

            // So that `T` is not double-dropped on dtor
            self.some = false;

            ret
        })
    }

    /// Return whether the `Maybe` value is empty.
    pub fn is_none(&self) -> bool {
        !self.some
    }

    /// Return whether the `Maybe` value is not empty.
    pub fn is_some(&self) -> bool {
        self.some
    }
}

impl<T, G> Drop for Maybe<T, G> {
    fn drop(&mut self) {
        // Explicit drop to ensure that the wrapped value is dropped
        // The compiler won't drop it automatically, because it is tracked as `MaybeUninit<T>`
        // (even if it is initialized in the meantime, i.e. `self.some == true`)
        self.clear();
    }
}

impl<T, G> Default for Maybe<T, G> {
    fn default() -> Self {
        Self::none()
    }
}

impl<T, G> From<Option<T>> for Maybe<T, G> {
    fn from(value: Option<T>) -> Self {
        Self::new(value)
    }
}

impl<T, G> From<Maybe<T, G>> for Option<T> {
    fn from(value: Maybe<T, G>) -> Self {
        value.into_option()
    }
}

impl<T, G> Clone for Maybe<T, G>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Maybe::<_, G>::new(self.as_opt_ref().cloned())
    }
}

impl<T, G> PartialEq for Maybe<T, G>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.as_opt_ref() == other.as_opt_ref()
    }
}

impl<T, G> Eq for Maybe<T, G> where T: Eq {}

impl<T, G> Hash for Maybe<T, G>
where
    T: Hash,
{
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_opt_ref().hash(state)
    }
}

#[cfg(feature = "defmt")]
impl<T, G> defmt::Format for Maybe<T, G>
where
    T: defmt::Format,
{
    fn format(&self, f: defmt::Formatter<'_>) {
        if self.is_none() {
            defmt::write!(f, "None")
        } else {
            defmt::write!(f, "Some({})", unsafe { self.value.assume_init_ref() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Maybe;

    macro_rules! droppable {
        () => {
            static COUNT: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

            #[derive(Eq, Ord, PartialEq, PartialOrd)]
            struct Droppable(());

            impl Droppable {
                fn new() -> Self {
                    COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    Droppable(())
                }

                fn count() -> i32 {
                    COUNT.load(core::sync::atomic::Ordering::Relaxed)
                }
            }

            impl Drop for Droppable {
                fn drop(&mut self) {
                    COUNT.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
                }
            }

            impl Clone for Droppable {
                fn clone(&self) -> Self {
                    COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

                    Self(())
                }
            }
        };
    }

    #[test]
    fn drop() {
        droppable!();

        // Test dropping none

        assert_eq!(Droppable::count(), 0);

        {
            let _m: Maybe<Droppable> = Maybe::none();
        }

        assert_eq!(Droppable::count(), 0);

        // Test dropping some

        {
            let _m: Maybe<Droppable> = Maybe::some(Droppable::new());
        }

        assert_eq!(Droppable::count(), 0);

        // Test `into_option` destructuring
        {
            let m: Maybe<Droppable> = Maybe::some(Droppable::new());
            m.into_option();
        }

        assert_eq!(Droppable::count(), 0);

        // Test clone semantics w.r.t. drop

        {
            let m: Maybe<Droppable> = Maybe::some(Droppable::new());

            let _m2 = m.clone();

            core::mem::drop(m);

            assert_eq!(Droppable::count(), 1);
        }

        assert_eq!(Droppable::count(), 0);

        // Test clear semantics w.r.t. drop

        {
            let mut m: Maybe<Droppable> = Maybe::some(Droppable::new());

            m.clear();
        }

        assert_eq!(Droppable::count(), 0);
    }
}
