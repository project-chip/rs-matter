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
    pub fn init_none<I: init::Init<T, E>, E>() -> impl init::Init<Self, E> {
        Self::init::<I, E>(None)
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

    /// Return a mutable reference to the wrapped value, if it exists.
    pub fn as_mut(&mut self) -> Option<&mut T> {
        if self.some {
            Some(unsafe { self.value.assume_init_mut() })
        } else {
            None
        }
    }

    /// Return a reference to the wrapped value, if it exists.
    pub fn as_ref(&self) -> Option<&T> {
        if self.some {
            Some(unsafe { self.value.assume_init_ref() })
        } else {
            None
        }
    }

    /// Derefs the wrapped value, if it exists.
    pub fn as_deref(&self) -> Option<&T::Target>
    where
        T: Deref,
    {
        match self.as_ref() {
            Some(t) => Some(t.deref()),
            None => None,
        }
    }

    /// Derefs mutably the wrapped value, if it exists.
    pub fn as_deref_mut(&mut self) -> Option<&mut T::Target>
    where
        T: DerefMut,
    {
        match self.as_mut() {
            Some(t) => Some(t.deref_mut()),
            None => None,
        }
    }

    /// Consume the `Maybe` value and return the wrapped value, if it exists.
    ///
    /// Note that this method is not efficient when the wrapped value is large
    /// (might result in big stack memory usage due to moves), hence its usage
    /// is not recommended when the wrapped value is large.
    pub fn into_option(self) -> Option<T> {
        if self.some {
            Some(unsafe { self.value.assume_init() })
        } else {
            None
        }
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
        Maybe::<_, G>::new(self.as_ref().cloned())
    }
}

impl<T, G> Copy for Maybe<T, G> where T: Copy {}

impl<T, G> PartialEq for Maybe<T, G>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl<T, G> Eq for Maybe<T, G> where T: Eq {}

impl<T, G> Hash for Maybe<T, G>
where
    T: Hash,
{
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state)
    }
}
