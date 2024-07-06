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

use core::future::poll_fn;
use core::task::{Context, Poll};

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::waitqueue::WakerRegistration;

use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};

use super::blocking::Mutex;

struct State<S> {
    state: S,
    waker: WakerRegistration,
}

impl<S> State<S> {
    const fn new(state: S) -> Self {
        Self {
            state,
            waker: WakerRegistration::new(),
        }
    }

    fn init<I: Init<S>>(state: I) -> impl Init<Self> {
        init!(Self {
            state <- state,
            waker: WakerRegistration::new(),
        })
    }
}

/// `Signal` is an async synchonization primitive that can be viewed as a generalization of the `embassy_sync::Signal` primitive
/// that takes callback closures.
///
/// It allows for waiting on a condition of its state `S` to become true, where whether the condition is met is decided by a callback closure.
///
/// It also allows for modifying the state `S` and waking up the waiters - but only as long as a callback closure provides information that
/// the state is modified in such a way, that the waiters should be notified.
///
/// The generic nature of `Signal` allows for a wide range of use cases, including the implementation of:
/// - the `Notification` primitive
/// - the `IfMutex` primitive
pub struct Signal<M, S> {
    inner: Mutex<M, RefCell<State<S>>>,
}

impl<M, S> Signal<M, S>
where
    M: RawMutex,
{
    /// Create a `Signal` with the given initial state `S`.
    pub const fn new(state: S) -> Self {
        Self {
            inner: Mutex::new(RefCell::new(State::new(state))),
        }
    }

    /// Create a `Signal` in-place initializer with the given initial state initializer `I`.
    pub fn init<I: Init<S>>(state: I) -> impl Init<Self> {
        init!(Self {
            inner <- Mutex::init(RefCell::init(State::init(state))),
        })
    }

    // Modify the state `S` and wake up the waiters if necessary.
    pub fn modify<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut S) -> (bool, R),
    {
        self.inner.lock(|s| {
            let mut s = s.borrow_mut();

            let (wake, result) = f(&mut s.state);

            if wake {
                s.waker.wake();
            }

            result
        })
    }

    // Wait for the condition of the state `S` to become true.
    pub async fn wait<F, R>(&self, mut f: F) -> R
    where
        F: FnMut(&mut S) -> Option<R>,
    {
        poll_fn(move |ctx| self.poll_wait(ctx, &mut f)).await
    }

    // Poll the condition of the state `S` to become true.
    pub fn poll_wait<F, R>(&self, ctx: &mut Context, f: F) -> Poll<R>
    where
        F: FnOnce(&mut S) -> Option<R>,
    {
        self.inner.lock(|s| {
            let mut s = s.borrow_mut();

            if let Some(result) = f(&mut s.state) {
                Poll::Ready(result)
            } else {
                s.waker.register(ctx.waker());
                Poll::Pending
            }
        })
    }
}
