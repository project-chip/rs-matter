/*
 *
 *    Copyright (c) 2024-2026 Project CHIP Authors
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
use core::future::{poll_fn, Future};
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::ptr::NonNull;
use core::task::{Context, Poll, Waker};

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::waitqueue::WakerRegistration;

use crate::cell::RefCell;
use crate::init::{init, Init};

use super::blocking::raw::MatterRawMutex;
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
///
/// A `Signal` keeps a single waker, so the code that uses it directly must never have
/// waiters with different wakers at the same time: waiters from other tasks or threads,
/// or from the futures of a `FuturesUnordered`, keep waking each other until their
/// condition holds. Several waiters inside one future share one waker and are fine.
/// Where waiters with different wakers are possible, use [`MultiSignal`] instead.
pub struct Signal<S, M = MatterRawMutex> {
    inner: Mutex<RefCell<State<S>>, M>,
}

impl<S, M> Signal<S, M>
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

    /// Access the state `S` immutably without waking up the waiters.
    pub fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&S) -> R,
    {
        self.modify(|state| (false, f(state)))
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

impl<T, M> Signal<Option<T>, M>
where
    M: RawMutex,
{
    /// Notify the waiter.
    pub fn signal(&self, value: T) {
        self.modify(|state| {
            *state = Some(value);
            (true, ())
        });
    }

    /// Wait for the notification.
    pub async fn wait_signalled(&self) -> T {
        self.wait(|state| state.take()).await
    }
}

/// A waiter of a [`MultiSignal`].
///
/// It lives inside a [`MultiSignalWait`] future, and is linked into the list of waiters
/// of the signal while that future is pending.
struct Node {
    links: UnsafeCell<Links>,
    _pin: PhantomPinned,
}

struct Links {
    waker: Option<Waker>,
    prev: Option<NonNull<Node>>,
    next: Option<NonNull<Node>>,
}

// Safety: `links` is only accessed with the blocking mutex of the signal locked
unsafe impl Send for Node {}

impl Node {
    const fn new() -> Self {
        Self {
            links: UnsafeCell::new(Links {
                waker: None,
                prev: None,
                next: None,
            }),
            _pin: PhantomPinned,
        }
    }

    /// # Safety
    ///
    /// The signal must be locked.
    unsafe fn set_waker(&self, waker: &Waker) {
        let current = &mut (*self.links.get()).waker;

        if !current
            .as_ref()
            .is_some_and(|current| current.will_wake(waker))
        {
            *current = Some(waker.clone());
        }
    }
}

/// The waiters of a [`MultiSignal`]: an intrusive doubly linked list of nodes.
///
/// It is only accessed with the blocking mutex of the signal locked.
struct Waiters {
    head: Option<NonNull<Node>>,
}

// Safety: the nodes are only accessed with the blocking mutex of the signal locked
unsafe impl Send for Waiters {}

impl Waiters {
    const fn new() -> Self {
        Self { head: None }
    }

    /// Set the waker of `node`, and link `node` if it is not linked.
    ///
    /// # Safety
    ///
    /// `node` must not move, and must be unlinked before it is dropped.
    // The list operations are not inlined, as they are the same for all signals
    #[inline(never)]
    unsafe fn register(&mut self, node: NonNull<Node>, linked: &mut bool, waker: &Waker) {
        node.as_ref().set_waker(waker);

        if !*linked {
            let links = &mut *node.as_ref().links.get();

            links.prev = None;
            links.next = self.head;

            if let Some(head) = self.head {
                (*head.as_ref().links.get()).prev = Some(node);
            }

            self.head = Some(node);
            *linked = true;
        }
    }

    /// Unlink `node` if it is linked.
    ///
    /// # Safety
    ///
    /// If `node` is linked, it must be linked into this list.
    #[inline(never)]
    unsafe fn unregister(&mut self, node: NonNull<Node>, linked: &mut bool) {
        if *linked {
            let links = &mut *node.as_ref().links.get();

            match links.prev {
                Some(prev) => (*prev.as_ref().links.get()).next = links.next,
                None => self.head = links.next,
            }

            if let Some(next) = links.next {
                (*next.as_ref().links.get()).prev = links.prev;
            }

            *linked = false;
        }
    }

    /// Wake all waiters. They stay linked until their condition holds or they are dropped.
    #[inline(never)]
    fn wake(&self) {
        let mut current = self.head;

        while let Some(node) = current {
            // Safety: linked nodes are alive, and the signal is locked
            let links = unsafe { &*node.as_ref().links.get() };

            if let Some(waker) = &links.waker {
                waker.wake_by_ref();
            }

            current = links.next;
        }
    }
}

struct MultiState<S> {
    state: S,
    waiters: Waiters,
}

impl<S> MultiState<S> {
    const fn new(state: S) -> Self {
        Self {
            state,
            waiters: Waiters::new(),
        }
    }

    fn init<I: Init<S>>(state: I) -> impl Init<Self> {
        init!(Self {
            state <- state,
            waiters: Waiters::new(),
        })
    }
}

/// A [`Signal`] that any number of waiters, with different wakers, can wait on at the same time.
///
/// Each waiter keeps its own waker in an intrusive list, so the waiters do not wake each other.
/// A change of the state which wakes the waiters wakes all of them.
pub struct MultiSignal<S, M = MatterRawMutex> {
    inner: Mutex<RefCell<MultiState<S>>, M>,
}

impl<S, M> MultiSignal<S, M>
where
    M: RawMutex,
{
    /// Create a `MultiSignal` with the given initial state `S`.
    pub const fn new(state: S) -> Self {
        Self {
            inner: Mutex::new(RefCell::new(MultiState::new(state))),
        }
    }

    /// Create a `MultiSignal` in-place initializer with the given initial state initializer `I`.
    pub fn init<I: Init<S>>(state: I) -> impl Init<Self> {
        init!(Self {
            inner <- Mutex::init(RefCell::init(MultiState::init(state))),
        })
    }

    /// Access the state `S` immutably without waking up the waiters.
    pub fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&S) -> R,
    {
        self.inner.lock(|s| f(&s.borrow().state))
    }

    /// Modify the state `S` and wake up all waiters if necessary.
    pub fn modify<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut S) -> (bool, R),
    {
        self.inner.lock(|s| {
            let mut s = s.borrow_mut();

            let (wake, result) = f(&mut s.state);

            if wake {
                s.waiters.wake();
            }

            result
        })
    }

    /// Wait for the condition of the state `S` to become true.
    pub fn wait<F, R>(&self, f: F) -> MultiSignalWait<'_, S, M, F>
    where
        F: FnMut(&mut S) -> Option<R>,
    {
        MultiSignalWait {
            signal: self,
            f,
            node: Node::new(),
            linked: false,
        }
    }

    #[inline(never)]
    fn unregister(&self, node: NonNull<Node>, linked: &mut bool) {
        self.inner
            .lock(|s| unsafe { s.borrow_mut().waiters.unregister(node, linked) });
    }
}

impl<T, M> MultiSignal<Option<T>, M>
where
    M: RawMutex,
{
    /// Notify the waiters.
    pub fn signal(&self, value: T) {
        self.modify(|state| {
            *state = Some(value);
            (true, ())
        });
    }

    /// Wait for the notification. Only one of the waiters gets it.
    pub async fn wait_signalled(&self) -> T {
        self.wait(|state| state.take()).await
    }
}

/// The future returned by [`MultiSignal::wait`].
pub struct MultiSignalWait<'a, S, M, F>
where
    M: RawMutex,
{
    signal: &'a MultiSignal<S, M>,
    f: F,
    node: Node,
    // Only this future links and unlinks `node`, so it knows without the lock
    linked: bool,
}

impl<S, M, F, R> Future for MultiSignalWait<'_, S, M, F>
where
    M: RawMutex,
    F: FnMut(&mut S) -> Option<R>,
{
    type Output = R;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<R> {
        // Safety: nothing is moved out of `self`, so `node` stays where it is
        let this = unsafe { self.get_unchecked_mut() };
        let signal = this.signal;
        let node = NonNull::from(&this.node);

        signal.inner.lock(|s| {
            let s = &mut *s.borrow_mut();

            if let Some(result) = (this.f)(&mut s.state) {
                unsafe { s.waiters.unregister(node, &mut this.linked) };

                Poll::Ready(result)
            } else {
                // Safety: this future is pinned, and `drop` unlinks `node`
                unsafe { s.waiters.register(node, &mut this.linked, ctx.waker()) };

                Poll::Pending
            }
        })
    }
}

impl<S, M, F> Drop for MultiSignalWait<'_, S, M, F>
where
    M: RawMutex,
{
    fn drop(&mut self) {
        if self.linked {
            // If unlinking panics, `node` stays linked after this future is gone,
            // so the panic must not unwind
            let abort = AbortOnUnwind;

            self.signal
                .unregister(NonNull::from(&self.node), &mut self.linked);

            core::mem::forget(abort);
        }
    }
}

/// Turns a panic into an abort: it is dropped only while unwinding, and a panic
/// while unwinding aborts.
struct AbortOnUnwind;

impl Drop for AbortOnUnwind {
    fn drop(&mut self) {
        panic!("Unlinking a waiter panicked");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use core::future::Future;
    use core::mem::ManuallyDrop;
    use core::pin::pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use std::boxed::Box;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::Wake;
    use std::vec::Vec;

    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    use crate::sync::blocking::raw::StdRawMutex;

    use super::MultiSignal;

    struct Counter(AtomicUsize);

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn waker() -> (Waker, Arc<Counter>) {
        let counter = Arc::new(Counter(AtomicUsize::new(0)));

        (Waker::from(counter.clone()), counter)
    }

    fn count(counter: &Counter) -> usize {
        counter.0.load(Ordering::SeqCst)
    }

    fn set(signal: &MultiSignal<u32, NoopRawMutex>, value: u32) {
        signal.modify(|v| {
            *v = value;
            (true, ())
        });
    }

    #[test]
    fn waiters_with_different_wakers() {
        let signal = MultiSignal::<u32, NoopRawMutex>::new(0);

        let (wa, ca) = waker();
        let (wb, cb) = waker();
        let mut cxa = Context::from_waker(&wa);
        let mut cxb = Context::from_waker(&wb);

        let mut a = pin!(signal.wait(|v| (*v >= 1).then_some(*v)));
        let mut b = pin!(signal.wait(|v| (*v >= 2).then_some(*v)));

        // The waiters do not wake each other when they register
        for _ in 0..3 {
            assert!(a.as_mut().poll(&mut cxa).is_pending());
            assert!(b.as_mut().poll(&mut cxb).is_pending());
        }
        assert_eq!((count(&ca), count(&cb)), (0, 0));

        set(&signal, 1);
        assert_eq!((count(&ca), count(&cb)), (1, 1));

        assert_eq!(a.as_mut().poll(&mut cxa), Poll::Ready(1));
        assert!(b.as_mut().poll(&mut cxb).is_pending());

        // `a` is done and unlinked, so only `b` is woken
        set(&signal, 2);
        assert_eq!((count(&ca), count(&cb)), (1, 2));
        assert_eq!(b.as_mut().poll(&mut cxb), Poll::Ready(2));
    }

    #[test]
    fn dropped_waiters_are_unlinked() {
        let signal = MultiSignal::<u32, NoopRawMutex>::new(0);

        let wakers: Vec<_> = (0..4).map(|_| waker()).collect();
        let mut futs: Vec<_> = (0..4)
            .map(|_| Box::pin(signal.wait(|v| (*v >= 10).then_some(()))))
            .collect();

        for (fut, (w, _)) in futs.iter_mut().zip(&wakers) {
            assert!(fut.as_mut().poll(&mut Context::from_waker(w)).is_pending());
        }

        // The middle, the head (linked last) and the tail (linked first)
        drop(futs.remove(2));
        drop(futs.pop());
        drop(futs.remove(0));

        set(&signal, 1);

        let counts: Vec<_> = wakers.iter().map(|(_, c)| count(c)).collect();
        assert_eq!(counts, [0, 1, 0, 0]);

        drop(futs);

        set(&signal, 2);
        assert_eq!(count(&wakers[1].1), 1);
    }

    #[test]
    fn waker_is_replaced() {
        let signal = MultiSignal::<u32, NoopRawMutex>::new(0);

        let (w1, c1) = waker();
        let (w2, c2) = waker();

        let mut fut = pin!(signal.wait(|v| (*v >= 1).then_some(())));
        assert!(fut
            .as_mut()
            .poll(&mut Context::from_waker(&w1))
            .is_pending());
        assert!(fut
            .as_mut()
            .poll(&mut Context::from_waker(&w2))
            .is_pending());

        set(&signal, 1);
        assert_eq!((count(&c1), count(&c2)), (0, 1));
    }

    #[test]
    fn forgotten_waiters() {
        let signal = MultiSignal::<u32, NoopRawMutex>::new(0);

        // Not polled, so not linked
        core::mem::forget(signal.wait(|v| (*v >= 1).then_some(())));

        // A pinned box that is never dropped keeps its memory, so the node stays valid
        let mut leaked = ManuallyDrop::new(Box::pin(signal.wait(|v| (*v >= 2).then_some(()))));
        assert!(leaked
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());

        set(&signal, 1);

        // Only for the leak check of Miri
        drop(ManuallyDrop::into_inner(leaked));
    }

    #[test]
    #[should_panic(expected = "already mutably borrowed")]
    fn reentrant_lock_panics() {
        // A waker that locks the signal again from inside `modify`, which the reentrant
        // `NoopRawMutex` allows; the `RefCell` turns it into a panic
        fn raw_waker(signal: *const ()) -> RawWaker {
            fn clone(signal: *const ()) -> RawWaker {
                raw_waker(signal)
            }

            fn wake(signal: *const ()) {
                let signal = unsafe { &*(signal as *const MultiSignal<u32, NoopRawMutex>) };

                signal.access(|_| ());
            }

            fn drop(_: *const ()) {}

            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, drop);

            RawWaker::new(signal, &VTABLE)
        }

        let signal = MultiSignal::<u32, NoopRawMutex>::new(0);

        let waker = unsafe { Waker::from_raw(raw_waker(&signal as *const _ as *const ())) };

        let mut fut = pin!(signal.wait(|v| (*v >= 1).then_some(())));
        assert!(fut
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending());

        set(&signal, 1);
    }

    #[test]
    fn signal_and_wait_signalled() {
        let signal = MultiSignal::<Option<u32>, NoopRawMutex>::new(None);

        futures_lite::future::block_on(async {
            let (value, ()) = futures_lite::future::zip(signal.wait_signalled(), async {
                signal.signal(7);
            })
            .await;

            assert_eq!(value, 7);
        });

        assert_eq!(signal.access(|v| *v), None);
    }

    #[test]
    fn threads() {
        const THREADS: usize = 4;
        const STEPS: u32 = if cfg!(miri) { 20 } else { 1000 };

        let signal = MultiSignal::<u32, StdRawMutex>::new(0);

        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    futures_lite::future::block_on(async {
                        // Wait for each step, with a cancelled wait before each one
                        for step in 1..=STEPS {
                            let mut cancelled = pin!(signal.wait(|v| (*v > STEPS).then_some(())));
                            let _ = futures_lite::future::poll_once(cancelled.as_mut()).await;

                            signal.wait(|v| (*v >= step).then_some(())).await;
                        }
                    })
                });
            }

            for _ in 0..STEPS {
                signal.modify(|v| {
                    *v += 1;
                    (true, ())
                });
                std::thread::yield_now();
            }
        });

        assert_eq!(signal.access(|v| *v), STEPS);
    }

    #[test]
    fn wait_is_send() {
        fn assert_send<T: Send>(_: &T) {}

        let signal = MultiSignal::<u32, StdRawMutex>::new(0);

        assert_send(&signal.wait(|v| (*v >= 1).then_some(())));
    }
}
