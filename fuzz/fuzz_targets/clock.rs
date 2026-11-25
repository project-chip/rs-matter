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

//! The time driver of `embassy-time` for the targets: a clock that moves only when the
//! target moves it. A run then does the same each time, and its input decides when the
//! timers fire.

use core::cell::Cell;
use core::task::Waker;

use embassy_time_driver::{Driver, TICK_HZ};

use rs_matter::utils::sync::blocking::raw::StdRawMutex;
use rs_matter::utils::sync::blocking::Mutex;

/// The most times that the clock stops on the way when it moves on once, and in a run.
/// They bound how long a run takes, as a timer that fires again and again, such as for
/// a simulated sensor, would make the clock stop at each of its times.
const MAX_STOPS: usize = 64;
const MAX_RUN_STOPS: usize = 512;

#[derive(Clone, Copy)]
struct State {
    /// The time, in ticks.
    now: u64,
    /// The earliest time that a timer waits for, since the last stop.
    wake_at: Option<u64>,
    /// How many more times the clock may stop in the run.
    stops: usize,
}

impl State {
    const fn new() -> Self {
        Self {
            now: 0,
            wake_at: None,
            stops: MAX_RUN_STOPS,
        }
    }
}

static STATE: Mutex<Cell<State>, StdRawMutex> = Mutex::new(Cell::new(State::new()));

struct Clock;

embassy_time_driver::time_driver_impl!(static CLOCK: Clock = Clock);

impl Driver for Clock {
    fn now(&self) -> u64 {
        STATE.lock(|state| state.get().now)
    }

    // Nothing to wake, as the targets poll until there is nothing left to do, and a timer
    // is ready when it is polled after its time. But the clock stops at that time, if it
    // is still to come.
    fn schedule_wake(&self, at: u64, _waker: &Waker) {
        STATE.lock(|state| {
            let mut s = state.get();
            if at > s.now {
                s.wake_at = Some(s.wake_at.map_or(at, |wake_at| wake_at.min(at)));
                state.set(s);
            }
        });
    }
}

/// Sets the clock back to 0, as for a device that has just started.
pub fn reset() {
    STATE.lock(|state| state.set(State::new()));
}

/// Moves the clock on by `ms` milliseconds. On the way, it stops at each time that a
/// timer waits for, up to `MAX_STOPS` times, so that `run` runs what is due then, as
/// time would pass for a device. Returns `false` as soon as `run` does.
pub fn advance(ms: u64, mut run: impl FnMut() -> bool) -> bool {
    let until = STATE.lock(|state| state.get().now) + ms * TICK_HZ / 1000;

    for _ in 0..MAX_STOPS {
        // The timers that `run` polls and that are still waiting ask again
        let stop = STATE.lock(|state| {
            let mut s = state.get();
            let stop = s.wake_at.take().filter(|at| *at <= until && s.stops > 0);
            if let Some(at) = stop {
                s.now = s.now.max(at);
                s.stops -= 1;
            }
            state.set(s);
            stop
        });

        if stop.is_none() {
            break;
        }

        if !run() {
            return false;
        }
    }

    STATE.lock(|state| {
        let mut s = state.get();
        s.now = until;
        s.wake_at = None;
        state.set(s);
    });

    true
}
