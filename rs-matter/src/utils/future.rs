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

use core::future::{poll_fn, Future};
use core::task::Poll;

/// Create a future that will call the provided closure when polled, allowing for delayed computation of the "ready" value.
#[inline(always)]
pub fn delayed_ready<F, O>(f: F) -> impl Future<Output = O>
where
    F: FnOnce() -> O,
{
    let mut f = Some(f);

    poll_fn(move |_| {
        if let Some(f) = f.take() {
            Poll::Ready(f())
        } else {
            panic!("delayed_ready polled after completion");
        }
    })
}
