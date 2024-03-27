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

use core::future::Future;

use embassy_futures::{
    join::{Join, Join3, Join4, Join5},
    select::{Either, Either3, Either4, Select, Select3, Select4},
};

/// A trait for coalescing the outputs of `embassy_futures::Select*` and `embassy_futures::Join*` futures.
///
/// - The outputs of the `embassy_futures::Select*` future can be coalesced only
///   if all legs of the `Select*` future return the same type
///
/// - The outputs of the `embassy_futures::Join*` future can be coalesced only if
///   all legs of the `Join*` future return `Result<(), T>` where T is the same error type.
///   Note that in the case when multiple legs of the `Join*` future resulted in an error,
///   only the error of the leftmost leg is returned, while the others are discarded.
pub trait Coalesce<T> {
    fn coalesce(self) -> impl Future<Output = T>;
}

impl<T, F1, F2> Coalesce<T> for Select<F1, F2>
where
    F1: Future<Output = T>,
    F2: Future<Output = T>,
{
    async fn coalesce(self) -> T {
        match self.await {
            Either::First(t) => t,
            Either::Second(t) => t,
        }
    }
}

impl<T, F1, F2, F3> Coalesce<T> for Select3<F1, F2, F3>
where
    F1: Future<Output = T>,
    F2: Future<Output = T>,
    F3: Future<Output = T>,
{
    async fn coalesce(self) -> T {
        match self.await {
            Either3::First(t) => t,
            Either3::Second(t) => t,
            Either3::Third(t) => t,
        }
    }
}

impl<T, F1, F2, F3, F4> Coalesce<T> for Select4<F1, F2, F3, F4>
where
    F1: Future<Output = T>,
    F2: Future<Output = T>,
    F3: Future<Output = T>,
    F4: Future<Output = T>,
{
    async fn coalesce(self) -> T {
        match self.await {
            Either4::First(t) => t,
            Either4::Second(t) => t,
            Either4::Third(t) => t,
            Either4::Fourth(t) => t,
        }
    }
}

impl<T, F1, F2> Coalesce<Result<(), T>> for Join<F1, F2>
where
    F1: Future<Output = Result<(), T>>,
    F2: Future<Output = Result<(), T>>,
{
    async fn coalesce(self) -> Result<(), T> {
        match self.await {
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(e),
            _ => Ok(()),
        }
    }
}

impl<T, F1, F2, F3> Coalesce<Result<(), T>> for Join3<F1, F2, F3>
where
    F1: Future<Output = Result<(), T>>,
    F2: Future<Output = Result<(), T>>,
    F3: Future<Output = Result<(), T>>,
{
    async fn coalesce(self) -> Result<(), T> {
        match self.await {
            (Err(e), _, _) => Err(e),
            (_, Err(e), _) => Err(e),
            (_, _, Err(e)) => Err(e),
            _ => Ok(()),
        }
    }
}

impl<T, F1, F2, F3, F4> Coalesce<Result<(), T>> for Join4<F1, F2, F3, F4>
where
    F1: Future<Output = Result<(), T>>,
    F2: Future<Output = Result<(), T>>,
    F3: Future<Output = Result<(), T>>,
    F4: Future<Output = Result<(), T>>,
{
    async fn coalesce(self) -> Result<(), T> {
        match self.await {
            (Err(e), _, _, _) => Err(e),
            (_, Err(e), _, _) => Err(e),
            (_, _, Err(e), _) => Err(e),
            (_, _, _, Err(e)) => Err(e),
            _ => Ok(()),
        }
    }
}

impl<T, F1, F2, F3, F4, F5> Coalesce<Result<(), T>> for Join5<F1, F2, F3, F4, F5>
where
    F1: Future<Output = Result<(), T>>,
    F2: Future<Output = Result<(), T>>,
    F3: Future<Output = Result<(), T>>,
    F4: Future<Output = Result<(), T>>,
    F5: Future<Output = Result<(), T>>,
{
    async fn coalesce(self) -> Result<(), T> {
        match self.await {
            (Err(e), _, _, _, _) => Err(e),
            (_, Err(e), _, _, _) => Err(e),
            (_, _, Err(e), _, _) => Err(e),
            (_, _, _, Err(e), _) => Err(e),
            (_, _, _, _, Err(e)) => Err(e),
            _ => Ok(()),
        }
    }
}
