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

/// An extension trait for `Iterator` implementing several utility methods.
pub trait TryFindIterator<T, E>: Iterator<Item = Result<T, E>> + Sized {
    /// Find the first element that satisfies the supplied `predicate`.
    ///
    /// Method name is `do_try_find` to avoid collissions with `Iterator::try_find`
    /// once it gets stabilized.
    fn do_try_find<P>(self, mut predicate: P) -> Result<Option<T>, E>
    where
        P: FnMut(&T) -> Result<bool, E>,
    {
        for val in self {
            let val = val?;

            let result = predicate(&val);
            match result {
                Ok(matches) => {
                    if matches {
                        return Ok(Some(val));
                    }
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        Ok(None)
    }
}

impl<T, I, E> TryFindIterator<T, E> for I where I: Iterator<Item = Result<T, E>> {}
