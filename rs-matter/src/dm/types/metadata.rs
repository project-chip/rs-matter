/*
 *
 *    Copyright (c) 2023-2026 Project CHIP Authors
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

use crate::dm::Node;

use super::Async;

/// A trait for types that can provide access to a `Node` for the purpose of metadata retrieval.
pub trait Metadata {
    /// Access the `Node` associated with this metadata provider.
    ///
    /// # Arguments
    /// - `f`: A closure that takes a reference to a `Node` and returns a value of type `R`.
    fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Node<'_>) -> R;
}

impl<T> Metadata for &T
where
    T: Metadata,
{
    fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Node<'_>) -> R,
    {
        (**self).access(f)
    }
}

impl Metadata for Node<'_> {
    fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Node<'_>) -> R,
    {
        f(self)
    }
}

impl<M, H> Metadata for (M, H)
where
    M: Metadata,
{
    fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Node<'_>) -> R,
    {
        self.0.access(f)
    }
}

impl<T> Metadata for Async<T>
where
    T: Metadata,
{
    fn access<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Node<'_>) -> R,
    {
        self.0.access(f)
    }
}
