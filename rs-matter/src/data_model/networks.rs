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

//! A module containing various types for managing Ethernet, Thread and Wifi networks.

pub mod eth;
#[cfg(all(unix, feature = "os", not(target_os = "espidf")))]
pub mod unix;
pub mod wireless;

/// A generic trait for network change notifications.
pub trait NetChangeNotif {
    /// Wait until a change occurs.
    async fn wait_changed(&self);
}

impl<T> NetChangeNotif for &T
where
    T: NetChangeNotif,
{
    async fn wait_changed(&self) {
        (*self).wait_changed().await
    }
}
