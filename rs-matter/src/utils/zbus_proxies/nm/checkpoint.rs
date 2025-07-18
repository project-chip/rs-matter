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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Checkpoint`

use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;

#[proxy(
    interface = "org.freedesktop.NetworkManager.Checkpoint",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Checkpoint {
    /// Devices property
    #[zbus(property)]
    fn devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Created property
    #[zbus(property)]
    fn created(&self) -> zbus::Result<i64>;

    /// RollbackTimeout property
    #[zbus(property)]
    fn rollback_timeout(&self) -> zbus::Result<u32>;
}
