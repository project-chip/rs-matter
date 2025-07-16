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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device.Statistics`

use zbus::proxy;

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.Statistics",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Statistics {
    /// RefreshRateMs property
    #[zbus(property)]
    fn refresh_rate_ms(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn set_refresh_rate_ms(&self, value: u32) -> zbus::Result<()>;

    /// RxBytes property
    #[zbus(property)]
    fn rx_bytes(&self) -> zbus::Result<u64>;

    /// TxBytes property
    #[zbus(property)]
    fn tx_bytes(&self) -> zbus::Result<u64>;
}
