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

//! # D-Bus interface proxy for: `org.freedesktop.NetworkManager.Device.Macsec`

use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;

#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.Macsec",
    default_service = "org.freedesktop.NetworkManager"
)]
pub trait Macsec {
    /// Parent property
    #[zbus(property)]
    fn parent(&self) -> zbus::Result<OwnedObjectPath>;

    /// Sci property
    #[zbus(property)]
    fn sci(&self) -> zbus::Result<u64>;

    /// IcvLength property
    #[zbus(property)]
    fn icv_length(&self) -> zbus::Result<u8>;

    /// CipherSuite property
    #[zbus(property)]
    fn cipher_suite(&self) -> zbus::Result<u64>;

    /// Window property
    #[zbus(property)]
    fn window(&self) -> zbus::Result<u32>;

    /// EncodingSa property
    #[zbus(property)]
    fn encoding_sa(&self) -> zbus::Result<u8>;

    /// Validation property
    #[zbus(property)]
    fn validation(&self) -> zbus::Result<String>;

    /// Encrypt property
    #[zbus(property)]
    fn encrypt(&self) -> zbus::Result<bool>;

    /// Protect property
    #[zbus(property)]
    fn protect(&self) -> zbus::Result<bool>;

    /// IncludeSci property
    #[zbus(property)]
    fn include_sci(&self) -> zbus::Result<bool>;

    /// Es property
    #[zbus(property)]
    fn es(&self) -> zbus::Result<bool>;

    /// Scb property
    #[zbus(property)]
    fn scb(&self) -> zbus::Result<bool>;

    /// ReplayProtect property
    #[zbus(property)]
    fn replay_protect(&self) -> zbus::Result<bool>;
}
