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

//! # D-Bus interface proxy for: `org.bluez.Agent1`

use zbus::{proxy, zvariant::ObjectPath};

#[proxy(interface = "org.bluez.Agent1", assume_defaults = true)]
pub trait Agent {
    /// AuthorizeService method
    fn authorize_service(&self, device: &ObjectPath<'_>, uuid: &str) -> zbus::Result<()>;

    /// Cancel method
    fn cancel(&self) -> zbus::Result<()>;

    /// DisplayPinCode method
    fn display_pin_code(&self, device: &ObjectPath<'_>, pincode: &str) -> zbus::Result<()>;

    /// Release method
    fn release(&self) -> zbus::Result<()>;

    /// RequestAuthorization method
    fn request_authorization(&self, device: &ObjectPath<'_>) -> zbus::Result<()>;

    /// RequestConfirmation method
    fn request_confirmation(&self, device: &ObjectPath<'_>) -> zbus::Result<()>;

    /// RequestPasskey method
    fn request_passkey(&self, device: &ObjectPath<'_>) -> zbus::Result<()>;

    /// RequestPinCode method
    fn request_pin_code(&self, device: &ObjectPath<'_>) -> zbus::Result<String>;
}
