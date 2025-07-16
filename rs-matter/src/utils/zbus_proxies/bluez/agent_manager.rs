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

//! # D-Bus interface proxy for: `org.bluez.AgentManager1`

use zbus::{proxy, zvariant::ObjectPath};

#[proxy(
    interface = "org.bluez.AgentManager1",
    default_service = "org.bluez",
    default_path = "/org/bluez"
)]
pub trait AgentManager {
    /// RegisterAgent method
    fn register_agent(&self, agent: &ObjectPath<'_>, capability: &str) -> zbus::Result<()>;

    /// RequestDefaultAgent method
    fn request_default_agent(&self, agent: &ObjectPath<'_>) -> zbus::Result<()>;

    /// UnregisterAgent method
    fn unregister_agent(&self, agent: &ObjectPath<'_>) -> zbus::Result<()>;
}
