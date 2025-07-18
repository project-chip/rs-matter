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

//! # D-Bus interface proxy for: `org.bluez.Media1`

use std::collections::HashMap;

use zbus::{
    proxy,
    zvariant::{ObjectPath, Value},
};

#[proxy(interface = "org.bluez.Media1", default_service = "org.bluez")]
pub trait Media {
    /// RegisterApplication method
    fn register_application(
        &self,
        application: &ObjectPath<'_>,
        options: HashMap<&str, &Value<'_>>,
    ) -> zbus::Result<()>;

    /// RegisterEndpoint method
    fn register_endpoint(
        &self,
        endpoint: &ObjectPath<'_>,
        properties: HashMap<&str, &Value<'_>>,
    ) -> zbus::Result<()>;

    /// RegisterPlayer method
    fn register_player(
        &self,
        player: &ObjectPath<'_>,
        properties: HashMap<&str, &Value<'_>>,
    ) -> zbus::Result<()>;

    /// UnregisterApplication method
    fn unregister_application(&self, application: &ObjectPath<'_>) -> zbus::Result<()>;

    /// UnregisterEndpoint method
    fn unregister_endpoint(&self, endpoint: &ObjectPath<'_>) -> zbus::Result<()>;

    /// UnregisterPlayer method
    fn unregister_player(&self, player: &ObjectPath<'_>) -> zbus::Result<()>;

    /// SupportedUUIDs property
    #[zbus(property, name = "SupportedUUIDs")]
    fn supported_uuids(&self) -> zbus::Result<Vec<String>>;
}
