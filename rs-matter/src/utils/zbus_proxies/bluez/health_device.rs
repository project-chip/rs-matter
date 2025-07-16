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

//! # D-Bus interface proxy for: `org.bluez.HealthDevice1`

use zbus::{
    proxy,
    zvariant::{ObjectPath, OwnedObjectPath},
};

#[proxy(interface = "org.bluez.HealthDevice1", assume_defaults = true)]
pub trait HealthDevice {
    /// ChannelConnected method
    fn channel_connected(&self, channel: &ObjectPath<'_>) -> zbus::Result<()>;

    /// ChannelDeleted method
    fn channel_deleted(&self, channel: &ObjectPath<'_>) -> zbus::Result<()>;

    /// CreateChannel method
    fn create_channel(
        &self,
        application: &ObjectPath<'_>,
        configuration: &str,
    ) -> zbus::Result<OwnedObjectPath>;

    /// DestroyChannel method
    fn destroy_channel(&self, channel: &ObjectPath<'_>) -> zbus::Result<()>;

    /// Echo method
    fn echo(&self) -> zbus::Result<bool>;
}
