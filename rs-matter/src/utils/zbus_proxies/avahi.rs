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

//! zbus proxies for `org.freedesktop.resolve1`.
//!
//! All proxy traits are generated using introspection (i.e. `zbus-xmlgen file ...`),
//! with introspection (.xml) files as available here (circa 2025-07-15):
//! https://github.com/avahi/avahi/tree/master/avahi-daemon

pub mod address_resolver;
pub mod domain_browser;
pub mod entry_group;
pub mod host_name_resolver;
pub mod record_browser;
pub mod server;
pub mod server2;
pub mod service_browser;
pub mod service_resolver;
pub mod service_type_browser;
