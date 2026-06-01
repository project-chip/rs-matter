/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! zbus proxies for OpenThread Border Router (`otbr-agent`).
//!
//! OTBR exposes a per-Thread-interface D-Bus service named
//! `io.openthread.BorderRouter.<ifname>` (typically `io.openthread.BorderRouter.wpan0`)
//! under the well-known object path `/io/openthread/BorderRouter/<ifname>`.
//!
//! The full interface is defined in `openthread/src/posix/platform/dbus/` and
//! documented at <https://github.com/openthread/ot-br-posix>.

pub mod border_router;
