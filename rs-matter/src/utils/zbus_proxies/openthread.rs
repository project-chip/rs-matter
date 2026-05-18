/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 */

//! zbus proxies for OpenThread Border Router (`otbr-agent`).
//!
//! OTBR exposes a per-Thread-interface D-Bus service named
//! `io.openthread.BorderRouter.<ifname>` (typically `io.openthread.BorderRouter.wpan0`)
//! under the well-known object path `/io/openthread/BorderRouter/<ifname>`.
//!
//! The full interface is defined in `openthread/src/posix/platform/dbus/` and
//! documented at <https://github.com/openthread/ot-br-posix>. We only proxy
//! the surface needed by the controller today; more methods can be added
//! incrementally without disturbing this module's existing users.

pub mod border_router;
