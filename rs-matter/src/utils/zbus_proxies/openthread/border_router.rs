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

//! # D-Bus interface proxy for: `io.openthread.BorderRouter`
//!
//! Hand-written from the OpenThread sources at
//! <https://github.com/openthread/ot-br-posix/blob/main/src/dbus/server/introspect.xml>
//! and verified against a live `otbr-agent` via:
//!
//! ```text
//! busctl introspect io.openthread.BorderRouter.wpan0 \
//!     /io/openthread/BorderRouter/wpan0
//! ```
//!
//! Only the properties/methods needed today are proxied. The interface
//! exposes many more (`Scan`, `EnergyScan`, `Attach`, `Detach`,
//! `JoinerStart`, `FactoryReset`, etc.) — they can be added incrementally.

use zbus::proxy;

#[proxy(
    interface = "io.openthread.BorderRouter",
    default_service = "io.openthread.BorderRouter.wpan0",
    default_path = "/io/openthread/BorderRouter/wpan0"
)]
pub trait BorderRouter {
    /// Active Thread Operational Dataset, TLV-encoded.
    ///
    /// This is the same byte sequence `ot-ctl dataset active -x` emits
    /// (just unhexed). Roughly 100–110 bytes for a typical dataset.
    ///
    /// Returned when there's an active dataset; empty if the device is
    /// disabled/detached.
    #[zbus(property)]
    fn active_dataset_tlvs(&self) -> zbus::Result<Vec<u8>>;

    /// Set the active dataset (TLV-encoded). Triggers re-attach.
    #[zbus(property)]
    fn set_active_dataset_tlvs(&self, value: Vec<u8>) -> zbus::Result<()>;

    /// Pending Thread Operational Dataset, TLV-encoded.
    ///
    /// Used for coordinated dataset rotations. Empty if no pending change.
    #[zbus(property)]
    fn pending_dataset_tlvs(&self) -> zbus::Result<Vec<u8>>;

    /// Device role on the Thread network. One of:
    /// `"disabled" | "detached" | "child" | "router" | "leader"`.
    #[zbus(property)]
    fn device_role(&self) -> zbus::Result<String>;

    /// 64-bit IEEE EUI-64 of the Thread radio, as a hex string.
    #[zbus(property)]
    fn eui64(&self) -> zbus::Result<String>;

    /// Currently-active Thread channel (11-26 for 2.4 GHz).
    #[zbus(property)]
    fn channel(&self) -> zbus::Result<u16>;
}
