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

use rs_matter_pairing::DiscoveryCapabilities;
use rs_matter_utils::init::{init_from_closure, Init};
use rs_matter_utils::sync::MaybeSendSync;

use crate::private::Sealed;

/// User data that can be embedded in the stack network
pub trait Embedding: MaybeSendSync {
    const INIT: Self;

    fn init() -> impl Init<Self>;
}

impl Embedding for () {
    const INIT: Self = ();

    fn init() -> impl Init<Self> {
        unsafe { init_from_closure(|_| Ok(())) }
    }
}

/// A trait modeling a specific network type.
/// `MatterStack` is parameterized by a network type implementing this trait.
///
/// The trait is sealed and has only two implementations: `Eth` and `WirelessBle`.
pub trait Network: Sealed + MaybeSendSync {
    const INIT: Self;

    /// Optional additional state embedded in the network state
    type Embedding<'a>: Embedding
    where
        Self: 'a;

    /// Return an in-place initializer for the network type.
    fn init() -> impl Init<Self>;

    /// Return the discovery capabilities of this network when commissioning the device.
    fn discovery_capabilities(&self) -> DiscoveryCapabilities;

    /// Return a reference to the embedded user data.
    fn embedding(&self) -> &Self::Embedding<'_>;
}
