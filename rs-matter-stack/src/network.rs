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

use rs_matter_dm::clusters::net_comm::{NetworkType, Networks};
use rs_matter_dm::networks::any::AnyNetworks;
use rs_matter_dm::networks::eth::EthNetwork;
use rs_matter_dm::networks::wireless::{
    ThreadNetworks, WifiNetworks, WirelessNetwork, WirelessNetworks,
};
use rs_matter_utils::init::{init_from_closure, Init};
use rs_matter_utils::sync::MaybeSendSync;

/// Data the stack holds: user data, the networks store, and the memory the drivers of the
/// platform need.
pub trait Embedding: MaybeSendSync {
    const INIT: Self;

    fn init() -> impl Init<Self>;
}

/// The network of a `MatterStack`: the networks store of its operational network interface,
/// and the memory the drivers of the platform need, which the stack holds for them.
///
/// The networks stores (`EthNetwork`, `WifiNetworks`, `ThreadNetworks` and `AnyNetworks`)
/// are stack networks themselves, with no memory for the drivers. Platform crates pair a
/// store with the memory of their drivers in types of their own.
///
/// Which run methods a stack has depends on which of `EthStackNetwork`, `WifiStackNetwork`,
/// `ThreadStackNetwork` and `AnyStackNetwork` its network implements, so that e.g. a stack
/// with a Thread store cannot run Wifi.
pub trait StackNetwork {
    /// The networks store of the operational network interface.
    type Store: Networks + Embedding;
    /// The memory the drivers of the platform need.
    type Context: Embedding;
}

/// A `StackNetwork` for Ethernet, which the stack runs with `run_eth`.
pub trait EthStackNetwork: StackNetwork {}

/// A `StackNetwork` for Wifi, which the stack runs with `run_wifi`, `run_wifi_no_coex` and
/// `run_wifi_oper`.
pub trait WifiStackNetwork: StackNetwork {}

/// A `StackNetwork` for Thread, which the stack runs with `run_thread`, `run_thread_no_coex`
/// and `run_thread_oper`.
pub trait ThreadStackNetwork: StackNetwork {}

/// A `StackNetwork` for Ethernet, Wifi or Thread, whichever the node picks at runtime, which
/// the stack runs with `run`, `run_no_coex` and `run_oper`.
pub trait AnyStackNetwork: StackNetwork {}

impl Embedding for () {
    const INIT: Self = ();

    fn init() -> impl Init<Self> {
        unsafe { init_from_closure(|_| Ok(())) }
    }
}

impl<const N: usize, T> Embedding for WirelessNetworks<N, T>
where
    T: WirelessNetwork + MaybeSendSync,
{
    const INIT: Self = Self::new();

    fn init() -> impl Init<Self> {
        WirelessNetworks::init()
    }
}

impl<const N: usize, T> StackNetwork for WirelessNetworks<N, T>
where
    T: WirelessNetwork + MaybeSendSync,
{
    type Store = Self;
    type Context = ();
}

impl<const N: usize> WifiStackNetwork for WifiNetworks<N> {}

impl<const N: usize> ThreadStackNetwork for ThreadNetworks<N> {}

impl Embedding for EthNetwork<'static> {
    const INIT: Self = Self::new_default();

    fn init() -> impl Init<Self> {
        unsafe {
            init_from_closure(|slot: *mut Self| {
                slot.write(Self::INIT);
                Ok(())
            })
        }
    }
}

impl StackNetwork for EthNetwork<'static> {
    type Store = Self;
    type Context = ();
}

impl EthStackNetwork for EthNetwork<'static> {}

/// An `AnyNetworks` store starts out as a Thread one; tell it its network with
/// `MatterStack::networks` before the stack runs.
impl<const N: usize> Embedding for AnyNetworks<N> {
    const INIT: Self = Self::new(NetworkType::Thread);

    fn init() -> impl Init<Self> {
        AnyNetworks::init(NetworkType::Thread)
    }
}

impl<const N: usize> StackNetwork for AnyNetworks<N> {
    type Store = Self;
    type Context = ();
}

impl<const N: usize> AnyStackNetwork for AnyNetworks<N> {}
