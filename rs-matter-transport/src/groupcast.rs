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

//! The Groupcast testing mode: the observations of the transport and the
//! Interaction Model, collected for the Groupcast cluster handler, which turns
//! them into `GroupcastTesting` events.

use core::num::NonZeroU8;

use crate::dm::EndptId;
use crate::fabric::{Fabrics, MulticastAddrPolicy};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;
use crate::utils::timers::Instant;

/// Max buffered testing observations; when full, new observations are
/// dropped (the CHIP test harness tolerates missing duplicates - it re-sends
/// and de-duplicates).
const MAX_PENDING_OBSERVATIONS: usize = 4;

/// A `GroupcastTesting` test operation that can be armed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TestingOperation {
    /// Listener testing: the reception of group messages is observed.
    Listener,
    /// Sender testing: the sending of group messages is observed.
    Sender,
}

/// The result of a `GroupcastTesting` observation.
///
/// The variants are the ones of the Groupcast cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TestResult {
    Success,
    GeneralError,
    MessageReplay,
    FailedAuth,
    NoAvailableKey,
    SendFailure,
}

/// The state of an ongoing `GroupcastTesting` test session.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestingMode {
    /// The fabric that armed the testing mode (`FabricUnderTest`).
    pub fab_idx: NonZeroU8,
    /// The test operation being executed.
    pub operation: TestingOperation,
    /// When the testing mode auto-expires.
    pub deadline: Instant,
}

/// A `GroupcastTesting` diagnostic observation, recorded at the place where
/// it happens (the transport's group-message RX path, the Interaction
/// Model's group-invoke processing) and turned into a `GroupcastTesting`
/// *event* by the `run` of the Groupcast cluster handler - the recording sites have no access
/// to the Interaction Model's event machinery.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestingObservation {
    pub src_ip: Option<[u8; 16]>,
    pub dst_ip: Option<[u8; 16]>,
    pub group_id: Option<u16>,
    pub endpoint_id: Option<EndptId>,
    pub cluster_id: Option<u32>,
    pub element_id: Option<u32>,
    pub access_allowed: Option<bool>,
    pub result: TestResult,
}

impl TestingObservation {
    /// The IPv6 octets of the multicast address the given group uses, for the
    /// `GroupcastTesting` event's `DestinationIpAddress` field.
    ///
    /// The transport does not surface the actual UDP destination address of a
    /// received datagram, so it is reconstructed from the group's multicast
    /// address policy; for an unknown group (e.g. the no-key-available case) the
    /// IANA-assigned address is assumed, as `IanaAddr` is the default policy.
    pub fn group_dst_ip(fabrics: &Fabrics, fab_idx: NonZeroU8, group_id: u16) -> [u8; 16] {
        fabrics
            .get(fab_idx)
            .and_then(|fabric| {
                fabric
                    .groups()
                    .get(group_id)
                    .map(|entry| match entry.effective_mcast_policy() {
                        MulticastAddrPolicy::IanaAddr => {
                            crate::utils::ipv6::IANA_GROUPCAST_MULTICAST_ADDR.octets()
                        }
                        MulticastAddrPolicy::PerGroup => {
                            crate::utils::ipv6::compute_group_multicast_addr(
                                fabric.fabric_id(),
                                group_id,
                            )
                            .octets()
                        }
                    })
            })
            .unwrap_or(crate::utils::ipv6::IANA_GROUPCAST_MULTICAST_ADDR.octets())
    }

    /// The IPv6 octets of a transport [`Address`], for the `GroupcastTesting`
    /// event's `SourceIpAddress` field (IPv4 addresses are V4-mapped).
    pub fn addr_ip(addr: &crate::network::Address) -> Option<[u8; 16]> {
        let crate::network::Address::Udp(addr) = addr else {
            return None;
        };

        Some(match addr.ip() {
            core::net::IpAddr::V6(ip) => ip.octets(),
            core::net::IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        })
    }
}

struct TestingBridgeState {
    mode: Option<TestingMode>,
    pending: Vec<TestingObservation, MAX_PENDING_OBSERVATIONS>,
}

impl TestingBridgeState {
    const fn new() -> Self {
        Self {
            mode: None,
            pending: Vec::new(),
        }
    }

    fn init() -> impl Init<Self> {
        init!(Self {
            mode: None,
            pending <- Vec::init(),
        })
    }
}

/// The bridge between the places that *observe* Groupcast test conditions
/// (the transport RX path, the Interaction Model's invoke processing, the
/// `GroupcastTesting` command) and the Groupcast cluster handler, which owns the
/// `FabricUnderTest` reporting and the `GroupcastTesting` event emission.
///
/// Lives on `Matter` so that all three parties can reach it.
pub struct TestingBridge {
    state: Mutex<RefCell<TestingBridgeState>>,
    changed: Notification,
}

impl TestingBridge {
    /// Create a new bridge, with testing disabled.
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(TestingBridgeState::new())),
            changed: Notification::new(),
        }
    }

    /// Return an in-place initializer for `TestingBridge`
    pub fn init() -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(TestingBridgeState::init())),
            changed <- Notification::init(),
        })
    }

    /// Set (or clear) the testing mode; wakes the `run` of the Groupcast cluster handler.
    pub fn set_mode(&self, mode: Option<TestingMode>) {
        self.state.lock(|state| state.borrow_mut().mode = mode);
        self.changed.notify();
    }

    /// The current testing mode, if any (including one that has expired but
    /// has not been swept by the `run` of the Groupcast cluster handler yet - callers that
    /// care use [`Self::armed`]).
    pub fn mode(&self) -> Option<TestingMode> {
        self.state.lock(|state| state.borrow().mode)
    }

    /// The current *unexpired* testing mode arming the given operation, if
    /// any.
    pub fn armed(&self, operation: TestingOperation) -> Option<TestingMode> {
        self.mode()
            .filter(|mode| mode.operation == operation && Instant::now() < mode.deadline)
    }

    /// Record a testing observation (dropped when the buffer is full);
    /// wakes the `run` of the Groupcast cluster handler to turn it into an event.
    pub fn observe(&self, observation: TestingObservation) {
        self.state.lock(|state| {
            let _ = state.borrow_mut().pending.push(observation);
        });
        self.changed.notify();
    }

    /// Take the oldest pending observation, if any.
    pub fn pop(&self) -> Option<TestingObservation> {
        self.state.lock(|state| {
            let pending = &mut state.borrow_mut().pending;
            (!pending.is_empty()).then(|| pending.remove(0))
        })
    }

    /// Wait for a mode change or a new observation.
    pub async fn wait_changed(&self) {
        self.changed.wait().await
    }
}

impl Default for TestingBridge {
    fn default() -> Self {
        Self::new()
    }
}
