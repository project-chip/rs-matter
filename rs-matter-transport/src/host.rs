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

//! What the transport needs from the node it runs in.

use crate::basic_info::BasicInfoConfig;
use crate::error::Error;
use crate::fabric::Fabrics;
#[cfg(feature = "groups")]
use crate::groupcast::TestingBridge;
use crate::icd::IcdAdvertisement;
use crate::network::MatterLocalService;
use crate::session::Sessions;
use crate::utils::sync::MaybeSendSync;
use crate::Transport;

/// What the transport needs from the node it runs in, besides its own state:
/// the fabrics, to decode group messages and to join their multicast groups, and
/// what mDNS advertises.
///
/// `Matter` implements it. A `dyn` is enough, as the only method used per message
/// is [`Self::with_fabrics`], and that only for group messages.
pub trait TransportHost: MaybeSendSync {
    /// The transport of the node.
    fn transport(&self) -> &Transport;

    /// Run `f` with the sessions of the transport locked, and with the fabrics of
    /// the node.
    ///
    /// Must not be called with the sessions locked already.
    fn with_fabrics(&self, f: &mut dyn FnMut(&mut Sessions, &Fabrics));

    /// Call `f` with each Matter mDNS service the node publishes.
    fn mdns_services(
        &self,
        f: &mut dyn FnMut(MatterLocalService) -> Result<(), Error>,
    ) -> Result<(), Error>;

    /// The basic information configuration of the node.
    fn dev_det(&self) -> &BasicInfoConfig<'_>;

    /// The port on which the node listens.
    fn port(&self) -> u16;

    /// What the node advertises as an ICD, or `None` when it is not one.
    fn icd_advertisement(&self) -> Option<IcdAdvertisement>;

    /// The Groupcast testing-mode bridge.
    #[cfg(feature = "groups")]
    fn groupcast_testing(&self) -> &TestingBridge;
}
