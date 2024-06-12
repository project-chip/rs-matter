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

use core::{borrow::Borrow, cell::RefCell};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use crate::{
    acl::AclMgr,
    data_model::{
        cluster_basic_information::BasicInfoConfig,
        sdm::{dev_att::DevAttDataFetcher, failsafe::FailSafe},
    },
    error::*,
    fabric::FabricMgr,
    mdns::{Mdns, MdnsService},
    pairing::{print_pairing_code_and_qr, DiscoveryCapabilities},
    secure_channel::{pake::PaseMgr, spake2p::VerifierData},
    transport::{
        core::{PacketBufferExternalAccess, TransportMgr},
        network::{NetworkReceive, NetworkSend},
    },
    utils::{buf::BufferAccess, epoch::Epoch, notification::Notification, rand::Rand},
};

/* The Matter Port */
pub const MATTER_PORT: u16 = 5540;

/// Device Commissioning Data
#[derive(Debug, Clone)]
pub struct CommissioningData {
    /// The data like password or verifier that is required to authenticate
    pub verifier: VerifierData,
    /// The 12-bit discriminator used to differentiate between multiple devices
    pub discriminator: u16,
}

/// The primary Matter Object
pub struct Matter<'a> {
    pub(crate) fabric_mgr: RefCell<FabricMgr>,
    pub acl_mgr: RefCell<AclMgr>, // Public for tests
    pub(crate) pase_mgr: RefCell<PaseMgr>,
    pub(crate) failsafe: RefCell<FailSafe>,
    pub transport_mgr: TransportMgr<'a>, // Public for tests
    persist_notification: Notification<NoopRawMutex>,
    pub(crate) epoch: Epoch,
    pub(crate) rand: Rand,
    dev_det: &'a BasicInfoConfig<'a>,
    dev_att: &'a dyn DevAttDataFetcher,
    pub(crate) port: u16,
}

impl<'a> Matter<'a> {
    #[cfg(feature = "std")]
    #[inline(always)]
    pub const fn new_default(
        dev_det: &'a BasicInfoConfig<'a>,
        dev_att: &'a dyn DevAttDataFetcher,
        mdns: MdnsService<'a>,
        port: u16,
    ) -> Self {
        use crate::utils::epoch::sys_epoch;
        use crate::utils::rand::sys_rand;

        Self::new(dev_det, dev_att, mdns, sys_epoch, sys_rand, port)
    }

    /// Creates a new Matter object
    ///
    /// # Parameters
    /// * dev_att: An object that implements the trait [DevAttDataFetcher]. Any Matter device
    ///   requires a set of device attestation certificates and keys. It is the responsibility of
    ///   this object to return the device attestation details when queried upon.
    #[inline(always)]
    pub const fn new(
        dev_det: &'a BasicInfoConfig<'a>,
        dev_att: &'a dyn DevAttDataFetcher,
        mdns: MdnsService<'a>,
        epoch: Epoch,
        rand: Rand,
        port: u16,
    ) -> Self {
        Self {
            fabric_mgr: RefCell::new(FabricMgr::new()),
            acl_mgr: RefCell::new(AclMgr::new()),
            pase_mgr: RefCell::new(PaseMgr::new(epoch, rand)),
            failsafe: RefCell::new(FailSafe::new()),
            transport_mgr: TransportMgr::new(mdns.new_impl(dev_det, port), epoch, rand),
            persist_notification: Notification::new(),
            epoch,
            rand,
            dev_det,
            dev_att,
            port,
        }
    }

    pub fn initialize_transport_buffers(&self) -> Result<(), Error> {
        self.transport_mgr.initialize_buffers()
    }

    pub fn dev_det(&self) -> &BasicInfoConfig<'_> {
        self.dev_det
    }

    pub fn dev_att(&self) -> &dyn DevAttDataFetcher {
        self.dev_att
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn load_fabrics(&self, data: &[u8]) -> Result<(), Error> {
        self.fabric_mgr
            .borrow_mut()
            .load(data, &self.transport_mgr.mdns)
    }

    pub fn load_acls(&self, data: &[u8]) -> Result<(), Error> {
        self.acl_mgr.borrow_mut().load(data)
    }

    pub fn store_fabrics<'b>(&self, buf: &'b mut [u8]) -> Result<Option<&'b [u8]>, Error> {
        self.fabric_mgr.borrow_mut().store(buf)
    }

    pub fn store_acls<'b>(&self, buf: &'b mut [u8]) -> Result<Option<&'b [u8]>, Error> {
        self.acl_mgr.borrow_mut().store(buf)
    }

    pub fn is_changed(&self) -> bool {
        self.acl_mgr.borrow().is_changed() || self.fabric_mgr.borrow().is_changed()
    }

    fn start_comissioning(
        &self,
        dev_comm: CommissioningData,
        discovery_capabilities: DiscoveryCapabilities,
        buf: &mut [u8],
    ) -> Result<bool, Error> {
        if !self.pase_mgr.borrow().is_pase_session_enabled() && self.fabric_mgr.borrow().is_empty()
        {
            print_pairing_code_and_qr(self.dev_det, &dev_comm, discovery_capabilities, buf)?;

            self.pase_mgr.borrow_mut().enable_pase_session(
                dev_comm.verifier,
                dev_comm.discriminator,
                &self.transport_mgr.mdns,
            )?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Resets the transport layer by clearing all sessions, exchanges, the RX buffer and the TX buffer
    /// NOTE: User should be careful _not_ to call this method while the transport layer and/or the built-in mDNS is running.
    pub fn reset_transport(&self) -> Result<(), Error> {
        self.transport_mgr.reset()
    }

    pub async fn run<S, R>(
        &self,
        send: S,
        recv: R,
        dev_comm: Option<(CommissioningData, DiscoveryCapabilities)>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
    {
        if let Some((dev_comm, discovery_caps)) = dev_comm {
            let buf_access = PacketBufferExternalAccess(&self.transport_mgr.rx);
            let mut buf = buf_access.get().await.ok_or(ErrorCode::NoSpace)?;

            self.start_comissioning(dev_comm, discovery_caps, &mut buf)?;
        }

        self.transport_mgr.run(send, recv).await
    }

    #[cfg(not(all(
        feature = "std",
        any(target_os = "macos", all(feature = "zeroconf", target_os = "linux"))
    )))]
    pub async fn run_builtin_mdns<S, R>(
        &self,
        send: S,
        recv: R,
        host: &crate::mdns::Host<'_>,
        interface: Option<u32>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
    {
        self.transport_mgr
            .run_builtin_mdns(send, recv, host, interface)
            .await
    }

    /// Notify that the ACLs or Fabrics _might_ have changed
    /// This method is supposed to be called after processing SC and IM messages that might affect the ACLs or Fabrics.
    ///
    /// The default IM and SC handlers (`DataModel` and `SecureChannel`) do call this method after processing the messages.
    ///
    /// TODO: Fix the method name as it is not clear enough. Potentially revamp the whole persistence notification logic
    pub fn notify_changed(&self) {
        if self.is_changed() {
            self.persist_notification.notify();
        }
    }

    /// A hook for user persistence code to wait for potential changes in ACLs and/or Fabrics.
    /// Once this future resolves, user code is supposed to inspect ACLs and Fabrics for changes, and
    /// if there are changes, persist them.
    ///
    /// TODO: Fix the method name as it is not clear enough. Potentially revamp the whole persistence notification logic
    pub async fn wait_changed(&self) {
        self.persist_notification.wait().await
    }
}

impl<'a> Borrow<RefCell<FabricMgr>> for Matter<'a> {
    fn borrow(&self) -> &RefCell<FabricMgr> {
        &self.fabric_mgr
    }
}

impl<'a> Borrow<RefCell<AclMgr>> for Matter<'a> {
    fn borrow(&self) -> &RefCell<AclMgr> {
        &self.acl_mgr
    }
}

impl<'a> Borrow<RefCell<PaseMgr>> for Matter<'a> {
    fn borrow(&self) -> &RefCell<PaseMgr> {
        &self.pase_mgr
    }
}

impl<'a> Borrow<RefCell<FailSafe>> for Matter<'a> {
    fn borrow(&self) -> &RefCell<FailSafe> {
        &self.failsafe
    }
}

impl<'a> Borrow<TransportMgr<'a>> for Matter<'a> {
    fn borrow(&self) -> &TransportMgr<'a> {
        &self.transport_mgr
    }
}

impl<'a> Borrow<BasicInfoConfig<'a>> for Matter<'a> {
    fn borrow(&self) -> &BasicInfoConfig<'a> {
        self.dev_det
    }
}

impl<'a> Borrow<dyn DevAttDataFetcher + 'a> for Matter<'a> {
    fn borrow(&self) -> &(dyn DevAttDataFetcher + 'a) {
        self.dev_att
    }
}

impl<'a> Borrow<dyn Mdns + 'a> for Matter<'a> {
    fn borrow(&self) -> &(dyn Mdns + 'a) {
        &self.transport_mgr.mdns
    }
}

impl<'a> Borrow<Epoch> for Matter<'a> {
    fn borrow(&self) -> &Epoch {
        &self.epoch
    }
}

impl<'a> Borrow<Rand> for Matter<'a> {
    fn borrow(&self) -> &Rand {
        &self.rand
    }
}
