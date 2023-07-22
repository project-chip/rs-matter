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

use crate::{
    acl::AclMgr,
    data_model::{
        cluster_basic_information::BasicInfoConfig,
        sdm::{dev_att::DevAttDataFetcher, failsafe::FailSafe},
    },
    error::*,
    fabric::FabricMgr,
    mdns::Mdns,
    pairing::{print_pairing_code_and_qr, DiscoveryCapabilities},
    secure_channel::{pake::PaseMgr, spake2p::VerifierData},
    transport::{
        exchange::{ExchangeCtx, MAX_EXCHANGES},
        session::SessionMgr,
    },
    utils::{epoch::Epoch, rand::Rand, select::Notification},
};

/* The Matter Port */
pub const MATTER_PORT: u16 = 5540;

/// Device Commissioning Data
pub struct CommissioningData {
    /// The data like password or verifier that is required to authenticate
    pub verifier: VerifierData,
    /// The 12-bit discriminator used to differentiate between multiple devices
    pub discriminator: u16,
}

/// The primary Matter Object
pub struct Matter<'a> {
    fabric_mgr: RefCell<FabricMgr>,
    pub acl_mgr: RefCell<AclMgr>, // Public for tests
    pase_mgr: RefCell<PaseMgr>,
    failsafe: RefCell<FailSafe>,
    persist_notification: Notification,
    pub(crate) send_notification: Notification,
    mdns: &'a dyn Mdns,
    pub(crate) epoch: Epoch,
    pub(crate) rand: Rand,
    dev_det: &'a BasicInfoConfig<'a>,
    dev_att: &'a dyn DevAttDataFetcher,
    pub(crate) port: u16,
    pub(crate) exchanges: RefCell<heapless::Vec<ExchangeCtx, MAX_EXCHANGES>>,
    pub session_mgr: RefCell<SessionMgr>, // Public for tests
}

impl<'a> Matter<'a> {
    #[cfg(feature = "std")]
    #[inline(always)]
    pub fn new_default(
        dev_det: &'a BasicInfoConfig<'a>,
        dev_att: &'a dyn DevAttDataFetcher,
        mdns: &'a dyn Mdns,
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
    /// requires a set of device attestation certificates and keys. It is the responsibility of
    /// this object to return the device attestation details when queried upon.
    #[inline(always)]
    pub fn new(
        dev_det: &'a BasicInfoConfig<'a>,
        dev_att: &'a dyn DevAttDataFetcher,
        mdns: &'a dyn Mdns,
        epoch: Epoch,
        rand: Rand,
        port: u16,
    ) -> Self {
        Self {
            fabric_mgr: RefCell::new(FabricMgr::new()),
            acl_mgr: RefCell::new(AclMgr::new()),
            pase_mgr: RefCell::new(PaseMgr::new(epoch, rand)),
            failsafe: RefCell::new(FailSafe::new()),
            persist_notification: Notification::new(),
            send_notification: Notification::new(),
            mdns,
            epoch,
            rand,
            dev_det,
            dev_att,
            port,
            exchanges: RefCell::new(heapless::Vec::new()),
            session_mgr: RefCell::new(SessionMgr::new(epoch, rand)),
        }
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
        self.fabric_mgr.borrow_mut().load(data, self.mdns)
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

    pub fn start_comissioning(
        &self,
        dev_comm: CommissioningData,
        buf: &mut [u8],
    ) -> Result<bool, Error> {
        if !self.pase_mgr.borrow().is_pase_session_enabled() && self.fabric_mgr.borrow().is_empty()
        {
            print_pairing_code_and_qr(
                self.dev_det,
                &dev_comm,
                DiscoveryCapabilities::default(),
                buf,
            )?;

            self.pase_mgr.borrow_mut().enable_pase_session(
                dev_comm.verifier,
                dev_comm.discriminator,
                self.mdns,
            )?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn notify_changed(&self) {
        if self.is_changed() {
            self.persist_notification.signal(());
        }
    }

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
        self.mdns
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
