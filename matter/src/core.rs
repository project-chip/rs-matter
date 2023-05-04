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
    data_model::{cluster_basic_information::BasicInfoConfig, sdm::failsafe::FailSafe},
    error::*,
    fabric::FabricMgr,
    mdns::{Mdns, MdnsMgr},
    pairing::{print_pairing_code_and_qr, DiscoveryCapabilities},
    secure_channel::{pake::PaseMgr, spake2p::VerifierData},
    utils::{epoch::Epoch, rand::Rand},
};

/// Device Commissioning Data
pub struct CommissioningData {
    /// The data like password or verifier that is required to authenticate
    pub verifier: VerifierData,
    /// The 12-bit discriminator used to differentiate between multiple devices
    pub discriminator: u16,
}

/// The primary Matter Object
pub struct Matter<'a> {
    pub fabric_mgr: RefCell<FabricMgr>,
    pub acl_mgr: RefCell<AclMgr>,
    pub pase_mgr: RefCell<PaseMgr>,
    pub failsafe: RefCell<FailSafe>,
    pub mdns_mgr: RefCell<MdnsMgr<'a>>,
    pub epoch: Epoch,
    pub rand: Rand,
    pub dev_det: &'a BasicInfoConfig<'a>,
}

impl<'a> Matter<'a> {
    #[cfg(feature = "std")]
    pub fn new_default(dev_det: &'a BasicInfoConfig, mdns: &'a mut dyn Mdns, port: u16) -> Self {
        use crate::utils::epoch::sys_epoch;
        use crate::utils::rand::sys_rand;

        Self::new(dev_det, mdns, sys_epoch, sys_rand, port)
    }

    /// Creates a new Matter object
    ///
    /// # Parameters
    /// * dev_att: An object that implements the trait [DevAttDataFetcher]. Any Matter device
    /// requires a set of device attestation certificates and keys. It is the responsibility of
    /// this object to return the device attestation details when queried upon.
    pub fn new(
        dev_det: &'a BasicInfoConfig,
        mdns: &'a mut dyn Mdns,
        epoch: Epoch,
        rand: Rand,
        port: u16,
    ) -> Self {
        Self {
            fabric_mgr: RefCell::new(FabricMgr::new()),
            acl_mgr: RefCell::new(AclMgr::new()),
            pase_mgr: RefCell::new(PaseMgr::new(epoch, rand)),
            failsafe: RefCell::new(FailSafe::new()),
            mdns_mgr: RefCell::new(MdnsMgr::new(
                dev_det.vid,
                dev_det.pid,
                dev_det.device_name,
                port,
                mdns,
            )),
            epoch,
            rand,
            dev_det,
        }
    }

    pub fn dev_det(&self) -> &BasicInfoConfig {
        self.dev_det
    }

    pub fn load_fabrics(&self, data: &[u8]) -> Result<(), Error> {
        self.fabric_mgr
            .borrow_mut()
            .load(data, &mut self.mdns_mgr.borrow_mut())
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

    pub fn start(&self, dev_comm: CommissioningData, buf: &mut [u8]) -> Result<(), Error> {
        let open_comm_window = self.fabric_mgr.borrow().is_empty();
        if open_comm_window {
            print_pairing_code_and_qr(
                self.dev_det,
                &dev_comm,
                DiscoveryCapabilities::default(),
                buf,
            )?;

            self.pase_mgr.borrow_mut().enable_pase_session(
                dev_comm.verifier,
                dev_comm.discriminator,
                &mut self.mdns_mgr.borrow_mut(),
            )?;
        }

        Ok(())
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

impl<'a> Borrow<RefCell<MdnsMgr<'a>>> for Matter<'a> {
    fn borrow(&self) -> &RefCell<MdnsMgr<'a>> {
        &self.mdns_mgr
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
