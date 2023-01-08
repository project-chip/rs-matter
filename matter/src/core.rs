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

use crate::{
    acl::AclMgr,
    data_model::{
        cluster_basic_information::BasicInfoConfig, core::DataModel,
        sdm::dev_att::DevAttDataFetcher,
    },
    error::*,
    fabric::FabricMgr,
    interaction_model::InteractionModel,
    mdns::Mdns,
    secure_channel::core::SecureChannel,
    transport,
};
use std::sync::Arc;

#[derive(Default)]
/// Device Commissioning Data
pub struct CommissioningData {
    /// The commissioning salt
    pub salt: [u8; 16],
    /// The password for commissioning the device
    // TODO: We should replace this with verifier instead of password
    pub passwd: u32,
    /// The 12-bit discriminator used to differentiate between multiple devices
    pub discriminator: u16,
}

/// The primary Matter Object
pub struct Matter {
    transport_mgr: transport::mgr::Mgr,
    data_model: DataModel,
    fabric_mgr: Arc<FabricMgr>,
}

impl Matter {
    /// Creates a new Matter object
    ///
    /// # Parameters
    /// * dev_att: An object that implements the trait [DevAttDataFetcher]. Any Matter device
    /// requires a set of device attestation certificates and keys. It is the responsibility of
    /// this object to return the device attestation details when queried upon.
    pub fn new(
        dev_det: BasicInfoConfig,
        dev_att: Box<dyn DevAttDataFetcher>,
        dev_comm: CommissioningData,
    ) -> Result<Box<Matter>, Error> {
        let mdns = Mdns::get()?;
        mdns.set_values(dev_det.vid, dev_det.pid);

        let fabric_mgr = Arc::new(FabricMgr::new()?);
        let acl_mgr = Arc::new(AclMgr::new()?);
        let open_comm_window = fabric_mgr.is_empty();
        let data_model = DataModel::new(dev_det, dev_att, fabric_mgr.clone(), acl_mgr)?;
        let mut matter = Box::new(Matter {
            transport_mgr: transport::mgr::Mgr::new()?,
            data_model,
            fabric_mgr,
        });
        let interaction_model =
            Box::new(InteractionModel::new(Box::new(matter.data_model.clone())));
        matter.transport_mgr.register_protocol(interaction_model)?;
        let mut secure_channel = Box::new(SecureChannel::new(matter.fabric_mgr.clone()));
        if open_comm_window {
            secure_channel.open_comm_window(
                &dev_comm.salt,
                dev_comm.passwd,
                dev_comm.discriminator,
            )?;
        }

        matter.transport_mgr.register_protocol(secure_channel)?;
        Ok(matter)
    }

    /// Returns an Arc to [DataModel]
    ///
    /// The Data Model is where you express what is the type of your device. Typically
    /// once you gets this reference, you acquire the write lock and add your device
    /// types, clusters, attributes, commands to the data model.
    pub fn get_data_model(&self) -> DataModel {
        self.data_model.clone()
    }

    /// Starts the Matter daemon
    ///
    /// This call does NOT return
    ///
    /// This call starts the Matter daemon that starts communication with other Matter
    /// devices on the network.
    pub fn start_daemon(&mut self) -> Result<(), Error> {
        self.transport_mgr.start()
    }
}
