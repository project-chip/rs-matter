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

mod dev_att;
use matter::core::{self, CommissioningData};
use matter::data_model::cluster_basic_information::BasicInfoConfig;
use matter::data_model::cluster_level_control::{LevelControlCluster, UpdateDataStore};
use matter::data_model::cluster_on_off::OnOffCluster;
use matter::data_model::device_types::{device_type_add_dimmable_light, DEV_TYPE_DIMMABLE_LIGHT};
use matter::secure_channel::spake2p::VerifierData;
use std::{thread, time};

fn main() {
    env_logger::init();
    let comm_data = CommissioningData {
        // TODO: Hard-coded for now
        verifier: VerifierData::new_with_pw(123456),
        discriminator: 250,
    };

    // vid/pid should match those in the DAC
    let dev_info = BasicInfoConfig {
        vid: 0xFFF1,
        pid: 0x8002,
        hw_ver: 2,
        sw_ver: 1,
        sw_ver_str: "1".to_string(),
        serial_no: "aabbccdd".to_string(),
        device_name: "OnOff Light".to_string(),
    };
    let dev_att = Box::new(dev_att::HardCodedDevAtt::new());

    let mut matter = core::Matter::new(dev_info, dev_att, comm_data).unwrap();
    let dm = matter.get_data_model();
    {
        let mut node = dm.node.write().unwrap();
        let endpoint = node.add_endpoint(DEV_TYPE_DIMMABLE_LIGHT).unwrap();

        node.add_cluster(endpoint, OnOffCluster::new().unwrap())
            .unwrap();

        let level_cluster = LevelControlCluster::new().unwrap();
        let event_loop = level_cluster.as_ref().get_event_loop_ref().clone();
        node.add_cluster(endpoint, level_cluster).unwrap();

        // BG updater thread:
        thread::spawn(move || {
            println!("[bg thread] sleeping for 5 seconds.");
            thread::sleep(time::Duration::from_secs(5));
            println!(
                "[bg thread] woke up. Pretend to process event from outside. Set Volume to 17."
            );
            let mut t = event_loop.lock().unwrap();
            t.update_level(17);
        });

        println!("Added OnOff Light Device type at endpoint id: {}", endpoint);
        println!("Data Model now is: {}", node);
    };

    matter.start_daemon().unwrap();
}
