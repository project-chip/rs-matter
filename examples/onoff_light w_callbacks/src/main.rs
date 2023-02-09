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
use matter::data_model::device_types::device_type_add_on_off_light;
use matter::secure_channel::spake2p::VerifierData;

#[cfg(feature = "state_hooks")]
use matter::data_model::cluster_on_off::OnOffCallbacks;
#[cfg(feature = "state_hooks")]
use matter::data_model::device_types::device_type_add_on_off_light_w_callbacks;


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
        #[cfg(feature="state_hooks")]
        {
            let on = || { println!("[CALLBACK] On callback called!") };
            let off = || { println!("[CALLBACK] Off callback called!") };
            let toggle = || { println!("[CALLBACK] Toggle callback called!") };
    
            let on_callback = Box::new(on);
            let off_callback = Box::new(off);
            let toggle_callback = Box::new(toggle);
            let state_hooks = OnOffCallbacks { on_callback: on_callback, off_callback: off_callback, toggle_callback: toggle_callback };
            let endpoint = device_type_add_on_off_light_w_callbacks(&mut node, state_hooks).unwrap();    
            println!("Added OnOff Light Device type at endpoint id: {}", endpoint);
            println!("Data Model now is: {}", node);    
        }
        #[cfg(not(feature = "state_hooks"))]
        {
            let endpoint = device_type_add_on_off_light(&mut node).unwrap();    
            println!("Added OnOff Light Device type at endpoint id: {}", endpoint);
            println!("Data Model now is: {}", node);
        }
    }

    matter.start_daemon().unwrap();
}
