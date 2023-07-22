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

// TODO
// mod dev_att;
// use rs_matter::core::{self, CommissioningData};
// use rs_matter::data_model::cluster_basic_information::BasicInfoConfig;
// use rs_matter::data_model::cluster_media_playback::{Commands, MediaPlaybackCluster};
// use rs_matter::data_model::device_types::DEV_TYPE_ON_SMART_SPEAKER;
// use rs_matter::secure_channel::spake2p::VerifierData;

fn main() {
    //     env_logger::init();
    //     let comm_data = CommissioningData {
    //         // TODO: Hard-coded for now
    //         verifier: VerifierData::new_with_pw(123456),
    //         discriminator: 250,
    //     };

    //     // vid/pid should match those in the DAC
    //     let dev_info = BasicInfoConfig {
    //         vid: 0xFFF1,
    //         pid: 0x8002,
    //         hw_ver: 2,
    //         sw_ver: 1,
    //         sw_ver_str: "1".to_string(),
    //         serial_no: "aabbccdd".to_string(),
    //         device_name: "Smart Speaker".to_string(),
    //     };
    //     let dev_att = Box::new(dev_att::HardCodedDevAtt::new());

    //     let mut matter = core::Matter::new(dev_info, dev_att, comm_data).unwrap();
    //     let dm = matter.get_data_model();
    //     {
    //         let mut node = dm.node.write().unwrap();

    //         let endpoint_audio = node.add_endpoint(DEV_TYPE_ON_SMART_SPEAKER).unwrap();
    //         let mut media_playback_cluster = MediaPlaybackCluster::new().unwrap();

    //         // Add some callbacks
    //         let play_callback = Box::new(|| log::info!("Comamnd [Play] handled with callback."));
    //         let pause_callback = Box::new(|| log::info!("Comamnd [Pause] handled with callback."));
    //         let stop_callback = Box::new(|| log::info!("Comamnd [Stop] handled with callback."));
    //         let start_over_callback =
    //             Box::new(|| log::info!("Comamnd [StartOver] handled with callback."));
    //         media_playback_cluster.add_callback(Commands::Play, play_callback);
    //         media_playback_cluster.add_callback(Commands::Pause, pause_callback);
    //         media_playback_cluster.add_callback(Commands::Stop, stop_callback);
    //         media_playback_cluster.add_callback(Commands::StartOver, start_over_callback);

    //         node.add_cluster(endpoint_audio, media_playback_cluster)
    //             .unwrap();
    //         println!("Added Speaker type at endpoint id: {}", endpoint_audio)
    //     }
    //     matter.start_daemon().unwrap();
}
