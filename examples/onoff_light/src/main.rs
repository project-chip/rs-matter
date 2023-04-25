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

use std::borrow::Borrow;

use matter::core::{CommissioningData, Matter};
use matter::data_model::cluster_basic_information::BasicInfoConfig;
use matter::data_model::cluster_on_off;
use matter::data_model::core::DataModel;
use matter::data_model::device_types::DEV_TYPE_ON_OFF_LIGHT;
use matter::data_model::objects::*;
use matter::data_model::root_endpoint;
use matter::data_model::sdm::dev_att::DevAttDataFetcher;
use matter::interaction_model::core::InteractionModel;
use matter::secure_channel::spake2p::VerifierData;
use matter::transport::{
    mgr::RecvAction, mgr::TransportMgr, packet::MAX_RX_BUF_SIZE, packet::MAX_TX_BUF_SIZE,
    udp::UdpListener,
};

mod dev_att;

fn main() {
    env_logger::init();

    // vid/pid should match those in the DAC
    let dev_info = BasicInfoConfig {
        vid: 0xFFF1,
        pid: 0x8000,
        hw_ver: 2,
        sw_ver: 1,
        sw_ver_str: "1",
        serial_no: "aabbccdd",
        device_name: "OnOff Light",
    };

    //let mut mdns = matter::mdns::astro::AstroMdns::new().unwrap();
    let mut mdns = matter::mdns::libmdns::LibMdns::new().unwrap();

    let matter = Matter::new_default(&dev_info, &mut mdns, matter::transport::udp::MATTER_PORT);

    let dev_att = dev_att::HardCodedDevAtt::new();

    matter
        .start::<4096>(
            CommissioningData {
                // TODO: Hard-coded for now
                verifier: VerifierData::new_with_pw(123456, *matter.borrow()),
                discriminator: 250,
            },
            &mut [0; 4096],
        )
        .unwrap();

    let matter = &matter;
    let dev_att = &dev_att;

    let mut transport = TransportMgr::new(matter);

    smol::block_on(async move {
        let udp = UdpListener::new().await.unwrap();

        loop {
            let mut rx_buf = [0; MAX_RX_BUF_SIZE];
            let mut tx_buf = [0; MAX_TX_BUF_SIZE];

            let (len, addr) = udp.recv(&mut rx_buf).await.unwrap();

            let mut completion = transport.recv(addr, &mut rx_buf[..len], &mut tx_buf);

            while let Some(action) = completion.next_action().unwrap() {
                match action {
                    RecvAction::Send(addr, buf) => {
                        udp.send(addr, buf).await.unwrap();
                    }
                    RecvAction::Interact(mut ctx) => {
                        let node = Node {
                            id: 0,
                            endpoints: &[
                                root_endpoint::endpoint(0),
                                Endpoint {
                                    id: 1,
                                    device_type: DEV_TYPE_ON_OFF_LIGHT,
                                    clusters: &[cluster_on_off::CLUSTER],
                                },
                            ],
                        };

                        let mut handler = handler(matter, dev_att);

                        let mut im =
                            InteractionModel(DataModel::new(matter.borrow(), &node, &mut handler));

                        if im.handle(&mut ctx).unwrap() {
                            if ctx.send().unwrap() {
                                udp.send(ctx.tx.peer, ctx.tx.as_slice()).await.unwrap();
                            }
                        }
                    }
                }
            }
        }
    });
}

fn handler<'a>(matter: &'a Matter<'a>, dev_att: &'a dyn DevAttDataFetcher) -> impl Handler + 'a {
    root_endpoint::handler(0, dev_att, matter).chain(
        1,
        cluster_on_off::ID,
        cluster_on_off::OnOffCluster::new(*matter.borrow()),
    )
}
