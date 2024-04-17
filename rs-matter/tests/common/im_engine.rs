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

use crate::common::echo_cluster;
use core::borrow::Borrow;
use core::future::pending;
use core::time::Duration;
use embassy_futures::select::select3;
use embassy_sync::{
    blocking_mutex::raw::{NoopRawMutex, RawMutex},
    zerocopy_channel::{Channel, Receiver, Sender},
};
use rs_matter::{
    acl::{AclEntry, AuthMode},
    data_model::{
        cluster_basic_information::{self, BasicInfoConfig},
        cluster_on_off::{self, OnOffCluster},
        device_types::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE},
        objects::{
            AttrData, AttrDataEncoder, AttrDetails, Endpoint, Handler, HandlerCompat, Metadata,
            Node, NonBlockingHandler, Privilege,
        },
        root_endpoint::{self, RootEndpointHandler},
        sdm::{
            admin_commissioning,
            dev_att::{DataType, DevAttDataFetcher},
            general_commissioning, noc, nw_commissioning,
        },
        system_model::{
            access_control,
            descriptor::{self, DescriptorCluster},
        },
    },
    error::{Error, ErrorCode},
    handler_chain_type,
    interaction_model::core::{OpCode, PROTO_ID_INTERACTION_MODEL},
    mdns::MdnsService,
    secure_channel::{self, common::PROTO_ID_SECURE_CHANNEL, spake2p::VerifierData},
    tlv::{TLVWriter, TagType, ToTLV},
    transport::{
        core::PacketBuffers,
        network::{Address, Ipv4Addr, NetworkReceive, NetworkSend, SocketAddr, SocketAddrV4},
        packet::{Packet, MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE},
        session::{CaseDetails, CloneData, NocCatIds, SessionMode},
    },
    utils::select::{EitherUnwrap, Notification},
    CommissioningData, Matter, MATTER_PORT,
};

use super::echo_cluster::EchoCluster;

const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    vid: 10,
    pid: 11,
    hw_ver: 12,
    sw_ver: 13,
    sw_ver_str: "13",
    serial_no: "aabbccdd",
    device_name: "Test Device",
    product_name: "TestProd",
    vendor_name: "TestVendor",
};

struct DummyDevAtt;

impl DevAttDataFetcher for DummyDevAtt {
    fn get_devatt_data(&self, _data_type: DataType, _data: &mut [u8]) -> Result<usize, Error> {
        Ok(2)
    }
}

pub const IM_ENGINE_PEER_ID: u64 = 445566;
pub const IM_ENGINE_REMOTE_PEER_ID: u64 = 123456;

const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        Endpoint {
            id: 0,
            clusters: &[
                descriptor::CLUSTER,
                cluster_basic_information::CLUSTER,
                general_commissioning::CLUSTER,
                nw_commissioning::CLUSTER,
                admin_commissioning::CLUSTER,
                noc::CLUSTER,
                access_control::CLUSTER,
                echo_cluster::CLUSTER,
            ],
            device_type: DEV_TYPE_ROOT_NODE,
        },
        Endpoint {
            id: 1,
            clusters: &[
                descriptor::CLUSTER,
                cluster_on_off::CLUSTER,
                echo_cluster::CLUSTER,
            ],
            device_type: DEV_TYPE_ON_OFF_LIGHT,
        },
    ],
};

pub struct ImInput<'a> {
    action: OpCode,
    data: &'a dyn ToTLV,
    delay: Option<u16>,
}

impl<'a> ImInput<'a> {
    pub fn new(action: OpCode, data: &'a dyn ToTLV) -> Self {
        Self::new_delayed(action, data, None)
    }

    pub fn new_delayed(action: OpCode, data: &'a dyn ToTLV, delay: Option<u16>) -> Self {
        Self {
            action,
            data,
            delay,
        }
    }
}

pub struct ImOutput {
    pub action: OpCode,
    pub data: heapless::Vec<u8, MAX_TX_BUF_SIZE>,
}

pub struct ImEngineHandler<'a> {
    handler: handler_chain_type!(OnOffCluster<'a>, EchoCluster, DescriptorCluster<'static>, EchoCluster | RootEndpointHandler<'a>),
}

impl<'a> ImEngineHandler<'a> {
    pub fn new(matter: &'a Matter<'a>) -> Self {
        let handler = root_endpoint::handler(0, matter)
            .chain(0, echo_cluster::ID, EchoCluster::new(2, *matter.borrow()))
            .chain(1, descriptor::ID, DescriptorCluster::new(*matter.borrow()))
            .chain(1, echo_cluster::ID, EchoCluster::new(3, *matter.borrow()))
            .chain(
                1,
                cluster_on_off::ID,
                OnOffCluster::new(*matter.borrow(), None),
            );

        Self { handler }
    }

    pub fn echo_cluster(&self, endpoint: u16) -> &EchoCluster {
        match endpoint {
            0 => &self.handler.next.next.next.handler,
            1 => &self.handler.next.handler,
            _ => panic!(),
        }
    }
}

impl<'a> Handler for ImEngineHandler<'a> {
    fn read(&self, attr: &AttrDetails, encoder: AttrDataEncoder) -> Result<(), Error> {
        self.handler.read(attr, encoder)
    }

    fn write(&self, attr: &AttrDetails, data: AttrData) -> Result<(), Error> {
        self.handler.write(attr, data)
    }

    fn invoke(
        &self,
        exchange: &rs_matter::transport::exchange::Exchange,
        cmd: &rs_matter::data_model::objects::CmdDetails,
        data: &rs_matter::tlv::TLVElement,
        encoder: rs_matter::data_model::objects::CmdDataEncoder,
    ) -> Result<(), Error> {
        self.handler.invoke(exchange, cmd, data, encoder)
    }
}

impl<'a> NonBlockingHandler for ImEngineHandler<'a> {}

impl<'a> Metadata for ImEngineHandler<'a> {
    type MetadataGuard<'g> = Node<'g> where Self: 'g;

    fn lock(&self) -> Self::MetadataGuard<'_> {
        NODE
    }
}

/// An Interaction Model Engine to facilitate easy testing
pub struct ImEngine<'a> {
    pub matter: Matter<'a>,
    cat_ids: NocCatIds,
}

impl<'a> ImEngine<'a> {
    pub fn new_default() -> Self {
        Self::new(Default::default())
    }

    /// Create the interaction model engine
    pub fn new(cat_ids: NocCatIds) -> Self {
        #[cfg(feature = "std")]
        use rs_matter::utils::epoch::sys_epoch as epoch;

        #[cfg(not(feature = "std"))]
        use rs_matter::utils::epoch::dummy_epoch as epoch;

        #[cfg(feature = "std")]
        use rs_matter::utils::rand::sys_rand as rand;

        #[cfg(not(feature = "std"))]
        use rs_matter::utils::rand::dummy_rand as rand;

        let matter = Matter::new(
            &BASIC_INFO,
            &DummyDevAtt,
            MdnsService::Disabled,
            epoch,
            rand,
            MATTER_PORT,
        );

        Self { matter, cat_ids }
    }

    pub fn add_default_acl(&self) {
        // Only allow the standard peer node id of the IM Engine
        let mut default_acl = AclEntry::new(1, Privilege::ADMIN, AuthMode::Case);
        default_acl.add_subject(IM_ENGINE_PEER_ID).unwrap();
        self.matter.acl_mgr.borrow_mut().add(default_acl).unwrap();
    }

    pub fn handler(&self) -> ImEngineHandler<'_> {
        ImEngineHandler::new(&self.matter)
    }

    pub fn process<const N: usize>(
        &self,
        handler: &ImEngineHandler,
        input: &[&ImInput],
        out: &mut heapless::Vec<ImOutput, N>,
    ) -> Result<(), Error> {
        self.matter.reset_transport();

        let clone_data = CloneData::new(
            IM_ENGINE_REMOTE_PEER_ID,
            IM_ENGINE_PEER_ID,
            1,
            1,
            Address::default(),
            SessionMode::Case(CaseDetails::new(1, &self.cat_ids)),
        );

        let sess_idx = self
            .matter
            .session_mgr
            .borrow_mut()
            .clone_session(&clone_data)
            .unwrap();

        let mut send_channel_buf = [heapless::Vec::new(); 1];
        let mut recv_channel_buf = [heapless::Vec::new(); 1];

        let mut send_channel = Channel::<NoopRawMutex, _>::new(&mut send_channel_buf);
        let mut recv_channel = Channel::<NoopRawMutex, _>::new(&mut recv_channel_buf);

        let handler = &handler;

        let mut msg_ctr = self
            .matter
            .session_mgr
            .borrow_mut()
            .mut_by_index(sess_idx)
            .unwrap()
            .get_msg_ctr();

        let resp_notif = Notification::new();
        let resp_notif = &resp_notif;

        let mut buffers = PacketBuffers::new();
        let buffers = &mut buffers;

        let (send, mut send_dest) = send_channel.split();
        let (mut recv_dest, recv) = recv_channel.split();

        embassy_futures::block_on(async move {
            select3(
                self.matter.run(
                    NetworkSender(send),
                    NetworkReceiver(recv),
                    buffers,
                    CommissioningData {
                        // TODO: Hard-coded for now
                        verifier: VerifierData::new_with_pw(123456, *self.matter.borrow()),
                        discriminator: 250,
                    },
                    &HandlerCompat(handler),
                ),
                async move {
                    let mut acknowledge = false;
                    for ip in input {
                        Self::send(ip, &mut recv_dest, msg_ctr, acknowledge).await?;
                        resp_notif.wait().await;

                        if let Some(delay) = ip.delay {
                            if delay > 0 {
                                #[cfg(feature = "std")]
                                std::thread::sleep(Duration::from_millis(delay as _));
                            }
                        }

                        msg_ctr += 2;
                        acknowledge = true;
                    }

                    pending::<()>().await;

                    Ok(())
                },
                async move {
                    out.clear();

                    while out.len() < input.len() {
                        let vec = send_dest.receive().await;

                        let mut rx = Packet::new_rx(vec);

                        rx.plain_hdr_decode()?;
                        rx.proto_decode(IM_ENGINE_REMOTE_PEER_ID, Some(&[0u8; 16]))?;

                        if rx.get_proto_id() != PROTO_ID_SECURE_CHANNEL
                            || rx.get_proto_opcode::<secure_channel::common::OpCode>()?
                                != secure_channel::common::OpCode::MRPStandAloneAck
                        {
                            out.push(ImOutput {
                                action: rx.get_proto_opcode()?,
                                data: heapless::Vec::from_slice(rx.as_slice())
                                    .map_err(|_| ErrorCode::NoSpace)?,
                            })
                            .map_err(|_| ErrorCode::NoSpace)?;

                            resp_notif.signal(());
                        }

                        send_dest.receive_done();
                    }

                    Ok(())
                },
            )
            .await
            .unwrap()
        })?;

        Ok(())
    }

    async fn send(
        input: &ImInput<'_>,
        sender: &mut Sender<'_, impl RawMutex, heapless::Vec<u8, MAX_RX_BUF_SIZE>>,
        msg_ctr: u32,
        acknowledge: bool,
    ) -> Result<(), Error> {
        let vec = sender.send().await;

        vec.clear();
        vec.extend(core::iter::repeat(0).take(MAX_RX_BUF_SIZE));

        let mut tx = Packet::new_tx(vec);

        tx.set_proto_id(PROTO_ID_INTERACTION_MODEL);
        tx.set_proto_opcode(input.action as u8);

        let mut tw = TLVWriter::new(tx.get_writebuf()?);

        input.data.to_tlv(&mut tw, TagType::Anonymous)?;

        tx.plain.ctr = msg_ctr + 1;
        tx.plain.sess_id = 1;
        tx.proto.set_initiator();

        if acknowledge {
            tx.proto.set_ack(msg_ctr - 1);
        }

        tx.proto_encode(
            Address::default(),
            Some(IM_ENGINE_REMOTE_PEER_ID),
            IM_ENGINE_PEER_ID,
            false,
            Some(&[0u8; 16]),
        )?;

        let start = tx.get_writebuf()?.get_start();
        let end = tx.get_writebuf()?.get_tail();

        if start > 0 {
            for offset in 0..(end - start) {
                vec[offset] = vec[start + offset];
            }
        }

        vec.truncate(end - start);

        sender.send_done();

        Ok(())
    }
}

struct NetworkSender<'a>(Sender<'a, NoopRawMutex, heapless::Vec<u8, MAX_TX_BUF_SIZE>>);

impl<'a> NetworkSend for NetworkSender<'a> {
    async fn send_to(&mut self, data: &[u8], _addr: Address) -> Result<(), Error> {
        let vec = self.0.send().await;

        vec.clear();
        vec.extend_from_slice(data).unwrap();

        self.0.send_done();

        Ok(())
    }
}

struct NetworkReceiver<'a>(Receiver<'a, NoopRawMutex, heapless::Vec<u8, MAX_RX_BUF_SIZE>>);

impl<'a> NetworkReceive for NetworkReceiver<'a> {
    async fn wait_available(&mut self) -> Result<(), Error> {
        self.0.receive().await;

        Ok(())
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        let vec = self.0.receive().await;

        buffer[..vec.len()].copy_from_slice(vec);
        let len = vec.len();

        self.0.receive_done();

        Ok((
            len,
            Address::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))),
        ))
    }
}
