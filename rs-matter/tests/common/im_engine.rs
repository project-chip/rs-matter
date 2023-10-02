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
use matter_rs::{
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
    mdns::DummyMdns,
    secure_channel::{self, common::PROTO_ID_SECURE_CHANNEL, spake2p::VerifierData},
    tlv::{TLVWriter, TagType, ToTLV},
    transport::{
        core::PacketBuffers,
        packet::{Packet, MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE},
        pipe::Pipe,
    },
    transport::{
        network::Address,
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
    handler: handler_chain_type!(OnOffCluster, EchoCluster, DescriptorCluster<'static>, EchoCluster | RootEndpointHandler<'a>),
}

impl<'a> ImEngineHandler<'a> {
    pub fn new(matter: &'a Matter<'a>) -> Self {
        let handler = root_endpoint::handler(0, matter)
            .chain(0, echo_cluster::ID, EchoCluster::new(2, *matter.borrow()))
            .chain(1, descriptor::ID, DescriptorCluster::new(*matter.borrow()))
            .chain(1, echo_cluster::ID, EchoCluster::new(3, *matter.borrow()))
            .chain(1, cluster_on_off::ID, OnOffCluster::new(*matter.borrow()));

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
        exchange: &matter_rs::transport::exchange::Exchange,
        cmd: &matter_rs::data_model::objects::CmdDetails,
        data: &matter_rs::tlv::TLVElement,
        encoder: matter_rs::data_model::objects::CmdDataEncoder,
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

static mut DNS: DummyMdns = DummyMdns;

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
        use matter_rs::utils::epoch::sys_epoch as epoch;

        #[cfg(not(feature = "std"))]
        use matter_rs::utils::epoch::dummy_epoch as epoch;

        #[cfg(feature = "std")]
        use matter_rs::utils::rand::sys_rand as rand;

        #[cfg(not(feature = "std"))]
        use matter_rs::utils::rand::dummy_rand as rand;

        let matter = Matter::new(
            &BASIC_INFO,
            &DummyDevAtt,
            unsafe { &mut DNS },
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

        let mut tx_pipe_buf = [0; MAX_RX_BUF_SIZE];
        let mut rx_pipe_buf = [0; MAX_TX_BUF_SIZE];

        let mut tx_buf = [0; MAX_RX_BUF_SIZE];
        let mut rx_buf = [0; MAX_TX_BUF_SIZE];

        let tx_pipe = Pipe::new(&mut tx_buf);
        let rx_pipe = Pipe::new(&mut rx_buf);

        let tx_pipe = &tx_pipe;
        let rx_pipe = &rx_pipe;
        let tx_pipe_buf = &mut tx_pipe_buf;
        let rx_pipe_buf = &mut rx_pipe_buf;

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

        embassy_futures::block_on(async move {
            select3(
                self.matter.run_piped(
                    buffers,
                    tx_pipe,
                    rx_pipe,
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
                        Self::send(ip, tx_pipe_buf, rx_pipe, msg_ctr, acknowledge).await?;
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
                        let (len, _) = tx_pipe.recv(rx_pipe_buf).await;

                        let mut rx = Packet::new_rx(&mut rx_pipe_buf[..len]);

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
        tx_buf: &mut [u8],
        rx_pipe: &Pipe<'_>,
        msg_ctr: u32,
        acknowledge: bool,
    ) -> Result<(), Error> {
        let mut tx = Packet::new_tx(tx_buf);

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

        rx_pipe.send(Address::default(), tx.as_slice()).await;

        Ok(())
    }
}
