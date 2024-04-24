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

use embassy_futures::{block_on, join::join, select::select3};

use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    zerocopy_channel::{Channel, Receiver, Sender},
};

use embassy_time::{Duration, Timer};

use rs_matter::{
    acl::{AclEntry, AuthMode},
    data_model::{
        cluster_basic_information::{self, BasicInfoConfig},
        cluster_on_off::{self, OnOffCluster},
        core::{DataModel, IMBuffer},
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
        subscriptions::Subscriptions,
        system_model::{
            access_control,
            descriptor::{self, DescriptorCluster},
        },
    },
    error::{Error, ErrorCode},
    handler_chain_type,
    interaction_model::core::{OpCode, PROTO_ID_INTERACTION_MODEL},
    mdns::MdnsService,
    respond::Responder,
    tlv::{TLVWriter, TagType, ToTLV},
    transport::{
        exchange::{Exchange, MessageMeta, MAX_EXCHANGE_TX_BUF_SIZE},
        network::{
            Address, Ipv4Addr, NetworkReceive, NetworkSend, SocketAddr, SocketAddrV4,
            MAX_RX_PACKET_SIZE, MAX_TX_PACKET_SIZE,
        },
        session::{CaseDetails, NocCatIds, ReservedSession, SessionMode},
    },
    utils::{buf::PooledBuffers, select::Coalesce},
    Matter, MATTER_PORT,
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
    pub data: heapless::Vec<u8, MAX_EXCHANGE_TX_BUF_SIZE>,
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
        Self {
            matter: Self::new_matter(),
            cat_ids,
        }
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

    fn new_matter() -> Matter<'static> {
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

        matter.initialize_transport_buffers().unwrap();

        matter
    }

    fn init_matter(matter: &Matter, local_nodeid: u64, remote_nodeid: u64, cat_ids: &NocCatIds) {
        matter.transport_mgr.reset();

        let mut session = ReservedSession::reserve_now(matter).unwrap();

        session
            .update(
                local_nodeid,
                remote_nodeid,
                1,
                1,
                ADDR,
                SessionMode::Case(CaseDetails::new(1, cat_ids)),
                None,
                None,
                None,
            )
            .unwrap();

        session.complete();
    }

    pub fn process<const N: usize>(
        &self,
        handler: &ImEngineHandler,
        input: &[&ImInput],
        out: &mut heapless::Vec<ImOutput, N>,
    ) -> Result<(), Error> {
        out.clear();

        Self::init_matter(
            &self.matter,
            IM_ENGINE_REMOTE_PEER_ID,
            IM_ENGINE_PEER_ID,
            &self.cat_ids,
        );

        let matter_client = Self::new_matter();
        Self::init_matter(
            &matter_client,
            IM_ENGINE_PEER_ID,
            IM_ENGINE_REMOTE_PEER_ID,
            &self.cat_ids,
        );

        let mut buf1 = [heapless::Vec::new(); 1];
        let mut buf2 = [heapless::Vec::new(); 1];

        let mut pipe1 = NetworkPipe::<MAX_RX_PACKET_SIZE>::new(&mut buf1);
        let mut pipe2 = NetworkPipe::<MAX_TX_PACKET_SIZE>::new(&mut buf2);

        let (send_remote, recv_local) = pipe1.split();
        let (send_local, recv_remote) = pipe2.split();

        let matter_client = &matter_client;

        let buffers = PooledBuffers::<10, NoopRawMutex, IMBuffer>::new(0);

        let subscriptions = Subscriptions::<1>::new();

        let responder = Responder::new(
            "Default",
            DataModel::new(&buffers, &subscriptions, HandlerCompat(handler)),
            &self.matter,
            0,
        );

        block_on(
            select3(
                matter_client
                    .transport_mgr
                    .run(NetworkSendImpl(send_local), NetworkReceiveImpl(recv_local)),
                self.matter.transport_mgr.run(
                    NetworkSendImpl(send_remote),
                    NetworkReceiveImpl(recv_remote),
                ),
                join(responder.respond_once("0"), async move {
                    let mut exchange =
                        Exchange::initiate(matter_client, IM_ENGINE_REMOTE_PEER_ID, true).await?;

                    for ip in input {
                        exchange
                            .send_with(|_, wb| {
                                ip.data
                                    .to_tlv(&mut TLVWriter::new(wb), TagType::Anonymous)?;

                                Ok(Some(MessageMeta {
                                    proto_id: PROTO_ID_INTERACTION_MODEL,
                                    proto_opcode: ip.action as _,
                                    reliable: true,
                                }))
                            })
                            .await?;

                        {
                            // In a separate block so that the RX message is dropped before we start waiting

                            let rx = exchange.recv().await?;

                            out.push(ImOutput {
                                action: rx.meta().opcode()?,
                                data: heapless::Vec::from_slice(rx.payload())
                                    .map_err(|_| ErrorCode::NoSpace)?,
                            })
                            .map_err(|_| ErrorCode::NoSpace)?;
                        }

                        let delay = ip.delay.unwrap_or(0);
                        if delay > 0 {
                            Timer::after(Duration::from_millis(delay as _)).await;
                        }
                    }

                    exchange.acknowledge().await?;

                    Ok(())
                })
                .coalesce(),
            )
            .coalesce(),
        )
    }
}

const ADDR: Address = Address::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));

type NetworkPipe<'a, const N: usize> = Channel<'a, NoopRawMutex, heapless::Vec<u8, N>>;
struct NetworkReceiveImpl<'a, const N: usize>(Receiver<'a, NoopRawMutex, heapless::Vec<u8, N>>);
struct NetworkSendImpl<'a, const N: usize>(Sender<'a, NoopRawMutex, heapless::Vec<u8, N>>);

impl<'a, const N: usize> NetworkSend for NetworkSendImpl<'a, N> {
    async fn send_to(&mut self, data: &[u8], _addr: Address) -> Result<(), Error> {
        let vec = self.0.send().await;

        vec.clear();
        vec.extend_from_slice(data).unwrap();

        self.0.send_done();

        Ok(())
    }
}

impl<'a, const N: usize> NetworkReceive for NetworkReceiveImpl<'a, N> {
    async fn wait_available(&mut self) -> Result<(), Error> {
        self.0.receive().await;

        Ok(())
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        let vec = self.0.receive().await;

        buffer[..vec.len()].copy_from_slice(vec);
        let len = vec.len();

        self.0.receive_done();

        Ok((len, ADDR))
    }
}
