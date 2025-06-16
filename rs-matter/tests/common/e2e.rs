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

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use core::num::NonZeroU8;

use embassy_futures::select::select3;
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    zerocopy_channel::{Channel, Receiver, Sender},
};

use rs_matter::acl::{AclEntry, AuthMode};
use rs_matter::crypto::KeyPair;
use rs_matter::dm::clusters::basic_info::BasicInfoConfig;
use rs_matter::dm::clusters::dev_att::{DataType, DevAttDataFetcher};
use rs_matter::dm::subscriptions::Subscriptions;
use rs_matter::dm::{AsyncHandler, AsyncMetadata, Privilege};
use rs_matter::dm::{DataModel, IMBuffer};
use rs_matter::error::Error;
use rs_matter::mdns::MdnsService;
use rs_matter::respond::Responder;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::{
    Address, NetworkReceive, NetworkSend, MAX_RX_PACKET_SIZE, MAX_TX_PACKET_SIZE,
};
use rs_matter::transport::session::{NocCatIds, ReservedSession, SessionMode};
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{BasicCommData, Matter, MATTER_PORT};

pub mod im;
pub mod test;
pub mod tlv;

// For backwards compatibility
pub type ImEngine = E2eRunner;

// For backwards compatibility
pub const IM_ENGINE_PEER_ID: u64 = E2eRunner::PEER_ID;

/// A test runner for end-to-end tests.
///
/// The runner works by instantiating two `Matter` instances, one for the local node and one for the
/// remote node which is being tested. The instances are connected over a fake UDP network.
///
/// The runner then pre-set a single session between the two nodes and runs all tests in the context
/// of a single exchange per test run.
///
/// All transport-related state is reset between test runs.
pub struct E2eRunner {
    pub matter: Matter<'static>,
    matter_client: Matter<'static>,
    buffers: PooledBuffers<10, NoopRawMutex, IMBuffer>,
    subscriptions: Subscriptions<1>,
    cat_ids: NocCatIds,
}

impl E2eRunner {
    const ADDR: Address = Address::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));

    const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
        vid: 1,
        pid: 1,
        hw_ver: 1,
        hw_ver_str: "1",
        sw_ver: 1,
        sw_ver_str: "1",
        serial_no: "E2E",
        device_name: "E2E",
        product_name: "E2E",
        vendor_name: "E2E",
        sai: None,
        sii: None,
    };

    const BASIC_COMM: BasicCommData = BasicCommData {
        password: 0,
        discriminator: 0,
    };

    /// The ID of the local Matter instance
    pub const PEER_ID: u64 = 445566;

    /// The ID of the remote (tested) Matter instance
    pub const REMOTE_PEER_ID: u64 = 123456;

    /// Create a new runner with default category IDs.
    pub fn new_default() -> Self {
        Self::new(NocCatIds::default())
    }

    /// Create a new runner with the given category IDs.
    pub fn new(cat_ids: NocCatIds) -> Self {
        Self {
            matter: Self::new_matter(),
            matter_client: Self::new_matter(),
            buffers: PooledBuffers::new(0),
            subscriptions: Subscriptions::new(),
            cat_ids,
        }
    }

    /// Initialize the local and remote (tested) Matter instances
    /// that the runner owns
    pub fn init(&self) -> Result<(), Error> {
        Self::init_matter(
            &self.matter,
            Self::REMOTE_PEER_ID,
            Self::PEER_ID,
            &self.cat_ids,
        )?;

        Self::init_matter(
            &self.matter_client,
            Self::PEER_ID,
            Self::REMOTE_PEER_ID,
            &self.cat_ids,
        )
    }

    /// Get the Matter instance for the local node (the test driver).
    pub fn matter_client(&self) -> &Matter<'static> {
        &self.matter_client
    }

    /// Add a default ACL entry to the remote (tested) Matter instance.
    pub fn add_default_acl(&self) {
        // Only allow the standard peer node id of the IM Engine
        let mut default_acl = AclEntry::new(None, Privilege::ADMIN, AuthMode::Case);
        default_acl.add_subject(Self::PEER_ID).unwrap();
        self.matter
            .fabric_mgr
            .borrow_mut()
            .acl_add(NonZeroU8::new(1).unwrap(), default_acl)
            .unwrap();
    }

    /// Initiates a new exchange on the local Matter instance
    pub async fn initiate_exchange(&self) -> Result<Exchange<'_>, Error> {
        Exchange::initiate(
            self.matter_client(),
            1, /*just one fabric in tests*/
            Self::REMOTE_PEER_ID,
            true,
        )
        .await
    }

    /// Runs both the local and the remote (tested) Matter instances,
    /// by connecting them with a fake UDP network.
    ///
    /// The remote (tested) Matter instance will run with the provided DM handler.
    ///
    /// The local Matter instance does not have a DM handler as it is only used to
    /// drive the tests (i.e. it does not have any server clusters and such).
    pub async fn run<H>(&self, handler: H) -> Result<(), Error>
    where
        H: AsyncHandler + AsyncMetadata,
    {
        self.init()?;

        let mut buf1 = [heapless::Vec::new(); 1];
        let mut buf2 = [heapless::Vec::new(); 1];

        let mut pipe1 = NetworkPipe::<MAX_RX_PACKET_SIZE>::new(&mut buf1);
        let mut pipe2 = NetworkPipe::<MAX_TX_PACKET_SIZE>::new(&mut buf2);

        let (send_remote, recv_local) = pipe1.split();
        let (send_local, recv_remote) = pipe2.split();

        let matter_client = &self.matter_client;

        let responder = Responder::new(
            "Default",
            DataModel::new(&self.buffers, &self.subscriptions, handler),
            &self.matter,
            0,
        );

        select3(
            matter_client
                .transport_mgr
                .run(NetworkSendImpl(send_local), NetworkReceiveImpl(recv_local)),
            self.matter.transport_mgr.run(
                NetworkSendImpl(send_remote),
                NetworkReceiveImpl(recv_remote),
            ),
            responder.run::<4>(),
        )
        .coalesce()
        .await
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
            &Self::BASIC_INFO,
            Self::BASIC_COMM,
            &E2eDummyDevAtt,
            MdnsService::Disabled,
            epoch,
            rand,
            MATTER_PORT,
        );

        matter
            .fabric_mgr
            .borrow_mut()
            .add_with_post_init(KeyPair::new(matter.rand()).unwrap(), |_| Ok(()))
            .unwrap();

        matter.initialize_transport_buffers().unwrap();

        matter
    }

    fn init_matter(
        matter: &Matter,
        local_nodeid: u64,
        remote_nodeid: u64,
        cat_ids: &NocCatIds,
    ) -> Result<(), Error> {
        matter.transport_mgr.reset()?;

        let mut session = ReservedSession::reserve_now(matter)?;

        session.update(
            local_nodeid,
            remote_nodeid,
            1,
            1,
            Self::ADDR,
            SessionMode::Case {
                fab_idx: NonZeroU8::new(1).unwrap(),
                cat_ids: *cat_ids,
            },
            None,
            None,
            None,
        )?;

        session.complete();

        Ok(())
    }
}

/// A dummy device attribute data fetcher that always returns the same hard-coded test data.
struct E2eDummyDevAtt;

impl DevAttDataFetcher for E2eDummyDevAtt {
    fn get_devatt_data(&self, _data_type: DataType, _data: &mut [u8]) -> Result<usize, Error> {
        Ok(2)
    }
}

type NetworkPipe<'a, const N: usize> = Channel<'a, NoopRawMutex, heapless::Vec<u8, N>>;

struct NetworkReceiveImpl<'a, const N: usize>(Receiver<'a, NoopRawMutex, heapless::Vec<u8, N>>);

impl<const N: usize> NetworkSend for NetworkSendImpl<'_, N> {
    async fn send_to(&mut self, data: &[u8], _addr: Address) -> Result<(), Error> {
        let vec = self.0.send().await;

        vec.clear();
        vec.extend_from_slice(data).unwrap();

        self.0.send_done();

        Ok(())
    }
}

struct NetworkSendImpl<'a, const N: usize>(Sender<'a, NoopRawMutex, heapless::Vec<u8, N>>);

impl<const N: usize> NetworkReceive for NetworkReceiveImpl<'_, N> {
    async fn wait_available(&mut self) -> Result<(), Error> {
        self.0.receive().await;

        Ok(())
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        let vec = self.0.receive().await;

        buffer[..vec.len()].copy_from_slice(vec);
        let len = vec.len();

        self.0.receive_done();

        Ok((len, E2eRunner::ADDR))
    }
}
