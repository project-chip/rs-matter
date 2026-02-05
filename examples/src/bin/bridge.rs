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

//! An example Matter Bridge that bridges two fictitious non-Matter devices as On-Off (Lamp) Matter devices.
//! The example operates over Ethernet for simplicity, but the concrete network protocol is orthogonal to
//! the notion of a Matter bridge anyway.

use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::{select, select4};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use rand::RngCore;
use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::level_control::LevelControlHooks;
use rs_matter::dm::clusters::net_comm::NetworkType;
use rs_matter::dm::clusters::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_AGGREGATOR, DEV_TYPE_BRIDGED_NODE, DEV_TYPE_ON_OFF_LIGHT};
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::subscriptions::DefaultSubscriptions;
use rs_matter::dm::{
    Async, AsyncHandler, AsyncMetadata, Cluster, DataModel, Dataver, EmptyHandler, Endpoint,
    EpClMatcher, InvokeContext, Node, ReadContext,
};
use rs_matter::error::Error;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{Psm, NO_NETWORKS};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::tlv::{TLVBuilderParent, Utf8StrBuilder};
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, with, Matter, MATTER_PORT};

pub use rs_matter::dm::clusters::decl::bridged_device_basic_information::{
    self, ClusterHandler as _, KeepActiveRequest,
};

#[path = "../common/mdns.rs"]
mod mdns;

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Create the Matter object
    let matter = Matter::new_default(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Need to call this once
    matter.initialize_transport_buffers()?;

    // Create the transport buffers
    let buffers = PooledBuffers::<10, NoopRawMutex, _>::new(0);

    // Create the subscriptions
    let subscriptions = DefaultSubscriptions::new();

    // Create the crypto instance
    let crypto = default_crypto::<NoopRawMutex, _>(rand::thread_rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // Our on-off clusters
    let on_off_handler_ep2 = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        2,
        TestOnOffDeviceLogic::new(false),
    );
    let on_off_handler_ep3 = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        3,
        TestOnOffDeviceLogic::new(false),
    );

    // Create the Data Model instance
    let dm = DataModel::new(
        &matter,
        &crypto,
        &buffers,
        &subscriptions,
        dm_handler(rand, &on_off_handler_ep2, &on_off_handler_ep3),
    );

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&dm);

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(responder.run::<4, 4>());

    // Run the background job of the data model
    let mut dm_job = pin!(dm.run());

    // Create the Matter UDP socket
    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter and mDNS transports
    let mut mdns = pin!(mdns::run_mdns(&matter, &crypto, &dm));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket));

    // Create, load and run the persister
    let mut psm: Psm<4096> = Psm::new();
    let path = std::env::temp_dir().join("rs-matter");

    psm.load(&path, &matter, NO_NETWORKS)?;

    if !matter.is_commissioned() {
        // If the device is not commissioned yet, print the QR text and code to the console
        // and enable basic commissioning

        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &dm)?;
    }

    let mut persist = pin!(psm.run(&path, &matter, NO_NETWORKS));

    // Combine all async tasks in a single one
    let all = select4(
        &mut transport,
        &mut mdns,
        &mut persist,
        select(&mut respond, &mut dm_job).coalesce(),
    );

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all.coalesce())
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        // The root (0) endpoint - as usual.
        endpoints::root_endpoint(NetworkType::Ethernet),
        // When the node contains one or more bridged endpoints, we need
        // at least one endpoint that would serve as the aggregator endpoint and will thus
        // enumerate all bridged endpoints which are bridged e.g. using the same technology.
        //
        // Optionally, the aggregator can declare and implement the `Actions` cluster
        // (see below in the handler the meaning of this cluster).
        // In any case, this endpoint must be of the Aggregator device type.
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_AGGREGATOR),
            clusters: clusters!(desc::DescHandler::CLUSTER),
        },
        // This is the first bridged device. It could have any ID as long as it is not 0 or 1.
        //
        // The Matter Bridge needs to declare as many endpoints as there are bridged devices.
        // If the bridged devices can vary over time, rather than using a static `Node`
        // definition, one could use an `(Async)MetaData` implementation that returns a node
        // which references the endpoints off from a `Vec` or a `heapless::Vec`.
        Endpoint {
            id: 2,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_BRIDGED_NODE),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                BridgedHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER
            ),
        },
        // This is the second bridged device.
        //
        // It could have a completely different device type, yet here - for simplicity - we
        // just declare another lamp.
        Endpoint {
            id: 3,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_BRIDGED_NODE),
            clusters: clusters!(
                desc::DescHandler::CLUSTER,
                BridgedHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER
            ),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter Bridge.
fn dm_handler<'a, OH: OnOffHooks, LH: LevelControlHooks>(
    mut rand: impl RngCore + Copy,
    on_off_ep2: &'a on_off::OnOffHandler<'a, OH, LH>,
    on_off_ep3: &'a on_off::OnOffHandler<'a, OH, LH>,
) -> impl AsyncMetadata + AsyncHandler + 'a {
    (
        NODE,
        endpoints::with_eth(
            &(),
            &UnixNetifs,
            rand,
            endpoints::with_sys(
                &false,
                rand,
                EmptyHandler
                    // The next chain is the handler for the "aggregator" endpoint 1.
                    //
                    // Note how the descriptor cluster is a bit different compared to the normal ones.
                    // The `Aggregator` descriptor cluster takes care of declaring all bridged endpoints
                    // as such.
                    //
                    // Implementing the "Actions" cluster (and declaring it in the ep1 meta-data)
                    // would allow one to designate locations/areas to the bridged devices. However, this is
                    // not yet supported by Google home and Apple, as per
                    // https://www.1home.io/docs/en/server/configure-devices#manage-rooms
                    .chain(
                        EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                        Async(
                            desc::DescHandler::new_aggregator(Dataver::new_rand(&mut rand)).adapt(),
                        ),
                    )
                    // The following chains are the handlers for the bridged devices corresponding to ep 2 and ep3.
                    //
                    // In addition to the usual clusters, every bridged endpoint needs to implement the
                    // "Bridged" cluster as well.
                    //
                    // Note also that we are re-using here the ready-made `OnOffHandler` from `rs-matter` for demoing purposes.
                    // In production setups, user is expected to define their own handler for their bridge device cluster(s)
                    // which is likely to do remote calls over a proprietary protocol so as to e.g. retrieve the state of
                    // the lamp, or to switch it on/off.
                    .chain(
                        EpClMatcher::new(Some(2), Some(desc::DescHandler::CLUSTER.id)),
                        Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                    )
                    .chain(
                        EpClMatcher::new(Some(2), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                        on_off::HandlerAsyncAdaptor(on_off_ep2),
                    )
                    .chain(
                        EpClMatcher::new(Some(2), Some(BridgedHandler::CLUSTER.id)),
                        Async(BridgedHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                    )
                    .chain(
                        EpClMatcher::new(Some(3), Some(desc::DescHandler::CLUSTER.id)),
                        Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                    )
                    .chain(
                        EpClMatcher::new(Some(3), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                        on_off::HandlerAsyncAdaptor(on_off_ep3),
                    )
                    .chain(
                        EpClMatcher::new(Some(3), Some(BridgedHandler::CLUSTER.id)),
                        Async(BridgedHandler::new(Dataver::new_rand(&mut rand)).adapt()),
                    ),
            ),
        ),
    )
}

#[derive(Clone, Debug)]
pub struct BridgedHandler {
    dataver: Dataver,
}

impl BridgedHandler {
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    pub const fn adapt(self) -> bridged_device_basic_information::HandlerAdaptor<Self> {
        bridged_device_basic_information::HandlerAdaptor(self)
    }
}

impl bridged_device_basic_information::ClusterHandler for BridgedHandler {
    const CLUSTER: Cluster<'static> = bridged_device_basic_information::FULL_CLUSTER
        .with_features(0)
        .with_attrs(with!(required))
        .with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn reachable(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        // This is the only mandatory attribute.
        //
        // We always report that the bridged device is reachable,
        // however - in production setup - the user might want to implement
        // true reachability logic here.
        Ok(true)
    }

    fn unique_id<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        _builder: Utf8StrBuilder<P>,
    ) -> Result<P, Error> {
        todo!()
    }

    fn handle_keep_active(
        &self,
        _ctx: impl InvokeContext,
        _request: KeepActiveRequest<'_>,
    ) -> Result<(), Error> {
        todo!()
    }

    // Note that at least the `node_label` optional attribute is also good to implement,
    // so that way users can name the bridged devices their own way, using the Matter controller.
}
