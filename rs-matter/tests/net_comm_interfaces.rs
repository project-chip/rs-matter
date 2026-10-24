/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! A node with two network interfaces: Wi-Fi as the primary one, on the root
//! endpoint, and Thread as a secondary one, on endpoint 2. Each Network
//! Commissioning instance owns its networks store and loads, reverts and
//! persists it under its own KV key.

use rand_core::Rng;

use rs_matter::crypto::{test_only_crypto, Crypto};
use rs_matter::dm::clusters::net_comm::{
    self, NetCommHandler, NetworkType, Networks, WirelessCreds,
};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::{DEV_TYPE_ROOT_NODE, DEV_TYPE_SECONDARY_NETWORK_INTERFACE};
use rs_matter::dm::networks::wireless::{NoopWirelessNetCtl, ThreadNetworks, WifiNetworks};
use rs_matter::dm::{
    AsyncHandler, ChainedHandler, DataModel, Dataver, EmptyHandler, Endpoint, HandlerContext,
    LifecycleOp, Node,
};
use rs_matter::error::Error;
use rs_matter::im::InteractionModel;
use rs_matter::im::InteractionModelState;
use rs_matter::persist::{NETWORKS_KEY, VENDOR_KEYS_START};
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::{Matter, MATTER_PORT};

use crate::common::{init_env_logger, MemKvBlobStore};

mod common;

/// The KV key of the networks store of the secondary interface.
const SECONDARY_NETWORKS_KEY: u16 = VENDOR_KEYS_START;

/// A Thread operational dataset with just the Extended PAN ID TLV.
const THREAD_DATASET: &[u8] = &[0x02, 0x08, 1, 2, 3, 4, 5, 6, 7, 8];

const NODE: Node<'static> = Node {
    endpoints: &[
        Endpoint::new(0, &[DEV_TYPE_ROOT_NODE], &[NetworkType::Wifi.cluster()]),
        Endpoint::new(
            2,
            &[DEV_TYPE_SECONDARY_NETWORK_INTERFACE],
            &[NetworkType::Thread.cluster()],
        ),
    ],
};

#[test]
fn network_interfaces_own_their_stores() -> Result<(), Error> {
    init_env_logger();

    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);
    let crypto = test_only_crypto();
    let mut rand = crypto.rand()?;
    let buffers: MatterBuffers = MatterBuffers::new();
    let state = InteractionModelState::<3, 0>::new();
    let kv = matter.kv(MemKvBlobStore::default());

    // What the node committed earlier, each interface under its own key
    let mut wifi = WifiNetworks::<2>::new();
    add_wifi(&mut wifi, b"Home")?;
    wifi.set_managed(true);
    net_comm::store_networks(&mut wifi, NETWORKS_KEY, &kv)?;

    let mut thread = ThreadNetworks::<2>::new();
    Networks::add_or_update(
        &mut thread,
        &WirelessCreds::Thread {
            dataset_tlv: THREAD_DATASET,
        },
    )
    .map_err(|_| rs_matter::error::ErrorCode::InvalidData)?;
    thread.set_managed(true);
    net_comm::store_networks(&mut thread, SECONDARY_NETWORKS_KEY, &kv)?;

    // On (re)boot, each instance loads its own store
    let mut wifi = WifiNetworks::<2>::new();
    let mut thread = ThreadNetworks::<2>::new();

    {
        let dm = data_model(&mut rand, &mut wifi, &mut thread);
        let im = InteractionModel::new(&matter, &crypto, &buffers, &dm, &kv, &state);

        futures_lite::future::block_on(im.startup())?;
    }

    assert_eq!(network_ids(&wifi)?, [b"Home".to_vec()]);
    assert_eq!(network_ids(&thread)?, [THREAD_DATASET[2..].to_vec()]);

    // A Wi-Fi network staged under the fail-safe is dropped by its expiry,
    // while the Thread store keeps what it has
    add_wifi(&mut wifi, b"Guest")?;
    wifi.set_managed(false);

    lifecycle(
        &matter,
        &crypto,
        &buffers,
        &kv,
        &state,
        &mut rand,
        &mut wifi,
        &mut thread,
        LifecycleOp::FailSafeExpiry,
    )?;

    assert_eq!(network_ids(&wifi)?, [b"Home".to_vec()]);
    assert!(wifi.managed());
    assert_eq!(network_ids(&thread)?, [THREAD_DATASET[2..].to_vec()]);

    // ... and persisted by the commit, each interface under its own key
    add_wifi(&mut wifi, b"Guest")?;
    wifi.set_managed(false);

    lifecycle(
        &matter,
        &crypto,
        &buffers,
        &kv,
        &state,
        &mut rand,
        &mut wifi,
        &mut thread,
        LifecycleOp::FailSafeCommit,
    )?;

    let mut committed_wifi = WifiNetworks::<2>::new();
    net_comm::load_networks(&mut committed_wifi, NETWORKS_KEY, &kv)?;
    assert_eq!(
        network_ids(&committed_wifi)?,
        [b"Home".to_vec(), b"Guest".to_vec()]
    );
    assert!(committed_wifi.managed());

    let mut committed_thread = ThreadNetworks::<2>::new();
    net_comm::load_networks(&mut committed_thread, SECONDARY_NETWORKS_KEY, &kv)?;
    assert_eq!(
        network_ids(&committed_thread)?,
        [THREAD_DATASET[2..].to_vec()]
    );

    Ok(())
}

/// The data model of the node: one Network Commissioning instance per interface.
fn data_model<'a>(
    rand: &mut impl Rng,
    wifi: &'a mut WifiNetworks<2>,
    thread: &'a mut ThreadNetworks<2>,
) -> impl DataModel + 'a {
    let handler = ChainedHandler::new(
        |e, c| e == 0 && c == net_comm::FULL_CLUSTER.id,
        NetCommHandler::new(
            Dataver::new_rand(rand),
            0,
            wifi,
            NETWORKS_KEY,
            NoopWirelessNetCtl::new(NetworkType::Wifi),
            &(),
        )
        .adapt(),
        EmptyHandler,
    )
    .chain(
        |e, c| e == 2 && c == net_comm::FULL_CLUSTER.id,
        NetCommHandler::new(
            Dataver::new_rand(rand),
            2,
            thread,
            SECONDARY_NETWORKS_KEY,
            NoopWirelessNetCtl::new(NetworkType::Thread),
            &(),
        )
        .adapt(),
    );

    (NODE, handler)
}

/// Broadcast `op` to the handlers of the data model.
#[allow(clippy::too_many_arguments)]
fn lifecycle(
    matter: &Matter<'_>,
    crypto: impl Crypto,
    buffers: &MatterBuffers,
    kv: impl rs_matter::persist::KvBlobStoreAccess,
    state: &InteractionModelState<3, 0>,
    rand: &mut impl Rng,
    wifi: &mut WifiNetworks<2>,
    thread: &mut ThreadNetworks<2>,
    op: LifecycleOp,
) -> Result<(), Error> {
    let dm = data_model(rand, wifi, thread);
    let im = InteractionModel::new(matter, crypto, buffers, &dm, kv, state);

    let result = im.handler().lifecycle(&im, op);

    result
}

fn add_wifi(networks: &mut WifiNetworks<2>, ssid: &[u8]) -> Result<(), Error> {
    Networks::add_or_update(
        networks,
        &WirelessCreds::Wifi {
            ssid,
            pass: b"pass",
        },
    )
    .map_err(|_| rs_matter::error::ErrorCode::InvalidData)?;

    Ok(())
}

fn network_ids(networks: &impl Networks) -> Result<Vec<Vec<u8>>, Error> {
    let mut ids = Vec::new();

    networks.networks(&mut |id| {
        ids.push(id.to_vec());

        Ok(())
    })?;

    Ok(ids)
}
