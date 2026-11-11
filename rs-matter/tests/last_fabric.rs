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

//! What a node does once its last fabric is removed. The commissioning policy
//! of the node decides whether the stored networks are removed too, and whether
//! a basic commissioning window is opened again.

use core::num::NonZeroU8;

use rand_core::Rng;

use rs_matter::crypto::{test_only_crypto, Crypto};
use rs_matter::dm::clusters::gen_comm::{self, CommPolicy, GenCommHandler};
use rs_matter::dm::clusters::net_comm::{
    self, NetCommHandler, NetworkType, Networks, WirelessCreds,
};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ROOT_NODE;
use rs_matter::dm::networks::wireless::{NoopWirelessNetCtl, WifiNetworks};
use rs_matter::dm::{
    Async, AsyncHandler, ChainedHandler, DataModel, Dataver, EmptyHandler, Endpoint,
    HandlerContext, LifecycleOp, Node,
};
use rs_matter::error::Error;
use rs_matter::im::{InteractionModel, InteractionModelState};
use rs_matter::persist::{KvBlobStoreAccess, NETWORKS_KEY};
use rs_matter::transport::exchange::MatterBuffers;
use rs_matter::{Matter, MATTER_PORT};

use crate::common::{init_env_logger, MemKvBlobStore};

mod common;

const NODE: Node<'static> = Node {
    endpoints: &[Endpoint::new(
        0,
        &[DEV_TYPE_ROOT_NODE],
        &[gen_comm::FULL_CLUSTER, net_comm::cluster(NetworkType::Wifi)],
    )],
};

#[test]
fn last_fabric_removes_the_networks_by_default() -> Result<(), Error> {
    init_env_logger();

    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);
    let kv = matter.kv(MemKvBlobStore::default());

    let mut wifi = commissioned(&matter, &kv, &false)?;

    let first = add_fabric(&matter);
    let second = add_fabric(&matter);

    // Another fabric is left, so the networks stay
    remove_fabric(&matter, &kv, &false, &mut wifi, first)?;

    assert_eq!(network_ids(&wifi)?, [b"Home".to_vec()]);

    // The last fabric takes them along, from storage too
    remove_fabric(&matter, &kv, &false, &mut wifi, second)?;

    assert!(network_ids(&wifi)?.is_empty());
    assert!(network_ids(&load(&matter, &kv, &false)?)?.is_empty());

    // No commissioning window, unless the policy asks for one
    assert!(!matter.comm_window_state().is_open());

    Ok(())
}

#[test]
fn last_fabric_follows_the_policy() -> Result<(), Error> {
    init_env_logger();

    let policy = Policy {
        remove_networks: false,
        open_comm_window: true,
    };

    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);
    let kv = matter.kv(MemKvBlobStore::default());

    let mut wifi = commissioned(&matter, &kv, &policy)?;

    let fabric = add_fabric(&matter);

    remove_fabric(&matter, &kv, &policy, &mut wifi, fabric)?;

    assert_eq!(network_ids(&wifi)?, [b"Home".to_vec()]);

    // The window is the device's own, so it is advertised on every transport
    assert!(matter.comm_window_state().is_open_on_all_transports());

    // A window that is open already is not an error
    let fabric = add_fabric(&matter);

    remove_fabric(&matter, &kv, &policy, &mut wifi, fabric)?;

    assert!(matter.comm_window_state().is_open_on_all_transports());

    Ok(())
}

/// A policy with configurable reactions to the removal of the last fabric.
struct Policy {
    remove_networks: bool,
    open_comm_window: bool,
}

impl CommPolicy for Policy {
    fn concurrent_connection_supported(&self) -> bool {
        false.concurrent_connection_supported()
    }

    fn failsafe_expiry_len_secs(&self) -> u16 {
        false.failsafe_expiry_len_secs()
    }

    fn failsafe_max_cml_secs(&self) -> u16 {
        false.failsafe_max_cml_secs()
    }

    fn location_cap(&self) -> gen_comm::RegulatoryLocationTypeEnum {
        false.location_cap()
    }

    fn remove_networks_on_last_fabric(&self) -> bool {
        self.remove_networks
    }

    fn open_comm_window_on_last_fabric(&self) -> bool {
        self.open_comm_window
    }
}

/// Store a committed Wi-Fi network, as commissioning does, and load it like a (re)boot would.
fn commissioned(
    matter: &Matter<'_>,
    kv: impl KvBlobStoreAccess,
    policy: &dyn CommPolicy,
) -> Result<WifiNetworks<2>, Error> {
    let mut wifi = WifiNetworks::<2>::new();

    Networks::add_or_update(
        &mut wifi,
        &WirelessCreds::Wifi {
            ssid: b"Home",
            pass: b"pass",
        },
    )
    .map_err(|_| rs_matter::error::ErrorCode::InvalidData)?;

    wifi.set_managed(true);

    net_comm::store_networks(&mut wifi, NETWORKS_KEY, &kv)?;

    let wifi = load(matter, kv, policy)?;

    assert_eq!(network_ids(&wifi)?, [b"Home".to_vec()]);

    Ok(wifi)
}

/// Load the networks from storage into a fresh store.
fn load(
    matter: &Matter<'_>,
    kv: impl KvBlobStoreAccess,
    policy: &dyn CommPolicy,
) -> Result<WifiNetworks<2>, Error> {
    let mut wifi = WifiNetworks::<2>::new();

    lifecycle(matter, kv, policy, &mut wifi, LifecycleOp::Startup)?;

    Ok(wifi)
}

fn add_fabric(matter: &Matter<'_>) -> NonZeroU8 {
    matter.with_state(|state| {
        state
            .fabrics
            .add_with_post_init(|_| Ok(()))
            .unwrap()
            .fab_idx()
    })
}

/// Remove a fabric, as `RemoveFabric` does, and tell the handlers about it.
fn remove_fabric(
    matter: &Matter<'_>,
    kv: impl KvBlobStoreAccess,
    policy: &dyn CommPolicy,
    wifi: &mut WifiNetworks<2>,
    fab_idx: NonZeroU8,
) -> Result<(), Error> {
    matter.with_state(|state| state.fabrics.remove(fab_idx))?;

    lifecycle(
        matter,
        kv,
        policy,
        wifi,
        LifecycleOp::FabricRemoval { fab_idx },
    )
}

/// Broadcast `op` to a data model with the General and the Network Commissioning handlers.
fn lifecycle(
    matter: &Matter<'_>,
    kv: impl KvBlobStoreAccess,
    policy: &dyn CommPolicy,
    wifi: &mut WifiNetworks<2>,
    op: LifecycleOp,
) -> Result<(), Error> {
    let crypto = test_only_crypto();
    let mut rand = crypto.rand()?;
    let buffers: MatterBuffers = MatterBuffers::new();
    let state = InteractionModelState::<3, 0>::new();

    let dm = data_model(matter, policy, &mut rand, wifi);
    let im = InteractionModel::new(matter, &crypto, &buffers, &dm, kv, &state);

    // Bound, so that the temporary handler is dropped before `im` and `dm`
    let result = im.handler().lifecycle(&im, op);

    result
}

fn data_model<'a>(
    matter: &'a Matter<'a>,
    policy: &'a dyn CommPolicy,
    rand: &mut impl Rng,
    wifi: &'a mut WifiNetworks<2>,
) -> impl DataModel + 'a {
    let handler = ChainedHandler::new(
        |e, c| e == 0 && c == net_comm::FULL_CLUSTER.id,
        NetCommHandler::new(
            Dataver::new_rand(rand),
            matter,
            policy,
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
        |e, c| e == 0 && c == gen_comm::FULL_CLUSTER.id,
        Async(GenCommHandler::new(Dataver::new_rand(rand), matter, policy).adapt()),
    );

    (NODE, handler)
}

fn network_ids(networks: &impl Networks) -> Result<Vec<Vec<u8>>, Error> {
    let mut ids = Vec::new();

    networks.networks(&mut |id| {
        ids.push(id.to_vec());

        Ok(())
    })?;

    Ok(ids)
}
