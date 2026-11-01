/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

//! An example Matter accessory that implements a Speaker device over Ethernet.
//! Demonstrates how to make use of the `LevelControl` and `OnOff` cluster handlers,
//! and how to run a Matter device over Ethernet with mDNS discovery.

use core::pin::pin;

use rand::Rng;
use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::level_control::{
    self, test::TestLevelControlDeviceLogic, LevelControlHandler, LevelControlHooks,
};
use rs_matter::dm::clusters::app::on_off::{
    self, test::TestOnOffDeviceLogic, OnOffHandler, OnOffHooks,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_SMART_SPEAKER;
use rs_matter::dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{Async, DataModel, Dataver, EmptyHandler, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::persist::DirKvBlobStore;
use rs_matter::{clusters, devices, root_endpoint, Matter};

use rs_matter::stack::eth::EthMatterStack;
use rs_matter::stack::net::std::StdNetStack;
use rs_matter::utils::init::InitMaybeUninit;

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

/// The bump allocator size of the stack, in bytes.
///
/// If it is not enough, the stack panics while it starts. The futures of an
/// unoptimized build are much bigger than those of an optimized one.
const BUMP_SIZE: usize = 32 * 1024;

/// The stack is allocated statically to avoid program stack blowups.
static MATTER_STACK: StaticCell<EthMatterStack<BUMP_SIZE, ()>> = StaticCell::new();

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let stack = MATTER_STACK.uninit().init_with(EthMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));

    // Persistence
    let mut store = DirKvBlobStore::new_default();

    // Create the crypto instance
    let crypto = default_crypto(rand::rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // Re-hydrate the persisted state. If the device is not commissioned yet, this also
    // prints the QR text and code to the console and enables basic commissioning.
    futures_lite::future::block_on(stack.startup(&crypto, &mut store))?;

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = stack.kv(store);

    // OnOff cluster setup
    let on_off_handler = on_off::OnOffHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x10,
        TestOnOffDeviceLogic::new(true),
    );

    // LevelControl cluster setup
    let level_control_handler = LevelControlHandler::new(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x11,
        TestLevelControlDeviceLogic::new(),
    );

    // Cluster wiring, validation and initialisation
    on_off_handler.init(Some(&level_control_handler));
    level_control_handler.init(Some(&on_off_handler));

    // Run the stack, which adds the operational network clusters of endpoint 0 by itself
    let matter = pin!(stack.run_preex(
        // The UDP sockets of the node
        StdNetStack::new(),
        // The network interfaces of the host
        SysNetifs,
        // No Ethernet diagnostics to report
        &(),
        mdns::create_mdns(),
        &crypto,
        data_model(
            stack.matter(),
            rand,
            &on_off_handler,
            &level_control_handler
        ),
        kv,
        // No user task to run
        (),
    ));

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(matter)
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_SMART_SPEAKER),
            clusters!(
                desc::DescHandler::CLUSTER,
                TestOnOffDeviceLogic::CLUSTER,
                TestLevelControlDeviceLogic::CLUSTER
            ),
        ),
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the Speaker handler.
fn data_model<'a, LH: LevelControlHooks, OH: OnOffHooks>(
    matter: &'a Matter<'a>,
    mut rand: impl Rng + Copy,
    on_off: &'a OnOffHandler<'a, OH, LH>,
    level_control: &'a LevelControlHandler<'a, LH, OH>,
) -> impl DataModel + 'a {
    (
        NODE,
        EmptyHandler
            .chain(
                |e, _| e == ROOT_ENDPOINT_ID,
                Async(EthMatterStack::<0, ()>::root_handler(matter, &(), rand)),
            )
            .chain(
                |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == TestLevelControlDeviceLogic::CLUSTER.id,
                Async(level_control::HandlerAdaptor(level_control)),
            )
            .chain(
                |e, c| e == 1 && c == TestOnOffDeviceLogic::CLUSTER.id,
                Async(on_off::HandlerAdaptor(on_off)),
            ),
    )
}
