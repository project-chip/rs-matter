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

//! An example Matter device that implements the On/Off cluster over Ethernet,
//! assembled with `rs_matter::stack` instead of by hand.

use core::pin::pin;

use log::info;

use rand::rngs::StdRng;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::on_off;
use rs_matter::dm::clusters::app::on_off::test::TestOnOffDeviceLogic;
use rs_matter::dm::clusters::app::on_off::OnOffHooks;
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::{Async, Dataver, EmptyHandler, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::persist::{DirKvBlobStore, VENDOR_KEYS_START};
use rs_matter::stack::eth::EthMatterStack;
use rs_matter::stack::net::std::StdNetStack;
use rs_matter::transport::network::mdns::builtin::BuiltinMdns;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::{clusters, devices};

use static_cell::StaticCell;

/// The bump allocator size of the stack, in bytes.
///
/// If it is not enough, the stack panics while it starts. The futures of an
/// unoptimized build are much bigger than those of an optimized one.
const BUMP_SIZE: usize = 32 * 1024;

/// Endpoint 0 runs the Matter system clusters, so the light is on endpoint 1
const LIGHT_ENDPOINT_ID: u16 = 1;

/// The Matter Light device Node
const NODE: Node = Node {
    endpoints: &[
        EthMatterStack::<0, ()>::root_endpoint(),
        Endpoint::new(
            LIGHT_ENDPOINT_ID,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(desc::DescHandler::CLUSTER, TestOnOffDeviceLogic::CLUSTER),
        ),
    ],
};

/// The stack is allocated statically to avoid program stack blowups.
static MATTER_STACK: StaticCell<EthMatterStack<BUMP_SIZE, ()>> = StaticCell::new();

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    info!("Starting...");

    let stack = MATTER_STACK.uninit().init_with(EthMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));

    // `rand::rng()` is not `Send`
    let crypto = default_crypto(rand::make_rng::<StdRng>(), DAC_PRIVKEY);

    let mut rand = crypto.weak_rand()?;

    let on_off = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        LIGHT_ENDPOINT_ID,
        // The KV key under which the cluster persists its state
        VENDOR_KEYS_START + 0x10,
        TestOnOffDeviceLogic::new(false),
    );

    // The stack adds the operational network clusters of endpoint 0 by itself
    let handler = EmptyHandler
        .chain(
            |e, _| e == ROOT_ENDPOINT_ID,
            Async(EthMatterStack::<0, ()>::root_handler(
                stack.matter(),
                &(),
                &mut rand,
            )),
        )
        .chain(
            |e, c| e == LIGHT_ENDPOINT_ID && c == TestOnOffDeviceLogic::CLUSTER.id,
            Async(on_off::HandlerAdaptor(&on_off)),
        )
        .chain(
            |e, c| e == LIGHT_ENDPOINT_ID && c == desc::DescHandler::CLUSTER.id,
            Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
        );

    let mut store = DirKvBlobStore::new_default();
    futures_lite::future::block_on(stack.startup(&crypto, &mut store))?;

    let kv = stack.matter().kv(store);

    let matter = pin!(stack.run_preex(
        StdNetStack::new(),
        UnixNetifs,
        // No Ethernet diagnostics to report
        &(),
        BuiltinMdns::new(),
        &crypto,
        (NODE, handler),
        kv,
        // No user task to run
        (),
    ));

    futures_lite::future::block_on(matter)
}
