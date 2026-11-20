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

//! A PASE session to a device that answers from another address than the one
//! it was dialled at.
//!
//! A node may have several addresses, and the one it answers from is chosen by
//! its IP stack. Here the device's socket is bound to `0.0.0.0` and dialled at
//! `127.0.0.2`, so its answers come from `127.0.0.1`. The controller must still
//! use the session it established.

#![cfg(all(feature = "std", feature = "async-io", target_os = "linux"))]

use core::future::Future;
use core::pin::pin;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

use rand_core::Rng;

use rs_matter::crypto::{test_only_crypto, Crypto};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{
    self, test::TestOnOffDeviceLogic, OnOffClient, OnOffHooks,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{endpoints, Async, DataModel, Dataver, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::im::subscriptions::DEFAULT_MAX_SUBSCRIPTIONS;
use rs_matter::im::{InteractionModel, InteractionModelState};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::sc::ExchangeInitiator as _;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::{Address, NoNetwork, SocketAddr};
use rs_matter::transport::MatterBuffers;
use rs_matter::utils::futures::{select, select3, Coalesce, Either};
use rs_matter::utils::timers::{Duration, Timer};
use rs_matter::{clusters, devices, root_endpoint, Matter};

use crate::common::{init_env_logger, run_device_controller, run_with_transport, MemKvBlobStore};

#[allow(dead_code)]
mod common;

/// Passcode used by `TEST_DEV_COMM`
const TEST_PASSCODE: u32 = 20202021;

const TIMEOUT_SECS: u64 = 15;

const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(desc::DescHandler::CLUSTER, TestOnOffDeviceLogic::CLUSTER),
        ),
    ],
};

type DeviceDmState = InteractionModelState<DEFAULT_MAX_SUBSCRIPTIONS, 0>;

#[test]
fn test_pase_to_device_answering_from_other_addr() {
    // A device plus a controller in one future need more than the default
    // 2 MiB stack.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            init_env_logger();
            futures_lite::future::block_on(async { run().await.unwrap() });
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn run() -> Result<(), Error> {
    let crypto = test_only_crypto();

    // ---- Device ----

    let device_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
    let mut rand = crypto.rand()?;
    let buffers: MatterBuffers = MatterBuffers::new();
    let state: DeviceDmState = InteractionModelState::new();
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x10,
        TestOnOffDeviceLogic::new(false),
    );
    let store = MemKvBlobStore::default();
    let kv = device_matter.kv(store.clone());
    let dm = InteractionModel::new(
        &device_matter,
        &crypto,
        &buffers,
        data_model(&device_matter, rand, &on_off_handler),
        &kv,
        &state,
    );

    device_matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;

    let responder = DefaultResponder::new(&dm);

    let device_socket =
        async_io::Async::<UdpSocket>::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    let port = device_socket.get_ref().local_addr()?.port();

    let device_fut = async {
        select3(
            device_matter.run(&crypto, &device_socket, &device_socket, NoNetwork),
            responder.run::<4, 4>(),
            dm.run(),
        )
        .coalesce()
        .await
    };

    // ---- Controller ----

    let ctrl_matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
    let ctrl_socket =
        async_io::Async::<UdpSocket>::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;

    let dialled = Address::Udp(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(127, 0, 0, 2),
        port,
    )));

    let ctrl_flow = async {
        let pase_session_id = with_timeout(
            Exchange::establish_pase(&ctrl_matter, &crypto, dialled, TEST_PASSCODE),
            "PASE",
        )
        .await?;

        // The session is used for more than one exchange, as in commissioning.
        for _ in 0..2 {
            let exchange =
                Exchange::initiate_for_session(ctrl_matter.transport(), &crypto, pase_session_id)?;
            let on = with_timeout(exchange.on_off().on_off_read(1), "read over PASE").await?;
            assert!(!on);
        }

        Ok(())
    };

    let ctrl_fut = run_with_transport(
        ctrl_matter.run(&crypto, &ctrl_socket, &ctrl_socket, NoNetwork),
        ctrl_flow,
    );

    run_device_controller(device_fut, ctrl_fut).await
}

fn data_model<'a, OH: OnOffHooks, LH: LevelControlHooks>(
    matter: &'a Matter<'a>,
    mut rand: impl Rng + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
) -> impl DataModel + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&SysNetifs)
            .build(matter, rand)
            .chain(
                |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == TestOnOffDeviceLogic::CLUSTER.id,
                Async(on_off::HandlerAdaptor(on_off)),
            ),
    )
}

async fn with_timeout<T, F>(fut: F, what: &str) -> Result<T, Error>
where
    F: Future<Output = Result<T, Error>>,
{
    let mut fut = pin!(fut);
    let mut timeout = pin!(Timer::after(Duration::from_secs(TIMEOUT_SECS)));

    match select(&mut fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => panic!("{what} timed out after {TIMEOUT_SECS}s"),
    }
}
