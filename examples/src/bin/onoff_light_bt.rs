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

//! An example Matter device that implements the On/Off Light cluster over Wifi with commissioning over Bluetooth (Linux only).
//!
//! The example uses the BlueZ BLE stack and either the `NetworkManager` or directly the `wpa_supplicant` daemon
//! to connect to BT and to manage Wifi networks.
//! Therefore, it is likely to run only on Linux-based systems (e.g., Ubuntu, Debian, etc.), because BlueZ is Linux-specific.
//!
//! Do note that running the app with the `wpa_supplicant` daemon, some Linux systems might require the user running the app to have
//! elevated permissions, so run with `sudo`!
//! E.g. `sudo ./onoff_light_bt <your-wlan-interface-name>`
//!
//! Utilizing `wpa_supplicant` and `dhclient` to manage Wifi networks is useful primarily in embedded Linux scenarios,
//! where - moreover - the Linux stack does not have NetworkManager installed. For regular Linux systems, or for embedded
//! Linux systems having NetworkManager, using the NetworkManager code-path is recommended, as it is much
//! more straightfoward to run it, in that it does not need elevated permissions, nor the presence of the `dhclient` and `ip` commands.
#![recursion_limit = "256"]

use core::pin::pin;

use log::{info, warn};

use rand::Rng;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::NetCtl;
use rs_matter::dm::clusters::wifi_diag::WifiDiag;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::networks::wifi::nm::NetMgrCtl;
use rs_matter::dm::networks::wifi::wpa_supp::unix::DhClientCtl;
use rs_matter::dm::networks::wifi::wpa_supp::WpaSuppCtl;
use rs_matter::dm::networks::NetChangeNotif;
use rs_matter::dm::{Async, DataModel, Dataver, EmptyHandler, Endpoint, Node};
use rs_matter::error::Error;
use rs_matter::persist::DirKvBlobStore;
use rs_matter::utils::zbus::Connection;
use rs_matter::{clusters, devices, root_endpoint, Matter};

use rs_matter::stack::ble::BluezGattPeripheral;
use rs_matter::stack::net::std::StdNetStack;
use rs_matter::stack::wireless::{PreexistingWireless, WifiMatterStack};
use rs_matter::utils::init::InitMaybeUninit;

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

/// The bump allocator size of the stack, in bytes.
///
/// If it is not enough, the stack panics while it starts. The futures of an
/// unoptimized build are much bigger than those of an optimized one.
const BUMP_SIZE: usize = 64 * 1024;

/// The stack is allocated statically to avoid program stack blowups.
static MATTER_STACK: StaticCell<WifiMatterStack<BUMP_SIZE, ()>> = StaticCell::new();

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() > 2 {
        eprintln!("Usage: onoff_light_bt [-w] [if_name]");
        eprintln!(
            "  -w      - use wpa_supplicant to manage Wifi networks (default is NetworkManager)"
        );
        eprintln!("  if_name - the name of the Wifi interface to use, e.g. 'wlan0', 'wlx80afca061a16', etc.");
        eprintln!("            If not set, defaults to 'wlan0'.");

        return Ok(());
    }

    let use_wpa_supp = args.iter().any(|arg| arg == "-w");
    if use_wpa_supp {
        warn!("Using wpa_supplicant to manage Wifi networks, make sure you run with `sudo`!");
    } else {
        info!("Using NetworkManager to manage Wifi networks");
    }

    let if_name = args.into_iter().find(|arg| arg != "-w").unwrap_or_else(|| {
        warn!("Ran without iface arg, using 'wlan0' as the Wifi interface name");
        "wlan0".into()
    });

    let connection = futures_lite::future::block_on(Connection::system()).unwrap();

    if use_wpa_supp {
        run(
            &connection,
            WpaSuppCtl::new(&connection, &if_name, DhClientCtl::new(&if_name, true)),
        )
    } else {
        run(&connection, NetMgrCtl::new(&connection, &if_name))
    }
}

fn run<N: NetCtl + WifiDiag + NetChangeNotif>(
    connection: &Connection,
    net_ctl: N,
) -> Result<(), Error> {
    let stack = MATTER_STACK.uninit().init_with(WifiMatterStack::init(
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

    // Our on-off cluster
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        rs_matter::persist::VENDOR_KEYS_START + 0x10,
        TestOnOffDeviceLogic::new(true),
    );

    // Run the stack in its non-concurrent commissioning mode: BLE while the commissioning
    // window is open, and Wifi once the commissioner has provisioned the network. The stack
    // adds the operational network clusters of endpoint 0 by itself.
    let matter = pin!(stack.run(
        PreexistingWireless::new(
            // The UDP sockets of the node
            StdNetStack::new(),
            // The network interfaces of the host
            UnixNetifs,
            net_ctl,
            mdns::create_mdns(),
            // Here's how to run with the BlueR peripheral instead:
            // `rs_matter::stack::ble::BluerGattPeripheral::new(None)`
            BluezGattPeripheral::new(connection, None),
        ),
        &crypto,
        data_model(stack.matter(), rand, &on_off_handler),
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
        root_endpoint!(wifi),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters!(
                desc::DescHandler::CLUSTER,
                groups::GroupsHandler::CLUSTER,
                on_off::test::TestOnOffDeviceLogic::CLUSTER
            ),
        ),
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off handler and its descriptor.
fn data_model<'a, OH: OnOffHooks, LH: LevelControlHooks>(
    matter: &'a Matter<'a>,
    mut rand: impl Rng + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
) -> impl DataModel + 'a {
    (
        NODE,
        EmptyHandler
            .chain(
                |e, _| e == ROOT_ENDPOINT_ID,
                Async(WifiMatterStack::<0, ()>::root_handler(matter, &(), rand)),
            )
            .chain(
                |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == groups::GroupsHandler::CLUSTER.id,
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand), matter).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == TestOnOffDeviceLogic::CLUSTER.id,
                Async(on_off::HandlerAdaptor(on_off)),
            ),
    )
}
