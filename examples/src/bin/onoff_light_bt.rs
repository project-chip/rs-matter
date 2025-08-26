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

use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::{select, select4};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Duration, Timer};
use log::{info, warn};

use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::{NetCtl, NetCtlStatus, NetworkType, Networks};
use rs_matter::dm::clusters::on_off::{self, ClusterHandler as _};
use rs_matter::dm::clusters::wifi_diag::WifiDiag;
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::networks::wireless::{NetCtlState, NetCtlWithStatusImpl, WifiNetworks};
use rs_matter::dm::subscriptions::DefaultSubscriptions;
use rs_matter::dm::{
    Async, AsyncHandler, AsyncMetadata, Dataver, EmptyHandler, Endpoint, EpClMatcher, Node,
};
use rs_matter::error::Error;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::Psm;
use rs_matter::respond::DefaultResponder;
use rs_matter::transport::network::btp::bluez::BluezGattPeripheral;
use rs_matter::transport::network::btp::{Btp, BtpContext};
use rs_matter::transport::network::wifi::nm::NetMgrCtl;
use rs_matter::transport::network::wifi::wpa_supp::unix::DhClientCtl;
use rs_matter::transport::network::wifi::wpa_supp::WpaSuppCtl;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::utils::sync::blocking::raw::StdRawMutex;
use rs_matter::utils::zbus::Connection;
use rs_matter::{clusters, devices, Matter, MATTER_PORT};

#[path = "../common/mdns.rs"]
mod mdns;

/// Needs to be `'static`, for now
static BTP_CONTEXT: BtpContext<StdRawMutex> = BtpContext::<StdRawMutex>::new();

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug"),
    );

    let args = std::env::args().into_iter().skip(1).collect::<Vec<_>>();
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

    // Create the Matter object
    let matter = Matter::new_default(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Need to call this once
    matter.initialize_transport_buffers()?;

    // Create the transport buffers
    let buffers = PooledBuffers::<10, NoopRawMutex, _>::new(0);

    // Create the subscriptions
    let subscriptions = DefaultSubscriptions::new();

    // Our on-off cluster
    let on_off = on_off::OnOffHandler::new(Dataver::new_rand(matter.rand()));

    // A storage for the Wifi networks
    let networks = WifiNetworks::<3, NoopRawMutex>::new();

    let connection = futures_lite::future::block_on(Connection::system()).unwrap();

    // The network controller based on `wpa_supplicant` and `dhclient`.
    let net_ctl_state = NetCtlState::new_with_mutex::<NoopRawMutex>();

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(async {
        if use_wpa_supp {
            let wpa_supp = NetCtlWithStatusImpl::new(
                &net_ctl_state,
                WpaSuppCtl::new(&connection, &if_name, DhClientCtl::new(&if_name, true)),
            );

            let dm_handler = dm_handler(&matter, &on_off, &wpa_supp, &networks);
            let responder = DefaultResponder::new(&matter, &buffers, &subscriptions, &dm_handler);

            select(responder.run::<4, 4>(), dm_handler.run()).await
        } else {
            let nm =
                NetCtlWithStatusImpl::new(&net_ctl_state, NetMgrCtl::new(&connection, &if_name));

            let dm_handler = dm_handler(&matter, &on_off, &nm, &networks);
            let responder = DefaultResponder::new(&matter, &buffers, &subscriptions, &dm_handler);

            select(responder.run::<4, 4>(), dm_handler.run()).await
        }
    });

    // This is a sample code that simulates state changes triggered by the HAL
    // Changes will be properly communicated to the Matter controllers and other Matter apps (i.e. Google Home, Alexa), thanks to subscriptions
    let mut device = pin!(async {
        loop {
            Timer::after(Duration::from_secs(5)).await;

            on_off.set(!on_off.get());
            subscriptions.notify_changed();

            info!("Lamp toggled");
        }
    });

    // Create, load and run the persister
    let mut psm: Psm<4096> = Psm::new();
    let path = std::env::temp_dir().join("rs-matter");

    psm.load(&path, &matter, Some(&networks))?;

    let mut persist = pin!(psm.run(&path, &matter, Some(&networks)));

    // Create and run the mDNS responder
    let mut mdns = pin!(mdns::run_mdns(&matter));

    if !matter.is_commissioned() {
        // Not commissioned yet, start commissioning first

        // The BTP transport impl
        let btp = Btp::new(BluezGattPeripheral::new(None, &connection), &BTP_CONTEXT);
        let mut bluetooth = pin!(btp.run("MT", &TEST_DEV_DET, TEST_DEV_COMM.discriminator));

        let mut transport = pin!(matter.run(&btp, &btp, DiscoveryCapabilities::BLE));
        let mut wifi_prov_task = pin!(async {
            NetCtlState::wait_prov_ready(&net_ctl_state, &btp).await;
            Ok(())
        });

        // Combine all async tasks in a single one
        let all = select4(
            &mut transport,
            &mut bluetooth,
            select(&mut wifi_prov_task, &mut persist).coalesce(),
            select(&mut respond, &mut device).coalesce(),
        );

        // Run with a simple `block_on`. Any local executor would do.
        futures_lite::future::block_on(all.coalesce())?;

        matter.reset_transport()?;
    }

    // Create the Matter UDP socket
    let udp = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter transport
    let mut transport = pin!(matter.run_transport(&udp, &udp));

    // Combine all async tasks in a single one
    let all = select4(
        &mut transport,
        &mut mdns,
        &mut persist,
        select(&mut respond, &mut device).coalesce(),
    );

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all.coalesce())
}

/// The Node meta-data describing our Matter device.
const NODE: Node<'static> = Node {
    id: 0,
    endpoints: &[
        endpoints::root_endpoint(NetworkType::Wifi),
        Endpoint {
            id: 1,
            device_types: devices!(DEV_TYPE_ON_OFF_LIGHT),
            clusters: clusters!(desc::DescHandler::CLUSTER, on_off::OnOffHandler::CLUSTER),
        },
    ],
};

/// The Data Model handler + meta-data for our Matter device.
/// The handler is the root endpoint 0 handler plus the on-off handler and its descriptor.
fn dm_handler<'a, N>(
    matter: &'a Matter<'a>,
    on_off: &'a on_off::OnOffHandler,
    net_ctl: &'a N,
    networks: &'a dyn Networks,
) -> impl AsyncMetadata + AsyncHandler + 'a
where
    N: NetCtl + NetCtlStatus + WifiDiag,
{
    (
        NODE,
        endpoints::with_wifi(
            &(),
            &UnixNetifs,
            net_ctl,
            networks,
            matter.rand(),
            endpoints::with_sys(
                &true,
                matter.rand(),
                EmptyHandler
                    .chain(
                        EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                        Async(desc::DescHandler::new(Dataver::new_rand(matter.rand())).adapt()),
                    )
                    .chain(
                        EpClMatcher::new(Some(1), Some(on_off::OnOffHandler::CLUSTER.id)),
                        Async(on_off::HandlerAdaptor(on_off)),
                    ),
            ),
        ),
    )
}
