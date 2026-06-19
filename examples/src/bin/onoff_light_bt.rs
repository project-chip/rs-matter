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

use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::{select, select4};

use log::{info, warn};

use rand::RngCore;

use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::app::level_control::LevelControlHooks;
use rs_matter::dm::clusters::app::on_off::{self, test::TestOnOffDeviceLogic, OnOffHooks};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::groups::{self, ClusterHandler as _};
use rs_matter::dm::clusters::net_comm::{NetCtl, NetCtlStatus};
use rs_matter::dm::clusters::wifi_diag::WifiDiag;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_ON_OFF_LIGHT;
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::unix::UnixNetifs;
use rs_matter::dm::networks::wireless::{NetCtlState, NetCtlWithStatusImpl, WifiNetworks};
use rs_matter::dm::networks::NetChangeNotif;
use rs_matter::dm::{
    Async, DataModelHandler, Dataver, Endpoint, EpClMatcher, InteractionModel, Node,
    WirelessDataModelState,
};
use rs_matter::error::Error;
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{DirKvBlobStore, SharedKvBlobStore};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::MatterBuffers;
#[cfg(target_os = "linux")]
use rs_matter::transport::network::btp::bluez;
use rs_matter::transport::network::btp::{AdvData, Btp};
use rs_matter::transport::network::wifi::nm::NetMgrCtl;
use rs_matter::transport::network::wifi::wpa_supp::unix::DhClientCtl;
use rs_matter::transport::network::wifi::wpa_supp::WpaSuppCtl;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::zbus::Connection;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

#[path = "../common/mdns.rs"]
mod mdns;

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
    // Create the Matter object
    let mut matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Persistence
    let mut kv = DirKvBlobStore::new_default();

    // Create the transport buffers
    let buffers: MatterBuffers = MatterBuffers::new();

    // Create the data model state (subscriptions, events, the Wifi network store).
    // It owns the KV scratch buffer, so the one-time startup loads below reuse it
    // (`state.kv_buf_mut()`) rather than allocating a separate buffer.
    let mut state: WirelessDataModelState<WifiNetworks<3>> =
        WirelessDataModelState::new(WifiNetworks::new());

    // Re-hydrate persisted state: the `Matter` instance (fabrics, ACLs, basic
    // info) and the data model state itself (event-number epoch + Wifi networks).
    futures_lite::future::block_on(matter.load_persist(&mut kv, state.kv_buf_mut()))?;
    futures_lite::future::block_on(state.load_persist(&mut kv))?;

    // Create the crypto instance
    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);

    let mut rand = crypto.rand()?;

    // Our on-off cluster
    let on_off_handler = on_off::OnOffHandler::new_standalone(
        Dataver::new_rand(&mut rand),
        1,
        TestOnOffDeviceLogic::new(true),
    );

    // The network controller
    let net_ctl_state = NetCtlState::new_with_mutex();

    let net_ctl = NetCtlWithStatusImpl::new(&net_ctl_state, net_ctl);

    // Create the Data Model instance. The same `net_ctl` is wired both into the
    // `NetworkCommissioning` handler (above) and into the data model, which drives
    // the operational Wifi connection manager from `InteractionModel::run`.
    let im = InteractionModel::new_with_net_ctl(
        &matter,
        &crypto,
        &buffers,
        dm_handler(rand, &on_off_handler, &net_ctl, &net_ctl),
        SharedKvBlobStore::new(kv),
        &net_ctl,
        &state,
    );

    // Create a default responder capable of handling up to 3 subscriptions
    // All other subscription requests will be turned down with "resource exhausted"
    let responder = DefaultResponder::new(&im);

    // Run the responder with up to 4 handlers (i.e. 4 exchanges can be handled simultaneously)
    // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
    let mut respond = pin!(responder.run::<4, 4>());

    // Run the background job of the data model
    let mut im_job = pin!(im.run());

    // Create and run the mDNS responder
    let mut mdns = pin!(mdns::run_mdns(&matter, &crypto));

    if !matter.is_commissioned() {
        // Not commissioned yet, start commissioning first

        // Print the QR text and code to the console
        // and enable basic commissioning

        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;

        // BLE commissioning via BlueZ is Linux-only.
        #[cfg(not(target_os = "linux"))]
        panic!("BLE commissioning requires Linux (BlueZ)");

        #[cfg(target_os = "linux")]
        {
            // The BTP transport impl

            use rs_matter::transport::network::NoNetwork;
            let btp = Btp::new();
            // BlueZ seems to report an incorrect GATT MTU, so we need to enable the relaxed MTU negotiation mode to be able to connect to BlueZ peripherals with MTU bigger than the minimum one
            btp.set_relaxed_mtu_nego(true);
            let adv_data = AdvData::new(&TEST_DEV_DET, TEST_DEV_COMM.discriminator);
            let mut bluetooth = pin!(bluez::run_peripheral(
                connection, None, "MT", &adv_data, &btp
            ));
            // Here's how to run with the BlueR peripheral instead:
            // let mut bluetooth = pin!(async_compat::Compat::new(rs_matter::transport::network::btp::bluer::run_peripheral(
            //     None, "MT", &adv_data, &btp
            // )));

            let mut transport = pin!(matter.run(&crypto, &btp, &btp, NoNetwork));
            let mut wifi_prov_task = pin!(async {
                NetCtlState::wait_prov_ready(&net_ctl_state, &btp).await;
                Ok(())
            });

            // Combine all async tasks in a single one
            let all = select4(
                &mut transport,
                &mut bluetooth,
                &mut wifi_prov_task,
                select(&mut respond, &mut im_job).coalesce(),
            );

            // Run with a simple `block_on`. Any local executor would do.
            futures_lite::future::block_on(all.coalesce())?;

            matter.reset_transport()?;
        }
    }

    // Create the Matter UDP socket
    let udp = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    // Run the Matter transport
    let mut transport = pin!(matter.run(&crypto, &udp, &udp, &udp));

    // Combine all async tasks in a single one
    let all = select4(&mut transport, &mut mdns, &mut respond, &mut im_job).coalesce();

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(all)
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
fn dm_handler<'a, OH: OnOffHooks, LH: LevelControlHooks, T>(
    mut rand: impl RngCore + Copy,
    on_off: &'a on_off::OnOffHandler<'a, OH, LH>,
    wifi_diag: &'a dyn WifiDiag,
    net_ctl: T,
) -> impl DataModelHandler + 'a
where
    T: NetCtl + NetCtlStatus + 'a,
{
    (
        NODE,
        endpoints::WifiSysHandlerBuilder::new(net_ctl, wifi_diag)
            .netif_diag(&UnixNetifs)
            .build(rand)
            .chain(
                EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(groups::GroupsHandler::CLUSTER.id)),
                Async(groups::GroupsHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
                on_off::HandlerAsyncAdaptor(on_off),
            ),
    )
}
