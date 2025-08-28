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

//! A `GattPeripheral` implementation using the BlueZ GATT stack over dBus.

use core::iter::once;
use core::marker::PhantomData;
use core::pin::pin;

use alloc::sync::Arc;

use std::collections::HashMap;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;

use async_io::Async;

use embassy_futures::select::{select, select_slice, Either};

use uuid::Uuid;

use zbus::fdo::{ObjectManager, ObjectManagerProxy};
use zbus::object_server::Interface;
use zbus::zvariant::{ObjectPath, OwnedFd, OwnedObjectPath, OwnedValue, Value};
use zbus::{interface, Connection};

use crate::error::{Error, ErrorCode};
use crate::transport::network::{btp::context::MAX_BTP_SESSIONS, BtAddr};
use crate::utils::storage;
use crate::utils::sync::blocking::raw::StdRawMutex;
use crate::utils::sync::{IfMutex, IfMutexGuard, Notification};
use crate::utils::zbus_proxies::bluez::adapter::AdapterProxy;
use crate::utils::zbus_proxies::bluez::gatt_manager::GattManagerProxy;
use crate::utils::zbus_proxies::bluez::le_advertising_manager::LEAdvertisingManagerProxy;

use super::{
    AdvData, GattPeripheral, GattPeripheralEvent, C1_CHARACTERISTIC_UUID, C2_CHARACTERISTIC_UUID,
    MATTER_BLE_SERVICE_UUID,
};

const MAX_CONNECTIONS: usize = MAX_BTP_SESSIONS;

const BLUEZ_MATTER_BLE_SERVICE_UUID: Uuid = Uuid::from_u128(MATTER_BLE_SERVICE_UUID);
const BLUEZ_MATTER_C1_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(C1_CHARACTERISTIC_UUID);
const BLUEZ_MATTER_C2_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(C2_CHARACTERISTIC_UUID);
const BLUEZ_PATH_PREFIX: &str = "/org/projectchip/rs_matter/bluez";

/// Implements the `GattPeripheral` trait using the BlueZ GATT stack.
pub struct BluezGattPeripheral<'a> {
    adapter_name: Option<&'a str>,
    connection: &'a Connection,
    ind_peers: Arc<IndPeers>,
}

impl<'a> BluezGattPeripheral<'a> {
    /// Create a new instance.
    ///
    /// Arguments:
    /// - `adapter_name`: The name of the Bluetooth adapter to use, or `None` to use the first available adapter.
    /// - `connection`: The dBus connection to use for the GATT service.
    pub fn new(adapter_name: Option<&'a str>, connection: &'a Connection) -> Self {
        Self {
            adapter_name,
            connection,
            ind_peers: Arc::new(IndPeers::new()),
        }
    }

    /// Runs the GATT peripheral service.
    /// What this means in details:
    /// - Advertises the service with the provided name and advertising data, where the advertising data
    ///   contains the elements specified in the Matter Core spec.
    /// - Serves a GATT peripheral service with the `C1` and `C2` characteristics, as specified
    ///   in the Matter Core spec.
    /// - Calls the provided callback with the events that occur during the service lifetime, on the `C1`
    ///   and `C2` characteristics.
    pub async fn run<F>(
        &self,
        service_adv_name: &str,
        service_adv_data: &AdvData,
        callback: F,
    ) -> Result<(), Error>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + 'static,
    {
        let adapter_path = self.adapter_path().await?;

        let adapter = AdapterProxy::new(self.connection, adapter_path.as_ref()).await?;
        adapter.set_powered(true).await?;

        info!(
            "Serving Matter GATT BTP service on Bluetooth adapter {}",
            adapter_path
        );

        // Register a "NoInputNoOutput" agent that will accept all incoming requests.
        // TODO
        // let _handle = bluez.register_agent(Agent::default()).await?;

        self.ind_peers.reset().await;

        let mut app = AppReg::new(
            self.connection,
            service_adv_name,
            service_adv_data,
            adapter_path.as_ref(),
            self.ind_peers.clone(),
            callback,
        )
        .await?;

        info!(
            "Registered Matter GATT BTP service on Bluetooth adapter {}",
            adapter_path,
        );

        app.start_adv().await?;

        info!(
            "Advertising Matter GATT BTP service on Bluetooth adapter {}",
            adapter_path,
        );

        let callback = app.callback.clone();

        self.ind_peers.monitor(move |event| callback(event)).await
    }

    /// Indicate new data on characteristic `C2` to a remote peer.
    pub async fn indicate(&self, data: &[u8], addr: BtAddr) -> Result<(), Error> {
        self.ind_peers.indicate(data, addr).await
    }

    /// Get the path to the Bluetooth adapter designated by `adapter_name`,
    /// or the first available adapter if `adapter_name` is `None`.
    async fn adapter_path(&self) -> Result<OwnedObjectPath, Error> {
        let om = ObjectManagerProxy::new(self.connection, "org.bluez", "/").await?;

        let objects = om.get_managed_objects().await?;

        let adapter_path = objects
            .into_iter()
            .find(|(path, interfaces)| {
                if interfaces.contains_key("org.bluez.GattManager1")
                    && interfaces.contains_key("org.bluez.Adapter1")
                    && interfaces.contains_key("org.bluez.LEAdvertisingManager1")
                {
                    self.adapter_name
                        .map(|adapter_name| {
                            path.as_str().split('/').next_back() == Some(adapter_name)
                        })
                        .unwrap_or(true)
                } else {
                    false
                }
            })
            .map(|(path, _)| path);

        adapter_path.ok_or_else(|| ErrorCode::NoNetworkInterface.into())
    }
}

impl GattPeripheral for BluezGattPeripheral<'_> {
    async fn run<F>(&self, service_name: &str, adv_data: &AdvData, callback: F) -> Result<(), Error>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + 'static,
    {
        BluezGattPeripheral::run(self, service_name, adv_data, callback).await
    }

    async fn indicate(&self, data: &[u8], address: BtAddr) -> Result<(), Error> {
        BluezGattPeripheral::indicate(self, data, address).await
    }
}

/// A helper type facilitating the sending of indications to all peers subscribed to characteristic C2.
///
/// Sending indications is a bit involved because in order to indicate data to a single, _concrete_ peer
/// (that is, assuming that there _will_ be more than 1 connected peers at a time, which is actually the exception rather than the rule),
/// is relatively involved because we have to use the `AcquireNotify` method of BlueZ's `GattCharacteristic1` interface,
/// and this implies creating a duplex Unix domain socket connection with the peer.
struct IndPeers {
    /// The state of the of the type, which contains the list of subscribed peers
    state: IfMutex<StdRawMutex, IndPeersState>,
    /// Notification to stop monitoring the read (confirmation) half of the peer subscriptions
    stop_monitoring_notif: Notification<StdRawMutex>,
}

impl IndPeers {
    /// Create a new instance.
    fn new() -> Self {
        Self {
            state: IfMutex::new(IndPeersState {
                peers: storage::Vec::new(),
                monitoring: true,
            }),
            stop_monitoring_notif: Notification::new(),
        }
    }

    /// Reset the state of the `IndPeers` type, effectively removing all subscribed peers
    async fn reset(&self) {
        let mut state = self.state.lock().await;

        state.peers.clear();
        state.monitoring = true;
    }

    /// Indicate new data to a peer
    ///
    /// Arguments:
    /// - `data`: The data to indicate to the peer.
    /// - `peer_addr`: The address of the peer to indicate the data to.
    async fn indicate(&self, data: &[u8], peer_addr: BtAddr) -> Result<(), Error> {
        let state = self.lock(false).await;

        let endpoint = state
            .peers
            .iter()
            .find(|endpoint| endpoint.addr == peer_addr);

        if let Some(endpoint) = endpoint {
            assert_eq!(endpoint.socket.send(data).await?, data.len());

            trace!("Sent indication to peer {}: {:?}", peer_addr, data);

            // NOTE: This code would only work for BlueZ >= 5.80
            // See https://github.com/project-chip/connectedhomeip/pull/40147
            //
            // Also note that when/if enabling this code, we should also
            // reconsider how we handle the `monitor_close` method, as it currently
            // assumes that the socket becoming readable means it is being closed
            // (i.e. the peer is unsubscribing from the C2 characteristic).
            //
            // Interestingly, latest-released `bluer`does not do this either,
            // so I wonder if it is in sync with latezt BlueZ releases?

            // // let mut confirmation = [0];
            // // endpoint.socket.recv_from(&mut confirmation).await?;

            // // trace!(
            // //     "Received confirmation from peer {}: {:?}",
            // //     peer_addr, confirmation
            // // );

            // if confirmation[0] != 1 {
            //     return Err(Error::new(ErrorCode::Invalid));
            // }
        }

        Ok(())
    }

    /// Add a new peer.
    ///
    /// Arguments:
    /// - `peer_addr`: The address of the peer to add.
    /// - `f`: A callback function that will be called when the peer subscribes to notifications.
    async fn add<F>(&self, peer_addr: BtAddr, f: F) -> zbus::fdo::Result<std::os::fd::OwnedFd>
    where
        F: Fn(GattPeripheralEvent),
    {
        let mut state = self.lock(false).await;

        if state.peers.len() < MAX_CONNECTIONS {
            // Enough space for a new peer.
            // Create a new socket pipe for it, notify that a new peer had subscribed
            // and send to the peer the other end of the socket pipe.

            let (local, remote) = IndPeer::uds_pair().map_err(|e| {
                zbus::fdo::Error::Failed(format!("Failed to create UDS pair: {}", e))
            })?;

            unwrap!(
                state.peers.push(IndPeer {
                    socket: local,
                    addr: peer_addr,
                }),
                "Failed to add new peer, maximum number of connections reached"
            );

            trace!("Added new peer {}", peer_addr);

            f(GattPeripheralEvent::NotifyConnected(peer_addr));
            f(GattPeripheralEvent::NotifySubscribed(peer_addr));

            Ok(remote
                .into_inner()
                .map_err(|e| {
                    zbus::fdo::Error::Failed(format!("Failed to convert UDS to OwnedFd: {}", e))
                })?
                .into())
        } else {
            // No space for another subscription
            Err(zbus::fdo::Error::NoMemory(
                "Maximum number of connections reached".into(),
            ))
        }
    }

    /// Run the monitoring loop, monitoring for peers which did unsubscribe
    /// from the C2 characteristic and deregistering those.
    async fn monitor<F>(&self, f: F) -> !
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + 'static,
    {
        loop {
            let mut state = self.lock(true).await;

            trace!("Monitoring for peer disconnections...");

            Self::monitor_close(&mut state, &self.stop_monitoring_notif, &f).await;
        }
    }

    /// Monitor the peers for disconnections by reading from the peers' sockets.
    ///
    /// This method will block until either a peer's socket becomes readable (indicating a disconnection or an error)
    /// or the `notif` is notified to stop monitoring.
    async fn monitor_close<F>(state: &mut IndPeersState, notif: &Notification<StdRawMutex>, f: F)
    where
        F: Fn(GattPeripheralEvent),
    {
        let result = {
            let read = state
                .peers
                .iter_mut()
                .map(|endpoint| endpoint.socket.readable())
                .collect::<storage::Vec<_, MAX_CONNECTIONS>>();

            let read = pin!(read);
            let read = unsafe { read.map_unchecked_mut(|read| read.as_mut_slice()) };

            select(select_slice(read), notif.wait()).await
        };

        match result {
            Either::First((result, index)) => {
                // A read on one of the peers did resolve with a success or an error
                // Analyze and take actions
                match result {
                    Ok(()) => {
                        trace!(
                            "Peer {} disconnected or an error occurred: {:?}",
                            state.peers[index].addr,
                            result
                        );

                        // Unsubscribe the peer on error or on 0 bytes read = EOF
                        let peer_addr = state.peers[index].addr;

                        state.peers.swap_remove(index);

                        f(GattPeripheralEvent::NotifyUnsubscribed(peer_addr));
                        f(GattPeripheralEvent::NotifyDisconnected(peer_addr));
                    }
                    Err(e) => {
                        // Reading data from the peer in the absence of a pending indication
                        // is not expected, so we log an error and ignore it.

                        error!(
                            "Error reading from peer {}: {:?}",
                            state.peers[index].addr, e
                        );
                    }
                }
            }
            Either::Second(_) => state.monitoring = false,
        }
    }

    async fn lock(&self, for_monitoring: bool) -> IfMutexGuard<'_, StdRawMutex, IndPeersState> {
        if !for_monitoring {
            loop {
                // Stop the monitoring loop temporarily to allow adding a new peer
                // This will release the mutex lock on the state and the `monitoring` flag will be set to false
                self.stop_monitoring_notif.notify();

                let guard = self.state.lock_if(|state| !state.monitoring);

                // Timeout when waiting the lock is necessary because there are two futures competing to get the lock in
                // non-monitoring state:
                // - the `add` method, which is called when a new peer subscribes to the C2 characteristic;
                // - the `indicate` method, which is called when we want to indicate data to a peer.
                let timeout = embassy_time::Timer::after(embassy_time::Duration::from_millis(100));

                if let Either::First(mut guard) = select(guard, timeout).await {
                    // We got the lock, so we can return it
                    guard.monitoring = true; // .. for when the future where this guard will be used completes or is dropped
                    break guard;
                }
            }
        } else {
            let mut guard = self.state.lock_if(|state| state.monitoring).await;
            guard.monitoring = false; // .. for when the future where this guard will be used completes or is dropped

            guard
        }
    }
}

/// The state of the `IndPeers` type
struct IndPeersState {
    /// The list of peers that are subscribed to the C2 characteristic
    peers: storage::Vec<IndPeer, MAX_CONNECTIONS>,
    /// Whether the monitoring loop is currently running
    monitoring: bool,
}

/// A peer that is subscribed to the C2 characteristic.
#[derive(Debug)]
struct IndPeer {
    /// The socket used to communicate with the peer (write an indication payload and read a confirmation 1-byte reply)
    socket: Async<UnixDatagram>,
    /// The address of the peer
    addr: BtAddr,
}

impl IndPeer {
    // Why is this method necessary (copied from `bluer`)?
    // Why not just `let (local, remote) = Async::<UnixDatagram>::pair()`?
    // Because using the Rust STD pair method creates the UDS pair with the `SOCK_DGRAM` type,
    // which is not what we want. We need the `SOCK_SEQPACKET` type, which is what BlueZ apparently requires.
    // (Otherwise we can't monitor the socket with the `readable()` method, which is used to detect peer disconnections.)
    fn uds_pair() -> std::io::Result<(Async<UnixDatagram>, Async<UnixDatagram>)> {
        let mut sv: [RawFd; 2] = [0; 2];

        if unsafe {
            libc::socketpair(
                libc::AF_LOCAL,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error());
        }

        let [fd1, fd2] = sv;

        let local = Async::new(unsafe { UnixDatagram::from_raw_fd(fd1) })?;
        let remote = Async::new(unsafe { UnixDatagram::from_raw_fd(fd2) })?;

        Ok((local, remote))
    }
}

/// A dBus object representing the Matter BLE advertisement.
struct AdObj {
    name: String,
    service_data: Vec<u8>,
}

impl AdObj {
    /// Create a new instance of the `AdObj` type.
    fn new(name: &str, data: &AdvData) -> Self {
        Self {
            name: name.to_string(),
            service_data: data.service_payload_iter().collect(),
        }
    }
}

#[interface(name = "org.bluez.LEAdvertisement1")]
impl AdObj {
    #[zbus(property)]
    pub fn local_name(&self) -> &str {
        &self.name
    }

    #[zbus(property, name = "Type")]
    pub fn adv_type(&self) -> &str {
        "peripheral"
    }

    #[zbus(property)]
    pub fn discoverable(&self) -> bool {
        true
    }

    #[zbus(property, name = "ServiceUUIDs")]
    pub fn service_uuids(&self) -> Vec<String> {
        vec![BLUEZ_MATTER_BLE_SERVICE_UUID.to_string()]
    }

    #[zbus(property)]
    pub fn service_data(&self) -> HashMap<String, OwnedValue> {
        once((
            BLUEZ_MATTER_BLE_SERVICE_UUID.to_string(),
            unwrap!(Value::Array(self.service_data.as_slice().into()).try_to_owned()),
        ))
        .collect()
    }
}

/// A dBus object representing the Matter BLE GATT service.
struct ServiceObj;

impl ServiceObj {
    /// Extract the `mtu` value from the provided dictionary
    fn dict_mtu(dict: &HashMap<&str, Value<'_>>) -> zbus::fdo::Result<u16> {
        let mtu = dict
            .get("mtu")
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("`mtu` not present in dict".into()))?;

        mtu.try_into().map_err(|_| {
            zbus::fdo::Error::InvalidArgs(format!("`mtu` is not a valid u16: {}", mtu))
        })
    }

    /// Extract the peer address value from the provided dictionary
    fn dict_peer_addr(dict: &HashMap<&str, Value<'_>>) -> zbus::fdo::Result<BtAddr> {
        let device = dict
            .get("device")
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("`device` not present in dict".into()))?;

        Self::peer_addr(&device.try_into().map_err(|_| {
            zbus::fdo::Error::InvalidArgs(format!("`device` is not a valid ObjectPath: {}", device))
        })?)
    }

    /// Extract the Bluetooth address from the provided object path of the peer device
    fn peer_addr(path: &ObjectPath<'_>) -> zbus::fdo::Result<BtAddr> {
        let err = || {
            zbus::fdo::Error::InvalidArgs(format!("`device` path is not valid, expected `/<adapter-path>/dev_<bt_addr_hex1>_.._<bt_addr_hex6>`: {}", path))
        };

        // Extract the BT address from the object path, which is expected to be in the format:
        // "/<adapter-path>/dev_<bt_addr>"
        // where <bt_addr> is a sequence of octets in hex separated by a '_'
        let bt_addr_str = path
            .as_str()
            .rsplit('/')
            .next()
            .ok_or_else(err)?
            .strip_prefix("dev_")
            .ok_or_else(err)?;

        let bt_addr = bt_addr_str
            .split('_')
            .map(|s| u8::from_str_radix(s, 16).map_err(|_| err()))
            .collect::<Result<heapless::Vec<_, 6>, _>>()?;

        bt_addr.into_array().map(BtAddr).map_err(|_| err())
    }
}

#[interface(name = "org.bluez.GattService1")]
impl ServiceObj {
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> String {
        BLUEZ_MATTER_BLE_SERVICE_UUID.to_string()
    }

    #[zbus(property)]
    fn primary(&self) -> bool {
        true
    }
}

/// A dBus object representing the Matter BLE GATT characteristics `C1`.
struct C1Obj {
    /// The path to the Matter GATT service that this characteristic belongs to
    service: OwnedObjectPath,
    /// The callback function that will be called with GATT events
    callback: Arc<dyn Fn(GattPeripheralEvent) + Send + Sync>,
}

impl C1Obj {
    /// Create a new instance of the `C1Obj` type.
    fn new(
        service: OwnedObjectPath,
        callback: Arc<dyn Fn(GattPeripheralEvent) + Send + Sync>,
    ) -> Self {
        Self { service, callback }
    }
}

#[interface(name = "org.bluez.GattCharacteristic1")]
impl C1Obj {
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> String {
        BLUEZ_MATTER_C1_CHARACTERISTIC_UUID.to_string()
    }

    #[zbus(property)]
    fn flags(&self) -> Vec<String> {
        vec!["write".to_string()]
    }

    #[zbus(property)]
    fn service(&self) -> OwnedObjectPath {
        self.service.clone()
    }

    fn write_value(
        &self,
        value: &[u8],
        options: HashMap<&str, Value<'_>>,
    ) -> zbus::fdo::Result<()> {
        let peer_addr = ServiceObj::dict_peer_addr(&options)?;

        trace!(
            "Received write request for C1 characteristic from peer {}: {:?}",
            peer_addr,
            value
        );

        (self.callback)(GattPeripheralEvent::Write {
            gatt_mtu: Some(ServiceObj::dict_mtu(&options)?),
            address: peer_addr,
            data: value,
        });

        Ok(())
    }
}

/// A dBus object representing the Matter BLE GATT characteristics `C2`.
struct C2Obj {
    /// The path to the Matter GATT service that this characteristic belongs to
    service: OwnedObjectPath,
    /// The `IndPeers` instance that will be notified when a new peer subscribes to this characteristic
    ind_peers: Arc<IndPeers>,
    /// The callback function that will be called with GATT events
    callback: Arc<dyn Fn(GattPeripheralEvent) + Send + Sync>,
}

impl C2Obj {
    /// Create a new instance of the `C2Obj` type.
    fn new(
        service: OwnedObjectPath,
        indications: Arc<IndPeers>,
        callback: Arc<dyn Fn(GattPeripheralEvent) + Send + Sync>,
    ) -> Self {
        Self {
            service,
            ind_peers: indications,
            callback,
        }
    }
}

#[interface(name = "org.bluez.GattCharacteristic1")]
impl C2Obj {
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> String {
        BLUEZ_MATTER_C2_CHARACTERISTIC_UUID.to_string()
    }

    #[zbus(property)]
    fn flags(&self) -> Vec<String> {
        vec!["indicate".to_string()]
    }

    #[zbus(property)]
    fn service(&self) -> OwnedObjectPath {
        self.service.clone()
    }

    #[zbus(property)]
    fn notify_acquired(&self) -> bool {
        false // Initially not acquired
    }

    async fn acquire_notify(
        &self,
        options: HashMap<&str, Value<'_>>,
    ) -> zbus::fdo::Result<(OwnedFd, u16)> {
        let peer_addr = ServiceObj::dict_peer_addr(&options)?;
        let mtu = ServiceObj::dict_mtu(&options)?;

        trace!(
            "Received acquire_notify request for C2 characteristic from peer {}",
            peer_addr
        );

        let callback = self.callback.clone();

        let fd = self
            .ind_peers
            .add(peer_addr, move |event| callback(event))
            .await?;

        Ok((fd.into(), mtu))
    }
}

/// A type that registers our Matter BTP GATT application in the BlueZ GATT stack.
///
/// The registered application has the (Matter) service and the (Matter C1 & C2) characteristics
/// as described in the BTP protocol section of the Matter Core spec.
struct AppReg<'a> {
    /// The path to the registered GATT application
    /// We keep it around as we need to unregister the app on drop
    app_path: OwnedObjectPath,
    /// The GATT Matter app root
    /// (needs to have `ObjectManager` interface registered on it to be able to register the app in the BlueZ GATT stack)
    app: ObjReg<'a, ObjectManager>,
    /// The GATT manager proxy used to register/unregister the application
    gm: GattManagerProxy<'a>,
    /// The LEAdvertisingManager proxy used to register/unregister the advertisement
    lm: LEAdvertisingManagerProxy<'a>,
    /// The GATT Service object registration in dBus
    service: ObjReg<'a, ServiceObj>,
    /// The GATT C1 characteristic object registration in dBus
    c1: ObjReg<'a, C1Obj>,
    /// The GATT C2 characteristic object registration in dBus
    c2: ObjReg<'a, C2Obj>,
    /// The GATT Advertisement object registration in dBus
    ad: ObjReg<'a, AdObj>,
    /// The callback function that will be called with GATT events
    callback: Arc<dyn Fn(GattPeripheralEvent) + Send + Sync>,
    /// Whether the app registration is deregistered or still active
    closed: bool,
}

impl<'a> AppReg<'a> {
    /// Create a new instance of the `AppReg` type.
    ///
    /// Arguments:
    /// - `conn`: The dBus connection to use for the registration.
    /// - `service_adv_name`: The name of the service to advertise.
    /// - `service_adv_data`: The advertising data to use for the service.
    /// - `adapter`: The path to the Bluetooth adapter to use for the registration.
    /// - `ind_peers`: The `IndPeers` instance to notify for newly-subscribed peers on the C2 characteristic.
    /// - `f`: A callback function that will be called with GATT events.
    async fn new<F>(
        conn: &'a Connection,
        service_adv_name: &str,
        service_adv_data: &AdvData,
        adapter: ObjectPath<'a>,
        ind_peers: Arc<IndPeers>,
        f: F,
    ) -> Result<Self, Error>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + 'static,
    {
        let callback = Arc::new(f);

        let app_id = Uuid::new_v4().simple().to_string();
        let app_path = Self::path_for(&app_id, "app")?;

        let app = ObjReg::new(conn, app_path.clone(), ObjectManager).await?;

        let service =
            ObjReg::new(conn, Self::path_for(&app_id, "app/service")?, ServiceObj).await?;

        let c1 = ObjReg::new(
            conn,
            Self::path_for(&app_id, "app/service/c1")?,
            C1Obj::new(service.path().into(), callback.clone()),
        )
        .await?;

        let c2 = ObjReg::new(
            conn,
            Self::path_for(&app_id, "app/service/c2")?,
            C2Obj::new(service.path().into(), ind_peers, callback.clone()),
        )
        .await?;

        let ad = ObjReg::new(
            conn,
            Self::path_for(&app_id, "ad")?,
            AdObj::new(service_adv_name, service_adv_data),
        )
        .await?;

        let gm = GattManagerProxy::new(conn, adapter.clone()).await?;

        gm.register_application(&app_path.as_ref(), HashMap::new())
            .await?;

        let lm = LEAdvertisingManagerProxy::new(conn, adapter).await?;

        Ok(Self {
            app_path,
            app,
            gm,
            lm,
            service,
            c1,
            c2,
            ad,
            callback,
            closed: false,
        })
    }

    /// Start advertising the Matter BTP service.
    async fn start_adv(&mut self) -> Result<(), Error> {
        if !self.closed {
            self.lm
                .register_advertisement(&self.ad.path(), HashMap::new())
                .await?;
        }

        Ok(())
    }

    /// Stop advertising the Matter BTP service.
    async fn stop_adv(&mut self) -> Result<(), Error> {
        if !self.closed {
            self.lm.unregister_advertisement(&self.ad.path()).await?;
        }

        Ok(())
    }

    /// Close (unregister) the GATT application registration.
    async fn close(&mut self) -> Result<(), Error> {
        if !self.closed {
            self.stop_adv().await?;
            self.ad.deregister().await?;
            self.gm.unregister_application(&self.app_path).await?;
            self.c2.deregister().await?;
            self.c1.deregister().await?;
            self.service.deregister().await?;
            self.app.deregister().await?;
            self.closed = true;
        }

        Ok(())
    }

    /// A utility function to create the object path for an object who must live under the
    /// Matter BlueZ GATT service.
    fn path_for(app_id: &str, obj_name: &str) -> Result<OwnedObjectPath, Error> {
        Ok(format!("{BLUEZ_PATH_PREFIX}/{app_id}/{obj_name}").try_into()?)
    }
}

impl Drop for AppReg<'_> {
    fn drop(&mut self) {
        futures_lite::future::block_on(self.close()).unwrap_or_else(|e| {
            error!("Failed to deregister Matter presence: {}", e);
        });
    }
}

/// A utility type that registers a dBus object in the BlueZ object server, under the Matter BlueZ dBus object tree.
struct ObjReg<'a, T>
where
    T: Interface,
{
    /// The dBus connection to use for the registration
    connection: &'a Connection,
    /// The path to the registered object
    path: OwnedObjectPath,
    /// Whether the object is registered in the dBus object server
    registered: bool,
    _t: PhantomData<fn() -> T>,
}

impl<'a, T> ObjReg<'a, T>
where
    T: Interface,
{
    /// Create a new instance of the `ObjReg` type and thus register the object in the dBus object server.
    async fn new(connection: &'a Connection, path: OwnedObjectPath, obj: T) -> Result<Self, Error> {
        connection.object_server().at(&path, obj).await?;

        Ok(Self {
            connection,
            path,
            registered: true,
            _t: PhantomData,
        })
    }

    /// Get the path of the registered object.
    fn path(&self) -> ObjectPath<'_> {
        self.path.as_ref()
    }

    /// Deregister the object from the dBus object server.
    async fn deregister(&mut self) -> Result<(), Error> {
        if self.registered {
            // Remove the object from the object server
            self.connection
                .object_server()
                .remove::<T, _>(&self.path)
                .await?;

            info!("Deregistered {}", self.path);

            self.registered = false;
        }

        Ok(())
    }
}

impl<T> Drop for ObjReg<'_, T>
where
    T: Interface,
{
    fn drop(&mut self) {
        futures_lite::future::block_on(self.deregister()).unwrap_or_else(|e| {
            error!("Failed to deregister {}: {}", self.path, e);
        });
    }
}
