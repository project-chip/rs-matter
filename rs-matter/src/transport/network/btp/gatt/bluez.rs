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
use core::sync::atomic::{AtomicBool, Ordering};

use alloc::sync::Arc;

use std::collections::HashMap;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;

use async_channel::{Receiver, Sender};
use async_io::Async;

use embassy_futures::select::{select, select3, Either};

use uuid::Uuid;

use zbus::fdo::{ObjectManager, ObjectManagerProxy};
use zbus::object_server::Interface;
use zbus::zvariant::{ObjectPath, OwnedFd, OwnedObjectPath, OwnedValue, Value};
use zbus::{interface, Connection};

use crate::error::{Error, ErrorCode};
use crate::transport::network::btp::Btp;
use crate::transport::network::BtAddr;
use crate::utils::select::Coalesce;
use crate::utils::zbus_proxies::bluez::adapter::AdapterProxy;
use crate::utils::zbus_proxies::bluez::gatt_manager::GattManagerProxy;
use crate::utils::zbus_proxies::bluez::le_advertising_manager::LEAdvertisingManagerProxy;

use super::{AdvData, C1_CHARACTERISTIC_UUID, C2_CHARACTERISTIC_UUID, MATTER_BLE_SERVICE_UUID};

const BLUEZ_MATTER_BLE_SERVICE_UUID: Uuid = Uuid::from_u128(MATTER_BLE_SERVICE_UUID);
const BLUEZ_MATTER_C1_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(C1_CHARACTERISTIC_UUID);
const BLUEZ_MATTER_C2_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(C2_CHARACTERISTIC_UUID);
const BLUEZ_PATH_PREFIX: &str = "/org/projectchip/rs_matter/bluez";

pub async fn run_peripheral(
    connection: &Connection,
    adapter_name: Option<&str>,
    service_name: &str,
    service_adv_data: &AdvData,
    btp: &Btp,
) -> Result<(), Error> {
    let adapter_path = adapter_path(connection, adapter_name).await?;

    let adapter = AdapterProxy::new(connection, adapter_path.as_ref()).await?;
    adapter.set_powered(true).await?;

    // Register a "NoInputNoOutput" agent that will accept all incoming requests.
    // TODO
    // let _handle = bluez.register_agent(Agent::default()).await?;

    let (write_sender, write_receiver) = async_channel::bounded(1);
    let (notify_sender, notify_receiver) = async_channel::bounded(1);

    let notifier_created = Arc::new(AtomicBool::new(false));

    let mut app = AppReg::new(
        connection,
        service_name,
        service_adv_data,
        adapter_path.as_ref(),
        write_sender,
        notify_sender,
        notifier_created.clone(),
    )
    .await?;

    info!(
        "Serving Matter GATT BTP service on Bluetooth adapter {}",
        adapter_path
    );

    loop {
        info!(
            "Advertising Matter GATT BTP service on Bluetooth adapter {}",
            adapter_path,
        );

        app.start_adv().await?;

        let notifier = notify_receiver.recv().await.unwrap();

        app.stop_adv().await?;

        btp.reset();

        select3(
            wait_complete(btp, &notifier),
            process_write(btp, &write_receiver),
            process_indicate(btp, None, &notifier, &mut [0; 512]),
        )
        .coalesce()
        .await?;

        notifier_created.store(false, Ordering::SeqCst);
    }
}

/// Process incoming writes on characteristic `C1` and pass them to the BTP session for processing.
async fn process_write(
    btp: &Btp,
    receiver: &Receiver<(u16, BtAddr, Vec<u8>)>,
) -> Result<(), Error> {
    while let Ok((mtu, addr, value)) = receiver.recv().await {
        btp.process_incoming(Some(mtu), addr, &value)?;
    }

    Ok(())
}

/// Indicate new data on characteristic `C2` to a remote peer.
async fn process_indicate(
    btp: &Btp,
    gatt_mtu: Option<u16>,
    notifier: &Async<UnixDatagram>,
    buf: &mut [u8],
) -> Result<(), Error> {
    loop {
        let len = btp.process_outgoing(gatt_mtu, buf)?;

        if len > 0 {
            notifier.send(&buf[..len]).await?;

            trace!("Sent indication to peer: {:?}", &buf[..len]);

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
        } else {
            btp.wait_outgoing().await;
        }
    }
}

/// Listen for unsubscription from characteristic `C2` as well as for session connection timeout.
async fn wait_complete(btp: &Btp, notifier: &Async<UnixDatagram>) -> Result<(), Error> {
    let result = select(notifier.readable(), btp.wait_timeout()).await;

    match result {
        Either::First(_) => info!("Peer unsubscribed"),
        Either::Second(_) => info!("Timeout while waiting for data from the peer"),
    }

    Ok(())
}

/// Get the path to the Bluetooth adapter designated by `adapter_name`,
/// or the first available adapter if `adapter_name` is `None`.
async fn adapter_path(
    connection: &Connection,
    adapter_name: Option<&str>,
) -> Result<OwnedObjectPath, Error> {
    let om = ObjectManagerProxy::new(connection, "org.bluez", "/").await?;

    let objects = om.get_managed_objects().await?;

    let adapter_path = objects
        .into_iter()
        .find(|(path, interfaces)| {
            if interfaces.contains_key("org.bluez.GattManager1")
                && interfaces.contains_key("org.bluez.Adapter1")
                && interfaces.contains_key("org.bluez.LEAdvertisingManager1")
            {
                adapter_name
                    .map(|adapter_name| path.as_str().split('/').next_back() == Some(adapter_name))
                    .unwrap_or(true)
            } else {
                false
            }
        })
        .map(|(path, _)| path);

    adapter_path.ok_or_else(|| ErrorCode::NoNetworkInterface.into())
}

/// Add a new peer.
///
/// Arguments:
/// - `peer_addr`: The address of the peer to add.
fn create_socket(
    _peer_addr: BtAddr,
) -> zbus::fdo::Result<(Async<UnixDatagram>, std::os::fd::OwnedFd)> {
    let (local, remote) = uds_pair()
        .map_err(|e| zbus::fdo::Error::Failed(format!("Failed to create UDS pair: {}", e)))?;

    Ok((
        local,
        remote
            .into_inner()
            .map_err(|e| {
                zbus::fdo::Error::Failed(format!("Failed to convert UDS to OwnedFd: {}", e))
            })?
            .into(),
    ))
}

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
    callback: Sender<(u16, BtAddr, Vec<u8>)>,
}

impl C1Obj {
    /// Create a new instance of the `C1Obj` type.
    fn new(service: OwnedObjectPath, callback: Sender<(u16, BtAddr, Vec<u8>)>) -> Self {
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

    async fn write_value(
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

        self.callback
            .send((ServiceObj::dict_mtu(&options)?, peer_addr, value.to_vec()))
            .await
            .unwrap();

        Ok(())
    }
}

/// A dBus object representing the Matter BLE GATT characteristics `C2`.
struct C2Obj {
    /// The path to the Matter GATT service that this characteristic belongs to
    service: OwnedObjectPath,
    /// The callback function that will be called with GATT events
    callback: Sender<Async<UnixDatagram>>,
    /// Whether the notifier has been created (i.e. whether the `acquire_notify` method has been called)
    notifier_created: Arc<AtomicBool>,
}

impl C2Obj {
    /// Create a new instance of the `C2Obj` type.
    fn new(
        service: OwnedObjectPath,
        callback: Sender<Async<UnixDatagram>>,
        notifier_created: Arc<AtomicBool>,
    ) -> Self {
        Self {
            service,
            callback,
            notifier_created,
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

        if self.notifier_created.swap(true, Ordering::SeqCst) {
            return Err(zbus::fdo::Error::Failed(
                "Notifier already created for C2 characteristic".into(),
            ));
        }

        let (socket, fd) = create_socket(peer_addr)?;

        self.callback.send(socket).await.unwrap();

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
    /// - `c1_cb`: A callback function that will be called with C1 characteristic events.
    /// - `c2_cb`: A callback function that will be called with C2 characteristic events.
    async fn new(
        conn: &'a Connection,
        service_adv_name: &str,
        service_adv_data: &AdvData,
        adapter: ObjectPath<'a>,
        c1_cb: Sender<(u16, BtAddr, Vec<u8>)>,
        c2_cb: Sender<Async<UnixDatagram>>,
        c2_notifier_created: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        let app_id = Uuid::new_v4().simple().to_string();
        let app_path = Self::path_for(&app_id, "app")?;

        let app = ObjReg::new(conn, app_path.clone(), ObjectManager).await?;

        let service =
            ObjReg::new(conn, Self::path_for(&app_id, "app/service")?, ServiceObj).await?;

        let c1 = ObjReg::new(
            conn,
            Self::path_for(&app_id, "app/service/c1")?,
            C1Obj::new(service.path().into(), c1_cb),
        )
        .await?;

        let c2 = ObjReg::new(
            conn,
            Self::path_for(&app_id, "app/service/c2")?,
            C2Obj::new(service.path().into(), c2_cb, c2_notifier_created),
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
