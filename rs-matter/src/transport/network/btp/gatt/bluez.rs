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

//! A GATT Peripheral implementation using the BlueZ GATT stack over dBus.

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
use embassy_time::{Duration, Instant, Timer};

use futures_lite::StreamExt;

use uuid::Uuid;

use zbus::fdo::{ObjectManager, ObjectManagerProxy};
use zbus::object_server::Interface;
use zbus::zvariant::{ObjectPath, OwnedFd, OwnedObjectPath, OwnedValue, Value};
use zbus::{interface, Connection};

use crate::error::{Error, ErrorCode};
use crate::transport::network::btp::Btp;
use crate::transport::network::mdns::CommissionableFilter;
use crate::transport::network::BtAddr;
use crate::utils::select::Coalesce;
use crate::utils::zbus_proxies::bluez::adapter::AdapterProxy;
use crate::utils::zbus_proxies::bluez::device::DeviceProxy;
use crate::utils::zbus_proxies::bluez::gatt_characteristic::GattCharacteristicProxy;
use crate::utils::zbus_proxies::bluez::gatt_manager::GattManagerProxy;
use crate::utils::zbus_proxies::bluez::gatt_service::GattServiceProxy;
use crate::utils::zbus_proxies::bluez::le_advertising_manager::LEAdvertisingManagerProxy;

use super::{AdvData, C1_CHARACTERISTIC_UUID, C2_CHARACTERISTIC_UUID, MATTER_BLE_SERVICE_UUID};

const BLUEZ_MATTER_BLE_SERVICE_UUID: Uuid = Uuid::from_u128(MATTER_BLE_SERVICE_UUID);
const BLUEZ_MATTER_C1_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(C1_CHARACTERISTIC_UUID);
const BLUEZ_MATTER_C2_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(C2_CHARACTERISTIC_UUID);
const BLUEZ_PATH_PREFIX: &str = "/org/projectchip/rs_matter/bluez";

/// The default amount of time [`run_central`] will scan for a matching
/// commissionable advertisement before giving up.
pub const DEFAULT_SCAN_TIMEOUT_SECS: u16 = 60;

/// Build a `Device1` proxy bound to a specific device object path.
///
/// The BlueZ proxies are declared with `assume_defaults = true`, so their
/// `new(connection)` constructor bakes in a default path; to target a specific
/// object we go through the proxy builder.
async fn device_proxy<'a>(
    connection: &'a Connection,
    path: &OwnedObjectPath,
) -> Result<DeviceProxy<'a>, Error> {
    // These proxies are `assume_defaults = true` (no `default_service`), so the
    // destination defaults to the interface name (`org.bluez.Device1`) unless we
    // set it explicitly - it must be `org.bluez`.
    Ok(DeviceProxy::builder(connection)
        .destination("org.bluez")?
        .path(path.clone())?
        .build()
        .await?)
}

/// Build a `GattService1` proxy bound to a specific object path.
async fn gatt_service_proxy<'a>(
    connection: &'a Connection,
    path: &OwnedObjectPath,
) -> Result<GattServiceProxy<'a>, Error> {
    Ok(GattServiceProxy::builder(connection)
        .destination("org.bluez")?
        .path(path.clone())?
        .build()
        .await?)
}

/// Build a `GattCharacteristic1` proxy bound to a specific object path.
async fn gatt_characteristic_proxy<'a>(
    connection: &'a Connection,
    path: &OwnedObjectPath,
) -> Result<GattCharacteristicProxy<'a>, Error> {
    Ok(GattCharacteristicProxy::builder(connection)
        .destination("org.bluez")?
        .path(path.clone())?
        .build()
        .await?)
}

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

/// Run the GATT central (Commissioner-side) BTP transport using the BlueZ GATT stack over dBus.
///
/// This is the connect-and-pump half of the Controller / Commissioner role (the discovery half is
/// [`scan`]). Given the Bluetooth address of a commissionable device (as returned by [`scan`]), it:
/// - Connects to the device as a GATT Central and discovers the Matter GATT service, together with
///   its `C1` (write) and `C2` (indicate) characteristics.
/// - Subscribes to `C2` indications, feeding them into [`Btp::process_incoming`], and writes the
///   BTP output from [`Btp::process_outgoing`] to `C1` (as an acknowledged GATT Write Request).
/// - Drives `btp` in the initiator role (it calls [`Btp::set_initiator`] with `true`), so the
///   BTP handshake is started by us.
///
/// The caller passes commissioning requests to the device as `Address::Btp(addr)` while
/// `matter.run(.., &btp, &btp, ..)` pumps the transport (i.e. `run_central` is `select`-ed against
/// `matter.run`).
///
/// This function returns once the peer disconnects, the session times out, or an error occurs.
/// It does not loop / reconnect - a Commissioner establishes one BTP session for the duration of
/// commissioning.
///
/// `addr` must belong to a device that BlueZ already knows about (i.e. one that has been discovered
/// at least once - typically via a preceding [`scan`] on the same adapter). Otherwise BlueZ has no
/// object for it and the connect fails.
///
/// # Arguments
/// - `connection`: The dBus (system-bus) connection to BlueZ.
/// - `adapter_name`: The Bluetooth adapter to use. If `None`, the first suitable adapter is used.
///   It must be the same adapter the device was discovered on.
/// - `addr`: The Bluetooth address of the device to connect to (from [`scan`]).
/// - `btp`: The BTP session to drive.
pub async fn run_central(
    connection: &Connection,
    adapter_name: Option<&str>,
    addr: BtAddr,
    btp: &Btp,
) -> Result<(), Error> {
    let adapter_path = adapter_path_for_central(connection, adapter_name).await?;

    let adapter = AdapterProxy::new(connection, adapter_path.as_ref()).await?;
    adapter.set_powered(true).await?;

    // BlueZ device object paths are a deterministic function of the adapter path and the peer MAC:
    // `<adapter_path>/dev_AA_BB_CC_DD_EE_FF`.
    let device_path = device_path_for(&adapter_path, addr)?;

    info!(
        "Connecting to commissionable device {} ({})",
        device_path, addr
    );

    let device = device_proxy(connection, &device_path).await?;

    device.connect().await?;

    wait_services_resolved(&device).await?;

    // Discover the Matter GATT service and its C1/C2 characteristics.
    let (c1, c2) = discover_matter_characteristics(connection, &device_path).await?;

    // The negotiated ATT MTU, as reported by BlueZ on the characteristic. It may be `0`/unknown
    // on older BlueZ; in that case the BTP handshake falls back to the minimum MTU.
    let gatt_mtu = c1.mtu().await.ok().filter(|mtu| *mtu > 0);

    debug!(
        "Discovered Matter GATT characteristics C1/C2, ATT MTU: {:?}",
        gatt_mtu
    );

    // Subscribe to C2 indications before we start the handshake, so we don't miss the peer's
    // Handshake Response.
    c2.start_notify().await?;

    let mut value_changed = c2.receive_value_changed().await;

    // We are the initiator: drive the BTP handshake from our side.
    //
    // NOTE: we deliberately do NOT `btp.reset()` here. The caller is expected to
    // have reset the session and set the initiator role *before* it started
    // driving Matter traffic through this `Btp` - resetting here would race with,
    // and wipe, any Matter SDU the caller has already queued (e.g. the PASE
    // PBKDFParamRequest a commissioner sends as soon as the transport is up).
    btp.set_initiator(true);

    let result = select3(
        wait_central_complete(btp, &device_path, connection),
        process_c2_indications(btp, addr, gatt_mtu, &mut value_changed),
        process_c1_writes(btp, gatt_mtu, &c1, &mut [0; 512]),
    )
    .coalesce()
    .await;

    // Best-effort teardown so a subsequent commissioning attempt starts clean.
    let _ = c2.stop_notify().await;

    result
}

/// Scan BLE advertisements for commissionable Matter devices and report each match to `on_found`.
///
/// This is the discovery half of the Controller / Commissioner role (the connect half is
/// [`run_central`]) - the BLE analogue of an mDNS commissionable browse. It puts the adapter into
/// LE discovery (the Matter service UUID is matched per-device from the advertised service data,
/// not via a discovery filter - see the note in the body), and for every discovered device whose
/// advertised service data both parses as a commissionable Matter advertisement and matches
/// `filter`, it invokes `on_found(addr, &adv)`.
///
/// `on_found` decides when to stop: returning `Some(value)` stops the scan and makes `scan` return
/// `Ok(value)`; returning `None` keeps scanning. Each matching device is reported at most once. If
/// the timeout elapses with no accepted match, `scan` returns `Err(NoNetworkInterface)`.
///
/// The common "connect to the first match" case is simply:
///
/// ```ignore
/// let addr = scan(&conn, None, &filter, None, |addr, _adv| Some(addr)).await?;
/// run_central(&conn, None, addr, &btp).await?;
/// ```
///
/// # Arguments
/// - `connection`: The dBus (system-bus) connection to BlueZ.
/// - `adapter_name`: The Bluetooth adapter to use. If `None`, the first suitable adapter is used.
/// - `filter`: The commissionable-device filter to match advertisements against. An empty filter
///   matches every commissionable Matter device seen.
/// - `scan_timeout`: How long to scan before giving up. If `None`, [`DEFAULT_SCAN_TIMEOUT_SECS`].
/// - `on_found`: Callback invoked for each newly-matched device; returning `Some` stops the scan.
pub async fn scan<F, R>(
    connection: &Connection,
    adapter_name: Option<&str>,
    filter: &CommissionableFilter,
    scan_timeout: Option<u16>,
    mut on_found: F,
) -> Result<R, Error>
where
    F: FnMut(BtAddr, &AdvData) -> Option<R>,
{
    let adapter_path = adapter_path_for_central(connection, adapter_name).await?;

    let adapter = AdapterProxy::new(connection, adapter_path.as_ref()).await?;
    adapter.set_powered(true).await?;

    info!(
        "Scanning for a commissionable Matter device on Bluetooth adapter {} (filter: {:?})",
        adapter_path, filter
    );

    // Constrain discovery to LE, so BlueZ populates `Device1.ServiceData` for advertising devices.
    //
    // Note: we deliberately do NOT set a `UUIDs` service-UUID filter here. In
    // practice, passing `UUIDs` to `SetDiscoveryFilter` over this D-Bus binding
    // leaves the adapter's `Discovering` property `false` (BlueZ accepts the call
    // but never actually starts scanning), so no advertisements ever arrive. We
    // instead filter to the Matter service UUID in `report_matching_devices` when
    // we inspect each device's advertised service data - which we have to do
    // anyway to parse the advertisement.
    let transport = Value::from("le");
    let mut discovery_filter: HashMap<&str, &Value<'_>> = HashMap::new();
    discovery_filter.insert("Transport", &transport);

    adapter.set_discovery_filter(discovery_filter).await?;
    adapter.start_discovery().await?;

    // Poll the object tree for matching devices. We poll (rather than only relying on
    // `InterfacesAdded`) so that devices already known to BlueZ, and service-data that arrives via
    // `PropertiesChanged` on an existing device, are both handled uniformly.
    let om = ObjectManagerProxy::new(connection, "org.bluez", "/").await?;

    let deadline = Instant::now()
        + Duration::from_secs(scan_timeout.unwrap_or(DEFAULT_SCAN_TIMEOUT_SECS) as u64);

    // Devices already reported to `on_found`, so we report each at most once.
    let mut reported: heapless::Vec<BtAddr, 16> = heapless::Vec::new();

    let outcome = loop {
        if let Some(result) =
            report_matching_devices(&om, &adapter_path, filter, &mut reported, &mut on_found)
                .await?
        {
            break Some(result);
        }

        if Instant::now() >= deadline {
            break None;
        }

        Timer::after(Duration::from_millis(250)).await;
    };

    // Stop discovery (best-effort) before returning.
    let _ = adapter.stop_discovery().await;

    outcome.ok_or_else(|| {
        warn!(
            "No commissionable Matter device matching the filter was found within the scan timeout"
        );
        ErrorCode::NoNetworkInterface.into()
    })
}

/// Feed C2 indications (BlueZ surfaces them as `Value` property changes) into the BTP session.
async fn process_c2_indications(
    btp: &Btp,
    peer_addr: BtAddr,
    gatt_mtu: Option<u16>,
    value_changed: &mut zbus::proxy::PropertyStream<'_, Vec<u8>>,
) -> Result<(), Error> {
    while let Some(change) = value_changed.next().await {
        let value = change.get().await?;

        // BlueZ emits the characteristic's *current* `Value` (initially empty) as
        // the first property change right after `start_notify()`, before any real
        // indication has arrived. It also may re-deliver an unchanged value. An
        // empty payload is never a valid BTP frame, so skip it rather than feeding
        // it to the BTP layer (which would reject it as invalid).
        if value.is_empty() {
            continue;
        }

        trace!(
            "Received C2 indication from peer {}: {:?}",
            peer_addr,
            value
        );

        btp.process_incoming(gatt_mtu, peer_addr, &value)?;
    }

    // The property stream ended - treat as a disconnect.
    Ok(())
}

/// Drive BTP output and write it to characteristic `C1` (as a GATT Write Request).
async fn process_c1_writes(
    btp: &Btp,
    gatt_mtu: Option<u16>,
    c1: &GattCharacteristicProxy<'_>,
    buf: &mut [u8],
) -> Result<(), Error> {
    // BTP writes to `C1` are GATT "Write Requests" (i.e. *acknowledged*
    // `ATT_WRITE_REQ`), as mandated by the Matter Core spec (§4.19.4:
    // "Clients SHALL exclusively use GATT Write Characteristic Value sub-procedure
    // to send data to servers" - which is the acknowledged write). BlueZ's write
    // type for that is `"request"`.
    //
    // This is not just a conformance detail: the per-write GATT acknowledgement is
    // the client-to-server half of BTP flow control. With an unacknowledged
    // "Write Command", back-to-back segments of a multi-segment SDU (e.g. the
    // AddNOC request) get packed into one BLE connection event and are dropped by
    // the server's ATT layer (observed as `GATTS_SendRsp ... Sending response
    // failed` on ESP-IDF, then a BTP sequence gap and a disconnect). Awaiting the
    // Write Response before sending the next segment prevents that.
    let mut options = HashMap::new();
    let write_type = Value::from("request");
    options.insert("type", &write_type);

    loop {
        let len = btp.process_outgoing(gatt_mtu, buf)?;

        if len > 0 {
            trace!("Writing to C1: {:?}", &buf[..len]);

            // `write_value` (an `ATT_WRITE_REQ`) completes only when the server
            // returns its Write Response, so segments are paced one at a time.
            c1.write_value(&buf[..len], options.clone()).await?;
        } else {
            btp.wait_outgoing().await;
        }
    }
}

/// Wait for the BTP session to complete because it timed out (no data from the peer for the BTP
/// idle timeout).
///
/// We deliberately do NOT also race a `Connected == false` watch here. BlueZ can briefly report a
/// device as not-connected during a busy session (e.g. an LE connection-parameter update right
/// after PASE), which would spuriously abort commissioning. A genuine disconnect surfaces promptly
/// as an error from the `C1` write / `C2` notify paths instead, and a truly idle session is caught
/// by the BTP timeout below.
async fn wait_central_complete(
    btp: &Btp,
    _device_path: &OwnedObjectPath,
    _connection: &Connection,
) -> Result<(), Error> {
    btp.wait_timeout().await;
    info!("Timeout while waiting for data from the peer");

    Ok(())
}

/// Look through the BlueZ object tree for `Device1` objects on `adapter_path` whose advertised
/// Matter service data both parses and matches `filter`, and report each not-yet-reported one to
/// `on_found`. Returns `Some(result)` as soon as `on_found` returns `Some` (stopping the scan).
async fn report_matching_devices<F, R>(
    om: &ObjectManagerProxy<'_>,
    adapter_path: &OwnedObjectPath,
    filter: &CommissionableFilter,
    reported: &mut heapless::Vec<BtAddr, 16>,
    on_found: &mut F,
) -> Result<Option<R>, Error>
where
    F: FnMut(BtAddr, &AdvData) -> Option<R>,
{
    let matter_uuid = BLUEZ_MATTER_BLE_SERVICE_UUID.to_string();

    let objects = om.get_managed_objects().await?;

    for (path, interfaces) in objects {
        let Some(device) = interfaces.get("org.bluez.Device1") else {
            continue;
        };

        // Only consider devices on our adapter.
        if !path.as_str().starts_with(adapter_path.as_str()) {
            continue;
        }

        // Pull the advertised service data (a `UUID -> bytes` map) and look for the Matter one.
        let Some(service_data) = device.get("ServiceData") else {
            continue;
        };

        let Ok(service_data) = <HashMap<String, OwnedValue>>::try_from(service_data.clone()) else {
            continue;
        };

        let Some(matter_data) = service_data
            .iter()
            .find(|(uuid, _)| uuid.eq_ignore_ascii_case(&matter_uuid))
            .map(|(_, data)| data)
        else {
            continue;
        };

        let Ok(bytes) = <Vec<u8>>::try_from(matter_data.clone()) else {
            continue;
        };

        let Some(adv) = AdvData::parse_service_data(&bytes) else {
            continue;
        };

        if !adv.matches(filter) {
            continue;
        }

        let Ok(addr) = bt_addr_from_device_path(&path.as_ref()) else {
            continue;
        };

        // Report each matching device at most once.
        if reported.contains(&addr) {
            continue;
        }

        // If the dedup buffer is full we simply stop deduplicating (and may re-report); never drop
        // an actual match on the floor.
        let _ = reported.push(addr);

        debug!(
            "Matched commissionable device {} ({}) (adv: {:?})",
            path, addr, adv
        );

        if let Some(result) = on_found(addr, &adv) {
            return Ok(Some(result));
        }
    }

    Ok(None)
}

/// Construct the BlueZ `Device1` object path for a peer MAC on the given adapter:
/// `<adapter_path>/dev_AA_BB_CC_DD_EE_FF`. This is the inverse of [`bt_addr_from_device_path`].
fn device_path_for(adapter_path: &OwnedObjectPath, addr: BtAddr) -> Result<OwnedObjectPath, Error> {
    let [a, b, c, d, e, f] = addr.0;
    let path = format!(
        "{}/dev_{:02X}_{:02X}_{:02X}_{:02X}_{:02X}_{:02X}",
        adapter_path.as_str(),
        a,
        b,
        c,
        d,
        e,
        f
    );

    Ok(path.try_into()?)
}

/// Wait until the device reports that its GATT services have been resolved.
async fn wait_services_resolved(device: &DeviceProxy<'_>) -> Result<(), Error> {
    if device.services_resolved().await.unwrap_or(false) {
        return Ok(());
    }

    let mut resolved_changed = device.receive_services_resolved_changed().await;

    while let Some(change) = resolved_changed.next().await {
        if change.get().await.unwrap_or(false) {
            break;
        }
    }

    Ok(())
}

/// Find the `C1` (write) and `C2` (indicate) characteristics of the Matter GATT service on the
/// connected device.
async fn discover_matter_characteristics<'a>(
    connection: &'a Connection,
    device_path: &OwnedObjectPath,
) -> Result<(GattCharacteristicProxy<'a>, GattCharacteristicProxy<'a>), Error> {
    let om = ObjectManagerProxy::new(connection, "org.bluez", "/").await?;
    let objects = om.get_managed_objects().await?;

    // Find the Matter GATT service under this device.
    let mut service_path: Option<OwnedObjectPath> = None;
    for (path, interfaces) in &objects {
        if !path.as_str().starts_with(device_path.as_str()) {
            continue;
        }

        if interfaces.contains_key("org.bluez.GattService1") {
            let service = gatt_service_proxy(connection, path).await?;
            if service
                .uuid()
                .await
                .map(|uuid| uuid.eq_ignore_ascii_case(&BLUEZ_MATTER_BLE_SERVICE_UUID.to_string()))
                .unwrap_or(false)
            {
                service_path = Some(path.clone());
                break;
            }
        }
    }

    let service_path = service_path.ok_or_else(|| {
        warn!("The connected device does not expose the Matter GATT service");
        Error::from(ErrorCode::NoNetworkInterface)
    })?;

    // Find C1 and C2 under the service.
    let mut c1: Option<GattCharacteristicProxy<'a>> = None;
    let mut c2: Option<GattCharacteristicProxy<'a>> = None;

    for (path, interfaces) in &objects {
        if !path.as_str().starts_with(service_path.as_str()) {
            continue;
        }

        if !interfaces.contains_key("org.bluez.GattCharacteristic1") {
            continue;
        }

        let chr = gatt_characteristic_proxy(connection, path).await?;
        let Ok(uuid) = chr.uuid().await else {
            continue;
        };

        if uuid.eq_ignore_ascii_case(&BLUEZ_MATTER_C1_CHARACTERISTIC_UUID.to_string()) {
            c1 = Some(chr);
        } else if uuid.eq_ignore_ascii_case(&BLUEZ_MATTER_C2_CHARACTERISTIC_UUID.to_string()) {
            c2 = Some(chr);
        }
    }

    let c1 = c1.ok_or_else(|| {
        warn!("The Matter GATT service is missing the C1 characteristic");
        Error::from(ErrorCode::NoNetworkInterface)
    })?;
    let c2 = c2.ok_or_else(|| {
        warn!("The Matter GATT service is missing the C2 characteristic");
        Error::from(ErrorCode::NoNetworkInterface)
    })?;

    Ok((c1, c2))
}

/// Extract a [`BtAddr`] from a BlueZ device object path of the form
/// `/org/bluez/<adapter>/dev_XX_XX_XX_XX_XX_XX`.
fn bt_addr_from_device_path(path: &ObjectPath<'_>) -> Result<BtAddr, Error> {
    let bt_addr_str = path
        .as_str()
        .rsplit('/')
        .next()
        .and_then(|last| last.strip_prefix("dev_"))
        .ok_or(ErrorCode::InvalidData)?;

    let bt_addr = bt_addr_str
        .split('_')
        .map(|s| u8::from_str_radix(s, 16).map_err(|_| Error::from(ErrorCode::InvalidData)))
        .collect::<Result<heapless::Vec<_, 6>, _>>()?;

    bt_addr
        .into_array()
        .map(BtAddr)
        .map_err(|_| ErrorCode::InvalidData.into())
}

/// Get the path to a Bluetooth adapter suitable for the Central role.
///
/// Unlike the Peripheral role (which needs `GattManager1` + `LEAdvertisingManager1`), the Central
/// role only needs an `Adapter1`.
async fn adapter_path_for_central(
    connection: &Connection,
    adapter_name: Option<&str>,
) -> Result<OwnedObjectPath, Error> {
    let om = ObjectManagerProxy::new(connection, "org.bluez", "/").await?;

    let objects = om.get_managed_objects().await?;

    objects
        .into_iter()
        .find(|(path, interfaces)| {
            if interfaces.contains_key("org.bluez.Adapter1") {
                adapter_name
                    .map(|adapter_name| path.as_str().split('/').next_back() == Some(adapter_name))
                    .unwrap_or(true)
            } else {
                false
            }
        })
        .map(|(path, _)| path)
        .ok_or_else(|| ErrorCode::NoNetworkInterface.into())
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
