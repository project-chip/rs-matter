/*
 *
 *    Copyright (c) 2024-2026 Project CHIP Authors
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

//! A GATT Peripheral implementation using the BlueZ GATT stack via the `bluer` crate.

use core::iter::once;
use core::pin::pin;

use bluer::adv::Advertisement;
use bluer::agent::Agent;
use bluer::gatt::local::{
    characteristic_control, Application, Characteristic, CharacteristicControl,
    CharacteristicControlEvent, CharacteristicNotify, CharacteristicNotifyMethod,
    CharacteristicWrite, CharacteristicWriteMethod, CharacteristicWriteRequest, Service,
};
use bluer::gatt::remote::Characteristic as RemoteCharacteristic;
use bluer::gatt::{CharacteristicWriter, WriteOp};
use bluer::{Adapter, AdapterEvent, Address, DiscoveryFilter, DiscoveryTransport, Uuid};

use embassy_futures::select::{select, select3, select4, Either};
use embassy_time::{Duration, Timer};

use tokio::sync::mpsc::Receiver;
use tokio_stream::StreamExt;

use crate::error::{Error, ErrorCode};
use crate::transport::network::btp::Btp;
use crate::transport::network::mdns::CommissionableFilter;
use crate::transport::network::BtAddr;
use crate::utils::select::Coalesce;

use super::{AdvData, C1_CHARACTERISTIC_UUID, C2_CHARACTERISTIC_UUID, MATTER_BLE_SERVICE_UUID};

/// The default amount of time [`scan`] will scan for a matching commissionable
/// advertisement before giving up.
pub const DEFAULT_SCAN_TIMEOUT_SECS: u16 = 60;

/// How many times [`run_central`] will attempt the initial GATT connection before
/// giving up, and how long it waits between attempts.
///
/// A connect issued right after discovery has stopped can lose a race with the
/// stack still tearing the scan down (surfacing as `le-connection-abort-by-local`).
/// The device was just seen advertising, so a connect failure here is almost always
/// transient - a short, bounded retry turns it into a non-event.
const CONNECT_ATTEMPTS: u8 = 4;
const CONNECT_RETRY_DELAY_MS: u64 = 500;

/// Run the GATT peripheral service.
///
/// What this means in details:
/// - Serve a GATT peripheral service with the `C1`, `C2` and `C3` characteristics, as specified
/// - Advertise the service with the provided name and advertising data, where the advertising data
///   contains the elements specified in the Matter Core spec.
/// - Stop advertising when a connection is established and a subscription to characteristic `C2` is received, as per the Matter Core spec.
///   in the Matter Core spec.
/// - Call `Btp::process_incoming` when a write is received on characteristic `C1`.
/// - Call `Btp::process_outgoing` and indicate the result on characteristic `C2` as appropriate.
///
/// # Arguments
/// - `adapter_name`: The name of the Bluetooth adapter to use. If `None`, the default adapter will be used.
/// - `service_name`: The name to advertise for the GATT service.
/// - `service_adv_data`: The advertising data to use for the GATT service advertisement.
/// - `btp`: The BTP session to use for processing incoming and outgoing packets.
pub async fn run_peripheral(
    adapter_name: Option<&str>,
    service_name: &str,
    service_adv_data: &AdvData,
    btp: &Btp,
) -> Result<(), Error> {
    let session = bluer::Session::new().await?;

    // Register a "NoInputNoOutput" agent that will accept all incoming requests.
    let _handle = session.register_agent(Agent::default()).await?;

    let adapter = if let Some(adapter_name) = adapter_name {
        session.adapter(adapter_name)?
    } else {
        session.default_adapter().await?
    };

    adapter.set_powered(true).await?;

    let le_advertisement = Advertisement {
        discoverable: Some(true),
        local_name: Some(service_name.into()),
        service_uuids: once(Uuid::from_u128(MATTER_BLE_SERVICE_UUID)).collect(),
        service_data: once((
            Uuid::from_u128(MATTER_BLE_SERVICE_UUID),
            service_adv_data.service_payload_iter().collect(),
        ))
        .collect(),
        ..Default::default()
    };

    let (write_sender, mut write_receiver) = tokio::sync::mpsc::channel(1);

    let (mut notify_cc, notify_cc_handle) = characteristic_control();

    // Service and characteristics as per the Matter Core spec
    let app = Application {
        services: vec![Service {
            uuid: Uuid::from_u128(MATTER_BLE_SERVICE_UUID),
            primary: true,
            characteristics: vec![
                Characteristic {
                    uuid: Uuid::from_u128(C1_CHARACTERISTIC_UUID),
                    write: Some(CharacteristicWrite {
                        write: true,
                        method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, req| {
                            let sender = write_sender.clone();

                            Box::pin(async move {
                                sender.send((new_value, req)).await.unwrap();

                                Ok(())
                            })
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                Characteristic {
                    uuid: Uuid::from_u128(C2_CHARACTERISTIC_UUID),
                    notify: Some(CharacteristicNotify {
                        indicate: true,
                        // Reason why we don't use the (simpler) callback-based approach here:
                        // The callback approach does not provide us with access to the remote peer address
                        // when a notification subscription is received. This is necessary for the Matter BTP protocol
                        // to work correctly.
                        //
                        // Restriction seems to come from BlueZ dBus bindings, where their `StartNotify` method does not
                        // provide the address of the remote peer, nor any other peer properties thereof.
                        method: CharacteristicNotifyMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: notify_cc_handle,
                    ..Default::default()
                },
                // Characteristic {
                //     uuid: Uuid::from_u128(C3_CHARACTERISTIC_UUID),
                //     read: Some(CharacteristicRead {
                //         method: CharacteristicReadMethod::Io,
                //         ..Default::default()
                //     }),
                //     control_handle: write_handle,
                //     ..Default::default()
                // },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };

    let _app_handle = adapter.serve_gatt_application(app).await?;

    info!(
        "Serving Matter GATT BTP service on Bluetooth adapter {}",
        adapter.name()
    );

    loop {
        let notifier = {
            // Advertise until we get a connection + subscription to char C2
            // Then stop advertising, as per the Matter Core spec, since the peer is now connected and can interact with the GATT service.

            let _adv_handle = adapter.advertise(le_advertisement.clone()).await?;

            info!(
                "Advertising Matter GATT BTP service on Bluetooth adapter {}",
                adapter.name(),
            );

            notifier(&mut notify_cc).await
        };

        btp.reset();

        select4(
            wait_complete(btp, &notifier),
            process_write(btp, &mut write_receiver),
            process_indicate(btp, None, &notifier, &mut [0; 512]),
            process_cc_events(&mut notify_cc),
        )
        .coalesce()
        .await?;
    }
}

/// Scan BLE advertisements for commissionable Matter devices and report each match to `on_found`.
///
/// This is the discovery half of the Controller / Commissioner role (the connect half is
/// [`run_central`]) - the BLE analogue of an mDNS commissionable browse. It puts the adapter into
/// LE discovery (restricted to the Matter service UUID), and for every discovered device whose
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
/// let addr = scan(None, &filter, None, |addr, _adv| Some(addr)).await?;
/// run_central(None, addr, &btp).await?;
/// ```
///
/// # Arguments
/// - `adapter_name`: The Bluetooth adapter to use. If `None`, the default adapter is used.
/// - `filter`: The commissionable-device filter to match advertisements against. An empty filter
///   matches every commissionable Matter device seen.
/// - `scan_timeout`: How long to scan before giving up. If `None`, [`DEFAULT_SCAN_TIMEOUT_SECS`].
/// - `on_found`: Callback invoked for each newly-matched device; returning `Some` stops the scan.
pub async fn scan<F, R>(
    adapter_name: Option<&str>,
    filter: &CommissionableFilter,
    scan_timeout: Option<u16>,
    mut on_found: F,
) -> Result<R, Error>
where
    F: FnMut(BtAddr, &AdvData) -> Option<R>,
{
    let session = bluer::Session::new().await?;
    let adapter = open_adapter(&session, adapter_name).await?;

    adapter.set_powered(true).await?;

    info!(
        "Scanning for a commissionable Matter device on Bluetooth adapter {} (filter: {:?})",
        adapter.name(),
        filter
    );

    // Restrict discovery to LE devices advertising the Matter service UUID, so BlueZ populates the
    // devices' service data.
    let discovery_filter = DiscoveryFilter {
        uuids: once(Uuid::from_u128(MATTER_BLE_SERVICE_UUID)).collect(),
        transport: DiscoveryTransport::Le,
        ..Default::default()
    };
    adapter.set_discovery_filter(discovery_filter).await?;

    // `discover_devices_with_changes`, not `discover_devices`: both include the
    // devices BlueZ already knows about, but only this one re-emits `DeviceAdded`
    // *every time a device's properties change*.
    //
    // That matters, and is easy to get wrong. BlueZ populates a device's properties
    // asynchronously, so the advertised service data we match on is routinely absent
    // at the moment the device first shows up - and a device BlueZ already knows
    // never "appears" again at all. With plain `discover_devices` we would look at
    // each device exactly once, quite possibly before its service data landed, and
    // then wait forever. (This is the same trap the `zbus` backend sidesteps by
    // re-reading the object tree on a timer; `bluer` just gives us a better tool.)
    let device_events = adapter.discover_devices_with_changes().await?;
    let mut device_events = pin!(device_events);

    // Devices already reported to `on_found`, so we report each at most once.
    // Note this only suppresses re-reporting a device we already *matched*: one that
    // does not match yet (e.g. no service data so far) is left out, so a later
    // `DeviceAdded` for it gets another look.
    let mut reported: heapless::Vec<BtAddr, 16> = heapless::Vec::new();

    let scan_fut = async {
        while let Some(event) = device_events.next().await {
            if let AdapterEvent::DeviceAdded(addr) = event {
                if let Some(result) =
                    try_match_device(&adapter, addr, filter, &mut reported, &mut on_found).await?
                {
                    return Ok(Some(result));
                }
            }
        }

        Ok::<Option<R>, Error>(None)
    };

    let timeout = Timer::after(Duration::from_secs(
        scan_timeout.unwrap_or(DEFAULT_SCAN_TIMEOUT_SECS) as u64,
    ));

    let outcome = match select(scan_fut, timeout).await {
        Either::First(result) => result?,
        Either::Second(_) => None,
    };

    outcome.ok_or_else(|| {
        warn!(
            "No commissionable Matter device matching the filter was found within the scan timeout"
        );
        ErrorCode::NoNetworkInterface.into()
    })
}

/// If the device at `addr` advertises Matter service data that parses and matches `filter`, and it
/// has not been reported yet, invoke `on_found` and return its result.
async fn try_match_device<F, R>(
    adapter: &Adapter,
    addr: Address,
    filter: &CommissionableFilter,
    reported: &mut heapless::Vec<BtAddr, 16>,
    on_found: &mut F,
) -> Result<Option<R>, Error>
where
    F: FnMut(BtAddr, &AdvData) -> Option<R>,
{
    let bt_addr = BtAddr(addr.0);

    if reported.contains(&bt_addr) {
        return Ok(None);
    }

    let Ok(device) = adapter.device(addr) else {
        return Ok(None);
    };

    // The advertised service data (a `UUID -> bytes` map); look for the Matter one.
    let Ok(Some(service_data)) = device.service_data().await else {
        return Ok(None);
    };

    let Some(bytes) = service_data.get(&Uuid::from_u128(MATTER_BLE_SERVICE_UUID)) else {
        return Ok(None);
    };

    let Some(adv) = AdvData::parse_service_data(bytes) else {
        return Ok(None);
    };

    if !adv.matches(filter) {
        return Ok(None);
    }

    // Report each matching device at most once. If the dedup buffer is full we simply stop
    // deduplicating (and may re-report); never drop an actual match on the floor.
    let _ = reported.push(bt_addr);

    debug!("Matched commissionable device {} (adv: {:?})", bt_addr, adv);

    Ok(on_found(bt_addr, &adv))
}

/// Run the GATT central (Commissioner-side) BTP transport using the `bluer` crate.
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
/// `matter.run(.., &btp, &btp, ..)` pumps the transport.
///
/// This function returns once the peer disconnects, the session times out, or an error occurs.
/// It does not loop / reconnect - a Commissioner establishes one BTP session for the duration of
/// commissioning.
///
/// `addr` must belong to a device that BlueZ already knows about (i.e. one that has been discovered
/// at least once - typically via a preceding [`scan`] on the same adapter).
///
/// # Arguments
/// - `adapter_name`: The Bluetooth adapter to use. If `None`, the default adapter is used. It must
///   be the same adapter the device was discovered on.
/// - `addr`: The Bluetooth address of the device to connect to (from [`scan`]).
/// - `btp`: The BTP session to drive.
pub async fn run_central(adapter_name: Option<&str>, addr: BtAddr, btp: &Btp) -> Result<(), Error> {
    let session = bluer::Session::new().await?;

    // Register a "NoInputNoOutput" agent that will accept all incoming requests.
    let _handle = session.register_agent(Agent::default()).await?;

    let adapter = open_adapter(&session, adapter_name).await?;
    adapter.set_powered(true).await?;

    let device = adapter.device(Address(addr.0))?;

    info!("Connecting to commissionable device {}", addr);

    connect_with_retry(&device).await?;

    // Discover the Matter GATT service and its C1/C2 characteristics. `Device::services()`
    // internally waits for the remote GATT services to be resolved first.
    let (c1, c2) = discover_matter_characteristics(&device).await?;

    debug!("Discovered Matter GATT characteristics C1/C2");

    // Subscribe to C2 indications before we start the handshake, so we don't miss the peer's
    // Handshake Response.
    let c2_notify = c2.notify().await?;
    let mut c2_notify = pin!(c2_notify);

    // We are the initiator: drive the BTP handshake from our side.
    //
    // NOTE: we deliberately do NOT `btp.reset()` here - resetting would race with,
    // and wipe, any Matter SDU the caller has already queued (e.g. the PASE
    // PBKDFParamRequest a commissioner sends as soon as the transport is up). The
    // caller resets + sets the initiator role before driving Matter traffic.
    btp.set_initiator(true);

    // We pass `None` for the GATT MTU (as the peripheral side does), relying on the BTP handshake
    // to negotiate the effective MTU. `bluer`'s simple `write`/`notify` don't surface it anyway.
    let gatt_mtu = None;

    select3(
        wait_central_complete(btp, &device),
        process_c2_indications(btp, addr, gatt_mtu, &mut c2_notify),
        process_c1_writes(btp, gatt_mtu, &c1, &mut [0; 512]),
    )
    .coalesce()
    .await
}

/// Feed C2 indications into the BTP session.
async fn process_c2_indications(
    btp: &Btp,
    peer_addr: BtAddr,
    gatt_mtu: Option<u16>,
    c2_notify: &mut (impl StreamExt<Item = Vec<u8>> + Unpin),
) -> Result<(), Error> {
    while let Some(value) = c2_notify.next().await {
        // An empty payload is never a valid BTP frame, and handing one to the BTP
        // layer would fail the whole session rather than ignore a stray indication.
        //
        // The `zbus` backend *must* filter these, as BlueZ delivers the
        // characteristic's initial (empty) `Value` as a property change right after
        // subscribing. `bluer` hands us a real notification stream instead, so here
        // this is belt-and-braces - but it costs one comparison, and what it guards
        // against is a dropped connection.
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

    // The notification stream ended - treat as a disconnect.
    Ok(())
}

/// Drive BTP output and write it to characteristic `C1` (as an acknowledged GATT Write Request).
async fn process_c1_writes(
    btp: &Btp,
    gatt_mtu: Option<u16>,
    c1: &RemoteCharacteristic,
    buf: &mut [u8],
) -> Result<(), Error> {
    // BTP writes to `C1` are GATT "Write Requests" (acknowledged `ATT_WRITE_REQ`),
    // as mandated by the Matter Core spec (§4.19.4: clients use the GATT Write
    // Characteristic Value sub-procedure). Beyond conformance, awaiting each Write
    // Response is the client-to-server half of BTP flow control: it paces the
    // segments of a multi-segment SDU (e.g. the AddNOC request) one at a time, so
    // the server's ATT layer doesn't drop back-to-back segments.
    let req = bluer::gatt::remote::CharacteristicWriteRequest {
        op_type: WriteOp::Request,
        ..Default::default()
    };

    loop {
        let len = btp.process_outgoing(gatt_mtu, buf)?;

        if len > 0 {
            trace!("Writing to C1: {:?}", &buf[..len]);

            c1.write_ext(&buf[..len], &req).await?;
        } else {
            btp.wait_outgoing().await;
        }
    }
}

/// Wait for the BTP session to complete because it timed out (no data from the peer for the BTP
/// idle timeout).
///
/// We deliberately do NOT also race a `Connected == false` watch here: BlueZ can briefly report a
/// device as not-connected during a busy session (e.g. an LE connection-parameter update right
/// after PASE), which would spuriously abort commissioning. A genuine disconnect surfaces promptly
/// as an error from the `C1` write / `C2` notify paths instead.
async fn wait_central_complete(btp: &Btp, _device: &bluer::Device) -> Result<(), Error> {
    btp.wait_timeout().await;
    info!("Timeout while waiting for data from the peer");

    Ok(())
}

/// Connect to the device, retrying a bounded number of times on transient failures
/// (notably `le-connection-abort-by-local`; see [`CONNECT_ATTEMPTS`]).
async fn connect_with_retry(device: &bluer::Device) -> Result<(), Error> {
    for attempt in 1..=CONNECT_ATTEMPTS {
        match device.connect().await {
            Ok(()) => return Ok(()),
            Err(e) if attempt < CONNECT_ATTEMPTS => {
                warn!(
                    "Connect attempt {}/{} failed ({:?}); retrying",
                    attempt, CONNECT_ATTEMPTS, e
                );
                Timer::after(Duration::from_millis(CONNECT_RETRY_DELAY_MS)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Unreachable: the last attempt either returns `Ok` or the `Err` arm above.
    Err(ErrorCode::NoNetworkInterface.into())
}

/// Find the `C1` (write) and `C2` (indicate) characteristics of the Matter GATT service on the
/// connected device.
async fn discover_matter_characteristics(
    device: &bluer::Device,
) -> Result<(RemoteCharacteristic, RemoteCharacteristic), Error> {
    let matter_service_uuid = Uuid::from_u128(MATTER_BLE_SERVICE_UUID);
    let c1_uuid = Uuid::from_u128(C1_CHARACTERISTIC_UUID);
    let c2_uuid = Uuid::from_u128(C2_CHARACTERISTIC_UUID);

    for service in device.services().await? {
        if service.uuid().await? != matter_service_uuid {
            continue;
        }

        let mut c1 = None;
        let mut c2 = None;

        for chr in service.characteristics().await? {
            let uuid = chr.uuid().await?;
            if uuid == c1_uuid {
                c1 = Some(chr);
            } else if uuid == c2_uuid {
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

        return Ok((c1, c2));
    }

    warn!("The connected device does not expose the Matter GATT service");
    Err(ErrorCode::NoNetworkInterface.into())
}

/// Open the Bluetooth adapter designated by `adapter_name`, or the default adapter if `None`.
async fn open_adapter(
    session: &bluer::Session,
    adapter_name: Option<&str>,
) -> Result<Adapter, Error> {
    let adapter = if let Some(adapter_name) = adapter_name {
        session.adapter(adapter_name)?
    } else {
        session.default_adapter().await?
    };

    Ok(adapter)
}

/// Process incoming writes on characteristic `C1` and pass them to the BTP session for processing.
async fn process_write(
    btp: &Btp,
    receiver: &mut Receiver<(Vec<u8>, CharacteristicWriteRequest)>,
) -> Result<(), Error> {
    while let Some((value, req)) = receiver.recv().await {
        btp.process_incoming(Some(req.mtu), BtAddr(req.device_address.0), &value)?;
    }

    Ok(())
}

/// Indicate new data on characteristic `C2` to a remote peer.
async fn process_indicate(
    btp: &Btp,
    gatt_mtu: Option<u16>,
    notifier: &CharacteristicWriter,
    buf: &mut [u8],
) -> Result<(), Error> {
    loop {
        let len = btp.process_outgoing(gatt_mtu, buf)?;

        if len > 0 {
            notifier.send(&buf[..len]).await?;
        } else {
            btp.wait_outgoing().await;
        }
    }
}

/// Pull new subscription notifications from the `C2` characteristic and drop then on the floor.
/// We need just one active subscription at a time.
async fn process_cc_events(cc: &mut CharacteristicControl) -> Result<(), Error> {
    loop {
        let _ = notifier(cc).await;
    }
}

/// Listen for unsubscription from characteristic `C2` as well as for session connection timeout.
async fn wait_complete(btp: &Btp, notifier: &CharacteristicWriter) -> Result<(), Error> {
    let result = select(notifier.closed(), btp.wait_timeout()).await;

    match result {
        Either::First(_) => info!("Peer unsubscribed"),
        Either::Second(_) => info!("Timeout while waiting for data from the peer"),
    }

    Ok(())
}

/// Wait for the next notification subscription event on the given `CharacteristicControl` and return the corresponding `CharacteristicWriter`.
async fn notifier(cc: &mut CharacteristicControl) -> CharacteristicWriter {
    loop {
        if let Some(notifier) = cc.next().await.map(|event| {
            let CharacteristicControlEvent::Notify(notifier) = event else {
                // Should never happen, as characteristic `C2` is not marked as capable of taking writes.
                unreachable!();
            };

            notifier
        }) {
            break notifier;
        }
    }
}
