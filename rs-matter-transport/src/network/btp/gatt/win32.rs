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

//! A GATT Peripheral and a GATT Central over the Bluetooth LE API of Windows
//! (WinRT), on the default Bluetooth adapter.
//!
//! WinRT runs event handlers on its own threads; channels bring what they get
//! to the futures here.

use core::future::{Future, IntoFuture};

use async_channel::{Receiver, Sender};

use windows::core::{IInspectable, GUID};
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher,
    BluetoothLEScanningMode,
};
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristic, GattCharacteristicProperties,
    GattClientCharacteristicConfigurationDescriptorValue, GattCommunicationStatus,
    GattDeviceService, GattLocalCharacteristic, GattLocalCharacteristicParameters,
    GattProtectionLevel, GattServiceProvider, GattServiceProviderAdvertisementStatus,
    GattServiceProviderAdvertisementStatusChangedEventArgs,
    GattServiceProviderAdvertisingParameters, GattSession, GattSubscribedClient,
    GattValueChangedEventArgs, GattWriteOption, GattWriteRequestedEventArgs,
};
use windows::Devices::Bluetooth::{
    BluetoothAdapter, BluetoothCacheMode, BluetoothError, BluetoothLEDevice,
};
use windows::Devices::Radios::RadioState;
use windows::Foundation::{Deferral, TypedEventHandler};
use windows::Storage::Streams::{DataReader, DataWriter, IBuffer};

use crate::error::{Error, ErrorCode};
use crate::network::btp::Btp;
use crate::network::mdns::CommissionableFilter;
use crate::network::BtAddr;
use crate::utils::futures::{select, select3, Coalesce, Either};
use crate::utils::timers::{Duration, Instant, Timer};

use super::{AdvData, C1_CHARACTERISTIC_UUID, C2_CHARACTERISTIC_UUID, MATTER_BLE_SERVICE_UUID};

/// The default amount of time [`scan`] will scan for a matching commissionable
/// advertisement before giving up.
pub const DEFAULT_SCAN_TIMEOUT_SECS: u16 = 60;

/// Advertisements waiting for the scan; more are dropped, as devices advertise
/// again soon.
const ADVERTISEMENTS_QUEUED: usize = 16;

/// C1 writes waiting for the BTP session. The first one comes before the peer
/// subscribes to C2, so that the session can start.
const C1_WRITES_QUEUED: usize = 8;

/// How many times the first GATT request, which connects, is tried, and the
/// wait between tries.
const CONNECT_ATTEMPTS: u8 = 3;
const CONNECT_RETRY_DELAY_MS: u64 = 500;

/// The ATT MTU before the peers exchange theirs.
const DEFAULT_ATT_MTU: u16 = 23;

/// How long to wait for Windows to exchange a larger ATT MTU after connecting,
/// and how often to look.
const MTU_WAIT_MS: u64 = 1000;
const MTU_POLL_MS: u64 = 50;

/// Runs its closure when dropped: ends what a future started, also when the
/// future is cancelled.
struct OnDrop<F: FnMut()>(F);

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)()
    }
}

/// A write to C1, already acknowledged to the peer.
struct C1Write {
    addr: BtAddr,
    mtu: u16,
    value: Vec<u8>,
}

/// Run the GATT peripheral: serve the Matter GATT service with its `C1` and `C2`
/// characteristics, advertise it, and carry `btp` over the connection of each
/// client that subscribes to `C2`, one at a time.
///
/// Advertising goes on during a session, as Windows has no documented way to stop
/// it and keep the service published. It carries no name of ours, as Windows does
/// not take one.
///
/// # Arguments
/// - `service_adv_data`: The advertising data of the service.
/// - `btp`: The BTP session to drive.
pub async fn run_peripheral(service_adv_data: &AdvData, btp: &Btp) -> Result<(), Error> {
    if let Some(why) = peripheral_unavailable().await {
        warn!("Bluetooth: cannot run the GATT peripheral: {}", why);
        return Err(ErrorCode::NoNetworkInterface.into());
    }

    let what = "create the Matter GATT service";

    let created = result(GattServiceProvider::CreateAsync(GUID::from_u128(
        MATTER_BLE_SERVICE_UUID,
    )))
    .await
    .map_err(btp_error(what))?;
    check_bluetooth(created.Error().map_err(btp_error(what))?, what)?;
    let provider = created.ServiceProvider().map_err(btp_error(what))?;

    let c1 = local_characteristic(
        &provider,
        C1_CHARACTERISTIC_UUID,
        GattCharacteristicProperties::Write,
    )
    .await?;
    let c2 = local_characteristic(
        &provider,
        C2_CHARACTERISTIC_UUID,
        GattCharacteristicProperties::Indicate,
    )
    .await?;

    let (request_sender, requests) = async_channel::unbounded();
    let token = {
        let handler =
            TypedEventHandler::<GattLocalCharacteristic, GattWriteRequestedEventArgs>::new(
                move |_, args| {
                    if let Some(args) = args.as_ref() {
                        let _ = request_sender.try_send((args.clone(), args.GetDeferral()?));
                    }

                    Ok(())
                },
            );
        c1.WriteRequested(&handler).map_err(btp_error(what))?
    };
    let _requested = OnDrop(|| {
        let _ = c1.RemoveWriteRequested(token);
    });

    // Only says that the list changed: whoever waits reads the list itself.
    let (change_sender, changes) = async_channel::bounded(1);
    let token = {
        let handler =
            TypedEventHandler::<GattLocalCharacteristic, IInspectable>::new(move |_, _| {
                let _ = change_sender.try_send(());

                Ok(())
            });
        c2.SubscribedClientsChanged(&handler)
            .map_err(btp_error(what))?
    };
    let _subscribed = OnDrop(|| {
        let _ = c2.RemoveSubscribedClientsChanged(token);
    });

    let (abort_sender, aborted) = async_channel::bounded(1);
    let token = {
        let handler = TypedEventHandler::<
            GattServiceProvider,
            GattServiceProviderAdvertisementStatusChangedEventArgs,
        >::new(move |_, args| {
            if let Some(args) = args.as_ref() {
                let status = args.Status()?;

                if status == GattServiceProviderAdvertisementStatus::Aborted {
                    let _ = abort_sender.try_send(args.Error()?);
                } else if status
                    == GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData
                {
                    warn!("Bluetooth: the Matter advertisement went out without all of its data");
                }
            }

            Ok(())
        });
        provider
            .AdvertisementStatusChanged(&handler)
            .map_err(btp_error(what))?
    };
    let _advertising_status = OnDrop(|| {
        let _ = provider.RemoveAdvertisementStatusChanged(token);
    });

    let what = "advertise the Matter GATT service";

    let parameters = GattServiceProviderAdvertisingParameters::new().map_err(btp_error(what))?;
    parameters.SetIsConnectable(true).map_err(btp_error(what))?;
    parameters
        .SetIsDiscoverable(true)
        .map_err(btp_error(what))?;
    parameters
        .SetServiceData(
            &buffer(&service_adv_data.service_payload_iter().collect::<Vec<_>>())
                .map_err(btp_error(what))?,
        )
        .map_err(btp_error(what))?;

    provider
        .StartAdvertisingWithParameters(&parameters)
        .map_err(btp_error(what))?;
    let _advertising = OnDrop(|| {
        let _ = provider.StopAdvertising();
    });

    info!("Advertising the Matter GATT BTP service");

    let (write_sender, writes) = async_channel::bounded(C1_WRITES_QUEUED);

    select3(
        wait_advertising_aborted(&aborted),
        accept_c1_writes(&requests, &write_sender),
        serve_sessions(btp, &c2, &changes, &writes),
    )
    .coalesce()
    .await
}

/// Report the commissionable devices matching `filter` to `on_found`, each once.
///
/// This is the discovery half of the Controller / Commissioner role (the connect
/// half is [`run_central`]). `on_found` decides when to stop: returning
/// `Some(value)` stops the scan and makes `scan` return `Ok(value)`. If the
/// timeout elapses with no accepted match, `scan` returns `Err(NoNetworkInterface)`.
///
/// # Arguments
/// - `filter`: The commissionable-device filter to match advertisements against.
/// - `scan_timeout`: How long to scan before giving up. If `None`, [`DEFAULT_SCAN_TIMEOUT_SECS`].
/// - `on_found`: Callback invoked for each newly-matched device; returning `Some` stops the scan.
pub async fn scan<F, R>(
    filter: &CommissionableFilter,
    scan_timeout: Option<u16>,
    mut on_found: F,
) -> Result<R, Error>
where
    F: FnMut(BtAddr, &AdvData) -> Option<R>,
{
    let what = "scan for Bluetooth LE devices";

    let watcher = BluetoothLEAdvertisementWatcher::new().map_err(btp_error(what))?;
    watcher
        .SetScanningMode(BluetoothLEScanningMode::Active)
        .map_err(btp_error(what))?;

    let (sender, advertisements) = async_channel::bounded(ADVERTISEMENTS_QUEUED);
    let token = {
        let handler = TypedEventHandler::<
            BluetoothLEAdvertisementWatcher,
            BluetoothLEAdvertisementReceivedEventArgs,
        >::new(move |_, args| {
            if let Some(found) = args.as_ref().and_then(matter_advertisement) {
                let _ = sender.try_send(found);
            }

            Ok(())
        });

        watcher.Received(&handler).map_err(btp_error(what))?
    };
    let _watching = OnDrop(|| {
        let _ = watcher.Stop();
        let _ = watcher.RemoveReceived(token);
    });
    watcher.Start().map_err(btp_error(what))?;

    info!(
        "Scanning for a commissionable Matter device (filter: {:?})",
        filter
    );

    let mut reported = Vec::new();

    let timeout = Timer::after(Duration::from_secs(
        scan_timeout.unwrap_or(DEFAULT_SCAN_TIMEOUT_SECS).into(),
    ));

    let found = report_advertisements(&advertisements, filter, &mut reported, &mut on_found);

    match select(found, timeout).await {
        Either::First(Some(result)) => Ok(result),
        _ => {
            warn!(
                "No commissionable Matter device matching the filter was found within the scan timeout"
            );
            Err(ErrorCode::NoNetworkInterface.into())
        }
    }
}

/// Connect to the device at `addr`, found by [`scan`], and carry `btp` over the
/// connection, as the initiator, until it fails or the peer goes silent.
///
/// The caller passes commissioning requests to the device as `Address::Btp(addr)`
/// while `matter.run(.., &btp, &btp, ..)` pumps the transport. This function does
/// not reconnect.
pub async fn run_central(addr: BtAddr, btp: &Btp) -> Result<(), Error> {
    info!("Connecting to commissionable device {}", addr);

    let device = result(BluetoothLEDevice::FromBluetoothAddressAsync(windows_addr(
        addr,
    )))
    .await
    .map_err(btp_error("find the device"))?;
    // Windows keeps the connection while the device, its GATT session or its
    // services are open.
    let _device = OnDrop(|| {
        let _ = device.Close();
    });

    // Windows connects on the first GATT request, and drops an idle connection
    // unless the session keeps it.
    let session = result(
        device
            .BluetoothDeviceId()
            .and_then(|id| GattSession::FromDeviceIdAsync(&id)),
    )
    .await
    .map_err(btp_error("open a GATT session"))?;
    let _session = OnDrop(|| {
        let _ = session.Close();
    });
    session
        .SetMaintainConnection(true)
        .map_err(btp_error("keep the connection"))?;

    let service = matter_service(&device).await?;
    let _service = OnDrop(|| {
        let _ = service.Close();
    });

    let c1 = characteristic(&service, C1_CHARACTERISTIC_UUID, "C1").await?;
    let c2 = characteristic(&service, C2_CHARACTERISTIC_UUID, "C2").await?;

    let gatt_mtu = att_mtu(&session).await;

    debug!(
        "Discovered Matter GATT characteristics C1/C2, ATT MTU: {:?}",
        gatt_mtu
    );

    // The peripheral prepares its capabilities response after the C1 write,
    // then sends it when we subscribe to C2. Subscribe-first loses that trigger
    // on devices using the Matter SDK's BLEEndPoint implementation.
    btp.set_initiator(true);
    let mut buf = [0; 512];
    let len = btp.process_outgoing(gatt_mtu, &mut buf)?;
    if len == 0 {
        return Err(ErrorCode::InvalidState.into());
    }
    write_c1(&c1, &buf[..len]).await?;

    let (sender, indications) = async_channel::unbounded();
    let token = {
        let handler = TypedEventHandler::<GattCharacteristic, GattValueChangedEventArgs>::new(
            move |_, args| {
                let value = args
                    .as_ref()
                    .and_then(|args| args.CharacteristicValue().ok())
                    .and_then(|value| bytes(&value).ok());
                if let Some(value) = value {
                    let _ = sender.try_send(value);
                }

                Ok(())
            },
        );
        c2.ValueChanged(&handler)
            .map_err(btp_error("listen to C2"))?
    };
    let _listening = OnDrop(|| {
        let _ = c2.RemoveValueChanged(token);
    });

    info!("C1 handshake acknowledged; subscribing to C2 indications");
    let status = result(c2.WriteClientCharacteristicConfigurationDescriptorAsync(
        GattClientCharacteristicConfigurationDescriptorValue::Indicate,
    ))
    .await
    .map_err(btp_error("subscribe to C2"))?;
    check(status, "subscribe to C2")?;
    info!("C2 indication subscription completed; waiting for BTP response");

    select3(
        wait_central_timeout(btp),
        process_c2_indications(btp, addr, gatt_mtu, &indications),
        process_c1_writes(btp, gatt_mtu, &c1, &mut buf),
    )
    .coalesce()
    .await
}

/// Why [`run_central`] cannot run now, if it cannot: there is no Bluetooth LE
/// adapter that can connect to devices, or it is off.
pub fn central_unavailable() -> impl Future<Output = Option<&'static str>> {
    unavailable(
        BluetoothAdapter::IsCentralRoleSupported,
        "the Bluetooth adapter cannot connect to Bluetooth LE devices",
    )
}

/// Why [`run_peripheral`] cannot run now, if it cannot: there is no Bluetooth LE
/// adapter that can advertise and take connections, or it is off.
pub fn peripheral_unavailable() -> impl Future<Output = Option<&'static str>> {
    unavailable(
        BluetoothAdapter::IsPeripheralRoleSupported,
        "the Bluetooth adapter cannot act as a Bluetooth LE peripheral",
    )
}

async fn unavailable(
    role_supported: fn(&BluetoothAdapter) -> windows::core::Result<bool>,
    role_unsupported: &'static str,
) -> Option<&'static str> {
    let Ok(adapter) = result(BluetoothAdapter::GetDefaultAsync()).await else {
        return Some("there is no Bluetooth adapter");
    };

    if !adapter.IsLowEnergySupported().unwrap_or(false)
        || !role_supported(&adapter).unwrap_or(false)
    {
        return Some(role_unsupported);
    }

    // An unknown radio state is no reason to refuse.
    let state = result(adapter.GetRadioAsync())
        .await
        .and_then(|radio| radio.State());
    if state.is_ok_and(|state| state != RadioState::On) {
        return Some("the Bluetooth adapter is off");
    }

    None
}

/// Add a characteristic to the Matter GATT service. No pairing is asked for,
/// as Matter secures its own traffic.
async fn local_characteristic(
    provider: &GattServiceProvider,
    uuid: u128,
    properties: GattCharacteristicProperties,
) -> Result<GattLocalCharacteristic, Error> {
    let what = "create a Matter GATT characteristic";

    let parameters = GattLocalCharacteristicParameters::new().map_err(btp_error(what))?;
    parameters
        .SetCharacteristicProperties(properties)
        .map_err(btp_error(what))?;
    parameters
        .SetReadProtectionLevel(GattProtectionLevel::Plain)
        .map_err(btp_error(what))?;
    parameters
        .SetWriteProtectionLevel(GattProtectionLevel::Plain)
        .map_err(btp_error(what))?;

    let created =
        result(provider.Service().and_then(|service| {
            service.CreateCharacteristicAsync(GUID::from_u128(uuid), &parameters)
        }))
        .await
        .map_err(btp_error(what))?;
    check_bluetooth(created.Error().map_err(btp_error(what))?, what)?;

    created.Characteristic().map_err(btp_error(what))
}

/// Fail once Windows gives up advertising.
async fn wait_advertising_aborted(aborted: &Receiver<BluetoothError>) -> Result<(), Error> {
    if let Ok(error) = aborted.recv().await {
        warn!(
            "Bluetooth: advertising the Matter GATT service aborted: {:?}",
            error
        );
    }

    Err(ErrorCode::BtpError.into())
}

/// Acknowledge the writes to C1 as they come, and queue them for the BTP session.
///
/// This does not wait for a session: the peer subscribes to C2 only once its first
/// write is acknowledged.
async fn accept_c1_writes(
    requests: &Receiver<(GattWriteRequestedEventArgs, Deferral)>,
    writes: &Sender<C1Write>,
) -> Result<(), Error> {
    while let Ok((args, deferral)) = requests.recv().await {
        if let Err(e) = accept_c1_write(&args, writes).await {
            warn!("Bluetooth: cannot take a write to C1: {}", e);
        }

        let _ = deferral.Complete();
    }

    Ok(())
}

async fn accept_c1_write(
    args: &GattWriteRequestedEventArgs,
    writes: &Sender<C1Write>,
) -> windows::core::Result<()> {
    let request = args.GetRequestAsync()?.await?;
    let session = args.Session()?;

    let Some(addr) = session_addr(&session) else {
        return Ok(());
    };

    let write = C1Write {
        addr,
        mtu: session.MaxPduSize()?,
        value: bytes(&request.Value()?)?,
    };

    let _ = writes.send(write).await;

    if request.Option()? == GattWriteOption::WriteWithResponse {
        request.Respond()?;
    }

    Ok(())
}

/// Serve the clients that subscribe to C2, one at a time.
async fn serve_sessions(
    btp: &Btp,
    c2: &GattLocalCharacteristic,
    changes: &Receiver<()>,
    writes: &Receiver<C1Write>,
) -> Result<(), Error> {
    // The client of the last session, for as long as it stays subscribed: its
    // session may have ended on a timeout.
    let mut served = None;

    loop {
        let (client, peer) = wait_subscribed(c2, changes, &mut served).await?;

        info!("Peer {} subscribed to C2", peer);

        btp.reset();

        select3(
            wait_complete(btp, c2, peer, changes),
            process_write(btp, peer, writes),
            process_indicate(btp, c2, &client, &mut [0; 512]),
        )
        .coalesce()
        .await?;

        served = Some(peer);

        while writes.try_recv().is_ok() {}

        // Windows has no call to drop a connection; this lets it go of its own
        // accord, if nothing else uses it.
        if let Ok(session) = client.Session() {
            let _ = session.Close();
        }
    }
}

/// Wait for a client subscribed to C2, other than the one already `served`.
async fn wait_subscribed(
    c2: &GattLocalCharacteristic,
    changes: &Receiver<()>,
    served: &mut Option<BtAddr>,
) -> Result<(GattSubscribedClient, BtAddr), Error> {
    loop {
        let clients = subscribed_clients(c2)?;

        if !clients.iter().any(|(_, addr)| Some(*addr) == *served) {
            *served = None;
        }

        if let Some(found) = clients.into_iter().find(|(_, addr)| Some(*addr) != *served) {
            return Ok(found);
        }

        let _ = changes.recv().await;
    }
}

/// The clients subscribed to C2, with their addresses.
fn subscribed_clients(
    c2: &GattLocalCharacteristic,
) -> Result<Vec<(GattSubscribedClient, BtAddr)>, Error> {
    let clients = c2
        .SubscribedClients()
        .map_err(btp_error("read the subscribers of C2"))?;

    Ok(clients
        .into_iter()
        .filter_map(|client| {
            let addr = session_addr(&client.Session().ok()?)?;

            Some((client, addr))
        })
        .collect())
}

/// Listen for `peer` unsubscribing from C2, and for the session timing out.
async fn wait_complete(
    btp: &Btp,
    c2: &GattLocalCharacteristic,
    peer: BtAddr,
    changes: &Receiver<()>,
) -> Result<(), Error> {
    match select(wait_unsubscribed(c2, peer, changes), btp.wait_timeout()).await {
        Either::First(result) => {
            info!("Peer unsubscribed");
            result
        }
        Either::Second(_) => {
            info!("Timeout while waiting for data from the peer");
            Ok(())
        }
    }
}

async fn wait_unsubscribed(
    c2: &GattLocalCharacteristic,
    peer: BtAddr,
    changes: &Receiver<()>,
) -> Result<(), Error> {
    while subscribed_clients(c2)?
        .iter()
        .any(|(_, addr)| *addr == peer)
    {
        let _ = changes.recv().await;
    }

    Ok(())
}

/// Pass the writes of `peer` to C1 to the BTP session. Other clients are ignored:
/// there is one session at a time.
async fn process_write(btp: &Btp, peer: BtAddr, writes: &Receiver<C1Write>) -> Result<(), Error> {
    while let Ok(write) = writes.recv().await {
        if write.addr == peer {
            btp.process_incoming(Some(write.mtu), write.addr, &write.value)?;
        } else {
            warn!("Ignoring a write to C1 from {}, not in session", write.addr);
        }
    }

    Ok(())
}

/// Indicate new data on C2 to the peer. A failed indication ends the session.
async fn process_indicate(
    btp: &Btp,
    c2: &GattLocalCharacteristic,
    client: &GattSubscribedClient,
    buf: &mut [u8],
) -> Result<(), Error> {
    let what = "indicate on C2";

    loop {
        let len = btp.process_outgoing(None, buf)?;

        if len > 0 {
            let sent = result(
                buffer(&buf[..len])
                    .and_then(|value| c2.NotifyValueForSubscribedClientAsync(&value, client)),
            )
            .await
            .map_err(btp_error(what))?;
            let status = sent.Status().map_err(btp_error(what))?;

            if status != GattCommunicationStatus::Success {
                warn!("Bluetooth: cannot {}: GATT status {:?}", what, status);
                return Ok(());
            }
        } else {
            btp.wait_outgoing().await;
        }
    }
}

/// The address of the peer of `session`.
fn session_addr(session: &GattSession) -> Option<BtAddr> {
    let id = session.DeviceId().ok()?.Id().ok()?.to_string();
    let addr = device_id_addr(&id);

    if addr.is_none() {
        warn!("Bluetooth: no peer address in the device ID {}", id);
    }

    addr
}

/// The peer address at the end of a Bluetooth LE device ID of Windows:
/// `BluetoothLE#BluetoothLE<adapter address>-<peer address>`.
fn device_id_addr(id: &str) -> Option<BtAddr> {
    let (_, addr) = id.rsplit_once('-')?;

    let mut parts = addr.split(':');
    let mut bytes = [0; 6];

    for byte in &mut bytes {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }

    parts.next().is_none().then_some(BtAddr(bytes))
}

/// Hand the matching advertisements to `on_found`, each device once, until it
/// returns `Some`.
async fn report_advertisements<F, R>(
    advertisements: &Receiver<(BtAddr, AdvData)>,
    filter: &CommissionableFilter,
    reported: &mut Vec<BtAddr>,
    on_found: &mut F,
) -> Option<R>
where
    F: FnMut(BtAddr, &AdvData) -> Option<R>,
{
    while let Ok((addr, adv)) = advertisements.recv().await {
        if reported.contains(&addr) || !adv.matches(filter) {
            continue;
        }
        reported.push(addr);

        debug!("Matched commissionable device {} (adv: {:?})", addr, adv);

        if let Some(result) = on_found(addr, &adv) {
            return Some(result);
        }
    }

    None
}

/// The Matter commissionable advertisement in `args`, if it has one.
fn matter_advertisement(
    args: &BluetoothLEAdvertisementReceivedEventArgs,
) -> Option<(BtAddr, AdvData)> {
    // The advertisement as sent: a length-type-data record per section.
    let mut raw = Vec::new();
    for section in args.Advertisement().ok()?.DataSections().ok()? {
        let data = bytes(&section.Data().ok()?).ok()?;
        raw.push(u8::try_from(data.len() + 1).ok()?);
        raw.push(section.DataType().ok()?);
        raw.extend_from_slice(&data);
    }

    let adv = AdvData::parse_adv(&raw)?;

    Some((bt_addr(args.BluetoothAddress().ok()?), adv))
}

/// The device's Matter GATT service. Asking for it connects, so a device that
/// is unreachable is asked again a few times.
async fn matter_service(device: &BluetoothLEDevice) -> Result<GattDeviceService, Error> {
    let what = "discover the Matter GATT service";

    let mut attempt = 1;
    let services = loop {
        // Uncached: Windows may remember the services of another device that
        // had this address.
        let services = result(device.GetGattServicesForUuidWithCacheModeAsync(
            GUID::from_u128(MATTER_BLE_SERVICE_UUID),
            BluetoothCacheMode::Uncached,
        ))
        .await
        .map_err(btp_error(what))?;
        let status = services.Status().map_err(btp_error(what))?;

        if status != GattCommunicationStatus::Unreachable || attempt == CONNECT_ATTEMPTS {
            check(status, what)?;
            break services;
        }

        warn!(
            "Connect attempt {}/{}: the device is unreachable; retrying",
            attempt, CONNECT_ATTEMPTS
        );
        attempt += 1;
        Timer::after(Duration::from_millis(CONNECT_RETRY_DELAY_MS)).await;
    };

    services
        .Services()
        .map_err(btp_error(what))?
        .into_iter()
        .next()
        .ok_or_else(|| {
            warn!("The connected device does not expose the Matter GATT service");
            ErrorCode::NoNetworkInterface.into()
        })
}

/// The characteristic `uuid`, called `name`, of the Matter GATT service.
async fn characteristic(
    service: &GattDeviceService,
    uuid: u128,
    name: &str,
) -> Result<GattCharacteristic, Error> {
    let what = "discover the Matter GATT characteristics";

    let characteristics = result(service.GetCharacteristicsForUuidWithCacheModeAsync(
        GUID::from_u128(uuid),
        BluetoothCacheMode::Uncached,
    ))
    .await
    .map_err(btp_error(what))?;
    check(characteristics.Status().map_err(btp_error(what))?, what)?;

    characteristics
        .Characteristics()
        .map_err(btp_error(what))?
        .into_iter()
        .next()
        .ok_or_else(|| {
            warn!(
                "The Matter GATT service is missing the {} characteristic",
                name
            );
            ErrorCode::NoNetworkInterface.into()
        })
}

/// The ATT MTU. Windows exchanges a larger one on its own after connecting,
/// so this waits a little while it still reads as the default.
async fn att_mtu(session: &GattSession) -> Option<u16> {
    let deadline = Instant::now() + Duration::from_millis(MTU_WAIT_MS);

    loop {
        let mtu = session.MaxPduSize().ok()?;
        if mtu > DEFAULT_ATT_MTU || Instant::now() >= deadline {
            return Some(mtu);
        }

        Timer::after(Duration::from_millis(MTU_POLL_MS)).await;
    }
}

/// End once the peer has sent nothing for the BTP idle timeout. A disconnect
/// shows up sooner, as a failed C1 write.
async fn wait_central_timeout(btp: &Btp) -> Result<(), Error> {
    btp.wait_timeout().await;
    info!("Timeout while waiting for data from the peer");

    Ok(())
}

/// Feed C2 indications into the BTP session.
async fn process_c2_indications(
    btp: &Btp,
    peer: BtAddr,
    gatt_mtu: Option<u16>,
    indications: &Receiver<Vec<u8>>,
) -> Result<(), Error> {
    while let Ok(value) = indications.recv().await {
        // Never a BTP frame; the BTP layer would fail the session on it.
        if value.is_empty() {
            continue;
        }

        btp.process_incoming(gatt_mtu, peer, &value)
            .inspect_err(|e| {
                warn!(
                    "C2 indication rejected by BTP: {}B, error code {:?}",
                    value.len(),
                    e.code()
                )
            })?;
    }

    Ok(())
}

/// Write the BTP output to C1.
async fn process_c1_writes(
    btp: &Btp,
    gatt_mtu: Option<u16>,
    c1: &GattCharacteristic,
    buf: &mut [u8],
) -> Result<(), Error> {
    loop {
        let len = btp.process_outgoing(gatt_mtu, buf)?;

        if len > 0 {
            write_c1(c1, &buf[..len]).await?;
        } else {
            btp.wait_outgoing().await;
        }
    }
}

/// Write `value` to C1 as a Write Request, as Matter requires; waiting for the
/// response also paces the segments.
async fn write_c1(c1: &GattCharacteristic, value: &[u8]) -> Result<(), Error> {
    let what = "write to C1";

    let status = result(buffer(value).and_then(|value| {
        c1.WriteValueWithOptionAsync(&value, GattWriteOption::WriteWithResponse)
    }))
    .await
    .map_err(btp_error(what))?;

    check(status, what)
}

/// The result of a WinRT operation, once it completes.
async fn result<O, T>(op: windows::core::Result<O>) -> windows::core::Result<T>
where
    O: IntoFuture<Output = windows::core::Result<T>>,
{
    op?.await
}

/// Fail unless the GATT request succeeded.
fn check(status: GattCommunicationStatus, what: &str) -> Result<(), Error> {
    if status == GattCommunicationStatus::Success {
        Ok(())
    } else {
        warn!("Bluetooth: cannot {}: GATT status {:?}", what, status);
        Err(ErrorCode::BtpError.into())
    }
}

/// Fail unless the Bluetooth call succeeded.
fn check_bluetooth(error: BluetoothError, what: &str) -> Result<(), Error> {
    if error == BluetoothError::Success {
        Ok(())
    } else {
        warn!("Bluetooth: cannot {}: {:?}", what, error);
        Err(ErrorCode::BtpError.into())
    }
}

/// Log a WinRT error with what failed, and turn it into a BTP error.
fn btp_error(what: &str) -> impl FnOnce(windows::core::Error) -> Error + '_ {
    move |e| {
        warn!("Bluetooth: cannot {}: {}", what, e);
        ErrorCode::BtpError.into()
    }
}

/// The bytes in `buffer`.
fn bytes(buffer: &IBuffer) -> windows::core::Result<Vec<u8>> {
    let mut bytes = vec![0; buffer.Length()? as usize];
    DataReader::FromBuffer(buffer)?.ReadBytes(&mut bytes)?;

    Ok(bytes)
}

/// `bytes` in a buffer.
fn buffer(bytes: &[u8]) -> windows::core::Result<IBuffer> {
    let writer = DataWriter::new()?;
    writer.WriteBytes(bytes)?;

    writer.DetachBuffer()
}

/// Windows' address (48 bits, most significant byte first) as a `BtAddr`.
fn bt_addr(addr: u64) -> BtAddr {
    let [_, _, bytes @ ..] = addr.to_be_bytes();

    BtAddr(bytes)
}

/// A `BtAddr` as Windows' address.
fn windows_addr(addr: BtAddr) -> u64 {
    let mut bytes = [0; 8];
    bytes[2..].copy_from_slice(&addr.0);

    u64::from_be_bytes(bytes)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn addresses_round_trip() {
        let addr = BtAddr([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);

        assert_eq!(windows_addr(addr), 0x1234_5678_9ABC);
        assert_eq!(bt_addr(windows_addr(addr)), addr);
    }

    #[test]
    fn peer_address_comes_from_the_device_id() {
        assert_eq!(
            device_id_addr("BluetoothLE#BluetoothLE00:1a:7d:da:71:13-12:34:56:78:9a:bc"),
            Some(BtAddr([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]))
        );

        assert_eq!(device_id_addr("BluetoothLE#BluetoothLE"), None);
        assert_eq!(device_id_addr("x-12:34:56:78:9a"), None);
        assert_eq!(device_id_addr("x-12:34:56:78:9a:bc:de"), None);
        assert_eq!(device_id_addr("x-12:34:56:78:9a:zz"), None);
    }
}
