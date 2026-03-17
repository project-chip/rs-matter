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

//! A `GattPeripheral` implementation using the BlueZ GATT stack via the `bluer` crate.

use core::iter::once;

use bluer::adv::Advertisement;
use bluer::agent::Agent;
use bluer::gatt::local::{
    characteristic_control, Application, Characteristic, CharacteristicControl,
    CharacteristicControlEvent, CharacteristicNotify, CharacteristicNotifyMethod,
    CharacteristicWrite, CharacteristicWriteMethod, CharacteristicWriteRequest, Service,
};
use bluer::gatt::CharacteristicWriter;
use bluer::Uuid;

use embassy_futures::select::{select, select4};

use tokio::sync::mpsc::Receiver;
use tokio_stream::StreamExt;

use crate::error::Error;
use crate::transport::network::btp::Btp;
use crate::transport::network::BtAddr;
use crate::utils::select::Coalesce;

use super::{AdvData, C1_CHARACTERISTIC_UUID, C2_CHARACTERISTIC_UUID, MATTER_BLE_SERVICE_UUID};

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

    info!(
        "Advertising on Bluetooth adapter {} with address {}",
        adapter.name(),
        BtAddr(adapter.address().await?.0)
    );

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

    info!(
        "Serving GATT echo service on Bluetooth adapter {}",
        adapter.name()
    );

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

    loop {
        let notifier = {
            // Advertise until we get a connection + subscription to char C2
            // Then stop advertising, as per the Matter Core spec, since the peer is now connected and can interact with the GATT service.

            let _adv_handle = adapter.advertise(le_advertisement.clone()).await?;

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
    select(notifier.closed(), btp.wait_timeout()).await;

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
