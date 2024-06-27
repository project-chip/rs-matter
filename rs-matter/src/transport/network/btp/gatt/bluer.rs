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

use core::iter::once;

use alloc::sync::Arc;

use bluer::adv::Advertisement;
use bluer::agent::Agent;
use bluer::gatt::local::{
    characteristic_control, Application, Characteristic, CharacteristicControl,
    CharacteristicControlEvent, CharacteristicNotify, CharacteristicNotifyMethod,
    CharacteristicWrite, CharacteristicWriteMethod, Service,
};
use bluer::gatt::CharacteristicWriter;
use bluer::Uuid;

use embassy_futures::select::{select, select_slice, Either};

use log::{info, trace, warn};

use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;

use crate::transport::network::btp::MIN_MTU;
use crate::{
    error::{Error, ErrorCode},
    transport::network::{btp::context::MAX_BTP_SESSIONS, BtAddr},
    utils::{ifmutex::IfMutex, select::Coalesce, signal::Signal, std_mutex::StdRawMutex},
};

use super::{AdvData, GattPeripheral, GattPeripheralEvent};
use super::{C1_CHARACTERISTIC_UUID, C2_CHARACTERISTIC_UUID, MATTER_BLE_SERVICE_UUID};

const MAX_CONNECTIONS: usize = MAX_BTP_SESSIONS;

/// The internal state of the peripheral.
/// Arc-ed so as to be thread-safe and to have `'static` interior, as demanded by the BlueR bindings.
struct GattState {
    /// The name of the bluetooth adapter to use. If `None`, the default adapter is used.
    adapter_name: Option<String>,
    /// The list of active notifiers on characteristic `C2`.
    notifiers: IfMutex<StdRawMutex, heapless::Vec<CharacteristicWriter, MAX_CONNECTIONS>>,
    /// A signal necessary so that we can switch between two states:
    /// - Indicating data to a notifier
    /// - Listening all notifiers for a closed one (i.e. a remote peer had unsubscribed from characteristic `C2`)
    notifiers_listen_allowed: Signal<StdRawMutex, bool>,
}

/// Implements the `GattPeripheral` trait using the BlueZ GATT stack.
#[derive(Clone)]
pub struct BluerGattPeripheral(Arc<GattState>);

impl Default for BluerGattPeripheral {
    fn default() -> Self {
        Self::new(None)
    }
}

impl BluerGattPeripheral {
    /// Create a new instance.
    pub fn new(adapter_name: Option<&str>) -> Self {
        Self(Arc::new(GattState {
            adapter_name: adapter_name.map(|name| name.into()),
            notifiers: IfMutex::new(heapless::Vec::new()),
            notifiers_listen_allowed: Signal::new(true),
        }))
    }

    /// Runs the GATT peripheral service.
    /// What this means in details:
    /// - Advertises the service with the provided name and advertising data, where the advertising data
    ///   contains the elements specified in the Matter Core spec.
    /// - Serves a GATT peripheral service with the `C1`, `C2` and `C3` characteristics, as specified
    ///   in the Matter Core spec.
    /// - Calls the provided callback with the events that occur during the service lifetime, on the `C1`
    ///   and `C2` characteristics.
    pub async fn run<F>(
        &self,
        service_name: &str,
        service_adv_data: &AdvData,
        callback: F,
    ) -> Result<(), Error>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + 'static,
    {
        let session = bluer::Session::new().await?;

        // Register a "NoInputNoOutput" agent that will accept all incoming requests.
        let _handle = session.register_agent(Agent::default()).await?;

        let adapter = if let Some(adapter_name) = self.0.adapter_name.as_ref() {
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
            service_data: once((
                Uuid::from_u128(MATTER_BLE_SERVICE_UUID),
                service_adv_data.service_payload_iter().collect(),
            ))
            .collect(),
            ..Default::default()
        };

        // TODO: Stop advertizing after the first connection?
        let _adv_handle = adapter.advertise(le_advertisement).await?;

        info!(
            "Serving GATT echo service on Bluetooth adapter {}",
            adapter.name()
        );

        let callback_w = Arc::new(callback);
        let callback_n = callback_w.clone();
        let callback_s = callback_w.clone();

        let (notify, notify_handle) = characteristic_control();

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
                            method: CharacteristicWriteMethod::Fun(Box::new(
                                move |new_value, req| {
                                    let address = BtAddr(req.device_address.0);
                                    let data = &new_value;

                                    trace!("Got write request from {address}: {data:02x?}");

                                    // Notify the BTP protocol implementation for the write
                                    callback_w(GattPeripheralEvent::Write {
                                        gatt_mtu: (req.mtu > MIN_MTU).then_some(req.mtu),
                                        address,
                                        data,
                                    });

                                    // We don't need a future because the callback is synchronous
                                    Box::pin(core::future::ready(Ok(())))
                                },
                            )),
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
                        control_handle: notify_handle,
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

        select(
            self.closed(callback_s),
            self.pull_notify(notify, callback_n),
        )
        .coalesce()
        .await
    }

    /// Indicate new data on characteristic `C2` to a remote peer.
    pub async fn indicate(&self, data: &[u8], address: BtAddr) -> Result<(), Error> {
        self.0.notifiers_listen_allowed.modify(|listen| {
            *listen = false;

            (true, ())
        });

        let mut notifiers = self.0.notifiers.lock().await;

        let result = if let Some(notifier) = notifiers
            .iter_mut()
            .find(|notifier| notifier.device_address().0 == address.0)
        {
            notifier.write_all(data).await.map_err(|e| e.into())
        } else {
            Err(Error::new(ErrorCode::NoNetworkInterface))
        };

        self.0.notifiers_listen_allowed.modify(|listen| {
            *listen = true;

            (true, ())
        });

        result?;

        trace!("Indicated {data:02x?} bytes to address {address}");

        Ok(())
    }

    /// Handle a new subscription to the `C2` characteristic
    /// by registering the notifier in the internal state.
    async fn add_notifier(&self, notifier: CharacteristicWriter) {
        // Tell the `Self::closed` method to unlock the `notifiers` mutex
        self.0.notifiers_listen_allowed.modify(|listen| {
            *listen = false;

            (true, ())
        });

        let mut notifiers = self.0.notifiers.lock().await;

        let address = BtAddr(notifier.device_address().0);

        if notifiers.len() < MAX_CONNECTIONS {
            // Unwraping is safe because we just checked the length
            notifiers.push(notifier).map_err(|_| ()).unwrap();
            trace!("Notify connection from address {address} started");
        } else {
            warn!("Notifiers limit reached; ignoring notifier from address {address}");
        }

        drop(notifiers);

        // `Self::close` can listen again for closed connections
        self.0.notifiers_listen_allowed.modify(|listen| {
            *listen = true;

            (true, ())
        });
    }

    /// Pull new subscription notifications from the `C2` characteristic.
    async fn pull_notify<F>(
        &self,
        mut notify: CharacteristicControl,
        callback: Arc<F>,
    ) -> Result<(), Error>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + 'static,
    {
        while let Some(event) = notify.next().await {
            match event {
                // Should never happen, as characteristic `C2` is not marked as capable of taking writes.
                CharacteristicControlEvent::Write(_) => unreachable!(),
                CharacteristicControlEvent::Notify(writer) => {
                    let address = BtAddr(writer.device_address().0);

                    self.add_notifier(writer).await;

                    // Notify the BTP protocol implementation
                    callback(GattPeripheralEvent::NotifySubscribed(address));
                }
            }
        }

        Ok(())
    }

    /// Listen for stopped connections (i.e. unsubscriptions from characteristic `C2`).
    async fn closed<F>(&self, callback: Arc<F>) -> Result<(), Error>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + 'static,
    {
        loop {
            // Wait until we are allowed to listen for closed connections
            self.0
                .notifiers_listen_allowed
                .wait(|allowed| (*allowed).then_some(()))
                .await;

            {
                let mut notifiers = self.0.notifiers.lock().await;

                let notifiers_listen_allowed = self
                    .0
                    .notifiers_listen_allowed
                    .wait(|allowed| (!*allowed).then_some(()));

                let mut closed = notifiers
                    .iter()
                    .map(|notifier| notifier.closed())
                    .collect::<heapless::Vec<_, MAX_CONNECTIONS>>();

                // Await until we are no longer allowed to await (future notifiers_listen_allowed)
                // or until we have a closed notifier
                let result = select(notifiers_listen_allowed, select_slice(&mut closed)).await;

                match result {
                    // No longer allowed to await for closed connections, wait until we are allowed again
                    Either::First(_) => continue,
                    Either::Second((_, index)) => {
                        // Remove the closed notifier

                        let address = BtAddr(notifiers[index].device_address().0);

                        drop(closed);

                        notifiers.swap_remove(index);

                        // Notify the BTP protocol implementation
                        callback(GattPeripheralEvent::NotifyUnsubscribed(address));

                        trace!("Notify connection from address {address} stopped");
                    }
                }
            }
        }
    }
}

impl GattPeripheral for BluerGattPeripheral {
    async fn run<F>(&self, service_name: &str, adv_data: &AdvData, callback: F) -> Result<(), Error>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + 'static,
    {
        BluerGattPeripheral::run(self, service_name, adv_data, callback).await
    }

    async fn indicate(&self, data: &[u8], address: BtAddr) -> Result<(), Error> {
        BluerGattPeripheral::indicate(self, data, address).await
    }
}
