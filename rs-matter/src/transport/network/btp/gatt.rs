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

use core::iter::{empty, once};

use crate::data_model::cluster_basic_information::BasicInfoConfig;
use crate::error::Error;
use crate::transport::network::BtAddr;

#[cfg(all(feature = "std", target_os = "linux"))]
pub use builtin::BluerGattPeripheral as BuiltinGattPeripheral;

use super::{GATT_HEADER_SIZE, MAX_BTP_SEGMENT_SIZE};

#[cfg(all(feature = "std", target_os = "linux"))]
#[path = "gatt/bluer.rs"]
mod builtin;

// The 16-bit, registered Matter Service UUID, as per the Matter Core spec.
pub const MATTER_BLE_SERVICE_UUID16: u16 = 0xFFF6;
// A 128-bit expanded representation of the Matter Service UUID.
pub const MATTER_BLE_SERVICE_UUID: u128 = 0x0000FFF600001000800000805F9B34FB;

/// `C1` characteristic UUID, as per the Matter Core spec.
pub const C1_CHARACTERISTIC_UUID: u128 = 0x18EE2EF5263D4559959F4F9C429F9D11;
/// `C2` characteristic UUID, as per the Matter Core spec.
pub const C2_CHARACTERISTIC_UUID: u128 = 0x18EE2EF5263D4559959F4F9C429F9D12;
/// `C3` characteristic UUID, as per the Matter Core spec.
pub const C3_CHARACTERISTIC_UUID: u128 = 0x64630238877245F2B87D748A83218F04;

/// The maximum length of packet data written to the `C1` characteristic, as per the Matter Core spec, and as advertised in the GATT service.
pub const C1_MAX_LEN: usize = MAX_BTP_SEGMENT_SIZE + GATT_HEADER_SIZE;
/// The maximum length of packet data indicated via the `C2` characteristic, as per the Matter Core spec, and as advertised in the GATT service.
pub const C2_MAX_LEN: usize = MAX_BTP_SEGMENT_SIZE + GATT_HEADER_SIZE;
/// The maximum length of data read from the `C3` characteristic, as per the Matter Core spec, and as advertised in the GATT service.
pub const C3_MAX_LEN: usize = 512;

/// Encapsulates the advertising data for the Matter BTP protocol.
///
/// See section "5.4.2.5.6. Advertising Data" in the Core Matter spec
#[derive(Clone)]
pub struct AdvData {
    vid: u16,
    pid: u16,
    discriminator: u16,
}

impl AdvData {
    /// Create a new instance by using the provided `BasicInfoConfig` and `CommissioningData`.
    pub const fn new(dev_det: &BasicInfoConfig, discriminator: u16) -> Self {
        Self {
            vid: dev_det.vid,
            pid: dev_det.pid,
            discriminator,
        }
    }

    /// Return an iterator over the binary representation of the advertising data.
    ///
    /// As per the Matter Core spec, the advertising data consists of
    /// an AD1 record which is of Flags type, and an AD2 record, which is of type UUID16+Service Data
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        self.flags_iter().chain(self.service_iter())
    }

    /// Return an iterator over the binary representation of the AD1 advertising data (Flags).
    /// Useful with GATT stacks that require the advertising data to be reported as separate AD records
    pub fn flags_iter(&self) -> impl Iterator<Item = u8> + '_ {
        empty()
            .chain(once(self.flags_payload_iter().count() as u8 + 1)) // 1-byte type
            .chain(once(self.flags_adv_type()))
            .chain(self.flags_payload_iter())
    }

    /// The AD1 advertising data type (Flags).
    pub const fn flags_adv_type(&self) -> u8 {
        0x01
    }

    /// Return an iterator over the binary representation of the AD1 advertising data _payload_.
    /// Useful with GATT stacks that require the advertising data to be reported as separate AD records
    pub fn flags_payload_iter(&self) -> impl Iterator<Item = u8> + '_ {
        once(0x06)
    }

    /// Return an iterator over the binary representation of the AD2 advertising data (UUID16+Service Data).
    pub fn service_iter(&self) -> impl Iterator<Item = u8> + '_ {
        empty()
            .chain(once(self.service_payload_iter().count() as u8 + 3)) // + 1-byte type and 2-bytes Matter UUID16 Service
            .chain(once(self.service_adv_type()))
            .chain(MATTER_BLE_SERVICE_UUID16.to_le_bytes())
            .chain(self.service_payload_iter())
    }

    /// The AD2 advertising data type (UUID16+Service Data).
    pub const fn service_adv_type(&self) -> u8 {
        0x16
    }

    /// Return an iterator over the binary representation of the AD2 advertising data _payload_.
    /// Useful with GATT stacks that require the advertising data to be reported as separate AD records
    pub fn service_payload_iter(&self) -> impl Iterator<Item = u8> + '_ {
        [
            0, // Always 0 = "Commissionable"
            self.discriminator.to_le_bytes()[0],
            self.discriminator.to_le_bytes()[1],
            self.vid.to_le_bytes()[0],
            self.vid.to_le_bytes()[1],
            self.pid.to_le_bytes()[0],
            self.pid.to_le_bytes()[1],
            0, // No additional data
        ]
        .into_iter()
    }
}

/// A minimal GATT peripheral event.
/// This enum is used to abstract the platform-specific GATT peripheral events.
///
/// The abstraction is "minimal" in the sense that it is good enough for the purposes of
/// the Matter BTP protocol, but is otherwise not really having the ambition to model all
/// possible events of a generic GATT peripheral, which would result in a much larger API surface.
#[derive(Debug, Clone)]
pub enum GattPeripheralEvent<'a> {
    /// A GATT central has subscribed for notifications from characteristic `C2`.
    /// In other words, the GATT central is now ready to receive BTP packets.
    ///
    /// See the Matter Core spec w.r.t. details on characteristic `C2`.
    NotifySubscribed(BtAddr),
    /// A GATT central has unsubscribed for notifications from characteristic `C2`.
    /// In other words, the GATT central is closing the BTP session.
    ///
    /// See the Matter Core spec w.r.t. details on characteristic `C2`.
    NotifyUnsubscribed(BtAddr),
    /// A GATT central has requested a Write to characteristic `C1`.
    /// In other words, the GATT central had sent a BTP packet.
    ///
    /// See the Matter Core spec w.r.t. details on characteristic `C1`.
    ///
    /// `gatt_mtu` is the ATT MTU (contains +3 bytes for the GATT header)
    /// as negotiated between the GATT central and the GATT peripheral.
    /// Might be `None` if a concrete GATT peripheral implementation does
    /// not provide access to this value. In that case, the minimum MTU
    /// will be used (23 bytes, including the GATT header).
    Write {
        address: BtAddr,
        data: &'a [u8],
        gatt_mtu: Option<u16>,
    },
}

/// A minimal GATT peripheral trait.
/// This trait is used to abstract the platform-specific GATT peripheral implementation.
///
/// The abstraction is "minimal" in the sense that it is good enough for the purposes of
/// the Matter BTP protocol, but is otherwise not really having the ambition to model all
/// the aspects of a generic GATT peripheral, which would result in a much larger trait.
///
/// The design of this trait is deliberately chosen to be simple and easy to implement
/// on top of MCU-based GATT peripherals; hence the blocking, callback-based approach for modeling
/// notification subscriptions and chracteristic writes, which - while making the BTP protocol
/// implementation more complex - is a good fit for MCUs where these operations might also be
/// implemented via a callback which cannot await.
pub trait GattPeripheral {
    /// Run the GATT peripheral.
    ///
    /// The implementation of this method is expected to do the following:
    /// - GATT peripheral lifecycle:
    ///   - Start avertising a GATT service with UUID `MATTER_BLE_SERVICE_UUID16`, by utilizing
    ///     the provided `service_name` and `adv_data` parameters.
    ///   - Possibly stop advertising the GATT service when the first notification subscription is received.
    ///   - Stop advertising and tear down the GATT service when the future of this method is dropped.
    /// - Gatt peripheral incoming data:
    ///   - Handle incoming GATT events, and call the provided `callback` function for each event.
    ///     See `GattPeripheralEvent` for the possible events and their semantics.
    ///
    /// The callback is constraned to be `Send`, `Sync`, `Clone` and `'static` on purpose, as it might be
    /// the case that the GATT implementation needs to invoke the callback from a different thread than the Matter thread,
    /// as well as it might need multiple instances of it.
    /// Therefore, this constraint is not a problem but an advantage for `GattPeripheral` trait implementors (it is a deliberate design decision).
    async fn run<F>(
        &self,
        service_name: &str,
        adv_data: &AdvData,
        callback: F,
    ) -> Result<(), Error>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + Clone + 'static;

    /// Indicate data changes in characteristics `C2` to to a GATT central.
    /// In other words, send a BTP packet to a GATT central.
    ///
    /// See the Matter Core spec w.r.t. details on characteristic C2.
    async fn indicate(&self, data: &[u8], address: BtAddr) -> Result<(), Error>;
}

impl<T> GattPeripheral for &T
where
    T: GattPeripheral,
{
    fn run<F>(
        &self,
        service_name: &str,
        adv_data: &AdvData,
        callback: F,
    ) -> impl core::future::Future<Output = Result<(), Error>>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + Clone + 'static,
    {
        (*self).run(service_name, adv_data, callback)
    }

    async fn indicate(&self, data: &[u8], address: BtAddr) -> Result<(), Error> {
        (*self).indicate(data, address).await
    }
}

impl<T> GattPeripheral for &mut T
where
    T: GattPeripheral,
{
    fn run<F>(
        &self,
        service_name: &str,
        adv_data: &AdvData,
        callback: F,
    ) -> impl core::future::Future<Output = Result<(), Error>>
    where
        F: Fn(GattPeripheralEvent) + Send + Sync + Clone + 'static,
    {
        (**self).run(service_name, adv_data, callback)
    }

    async fn indicate(&self, data: &[u8], address: BtAddr) -> Result<(), Error> {
        (**self).indicate(data, address).await
    }
}
