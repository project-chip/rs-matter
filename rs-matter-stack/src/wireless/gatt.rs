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

use core::future::Future;

use rs_matter_utils::error::Error;
use rs_matter_utils::sync::MaybeSend;

use crate::ble::GattPeripheral;

use super::PreexistingWireless;

/// A trait representing a task that needs access to the BLE GATT peripheral to perform its work
/// (e.g. the first part of a non-concurrent commissioning flow)
pub trait GattTask: MaybeSend {
    /// Run the task with the given GATT peripheral
    fn run<P>(&mut self, peripheral: P) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        P: GattPeripheral;
}

impl<T> GattTask for &mut T
where
    T: GattTask,
{
    fn run<P>(&mut self, peripheral: P) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        P: GattPeripheral,
    {
        T::run(*self, peripheral)
    }
}

/// A trait for running a task within a context where the BLE peripheral is initialized and operable
/// (e.g. the first part of a non-concurrent commissioning workflow)
pub trait GattDriver: MaybeSend {
    /// Setup the radio to operate in BLE mode and run the given task.
    fn run<T>(&mut self, task: T) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        T: GattTask;
}

impl<T> GattDriver for &mut T
where
    T: GattDriver,
{
    fn run<A>(&mut self, task: A) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        A: GattTask,
    {
        T::run(self, task)
    }
}

impl<U, N, C, M, P> GattDriver for PreexistingWireless<U, N, C, M, P>
where
    U: MaybeSend,
    N: MaybeSend,
    C: MaybeSend,
    M: MaybeSend,
    P: GattPeripheral,
{
    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: GattTask,
    {
        task.run(&mut self.gatt).await
    }
}
