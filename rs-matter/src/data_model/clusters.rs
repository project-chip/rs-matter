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

//! This module imports all system clusters that are used by the `rs-matter` itself.
//!
//! Additionally, it imports the following extra ones:
//! - OnOff - for demoing purposes
//! - UnitTesting - for testing purposes

crate::import!(
    AdministratorCommissioning,
    AccessControl,
    BasicInformation,
    Descriptor,
    EthernetNetworkDiagnostics,
    GeneralCommissioning,
    GroupKeyManagement,
    NetworkCommissioning,
    OnOff,
    OperationalCredentials,
    ThreadNetworkDiagnostics,
    UnitTesting,
    WifiNetworkDiagnostics,
);
