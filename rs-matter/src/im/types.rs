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

//! Type aliases for first-class Matter types

pub type NodeId = u64;
pub type EndptId = u16;
pub type ClusterId = u32;
pub type AttrId = u32;
pub type CmdId = u32;
pub type ActionId = u8;
pub type ClusterStatus = u8;
pub type CommandRef = u16;
pub type CompressedFabricId = u64;
pub type DataVersion = u32;
pub type DeviceTypeId = u32;
pub type ElapsedS = u32;
pub type EventId = u32;
pub type EventNumber = u64;
pub type FabricId = u64;
pub type FabricIndex = u8;
pub type FieldId = u32;
pub type ListIndex = u16;
pub type LocalizedStringIdentifier = u16;
pub type TransactionId = u32;
pub type KeysetId = u16;
pub type InteractionModelRevision = u8;
pub type SubscriptionId = u32;
pub type SceneId = u8;
pub type Percent = u8;
pub type Percent100ths = u16;
pub type EnergyMilliWh = i64;
pub type EnergyMilliVAh = i64;
pub type EnergyMilliVARh = i64;
pub type AmperageMilliA = i64;
pub type PowerMilliW = i64;
pub type PowerMilliVA = i64;
pub type PowerMilliVAR = i64;
pub type VoltageMilliV = i64;
pub type Money = i64;
