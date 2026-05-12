/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

use super::types::DeviceType;

pub mod test;

/// A constant representing the device type for the root (ep0) endpoint in Matter.
///
/// Matter Device Library §2.1.1 revision history: rev 1 was initial; rev 2
/// added Power Source (conditional, optional); rev 3 added MNGD-feature
/// restriction on Access Control; rev 4 added conditions and cluster
/// requirements for Time Sync, TLS Certificate/Client Management. All four
/// rev-2..4 additions are either conditional or `O` (optional) per §2.1.5;
/// rs-matter implements the rev-1 mandatory set (BasicInfo, AccessControl,
/// GeneralCommissioning, NetworkCommissioning, GeneralDiagnostics,
/// AdminCommissioning, OperationalCredentials, GroupKeyManagement) and is
/// therefore conformant at rev 4.
pub const DEV_TYPE_ROOT_NODE: DeviceType = DeviceType {
    dtype: 0x0016,
    drev: 4,
};

/// A constant representing the device type for a bridged device endpoint in the node.
pub const DEV_TYPE_BRIDGED_NODE: DeviceType = DeviceType {
    dtype: 0x0013,
    drev: 1,
};

/// A constant representing the device type for an aggregator endpoint in the node
///  when the Node contains bridged endpoints.
pub const DEV_TYPE_AGGREGATOR: DeviceType = DeviceType {
    dtype: 0x000e,
    drev: 1,
};

/// A constant representing the On/Off Light device in Matter.
///
/// Matter Device Library §4.1.1 revision history: rev 1 was Zigbee-3.0
/// initial; rev 2 was the new data-model-format/notation rewrite; rev 3
/// swapped the deprecated Scenes cluster (0x0005) for Scenes Management
/// (0x0062). Conformance tests (TC_DeviceConformance::test_TC_IDM_10_5/_6)
/// always evaluate the cluster set against the *current* spec, so claiming
/// the latest revision matches the test framework's expectation.
///
/// Note: `On/Off Light` mandates Identify, Groups, On/Off (with the `LT`
/// Lighting feature), and Scenes Management at rev 3. rs-matter does not
/// yet implement Scenes Management — applications using this device type
/// won't pass `test_TC_IDM_10_5` until that gap is closed.
pub const DEV_TYPE_ON_OFF_LIGHT: DeviceType = DeviceType {
    dtype: 0x0100,
    drev: 3,
};

pub const DEV_TYPE_DIMMABLE_LIGHT: DeviceType = DeviceType {
    dtype: 0x0101,
    drev: 3,
};

/// A constant representing the Smart Speaker device in Matter.
pub const DEV_TYPE_SMART_SPEAKER: DeviceType = DeviceType {
    dtype: 0x0022,
    drev: 2,
};

/// A constant representing the casting video player device in Matter.
pub const DEV_TYPE_CASTING_VIDEO_PLAYER: DeviceType = DeviceType {
    dtype: 0x0023,
    drev: 1,
};

/// A constant representing the video player device in Matter.
pub const DEV_TYPE_VIDEO_PLAYER: DeviceType = DeviceType {
    dtype: 0x0028,
    drev: 1,
};

/// A macro to generate the devices for an endpoint.
#[allow(unused_macros)]
#[macro_export]
macro_rules! devices {
    ($($device:expr $(,)?)*) => {
        &[
            $($device,)*
        ]
    }
}
