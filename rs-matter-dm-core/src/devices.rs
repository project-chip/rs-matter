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

//! The device types of the Matter 1.6 Device Library, in the order and
//! grouping of the Device Library.
//!
//! Each constant carries the latest revision of its device type. A node has to
//! report exactly that revision for the specification version it reports in
//! Basic Information, and the certification tests check this. So when the
//! specification version is raised, the revisions here have to follow.
//!
//! Having a constant here does not mean that rs-matter implements all the
//! clusters the device type requires.

use crate::DeviceType;

// Utility device types

/// A constant representing the device type for the root (ep0) endpoint in Matter.
///
/// Matter Device Library revision history: rev 1 was initial; rev 2
/// added Power Source (conditional, optional); rev 3 added MNGD-feature
/// restriction on Access Control; rev 4 added conditions and cluster
/// requirements for Time Sync, TLS Certificate/Client Management. All four
/// rev-2..4 additions are either conditional or `O` (optional) per spec;
/// rs-matter implements the rev-1 mandatory set (BasicInfo, AccessControl,
/// GeneralCommissioning, NetworkCommissioning, GeneralDiagnostics,
/// AdminCommissioning, OperationalCredentials, GroupKeyManagement) and is
/// therefore conformant at rev 4.
pub const DEV_TYPE_ROOT_NODE: DeviceType = DeviceType {
    dtype: 0x0016,
    drev: 4,
};

/// A constant representing the device type for a power source endpoint in the node.
///
/// Utility device type, node-scoped: it is declared *alongside* the primary
/// device type of the endpoint hosting the `PowerSource` cluster (typically the
/// root node - see Device Library spec which lists this device type under the
/// Root Node's requirements with `PowerSourceCond, O`).
pub const DEV_TYPE_POWER_SOURCE: DeviceType = DeviceType {
    dtype: 0x0011,
    drev: 1,
};

/// The OTA Requestor device type: a node that obtains and applies software
/// updates. It hosts the OTA Software Update Requestor cluster (server) and is a
/// client of the OTA Software Update Provider cluster.
pub const DEV_TYPE_OTA_REQUESTOR: DeviceType = DeviceType {
    dtype: 0x0012,
    drev: 1,
};

/// The OTA Provider device type: a node that serves software updates. It hosts
/// the OTA Software Update Provider cluster (server) and is a client of the OTA
/// Software Update Requestor cluster.
pub const DEV_TYPE_OTA_PROVIDER: DeviceType = DeviceType {
    dtype: 0x0014,
    drev: 1,
};

/// A constant representing the device type for a bridged device endpoint in the node.
pub const DEV_TYPE_BRIDGED_NODE: DeviceType = DeviceType {
    dtype: 0x0013,
    drev: 3,
};

/// Electrical Sensor (`0x0510`), Matter Device Library revision 1.
///
/// A **utility** device type: it does not stand on its own but attaches to an
/// endpoint that already carries an application device type, describing that
/// endpoint's electrical behaviour. Core spec 9.2.1 permits any number of
/// utility device types beside the single application one, which is how a
/// thermostat endpoint can also meter its heating element.
///
/// Mandates `PowerTopology` plus at least one of `ElectricalPowerMeasurement`
/// (instantaneous draw) and `ElectricalEnergyMeasurement` (energy over time).
///
/// See [`crate::clusters::app::power_topology`],
/// [`crate::clusters::app::elec_pwr_meas`] and
/// [`crate::clusters::app::elec_energy_meas`] for the handlers that back
/// it.
pub const DEV_TYPE_ELECTRICAL_SENSOR: DeviceType = DeviceType {
    dtype: 0x0510,
    drev: 1,
};

/// The Device Energy Management device type, a utility device type.
pub const DEV_TYPE_DEVICE_ENERGY_MANAGEMENT: DeviceType = DeviceType {
    dtype: 0x050D,
    drev: 3,
};

/// The Secondary Network Interface device type: an endpoint hosting the Network
/// Commissioning cluster of an additional network interface of the node, next
/// to the primary one on the root endpoint.
pub const DEV_TYPE_SECONDARY_NETWORK_INTERFACE: DeviceType = DeviceType {
    dtype: 0x0019,
    drev: 1,
};

/// The Joint Fabric Administrator device type, a utility device type.
pub const DEV_TYPE_JOINT_FABRIC_ADMINISTRATOR: DeviceType = DeviceType {
    dtype: 0x0130,
    drev: 1,
};

// Lighting device types

/// A constant representing the On/Off Light device in Matter.
///
/// Matter Device Library revision history: rev 1 was Zigbee-3.0
/// initial; rev 2 was the new data-model-format/notation rewrite; rev 3
/// swapped the deprecated Scenes cluster (0x0005) for Scenes Management
/// (0x0062). Conformance tests (TC_DeviceConformance::test_TC_IDM_10_5/_6)
/// always evaluate the cluster set against the *current* spec, so claiming
/// the latest revision matches the test framework's expectation.
pub const DEV_TYPE_ON_OFF_LIGHT: DeviceType = DeviceType {
    dtype: 0x0100,
    drev: 3,
};

/// The Dimmable Light device type, a superset of On/Off Light.
pub const DEV_TYPE_DIMMABLE_LIGHT: DeviceType = DeviceType {
    dtype: 0x0101,
    drev: 3,
};

/// The Color Temperature Light device type, a superset of Dimmable Light.
pub const DEV_TYPE_COLOR_TEMPERATURE_LIGHT: DeviceType = DeviceType {
    dtype: 0x010C,
    drev: 4,
};

/// Extended Color Light — mandates OnOff, LevelControl, and
/// ColorControl with the full feature set (HUE_AND_SATURATION, XY,
/// COLOR_TEMPERATURE, ENHANCED_HUE, COLOR_LOOP).
pub const DEV_TYPE_EXTENDED_COLOR_LIGHT: DeviceType = DeviceType {
    dtype: 0x010D,
    drev: 4,
};

// Smart plugs/outlets and other actuators

/// The On/Off Plug-in Unit device type.
pub const DEV_TYPE_ON_OFF_PLUG_IN_UNIT: DeviceType = DeviceType {
    dtype: 0x010A,
    drev: 4,
};

/// The Dimmable Plug-In Unit device type.
pub const DEV_TYPE_DIMMABLE_PLUG_IN_UNIT: DeviceType = DeviceType {
    dtype: 0x010B,
    drev: 5,
};

/// The Mounted On/Off Control device type, a superset of On/Off Plug-in Unit.
pub const DEV_TYPE_MOUNTED_ON_OFF_CONTROL: DeviceType = DeviceType {
    dtype: 0x010F,
    drev: 2,
};

/// The Mounted Dimmable Load Control device type, a superset of Dimmable
/// Plug-In Unit.
pub const DEV_TYPE_MOUNTED_DIMMABLE_LOAD_CONTROL: DeviceType = DeviceType {
    dtype: 0x0110,
    drev: 2,
};

/// The Pump device type.
pub const DEV_TYPE_PUMP: DeviceType = DeviceType {
    dtype: 0x0303,
    drev: 3,
};

/// The Water Valve device type.
pub const DEV_TYPE_WATER_VALVE: DeviceType = DeviceType {
    dtype: 0x0042,
    drev: 1,
};

/// The Irrigation System device type.
pub const DEV_TYPE_IRRIGATION_SYSTEM: DeviceType = DeviceType {
    dtype: 0x0040,
    drev: 1,
};

// Switches and controls device types

/// On/Off Light Switch — a controller device type that mandates the
/// `OnOff` cluster as a **client** (i.e. it initiates On/Off commands to a
/// bound light) plus the `Binding` cluster as a server (its address book of
/// bound targets). See the Matter Device Library spec.
pub const DEV_TYPE_ON_OFF_LIGHT_SWITCH: DeviceType = DeviceType {
    dtype: 0x0103,
    drev: 3,
};

/// The Dimmer Switch device type, a superset of On/Off Light Switch.
pub const DEV_TYPE_DIMMER_SWITCH: DeviceType = DeviceType {
    dtype: 0x0104,
    drev: 3,
};

/// The Color Dimmer Switch device type, a superset of Dimmer Switch.
pub const DEV_TYPE_COLOR_DIMMER_SWITCH: DeviceType = DeviceType {
    dtype: 0x0105,
    drev: 3,
};

/// The Control Bridge device type.
pub const DEV_TYPE_CONTROL_BRIDGE: DeviceType = DeviceType {
    dtype: 0x0840,
    drev: 3,
};

/// The Pump Controller device type.
pub const DEV_TYPE_PUMP_CONTROLLER: DeviceType = DeviceType {
    dtype: 0x0304,
    drev: 4,
};

/// Generic Switch — a device type for a button/switch that reports user
/// presses via the `Switch` cluster (as a **server**), emitting events such as
/// `InitialPress`/`ShortRelease`. Ecosystems surface these events as automation
/// triggers. Unlike `DEV_TYPE_ON_OFF_LIGHT_SWITCH`, it does not bind to or
/// command any device itself. See the Matter Device Library spec.
pub const DEV_TYPE_GENERIC_SWITCH: DeviceType = DeviceType {
    dtype: 0x000F,
    drev: 3,
};

// Sensor device types

/// The Contact Sensor device type.
pub const DEV_TYPE_CONTACT_SENSOR: DeviceType = DeviceType {
    dtype: 0x0015,
    drev: 2,
};

/// The Light Sensor device type.
pub const DEV_TYPE_LIGHT_SENSOR: DeviceType = DeviceType {
    dtype: 0x0106,
    drev: 4,
};

/// The Occupancy Sensor device type.
pub const DEV_TYPE_OCCUPANCY_SENSOR: DeviceType = DeviceType {
    dtype: 0x0107,
    drev: 4,
};

/// The Temperature Sensor device type.
pub const DEV_TYPE_TEMPERATURE_SENSOR: DeviceType = DeviceType {
    dtype: 0x0302,
    drev: 3,
};

/// The Pressure Sensor device type.
pub const DEV_TYPE_PRESSURE_SENSOR: DeviceType = DeviceType {
    dtype: 0x0305,
    drev: 3,
};

/// The Flow Sensor device type.
pub const DEV_TYPE_FLOW_SENSOR: DeviceType = DeviceType {
    dtype: 0x0306,
    drev: 3,
};

/// The Humidity Sensor device type.
pub const DEV_TYPE_HUMIDITY_SENSOR: DeviceType = DeviceType {
    dtype: 0x0307,
    drev: 3,
};

/// The On/Off Sensor device type.
pub const DEV_TYPE_ON_OFF_SENSOR: DeviceType = DeviceType {
    dtype: 0x0850,
    drev: 3,
};

/// The Smoke CO Alarm device type.
pub const DEV_TYPE_SMOKE_CO_ALARM: DeviceType = DeviceType {
    dtype: 0x0076,
    drev: 1,
};

/// The Air Quality Sensor device type.
pub const DEV_TYPE_AIR_QUALITY_SENSOR: DeviceType = DeviceType {
    dtype: 0x002C,
    drev: 1,
};

/// The Water Freeze Detector device type.
pub const DEV_TYPE_WATER_FREEZE_DETECTOR: DeviceType = DeviceType {
    dtype: 0x0041,
    drev: 2,
};

/// The Water Leak Detector device type.
pub const DEV_TYPE_WATER_LEAK_DETECTOR: DeviceType = DeviceType {
    dtype: 0x0043,
    drev: 2,
};

/// The Rain Sensor device type.
pub const DEV_TYPE_RAIN_SENSOR: DeviceType = DeviceType {
    dtype: 0x0044,
    drev: 2,
};

/// The Soil Sensor device type.
pub const DEV_TYPE_SOIL_SENSOR: DeviceType = DeviceType {
    dtype: 0x0045,
    drev: 1,
};

// Entry control device types

/// The Door Lock device type.
pub const DEV_TYPE_DOOR_LOCK: DeviceType = DeviceType {
    dtype: 0x000A,
    drev: 4,
};

/// The Door Lock Controller device type.
pub const DEV_TYPE_DOOR_LOCK_CONTROLLER: DeviceType = DeviceType {
    dtype: 0x000B,
    drev: 3,
};

/// The Window Covering device type.
pub const DEV_TYPE_WINDOW_COVERING: DeviceType = DeviceType {
    dtype: 0x0202,
    drev: 6,
};

/// The Window Covering Controller device type.
pub const DEV_TYPE_WINDOW_COVERING_CONTROLLER: DeviceType = DeviceType {
    dtype: 0x0203,
    drev: 4,
};

/// The Closure device type.
pub const DEV_TYPE_CLOSURE: DeviceType = DeviceType {
    dtype: 0x0230,
    drev: 1,
};

/// The Closure Panel device type.
pub const DEV_TYPE_CLOSURE_PANEL: DeviceType = DeviceType {
    dtype: 0x0231,
    drev: 1,
};

/// The Closure Controller device type.
pub const DEV_TYPE_CLOSURE_CONTROLLER: DeviceType = DeviceType {
    dtype: 0x023E,
    drev: 1,
};

// HVAC device types

/// Thermostat (`0x0301`), Matter Device Library revision 6.
///
/// Mandates `Identify` and `Thermostat` as servers, plus `Groups` when the
/// device supports group communication. Revision history: rev 4 dropped Time
/// Synchronization, Scenes Management and the Zigbee-only clusters; rev 5 moved
/// the disallowed-element conformance into the Thermostat cluster itself; rev 6
/// added Ambient Context Sensing as an optional client.
///
/// See [`crate::clusters::app::thermostat`] for the heating-only cluster
/// handler that backs it.
pub const DEV_TYPE_THERMOSTAT: DeviceType = DeviceType {
    dtype: 0x0301,
    drev: 6,
};

/// Fan (`0x002B`), Matter Device Library revision 4.
///
/// A standalone, ceiling or wall fan that circulates the air in a room.
/// Mandates `Identify`, `Groups` and `FanControl` as servers, with `OnOff`
/// optional: the Device Library keeps the two independent, so that switching
/// the fan off through `OnOff` leaves `FanMode`, `PercentSetting` and
/// `SpeedSetting` where the occupant put them and only zeroes
/// `PercentCurrent` / `SpeedCurrent`. Revision history: rev 2 allowed the
/// composition with a Thermostat for fan heaters, rev 3 added `OnOff`, rev 4
/// moved the `FanModeSequence` requirement into the Fan Control cluster.
///
/// See [`crate::clusters::app::fan_control`] for the cluster handler that
/// backs it.
pub const DEV_TYPE_FAN: DeviceType = DeviceType {
    dtype: 0x002B,
    drev: 4,
};

/// The Air Purifier device type.
pub const DEV_TYPE_AIR_PURIFIER: DeviceType = DeviceType {
    dtype: 0x002D,
    drev: 2,
};

/// The Thermostat Controller device type.
pub const DEV_TYPE_THERMOSTAT_CONTROLLER: DeviceType = DeviceType {
    dtype: 0x030A,
    drev: 1,
};

// Media device types

/// The Basic Video Player device type.
pub const DEV_TYPE_BASIC_VIDEO_PLAYER: DeviceType = DeviceType {
    dtype: 0x0028,
    drev: 2,
};

/// A constant representing the casting video player device in Matter.
pub const DEV_TYPE_CASTING_VIDEO_PLAYER: DeviceType = DeviceType {
    dtype: 0x0023,
    drev: 2,
};

/// The Speaker device type.
pub const DEV_TYPE_SPEAKER: DeviceType = DeviceType {
    dtype: 0x0022,
    drev: 1,
};

/// The Content App device type.
pub const DEV_TYPE_CONTENT_APP: DeviceType = DeviceType {
    dtype: 0x0024,
    drev: 2,
};

/// The Casting Video Client device type.
pub const DEV_TYPE_CASTING_VIDEO_CLIENT: DeviceType = DeviceType {
    dtype: 0x0029,
    drev: 2,
};

/// The Video Remote Control device type.
pub const DEV_TYPE_VIDEO_REMOTE_CONTROL: DeviceType = DeviceType {
    dtype: 0x002A,
    drev: 2,
};

// Generic device types

/// Mode Select — a Simple, endpoint-scoped device type whose only mandatory
/// cluster is `ModeSelect` as a server. It exists so that a node can expose
/// several independent mode choices: an endpoint hosts at most one instance of
/// a given cluster ID, so each further choice needs its own endpoint. The
/// Matter Application Cluster spec's own example is a coffee machine with one
/// instance described `Milk` and another `Sugar`.
///
/// This is a Simple **application** device type, so per Core spec 9.2.1 an
/// endpoint carries exactly one of it and no other application type — use it
/// for an endpoint dedicated to a mode choice.
///
/// To attach a mode choice to an existing device instead, put the ModeSelect
/// *cluster* on that device's endpoint without declaring this device type, and
/// leave the endpoint's own application device type in place. That is what
/// CHIP's `all-clusters-app` does, and it is also what the `ON_OFF` feature
/// needs, since `OnMode` couples to an OnOff cluster on the same endpoint.
pub const DEV_TYPE_MODE_SELECT: DeviceType = DeviceType {
    dtype: 0x0027,
    drev: 1,
};

/// A constant representing the device type for an aggregator endpoint in the node
///  when the Node contains bridged endpoints.
pub const DEV_TYPE_AGGREGATOR: DeviceType = DeviceType {
    dtype: 0x000e,
    drev: 2,
};

// Robotic device types

/// The Robotic Vacuum Cleaner device type.
pub const DEV_TYPE_ROBOTIC_VACUUM_CLEANER: DeviceType = DeviceType {
    dtype: 0x0074,
    drev: 4,
};

// Appliance device types

/// The Laundry Washer device type.
pub const DEV_TYPE_LAUNDRY_WASHER: DeviceType = DeviceType {
    dtype: 0x0073,
    drev: 2,
};

/// The Refrigerator device type.
pub const DEV_TYPE_REFRIGERATOR: DeviceType = DeviceType {
    dtype: 0x0070,
    drev: 3,
};

/// The Room Air Conditioner device type.
pub const DEV_TYPE_ROOM_AIR_CONDITIONER: DeviceType = DeviceType {
    dtype: 0x0072,
    drev: 3,
};

/// The Temperature Controlled Cabinet device type.
pub const DEV_TYPE_TEMPERATURE_CONTROLLED_CABINET: DeviceType = DeviceType {
    dtype: 0x0071,
    drev: 6,
};

/// The Dishwasher device type.
pub const DEV_TYPE_DISHWASHER: DeviceType = DeviceType {
    dtype: 0x0075,
    drev: 2,
};

/// The Laundry Dryer device type.
pub const DEV_TYPE_LAUNDRY_DRYER: DeviceType = DeviceType {
    dtype: 0x007C,
    drev: 2,
};

/// The Cook Surface device type.
pub const DEV_TYPE_COOK_SURFACE: DeviceType = DeviceType {
    dtype: 0x0077,
    drev: 2,
};

/// The Cooktop device type.
pub const DEV_TYPE_COOKTOP: DeviceType = DeviceType {
    dtype: 0x0078,
    drev: 1,
};

/// The Oven device type.
pub const DEV_TYPE_OVEN: DeviceType = DeviceType {
    dtype: 0x007B,
    drev: 2,
};

/// The Extractor Hood device type.
pub const DEV_TYPE_EXTRACTOR_HOOD: DeviceType = DeviceType {
    dtype: 0x007A,
    drev: 1,
};

/// The Microwave Oven device type.
pub const DEV_TYPE_MICROWAVE_OVEN: DeviceType = DeviceType {
    dtype: 0x0079,
    drev: 2,
};

// Energy device types

/// The Energy EVSE device type.
pub const DEV_TYPE_ENERGY_EVSE: DeviceType = DeviceType {
    dtype: 0x050C,
    drev: 2,
};

/// The Water Heater device type.
pub const DEV_TYPE_WATER_HEATER: DeviceType = DeviceType {
    dtype: 0x050F,
    drev: 1,
};

/// The Solar Power device type.
pub const DEV_TYPE_SOLAR_POWER: DeviceType = DeviceType {
    dtype: 0x0017,
    drev: 1,
};

/// The Battery Storage device type.
pub const DEV_TYPE_BATTERY_STORAGE: DeviceType = DeviceType {
    dtype: 0x0018,
    drev: 2,
};

/// The Heat Pump device type.
pub const DEV_TYPE_HEAT_PUMP: DeviceType = DeviceType {
    dtype: 0x0309,
    drev: 1,
};

/// The Meter Reference Point device type.
pub const DEV_TYPE_METER_REFERENCE_POINT: DeviceType = DeviceType {
    dtype: 0x0512,
    drev: 1,
};

/// The Electrical Energy Tariff device type.
pub const DEV_TYPE_ELECTRICAL_ENERGY_TARIFF: DeviceType = DeviceType {
    dtype: 0x0513,
    drev: 1,
};

/// The Electrical Meter device type, a superset of Electrical Energy Tariff.
pub const DEV_TYPE_ELECTRICAL_METER: DeviceType = DeviceType {
    dtype: 0x0514,
    drev: 1,
};

/// The Electrical Utility Meter device type, a superset of Meter Reference
/// Point.
pub const DEV_TYPE_ELECTRICAL_UTILITY_METER: DeviceType = DeviceType {
    dtype: 0x0511,
    drev: 1,
};

// Network infrastructure device types

/// The Network Infrastructure Manager device type.
pub const DEV_TYPE_NETWORK_INFRASTRUCTURE_MANAGER: DeviceType = DeviceType {
    dtype: 0x0090,
    drev: 2,
};

/// The Thread Border Router device type.
pub const DEV_TYPE_THREAD_BORDER_ROUTER: DeviceType = DeviceType {
    dtype: 0x0091,
    drev: 2,
};

// Camera device types

/// The Camera device type.
pub const DEV_TYPE_CAMERA: DeviceType = DeviceType {
    dtype: 0x0142,
    drev: 1,
};

/// The Floodlight Camera device type.
pub const DEV_TYPE_FLOODLIGHT_CAMERA: DeviceType = DeviceType {
    dtype: 0x0144,
    drev: 1,
};

/// The Video Doorbell device type.
pub const DEV_TYPE_VIDEO_DOORBELL: DeviceType = DeviceType {
    dtype: 0x0143,
    drev: 1,
};

/// The Intercom device type.
pub const DEV_TYPE_INTERCOM: DeviceType = DeviceType {
    dtype: 0x0140,
    drev: 2,
};

/// The Audio Doorbell device type.
pub const DEV_TYPE_AUDIO_DOORBELL: DeviceType = DeviceType {
    dtype: 0x0141,
    drev: 2,
};

/// The Snapshot Camera device type.
pub const DEV_TYPE_SNAPSHOT_CAMERA: DeviceType = DeviceType {
    dtype: 0x0145,
    drev: 1,
};

/// The Chime device type.
pub const DEV_TYPE_CHIME: DeviceType = DeviceType {
    dtype: 0x0146,
    drev: 1,
};

/// The Camera Controller device type.
pub const DEV_TYPE_CAMERA_CONTROLLER: DeviceType = DeviceType {
    dtype: 0x0147,
    drev: 1,
};

/// The Doorbell device type.
pub const DEV_TYPE_DOORBELL: DeviceType = DeviceType {
    dtype: 0x0148,
    drev: 2,
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
