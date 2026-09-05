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

//! Tests for the opt-in provisional attributes:
//! - `BasicInformation::DeviceLocation`, advertised via
//!   [`basic_info::CLUSTER_DEVICE_LOCATION`];
//! - `Descriptor::EndpointUniqueID`, advertised via
//!   [`desc::CLUSTER_ENDPOINT_UNIQUE_ID`] and backed by
//!   [`Endpoint::unique_id`].
//!
//! Both are excluded from the default handler metadata, so these tests bring
//! their own `Node` that opts in. This is also the primary coverage for
//! `DeviceLocation`: upstream's `TC_BINFO_2_1` steps 24-28 cannot run against
//! any DUT that advertises the attribute (see the `TC_BINFO_2_1` note in
//! `xtask/src/itest.rs` for the catalogue of bugs in its support module).

use rs_matter::dm::clusters::basic_info::{
    self, BasicInfoConfig, BasicInfoHandler, DeviceLocationConfig,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _, DescHandler};
use rs_matter::dm::clusters::gen_comm::{self, ClusterHandler as _, GenCommHandler};
use rs_matter::dm::devices::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE};
use rs_matter::dm::{
    Async, ChainedHandler, Cluster, DataModel, Dataver, EmptyHandler, Endpoint, Node,
};
use rs_matter::im::{AttrPath, AttrStatus, GenericPath, IMStatusCode};
use rs_matter::tlv::{Nullable, ToTLV, Utf8Str};

use rs_matter::dm::devices::test::TEST_DEV_DET;

use crate::common::e2e::im::attributes::TestAttrData;
use crate::common::e2e::{new_default_runner, new_default_runner_with_dev_det};
use crate::common::init_env_logger;
use crate::{attr_data, attr_read_status_resp};

/// The unique ID the test `Node` attaches to endpoint 1.
const EP1_UNIQUE_ID: &str = "test-ep1-unique-id";

const CLUSTERS_EP0: &[Cluster<'static>] = &[
    basic_info::CLUSTER_DEVICE_LOCATION,
    // Plain metadata on EP0 - reading `EndpointUniqueID` here must answer
    // `UnsupportedAttribute` even though EP1 (same handler type) serves it.
    DescHandler::CLUSTER,
];

const CLUSTERS_EP1: &[Cluster<'static>] = &[desc::CLUSTER_ENDPOINT_UNIQUE_ID];

const NODE: Node<'static> = Node {
    endpoints: &[
        Endpoint::new(0, &[DEV_TYPE_ROOT_NODE], CLUSTERS_EP0),
        Endpoint::new(1, &[DEV_TYPE_ON_OFF_LIGHT], CLUSTERS_EP1).with_unique_id(EP1_UNIQUE_ID),
    ],
};

/// A data model over [`NODE`] serving `BasicInformation` on EP0 and
/// `Descriptor` on both endpoints.
fn dm_handler() -> impl DataModel {
    (
        NODE,
        ChainedHandler::new(
            |e, c| e == 0 && c == basic_info::CLUSTER_DEVICE_LOCATION.id,
            Async(BasicInfoHandler::new(Dataver::new(1)).adapt()),
            EmptyHandler,
        )
        .chain(
            |e, c| e == 0 && c == DescHandler::CLUSTER.id,
            Async(DescHandler::new(Dataver::new(2)).adapt()),
        )
        .chain(
            |e, c| e == 1 && c == desc::CLUSTER_ENDPOINT_UNIQUE_ID.id,
            Async(DescHandler::new(Dataver::new(3)).adapt()),
        ),
    )
}

/// Borrowed mirror of the global `LocationDescriptorStruct`, TLV-identical to
/// what the device serves: positional context tags 0..=2, TLV `Null` for the
/// null fields (which the owned `basic_info::DeviceLocation` - with its
/// `Option` fields - would instead omit).
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToTLV)]
struct TestDeviceLocation<'a> {
    location_name: Utf8Str<'a>,
    floor_number: Nullable<i16>,
    area_type: Nullable<u8>,
}

fn device_location_path() -> GenericPath {
    GenericPath::new(
        Some(0),
        Some(basic_info::CLUSTER_DEVICE_LOCATION.id),
        Some(basic_info::AttributeId::DeviceLocation as u32),
    )
}

#[test]
fn test_device_location_write_read() {
    init_env_logger();

    let path = device_location_path();
    let input = &[AttrPath::from_gp(&path)];

    let im = new_default_runner();
    im.add_default_acl();
    let dm = dm_handler();

    // Fresh device: the attribute is advertised and must read as Null.
    let null: Nullable<TestDeviceLocation> = Nullable::none();
    im.handle_read_reqs(
        &dm,
        input,
        &[attr_data!(
            0,
            40,
            basic_info::AttributeId::DeviceLocation,
            Some(&null)
        )],
    );

    // Admin-write a full struct (max-length name, non-null floor and area)
    // and read it back verbatim.
    let max_name = "location".repeat(16);
    assert_eq!(max_name.len(), 128);
    let location = TestDeviceLocation {
        location_name: &max_name,
        floor_number: Nullable::some(200),
        area_type: Nullable::some(2),
    };
    im.handle_write_reqs(
        &dm,
        &[TestAttrData::new(
            None,
            AttrPath::from_gp(&path),
            &location as _,
        )],
        &[AttrStatus::from_gp(&path, IMStatusCode::Success, None)],
    );
    im.handle_read_reqs(
        &dm,
        input,
        &[attr_data!(
            0,
            40,
            basic_info::AttributeId::DeviceLocation,
            Some(&location)
        )],
    );

    // A struct with null floor/area round-trips the nulls (they are
    // nullable-not-optional, so they stay present on the wire as TLV Null).
    let sparse = TestDeviceLocation {
        location_name: "",
        floor_number: Nullable::none(),
        area_type: Nullable::none(),
    };
    im.handle_write_reqs(
        &dm,
        &[TestAttrData::new(
            None,
            AttrPath::from_gp(&path),
            &sparse as _,
        )],
        &[AttrStatus::from_gp(&path, IMStatusCode::Success, None)],
    );
    im.handle_read_reqs(
        &dm,
        input,
        &[attr_data!(
            0,
            40,
            basic_info::AttributeId::DeviceLocation,
            Some(&sparse)
        )],
    );

    // Writing Null clears the attribute back to Null.
    im.handle_write_reqs(
        &dm,
        &[TestAttrData::new(
            None,
            AttrPath::from_gp(&path),
            &null as _,
        )],
        &[AttrStatus::from_gp(&path, IMStatusCode::Success, None)],
    );
    im.handle_read_reqs(
        &dm,
        input,
        &[attr_data!(
            0,
            40,
            basic_info::AttributeId::DeviceLocation,
            Some(&null)
        )],
    );

    // A location name over the 128-byte limit is rejected with
    // ConstraintError and leaves the (Null) value untouched.
    let long_name = "x".repeat(129);
    let too_long = TestDeviceLocation {
        location_name: &long_name,
        floor_number: Nullable::none(),
        area_type: Nullable::none(),
    };
    im.handle_write_reqs(
        &dm,
        &[TestAttrData::new(
            None,
            AttrPath::from_gp(&path),
            &too_long as _,
        )],
        &[AttrStatus::from_gp(
            &path,
            IMStatusCode::ConstraintError,
            None,
        )],
    );
    im.handle_read_reqs(
        &dm,
        input,
        &[attr_data!(
            0,
            40,
            basic_info::AttributeId::DeviceLocation,
            Some(&null)
        )],
    );
}

#[test]
fn test_endpoint_unique_id_read() {
    init_env_logger();

    let ep1_path = GenericPath::new(
        Some(1),
        Some(desc::CLUSTER_ENDPOINT_UNIQUE_ID.id),
        Some(desc::AttributeId::EndpointUniqueID as u32),
    );
    let ep0_path = GenericPath::new(
        Some(0),
        Some(DescHandler::CLUSTER.id),
        Some(desc::AttributeId::EndpointUniqueID as u32),
    );

    let im = new_default_runner();
    im.add_default_acl();
    let dm = dm_handler();

    // EP1 advertises the attribute and serves `Endpoint::unique_id`.
    im.handle_read_reqs(
        &dm,
        &[AttrPath::from_gp(&ep1_path)],
        &[attr_data!(
            1,
            29,
            desc::AttributeId::EndpointUniqueID,
            Some(&EP1_UNIQUE_ID)
        )],
    );

    // EP0 uses the default `Descriptor` metadata (same handler type), where
    // the attribute is not advertised.
    im.handle_read_reqs(
        &dm,
        &[AttrPath::from_gp(&ep0_path)],
        &[attr_read_status_resp!(
            &ep0_path,
            IMStatusCode::UnsupportedAttribute
        )],
    );
}

/// Device configuration carrying factory defaults for both `Location` and
/// `DeviceLocation`.
static DEV_DET_WITH_DEFAULTS: BasicInfoConfig<'static> = BasicInfoConfig {
    location: Some("BG"),
    device_location: Some(DeviceLocationConfig {
        location_name: "Attic",
        floor_number: Some(2),
        area_type: None,
    }),
    ..TEST_DEV_DET
};

/// The `BasicInfoConfig` factory defaults must be reported live - with no
/// startup seeding involved - until a value is configured at runtime, and an
/// admin-written value (including an explicit `Null` `DeviceLocation`) must
/// take precedence.
#[test]
fn test_config_factory_defaults() {
    init_env_logger();

    let path = device_location_path();
    let input = &[AttrPath::from_gp(&path)];

    let im = new_default_runner_with_dev_det(&DEV_DET_WITH_DEFAULTS);
    im.add_default_acl();
    let dm = dm_handler();

    // Fresh device: both attributes report the factory defaults.
    let factory = TestDeviceLocation {
        location_name: "Attic",
        floor_number: Nullable::some(2),
        area_type: Nullable::none(),
    };
    im.handle_read_reqs(
        &dm,
        input,
        &[attr_data!(
            0,
            40,
            basic_info::AttributeId::DeviceLocation,
            Some(&factory)
        )],
    );

    let location_path = GenericPath::new(
        Some(0),
        Some(basic_info::CLUSTER_DEVICE_LOCATION.id),
        Some(basic_info::AttributeId::Location as u32),
    );
    im.handle_read_reqs(
        &dm,
        &[AttrPath::from_gp(&location_path)],
        &[attr_data!(
            0,
            40,
            basic_info::AttributeId::Location,
            Some(&"BG")
        )],
    );

    // An explicitly-written `Null` overrides the factory default...
    let null: Nullable<TestDeviceLocation> = Nullable::none();
    im.handle_write_reqs(
        &dm,
        &[TestAttrData::new(
            None,
            AttrPath::from_gp(&path),
            &null as _,
        )],
        &[AttrStatus::from_gp(&path, IMStatusCode::Success, None)],
    );
    im.handle_read_reqs(
        &dm,
        input,
        &[attr_data!(
            0,
            40,
            basic_info::AttributeId::DeviceLocation,
            Some(&null)
        )],
    );

    // ...and so does an admin-written value.
    let written = TestDeviceLocation {
        location_name: "Garage",
        floor_number: Nullable::none(),
        area_type: Nullable::none(),
    };
    im.handle_write_reqs(
        &dm,
        &[TestAttrData::new(
            None,
            AttrPath::from_gp(&path),
            &written as _,
        )],
        &[AttrStatus::from_gp(&path, IMStatusCode::Success, None)],
    );
    im.handle_read_reqs(
        &dm,
        input,
        &[attr_data!(
            0,
            40,
            basic_info::AttributeId::DeviceLocation,
            Some(&written)
        )],
    );
}

// ---- General Commissioning: Network Recovery (provisional 1.6) -------------
//
// `RecoveryIdentifier` (0x000A) and `NetworkRecoveryReason` (0x000B) plus the
// `NetworkRecovery` (`NR`) FeatureMap bit are advertised only via the opt-in
// `gen_comm::CLUSTER_NETWORK_RECOVERY` metadata; the default
// `GenCommHandler::CLUSTER` keeps them hidden (provisional, and no upstream
// test references them). The runtime `GenCommHandler` always implements both
// reads, so - as with `DeviceLocation` - the choice is purely a metadata swap.
//
// NOTE: `RecoveryIdentifier` is minted lazily on first read from the CSPRNG, so
// its value is not deterministic here; its persistence and factory-reset
// semantics are covered by the `BasicInfoSettings` unit tests. These e2e tests
// therefore assert the deterministic surface: the feature bit, the always-null
// `NetworkRecoveryReason`, and that both attributes are gated off by default.

/// EP0 metadata exposing General Commissioning with Network Recovery enabled.
const CLUSTERS_EP0_NR: &[Cluster<'static>] = &[gen_comm::CLUSTER_NETWORK_RECOVERY];

const NODE_NR: Node<'static> = Node {
    endpoints: &[Endpoint::new(0, &[DEV_TYPE_ROOT_NODE], CLUSTERS_EP0_NR)],
};

/// A data model over [`NODE_NR`] serving General Commissioning with the Network
/// Recovery feature (and its two provisional attributes) exposed. `&true` is
/// the no-op `CommPolicy` (concurrent-connection, indoor/outdoor, default
/// fail-safe timings) - none of which the recovery reads consult.
fn nr_dm_handler() -> impl DataModel {
    (
        NODE_NR,
        ChainedHandler::new(
            |e, c| e == 0 && c == gen_comm::CLUSTER_NETWORK_RECOVERY.id,
            Async(GenCommHandler::new(Dataver::new(1), &true).adapt()),
            EmptyHandler,
        ),
    )
}

/// EP0 metadata using the *default* General Commissioning cluster (Network
/// Recovery not advertised).
const CLUSTERS_EP0_GC: &[Cluster<'static>] = &[GenCommHandler::CLUSTER];

const NODE_GC: Node<'static> = Node {
    endpoints: &[Endpoint::new(0, &[DEV_TYPE_ROOT_NODE], CLUSTERS_EP0_GC)],
};

/// A data model over [`NODE_GC`] - the same `GenCommHandler`, but with the
/// default metadata that hides the provisional Network Recovery attributes.
fn gc_dm_handler() -> impl DataModel {
    (
        NODE_GC,
        ChainedHandler::new(
            |e, c| e == 0 && c == GenCommHandler::CLUSTER.id,
            Async(GenCommHandler::new(Dataver::new(1), &true).adapt()),
            EmptyHandler,
        ),
    )
}

fn nr_attr_path(attr: gen_comm::AttributeId) -> GenericPath {
    GenericPath::new(
        Some(0),
        Some(gen_comm::CLUSTER_NETWORK_RECOVERY.id),
        Some(attr as u32),
    )
}

#[test]
fn test_network_recovery_feature_and_reason() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let dm = nr_dm_handler();

    // The Network Recovery feature bit (`NR` == 0x2) is advertised in FeatureMap.
    let feature_map_path = nr_attr_path(gen_comm::AttributeId::FeatureMap);
    im.handle_read_reqs(
        &dm,
        &[AttrPath::from_gp(&feature_map_path)],
        &[attr_data!(
            0,
            48,
            gen_comm::AttributeId::FeatureMap,
            Some(&2u32)
        )],
    );

    // `NetworkRecoveryReason` is exposed and reads as Null - the node never
    // autonomously enters recovery mode (Matter Core Spec 11.10.6.12).
    let reason_path = nr_attr_path(gen_comm::AttributeId::NetworkRecoveryReason);
    let null: Nullable<u8> = Nullable::none();
    im.handle_read_reqs(
        &dm,
        &[AttrPath::from_gp(&reason_path)],
        &[attr_data!(
            0,
            48,
            gen_comm::AttributeId::NetworkRecoveryReason,
            Some(&null)
        )],
    );
}

#[test]
fn test_network_recovery_attributes_gated_by_default() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();
    let dm = gc_dm_handler();

    // With the default metadata, both provisional attributes are absent from
    // the cluster and read back `UnsupportedAttribute` - even though the same
    // handler type implements them for a Network-Recovery-enabled node.
    for attr in [
        gen_comm::AttributeId::RecoveryIdentifier,
        gen_comm::AttributeId::NetworkRecoveryReason,
    ] {
        let path = GenericPath::new(Some(0), Some(GenCommHandler::CLUSTER.id), Some(attr as u32));
        im.handle_read_reqs(
            &dm,
            &[AttrPath::from_gp(&path)],
            &[attr_read_status_resp!(
                &path,
                IMStatusCode::UnsupportedAttribute
            )],
        );
    }
}
