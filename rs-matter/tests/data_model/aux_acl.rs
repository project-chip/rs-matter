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

//! Tests for the opt-in `AuxiliaryACL` support of the Access Control cluster
//! ([`acl::CLUSTER_AUX`]): serving the attribute (an empty list until a
//! producing feature such as Groupcast exists - entries are derived on the
//! fly, never stored), and rejecting `AuxiliaryType` in writable-`ACL`
//! writes.
//!
//! The root-endpoint exclusion for wildcard-target Group-auth entries is
//! covered by the unit tests in `rs-matter/src/acl.rs`.

use rs_matter::tlv::Nullable;
use rs_matter::dm::clusters::acl::{self, AclHandler};
use rs_matter::dm::devices::DEV_TYPE_ROOT_NODE;
use rs_matter::dm::{
    Async, ChainedHandler, Cluster, DataModel, Dataver, EmptyHandler, Endpoint, EpClMatcher, Node,
};
use rs_matter::im::{AttrPath, AttrStatus, GenericPath, IMStatusCode};
use rs_matter::tlv::ToTLV;

use crate::common::e2e::im::attributes::TestAttrData;
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;
use crate::{attr_data, attr_data_path};

const GROUP_ID: u64 = 0x12AB;

const CLUSTERS_EP0: &[Cluster<'static>] = &[acl::CLUSTER_AUX];

const NODE: Node<'static> = Node {
    endpoints: &[Endpoint::new(0, &[DEV_TYPE_ROOT_NODE], CLUSTERS_EP0)],
};

/// A data model over [`NODE`] serving the Access Control cluster (with the
/// `AUXILIARY` feature) on EP0.
fn dm_handler() -> impl DataModel {
    (
        NODE,
        ChainedHandler::new(
            EpClMatcher::new(Some(0), Some(acl::CLUSTER_AUX.id)),
            Async(AclHandler::new(Dataver::new(1)).adapt()),
            EmptyHandler,
        ),
    )
}

/// TLV mirror of the `AccessControlTargetStruct`: positional context tags
/// 0..=2, with TLV `Null` for the null fields (which the `Option`-based
/// [`Target`] would instead omit).
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestTarget {
    cluster: Nullable<u32>,
    endpoint: Nullable<u16>,
    device_type: Nullable<u32>,
}

impl TestTarget {
    fn endpoint(endpoint: u16) -> Self {
        Self {
            cluster: Nullable::none(),
            endpoint: Nullable::some(endpoint),
            device_type: Nullable::none(),
        }
    }
}

/// The shape of a legal client-written `ACL` list entry: positional context
/// tags 1..=4.
#[derive(Debug, Clone, PartialEq, ToTLV)]
#[tlvargs(start = 1)]
struct TestAclEntry<'a> {
    privilege: u8,
    auth_mode: u8,
    subjects: &'a [u64],
    targets: &'a [TestTarget],
}

/// Same as [`TestAclEntry`], but carrying the (server-only) `AuxiliaryType`
/// field - the shape of an *illegal* client-written `ACL` list entry.
#[derive(Debug, Clone, PartialEq, ToTLV)]
#[tlvargs(start = 1)]
struct TestAuxEntryWrite<'a> {
    privilege: u8,
    auth_mode: u8,
    subjects: &'a [u64],
    targets: &'a [TestTarget],
    auxiliary_type: u8,
}

const PRIVILEGE_OPERATE: u8 = 3;
const AUTH_MODE_GROUP: u8 = 3;
const AUX_TYPE_GROUPCAST: u8 = 1;


#[test]
fn test_auxiliary_acl_read() {
    init_env_logger();

    let path = GenericPath::new(
        Some(0),
        Some(acl::CLUSTER_AUX.id),
        Some(acl::AttributeId::AuxiliaryACL as u32),
    );
    let input = &[AttrPath::from_gp(&path)];

    let im = new_default_runner();
    im.add_default_acl();
    let dm = dm_handler();

    // Nothing synthesized yet: the attribute reads as an empty list.
    let no_entries: &[TestAclEntry] = &[];
    im.handle_read_reqs(
        &dm,
        input,
        &[attr_data!(
            0,
            31,
            acl::AttributeId::AuxiliaryACL,
            Some(&no_entries)
        )],
    );
}

#[test]
fn test_acl_write_rejects_auxiliary_type() {
    init_env_logger();

    let path = GenericPath::new(
        Some(0),
        Some(acl::CLUSTER_AUX.id),
        Some(acl::AttributeId::Acl as u32),
    );

    let im = new_default_runner();
    im.add_default_acl();
    let dm = dm_handler();

    // A write of an `ACL` list entry carrying the (server-only)
    // `AuxiliaryType` field must be rejected with `ConstraintError`.
    let targets = [TestTarget::endpoint(1)];
    let bad = &[TestAuxEntryWrite {
        privilege: PRIVILEGE_OPERATE,
        auth_mode: AUTH_MODE_GROUP,
        subjects: &[GROUP_ID],
        targets: &targets,
        auxiliary_type: AUX_TYPE_GROUPCAST,
    }][..];
    im.handle_write_reqs(
        &dm,
        &[TestAttrData::new(None, AttrPath::from_gp(&path), &bad as _)],
        &[AttrStatus::from_gp(
            &path,
            IMStatusCode::ConstraintError,
            None,
        )],
    );

    // The same entry without `AuxiliaryType` is accepted.
    let good = &[TestAclEntry {
        privilege: PRIVILEGE_OPERATE,
        auth_mode: AUTH_MODE_GROUP,
        subjects: &[GROUP_ID],
        targets: &targets,
    }][..];
    im.handle_write_reqs(
        &dm,
        &[TestAttrData::new(None, AttrPath::from_gp(&path), &good as _)],
        &[AttrStatus::from_gp(&path, IMStatusCode::Success, None)],
    );
}

// Silence unused-import lint (used only via macro expansion)
#[allow(unused)]
use attr_data_path as _;
