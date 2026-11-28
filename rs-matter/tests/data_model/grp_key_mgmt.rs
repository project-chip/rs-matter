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

//! Tests for the Group Key Management cluster, along the lines of TC-GRPKEY-2.1 and
//! TC-GRPKEY-2.2. They run also without the `groups` feature: the root node has the
//! cluster in any case.

use rs_matter::dm::clusters::grp_key_mgmt::{self, ClusterHandler as _, GrpKeyMgmtHandler};
use rs_matter::dm::devices::DEV_TYPE_ROOT_NODE;
use rs_matter::dm::{Async, ChainedHandler, Cluster, Dataver, EmptyHandler, Endpoint, Node};
use rs_matter::fabric::{MAX_GROUPS_PER_FABRIC, MAX_GROUP_KEYS_PER_FABRIC};
use rs_matter::im::{AttrPath, AttrStatus, CmdPath, CmdStatus, GenericPath, IMStatusCode};
use rs_matter::tlv::{Nullable, Octets, ToTLV};

use crate::common::e2e::im::attributes::{TestAttrData, TestAttrResp};
use crate::common::e2e::im::commands::{TestCmdData, TestCmdResp};
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

const CLUSTERS: &[Cluster<'static>] = &[GrpKeyMgmtHandler::CLUSTER];

const NODE: Node<'static> = Node {
    endpoints: &[Endpoint::new(0, &[DEV_TYPE_ROOT_NODE], CLUSTERS)],
};

const KEY_0: &[u8] = &[
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];
const KEY_1: &[u8] = &[
    0xd1, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];

/// TLV mirror of the `GroupKeyMapStruct`, as written: context tags 1..=2 (the
/// fabric-index tag 254 is filled in server-side).
#[derive(Debug, Clone, PartialEq, ToTLV)]
#[tlvargs(start = 1)]
struct TestGroupKeyMapEntry {
    group_id: u16,
    group_key_set_id: u16,
}

/// TLV mirror of the `GroupKeyMapStruct`, as read.
#[derive(Debug, Clone, PartialEq, ToTLV)]
#[tlvargs(start = 1)]
struct TestGroupKeyMapEntryRead {
    group_id: u16,
    group_key_set_id: u16,
    #[tagval(254)]
    fabric_index: u8,
}

/// TLV mirror of the `GroupKeySetStruct`.
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestKeySet<'a> {
    group_key_set_id: u16,
    group_key_security_policy: u8,
    epoch_key_0: Nullable<Octets<'a>>,
    epoch_start_time_0: Nullable<u64>,
    epoch_key_1: Nullable<Octets<'a>>,
    epoch_start_time_1: Nullable<u64>,
    epoch_key_2: Nullable<Octets<'a>>,
    epoch_start_time_2: Nullable<u64>,
    group_key_multicast_policy: Option<u8>,
}

impl<'a> TestKeySet<'a> {
    /// A key set with the epoch keys `KEY_0` from 1 and `KEY_1` from 2.
    fn new(group_key_set_id: u16) -> Self {
        Self {
            group_key_set_id,
            group_key_security_policy: 0,
            epoch_key_0: Nullable::some(Octets(KEY_0)),
            epoch_start_time_0: Nullable::some(1),
            epoch_key_1: Nullable::some(Octets(KEY_1)),
            epoch_start_time_1: Nullable::some(2),
            epoch_key_2: Nullable::none(),
            epoch_start_time_2: Nullable::none(),
            group_key_multicast_policy: None,
        }
    }

    /// The key set as `KeySetRead` reports it: without its epoch keys.
    fn redacted(&self) -> Self {
        Self {
            epoch_key_0: Nullable::none(),
            epoch_key_1: Nullable::none(),
            epoch_key_2: Nullable::none(),
            group_key_multicast_policy: Some(0),
            ..self.clone()
        }
    }
}

/// TLV mirror of `KeySetWriteRequest` and `KeySetReadResponse`.
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestKeySetReq<'a> {
    group_key_set: TestKeySet<'a>,
}

/// TLV mirror of `KeySetReadRequest` and `KeySetRemoveRequest`.
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestKeySetIdReq {
    group_key_set_id: u16,
}

/// TLV mirror of `KeySetReadAllIndicesRequest`.
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestEmptyReq {}

/// TLV mirror of `KeySetReadAllIndicesResponse`.
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestKeySetIdsResp<'a> {
    group_key_set_ids: &'a [u16],
}

fn attr_path(attr: grp_key_mgmt::AttributeId) -> GenericPath {
    GenericPath::new(
        Some(0),
        Some(GrpKeyMgmtHandler::CLUSTER.id),
        Some(attr as u32),
    )
}

fn cmd_path(cmd: grp_key_mgmt::CommandId) -> CmdPath {
    CmdPath::new(
        Some(0),
        Some(GrpKeyMgmtHandler::CLUSTER.id),
        Some(cmd as u32),
    )
}

fn cmd_status(cmd: grp_key_mgmt::CommandId, status: IMStatusCode) -> TestCmdResp<'static> {
    TestCmdResp::Status(CmdStatus::new(cmd_path(cmd), status, None, None))
}

#[test]
fn test_group_key_map() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();

    let dm = (
        NODE,
        ChainedHandler::new(
            |e, c| e == 0 && c == GrpKeyMgmtHandler::CLUSTER.id,
            Async(GrpKeyMgmtHandler::new(Dataver::new(1), &im.matter).adapt()),
            EmptyHandler,
        ),
    );

    let map_path = attr_path(grp_key_mgmt::AttributeId::GroupKeyMap);
    let write_map = |map: &[TestGroupKeyMapEntry], status| {
        im.handle_write_reqs(
            &dm,
            &[TestAttrData::new(
                None,
                AttrPath::from_gp(&map_path),
                &map as _,
            )],
            &[AttrStatus::from_gp(&map_path, status, None)],
        );
    };
    let read_map = |map: &[TestGroupKeyMapEntryRead]| {
        im.handle_read_reqs(
            &dm,
            &[AttrPath::from_gp(&map_path)],
            &[TestAttrResp::data(&map_path, &map)],
        );
    };

    write_map(
        &[TestGroupKeyMapEntry {
            group_id: 0x0103,
            group_key_set_id: 0x01a3,
        }],
        IMStatusCode::Success,
    );
    read_map(&[TestGroupKeyMapEntryRead {
        group_id: 0x0103,
        group_key_set_id: 0x01a3,
        fabric_index: 1,
    }]);

    // No groups
    let table_path = attr_path(grp_key_mgmt::AttributeId::GroupTable);
    im.handle_read_reqs(
        &dm,
        &[AttrPath::from_gp(&table_path)],
        &[TestAttrResp::data(&table_path, &&[0u8; 0][..])],
    );

    // Key set 0 is the IPK, which cannot be mapped to a group
    write_map(
        &[TestGroupKeyMapEntry {
            group_id: 0x0103,
            group_key_set_id: 0,
        }],
        IMStatusCode::ConstraintError,
    );

    // Over the capacity
    let too_many = (0..MAX_GROUPS_PER_FABRIC as u16 + 1)
        .map(|i| TestGroupKeyMapEntry {
            group_id: 0x0103 + i,
            group_key_set_id: 0x01a3,
        })
        .collect::<Vec<_>>();
    write_map(&too_many, IMStatusCode::Failure);

    // At the capacity
    write_map(&too_many[..MAX_GROUPS_PER_FABRIC], IMStatusCode::Success);

    write_map(&[], IMStatusCode::Success);
    read_map(&[]);
}

#[test]
fn test_key_sets() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();

    let dm = (
        NODE,
        ChainedHandler::new(
            |e, c| e == 0 && c == GrpKeyMgmtHandler::CLUSTER.id,
            Async(GrpKeyMgmtHandler::new(Dataver::new(1), &im.matter).adapt()),
            EmptyHandler,
        ),
    );

    let max_keys_path = attr_path(grp_key_mgmt::AttributeId::MaxGroupKeysPerFabric);
    im.handle_read_reqs(
        &dm,
        &[AttrPath::from_gp(&max_keys_path)],
        &[TestAttrResp::data(
            &max_keys_path,
            &(MAX_GROUP_KEYS_PER_FABRIC as u16 + 1),
        )],
    );

    let write = |key_set: TestKeySet, status| {
        im.handle_commands(
            &dm,
            &[TestCmdData::new(
                cmd_path(grp_key_mgmt::CommandId::KeySetWrite),
                &TestKeySetReq {
                    group_key_set: key_set,
                },
            )],
            &[cmd_status(grp_key_mgmt::CommandId::KeySetWrite, status)],
        );
    };
    let read = |group_key_set_id, key_set: Option<TestKeySet>| {
        let req = TestKeySetIdReq { group_key_set_id };
        let resp = key_set.map(|key_set| TestKeySetReq {
            group_key_set: key_set,
        });

        im.handle_commands(
            &dm,
            &[TestCmdData::new(
                cmd_path(grp_key_mgmt::CommandId::KeySetRead),
                &req,
            )],
            &[match &resp {
                Some(resp) => TestCmdResp::Cmd(TestCmdData::new(
                    CmdPath::new(
                        Some(0),
                        Some(GrpKeyMgmtHandler::CLUSTER.id),
                        Some(grp_key_mgmt::CommandResponseId::KeySetReadResponse as u32),
                    ),
                    resp,
                )),
                None => cmd_status(grp_key_mgmt::CommandId::KeySetRead, IMStatusCode::NotFound),
            }],
        );
    };
    let remove = |group_key_set_id, status| {
        im.handle_commands(
            &dm,
            &[TestCmdData::new(
                cmd_path(grp_key_mgmt::CommandId::KeySetRemove),
                &TestKeySetIdReq { group_key_set_id },
            )],
            &[cmd_status(grp_key_mgmt::CommandId::KeySetRemove, status)],
        );
    };

    let key_set = TestKeySet::new(0x01a);
    write(key_set.clone(), IMStatusCode::Success);
    read(0x01a, Some(key_set.redacted()));

    // Malformed key sets
    write(
        TestKeySet {
            epoch_key_0: Nullable::none(),
            ..TestKeySet::new(0x01a)
        },
        IMStatusCode::InvalidCommand,
    );
    write(
        TestKeySet {
            epoch_start_time_0: Nullable::some(0),
            ..TestKeySet::new(0x01a)
        },
        IMStatusCode::InvalidCommand,
    );
    write(
        TestKeySet {
            epoch_start_time_1: Nullable::some(1),
            ..TestKeySet::new(0x01a)
        },
        IMStatusCode::InvalidCommand,
    );
    write(
        TestKeySet {
            epoch_key_0: Nullable::some(Octets(&KEY_0[..1])),
            ..TestKeySet::new(0x01a)
        },
        IMStatusCode::ConstraintError,
    );
    write(TestKeySet::new(0), IMStatusCode::InvalidCommand);

    // None of them changed the key set
    read(0x01a, Some(key_set.redacted()));

    read(0x01b, None);

    remove(0x01a, IMStatusCode::Success);
    remove(0x01a, IMStatusCode::NotFound);
    remove(0, IMStatusCode::InvalidCommand);
    read(0x01a, None);

    // Up to the capacity, besides the IPK
    let ids = (1..=MAX_GROUP_KEYS_PER_FABRIC as u16).collect::<Vec<_>>();
    for &id in &ids {
        write(TestKeySet::new(id), IMStatusCode::Success);
    }
    write(
        TestKeySet::new(MAX_GROUP_KEYS_PER_FABRIC as u16 + 1),
        IMStatusCode::ResourceExhausted,
    );

    let all = [&[0][..], &ids].concat();
    im.handle_commands(
        &dm,
        &[TestCmdData::new(
            cmd_path(grp_key_mgmt::CommandId::KeySetReadAllIndices),
            &TestEmptyReq {},
        )],
        &[TestCmdResp::Cmd(TestCmdData::new(
            CmdPath::new(
                Some(0),
                Some(GrpKeyMgmtHandler::CLUSTER.id),
                Some(grp_key_mgmt::CommandResponseId::KeySetReadAllIndicesResponse as u32),
            ),
            &TestKeySetIdsResp {
                group_key_set_ids: &all,
            },
        ))],
    );
}
