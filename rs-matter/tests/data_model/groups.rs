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

//! Tests for the Groups cluster's `AddGroupIfIdentifying` command and its
//! coupling to the Identify cluster via `IdentifyStatus`: the command is a
//! successful no-op unless the endpoint is currently identifying, and on the
//! identifying path applies the same validation as `AddGroup` — reported as
//! a plain IM status, since the command has no response structure.

use rs_matter::dm::clusters::groups::{self, ClusterHandler as _, GroupsHandler};
use rs_matter::dm::clusters::grp_key_mgmt::{self, ClusterHandler as _, GrpKeyMgmtHandler};
use rs_matter::dm::clusters::identify::{self, IdentifyHandler};
use rs_matter::dm::devices::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE};
use rs_matter::dm::{Async, ChainedHandler, Cluster, Dataver, EmptyHandler, Endpoint, Node};
use rs_matter::im::{AttrPath, AttrStatus, CmdPath, CmdStatus, GenericPath, IMStatusCode};
use rs_matter::tlv::{Nullable, ToTLV};

use crate::common::e2e::im::attributes::TestAttrData;
use crate::common::e2e::im::commands::{TestCmdData, TestCmdResp};
use crate::common::e2e::new_default_runner;
use crate::common::init_env_logger;

const GROUP_ID: u16 = 0x0012;
const KEY_SET_ID: u16 = 0x01A3;

const CLUSTERS_EP0: &[Cluster<'static>] = &[GrpKeyMgmtHandler::CLUSTER];
const CLUSTERS_EP1: &[Cluster<'static>] = &[identify::CLUSTER, GroupsHandler::CLUSTER];

const NODE: Node<'static> = Node {
    endpoints: &[
        Endpoint::new(0, &[DEV_TYPE_ROOT_NODE], CLUSTERS_EP0),
        Endpoint::new(1, &[DEV_TYPE_ON_OFF_LIGHT], CLUSTERS_EP1),
    ],
};

/// TLV mirror of `AddGroupIfIdentifyingRequest`: positional context tags 0..=1.
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestAddGroupIfIdentifyingReq<'a> {
    group_id: u16,
    group_name: &'a str,
}

/// TLV mirror of `GetGroupMembershipRequest`: context tag 0.
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestGetGroupMembershipReq<'a> {
    group_list: &'a [u16],
}

/// TLV mirror of `GetGroupMembershipResponse`: positional context tags 0..=1.
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestGetGroupMembershipResp<'a> {
    capacity: Nullable<u8>,
    group_list: &'a [u16],
}

/// TLV mirror of the `GroupKeyMapStruct`: context tags 1..=2 (the
/// fabric-index tag 254 is filled in server-side).
#[derive(Debug, Clone, PartialEq, ToTLV)]
#[tlvargs(start = 1)]
struct TestGroupKeyMapEntry {
    group_id: u16,
    group_key_set_id: u16,
}

fn groups_cmd(cmd: groups::CommandId) -> CmdPath {
    CmdPath::new(Some(1), Some(GroupsHandler::CLUSTER.id), Some(cmd as u32))
}

fn groups_resp(resp: groups::CommandResponseId) -> CmdPath {
    CmdPath::new(Some(1), Some(GroupsHandler::CLUSTER.id), Some(resp as u32))
}

/// Invoke `GetGroupMembership` (empty filter = all groups) and expect
/// exactly `group_list` back.
fn expect_membership(
    im: &crate::common::e2e::E2eRunner<impl rs_matter::crypto::Crypto>,
    dm: &impl rs_matter::dm::DataModel,
    group_list: &[u16],
) {
    im.handle_commands(
        dm,
        &[TestCmdData::new(
            groups_cmd(groups::CommandId::GetGroupMembership),
            &TestGetGroupMembershipReq { group_list: &[] },
        )],
        &[TestCmdResp::Cmd(TestCmdData::new(
            groups_resp(groups::CommandResponseId::GetGroupMembershipResponse),
            &TestGetGroupMembershipResp {
                capacity: Nullable::none(),
                group_list,
            },
        ))],
    );
}

#[test]
fn test_add_group_if_identifying() {
    init_env_logger();

    let im = new_default_runner();
    im.add_default_acl();

    let identify_handler = IdentifyHandler::new(Dataver::new(1));

    let dm = (
        NODE,
        ChainedHandler::new(
            |e, c| e == 0 && c == GrpKeyMgmtHandler::CLUSTER.id,
            Async(GrpKeyMgmtHandler::new(Dataver::new(2)).adapt()),
            ChainedHandler::new(
                |e, c| e == 1 && c == identify::CLUSTER.id,
                Async(identify::HandlerAdaptor(&identify_handler)),
                ChainedHandler::new(
                    |e, c| e == 1 && c == GroupsHandler::CLUSTER.id,
                    Async(
                        GroupsHandler::new_with_identify(Dataver::new(3), &identify_handler)
                            .adapt(),
                    ),
                    EmptyHandler,
                ),
            ),
        ),
    );

    // Provision group key material (a GroupKeyMap entry) for GROUP_ID, so
    // that the identifying-path additions below pass the key-material check.
    let map_path = GenericPath::new(
        Some(0),
        Some(GrpKeyMgmtHandler::CLUSTER.id),
        Some(grp_key_mgmt::AttributeId::GroupKeyMap as u32),
    );
    let map = &[TestGroupKeyMapEntry {
        group_id: GROUP_ID,
        group_key_set_id: KEY_SET_ID,
    }][..];
    im.handle_write_reqs(
        &dm,
        &[TestAttrData::new(
            None,
            AttrPath::from_gp(&map_path),
            &map as _,
        )],
        &[AttrStatus::from_gp(&map_path, IMStatusCode::Success, None)],
    );

    // Not identifying: the command is accepted (SUCCESS)...
    let add_req = TestAddGroupIfIdentifyingReq {
        group_id: GROUP_ID,
        group_name: "gp1",
    };
    im.handle_commands(
        &dm,
        &[TestCmdData::new(
            groups_cmd(groups::CommandId::AddGroupIfIdentifying),
            &add_req,
        )],
        &[TestCmdResp::Status(CmdStatus::new(
            groups_cmd(groups::CommandId::AddGroupIfIdentifying),
            IMStatusCode::Success,
            None,
            None,
        ))],
    );

    // ...but has no effect
    expect_membership(&im, &dm, &[]);

    // Start identifying via an `IdentifyTime` write
    let time_path = GenericPath::new(
        Some(1),
        Some(identify::CLUSTER.id),
        Some(identify::AttributeId::IdentifyTime as u32),
    );
    im.handle_write_reqs(
        &dm,
        &[TestAttrData::new(
            None,
            AttrPath::from_gp(&time_path),
            &60u16 as _,
        )],
        &[AttrStatus::from_gp(&time_path, IMStatusCode::Success, None)],
    );

    // Identifying: constraint validation applies (group ID 0 is invalid)
    im.handle_commands(
        &dm,
        &[TestCmdData::new(
            groups_cmd(groups::CommandId::AddGroupIfIdentifying),
            &TestAddGroupIfIdentifyingReq {
                group_id: 0,
                group_name: "gp1",
            },
        )],
        &[TestCmdResp::Status(CmdStatus::new(
            groups_cmd(groups::CommandId::AddGroupIfIdentifying),
            IMStatusCode::ConstraintError,
            None,
            None,
        ))],
    );

    // Identifying: a group without key material is rejected
    im.handle_commands(
        &dm,
        &[TestCmdData::new(
            groups_cmd(groups::CommandId::AddGroupIfIdentifying),
            &TestAddGroupIfIdentifyingReq {
                group_id: 0x0034,
                group_name: "gp2",
            },
        )],
        &[TestCmdResp::Status(CmdStatus::new(
            groups_cmd(groups::CommandId::AddGroupIfIdentifying),
            IMStatusCode::UnsupportedAccess,
            None,
            None,
        ))],
    );

    // Identifying + key material: the group is added
    im.handle_commands(
        &dm,
        &[TestCmdData::new(
            groups_cmd(groups::CommandId::AddGroupIfIdentifying),
            &add_req,
        )],
        &[TestCmdResp::Status(CmdStatus::new(
            groups_cmd(groups::CommandId::AddGroupIfIdentifying),
            IMStatusCode::Success,
            None,
            None,
        ))],
    );

    expect_membership(&im, &dm, &[GROUP_ID]);
}
