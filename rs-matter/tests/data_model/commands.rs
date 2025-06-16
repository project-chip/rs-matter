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

use rs_matter::dm::clusters::on_off::{self, ClusterHandler as _};
use rs_matter::im::core::IMStatusCode;
use rs_matter::im::messages::ib::{CmdPath, CmdStatus};

use crate::common::e2e::im::commands::TestCmdResp;
use crate::common::e2e::im::echo_cluster;
use crate::common::e2e::ImEngine;
use crate::common::init_env_logger;
use crate::{cmd_data, echo_req, echo_resp};

#[test]
fn test_invoke_cmds_success() {
    // 2 echo Requests
    // - one on endpoint 0 with data 5,
    // - another on endpoint 1 with data 10
    init_env_logger();

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];
    let expected = &[echo_resp!(0, 10), echo_resp!(1, 30)];
    ImEngine::commands(input, expected);
}

#[test]
fn test_invoke_cmds_unsupported_fields() {
    // 5 commands
    // - endpoint doesn't exist - UnsupportedEndpoint
    // - cluster doesn't exist - UnsupportedCluster
    // - cluster doesn't exist and endpoint is wildcard - UnsupportedCluster
    // - command doesn't exist - UnsupportedCommand
    // - command doesn't exist and endpoint is wildcard - UnsupportedCommand
    init_env_logger();

    let invalid_endpoint = CmdPath::new(
        Some(2),
        Some(echo_cluster::ID),
        Some(echo_cluster::Commands::EchoReq as u32),
    );
    let invalid_cluster = CmdPath::new(
        Some(0),
        Some(0x1234),
        Some(echo_cluster::Commands::EchoReq as u32),
    );
    let invalid_cluster_wc_endpoint = CmdPath::new(
        None,
        Some(0x1234),
        Some(echo_cluster::Commands::EchoReq as u32),
    );
    let invalid_command = CmdPath::new(Some(0), Some(echo_cluster::ID), Some(0x1234));
    let invalid_command_wc_endpoint = CmdPath::new(None, Some(echo_cluster::ID), Some(0x1234));
    let input = &[
        cmd_data!(invalid_endpoint.clone(), 5),
        cmd_data!(invalid_cluster.clone(), 5),
        cmd_data!(invalid_cluster_wc_endpoint, 5),
        cmd_data!(invalid_command.clone(), 5),
        cmd_data!(invalid_command_wc_endpoint, 5),
    ];

    let expected = &[
        TestCmdResp::Status(CmdStatus::new(
            invalid_endpoint,
            IMStatusCode::UnsupportedEndpoint,
            0,
        )),
        TestCmdResp::Status(CmdStatus::new(
            invalid_cluster,
            IMStatusCode::UnsupportedCluster,
            0,
        )),
        TestCmdResp::Status(CmdStatus::new(
            invalid_command,
            IMStatusCode::UnsupportedCommand,
            0,
        )),
    ];
    ImEngine::commands(input, expected);
}

#[test]
fn test_invoke_cmd_wc_endpoint_all_have_clusters() {
    // 1 echo Request with wildcard endpoint
    // should generate 2 responses from the echo clusters on both
    init_env_logger();
    let path = CmdPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::Commands::EchoReq as u32),
    );
    let input = &[cmd_data!(path, 5)];
    let expected = &[echo_resp!(0, 10), echo_resp!(1, 15)];
    ImEngine::commands(input, expected);
}

#[test]
fn test_invoke_cmd_wc_endpoint_only_1_has_cluster() {
    // 1 on command for on/off cluster with wildcard endpoint
    // should generate 1 response from the on-off cluster
    init_env_logger();

    let target = CmdPath::new(
        None,
        Some(on_off::OnOffHandler::CLUSTER.id),
        Some(on_off::CommandId::On as u32),
    );
    let expected_path = CmdPath::new(
        Some(1),
        Some(on_off::OnOffHandler::CLUSTER.id),
        Some(on_off::CommandId::On as u32),
    );
    let input = &[cmd_data!(target, 1)];
    let expected = &[TestCmdResp::Status(CmdStatus::new(
        expected_path,
        IMStatusCode::Success,
        0,
    ))];
    ImEngine::commands(input, expected);
}
