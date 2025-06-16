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

use rs_matter::dm::{AsyncHandler, AsyncMetadata};
use rs_matter::error::Error;
use rs_matter::im::messages::ib::{CmdPath, CmdStatus};
use rs_matter::tlv::{TLVTag, TLVWrite, TLVWriter};

use crate::common::e2e::tlv::{TLVTest, TestToTLV};
use crate::common::e2e::E2eRunner;

/// A macro for creating a `TestCmdData` instance by using literal values for data.
#[macro_export]
macro_rules! cmd_data {
    ($path:expr, $data:literal) => {
        $crate::common::e2e::im::commands::TestCmdData::new($path, &($data as u32))
    };
}

#[macro_export]
macro_rules! echo_req {
    ($endpoint:literal, $data:literal) => {
        $crate::common::e2e::im::commands::TestCmdData::new(
            rs_matter::im::messages::ib::CmdPath::new(
                Some($endpoint),
                Some($crate::common::e2e::im::echo_cluster::ID),
                Some($crate::common::e2e::im::echo_cluster::Commands::EchoReq as u32),
            ),
            &($data as u32),
        )
    };
}

#[macro_export]
macro_rules! echo_resp {
    ($endpoint:literal, $data:literal) => {
        $crate::common::e2e::im::commands::TestCmdResp::Cmd(
            $crate::common::e2e::im::commands::TestCmdData::new(
                rs_matter::im::messages::ib::CmdPath::new(
                    Some($endpoint),
                    Some($crate::common::e2e::im::echo_cluster::ID),
                    Some($crate::common::e2e::im::echo_cluster::RespCommands::EchoResp as u32),
                ),
                &($data as u32),
            ),
        )
    };
}

/// A `TestCmdData` alternative more suitable for testing.
///
/// The main difference is that `TestCmdData::data` implements `TestToTLV`, whereas
/// `CmdData::data` is a `TLVElement`.
#[derive(Debug, Clone)]
pub struct TestCmdData<'a> {
    pub path: CmdPath,
    pub data: &'a dyn TestToTLV,
}

impl<'a> TestCmdData<'a> {
    /// Create a new `TestCmdData` instance.
    pub const fn new(path: CmdPath, data: &'a dyn TestToTLV) -> Self {
        Self { path, data }
    }
}

impl TestToTLV for TestCmdData<'_> {
    fn test_to_tlv(&self, tag: &TLVTag, tw: &mut TLVWriter) -> Result<(), Error> {
        tw.start_struct(tag)?;

        self.path.test_to_tlv(&TLVTag::Context(0), tw)?;

        self.data.test_to_tlv(&TLVTag::Context(1), tw)?;

        tw.end_container()?;

        Ok(())
    }
}

/// A `TestCmdResp` alternative more suitable for testing.
///
/// The main difference is that `TestCmdResp::data` implements `TestToTLV`, whereas
/// `CmdResp::data` is a `TLVElement`.
#[derive(Debug, Clone)]
pub enum TestCmdResp<'a> {
    Cmd(TestCmdData<'a>),
    Status(CmdStatus),
}

impl TestToTLV for TestCmdResp<'_> {
    fn test_to_tlv(&self, tag: &TLVTag, tw: &mut TLVWriter) -> Result<(), Error> {
        tw.start_struct(tag)?;

        match self {
            TestCmdResp::Cmd(data) => data.test_to_tlv(&TLVTag::Context(0), tw),
            TestCmdResp::Status(status) => status.test_to_tlv(&TLVTag::Context(1), tw),
        }?;

        tw.end_container()
    }
}

impl E2eRunner {
    /// For backwards compatibility.
    pub fn commands<'a>(input: &'a [TestCmdData<'a>], expected: &'a [TestCmdResp<'a>]) {
        let runner = Self::new_default();
        runner.add_default_acl();
        runner.handle_commands(runner.handler(), input, expected)
    }

    /// For backwards compatibility.
    pub fn handle_commands<'a, H>(
        &self,
        handler: H,
        input: &'a [TestCmdData<'a>],
        expected: &'a [TestCmdResp<'a>],
    ) where
        H: AsyncHandler + AsyncMetadata,
    {
        self.test_one(handler, TLVTest::inv_cmds(input, expected))
    }
}
