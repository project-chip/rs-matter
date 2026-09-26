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

//! Wire-level tests for the Fan Control cluster handler: the same rules the
//! unit tests in `dm::clusters::app::fan_control` cover, but driven over the
//! Interaction Model on the loopback runner, so that the `CONSTRAINT_ERROR` /
//! `INVALID_IN_STATE` statuses are the ones a controller would actually read
//! back rather than the `Error` the helper returned.
//!
//! The upstream `TC_FAN_*` suites cover the same ground against the CHIP
//! certification harness (`cargo xtask itest --suite fan`), but those only
//! run where `.build/itest` has been set up; these run in ordinary CI.

use rs_matter::dm::clusters::app::fan_control::{
    self, test::TestFanDeviceLogic, AirflowDirectionEnum, AttributeId, CommandId,
    FanControlHandler, FanControlHooks, FanModeEnum, FanModeSequenceEnum, RockBitmap,
    StepDirectionEnum, WindBitmap,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _, DescHandler};
use rs_matter::dm::devices::{DEV_TYPE_FAN, DEV_TYPE_ROOT_NODE};
use rs_matter::dm::{
    Async, ChainedHandler, Cluster, DataModel, Dataver, EmptyHandler, Endpoint, Node,
};
use rs_matter::im::{AttrPath, AttrStatus, CmdPath, CmdStatus, GenericPath, IMStatusCode};
use rs_matter::tlv::{Nullable, ToTLV};

use crate::common::e2e::im::attributes::{TestAttrData, TestAttrResp};
use crate::common::e2e::im::commands::{TestCmdData, TestCmdResp};
use crate::common::e2e::{new_default_runner, E2eRunner};
use crate::common::init_env_logger;

/// The endpoint the fan lives on.
const EP: u16 = 1;

const CLUSTERS_EP0: &[Cluster<'static>] = &[DescHandler::CLUSTER];
const CLUSTERS_EP1: &[Cluster<'static>] = &[
    DescHandler::CLUSTER,
    <TestFanDeviceLogic as FanControlHooks>::CLUSTER,
];

const NODE: Node<'static> = Node {
    endpoints: &[
        Endpoint::new(0, &[DEV_TYPE_ROOT_NODE], CLUSTERS_EP0),
        Endpoint::new(EP, &[DEV_TYPE_FAN], CLUSTERS_EP1),
    ],
};

/// TLV mirror of `StepRequest`: positional context tags 0..=2, the last two
/// optional.
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestStepReq {
    direction: StepDirectionEnum,
    wrap: Option<bool>,
    lowest_off: Option<bool>,
}

fn attr(attr: AttributeId) -> GenericPath {
    GenericPath::new(
        Some(EP),
        Some(<TestFanDeviceLogic as FanControlHooks>::CLUSTER.id),
        Some(attr as u32),
    )
}

fn step() -> CmdPath {
    CmdPath::new(
        Some(EP),
        Some(<TestFanDeviceLogic as FanControlHooks>::CLUSTER.id),
        Some(CommandId::Step as u32),
    )
}

/// A runner, and the simulated fan to put on [`EP`].
fn fan() -> (
    E2eRunner<impl rs_matter::crypto::Crypto>,
    TestFanDeviceLogic,
) {
    init_env_logger();

    let runner = new_default_runner();
    runner.add_default_acl();

    (runner, TestFanDeviceLogic::new())
}

fn data_model(logic: &TestFanDeviceLogic) -> impl DataModel + '_ {
    (
        NODE,
        ChainedHandler::new(
            |e, c| e == 0 && c == DescHandler::CLUSTER.id,
            Async(DescHandler::new(Dataver::new(1)).adapt()),
            ChainedHandler::new(
                |e, c| e == EP && c == DescHandler::CLUSTER.id,
                Async(desc::HandlerAdaptor(DescHandler::new(Dataver::new(2)))),
                ChainedHandler::new(
                    |e, c| e == EP && c == <TestFanDeviceLogic as FanControlHooks>::CLUSTER.id,
                    Async(fan_control::HandlerAdaptor(FanControlHandler::new(
                        Dataver::new(3),
                        EP,
                        rs_matter::persist::VENDOR_KEYS_START,
                        logic,
                    ))),
                    EmptyHandler,
                ),
            ),
        ),
    )
}

/// Write one attribute and expect one status back.
fn write(
    runner: &E2eRunner<impl rs_matter::crypto::Crypto>,
    dm: &impl DataModel,
    id: AttributeId,
    value: &dyn crate::common::e2e::tlv::TestToTLV,
    expected: IMStatusCode,
) {
    let path = attr(id);

    runner.handle_write_reqs(
        dm,
        &[TestAttrData::new(None, AttrPath::from_gp(&path), value)],
        &[AttrStatus::from_gp(&path, expected, None)],
    );
}

/// Read one attribute and expect one value back.
fn expect_read(
    runner: &E2eRunner<impl rs_matter::crypto::Crypto>,
    dm: &impl DataModel,
    id: AttributeId,
    value: &dyn crate::common::e2e::tlv::TestToTLV,
) {
    let path = attr(id);

    runner.handle_read_reqs(
        dm,
        &[AttrPath::from_gp(&path)],
        &[TestAttrResp::data(&path, value)],
    );
}

/// Read the whole speed setting - `FanMode`, `PercentSetting`,
/// `SpeedSetting` - and what the fan is doing.
fn expect_setting(
    runner: &E2eRunner<impl rs_matter::crypto::Crypto>,
    dm: &impl DataModel,
    mode: FanModeEnum,
    percent: Option<u8>,
    speed: Option<u8>,
) {
    expect_read(runner, dm, AttributeId::FanMode, &mode);
    expect_read(
        runner,
        dm,
        AttributeId::PercentSetting,
        &Nullable::new(percent),
    );
    expect_read(runner, dm, AttributeId::SpeedSetting, &Nullable::new(speed));
}

/// A fan that has never been touched: off, with the fixed attributes as the
/// device logic declares them.
#[test]
fn test_initial_attributes() {
    let (runner, logic) = fan();
    let dm = data_model(&logic);

    expect_setting(&runner, &dm, FanModeEnum::Off, Some(0), Some(0));
    expect_read(
        &runner,
        &dm,
        AttributeId::FanModeSequence,
        &FanModeSequenceEnum::OffLowMedHighAuto,
    );
    expect_read(&runner, &dm, AttributeId::PercentCurrent, &0u8);
    expect_read(&runner, &dm, AttributeId::SpeedMax, &10u8);
    expect_read(&runner, &dm, AttributeId::SpeedCurrent, &0u8);
    expect_read(
        &runner,
        &dm,
        AttributeId::RockSupport,
        &(RockBitmap::ROCK_LEFT_RIGHT | RockBitmap::ROCK_UP_DOWN),
    );
    expect_read(&runner, &dm, AttributeId::RockSetting, &RockBitmap::empty());
    expect_read(
        &runner,
        &dm,
        AttributeId::WindSupport,
        &WindBitmap::NATURAL_WIND,
    );
    expect_read(&runner, &dm, AttributeId::WindSetting, &WindBitmap::empty());
    expect_read(
        &runner,
        &dm,
        AttributeId::AirflowDirection,
        &AirflowDirectionEnum::Forward,
    );
}

/// A `PercentSetting` write lands verbatim, and the mode and speed follow;
/// the fan reaches it at once, so the current values follow too.
#[test]
fn test_percent_setting_write_cascades() {
    let (runner, logic) = fan();
    let dm = data_model(&logic);

    write(
        &runner,
        &dm,
        AttributeId::PercentSetting,
        &Nullable::some(64u8),
        IMStatusCode::Success,
    );

    expect_setting(&runner, &dm, FanModeEnum::Medium, Some(64), Some(7));
    expect_read(&runner, &dm, AttributeId::PercentCurrent, &64u8);
    expect_read(&runner, &dm, AttributeId::SpeedCurrent, &7u8);

    // Out of range.
    write(
        &runner,
        &dm,
        AttributeId::PercentSetting,
        &Nullable::some(101u8),
        IMStatusCode::ConstraintError,
    );
    expect_read(
        &runner,
        &dm,
        AttributeId::PercentSetting,
        &Nullable::some(64u8),
    );
}

/// A `SpeedSetting` write reads back unchanged, with the percentage it maps
/// to, and one above `SpeedMax` is a `CONSTRAINT_ERROR`.
#[test]
fn test_speed_setting_write_cascades() {
    let (runner, logic) = fan();
    let dm = data_model(&logic);

    write(
        &runner,
        &dm,
        AttributeId::SpeedSetting,
        &Nullable::some(3u8),
        IMStatusCode::Success,
    );
    expect_setting(&runner, &dm, FanModeEnum::Low, Some(30), Some(3));

    write(
        &runner,
        &dm,
        AttributeId::SpeedSetting,
        &Nullable::some(11u8),
        IMStatusCode::ConstraintError,
    );
    expect_read(
        &runner,
        &dm,
        AttributeId::SpeedSetting,
        &Nullable::some(3u8),
    );
}

/// A `FanMode` write sets the percentage and speed of the mode; `Off` zeroes
/// everything, `Auto` nulls the settings, and the deprecated `On` is `High`.
#[test]
fn test_fan_mode_write_cascades() {
    let (runner, logic) = fan();
    let dm = data_model(&logic);

    write(
        &runner,
        &dm,
        AttributeId::FanMode,
        &FanModeEnum::On,
        IMStatusCode::Success,
    );
    expect_setting(&runner, &dm, FanModeEnum::High, Some(100), Some(10));
    expect_read(&runner, &dm, AttributeId::PercentCurrent, &100u8);

    write(
        &runner,
        &dm,
        AttributeId::FanMode,
        &FanModeEnum::Auto,
        IMStatusCode::Success,
    );
    expect_setting(&runner, &dm, FanModeEnum::Auto, None, None);
    expect_read(
        &runner,
        &dm,
        AttributeId::SpeedCurrent,
        &fan_control::test::AUTO_SPEED,
    );

    write(
        &runner,
        &dm,
        AttributeId::FanMode,
        &FanModeEnum::Off,
        IMStatusCode::Success,
    );
    expect_setting(&runner, &dm, FanModeEnum::Off, Some(0), Some(0));
    expect_read(&runner, &dm, AttributeId::PercentCurrent, &0u8);
    expect_read(&runner, &dm, AttributeId::SpeedCurrent, &0u8);
}

/// Null is what `Auto` sets, not something a client can ask for: writing it
/// is `INVALID_IN_STATE` unless the fan is in `Auto` already.
#[test]
fn test_null_setting_write() {
    let (runner, logic) = fan();
    let dm = data_model(&logic);

    write(
        &runner,
        &dm,
        AttributeId::PercentSetting,
        &Nullable::some(50u8),
        IMStatusCode::Success,
    );

    write(
        &runner,
        &dm,
        AttributeId::PercentSetting,
        &Nullable::<u8>::none(),
        IMStatusCode::InvalidInState,
    );
    write(
        &runner,
        &dm,
        AttributeId::SpeedSetting,
        &Nullable::<u8>::none(),
        IMStatusCode::InvalidInState,
    );
    expect_read(
        &runner,
        &dm,
        AttributeId::PercentSetting,
        &Nullable::some(50u8),
    );

    write(
        &runner,
        &dm,
        AttributeId::FanMode,
        &FanModeEnum::Auto,
        IMStatusCode::Success,
    );
    write(
        &runner,
        &dm,
        AttributeId::PercentSetting,
        &Nullable::<u8>::none(),
        IMStatusCode::Success,
    );
    write(
        &runner,
        &dm,
        AttributeId::SpeedSetting,
        &Nullable::<u8>::none(),
        IMStatusCode::Success,
    );
}

/// A fan that cannot switch right now answers `INVALID_IN_STATE` and keeps
/// its setting.
#[test]
fn test_refused_setting_is_invalid_in_state() {
    let (runner, logic) = fan();
    let dm = data_model(&logic);

    write(
        &runner,
        &dm,
        AttributeId::PercentSetting,
        &Nullable::some(50u8),
        IMStatusCode::Success,
    );

    logic.refuse(true);

    write(
        &runner,
        &dm,
        AttributeId::PercentSetting,
        &Nullable::some(80u8),
        IMStatusCode::InvalidInState,
    );
    expect_setting(&runner, &dm, FanModeEnum::Medium, Some(50), Some(5));
}

/// A rocking or wind bit outside the support bitmap is a `CONSTRAINT_ERROR`,
/// and a combination the fan cannot do is reduced to its lowest bit.
#[test]
fn test_rock_and_wind_setting_writes() {
    let (runner, logic) = fan();
    let dm = data_model(&logic);

    write(
        &runner,
        &dm,
        AttributeId::RockSetting,
        &RockBitmap::ROCK_ROUND,
        IMStatusCode::ConstraintError,
    );
    write(
        &runner,
        &dm,
        AttributeId::WindSetting,
        &WindBitmap::SLEEP_WIND,
        IMStatusCode::ConstraintError,
    );

    write(
        &runner,
        &dm,
        AttributeId::RockSetting,
        &(RockBitmap::ROCK_LEFT_RIGHT | RockBitmap::ROCK_UP_DOWN),
        IMStatusCode::Success,
    );
    expect_read(
        &runner,
        &dm,
        AttributeId::RockSetting,
        &RockBitmap::ROCK_LEFT_RIGHT,
    );
    assert_eq!(logic.rock(), RockBitmap::ROCK_LEFT_RIGHT);

    write(
        &runner,
        &dm,
        AttributeId::WindSetting,
        &WindBitmap::NATURAL_WIND,
        IMStatusCode::Success,
    );
    expect_read(
        &runner,
        &dm,
        AttributeId::WindSetting,
        &WindBitmap::NATURAL_WIND,
    );

    write(
        &runner,
        &dm,
        AttributeId::AirflowDirection,
        &AirflowDirectionEnum::Reverse,
        IMStatusCode::Success,
    );
    expect_read(
        &runner,
        &dm,
        AttributeId::AirflowDirection,
        &AirflowDirectionEnum::Reverse,
    );
    assert_eq!(logic.direction(), AirflowDirectionEnum::Reverse);
}

/// `Step` moves one speed at a time, with the spec's fallbacks for the
/// optional fields: no wrap, and Off is a step.
#[test]
fn test_step_command() {
    let (runner, logic) = fan();
    let dm = data_model(&logic);

    let invoke = |req: TestStepReq| {
        runner.handle_commands(
            &dm,
            &[TestCmdData::new(step(), &req)],
            &[TestCmdResp::Status(CmdStatus::new(
                step(),
                IMStatusCode::Success,
                None,
                None,
            ))],
        );
    };

    write(
        &runner,
        &dm,
        AttributeId::PercentSetting,
        &Nullable::some(50u8),
        IMStatusCode::Success,
    );

    invoke(TestStepReq {
        direction: StepDirectionEnum::Increase,
        wrap: None,
        lowest_off: None,
    });
    expect_setting(&runner, &dm, FanModeEnum::Medium, Some(60), Some(6));
    expect_read(&runner, &dm, AttributeId::PercentCurrent, &60u8);

    // Down to speed 5, 4, ... and, with Off a step, all the way to 0.
    for speed in (0..=5u8).rev() {
        invoke(TestStepReq {
            direction: StepDirectionEnum::Decrease,
            wrap: Some(false),
            lowest_off: Some(true),
        });
        expect_read(
            &runner,
            &dm,
            AttributeId::SpeedSetting,
            &Nullable::some(speed),
        );
    }

    // Held at Off without wrap; wrapped to the top with it.
    invoke(TestStepReq {
        direction: StepDirectionEnum::Decrease,
        wrap: Some(false),
        lowest_off: Some(true),
    });
    expect_setting(&runner, &dm, FanModeEnum::Off, Some(0), Some(0));

    invoke(TestStepReq {
        direction: StepDirectionEnum::Decrease,
        wrap: Some(true),
        lowest_off: Some(true),
    });
    expect_setting(&runner, &dm, FanModeEnum::High, Some(100), Some(10));
}
