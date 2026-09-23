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

//! Wire-level tests for the Thermostat cluster handler: the same rules the
//! unit tests in `dm::clusters::app::thermostat` cover, but driven over the
//! Interaction Model on the loopback runner, so that the `CONSTRAINT_ERROR` /
//! `INVALID_COMMAND` statuses are the ones a controller would actually read
//! back rather than the `Error` the helper returned.
//!
//! The upstream `TC_TSTAT_*` suites cover the same ground against the CHIP
//! certification harness (`cargo xtask itest --suite thermostat`), but those
//! only run where `.build/itest` has been set up; these run in ordinary CI.

use rs_matter::dm::clusters::app::thermostat::{
    self, test::TestThermostatDeviceLogic, AttributeId, CommandId, ControlSequenceOfOperationEnum,
    SetpointChangeSourceEnum, SetpointRaiseLowerModeEnum, SystemModeEnum, ThermostatHandler,
    ThermostatHooks,
};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _, DescHandler};
use rs_matter::dm::devices::{DEV_TYPE_ROOT_NODE, DEV_TYPE_THERMOSTAT};
use rs_matter::dm::{
    Async, ChainedHandler, Cluster, DataModel, Dataver, EmptyHandler, Endpoint, Node,
};
use rs_matter::im::{
    AttrPath, AttrStatus, CmdPath, CmdStatus, EventPath, EventPriority, GenericPath, IMStatusCode,
};
use rs_matter::tlv::{Nullable, TLVTag, ToTLV};

use crate::common::e2e::im::attributes::{TestAttrData, TestAttrResp};
use crate::common::e2e::im::commands::{TestCmdData, TestCmdResp};
use crate::common::e2e::tlv::TLVTest;
use crate::common::e2e::{new_default_runner, E2eRunner};
use crate::common::init_env_logger;
use crate::event_data;

/// The endpoint the thermostat lives on.
const EP: u16 = 1;

const CLUSTERS_EP0: &[Cluster<'static>] = &[DescHandler::CLUSTER];
const CLUSTERS_EP1: &[Cluster<'static>] = &[
    DescHandler::CLUSTER,
    <TestThermostatDeviceLogic as ThermostatHooks>::CLUSTER,
];

const NODE: Node<'static> = Node {
    endpoints: &[
        Endpoint::new(0, &[DEV_TYPE_ROOT_NODE], CLUSTERS_EP0),
        Endpoint::new(EP, &[DEV_TYPE_THERMOSTAT], CLUSTERS_EP1),
    ],
};

/// TLV mirror of `SetpointRaiseLowerRequest`: positional context tags 0..=1.
#[derive(Debug, Clone, PartialEq, ToTLV)]
struct TestSetpointRaiseLowerReq {
    mode: SetpointRaiseLowerModeEnum,
    amount: i8,
}

/// TLV mirror of the `SetpointChange` event payload.
///
/// Written by hand rather than derived because the `Occupancy` field at tag 1
/// is `[OCC]`, which this device does not implement, so the tags are 0, 2, 3.
#[derive(Debug)]
struct TestSetpointChange {
    system_mode: SystemModeEnum,
    previous_setpoint: i16,
    current_setpoint: i16,
}

impl crate::common::e2e::tlv::TestToTLV for TestSetpointChange {
    fn test_to_tlv(
        &self,
        tag: &TLVTag,
        tw: &mut rs_matter::utils::storage::WriteBuf<'_>,
    ) -> Result<(), rs_matter::error::Error> {
        use rs_matter::tlv::TLVWrite;

        tw.start_struct(tag)?;
        tw.u8(&TLVTag::Context(0), self.system_mode as u8)?;
        tw.i16(&TLVTag::Context(2), self.previous_setpoint)?;
        tw.i16(&TLVTag::Context(3), self.current_setpoint)?;
        tw.end_container()
    }
}

/// The path every event of this thermostat arrives on.
fn events_path() -> EventPath {
    EventPath {
        node: None,
        endpoint: Some(EP),
        cluster: Some(<TestThermostatDeviceLogic as ThermostatHooks>::CLUSTER.id),
        event: None,
        is_urgent: None,
    }
}

fn attr(attr: AttributeId) -> GenericPath {
    GenericPath::new(
        Some(EP),
        Some(<TestThermostatDeviceLogic as ThermostatHooks>::CLUSTER.id),
        Some(attr as u32),
    )
}

fn raise_lower() -> CmdPath {
    CmdPath::new(
        Some(EP),
        Some(<TestThermostatDeviceLogic as ThermostatHooks>::CLUSTER.id),
        Some(CommandId::SetpointRaiseLower as u32),
    )
}

/// A runner, and a data model with the reference thermostat on [`EP`].
fn thermostat() -> (
    E2eRunner<impl rs_matter::crypto::Crypto>,
    TestThermostatDeviceLogic,
) {
    init_env_logger();

    let runner = new_default_runner();
    runner.add_default_acl();

    (runner, TestThermostatDeviceLogic::new())
}

fn data_model(logic: &TestThermostatDeviceLogic) -> impl DataModel + '_ {
    (
        NODE,
        ChainedHandler::new(
            |e, c| e == 0 && c == DescHandler::CLUSTER.id,
            Async(DescHandler::new(Dataver::new(1)).adapt()),
            ChainedHandler::new(
                |e, c| e == EP && c == DescHandler::CLUSTER.id,
                Async(desc::HandlerAdaptor(DescHandler::new(Dataver::new(2)))),
                ChainedHandler::new(
                    |e, c| {
                        e == EP && c == <TestThermostatDeviceLogic as ThermostatHooks>::CLUSTER.id
                    },
                    Async(thermostat::HandlerAdaptor(ThermostatHandler::new(
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

/// An in-range write lands; an out-of-range one comes back as
/// `CONSTRAINT_ERROR` rather than being clamped.
#[test]
fn test_occupied_heating_setpoint_write() {
    let (runner, logic) = thermostat();
    let dm = data_model(&logic);

    expect_read(&runner, &dm, AttributeId::OccupiedHeatingSetpoint, &2000i16);

    write(
        &runner,
        &dm,
        AttributeId::OccupiedHeatingSetpoint,
        &2200i16,
        IMStatusCode::Success,
    );
    expect_read(&runner, &dm, AttributeId::OccupiedHeatingSetpoint, &2200i16);

    // Above `AbsMaxHeatSetpointLimit` and below `AbsMinHeatSetpointLimit`.
    for out_of_range in [9000i16, 100i16] {
        write(
            &runner,
            &dm,
            AttributeId::OccupiedHeatingSetpoint,
            &out_of_range,
            IMStatusCode::ConstraintError,
        );
    }

    expect_read(&runner, &dm, AttributeId::OccupiedHeatingSetpoint, &2200i16);
}

/// A limit write that conflicts with the setpoint drags it along; one that
/// conflicts with another *limit* is a `CONSTRAINT_ERROR`.
#[test]
fn test_setpoint_limit_writes() {
    let (runner, logic) = thermostat();
    let dm = data_model(&logic);

    write(
        &runner,
        &dm,
        AttributeId::MinHeatSetpointLimit,
        &2400i16,
        IMStatusCode::Success,
    );
    expect_read(&runner, &dm, AttributeId::OccupiedHeatingSetpoint, &2400i16);

    // Below `AbsMinHeatSetpointLimit` (700) and above `AbsMaxHeatSetpointLimit`
    // (3000): no setpoint adjustment can resolve either.
    write(
        &runner,
        &dm,
        AttributeId::MinHeatSetpointLimit,
        &600i16,
        IMStatusCode::ConstraintError,
    );
    write(
        &runner,
        &dm,
        AttributeId::MaxHeatSetpointLimit,
        &3100i16,
        IMStatusCode::ConstraintError,
    );
}

/// `SystemMode` is limited by `ControlSequenceOfOperation`, which for a
/// heating-only thermostat leaves `Off` and `Heat`.
#[test]
fn test_system_mode_write_is_limited_by_the_control_sequence() {
    let (runner, logic) = thermostat();
    let dm = data_model(&logic);

    for refused in [
        SystemModeEnum::Cool,
        SystemModeEnum::Auto,
        SystemModeEnum::Precooling,
        SystemModeEnum::FanOnly,
    ] {
        write(
            &runner,
            &dm,
            AttributeId::SystemMode,
            &refused,
            IMStatusCode::ConstraintError,
        );
    }

    write(
        &runner,
        &dm,
        AttributeId::SystemMode,
        &SystemModeEnum::Heat,
        IMStatusCode::Success,
    );
    expect_read(&runner, &dm, AttributeId::SystemMode, &SystemModeEnum::Heat);
}

/// A write is silently ignored, and silently means `SUCCESS` rather than
/// `UNSUPPORTED_WRITE` - a distinction only visible on the wire.
#[test]
fn test_control_sequence_of_operation_write_is_silently_ignored() {
    let (runner, logic) = thermostat();
    let dm = data_model(&logic);

    write(
        &runner,
        &dm,
        AttributeId::ControlSequenceOfOperation,
        &ControlSequenceOfOperationEnum::CoolingOnly,
        IMStatusCode::Success,
    );

    expect_read(
        &runner,
        &dm,
        AttributeId::ControlSequenceOfOperation,
        &ControlSequenceOfOperationEnum::HeatingOnly,
    );
}

/// The command clamps where an attribute write would error, and refuses a
/// `Mode` it has no setpoint for with `INVALID_COMMAND`.
#[test]
fn test_setpoint_raise_lower() {
    let (runner, logic) = thermostat();
    let dm = data_model(&logic);

    let invoke = |req: TestSetpointRaiseLowerReq, expected: IMStatusCode| {
        runner.handle_commands(
            &dm,
            &[TestCmdData::new(raise_lower(), &req)],
            &[TestCmdResp::Status(CmdStatus::new(
                raise_lower(),
                expected,
                None,
                None,
            ))],
        );
    };

    // `Amount` is in steps of 0.1degC, the attribute in 0.01degC.
    invoke(
        TestSetpointRaiseLowerReq {
            mode: SetpointRaiseLowerModeEnum::Heat,
            amount: 10,
        },
        IMStatusCode::Success,
    );
    expect_read(&runner, &dm, AttributeId::OccupiedHeatingSetpoint, &2100i16);

    // `Both` is accepted regardless of feature support and adjusts only the
    // setpoint the server has.
    invoke(
        TestSetpointRaiseLowerReq {
            mode: SetpointRaiseLowerModeEnum::Both,
            amount: -25,
        },
        IMStatusCode::Success,
    );
    expect_read(&runner, &dm, AttributeId::OccupiedHeatingSetpoint, &1850i16);

    // No COOL feature, so `Cool` is INVALID_COMMAND.
    invoke(
        TestSetpointRaiseLowerReq {
            mode: SetpointRaiseLowerModeEnum::Cool,
            amount: 10,
        },
        IMStatusCode::InvalidCommand,
    );
    expect_read(&runner, &dm, AttributeId::OccupiedHeatingSetpoint, &1850i16);

    // Out of range clamps rather than failing.
    invoke(
        TestSetpointRaiseLowerReq {
            mode: SetpointRaiseLowerModeEnum::Heat,
            amount: 127,
        },
        IMStatusCode::Success,
    );
    expect_read(&runner, &dm, AttributeId::OccupiedHeatingSetpoint, &3000i16);
}

/// A setpoint write produces a `SetpointChange` naming the value before and
/// after, with `SystemMode` = `Heat` because a *heating* setpoint moved - not
/// because of what the `SystemMode` attribute says.
#[test]
fn test_setpoint_change_event() {
    let (runner, logic) = thermostat();
    let dm = data_model(&logic);

    write(
        &runner,
        &dm,
        AttributeId::OccupiedHeatingSetpoint,
        &2200i16,
        IMStatusCode::Success,
    );

    runner.test_one(
        &dm,
        TLVTest::read_events(
            core::slice::from_ref(&events_path()),
            &[event_data!(
                EP,
                <TestThermostatDeviceLogic as ThermostatHooks>::CLUSTER.id,
                rs_matter::dm::clusters::app::thermostat::EventId::SetpointChange as u32,
                1,
                EventPriority::Info,
                Some(&TestSetpointChange {
                    system_mode: SystemModeEnum::Heat,
                    previous_setpoint: 2000,
                    current_setpoint: 2200,
                })
            )],
        ),
    );
}

/// A change that arrived over Matter is `External`, and carries the delta and
/// the timestamp the device's clock offered.
#[test]
fn test_setpoint_change_source_attributes_report_an_external_write() {
    let (runner, logic) = thermostat();
    let dm = data_model(&logic);

    write(
        &runner,
        &dm,
        AttributeId::OccupiedHeatingSetpoint,
        &2200i16,
        IMStatusCode::Success,
    );

    expect_read(
        &runner,
        &dm,
        AttributeId::SetpointChangeSource,
        &(SetpointChangeSourceEnum::External as u8),
    );
    expect_read(&runner, &dm, AttributeId::SetpointChangeAmount, &200i16);
    expect_read(
        &runner,
        &dm,
        AttributeId::SetpointChangeSourceTimestamp,
        &1000u32,
    );
}

/// The same three attributes before anything has moved: the XML defaults, with
/// a null amount because "the previous setpoint was unknown".
#[test]
fn test_setpoint_change_source_attributes_start_empty() {
    let (runner, logic) = thermostat();
    let dm = data_model(&logic);

    expect_read(
        &runner,
        &dm,
        AttributeId::SetpointChangeSource,
        &(SetpointChangeSourceEnum::Manual as u8),
    );
    expect_read(
        &runner,
        &dm,
        AttributeId::SetpointChangeAmount,
        &Nullable::<i16>::none(),
    );
    expect_read(
        &runner,
        &dm,
        AttributeId::SetpointChangeSourceTimestamp,
        &0u32,
    );
}
