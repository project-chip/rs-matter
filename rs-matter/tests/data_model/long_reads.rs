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

use rs_matter::data_model::objects::GlobalElements;
use rs_matter::data_model::sdm::{
    admin_commissioning as adm_comm, general_commissioning as gen_comm, noc, nw_commissioning,
};
use rs_matter::data_model::system_model::{access_control as acl, descriptor};
use rs_matter::data_model::{cluster_basic_information as basic_info, cluster_on_off as onoff};
use rs_matter::interaction_model::core::IMStatusCode;
use rs_matter::interaction_model::messages::ib::AttrPath;
use rs_matter::interaction_model::messages::msg::{StatusResp, SubscribeResp};
use rs_matter::interaction_model::messages::GenericPath;

use crate::attr_data;
use crate::common::e2e::im::attributes::TestAttrResp;
use crate::common::e2e::im::{echo_cluster as echo, ReplyProcessor, TestSubscribeReq};
use crate::common::e2e::im::{TestReadReq, TestReportDataMsg};
use crate::common::e2e::test::E2eTest;
use crate::common::e2e::tlv::TLVTest;
use crate::common::e2e::ImEngine;
use crate::common::init_env_logger;

static PART_1: &[TestAttrResp<'static>] = &[
    attr_data!(0, 29, descriptor::Attributes::DeviceTypeList, None),
    attr_data!(0, 29, descriptor::Attributes::ServerList, None),
    attr_data!(0, 29, descriptor::Attributes::PartsList, None),
    attr_data!(0, 29, descriptor::Attributes::ClientList, None),
    attr_data!(0, 29, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 29, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 29, GlobalElements::AttributeList, None),
    attr_data!(0, 29, GlobalElements::FeatureMap, None),
    attr_data!(0, 29, GlobalElements::ClusterRevision, None),
    attr_data!(0, 40, basic_info::AttributeId::DataModelRevision, None),
    attr_data!(0, 40, basic_info::AttributeId::VendorName, None),
    attr_data!(0, 40, basic_info::AttributeId::VendorID, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductName, None),
    attr_data!(0, 40, basic_info::AttributeId::ProductID, None),
    attr_data!(0, 40, basic_info::AttributeId::NodeLabel, None),
    attr_data!(0, 40, basic_info::AttributeId::Location, None),
    attr_data!(0, 40, basic_info::AttributeId::HardwareVersion, None),
    attr_data!(0, 40, basic_info::AttributeId::HardwareVersionString, None),
    attr_data!(0, 40, basic_info::AttributeId::SoftwareVersion, None),
    attr_data!(0, 40, basic_info::AttributeId::SoftwareVersionString, None),
    attr_data!(0, 40, basic_info::AttributeId::SerialNumber, None),
    attr_data!(0, 40, basic_info::AttributeId::CapabilityMinima, None),
    attr_data!(0, 40, basic_info::AttributeId::SpecificationVersion, None),
    attr_data!(0, 40, basic_info::AttributeId::MaxPathsPerInvoke, None),
    attr_data!(0, 40, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 40, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 40, GlobalElements::AttributeList, None),
    attr_data!(0, 40, GlobalElements::FeatureMap, None),
    attr_data!(0, 40, GlobalElements::ClusterRevision, None),
    attr_data!(0, 48, gen_comm::AttributeId::Breadcrumb, None),
    attr_data!(0, 48, gen_comm::AttributeId::RegulatoryConfig, None),
    attr_data!(0, 48, gen_comm::AttributeId::LocationCapability, None),
    attr_data!(0, 48, gen_comm::AttributeId::BasicCommissioningInfo, None),
    attr_data!(
        0,
        48,
        gen_comm::AttributeId::SupportsConcurrentConnection,
        None
    ),
    attr_data!(0, 48, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 48, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 48, GlobalElements::AttributeList, None),
];

static PART_2: &[TestAttrResp<'static>] = &[
    attr_data!(0, 48, GlobalElements::FeatureMap, None),
    attr_data!(0, 48, GlobalElements::ClusterRevision, None),
    attr_data!(0, 49, nw_commissioning::Attributes::MaxNetworks, None),
    attr_data!(0, 49, nw_commissioning::Attributes::Networks, None),
    attr_data!(
        0,
        49,
        nw_commissioning::Attributes::ConnectMaxTimeSecs,
        None
    ),
    attr_data!(0, 49, nw_commissioning::Attributes::InterfaceEnabled, None),
    attr_data!(
        0,
        49,
        nw_commissioning::Attributes::LastNetworkingStatus,
        None
    ),
    attr_data!(0, 49, nw_commissioning::Attributes::LastNetworkID, None),
    attr_data!(
        0,
        49,
        nw_commissioning::Attributes::LastConnectErrorValue,
        None
    ),
    attr_data!(0, 49, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 49, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 49, GlobalElements::AttributeList, None),
    attr_data!(0, 49, GlobalElements::FeatureMap, None),
    attr_data!(0, 49, GlobalElements::ClusterRevision, None),
    attr_data!(0, 60, adm_comm::AttributesDiscriminants::WindowStatus, None),
    attr_data!(
        0,
        60,
        adm_comm::AttributesDiscriminants::AdminFabricIndex,
        None
    ),
    attr_data!(
        0,
        60,
        adm_comm::AttributesDiscriminants::AdminVendorId,
        None
    ),
    attr_data!(0, 60, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 60, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 60, GlobalElements::AttributeList, None),
    attr_data!(0, 60, GlobalElements::FeatureMap, None),
    attr_data!(0, 60, GlobalElements::ClusterRevision, None),
    attr_data!(
        0,
        62,
        noc::AttributesDiscriminants::CurrentFabricIndex,
        None
    ),
    attr_data!(0, 62, noc::AttributesDiscriminants::Fabrics, None),
    attr_data!(0, 62, noc::AttributesDiscriminants::SupportedFabrics, None),
    attr_data!(
        0,
        62,
        noc::AttributesDiscriminants::CommissionedFabrics,
        None
    ),
    attr_data!(0, 62, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 62, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 62, GlobalElements::AttributeList, None),
    attr_data!(0, 62, GlobalElements::FeatureMap, None),
    attr_data!(0, 62, GlobalElements::ClusterRevision, None),
    attr_data!(0, 31, acl::AttributesDiscriminants::Acl, None),
    attr_data!(0, 31, acl::AttributesDiscriminants::Extension, None),
    attr_data!(0, 31, acl::AttributesDiscriminants::SubjectsPerEntry, None),
    attr_data!(0, 31, acl::AttributesDiscriminants::TargetsPerEntry, None),
    attr_data!(0, 31, acl::AttributesDiscriminants::EntriesPerFabric, None),
    attr_data!(0, 31, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 31, GlobalElements::AcceptedCmdList, None),
];

static PART_3: &[TestAttrResp<'static>] = &[
    attr_data!(0, 31, GlobalElements::AttributeList, None),
    attr_data!(0, 31, GlobalElements::FeatureMap, None),
    attr_data!(0, 31, GlobalElements::ClusterRevision, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att1, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att2, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::AttCustom, None),
    attr_data!(0, echo::ID, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, echo::ID, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, echo::ID, GlobalElements::AttributeList, None),
    attr_data!(0, echo::ID, GlobalElements::FeatureMap, None),
    attr_data!(0, echo::ID, GlobalElements::ClusterRevision, None),
    attr_data!(1, 29, descriptor::Attributes::DeviceTypeList, None),
    attr_data!(1, 29, descriptor::Attributes::ServerList, None),
    attr_data!(1, 29, descriptor::Attributes::PartsList, None),
    attr_data!(1, 29, descriptor::Attributes::ClientList, None),
    attr_data!(1, 29, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, 29, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, 29, GlobalElements::AttributeList, None),
    attr_data!(1, 29, GlobalElements::FeatureMap, None),
    attr_data!(1, 29, GlobalElements::ClusterRevision, None),
    attr_data!(1, 6, onoff::AttributeId::OnOff, None),
    attr_data!(1, 6, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, 6, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, 6, GlobalElements::AttributeList, None),
    attr_data!(1, 6, GlobalElements::FeatureMap, None),
    attr_data!(1, 6, GlobalElements::ClusterRevision, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att1, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att2, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::AttCustom, None),
    attr_data!(1, echo::ID, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, echo::ID, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, echo::ID, GlobalElements::AttributeList, None),
    attr_data!(1, echo::ID, GlobalElements::FeatureMap, None),
    attr_data!(1, echo::ID, GlobalElements::ClusterRevision, None),
];

#[test]
fn test_long_read_success() {
    // Read the entire attribute database, which requires 2 reads to complete
    init_env_logger();

    let im = ImEngine::new_default();
    let handler = im.handler();

    im.add_default_acl();

    im.test_all(
        &handler,
        [
            &TLVTest::read(
                TestReadReq::reqs(&[AttrPath::new(&GenericPath::new(None, None, None))]),
                TestReportDataMsg {
                    attr_reports: Some(PART_1),
                    more_chunks: Some(true),
                    ..Default::default()
                },
                ReplyProcessor::remove_attr_data,
            ) as &dyn E2eTest,
            &TLVTest::continue_report(
                StatusResp {
                    status: IMStatusCode::Success,
                },
                TestReportDataMsg {
                    attr_reports: Some(PART_2),
                    more_chunks: Some(true),
                    ..Default::default()
                },
                ReplyProcessor::remove_attr_data,
            ),
            &TLVTest::continue_report(
                StatusResp {
                    status: IMStatusCode::Success,
                },
                TestReportDataMsg {
                    attr_reports: Some(PART_3),
                    suppress_response: Some(true),
                    ..Default::default()
                },
                ReplyProcessor::remove_attr_data,
            ),
        ],
    );
}

#[test]
fn test_long_read_subscription_success() {
    // Subscribe to the entire attribute database, which requires 2 reads to complete
    init_env_logger();

    let im = ImEngine::new_default();
    let handler = im.handler();

    im.add_default_acl();

    im.test_all(
        &handler,
        [
            &TLVTest::subscribe(
                TestSubscribeReq {
                    min_int_floor: 1,
                    max_int_ceil: 10,
                    ..TestSubscribeReq::reqs(&[AttrPath::new(&GenericPath::new(None, None, None))])
                },
                TestReportDataMsg {
                    subscription_id: Some(1),
                    attr_reports: Some(PART_1),
                    more_chunks: Some(true),
                    ..Default::default()
                },
                ReplyProcessor::remove_attr_data,
            ) as &dyn E2eTest,
            &TLVTest::continue_report(
                StatusResp {
                    status: IMStatusCode::Success,
                },
                TestReportDataMsg {
                    subscription_id: Some(1),
                    attr_reports: Some(PART_2),
                    more_chunks: Some(true),
                    ..Default::default()
                },
                ReplyProcessor::remove_attr_data,
            ),
            &TLVTest::continue_report(
                StatusResp {
                    status: IMStatusCode::Success,
                },
                TestReportDataMsg {
                    subscription_id: Some(1),
                    attr_reports: Some(PART_3),
                    ..Default::default()
                },
                ReplyProcessor::remove_attr_data,
            ),
            &TLVTest::subscribe_final(
                StatusResp {
                    status: IMStatusCode::Success,
                },
                SubscribeResp {
                    subs_id: 1,
                    max_int: 40,
                    ..Default::default()
                },
                ReplyProcessor::none,
            ),
        ],
    );
}
