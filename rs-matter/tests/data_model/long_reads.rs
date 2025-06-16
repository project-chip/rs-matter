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

use rs_matter::dm::clusters::{
    acl, adm_comm, basic_info, desc, gen_comm, gen_diag, grp_key_mgmt, net_comm, noc, on_off,
};
use rs_matter::dm::GlobalElements;
use rs_matter::im::core::IMStatusCode;
use rs_matter::im::messages::ib::AttrPath;
use rs_matter::im::messages::msg::{StatusResp, SubscribeResp};
use rs_matter::im::messages::GenericPath;

use crate::attr_data;
use crate::common::e2e::im::attributes::TestAttrResp;
use crate::common::e2e::im::{echo_cluster as echo, ReplyProcessor, TestSubscribeReq};
use crate::common::e2e::im::{TestReadReq, TestReportDataMsg};
use crate::common::e2e::test::E2eTest;
use crate::common::e2e::tlv::TLVTest;
use crate::common::e2e::ImEngine;
use crate::common::init_env_logger;

static ATTR_RESPS: &[TestAttrResp<'static>] = &[
    attr_data!(0, 29, desc::AttributeId::DeviceTypeList, None),
    attr_data!(0, 29, desc::AttributeId::ServerList, None),
    attr_data!(0, 29, desc::AttributeId::ClientList, None),
    attr_data!(0, 29, desc::AttributeId::PartsList, None),
    attr_data!(0, 29, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 29, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 29, GlobalElements::EventList, None),
    attr_data!(0, 29, GlobalElements::AttributeList, None),
    attr_data!(0, 29, GlobalElements::FeatureMap, None),
    attr_data!(0, 29, GlobalElements::ClusterRevision, None),
    attr_data!(0, 31, acl::AttributeId::Acl, None),
    attr_data!(0, 31, acl::AttributeId::SubjectsPerAccessControlEntry, None),
    attr_data!(0, 31, acl::AttributeId::TargetsPerAccessControlEntry, None),
    attr_data!(0, 31, acl::AttributeId::AccessControlEntriesPerFabric, None),
    attr_data!(0, 31, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 31, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 31, GlobalElements::EventList, None),
    attr_data!(0, 31, GlobalElements::AttributeList, None),
    attr_data!(0, 31, GlobalElements::FeatureMap, None),
    attr_data!(0, 31, GlobalElements::ClusterRevision, None),
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
    attr_data!(0, 40, GlobalElements::EventList, None),
    attr_data!(0, 40, GlobalElements::AttributeList, None),
    attr_data!(0, 40, GlobalElements::FeatureMap, None),
    attr_data!(0, 40, GlobalElements::ClusterRevision, None),
    attr_data!(0, 48, gen_comm::AttributeId::Breadcrumb, None),
    attr_data!(0, 48, gen_comm::AttributeId::BasicCommissioningInfo, None),
    attr_data!(0, 48, gen_comm::AttributeId::RegulatoryConfig, None),
    attr_data!(0, 48, gen_comm::AttributeId::LocationCapability, None),
    attr_data!(
        0,
        48,
        gen_comm::AttributeId::SupportsConcurrentConnection,
        None
    ),
    attr_data!(0, 48, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 48, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 48, GlobalElements::EventList, None),
    attr_data!(0, 48, GlobalElements::AttributeList, None),
    attr_data!(0, 48, GlobalElements::FeatureMap, None),
    attr_data!(0, 48, GlobalElements::ClusterRevision, None),
    attr_data!(0, 51, gen_diag::AttributeId::NetworkInterfaces, None),
    attr_data!(0, 51, gen_diag::AttributeId::RebootCount, None),
    attr_data!(0, 51, gen_diag::AttributeId::TestEventTriggersEnabled, None),
    attr_data!(0, 51, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 51, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 51, GlobalElements::EventList, None),
    attr_data!(0, 51, GlobalElements::AttributeList, None),
    attr_data!(0, 51, GlobalElements::FeatureMap, None),
    attr_data!(0, 51, GlobalElements::ClusterRevision, None),
    attr_data!(0, 60, adm_comm::AttributeId::WindowStatus, None),
    attr_data!(0, 60, adm_comm::AttributeId::AdminFabricIndex, None),
    attr_data!(0, 60, adm_comm::AttributeId::AdminVendorId, None),
    attr_data!(0, 60, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 60, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 60, GlobalElements::EventList, None),
    attr_data!(0, 60, GlobalElements::AttributeList, None),
    attr_data!(0, 60, GlobalElements::FeatureMap, None),
    attr_data!(0, 60, GlobalElements::ClusterRevision, None),
    attr_data!(0, 62, noc::AttributeId::NOCs, None),
    attr_data!(0, 62, noc::AttributeId::Fabrics, None),
    attr_data!(0, 62, noc::AttributeId::SupportedFabrics, None),
    attr_data!(0, 62, noc::AttributeId::CommissionedFabrics, None),
    attr_data!(0, 62, noc::AttributeId::TrustedRootCertificates, None),
    attr_data!(0, 62, noc::AttributeId::CurrentFabricIndex, None),
    attr_data!(0, 62, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 62, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 62, GlobalElements::EventList, None),
    attr_data!(0, 62, GlobalElements::AttributeList, None),
    attr_data!(0, 62, GlobalElements::FeatureMap, None),
    attr_data!(0, 62, GlobalElements::ClusterRevision, None),
    attr_data!(0, 63, grp_key_mgmt::AttributeId::GroupKeyMap, None),
    attr_data!(0, 63, grp_key_mgmt::AttributeId::GroupTable, None),
    attr_data!(0, 63, grp_key_mgmt::AttributeId::MaxGroupsPerFabric, None),
    attr_data!(
        0,
        63,
        grp_key_mgmt::AttributeId::MaxGroupKeysPerFabric,
        None
    ),
    attr_data!(0, 63, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 63, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 63, GlobalElements::EventList, None),
    attr_data!(0, 63, GlobalElements::AttributeList, None),
    attr_data!(0, 63, GlobalElements::FeatureMap, None),
    attr_data!(0, 63, GlobalElements::ClusterRevision, None),
    attr_data!(0, 49, net_comm::AttributeId::MaxNetworks, None),
    attr_data!(0, 49, net_comm::AttributeId::Networks, None),
    attr_data!(0, 49, net_comm::AttributeId::InterfaceEnabled, None),
    attr_data!(0, 49, net_comm::AttributeId::LastNetworkingStatus, None),
    attr_data!(0, 49, net_comm::AttributeId::LastNetworkID, None),
    attr_data!(0, 49, net_comm::AttributeId::LastConnectErrorValue, None),
    attr_data!(0, 49, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 49, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 49, GlobalElements::EventList, None),
    attr_data!(0, 49, GlobalElements::AttributeList, None),
    attr_data!(0, 49, GlobalElements::FeatureMap, None),
    attr_data!(0, 49, GlobalElements::ClusterRevision, None),
    attr_data!(0, 55, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, 55, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, 55, GlobalElements::EventList, None),
    attr_data!(0, 55, GlobalElements::AttributeList, None),
    attr_data!(0, 55, GlobalElements::FeatureMap, None),
    attr_data!(0, 55, GlobalElements::ClusterRevision, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att1, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att2, None),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::AttCustom, None),
    attr_data!(0, echo::ID, GlobalElements::GeneratedCmdList, None),
    attr_data!(0, echo::ID, GlobalElements::AcceptedCmdList, None),
    attr_data!(0, echo::ID, GlobalElements::EventList, None),
    attr_data!(0, echo::ID, GlobalElements::AttributeList, None),
    attr_data!(0, echo::ID, GlobalElements::FeatureMap, None),
    attr_data!(0, echo::ID, GlobalElements::ClusterRevision, None),
    attr_data!(1, 29, desc::AttributeId::DeviceTypeList, None),
    attr_data!(1, 29, desc::AttributeId::ServerList, None),
    attr_data!(1, 29, desc::AttributeId::ClientList, None),
    attr_data!(1, 29, desc::AttributeId::PartsList, None),
    attr_data!(1, 29, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, 29, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, 29, GlobalElements::EventList, None),
    attr_data!(1, 29, GlobalElements::AttributeList, None),
    attr_data!(1, 29, GlobalElements::FeatureMap, None),
    attr_data!(1, 29, GlobalElements::ClusterRevision, None),
    attr_data!(1, 6, on_off::AttributeId::OnOff, None),
    attr_data!(1, 6, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, 6, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, 6, GlobalElements::EventList, None),
    attr_data!(1, 6, GlobalElements::AttributeList, None),
    attr_data!(1, 6, GlobalElements::FeatureMap, None),
    attr_data!(1, 6, GlobalElements::ClusterRevision, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att1, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att2, None),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::AttCustom, None),
    attr_data!(1, echo::ID, GlobalElements::GeneratedCmdList, None),
    attr_data!(1, echo::ID, GlobalElements::AcceptedCmdList, None),
    attr_data!(1, echo::ID, GlobalElements::EventList, None),
    attr_data!(1, echo::ID, GlobalElements::AttributeList, None),
    attr_data!(1, echo::ID, GlobalElements::FeatureMap, None),
    attr_data!(1, echo::ID, GlobalElements::ClusterRevision, None),
];

#[test]
fn test_long_read_success() {
    const PART_1: usize = 38;
    const PART_2: usize = 37;
    const PART_3: usize = 37;

    // Read the entire attribute database, which requires 3 reads to complete
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
                    attr_reports: Some(&ATTR_RESPS[..PART_1]),
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
                    attr_reports: Some(&ATTR_RESPS[PART_1..][..PART_2]),
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
                    attr_reports: Some(&ATTR_RESPS[PART_1..][PART_2..][..PART_3]),
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
                    attr_reports: Some(&ATTR_RESPS[PART_1..][PART_2..][PART_3..]),
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
    const PART_1: usize = 38;
    const PART_2: usize = 37;
    const PART_3: usize = 37;

    // Subscribe to the entire attribute database, which requires 3 reads to complete
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
                    attr_reports: Some(&ATTR_RESPS[..PART_1]),
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
                    attr_reports: Some(&ATTR_RESPS[PART_1..][..PART_2]),
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
                    attr_reports: Some(&ATTR_RESPS[PART_1..][PART_2..][..PART_3]),
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
                    attr_reports: Some(&ATTR_RESPS[PART_1..][PART_2..][PART_3..]),
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
