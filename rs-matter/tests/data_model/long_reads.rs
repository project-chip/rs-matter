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

use rs_matter::{
    data_model::{
        cluster_basic_information as basic_info, cluster_on_off as onoff,
        objects::{EncodeValue, GlobalElements},
        sdm::{
            admin_commissioning as adm_comm, general_commissioning as gen_comm, noc,
            nw_commissioning,
        },
        system_model::{access_control as acl, descriptor},
    },
    interaction_model::{
        core::{IMStatusCode, OpCode},
        messages::{
            ib::{AttrData, AttrPath, AttrResp},
            msg::{ReadReq, ReportDataMsg, StatusResp, SubscribeResp},
        },
        messages::{msg::SubscribeReq, GenericPath},
    },
    tlv::{self, ElementType, FromTLV, TLVElement, TagType},
};

use crate::{
    attr_data,
    common::{
        attributes::*,
        echo_cluster as echo,
        im_engine::{ImEngine, ImInput},
        init_env_logger,
    },
};

fn wildcard_read_resp(part: u8) -> Vec<AttrResp<'static>> {
    // For brevity, we only check the AttrPath, not the actual 'data'
    let dont_care = ElementType::U8(0);
    let part1 = vec![
        attr_data!(0, 29, GlobalElements::FeatureMap, dont_care.clone()),
        attr_data!(0, 29, GlobalElements::AttributeList, dont_care.clone()),
        attr_data!(
            0,
            29,
            descriptor::Attributes::DeviceTypeList,
            dont_care.clone()
        ),
        attr_data!(0, 29, descriptor::Attributes::ServerList, dont_care.clone()),
        attr_data!(0, 29, descriptor::Attributes::PartsList, dont_care.clone()),
        attr_data!(0, 29, descriptor::Attributes::ClientList, dont_care.clone()),
        attr_data!(0, 40, GlobalElements::FeatureMap, dont_care.clone()),
        attr_data!(0, 40, GlobalElements::AttributeList, dont_care.clone()),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::DMRevision,
            dont_care.clone()
        ),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::VendorId,
            dont_care.clone()
        ),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::ProductId,
            dont_care.clone()
        ),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::HwVer,
            dont_care.clone()
        ),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::SwVer,
            dont_care.clone()
        ),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::SwVerString,
            dont_care.clone()
        ),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::SerialNo,
            dont_care.clone()
        ),
        attr_data!(0, 48, GlobalElements::FeatureMap, dont_care.clone()),
        attr_data!(0, 48, GlobalElements::AttributeList, dont_care.clone()),
        attr_data!(
            0,
            48,
            gen_comm::AttributesDiscriminants::BreadCrumb,
            dont_care.clone()
        ),
        attr_data!(
            0,
            48,
            gen_comm::AttributesDiscriminants::RegConfig,
            dont_care.clone()
        ),
        attr_data!(
            0,
            48,
            gen_comm::AttributesDiscriminants::LocationCapability,
            dont_care.clone()
        ),
        attr_data!(
            0,
            48,
            gen_comm::AttributesDiscriminants::BasicCommissioningInfo,
            dont_care.clone()
        ),
        attr_data!(0, 49, GlobalElements::FeatureMap, dont_care.clone()),
        attr_data!(0, 49, GlobalElements::AttributeList, dont_care.clone()),
        attr_data!(
            0,
            49,
            nw_commissioning::Attributes::MaxNetworks,
            dont_care.clone()
        ),
        attr_data!(
            0,
            49,
            nw_commissioning::Attributes::Networks,
            dont_care.clone()
        ),
        attr_data!(
            0,
            49,
            nw_commissioning::Attributes::ConnectMaxTimeSecs,
            dont_care.clone()
        ),
        attr_data!(
            0,
            49,
            nw_commissioning::Attributes::InterfaceEnabled,
            dont_care.clone()
        ),
        attr_data!(
            0,
            49,
            nw_commissioning::Attributes::LastNetworkingStatus,
            dont_care.clone()
        ),
        attr_data!(
            0,
            49,
            nw_commissioning::Attributes::LastNetworkID,
            dont_care.clone()
        ),
        attr_data!(
            0,
            49,
            nw_commissioning::Attributes::LastConnectErrorValue,
            dont_care.clone()
        ),
        attr_data!(0, 60, GlobalElements::FeatureMap, dont_care.clone()),
        attr_data!(0, 60, GlobalElements::AttributeList, dont_care.clone()),
        attr_data!(
            0,
            60,
            adm_comm::AttributesDiscriminants::WindowStatus,
            dont_care.clone()
        ),
        attr_data!(
            0,
            60,
            adm_comm::AttributesDiscriminants::AdminFabricIndex,
            dont_care.clone()
        ),
        attr_data!(
            0,
            60,
            adm_comm::AttributesDiscriminants::AdminVendorId,
            dont_care.clone()
        ),
        attr_data!(0, 62, GlobalElements::FeatureMap, dont_care.clone()),
        attr_data!(0, 62, GlobalElements::AttributeList, dont_care.clone()),
        attr_data!(
            0,
            62,
            noc::AttributesDiscriminants::CurrentFabricIndex,
            dont_care.clone()
        ),
    ];

    let part2 = vec![
        attr_data!(
            0,
            62,
            noc::AttributesDiscriminants::Fabrics,
            dont_care.clone()
        ),
        attr_data!(
            0,
            62,
            noc::AttributesDiscriminants::SupportedFabrics,
            dont_care.clone()
        ),
        attr_data!(
            0,
            62,
            noc::AttributesDiscriminants::CommissionedFabrics,
            dont_care.clone()
        ),
        attr_data!(0, 31, GlobalElements::FeatureMap, dont_care.clone()),
        attr_data!(0, 31, GlobalElements::AttributeList, dont_care.clone()),
        attr_data!(0, 31, acl::AttributesDiscriminants::Acl, dont_care.clone()),
        attr_data!(
            0,
            31,
            acl::AttributesDiscriminants::Extension,
            dont_care.clone()
        ),
        attr_data!(
            0,
            31,
            acl::AttributesDiscriminants::SubjectsPerEntry,
            dont_care.clone()
        ),
        attr_data!(
            0,
            31,
            acl::AttributesDiscriminants::TargetsPerEntry,
            dont_care.clone()
        ),
        attr_data!(
            0,
            31,
            acl::AttributesDiscriminants::EntriesPerFabric,
            dont_care.clone()
        ),
        attr_data!(0, echo::ID, GlobalElements::FeatureMap, dont_care.clone()),
        attr_data!(
            0,
            echo::ID,
            GlobalElements::AttributeList,
            dont_care.clone()
        ),
        attr_data!(
            0,
            echo::ID,
            echo::AttributesDiscriminants::Att1,
            dont_care.clone()
        ),
        attr_data!(
            0,
            echo::ID,
            echo::AttributesDiscriminants::Att2,
            dont_care.clone()
        ),
        attr_data!(
            0,
            echo::ID,
            echo::AttributesDiscriminants::AttCustom,
            dont_care.clone()
        ),
        attr_data!(1, 29, GlobalElements::FeatureMap, dont_care.clone()),
        attr_data!(1, 29, GlobalElements::AttributeList, dont_care.clone()),
        attr_data!(
            1,
            29,
            descriptor::Attributes::DeviceTypeList,
            dont_care.clone()
        ),
        attr_data!(1, 29, descriptor::Attributes::ServerList, dont_care.clone()),
        attr_data!(1, 29, descriptor::Attributes::PartsList, dont_care.clone()),
        attr_data!(1, 29, descriptor::Attributes::ClientList, dont_care.clone()),
        attr_data!(1, 6, GlobalElements::FeatureMap, dont_care.clone()),
        attr_data!(1, 6, GlobalElements::AttributeList, dont_care.clone()),
        attr_data!(
            1,
            6,
            onoff::AttributesDiscriminants::OnOff,
            dont_care.clone()
        ),
        attr_data!(1, echo::ID, GlobalElements::FeatureMap, dont_care.clone()),
        attr_data!(
            1,
            echo::ID,
            GlobalElements::AttributeList,
            dont_care.clone()
        ),
        attr_data!(
            1,
            echo::ID,
            echo::AttributesDiscriminants::Att1,
            dont_care.clone()
        ),
        attr_data!(
            1,
            echo::ID,
            echo::AttributesDiscriminants::Att2,
            dont_care.clone()
        ),
        attr_data!(
            1,
            echo::ID,
            echo::AttributesDiscriminants::AttCustom,
            dont_care
        ),
    ];

    if part == 1 {
        part1
    } else {
        part2
    }
}

#[test]
fn test_long_read_success() {
    // Read the entire attribute database, which requires 2 reads to complete
    init_env_logger();

    let mut out = heapless::Vec::<_, 3>::new();
    let im = ImEngine::new_default();
    let handler = im.handler();

    im.add_default_acl();

    let wc_path = GenericPath::new(None, None, None);

    let read_all = [AttrPath::new(&wc_path)];
    let read_req = ReadReq::new(true).set_attr_requests(&read_all);
    let expected_part1 = wildcard_read_resp(1);

    let status_report = StatusResp {
        status: IMStatusCode::Success,
    };
    let expected_part2 = wildcard_read_resp(2);

    im.process(
        &handler,
        &[
            &ImInput::new(OpCode::ReadRequest, &read_req),
            &ImInput::new(OpCode::StatusResponse, &status_report),
        ],
        &mut out,
    )
    .unwrap();

    assert_eq!(out.len(), 2);

    assert_eq!(out[0].action, OpCode::ReportData);

    let root = tlv::get_root_node_struct(&out[0].data).unwrap();
    let report_data = ReportDataMsg::from_tlv(&root).unwrap();
    assert_attr_report_skip_data(&report_data, &expected_part1);
    assert_eq!(report_data.more_chunks, Some(true));

    assert_eq!(out[1].action, OpCode::ReportData);

    let root = tlv::get_root_node_struct(&out[1].data).unwrap();
    let report_data = ReportDataMsg::from_tlv(&root).unwrap();
    assert_attr_report_skip_data(&report_data, &expected_part2);
    assert_eq!(report_data.more_chunks, None);
}

#[test]
fn test_long_read_subscription_success() {
    // Subscribe to the entire attribute database, which requires 2 reads to complete
    init_env_logger();

    let mut out = heapless::Vec::<_, 3>::new();
    let im = ImEngine::new_default();
    let handler = im.handler();

    im.add_default_acl();

    let wc_path = GenericPath::new(None, None, None);

    let read_all = [AttrPath::new(&wc_path)];
    let subs_req = SubscribeReq::new(true, 1, 20).set_attr_requests(&read_all);
    let expected_part1 = wildcard_read_resp(1);

    let status_report = StatusResp {
        status: IMStatusCode::Success,
    };
    let expected_part2 = wildcard_read_resp(2);

    im.process(
        &handler,
        &[
            &ImInput::new(OpCode::SubscribeRequest, &subs_req),
            &ImInput::new(OpCode::StatusResponse, &status_report),
            &ImInput::new(OpCode::StatusResponse, &status_report),
        ],
        &mut out,
    )
    .unwrap();

    assert_eq!(out.len(), 3);

    assert_eq!(out[0].action, OpCode::ReportData);

    let root = tlv::get_root_node_struct(&out[0].data).unwrap();
    let report_data = ReportDataMsg::from_tlv(&root).unwrap();
    assert_attr_report_skip_data(&report_data, &expected_part1);
    assert_eq!(report_data.more_chunks, Some(true));

    assert_eq!(out[1].action, OpCode::ReportData);

    let root = tlv::get_root_node_struct(&out[1].data).unwrap();
    let report_data = ReportDataMsg::from_tlv(&root).unwrap();
    assert_attr_report_skip_data(&report_data, &expected_part2);
    assert_eq!(report_data.more_chunks, None);

    assert_eq!(out[2].action, OpCode::SubscribeResponse);

    let root = tlv::get_root_node_struct(&out[2].data).unwrap();
    let subs_resp = SubscribeResp::from_tlv(&root).unwrap();
    assert_eq!(subs_resp.subs_id, 1);
}
