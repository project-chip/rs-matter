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

use matter::{
    data_model::{
        cluster_basic_information as basic_info, cluster_on_off as onoff,
        objects::{EncodeValue, GlobalElements},
        sdm::{admin_commissioning as adm_comm, general_commissioning as gen_comm, noc},
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
    mdns::DummyMdns,
    tlv::{self, ElementType, FromTLV, TLVElement, TagType, ToTLV},
    transport::{
        exchange::{self, Exchange},
        udp::MAX_RX_BUF_SIZE,
    },
    Matter,
};

use crate::{
    attr_data,
    common::{
        attributes::*,
        echo_cluster as echo,
        im_engine::{matter, ImEngine, ImInput},
    },
};

pub struct LongRead<'a> {
    im_engine: ImEngine<'a>,
}

impl<'a> LongRead<'a> {
    pub fn new(matter: &'a Matter<'a>) -> Self {
        let mut im_engine = ImEngine::new(matter);
        // Use the same exchange for all parts of the transaction
        im_engine.exch = Some(Exchange::new(1, 0, exchange::Role::Responder));
        Self { im_engine }
    }

    pub fn process<'p>(
        &mut self,
        action: OpCode,
        data: &dyn ToTLV,
        data_out: &'p mut [u8],
    ) -> (u8, &'p [u8]) {
        let input = ImInput::new(action, data);
        let (response, output) = self.im_engine.process(&input, data_out);
        (response, output)
    }
}

fn wildcard_read_resp(part: u8) -> Vec<AttrResp<'static>> {
    // For brevity, we only check the AttrPath, not the actual 'data'
    let dont_care = ElementType::U8(0);
    let part1 = vec![
        attr_data!(0, 29, GlobalElements::FeatureMap, dont_care),
        attr_data!(0, 29, GlobalElements::AttributeList, dont_care),
        attr_data!(0, 29, descriptor::Attributes::DeviceTypeList, dont_care),
        attr_data!(0, 29, descriptor::Attributes::ServerList, dont_care),
        attr_data!(0, 29, descriptor::Attributes::PartsList, dont_care),
        attr_data!(0, 29, descriptor::Attributes::ClientList, dont_care),
        attr_data!(0, 40, GlobalElements::FeatureMap, dont_care),
        attr_data!(0, 40, GlobalElements::AttributeList, dont_care),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::DMRevision,
            dont_care
        ),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::VendorId,
            dont_care
        ),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::ProductId,
            dont_care
        ),
        attr_data!(0, 40, basic_info::AttributesDiscriminants::HwVer, dont_care),
        attr_data!(0, 40, basic_info::AttributesDiscriminants::SwVer, dont_care),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::SwVerString,
            dont_care
        ),
        attr_data!(
            0,
            40,
            basic_info::AttributesDiscriminants::SerialNo,
            dont_care
        ),
        attr_data!(0, 48, GlobalElements::FeatureMap, dont_care),
        attr_data!(0, 48, GlobalElements::AttributeList, dont_care),
        attr_data!(
            0,
            48,
            gen_comm::AttributesDiscriminants::BreadCrumb,
            dont_care
        ),
        attr_data!(
            0,
            48,
            gen_comm::AttributesDiscriminants::RegConfig,
            dont_care
        ),
        attr_data!(
            0,
            48,
            gen_comm::AttributesDiscriminants::LocationCapability,
            dont_care
        ),
        attr_data!(
            0,
            48,
            gen_comm::AttributesDiscriminants::BasicCommissioningInfo,
            dont_care
        ),
        attr_data!(0, 49, GlobalElements::FeatureMap, dont_care),
        attr_data!(0, 49, GlobalElements::AttributeList, dont_care),
        attr_data!(0, 60, GlobalElements::FeatureMap, dont_care),
        attr_data!(0, 60, GlobalElements::AttributeList, dont_care),
        attr_data!(
            0,
            60,
            adm_comm::AttributesDiscriminants::WindowStatus,
            dont_care
        ),
        attr_data!(
            0,
            60,
            adm_comm::AttributesDiscriminants::AdminFabricIndex,
            dont_care
        ),
        attr_data!(
            0,
            60,
            adm_comm::AttributesDiscriminants::AdminVendorId,
            dont_care
        ),
        attr_data!(0, 62, GlobalElements::FeatureMap, dont_care),
        attr_data!(0, 62, GlobalElements::AttributeList, dont_care),
        attr_data!(
            0,
            62,
            noc::AttributesDiscriminants::CurrentFabricIndex,
            dont_care
        ),
        attr_data!(0, 62, noc::AttributesDiscriminants::Fabrics, dont_care),
        attr_data!(
            0,
            62,
            noc::AttributesDiscriminants::SupportedFabrics,
            dont_care
        ),
        attr_data!(
            0,
            62,
            noc::AttributesDiscriminants::CommissionedFabrics,
            dont_care
        ),
        attr_data!(0, 31, GlobalElements::FeatureMap, dont_care),
        attr_data!(0, 31, GlobalElements::AttributeList, dont_care),
        attr_data!(0, 31, acl::AttributesDiscriminants::Acl, dont_care),
        attr_data!(0, 31, acl::AttributesDiscriminants::Extension, dont_care),
        attr_data!(
            0,
            31,
            acl::AttributesDiscriminants::SubjectsPerEntry,
            dont_care
        ),
        attr_data!(
            0,
            31,
            acl::AttributesDiscriminants::TargetsPerEntry,
            dont_care
        ),
        attr_data!(
            0,
            31,
            acl::AttributesDiscriminants::EntriesPerFabric,
            dont_care
        ),
        attr_data!(0, echo::ID, GlobalElements::FeatureMap, dont_care),
        attr_data!(0, echo::ID, GlobalElements::AttributeList, dont_care),
        attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att1, dont_care),
        attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att2, dont_care),
        attr_data!(
            0,
            echo::ID,
            echo::AttributesDiscriminants::AttCustom,
            dont_care
        ),
        attr_data!(1, 29, GlobalElements::FeatureMap, dont_care),
        attr_data!(1, 29, GlobalElements::AttributeList, dont_care),
        attr_data!(1, 29, descriptor::Attributes::DeviceTypeList, dont_care),
    ];

    let part2 = vec![
        attr_data!(1, 29, descriptor::Attributes::ServerList, dont_care),
        attr_data!(1, 29, descriptor::Attributes::PartsList, dont_care),
        attr_data!(1, 29, descriptor::Attributes::ClientList, dont_care),
        attr_data!(1, 6, GlobalElements::FeatureMap, dont_care),
        attr_data!(1, 6, GlobalElements::AttributeList, dont_care),
        attr_data!(1, 6, onoff::AttributesDiscriminants::OnOff, dont_care),
        attr_data!(1, echo::ID, GlobalElements::FeatureMap, dont_care),
        attr_data!(1, echo::ID, GlobalElements::AttributeList, dont_care),
        attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att1, dont_care),
        attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att2, dont_care),
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
    let _ = env_logger::try_init();
    let mut mdns = DummyMdns;
    let matter = matter(&mut mdns);
    let mut lr = LongRead::new(&matter);
    let mut output = [0_u8; MAX_RX_BUF_SIZE + 100];

    let wc_path = GenericPath::new(None, None, None);

    let read_all = [AttrPath::new(&wc_path)];
    let read_req = ReadReq::new(true).set_attr_requests(&read_all);
    let expected_part1 = wildcard_read_resp(1);
    let (out_code, out_data) = lr.process(OpCode::ReadRequest, &read_req, &mut output);
    let root = tlv::get_root_node_struct(out_data).unwrap();
    let report_data = ReportDataMsg::from_tlv(&root).unwrap();
    assert_attr_report_skip_data(&report_data, &expected_part1);
    assert_eq!(report_data.more_chunks, Some(true));
    assert_eq!(out_code, OpCode::ReportData as u8);

    // Ask for the next read by sending a status report
    let status_report = StatusResp {
        status: IMStatusCode::Success,
    };
    let expected_part2 = wildcard_read_resp(2);
    let (out_code, out_data) = lr.process(OpCode::StatusResponse, &status_report, &mut output);
    let root = tlv::get_root_node_struct(out_data).unwrap();
    let report_data = ReportDataMsg::from_tlv(&root).unwrap();
    assert_attr_report_skip_data(&report_data, &expected_part2);
    assert_eq!(report_data.more_chunks, None);
    assert_eq!(out_code, OpCode::ReportData as u8);
}

#[test]
fn test_long_read_subscription_success() {
    // Subscribe to the entire attribute database, which requires 2 reads to complete
    let _ = env_logger::try_init();
    let mut mdns = DummyMdns;
    let matter = matter(&mut mdns);
    let mut lr = LongRead::new(&matter);
    let mut output = [0_u8; MAX_RX_BUF_SIZE + 100];

    let wc_path = GenericPath::new(None, None, None);

    let read_all = [AttrPath::new(&wc_path)];
    let subs_req = SubscribeReq::new(true, 1, 20).set_attr_requests(&read_all);
    let expected_part1 = wildcard_read_resp(1);
    let (out_code, out_data) = lr.process(OpCode::SubscribeRequest, &subs_req, &mut output);
    let root = tlv::get_root_node_struct(out_data).unwrap();
    let report_data = ReportDataMsg::from_tlv(&root).unwrap();
    assert_attr_report_skip_data(&report_data, &expected_part1);
    assert_eq!(report_data.more_chunks, Some(true));
    assert_eq!(out_code, OpCode::ReportData as u8);

    // Ask for the next read by sending a status report
    let status_report = StatusResp {
        status: IMStatusCode::Success,
    };
    let expected_part2 = wildcard_read_resp(2);
    let (out_code, out_data) = lr.process(OpCode::StatusResponse, &status_report, &mut output);
    let root = tlv::get_root_node_struct(out_data).unwrap();
    let report_data = ReportDataMsg::from_tlv(&root).unwrap();
    assert_attr_report_skip_data(&report_data, &expected_part2);
    assert_eq!(report_data.more_chunks, None);
    assert_eq!(out_code, OpCode::ReportData as u8);

    // Finally confirm subscription
    let (out_code, out_data) = lr.process(OpCode::StatusResponse, &status_report, &mut output);
    tlv::print_tlv_list(out_data);
    let root = tlv::get_root_node_struct(out_data).unwrap();
    let subs_resp = SubscribeResp::from_tlv(&root).unwrap();
    assert_eq!(out_code, OpCode::SubscribeResponse as u8);
    assert_eq!(subs_resp.subs_id, 1);
}
