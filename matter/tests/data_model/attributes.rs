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
        cluster_on_off,
        objects::{EncodeValue, GlobalElements},
    },
    interaction_model::{
        core::IMStatusCode,
        messages::ib::{AttrData, AttrPath, AttrResp, AttrStatus},
        messages::GenericPath,
    },
    mdns::DummyMdns,
    tlv::{ElementType, TLVElement, TLVWriter, TagType},
};

use crate::{
    attr_data, attr_data_path, attr_status,
    common::{
        attributes::*,
        echo_cluster,
        im_engine::{matter, ImEngine},
        init_env_logger,
    },
};

#[test]
fn test_read_success() {
    // 3 Attr Read Requests
    // - first on endpoint 0, att1
    // - second on endpoint 1, att2
    // - third on endpoint 1, attcustom a custom attribute
    init_env_logger();

    let ep0_att1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );
    let ep1_att2 = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att2 as u32),
    );
    let ep1_attcustom = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttCustom as u32),
    );
    let input = &[
        AttrPath::new(&ep0_att1),
        AttrPath::new(&ep1_att2),
        AttrPath::new(&ep1_attcustom),
    ];
    let expected = &[
        attr_data_path!(ep0_att1, ElementType::U16(0x1234)),
        attr_data_path!(ep1_att2, ElementType::U16(0x5678)),
        attr_data_path!(
            ep1_attcustom,
            ElementType::U32(echo_cluster::ATTR_CUSTOM_VALUE)
        ),
    ];
    ImEngine::new_with_read_reqs(&matter(&mut DummyMdns), input, expected);
}

#[test]
fn test_read_unsupported_fields() {
    // 6 reads
    // - endpoint doesn't exist - UnsupportedEndpoint
    // - cluster doesn't exist - UnsupportedCluster
    // - cluster doesn't exist and endpoint is wildcard - Silently ignore
    // - attribute doesn't exist - UnsupportedAttribute
    // - attribute doesn't exist and endpoint is wildcard - Silently ignore
    // - attribute doesn't exist and cluster is wildcard - Silently ignore
    init_env_logger();

    let invalid_endpoint = GenericPath::new(
        Some(2),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );
    let invalid_cluster = GenericPath::new(
        Some(0),
        Some(0x1234),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );
    let invalid_cluster_wc_endpoint = GenericPath::new(
        None,
        Some(0x1234),
        Some(echo_cluster::AttributesDiscriminants::AttCustom as u32),
    );
    let invalid_attribute = GenericPath::new(Some(0), Some(echo_cluster::ID), Some(0x1234));
    let invalid_attribute_wc_endpoint =
        GenericPath::new(None, Some(echo_cluster::ID), Some(0x1234));
    let invalid_attribute_wc_cluster = GenericPath::new(Some(0), None, Some(0x1234));
    let input = &[
        AttrPath::new(&invalid_endpoint),
        AttrPath::new(&invalid_cluster),
        AttrPath::new(&invalid_cluster_wc_endpoint),
        AttrPath::new(&invalid_attribute),
        AttrPath::new(&invalid_attribute_wc_endpoint),
        AttrPath::new(&invalid_attribute_wc_cluster),
    ];

    let expected = &[
        attr_status!(&invalid_endpoint, IMStatusCode::UnsupportedEndpoint),
        attr_status!(&invalid_cluster, IMStatusCode::UnsupportedCluster),
        attr_status!(&invalid_attribute, IMStatusCode::UnsupportedAttribute),
    ];
    ImEngine::new_with_read_reqs(&matter(&mut DummyMdns), input, expected);
}

#[test]
fn test_read_wc_endpoint_all_have_clusters() {
    // 1 Attr Read Requests
    // - wildcard endpoint, att1
    // - 2 responses are expected
    init_env_logger();

    let wc_ep_att1 = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
    );
    let input = &[AttrPath::new(&wc_ep_att1)];

    let expected = &[
        attr_data!(
            0,
            echo_cluster::ID,
            echo_cluster::AttributesDiscriminants::Att1,
            ElementType::U16(0x1234)
        ),
        attr_data!(
            1,
            echo_cluster::ID,
            echo_cluster::AttributesDiscriminants::Att1,
            ElementType::U16(0x1234)
        ),
    ];
    ImEngine::new_with_read_reqs(&matter(&mut DummyMdns), input, expected);
}

#[test]
fn test_read_wc_endpoint_only_1_has_cluster() {
    // 1 Attr Read Requests
    // - wildcard endpoint, on/off Cluster OnOff Attribute
    // - 1 response are expected
    init_env_logger();

    let wc_ep_onoff = GenericPath::new(
        None,
        Some(cluster_on_off::ID),
        Some(cluster_on_off::AttributesDiscriminants::OnOff as u32),
    );
    let input = &[AttrPath::new(&wc_ep_onoff)];

    let expected = &[attr_data_path!(
        GenericPath::new(
            Some(1),
            Some(cluster_on_off::ID),
            Some(cluster_on_off::AttributesDiscriminants::OnOff as u32)
        ),
        ElementType::False
    )];
    ImEngine::new_with_read_reqs(&matter(&mut DummyMdns), input, expected);
}

#[test]
fn test_read_wc_endpoint_wc_attribute() {
    // 1 Attr Read Request
    // - wildcard endpoint, wildcard attribute
    // - 8 responses are expected, 1+3 attributes on endpoint 0, 1+3 on endpoint 1
    init_env_logger();
    let wc_ep_wc_attr = GenericPath::new(None, Some(echo_cluster::ID), None);
    let input = &[AttrPath::new(&wc_ep_wc_attr)];

    let attr_list = TLVHolder::new_array(
        2,
        &[
            GlobalElements::FeatureMap as u16,
            GlobalElements::AttributeList as u16,
            echo_cluster::AttributesDiscriminants::Att1 as u16,
            echo_cluster::AttributesDiscriminants::Att2 as u16,
            echo_cluster::AttributesDiscriminants::AttWrite as u16,
            echo_cluster::AttributesDiscriminants::AttCustom as u16,
        ],
    );
    let attr_list_tlv = attr_list.to_tlv();

    let expected = &[
        attr_data_path!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(GlobalElements::FeatureMap as u32),
            ),
            ElementType::U8(0)
        ),
        attr_data_path!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(GlobalElements::AttributeList as u32),
            ),
            attr_list_tlv.get_element_type()
        ),
        attr_data_path!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
            ),
            ElementType::U16(0x1234)
        ),
        attr_data_path!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::AttributesDiscriminants::Att2 as u32),
            ),
            ElementType::U16(0x5678)
        ),
        attr_data_path!(
            GenericPath::new(
                Some(0),
                Some(echo_cluster::ID),
                Some(echo_cluster::AttributesDiscriminants::AttCustom as u32),
            ),
            ElementType::U32(echo_cluster::ATTR_CUSTOM_VALUE)
        ),
        attr_data_path!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(GlobalElements::FeatureMap as u32),
            ),
            ElementType::U8(0)
        ),
        attr_data_path!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(GlobalElements::AttributeList as u32),
            ),
            attr_list_tlv.get_element_type()
        ),
        attr_data_path!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(echo_cluster::AttributesDiscriminants::Att1 as u32),
            ),
            ElementType::U16(0x1234)
        ),
        attr_data_path!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(echo_cluster::AttributesDiscriminants::Att2 as u32),
            ),
            ElementType::U16(0x5678)
        ),
        attr_data_path!(
            GenericPath::new(
                Some(1),
                Some(echo_cluster::ID),
                Some(echo_cluster::AttributesDiscriminants::AttCustom as u32),
            ),
            ElementType::U32(echo_cluster::ATTR_CUSTOM_VALUE)
        ),
    ];
    ImEngine::new_with_read_reqs(&matter(&mut DummyMdns), input, expected);
}

#[test]
fn test_write_success() {
    // 2 Attr Write Request
    // - first on endpoint 0, AttWrite
    // - second on endpoint 1, AttWrite
    let val0 = 10;
    let val1 = 15;
    init_env_logger();
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };
    let attr_data1 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val1);
    };

    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let ep1_att = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );

    let input = &[
        AttrData::new(
            None,
            AttrPath::new(&ep0_att),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&ep1_att),
            EncodeValue::Closure(&attr_data1),
        ),
    ];
    let expected = &[
        AttrStatus::new(&ep0_att, IMStatusCode::Success, 0),
        AttrStatus::new(&ep1_att, IMStatusCode::Success, 0),
    ];

    let mut mdns = DummyMdns;
    let matter = matter(&mut mdns);
    let im = ImEngine::new_with_write_reqs(&matter, input, expected);
    assert_eq!(val0, im.echo_cluster(0).att_write);
    assert_eq!(val1, im.echo_cluster(1).att_write);
}

#[test]
fn test_write_wc_endpoint() {
    // 1 Attr Write Request
    // - wildcard endpoint, AttWrite
    let val0 = 10;
    init_env_logger();
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };

    let ep_att = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let input = &[AttrData::new(
        None,
        AttrPath::new(&ep_att),
        EncodeValue::Closure(&attr_data0),
    )];

    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );

    let ep1_att = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let expected = &[
        AttrStatus::new(&ep0_att, IMStatusCode::Success, 0),
        AttrStatus::new(&ep1_att, IMStatusCode::Success, 0),
    ];

    let mut mdns = DummyMdns;
    let matter = matter(&mut mdns);
    let im = ImEngine::new_with_write_reqs(&matter, input, expected);
    assert_eq!(val0, im.echo_cluster(0).att_write);
}

#[test]
fn test_write_unsupported_fields() {
    // 7 writes
    // - endpoint doesn't exist - UnsupportedEndpoint
    // - cluster doesn't exist - UnsupportedCluster
    // - attribute doesn't exist - UnsupportedAttribute
    // - cluster doesn't exist and endpoint is wildcard - Silently ignore
    // - attribute doesn't exist and endpoint is wildcard - Silently ignore
    // - cluster is wildcard - Cluster cannot be wildcard - UnsupportedCluster
    // - attribute is wildcard - Attribute cannot be wildcard - UnsupportedAttribute
    init_env_logger();

    let val0 = 50;
    let attr_data0 = |tag, t: &mut TLVWriter| {
        let _ = t.u16(tag, val0);
    };

    let invalid_endpoint = GenericPath::new(
        Some(4),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let invalid_cluster = GenericPath::new(
        Some(0),
        Some(0x1234),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let invalid_attribute = GenericPath::new(Some(0), Some(echo_cluster::ID), Some(0x1234));
    let wc_endpoint_invalid_cluster = GenericPath::new(
        None,
        Some(0x1234),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let wc_endpoint_invalid_attribute =
        GenericPath::new(None, Some(echo_cluster::ID), Some(0x1234));
    let wc_cluster = GenericPath::new(
        Some(0),
        None,
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let wc_attribute = GenericPath::new(Some(0), Some(echo_cluster::ID), None);

    let input = &[
        AttrData::new(
            None,
            AttrPath::new(&invalid_endpoint),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&invalid_cluster),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&invalid_attribute),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&wc_endpoint_invalid_cluster),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&wc_endpoint_invalid_attribute),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&wc_cluster),
            EncodeValue::Closure(&attr_data0),
        ),
        AttrData::new(
            None,
            AttrPath::new(&wc_attribute),
            EncodeValue::Closure(&attr_data0),
        ),
    ];
    let expected = &[
        AttrStatus::new(&invalid_endpoint, IMStatusCode::UnsupportedEndpoint, 0),
        AttrStatus::new(&invalid_cluster, IMStatusCode::UnsupportedCluster, 0),
        AttrStatus::new(&invalid_attribute, IMStatusCode::UnsupportedAttribute, 0),
        AttrStatus::new(&wc_cluster, IMStatusCode::UnsupportedCluster, 0),
        AttrStatus::new(&wc_attribute, IMStatusCode::UnsupportedAttribute, 0),
    ];
    let mut mdns = DummyMdns;
    let matter = matter(&mut mdns);
    let im = ImEngine::new_with_write_reqs(&matter, input, expected);
    assert_eq!(
        echo_cluster::ATTR_WRITE_DEFAULT_VALUE,
        im.echo_cluster(0).att_write
    );
}
