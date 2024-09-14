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

use rs_matter::interaction_model::core::IMStatusCode;
use rs_matter::interaction_model::messages::ib::{AttrPath, AttrStatus};
use rs_matter::interaction_model::messages::GenericPath;
use rs_matter::tlv::{Nullable, TLVValue};

use crate::common::e2e::im::attributes::TestAttrData;
use crate::common::e2e::im::echo_cluster::{self, TestChecker};
use crate::common::e2e::ImEngine;
use crate::common::init_env_logger;

// Helper for handling Write Attribute sequences
#[test]
/// This tests all the attribute list operations
/// add item, edit item, delete item, overwrite list, delete list
fn attr_list_ops() {
    let val0: u16 = 10;
    let val1: u16 = 15;
    let tc_handle = TestChecker::get().unwrap();

    init_env_logger();

    let delete_item = TLVValue::null();
    let delete_all: &[u32] = &[];

    let att_data = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWriteList as u32),
    );
    let mut att_path = AttrPath::new(&att_data);

    // Test 1: Add Operation - add val0
    let input = &[TestAttrData::new(None, att_path.clone(), &val0)];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Success, 0)];

    ImEngine::write_reqs(input, expected);
    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([Some(val0), None, None, None, None], tc.write_list);
    }

    // Test 2: Another Add Operation - add val1
    let input = &[TestAttrData::new(None, att_path.clone(), &val1)];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Success, 0)];

    ImEngine::write_reqs(input, expected);
    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([Some(val0), Some(val1), None, None, None], tc.write_list);
    }

    // Test 3: Edit Operation - edit val1 to val0
    att_path.list_index = Some(Nullable::some(1));
    let input = &[TestAttrData::new(None, att_path.clone(), &val0)];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Success, 0)];

    ImEngine::write_reqs(input, expected);
    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([Some(val0), Some(val0), None, None, None], tc.write_list);
    }

    // Test 4: Delete Operation - delete index 0
    att_path.list_index = Some(Nullable::some(0));
    let input = &[TestAttrData::new(None, att_path.clone(), &delete_item)];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Success, 0)];

    ImEngine::write_reqs(input, expected);
    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([None, Some(val0), None, None, None], tc.write_list);
    }

    // Test 5: Overwrite Operation - overwrite first 2 entries
    let overwrite_val: [u32; 2] = [20, 21];
    att_path.list_index = None;
    let input = &[TestAttrData::new(None, att_path.clone(), &overwrite_val)];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Success, 0)];

    ImEngine::write_reqs(input, expected);
    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([Some(20), Some(21), None, None, None], tc.write_list);
    }

    // Test 6: Overwrite Operation - delete whole list
    att_path.list_index = None;
    let input = &[TestAttrData::new(None, att_path, &delete_all)];
    let expected = &[AttrStatus::new(&att_data, IMStatusCode::Success, 0)];

    ImEngine::write_reqs(input, expected);
    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!([None, None, None, None, None], tc.write_list);
    }
}
