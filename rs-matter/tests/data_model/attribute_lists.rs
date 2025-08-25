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

use rs_matter::im::GenericPath;
use rs_matter::im::IMStatusCode;

use crate::attr_data_req;
use crate::attr_data_req_lel;
use crate::attr_status;
use crate::attr_status_lel;
use crate::common::e2e::im::echo_cluster::{self, TestChecker};
use crate::common::e2e::ImEngine;
use crate::common::init_env_logger;

// Helper for handling Write Attribute sequences
#[test]
/// This tests all the attribute list operations
/// add item, edit item, delete item, overwrite list, delete list
fn attr_list_ops() {
    let tc_handle = TestChecker::get().unwrap();

    init_env_logger();

    let replace_all: &[u16] = &[1, 2];
    let delete_all: &[u16] = &[];

    let path = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWriteList as u32),
    );

    // Test 1: Replace Operation - update the whole list by replacing it
    let input = &[attr_data_req!(&path, Some(&replace_all))];
    let expected = &[attr_status!(&path, IMStatusCode::Success)];

    ImEngine::write_reqs(input, expected);
    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!(replace_all, tc.write_list.as_slice());
    }

    // Test 2: Replace Operation with individual array items as separate paths
    let input = &[
        attr_data_req!(&path, Some(&delete_all)),
        attr_data_req_lel!(&path, Some(&3_u16)),
        attr_data_req_lel!(&path, Some(&4_u16)),
        attr_data_req_lel!(&path, Some(&5_u16)),
    ];
    let expected = &[
        attr_status!(&path, IMStatusCode::Success),
        attr_status_lel!(&path, IMStatusCode::Success),
        attr_status_lel!(&path, IMStatusCode::Success),
        attr_status_lel!(&path, IMStatusCode::Success),
    ];

    ImEngine::write_reqs(input, expected);
    {
        let tc = tc_handle.lock().unwrap();
        assert_eq!(&[3, 4, 5], tc.write_list.as_slice());
    }

    // Test 3: Replace Operation - delete the whole list by replacing it with an empty one
    let input = &[attr_data_req!(&path, Some(&delete_all))];
    let expected = &[attr_status!(&path, IMStatusCode::Success)];

    ImEngine::write_reqs(input, expected);
    {
        let tc = tc_handle.lock().unwrap();
        assert!(tc.write_list.is_empty());
    }
}
