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
use rs_matter::im::{EventPath};

use crate::common::e2e::im::{echo_cluster};
use crate::common::e2e::ImEngine;
use crate::common::init_env_logger;
use crate::{event_data_path};

#[test]
fn test_read_success() {
    // 3 Event Read Requests
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
        // TODO(events): make these fake attributes match some real events
        // TODO(events): How does the stubbing/real stuff here work wrt the queue? We need to test the queue..
        EventPath::from_gp(&ep0_att1),
        EventPath::from_gp(&ep1_att2),
        EventPath::from_gp(&ep1_attcustom),
    ];
    let expected = &[
        // TODO(events): These are not right
        event_data_path!(ep0_att1, Some(&0x1234u16)),
        event_data_path!(ep1_att2, Some(&0x5678u16)),
        event_data_path!(ep1_attcustom, Some(&echo_cluster::ATTR_CUSTOM_VALUE)),
    ];
    ImEngine::read_event_reqs(input, expected);
}
