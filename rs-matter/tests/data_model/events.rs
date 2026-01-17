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
    init_env_logger();

    let ep0_event1 = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(1), // TODO need to implement macros like  attribute_enum!() for events
    );
    let input = &[
        EventPath::from_gp(&ep0_event1),
    ];
    let expected = &[
        event_data_path!(ep0_event1, Some(&0x42u8)),
    ];
    ImEngine::read_event_reqs(input, expected);
}
