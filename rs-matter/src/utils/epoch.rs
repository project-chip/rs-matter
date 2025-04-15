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

use core::time::Duration;

pub type Epoch = fn() -> Duration;

// As per the spec, if Not After is 0, it should set the time to GeneralizedTime value of
// 99991231235959Z
// So CERT_DOESNT_EXPIRE value is calculated as epoch(99991231235959Z) - MATTER_EPOCH_SECS
pub const MATTER_CERT_DOESNT_EXPIRE: u64 = 252455615999;

pub const MATTER_EPOCH_SECS: u64 = 946684800; // Seconds from 1970/01/01 00:00:00 till 2000/01/01 00:00:00 UTC

pub fn dummy_epoch() -> Duration {
    Duration::from_secs(0)
}

#[cfg(feature = "std")]
pub fn sys_epoch() -> Duration {
    unwrap!(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH),
        "System time is before UNIX_EPOCH"
    )
}
