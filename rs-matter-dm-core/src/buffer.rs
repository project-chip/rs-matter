/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

use crate::utils::storage::Vec;

/// The size of an [`IMBuffer`]: that of the largest message an exchange can
/// receive (a Matter-over-TCP one with the `large-buffers` feature).
#[cfg(feature = "large-buffers")]
pub const IM_BUFFER_SIZE: usize = 1024 * 1024;
/// The size of an [`IMBuffer`]: that of the largest message an exchange can
/// receive (a Matter-over-TCP one with the `large-buffers` feature).
#[cfg(not(feature = "large-buffers"))]
pub const IM_BUFFER_SIZE: usize = 1583;

/// The buffer type used by the Interaction Model and the handlers for the
/// payloads of messages.
pub type IMBuffer = Vec<u8, IM_BUFFER_SIZE>;
