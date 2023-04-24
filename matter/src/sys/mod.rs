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

#[cfg(all(feature = "std", target_os = "macos"))]
mod sys_macos;
#[cfg(all(feature = "std", target_os = "macos"))]
pub use self::sys_macos::*;

#[cfg(all(feature = "std", target_os = "linux"))]
mod sys_linux;
#[cfg(all(feature = "std", target_os = "linux"))]
pub use self::sys_linux::*;

pub const SPAKE2_ITERATION_COUNT: u32 = 2000;

// The Packet Pool that is allocated from. POSIX systems can use
// higher values unlike embedded systems
pub const MAX_PACKET_POOL_SIZE: usize = 25;
