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

#[cfg(target_os = "macos")]
mod sys_macos;
#[cfg(target_os = "macos")]
pub use self::sys_macos::*;

#[cfg(target_os = "linux")]
mod sys_linux;
#[cfg(target_os = "linux")]
pub use self::sys_linux::*;

#[cfg(target_os = "espidf")]
mod sys_espidf;
#[cfg(target_os = "espidf")]
pub use self::sys_espidf::*;

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "espidf"))]
mod posix;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "espidf"))]
pub use self::posix::*;
