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

//! A re-export of the `zbus` crate, which provides D-Bus support in Rust.

pub use ::zbus::*;

use crate::error::ErrorCode;

impl From<zbus::Error> for crate::error::Error {
    fn from(e: zbus::Error) -> Self {
        Self::new_with_details(ErrorCode::DBusError, Box::new(e))
    }
}

impl From<zbus::zvariant::Error> for crate::error::Error {
    fn from(e: zbus::zvariant::Error) -> Self {
        Self::new_with_details(ErrorCode::DBusError, Box::new(e))
    }
}

impl From<zbus::fdo::Error> for crate::error::Error {
    fn from(e: zbus::fdo::Error) -> Self {
        Self::new_with_details(ErrorCode::DBusError, Box::new(e))
    }
}
