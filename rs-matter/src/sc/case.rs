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

//! CASE (Certificate Authenticated Session Establishment) protocol implementation.
//!
//! This module provides both the initiator (controller) and responder (device) sides
//! of the CASE protocol for establishing secure sessions using operational certificates.

use crate::cert::MAX_CERT_TLV_LEN;

pub(crate) mod casep;
mod initiator;
mod responder;

// Two certificates (NOC and ICAC), plus ECDSA etc -> approx 950b, doing 1024 to be safe
const CASE_LARGE_BUF_SIZE: usize = MAX_CERT_TLV_LEN * 2 + 224;

pub use initiator::CaseInitiator;
pub use responder::Case;
