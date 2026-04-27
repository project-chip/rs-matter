/*
 *
 *    Copyright (c) 2020-2026 Project CHIP Authors
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

//! The WebRTC Transport Requestor cluster (0x0554).
//!
//! The client-facing counterpart to `WebRTCTransportProvider`. A Matter
//! controller hosts this cluster to receive unsolicited Offer, Answer and
//! ICE-candidate notifications from a camera.
//!
//! For now, just re-exports the auto-generated types/traits so downstream
//! crates can implement `ClusterAsyncHandler` directly (Pattern A). The
//! `WebRTCTransportProvider` handler uses an outbound
//! invoke helper targeting this cluster on the controller node.

pub use crate::dm::clusters::decl::web_rtc_transport_requestor::*;
