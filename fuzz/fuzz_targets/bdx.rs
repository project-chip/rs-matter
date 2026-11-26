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

//! Arbitrary bytes as each BDX message, and as a status report.

#![no_main]

use libfuzzer_sys::fuzz_target;

use rs_matter_bdx::{Block, BlockQuery, BlockQueryWithSkip, TransferAccept, TransferInit};
use rs_matter_transport::proto::sc::StatusReport;
use rs_matter_utils::storage::ReadBuf;

fuzz_target!(|data: &[u8]| {
    let _ = TransferInit::parse(data);
    let _ = TransferAccept::parse(true, data);
    let _ = TransferAccept::parse(false, data);
    let _ = Block::parse(data);
    let _ = BlockQuery::parse(data);
    let _ = BlockQueryWithSkip::parse(data);
    let _ = StatusReport::read(&mut ReadBuf::new(data));
});
