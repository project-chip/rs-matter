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

//! Arbitrary bytes as each Interaction Model message: the requests a node
//! receives and the responses a controller receives.

#![no_main]

use core::fmt::{Debug, Write};

use libfuzzer_sys::fuzz_target;

use rs_matter_im_core::{
    InvReq, InvokeResp, ReadReq, ReportDataResp, StatusResp, SubscribeReq, SubscribeResp, TimedReq,
    WriteReq, WriteResp,
};
use rs_matter_tlv::{FromTLV, TLVArray, TLVElement};

/// Decodes every element of an array, as a handler would.
fn decode_all<'a, T, E>(array: Result<Option<TLVArray<'a, T>>, E>)
where
    T: FromTLV<'a>,
{
    if let Ok(Some(array)) = array {
        for item in &array {
            let _ = item;
        }
    }
}

/// Decodes a message with `FromTLV` and formats it.
fn decode<'a, T>(element: &TLVElement<'a>, text: &mut String)
where
    T: FromTLV<'a> + Debug,
{
    if let Ok(msg) = T::from_tlv(element) {
        write!(text, "{msg:?}").unwrap();
    }
}

fuzz_target!(|data: &[u8]| {
    let element = TLVElement::new(data);
    let mut text = String::new();

    let req = ReadReq::new(element.clone());
    decode_all(req.attr_requests());
    decode_all(req.event_requests());
    decode_all(req.event_filters());
    decode_all(req.dataver_filters());
    let _ = req.fabric_filtered();
    write!(text, "{req:?}").unwrap();

    let req = SubscribeReq::new(element.clone());
    let _ = req.keep_subs();
    let _ = req.min_int_floor();
    let _ = req.max_int_ceil();
    decode_all(req.attr_requests());
    decode_all(req.event_requests());
    decode_all(req.event_filters());
    decode_all(req.dataver_filters());
    let _ = req.split_dataver_filters();
    let _ = req.fabric_filtered();
    write!(text, "{req:?}").unwrap();

    let req = WriteReq::new(element.clone());
    let _ = req.supress_response();
    let _ = req.timed_request();
    decode_all(req.write_requests().map(Some));
    let _ = req.more_chunks();
    write!(text, "{req:?}").unwrap();

    let req = InvReq::new(element.clone());
    let _ = req.suppress_response();
    let _ = req.timed_request();
    decode_all(req.inv_requests());
    write!(text, "{req:?}").unwrap();

    decode::<TimedReq>(&element, &mut text);
    decode::<StatusResp>(&element, &mut text);
    decode::<ReportDataResp>(&element, &mut text);
    decode::<SubscribeResp>(&element, &mut text);
    decode::<WriteResp>(&element, &mut text);
    decode::<InvokeResp>(&element, &mut text);
});
