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

//! Regression tests for the mandatory `interactionModelRevision` field
//! (TLV context tag `0xFF`) in IM messages.
//!
//! Matter Core spec §8.1.1 (p. 545, doc 23-27349-009) requires every
//! Interaction Model message to carry an `InteractionModelRevision`
//! field at the top level. The encoded value has been `13` since
//! Matter 1.3 and is unchanged in 1.4 and 1.5. matter.js rejects
//! messages that omit it; the C++ SDK is tolerant in practice, which
//! is what masked the bug prior to PR #446.
//!
//! These tests pin down two invariants in pure-byte form:
//!
//! 1. **Client request builders** auto-inject the field at the
//!    default value when the caller doesn't call
//!    `interaction_model_revision()` explicitly, and honor an
//!    explicit override when the caller does.
//! 2. **Server response encoders** for `StatusResp` and
//!    `SubscribeResp` emit the field at the default value.
//!
//! All assertions are byte-level (`needle` search on the encoded
//! slice). TLV encoding of "context tag `0xFF`, type unsigned-int-8,
//! value `V`" is exactly the three bytes `[0x24, 0xff, V]`.

use rs_matter::im::{
    IMStatusCode, InvReqBuilder, ReadReqBuilder, StatusResp, SubscribeReqBuilder, SubscribeResp,
    WriteReqBuilder, IM_REVISION,
};
use rs_matter::tlv::{TLVTag, TLVWriteParent, ToTLV};
use rs_matter::utils::storage::WriteBuf;

/// Three-byte TLV encoding of `<context-tag 0xFF, u8 V>`.
fn im_rev_bytes(v: u8) -> [u8; 3] {
    [0x24, 0xff, v]
}

/// `true` if `needle` appears anywhere in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// =====================================================================
// Client-side: ReadReqBuilder
// =====================================================================

#[test]
fn read_req_auto_injects_im_revision() {
    let mut buf = [0u8; 256];
    let mut wb = WriteBuf::new(&mut buf);
    {
        let parent = TLVWriteParent::new((), &mut wb);
        ReadReqBuilder::new(parent, &TLVTag::Anonymous)
            .unwrap()
            .fabric_filtered(false)
            .unwrap()
            .end()
            .unwrap();
    }
    let bytes = wb.as_slice();
    assert!(
        contains(bytes, &im_rev_bytes(IM_REVISION)),
        "ReadRequest missing auto-injected IM revision; bytes={:02x?}",
        bytes
    );
}

#[test]
fn read_req_explicit_override_wins() {
    let mut buf = [0u8; 256];
    let mut wb = WriteBuf::new(&mut buf);
    {
        let parent = TLVWriteParent::new((), &mut wb);
        ReadReqBuilder::new(parent, &TLVTag::Anonymous)
            .unwrap()
            .fabric_filtered(false)
            .unwrap()
            .interaction_model_revision(14)
            .unwrap()
            .end()
            .unwrap();
    }
    let bytes = wb.as_slice();
    assert!(
        contains(bytes, &im_rev_bytes(14)),
        "explicit IM revision 14 not present; bytes={:02x?}",
        bytes
    );
    assert!(
        !contains(bytes, &im_rev_bytes(IM_REVISION)),
        "default IM revision should not have been written; bytes={:02x?}",
        bytes
    );
}

// =====================================================================
// Client-side: WriteReqBuilder
// =====================================================================

#[test]
fn write_req_auto_injects_im_revision() {
    let mut buf = [0u8; 256];
    let mut wb = WriteBuf::new(&mut buf);
    {
        let parent = TLVWriteParent::new((), &mut wb);
        WriteReqBuilder::new(parent, &TLVTag::Anonymous)
            .unwrap()
            .write_requests()
            .unwrap()
            .end()
            .unwrap()
            .end()
            .unwrap();
    }
    let bytes = wb.as_slice();
    assert!(
        contains(bytes, &im_rev_bytes(IM_REVISION)),
        "WriteRequest missing auto-injected IM revision; bytes={:02x?}",
        bytes
    );
}

#[test]
fn write_req_explicit_override_wins() {
    let mut buf = [0u8; 256];
    let mut wb = WriteBuf::new(&mut buf);
    {
        let parent = TLVWriteParent::new((), &mut wb);
        WriteReqBuilder::new(parent, &TLVTag::Anonymous)
            .unwrap()
            .write_requests()
            .unwrap()
            .end()
            .unwrap()
            .interaction_model_revision(14)
            .unwrap()
            .end()
            .unwrap();
    }
    let bytes = wb.as_slice();
    assert!(contains(bytes, &im_rev_bytes(14)));
    assert!(!contains(bytes, &im_rev_bytes(IM_REVISION)));
}

// =====================================================================
// Client-side: SubscribeReqBuilder
// =====================================================================

#[test]
fn subscribe_req_auto_injects_im_revision() {
    let mut buf = [0u8; 256];
    let mut wb = WriteBuf::new(&mut buf);
    {
        let parent = TLVWriteParent::new((), &mut wb);
        SubscribeReqBuilder::new(parent, &TLVTag::Anonymous)
            .unwrap()
            .keep_subs(true)
            .unwrap()
            .min_int_floor(0)
            .unwrap()
            .max_int_ceil(60)
            .unwrap()
            .fabric_filtered(true)
            .unwrap()
            .end()
            .unwrap();
    }
    let bytes = wb.as_slice();
    assert!(
        contains(bytes, &im_rev_bytes(IM_REVISION)),
        "SubscribeRequest missing auto-injected IM revision; bytes={:02x?}",
        bytes
    );
}

#[test]
fn subscribe_req_explicit_override_wins() {
    let mut buf = [0u8; 256];
    let mut wb = WriteBuf::new(&mut buf);
    {
        let parent = TLVWriteParent::new((), &mut wb);
        SubscribeReqBuilder::new(parent, &TLVTag::Anonymous)
            .unwrap()
            .keep_subs(true)
            .unwrap()
            .min_int_floor(0)
            .unwrap()
            .max_int_ceil(60)
            .unwrap()
            .fabric_filtered(true)
            .unwrap()
            .interaction_model_revision(14)
            .unwrap()
            .end()
            .unwrap();
    }
    let bytes = wb.as_slice();
    assert!(contains(bytes, &im_rev_bytes(14)));
    assert!(!contains(bytes, &im_rev_bytes(IM_REVISION)));
}

// =====================================================================
// Client-side: InvReqBuilder
// =====================================================================

#[test]
fn invoke_req_auto_injects_im_revision() {
    let mut buf = [0u8; 256];
    let mut wb = WriteBuf::new(&mut buf);
    {
        let parent = TLVWriteParent::new((), &mut wb);
        InvReqBuilder::new(parent, &TLVTag::Anonymous)
            .unwrap()
            .invoke_requests()
            .unwrap()
            .end()
            .unwrap()
            .end()
            .unwrap();
    }
    let bytes = wb.as_slice();
    assert!(
        contains(bytes, &im_rev_bytes(IM_REVISION)),
        "InvokeRequest missing auto-injected IM revision; bytes={:02x?}",
        bytes
    );
}

#[test]
fn invoke_req_explicit_override_wins() {
    let mut buf = [0u8; 256];
    let mut wb = WriteBuf::new(&mut buf);
    {
        let parent = TLVWriteParent::new((), &mut wb);
        InvReqBuilder::new(parent, &TLVTag::Anonymous)
            .unwrap()
            .invoke_requests()
            .unwrap()
            .end()
            .unwrap()
            .interaction_model_revision(14)
            .unwrap()
            .end()
            .unwrap();
    }
    let bytes = wb.as_slice();
    assert!(contains(bytes, &im_rev_bytes(14)));
    assert!(!contains(bytes, &im_rev_bytes(IM_REVISION)));
}

// =====================================================================
// Server-side response structs (PR #446 regression cover)
// =====================================================================
//
// `WriteResp`, `InvokeResp`, and `ReportDataResp` carry a `TLVArray`
// over borrowed wire bytes and aren't ergonomically constructed
// in-place — they're produced by the on-the-fly emitters in `dm.rs`,
// which are exercised end-to-end by the existing e2e suite. The two
// response types below are the cases that *can* be unit-tested
// directly without going through the data-model engine, and together
// they pin down the same `ToTLV` invariant.

#[test]
fn status_resp_default_carries_im_revision() {
    let mut buf = [0u8; 64];
    let mut wb = WriteBuf::new(&mut buf);
    let resp = StatusResp {
        status: IMStatusCode::Success,
        ..Default::default()
    };
    resp.to_tlv(&TLVTag::Anonymous, &mut wb).unwrap();
    let bytes = wb.as_slice();
    assert!(
        contains(bytes, &im_rev_bytes(IM_REVISION)),
        "StatusResp encoding missing IM revision; bytes={:02x?}",
        bytes
    );
}

#[test]
fn subscribe_resp_carries_im_revision() {
    let mut buf = [0u8; 64];
    let mut wb = WriteBuf::new(&mut buf);
    SubscribeResp::write(
        &mut wb,
        /* subscription_id */ 0x1234_5678,
        /* max_int */ 60,
    )
    .unwrap();
    let bytes = wb.as_slice();
    assert!(
        contains(bytes, &im_rev_bytes(IM_REVISION)),
        "SubscribeResp encoding missing IM revision; bytes={:02x?}",
        bytes
    );
}
