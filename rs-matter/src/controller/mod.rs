/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 */

//! Matter Controller (commissioner) building blocks.
//!
//! The bulk of `rs-matter` targets the **accessory** role — a node that
//! gets commissioned by an external controller. This module is the
//! inverse: the **controller** role — drives a freshly-paired accessory
//! through the post-PASE commissioning steps that bring it onto a
//! fabric.
//!
//! Scope of this first slice (validated end-to-end against `chip-tool`
//! `all-clusters-app`):
//!
//! - [`commissioner::arm_fail_safe`] — GeneralCommissioning::ArmFailSafe
//!   over PASE, with ArmFailSafeResponse status decode.
//! - [`commissioner::csr_request`] — OperationalCredentials::CSRRequest
//!   with CSRResponse decode (returns NOCSRElements + signature).
//! - [`commissioner::decode_nocsr_elements`] — TLV decoder for the
//!   NOCSRElements payload (§11.18.6.5.2), with nonce-echo helper.
//! - [`commissioner::add_noc`] — OperationalCredentials::AddNOC with
//!   NOCResponse status + FabricIndex decode.
//! - [`commissioner::commission_pase`] — end-to-end orchestrator that
//!   chains ArmFailSafe → CSRRequest → controller-side NOC issuance via
//!   [`crate::commissioner::FabricCredentials`] → AddTrustedRootCertificate
//!   → AddNOC → CommissioningComplete.
//! - [`setup_code`] — manual pairing code + QR-code (`MT:…`) parser
//!   following Matter spec §5.1.4.
//!
//! Out of scope for this slice (planned follow-ups):
//!
//! - BLE central + BTP framing for the bootstrap transport.
//! - DCL fetch + Device Attestation chain verification.
//! - NetworkCommissioning cluster (Thread / Wi-Fi credential delivery).
//! - Operational discovery (`_matter._tcp` mDNS-SD client) + CASE
//!   establishment.
//! - A higher-level state machine that ties the above together.
//!
//! Reference material consulted: python-matter-server (controller API
//! shape), connectedhomeip (wire-level protocol clarifications), Matter
//! Core Specification 1.4 (the source of truth — section references are
//! inline at each translation point).

pub mod commissioner;
pub mod error;
pub mod setup_code;

pub use error::ControllerError;
