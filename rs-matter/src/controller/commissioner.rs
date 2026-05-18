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

//! Commissioner-side IM invokes + end-to-end commission orchestrator.
//!
//! Provides the building blocks a controller needs to drive a Matter
//! accessory from a freshly-established PASE session through to
//! `CommissioningComplete`. Each step is its own `pub async fn` so
//! callers can drive the flow one stage at a time, and
//! [`commission_pase`] chains them together for the common case.
//!
//! Caller responsibilities (not provided by this module):
//!   - Open the BLE/IP transport and run [`crate::sc::pase::PaseInitiator`]
//!     to land a PASE-secured session against the device.
//!   - Hold a [`FabricCredentials`] for the destination fabric.
//!
//! After `commission_pase` returns successfully the device has been
//! given a NOC, has our RCAC installed, and has accepted
//! `CommissioningComplete`. Operational discovery (`_matter._tcp` mDNS
//! lookup) + CASE establishment are left to higher-level code.

use crate::commissioner::FabricCredentials;
use crate::crypto::Crypto;
use crate::im::client::{ImClient, TxOutcome};
use crate::im::CmdDataTag;
use crate::tlv::{TLVTag, TLVWrite};
use crate::transport::exchange::Exchange;
use crate::Matter;

use super::ControllerError;

// ─── Matter commissioning cluster + command IDs ──────────────────────────
// Application Cluster Spec references in parens.

const CL_GENERAL_COMMISSIONING: u32 = 0x0030;
const CMD_ARM_FAIL_SAFE: u32 = 0x00; // §11.10.6.1
const CMD_ARM_FAIL_SAFE_RESPONSE: u32 = 0x01; // §11.10.6.2
const CMD_COMMISSIONING_COMPLETE: u32 = 0x04; // §11.10.6.6

const CL_OPERATIONAL_CREDENTIALS: u32 = 0x003E;
const CMD_CSR_REQUEST: u32 = 0x04; // §11.18.6.5
const CMD_CSR_RESPONSE: u32 = 0x05; // §11.18.6.6
const CMD_ADD_NOC: u32 = 0x06; // §11.18.6.8
const CMD_NOC_RESPONSE: u32 = 0x08; // §11.18.6.10
const CMD_ADD_TRUSTED_ROOT_CERTIFICATE: u32 = 0x0B; // §11.18.6.13

// Endpoint 0 (Root Node) hosts the GeneralCommissioning / OperationalCredentials
// clusters during commissioning — that's the Matter spec invariant we rely on.
const COMMISSIONING_ENDPOINT: u16 = 0;

/// Invoke `GeneralCommissioning::ArmFailSafe(expiry_seconds, breadcrumb)`
/// on endpoint 0. Opens a fresh PASE-secured exchange (fab=0, peer=0,
/// secure=true — the Matter session manager keys PASE sessions on
/// that tuple) and decodes the ArmFailSafeResponse status:
/// CommissioningErrorEnum::OK == 0 ⇒ `Ok(())`, anything else ⇒
/// `Err(ControllerError::FailSafeExpired)`.
pub async fn arm_fail_safe(
    matter: &Matter<'_>,
    expiry_seconds: u16,
    breadcrumb: u64,
) -> Result<(), ControllerError> {
    let exchange = Exchange::initiate(matter, 0, 0, true)
        .await
        .map_err(ControllerError::from)?;
    let mut sender = exchange
        .invoke_sender(None)
        .await
        .map_err(ControllerError::from)?;
    let mut chunk = loop {
        match sender.tx().await.map_err(ControllerError::from)? {
            TxOutcome::BuildRequest(builder) => {
                sender = builder
                    .suppress_response(false)
                    .map_err(ControllerError::from)?
                    .timed_request(false)
                    .map_err(ControllerError::from)?
                    .invoke_requests()
                    .map_err(ControllerError::from)?
                    .push()
                    .map_err(ControllerError::from)?
                    .path(
                        COMMISSIONING_ENDPOINT,
                        CL_GENERAL_COMMISSIONING,
                        CMD_ARM_FAIL_SAFE,
                    )
                    .map_err(ControllerError::from)?
                    .data(|w| {
                        // CommandFields per Matter §8.7 is a struct at
                        // CmdDataTag::Data (Context(1)). Inside it we
                        // write the ArmFailSafe fields by field-id:
                        //   0: ExpiryLengthSeconds (u16)
                        //   1: Breadcrumb (u64)
                        w.start_struct(&TLVTag::Context(CmdDataTag::Data as u8))?;
                        w.u16(&TLVTag::Context(0), expiry_seconds)?;
                        w.u64(&TLVTag::Context(1), breadcrumb)?;
                        w.end_container()?;
                        Ok(())
                    })
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?;
            }
            TxOutcome::GotResponse(c) => break c,
        }
    };
    // Walk response chunks and decode ArmFailSafeResponse.ErrorCode.
    // CommissioningErrorEnum::OK = 0; anything else means the arm
    // didn't take (e.g. failsafe held by another controller, bad
    // regulatory config, etc.) and subsequent commissioning IM invokes
    // will fail with InvalidCommand. Bubble it up as ControllerError
    // so the operator sees the actual cause rather than a downstream
    // ghost "no response" error.
    use crate::dm::clusters::gen_comm::ArmFailSafeResponse;
    let mut got_response = false;
    loop {
        if !got_response {
            if let Some(resp) = chunk.response().map_err(ControllerError::from)? {
                // InvokeResponseIB carries the *response* command ID,
                // not the request — ArmFailSafe(0x00) →
                // ArmFailSafeResponse(0x01). Take the first response IB
                // for the path; a single-command invoke produces at
                // most one matching entry.
                if let Some((_endpoint, r)) = resp
                    .responses::<ArmFailSafeResponse>(
                        CL_GENERAL_COMMISSIONING,
                        CMD_ARM_FAIL_SAFE_RESPONSE,
                    )
                    .next()
                {
                    match r {
                        Ok(afs) => {
                            let code = afs.error_code().map_err(ControllerError::from)?;
                            if (code as u8) != 0 {
                                return Err(ControllerError::FailSafeExpired);
                            }
                            got_response = true;
                        }
                        Err(e) => return Err(ControllerError::Inner(e)),
                    }
                }
            }
        }
        match chunk.complete().await.map_err(ControllerError::from)? {
            Some(next) => chunk = next,
            None => break,
        }
    }
    Ok(())
}

/// Maximum NOCSRElements payload we'll accept back from a device. Per
/// spec the field is `octstr<400>` (Matter §11.18.6.6); rounding up to
/// a heapless::Vec of 512 keeps us defensive against future field-size
/// bumps.
pub const MAX_NOCSR_ELEMENTS_LEN: usize = 512;

/// Bytes returned by a successful CSRRequest. The two payloads each get
/// passed into different downstream steps:
///   - `nocsr_elements` → `FabricCredentials::generate_device_credentials`
///     (it contains the device's actual operational CSR, wrapped in a
///     TLV envelope that bundles a server-chosen nonce echo).
///   - `attestation_signature` → verified against the device's DAC public
///     key (extracted from its earlier AttestationResponse / certs).
pub struct CsrPayload {
    pub nocsr_elements: heapless::Vec<u8, MAX_NOCSR_ELEMENTS_LEN>,
    pub attestation_signature: heapless::Vec<u8, 64>,
}

/// Invoke `OperationalCredentials::CSRRequest(csr_nonce, is_for_update_noc?)`
/// on endpoint 0 over the PASE-secured exchange. Decodes the CSRResponse
/// and returns the NOCSRElements + signature.
///
/// The 32-byte `csr_nonce` MUST be random per invocation (Matter
/// §11.18.6.5 requires the device echo it inside the signed
/// NOCSRElements blob — replaying the same nonce defeats freshness).
pub async fn csr_request(
    matter: &Matter<'_>,
    csr_nonce: &[u8; 32],
) -> Result<CsrPayload, ControllerError> {
    use crate::dm::clusters::noc::CSRResponse;
    use crate::error::Error;

    let exchange = Exchange::initiate(matter, 0, 0, true)
        .await
        .map_err(ControllerError::from)?;
    let mut sender = exchange
        .invoke_sender(None)
        .await
        .map_err(ControllerError::from)?;
    let mut chunk = loop {
        match sender.tx().await.map_err(ControllerError::from)? {
            TxOutcome::BuildRequest(builder) => {
                sender = builder
                    .suppress_response(false)
                    .map_err(ControllerError::from)?
                    .timed_request(false)
                    .map_err(ControllerError::from)?
                    .invoke_requests()
                    .map_err(ControllerError::from)?
                    .push()
                    .map_err(ControllerError::from)?
                    .path(
                        COMMISSIONING_ENDPOINT,
                        CL_OPERATIONAL_CREDENTIALS,
                        CMD_CSR_REQUEST,
                    )
                    .map_err(ControllerError::from)?
                    .data(|w| {
                        // CommandFields struct at CmdDataTag::Data
                        // containing field 0: CSRNonce (32-byte octstr).
                        w.start_struct(&TLVTag::Context(CmdDataTag::Data as u8))?;
                        w.str(&TLVTag::Context(0), csr_nonce)?;
                        w.end_container()?;
                        Ok(())
                    })
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?;
            }
            TxOutcome::GotResponse(c) => break c,
        }
    };

    // Walk response chunks, extract the first CSRResponse payload, then
    // drain whatever's left for clean exchange teardown.
    let mut payload: Option<CsrPayload> = None;
    loop {
        if payload.is_none() {
            if let Some(resp) = chunk.response().map_err(ControllerError::from)? {
                if let Some((_endpoint, result)) = resp
                    .responses::<CSRResponse>(CL_OPERATIONAL_CREDENTIALS, CMD_CSR_RESPONSE)
                    .next()
                {
                    match result {
                        Ok(csr_resp) => {
                            let nocsr_bytes =
                                csr_resp.nocsr_elements().map_err(ControllerError::from)?;
                            let sig_bytes = csr_resp
                                .attestation_signature()
                                .map_err(ControllerError::from)?;
                            let mut nocsr: heapless::Vec<u8, MAX_NOCSR_ELEMENTS_LEN> =
                                heapless::Vec::new();
                            nocsr.extend_from_slice(nocsr_bytes.0).map_err(|_| {
                                ControllerError::Inner(Error::new(
                                    crate::error::ErrorCode::BufferTooSmall,
                                ))
                            })?;
                            let mut sig: heapless::Vec<u8, 64> = heapless::Vec::new();
                            sig.extend_from_slice(sig_bytes.0).map_err(|_| {
                                ControllerError::Inner(Error::new(
                                    crate::error::ErrorCode::BufferTooSmall,
                                ))
                            })?;
                            payload = Some(CsrPayload {
                                nocsr_elements: nocsr,
                                attestation_signature: sig,
                            });
                        }
                        Err(e) => return Err(ControllerError::Inner(e)),
                    }
                }
            }
        }
        match chunk.complete().await.map_err(ControllerError::from)? {
            Some(next) => chunk = next,
            None => break,
        }
    }
    payload.ok_or(ControllerError::PaseFailed)
}

/// Result of a successful AddNOC.
pub struct AddNocResult {
    /// Fabric slot the device assigned us. Persist this alongside the
    /// device's NodeID — it's needed for any subsequent UpdateNOC /
    /// RemoveFabric operations.
    pub fabric_index: u8,
}

/// Invoke `OperationalCredentials::AddNOC(noc, icac?, ipk, admin_subject,
/// admin_vendor_id)` on endpoint 0 over the PASE-secured exchange.
/// Returns the device-assigned FabricIndex.
///
/// `icac` may be empty when the controller signs NOCs directly from the
/// Root CA (the simpler chain — what `FabricCredentials::new` produces
/// before `enable_icac` is called).
pub async fn add_noc(
    matter: &Matter<'_>,
    noc: &[u8],
    icac: &[u8],
    ipk: &[u8],
    admin_case_subject: u64,
    admin_vendor_id: u16,
) -> Result<AddNocResult, ControllerError> {
    use crate::dm::clusters::noc::NOCResponse;
    use crate::error::Error;

    let exchange = Exchange::initiate(matter, 0, 0, true)
        .await
        .map_err(ControllerError::from)?;
    let mut sender = exchange
        .invoke_sender(None)
        .await
        .map_err(ControllerError::from)?;
    let mut chunk = loop {
        match sender.tx().await.map_err(ControllerError::from)? {
            TxOutcome::BuildRequest(builder) => {
                sender = builder
                    .suppress_response(false)
                    .map_err(ControllerError::from)?
                    .timed_request(false)
                    .map_err(ControllerError::from)?
                    .invoke_requests()
                    .map_err(ControllerError::from)?
                    .push()
                    .map_err(ControllerError::from)?
                    .path(
                        COMMISSIONING_ENDPOINT,
                        CL_OPERATIONAL_CREDENTIALS,
                        CMD_ADD_NOC,
                    )
                    .map_err(ControllerError::from)?
                    .data(|w| {
                        // CommandFields struct at CmdDataTag::Data.
                        // Fields per Matter §11.18.6.8:
                        //   0: NOCValue (octstr400)
                        //   1: ICACValue (octstr400) — present even if empty?
                        //   2: IPKValue (octstr16)
                        //   3: CaseAdminSubject (NodeID = u64)
                        //   4: AdminVendorId (u16)
                        w.start_struct(&TLVTag::Context(CmdDataTag::Data as u8))?;
                        w.str(&TLVTag::Context(0), noc)?;
                        w.str(&TLVTag::Context(1), icac)?;
                        w.str(&TLVTag::Context(2), ipk)?;
                        w.u64(&TLVTag::Context(3), admin_case_subject)?;
                        w.u16(&TLVTag::Context(4), admin_vendor_id)?;
                        w.end_container()?;
                        Ok(())
                    })
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?;
            }
            TxOutcome::GotResponse(c) => break c,
        }
    };

    let mut result: Option<AddNocResult> = None;
    loop {
        if result.is_none() {
            if let Some(resp) = chunk.response().map_err(ControllerError::from)? {
                if let Some((_endpoint, r)) = resp
                    .responses::<NOCResponse>(CL_OPERATIONAL_CREDENTIALS, CMD_NOC_RESPONSE)
                    .next()
                {
                    match r {
                        Ok(noc_resp) => {
                            let status = noc_resp.status_code().map_err(ControllerError::from)?;
                            // NodeOperationalCertStatusEnum::Ok = 0
                            if (status as u8) != 0 {
                                return Err(ControllerError::AddNocRejected);
                            }
                            let fabric_index = noc_resp
                                .fabric_index()
                                .map_err(ControllerError::from)?
                                .ok_or(ControllerError::AddNocRejected)?;
                            result = Some(AddNocResult { fabric_index });
                        }
                        Err(e) => return Err(ControllerError::Inner(e)),
                    }
                }
            }
        }
        match chunk.complete().await.map_err(ControllerError::from)? {
            Some(next) => chunk = next,
            None => break,
        }
    }
    let _ = Error::new(crate::error::ErrorCode::NoExchange); // silence unused import
    result.ok_or(ControllerError::AddNocRejected)
}

/// Invoke `OperationalCredentials::AddTrustedRootCertificate(rcac_tlv)`
/// on endpoint 0. Installs our fabric's Root CA on the device so the
/// subsequent AddNOC's certificate chain validates.
///
/// Response is status-only (no payload). Treating reachable-completion
/// as success — future enhancement would decode the StatusResponse and
/// surface non-success codes.
async fn add_trusted_root_certificate(
    matter: &Matter<'_>,
    rcac_tlv: &[u8],
) -> Result<(), ControllerError> {
    let exchange = Exchange::initiate(matter, 0, 0, true)
        .await
        .map_err(ControllerError::from)?;
    let mut sender = exchange
        .invoke_sender(None)
        .await
        .map_err(ControllerError::from)?;
    let mut chunk = loop {
        match sender.tx().await.map_err(ControllerError::from)? {
            TxOutcome::BuildRequest(builder) => {
                sender = builder
                    .suppress_response(false)
                    .map_err(ControllerError::from)?
                    .timed_request(false)
                    .map_err(ControllerError::from)?
                    .invoke_requests()
                    .map_err(ControllerError::from)?
                    .push()
                    .map_err(ControllerError::from)?
                    .path(
                        COMMISSIONING_ENDPOINT,
                        CL_OPERATIONAL_CREDENTIALS,
                        CMD_ADD_TRUSTED_ROOT_CERTIFICATE,
                    )
                    .map_err(ControllerError::from)?
                    .data(|w| {
                        // CommandFields struct at CmdDataTag::Data
                        // containing field 0: RootCACertificate (octstr).
                        w.start_struct(&TLVTag::Context(CmdDataTag::Data as u8))?;
                        w.str(&TLVTag::Context(0), rcac_tlv)?;
                        w.end_container()?;
                        Ok(())
                    })
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?;
            }
            TxOutcome::GotResponse(c) => break c,
        }
    };
    while let Some(next) = chunk.complete().await.map_err(ControllerError::from)? {
        chunk = next;
    }
    Ok(())
}

/// Invoke `GeneralCommissioning::CommissioningComplete()` on endpoint 0.
/// No fields. Marks the end of commissioning — the device disarms its
/// fail-safe, swaps from PASE to its operational identity, and begins
/// announcing on the operational network.
///
/// After this returns, the PASE session should be torn down by the
/// caller and operational discovery + CASE should begin.
async fn commissioning_complete(matter: &Matter<'_>) -> Result<(), ControllerError> {
    let exchange = Exchange::initiate(matter, 0, 0, true)
        .await
        .map_err(ControllerError::from)?;
    let mut sender = exchange
        .invoke_sender(None)
        .await
        .map_err(ControllerError::from)?;
    let mut chunk = loop {
        match sender.tx().await.map_err(ControllerError::from)? {
            TxOutcome::BuildRequest(builder) => {
                sender = builder
                    .suppress_response(false)
                    .map_err(ControllerError::from)?
                    .timed_request(false)
                    .map_err(ControllerError::from)?
                    .invoke_requests()
                    .map_err(ControllerError::from)?
                    .push()
                    .map_err(ControllerError::from)?
                    .path(
                        COMMISSIONING_ENDPOINT,
                        CL_GENERAL_COMMISSIONING,
                        CMD_COMMISSIONING_COMPLETE,
                    )
                    .map_err(ControllerError::from)?
                    .data(|w| {
                        // CommissioningComplete has no fields; emit an
                        // empty CommandFields struct so the TLV shape
                        // matches the schema.
                        w.start_struct(&TLVTag::Context(CmdDataTag::Data as u8))?;
                        w.end_container()?;
                        Ok(())
                    })
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?
                    .end()
                    .map_err(ControllerError::from)?;
            }
            TxOutcome::GotResponse(c) => break c,
        }
    };
    while let Some(next) = chunk.complete().await.map_err(ControllerError::from)? {
        chunk = next;
    }
    Ok(())
}

/// Decoded NOCSRElements TLV (Matter §11.18.6.5.2).
///
/// The device returns this inside the CSRResponse — it's the signed
/// payload the controller will hand to its FabricCredentials to mint a
/// NOC. We must verify `csr_nonce` matches the nonce we sent in
/// CSRRequest before trusting any of the contents.
pub struct DecodedNocsr<'a> {
    /// PKCS#10 CertificationRequest, DER-encoded. Hand straight to
    /// `FabricCredentials::generate_device_credentials`.
    pub csr_der: &'a [u8],
    /// 32-byte nonce. Must equal the one passed to `csr_request`.
    pub csr_nonce: &'a [u8],
}

/// Walk a NOCSRElements TLV blob and pull out the CSR DER + nonce.
///
/// Spec shape (1-indexed context tags):
/// ```text
/// struct NOCSRElements {
///     octstr csr              = 1,
///     octstr CSRNonce         = 2,
///     octstr vendor_reserved1 = 3 [optional],
///     octstr vendor_reserved2 = 4 [optional],
///     octstr vendor_reserved3 = 5 [optional],
/// }
/// ```
pub fn decode_nocsr_elements(blob: &[u8]) -> Result<DecodedNocsr<'_>, ControllerError> {
    use crate::tlv::TLVElement;
    let root = TLVElement::new(blob)
        .structure()
        .map_err(ControllerError::from)?;
    let csr_der = root
        .ctx(1)
        .map_err(ControllerError::from)?
        .str()
        .map_err(ControllerError::from)?;
    let csr_nonce = root
        .ctx(2)
        .map_err(ControllerError::from)?
        .str()
        .map_err(ControllerError::from)?;
    Ok(DecodedNocsr { csr_der, csr_nonce })
}

/// End-to-end commissioning orchestration over an existing PASE session.
///
/// Pre-condition: caller has already driven `PaseInitiator::initiate` on
/// `matter` against the device. From here:
///
///   1. `ArmFailSafe(fail_safe_secs, breadcrumb=0)` — opens the
///      commissioning window the device gates the rest behind.
///   2. `CSRRequest(random 32B nonce)` — receive NOCSRElements +
///      attestation signature.
///   3. Decode NOCSRElements, **verify nonce matches**.
///   4. `FabricCredentials::generate_device_credentials(csr_der, &[])` —
///      issue an operational NOC chain signed by our RCAC.
///   5. `AddTrustedRootCertificate(rcac)` — install our root on the
///      device so the chain validates locally.
///   6. `AddNOC(noc, icac?, ipk, admin_subject, admin_vendor_id)` —
///      device assigns us a FabricIndex.
///   7. *(Network commissioning happens here for Thread/WiFi devices —
///      not driven by this helper. For on-network devices the device
///      is already on its operational network and this step is a
///      no-op.)*
///   8. `CommissioningComplete()` — device disarms fail-safe, swaps to
///      operational identity, begins announcing on the operational
///      network.
///
/// On success returns the issued NOC bundle + the FabricIndex the
/// device assigned. Caller persists this alongside the device's NodeID
/// and switches to CASE for all subsequent communication.
pub struct PaseCommissionResult {
    pub fabric_index: u8,
    pub device_node_id: u64,
    pub noc_der: heapless::Vec<u8, 400>,
    pub icac_der: heapless::Vec<u8, 400>,
}

pub async fn commission_pase<C: Crypto>(
    matter: &crate::Matter<'_>,
    crypto: &C,
    fabric_creds: &mut FabricCredentials,
    admin_case_subject: u64,
    admin_vendor_id: u16,
    fail_safe_secs: u16,
) -> Result<PaseCommissionResult, ControllerError> {
    use crate::crypto::RngCore;

    // 1. ArmFailSafe(fail_safe_secs, breadcrumb=0).
    arm_fail_safe(matter, fail_safe_secs, 0).await?;

    // 2. CSRRequest with a fresh random nonce (drawn from the
    //    backend-provided CryptoRng — Matter §11.18.6.5 mandates a
    //    fresh nonce per CSRRequest to prevent replay).
    let mut csr_nonce = [0u8; 32];
    crypto
        .rand()
        .map_err(ControllerError::from)?
        .fill_bytes(&mut csr_nonce);
    let csr_payload = csr_request(matter, &csr_nonce).await?;

    // 3. Decode NOCSRElements, verify the device echoed our nonce.
    let nocsr = decode_nocsr_elements(&csr_payload.nocsr_elements)?;
    if nocsr.csr_nonce != &csr_nonce[..] {
        return Err(ControllerError::PaseFailed);
    }

    // 4. Issue NOC against our fabric's RCAC.
    let device_creds = fabric_creds
        .generate_device_credentials(crypto, nocsr.csr_der, &[])
        .map_err(ControllerError::from)?;

    // 5. AddTrustedRootCertificate — install RCAC so the chain
    //    validates on the device.
    add_trusted_root_certificate(matter, fabric_creds.root_cert()).await?;

    // 6. AddNOC.
    let icac_bytes: &[u8] = device_creds
        .icac
        .as_ref()
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    let ipk_ref = fabric_creds.ipk();
    let result = add_noc(
        matter,
        &device_creds.noc,
        icac_bytes,
        ipk_ref.access(),
        admin_case_subject,
        admin_vendor_id,
    )
    .await?;

    // 7. CommissioningComplete.
    commissioning_complete(matter).await?;

    let mut noc_out: heapless::Vec<u8, 400> = heapless::Vec::new();
    noc_out.extend_from_slice(&device_creds.noc).map_err(|_| {
        ControllerError::Inner(crate::error::Error::new(
            crate::error::ErrorCode::BufferTooSmall,
        ))
    })?;
    let mut icac_out: heapless::Vec<u8, 400> = heapless::Vec::new();
    if let Some(icac) = device_creds.icac.as_ref() {
        icac_out.extend_from_slice(icac).map_err(|_| {
            ControllerError::Inner(crate::error::Error::new(
                crate::error::ErrorCode::BufferTooSmall,
            ))
        })?;
    }

    Ok(PaseCommissionResult {
        fabric_index: result.fabric_index,
        device_node_id: device_creds.node_id,
        noc_der: noc_out,
        icac_der: icac_out,
    })
}
