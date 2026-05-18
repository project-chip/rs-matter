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

//! Controller-specific error type.

use crate::error::Error;

/// Errors produced by the controller-side commissioning flow.
///
/// Wraps the underlying rs-matter [`Error`] and adds context unique to
/// the controller role (which commissioning step rejected the request,
/// what the accessory returned, etc.). Variants are added as steps
/// land, hence `#[non_exhaustive]`.
#[derive(Debug)]
#[non_exhaustive]
pub enum ControllerError {
    /// Wrapped error from the rs-matter core (TLV, transport, IM).
    Inner(Error),

    /// PASE session establishment failed (wrong passcode, timeout,
    /// reply malformed, …) — or, by extension, any post-PASE invoke
    /// that returned an unparseable response.
    PaseFailed,

    /// `GeneralCommissioning::ArmFailSafe` returned a non-OK
    /// CommissioningErrorEnum, or the fail-safe expired during the
    /// commissioning window.
    FailSafeExpired,

    /// `OperationalCredentials::AddNOC` returned a non-OK
    /// NodeOperationalCertStatusEnum.
    AddNocRejected,
}

impl From<Error> for ControllerError {
    fn from(e: Error) -> Self {
        Self::Inner(e)
    }
}

impl core::fmt::Display for ControllerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inner(e) => write!(f, "matter: {:?}", e),
            Self::PaseFailed => write!(f, "PASE/post-PASE step failed"),
            Self::FailSafeExpired => write!(f, "ArmFailSafe failed or fail-safe expired"),
            Self::AddNocRejected => write!(f, "AddNOC rejected by accessory"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ControllerError {}
