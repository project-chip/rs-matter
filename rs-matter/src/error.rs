/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

use core::{array::TryFromSliceError, fmt, str::Utf8Error};

#[cfg(all(feature = "alloc", feature = "backtrace"))]
use alloc::{boxed::Box, string::ToString};

// TODO: The error code enum is in a need of an overhaul
//
// We need separate error enums per chunks of functionality
// and a way to map them to concrete IM and SC status codes
//
// This is a non-trivial effort though as we need to also generify
// the returned error type of all APIs that take callbacks that return errors
// (i.e., `Exchange::with_*`, `WriteBuf::append_with_buf` etc.)
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ErrorCode {
    AlreadyExists,
    AttributeNotFound,
    AttributeIsCustom,
    BufferTooSmall,
    ClusterNotFound,
    CommandNotFound,
    Duplicate,
    NodeNotFound,
    EndpointNotFound,
    EventNotFound,
    InvalidAction,
    InvalidCommand,
    FailSafeRequired,
    NeedsTimedInteraction,
    ConstraintError,
    DynamicConstraintError,
    InvalidDataType,
    UnsupportedAccess,
    ResourceExhausted,
    Busy,
    DataVersionMismatch,
    BtpError,
    MdnsError,
    NoCommand,
    NoEndpoint,
    NoExchange,
    NoFabricId,
    NoHandler,
    NoNetworkInterface,
    DBusError,
    NoNodeId,
    NoMemory,
    NoSession,
    // TODO: Rename to `TLVNoWriteSpace` or similar, so that it is clear
    // that this error code should _only_ be used when writing a TLV using
    // a `TLVWrite` instance which happens to run out of space
    //
    // All other cases of running out of space should use the generic:
    // - `ResourceExhausted` (when number of fabrics, ACLs, sessions or exchanges becomes too big)
    // - `BufferTooSmall` or `ConstraintError` when other internal buffers don't fit the data
    // - ... or use-case-specific error codes like `NoSpaceExchanges` and `NoSpaceSessions`.
    NoSpace,
    NoSpaceExchanges,
    NoSpaceSessions,
    TxTimeout,
    RxTimeout,
    NoTagFound,
    NotFound,
    PacketPoolExhaust,
    StdIoError,
    SysTimeFail,
    Invalid,
    InvalidAAD,
    InvalidData,
    /// An element was received on a transport that cannot carry it - a command
    /// with the `L` (Large Message) quality over a transport that is not
    /// large-message capable. Maps to `IMStatusCode::InvalidTransportType`.
    InvalidTransportType,
    InvalidKeyLength,
    InvalidOpcode,
    InvalidProto,
    InvalidPeerAddr,
    // Invalid Auth Key in the Matter Certificate
    InvalidAuthKey,
    InvalidSignature,
    InvalidState,
    InvalidTime,
    InvalidArgument,
    RwLock,
    TLVNotFound,
    TLVTypeMismatch,
    TruncatedPacket,
    Utf8Fail,
    GennCommInvalidAuthentication,
    NocInvalidNoc,
    NocInvalidPublicKey,
    NocMissingCsr,
    NocFabricTableFull,
    NocFabricConflict,
    NocLabelConflict,
    NocInvalidFabricIndex,
    NocInvalidAdminSubject,
    Failure,
    // Certification Declaration errors
    CdInvalidFormat,
    CdInvalidSignature,
    CdSigningKeyNotFound,
    CdInvalidVendorId,
    CdInvalidProductId,
    CdInvalidPaa,
}

impl From<ErrorCode> for Error {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

pub struct Error {
    code: ErrorCode,
    #[cfg(all(feature = "std", feature = "backtrace"))]
    backtrace: std::backtrace::Backtrace,
    #[cfg(all(feature = "alloc", feature = "backtrace"))]
    inner: Option<Box<dyn core::error::Error + Send + Sync>>,
}

impl Error {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            #[cfg(all(feature = "std", feature = "backtrace"))]
            backtrace: std::backtrace::Backtrace::capture(),
            #[cfg(all(feature = "alloc", feature = "backtrace"))]
            inner: None,
        }
    }

    #[cfg(all(feature = "alloc", feature = "backtrace"))]
    pub fn new_with_details(
        code: ErrorCode,
        detailed_err: Box<dyn core::error::Error + Send + Sync>,
    ) -> Self {
        Self {
            code,
            #[cfg(feature = "std")]
            backtrace: std::backtrace::Backtrace::capture(),
            inner: Some(detailed_err),
        }
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Whether this error means the peer never answered.
    pub const fn is_peer_unresponsive(&self) -> bool {
        matches!(self.code, ErrorCode::TxTimeout | ErrorCode::RxTimeout)
    }

    #[cfg(all(feature = "std", feature = "backtrace"))]
    pub const fn backtrace(&self) -> &std::backtrace::Backtrace {
        &self.backtrace
    }

    #[cfg(all(feature = "alloc", feature = "backtrace"))]
    pub fn details(&self) -> Option<&(dyn core::error::Error + Send + Sync)> {
        self.inner.as_ref().map(|err| err.as_ref())
    }
}

#[cfg(all(feature = "std", feature = "backtrace"))]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new_with_details(ErrorCode::StdIoError, Box::new(e))
    }
}

#[cfg(all(feature = "std", not(feature = "backtrace")))]
impl From<std::io::Error> for Error {
    fn from(_e: std::io::Error) -> Self {
        Self::new(ErrorCode::StdIoError)
    }
}

#[cfg(feature = "std")]
impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_e: std::sync::PoisonError<T>) -> Self {
        Self::new(ErrorCode::RwLock)
    }
}

#[cfg(all(
    feature = "os",
    target_os = "linux",
    feature = "bluer",
    not(feature = "backtrace")
))]
impl From<bluer::Error> for Error {
    fn from(e: bluer::Error) -> Self {
        // Log the error given that we lose all context from the
        // original error here
        error!("Error in BTP: {}", display2format!(e));
        Self::new(ErrorCode::BtpError)
    }
}

#[cfg(all(
    feature = "os",
    target_os = "linux",
    feature = "bluer",
    feature = "backtrace"
))]
impl From<bluer::Error> for Error {
    fn from(e: bluer::Error) -> Self {
        Self::new_with_details(ErrorCode::BtpError, Box::new(e))
    }
}

#[cfg(feature = "std")]
impl From<std::time::SystemTimeError> for Error {
    fn from(_e: std::time::SystemTimeError) -> Self {
        Error::new(ErrorCode::SysTimeFail)
    }
}

impl From<TryFromSliceError> for Error {
    fn from(_e: TryFromSliceError) -> Self {
        Self::new(ErrorCode::Invalid)
    }
}

impl From<Utf8Error> for Error {
    fn from(_e: Utf8Error) -> Self {
        Self::new(ErrorCode::Utf8Fail)
    }
}

impl<T: num_enum::TryFromPrimitive> From<num_enum::TryFromPrimitiveError<T>> for Error {
    fn from(_e: num_enum::TryFromPrimitiveError<T>) -> Self {
        Self::new(ErrorCode::Invalid)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(not(all(feature = "std", feature = "backtrace")))]
        {
            write!(f, "Error::{}", self)?;
        }

        #[cfg(all(feature = "std", feature = "backtrace"))]
        {
            writeln!(f, "Error::{} {{", self)?;
            write!(f, "{}", self.backtrace())?;
            writeln!(f, "}}")?;
        }

        Ok(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(all(feature = "alloc", feature = "backtrace"))]
        {
            let err_msg = self
                .inner
                .as_ref()
                .map_or(Default::default(), |err| err.to_string());

            if err_msg.is_empty() {
                write!(f, "{:?}", self.code())
            } else {
                write!(f, "{:?}: {}", self.code(), err_msg)
            }
        }
        #[cfg(not(all(feature = "alloc", feature = "backtrace")))]
        {
            write!(f, "{:?}", self.code())
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Error {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "{:?}", self.code())
    }
}

impl core::error::Error for Error {
    #[cfg(all(feature = "alloc", feature = "backtrace"))]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.inner
            .as_ref()
            .map(|e| e.as_ref() as &(dyn core::error::Error + 'static))
    }
}

impl embedded_io_async::Error for Error {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        embedded_io_async::ErrorKind::Other
    }
}

#[cfg(test)]
mod tests {
    use core::str::from_utf8;

    use super::{Error, ErrorCode};

    /// A representative slice of the error codes, covering the first and last
    /// variants and the ones with special `From` mappings.
    const CODES: &[ErrorCode] = &[
        ErrorCode::AlreadyExists,
        ErrorCode::AttributeNotFound,
        ErrorCode::BufferTooSmall,
        ErrorCode::ConstraintError,
        ErrorCode::Invalid,
        ErrorCode::InvalidData,
        ErrorCode::InvalidTransportType,
        ErrorCode::NoSpace,
        ErrorCode::TxTimeout,
        ErrorCode::RxTimeout,
        ErrorCode::StdIoError,
        ErrorCode::SysTimeFail,
        ErrorCode::RwLock,
        ErrorCode::Utf8Fail,
        ErrorCode::Failure,
        ErrorCode::CdInvalidPaa,
    ];

    #[test]
    fn code_roundtrips_through_error() {
        for code in CODES {
            let err = Error::new(*code);
            assert_eq!(err.code(), *code);

            let err: Error = (*code).into();
            assert_eq!(err.code(), *code);

            // `?` on an `ErrorCode` works via the same `From`
            let res: Result<(), Error> = (|| {
                Err(*code)?;
                Ok(())
            })();
            assert_eq!(res.unwrap_err().code(), *code);
        }
    }

    #[test]
    fn error_code_equality_and_hash() {
        use std::collections::HashSet;

        assert_eq!(ErrorCode::NoSpace, ErrorCode::NoSpace);
        assert_ne!(ErrorCode::NoSpace, ErrorCode::NoSpaceExchanges);

        let set: HashSet<ErrorCode> = CODES.iter().copied().collect();
        assert_eq!(set.len(), CODES.len());

        // Copy semantics
        let a = ErrorCode::Busy;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn display_and_debug_do_not_panic() {
        for code in CODES {
            let err = Error::new(*code);

            let display = format!("{err}");
            let debug = format!("{err:?}");
            let code_debug = format!("{code:?}");

            // Display is the code's Debug name; Debug wraps it as `Error::<name>`
            assert!(
                display.starts_with(&code_debug),
                "{display} vs {code_debug}"
            );
            assert!(
                debug.starts_with(&format!("Error::{code_debug}")),
                "{debug}"
            );
        }
    }

    #[test]
    fn is_peer_unresponsive_only_for_timeouts() {
        assert!(Error::new(ErrorCode::TxTimeout).is_peer_unresponsive());
        assert!(Error::new(ErrorCode::RxTimeout).is_peer_unresponsive());

        for code in CODES {
            if !matches!(code, ErrorCode::TxTimeout | ErrorCode::RxTimeout) {
                assert!(!Error::new(*code).is_peer_unresponsive(), "{code:?}");
            }
        }
    }

    #[test]
    fn core_conversions() {
        let slice_err = <[u8; 4]>::try_from(&[1u8, 2, 3][..]).unwrap_err();
        assert_eq!(Error::from(slice_err).code(), ErrorCode::Invalid);

        let utf8_err = from_utf8(&[0xff, 0xfe]).unwrap_err();
        assert_eq!(Error::from(utf8_err).code(), ErrorCode::Utf8Fail);

        #[derive(Debug, Copy, Clone, num_enum::TryFromPrimitive)]
        #[repr(u8)]
        enum Small {
            _One = 1,
        }
        let prim_err = Small::try_from(9u8).unwrap_err();
        assert_eq!(Error::from(prim_err).code(), ErrorCode::Invalid);
    }

    #[test]
    fn error_is_a_core_error() {
        let err = Error::new(ErrorCode::Busy);
        let dyn_err: &dyn core::error::Error = &err;

        // Without details attached there is no source
        assert!(dyn_err.source().is_none());

        // `?` from an `Error` into a boxed error works
        let boxed: Box<dyn core::error::Error + Send + Sync> = Box::new(err);
        assert!(boxed.to_string().contains("Busy"));
    }

    #[test]
    fn embedded_io_error_kind_is_other() {
        use embedded_io_async::Error as _;

        assert_eq!(
            Error::new(ErrorCode::NoSpace).kind(),
            embedded_io_async::ErrorKind::Other
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn std_conversions() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err = Error::from(io);
        assert_eq!(err.code(), ErrorCode::StdIoError);

        let lock = std::sync::Mutex::new(());
        let poisoned = std::sync::PoisonError::new(lock.lock().unwrap());
        assert_eq!(Error::from(poisoned).code(), ErrorCode::RwLock);

        let time_err = std::time::UNIX_EPOCH
            .duration_since(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap_err();
        assert_eq!(Error::from(time_err).code(), ErrorCode::SysTimeFail);
    }

    #[cfg(all(feature = "alloc", feature = "backtrace"))]
    #[test]
    fn details_are_kept_and_displayed() {
        let err = Error::new(ErrorCode::Busy);
        assert!(err.details().is_none());
        assert_eq!(format!("{err}"), "Busy");

        let inner = std::io::Error::new(std::io::ErrorKind::Other, "disk on fire");
        let err = Error::new_with_details(ErrorCode::StdIoError, Box::new(inner));
        assert_eq!(err.code(), ErrorCode::StdIoError);
        assert!(err.details().unwrap().to_string().contains("disk on fire"));
        assert_eq!(format!("{err}"), "StdIoError: disk on fire");

        // The details are exposed as the `source`
        let dyn_err: &dyn core::error::Error = &err;
        assert!(dyn_err
            .source()
            .unwrap()
            .to_string()
            .contains("disk on fire"));

        // `From<std::io::Error>` also attaches the details under `backtrace`
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err = Error::from(io);
        assert!(err.details().unwrap().to_string().contains("gone"));
    }

    #[cfg(all(feature = "std", feature = "backtrace"))]
    #[test]
    fn backtrace_capture_does_not_panic() {
        let err = Error::new(ErrorCode::Failure);

        // Capture may be disabled by the environment; only its presence is checked
        let _ = err.backtrace().status();
        let _ = format!("{}", err.backtrace());

        // Debug embeds the backtrace block
        let debug = format!("{err:?}");
        assert!(debug.starts_with("Error::Failure {"));
        assert!(debug.trim_end().ends_with('}'));
    }
}
