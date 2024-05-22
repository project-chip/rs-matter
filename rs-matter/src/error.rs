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

use core::{array::TryFromSliceError, fmt, str::Utf8Error};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorCode {
    AttributeNotFound,
    AttributeIsCustom,
    BufferTooSmall,
    ClusterNotFound,
    CommandNotFound,
    Duplicate,
    EndpointNotFound,
    InvalidAction,
    InvalidCommand,
    InvalidDataType,
    UnsupportedAccess,
    ResourceExhausted,
    Busy,
    DataVersionMismatch,
    Crypto,
    TLSStack,
    BtpError,
    MdnsError,
    NoCommand,
    NoEndpoint,
    NoExchange,
    NoFabricId,
    NoHandler,
    NoNetworkInterface,
    NoNodeId,
    NoMemory,
    NoSession,
    NoSpace,
    NoSpaceExchanges,
    NoSpaceSessions,
    NoSpaceAckTable,
    NoSpaceRetransTable,
    NoTagFound,
    NotFound,
    PacketPoolExhaust,
    StdIoError,
    SysTimeFail,
    Invalid,
    InvalidAAD,
    InvalidData,
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
    #[cfg(all(feature = "std", feature = "backtrace"))]
    inner: Option<Box<dyn std::error::Error + Send>>,
}

impl Error {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            #[cfg(all(feature = "std", feature = "backtrace"))]
            backtrace: std::backtrace::Backtrace::capture(),
            #[cfg(all(feature = "std", feature = "backtrace"))]
            inner: None,
        }
    }

    #[cfg(all(feature = "std", feature = "backtrace"))]
    pub fn new_with_details(
        code: ErrorCode,
        detailed_err: Box<dyn std::error::Error + Send>,
    ) -> Self {
        Self {
            code,
            #[cfg(all(feature = "std", feature = "backtrace"))]
            backtrace: std::backtrace::Backtrace::capture(),
            #[cfg(all(feature = "std", feature = "backtrace"))]
            inner: Some(detailed_err),
        }
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    #[cfg(all(feature = "std", feature = "backtrace"))]
    pub const fn backtrace(&self) -> &std::backtrace::Backtrace {
        &self.backtrace
    }

    #[cfg(all(feature = "std", feature = "backtrace"))]
    pub fn details(&self) -> Option<&(dyn std::error::Error + Send)> {
        self.inner.as_ref().map(|err| err.as_ref())
    }

    pub fn remap<F>(self, matcher: F, to: Self) -> Self
    where
        F: FnOnce(&Self) -> bool,
    {
        if matcher(&self) {
            to
        } else {
            self
        }
    }

    pub fn map_invalid(self, to: Self) -> Self {
        self.remap(
            |e| matches!(e.code(), ErrorCode::Invalid | ErrorCode::InvalidData),
            to,
        )
    }

    pub fn map_invalid_command(self) -> Self {
        self.map_invalid(Error::new(ErrorCode::InvalidCommand))
    }

    pub fn map_invalid_action(self) -> Self {
        self.map_invalid(Error::new(ErrorCode::InvalidAction))
    }

    pub fn map_invalid_data_type(self) -> Self {
        self.map_invalid(Error::new(ErrorCode::InvalidDataType))
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

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        ::log::error!("Error in TLS: {}", e);
        Self::new(ErrorCode::TLSStack)
    }
}

#[cfg(all(feature = "mbedtls", not(target_os = "espidf")))]
impl From<mbedtls::Error> for Error {
    fn from(e: mbedtls::Error) -> Self {
        ::log::error!("Error in TLS: {}", e);
        Self::new(ErrorCode::TLSStack)
    }
}

#[cfg(feature = "rustcrypto")]
impl From<ccm::aead::Error> for Error {
    fn from(_e: ccm::aead::Error) -> Self {
        Self::new(ErrorCode::Crypto)
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
        #[cfg(all(feature = "std", feature = "backtrace"))]
        {
            write!(
                f,
                "{:?}: {}",
                self.code(),
                self.inner
                    .as_ref()
                    .map_or(String::new(), |err| { err.to_string() })
            )
        }
        #[cfg(not(all(feature = "std", feature = "backtrace")))]
        {
            write!(f, "{:?}", self.code())
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
