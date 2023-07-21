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

#[cfg(not(any(feature = "openssl", feature = "mbedtls", feature = "rustcrypto")))]
pub use super::crypto_dummy::CryptoSpake2;
#[cfg(all(feature = "mbedtls", target_os = "espidf"))]
pub use super::crypto_esp_mbedtls::CryptoSpake2;
#[cfg(all(feature = "mbedtls", not(target_os = "espidf")))]
pub use super::crypto_mbedtls::CryptoSpake2;
#[cfg(feature = "openssl")]
pub use super::crypto_openssl::CryptoSpake2;
#[cfg(feature = "rustcrypto")]
pub use super::crypto_rustcrypto::CryptoSpake2;
