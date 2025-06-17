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
pub use self::dummy::CryptoSpake2;
#[cfg(all(feature = "mbedtls", target_os = "espidf"))]
pub use self::esp_mbedtls::CryptoSpake2;
#[cfg(all(feature = "mbedtls", not(target_os = "espidf")))]
pub use self::mbedtls::CryptoSpake2;
#[cfg(feature = "openssl")]
pub use self::openssl::CryptoSpake2;
#[cfg(feature = "rustcrypto")]
pub use self::rustcrypto::CryptoSpake2;

#[cfg(not(any(feature = "openssl", feature = "mbedtls", feature = "rustcrypto")))]
mod dummy;
#[cfg(all(feature = "mbedtls", target_os = "espidf"))]
mod esp_mbedtls;
#[cfg(all(feature = "mbedtls", not(target_os = "espidf")))]
mod mbedtls;
#[cfg(feature = "openssl")]
mod openssl;
#[cfg(feature = "rustcrypto")]
mod rustcrypto;
