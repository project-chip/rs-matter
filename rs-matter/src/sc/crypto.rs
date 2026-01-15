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

#[cfg(not(any(feature = "rustcrypto", feature = "mbedtls", feature = "openssl")))]
pub use self::dummy::CryptoSpake2;
#[cfg(all(feature = "mbedtls", not(feature = "rustcrypto")))]
pub use self::mbedtls::CryptoSpake2;
#[cfg(all(
    feature = "openssl",
    not(any(feature = "rustcrypto", feature = "mbedtls"))
))]
pub use self::openssl::CryptoSpake2;
#[cfg(feature = "rustcrypto")]
pub use self::rustcrypto::CryptoSpake2;

#[cfg(not(any(feature = "rustcrypto", feature = "mbedtls", feature = "openssl")))]
mod dummy;
#[cfg(all(feature = "mbedtls", not(feature = "rustcrypto")))]
mod mbedtls;
#[cfg(all(
    feature = "openssl",
    not(any(feature = "rustcrypto", feature = "mbedtls"))
))]
mod openssl;
#[cfg(feature = "rustcrypto")]
mod rustcrypto;
