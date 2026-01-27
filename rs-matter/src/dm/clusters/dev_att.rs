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

use crate::crypto::{CanonPkcPublicKey, CanonPkcSecretKey};

/// The Device Attestation trait
///
/// Objects that implement this trait allow the Matter subsystem to query the object
/// for the Device Attestation data that is programmed in the Matter device.
pub trait DeviceAttestation {
    /// Get the Certificate Declaration
    fn cert_declaration(&self) -> &[u8];

    /// Get the Product Attestation Intermediary Certificate
    fn pai(&self) -> &[u8];

    /// Get the Device Attestation Certificate
    fn dac(&self) -> &[u8];

    /// Get the Device Attestation Certificate Public Key
    fn dac_pub_key(&self) -> &CanonPkcPublicKey;

    /// Get the Device Attestation Certificate Private Key
    fn dac_priv_key(&self) -> &CanonPkcSecretKey;
}

impl<T> DeviceAttestation for &T
where
    T: DeviceAttestation,
{
    fn cert_declaration(&self) -> &[u8] {
        (*self).cert_declaration()
    }

    fn pai(&self) -> &[u8] {
        (*self).pai()
    }

    fn dac(&self) -> &[u8] {
        (*self).dac()
    }

    fn dac_pub_key(&self) -> &CanonPkcPublicKey {
        (*self).dac_pub_key()
    }

    fn dac_priv_key(&self) -> &CanonPkcSecretKey {
        (*self).dac_priv_key()
    }
}

impl DeviceAttestation for &dyn DeviceAttestation {
    fn cert_declaration(&self) -> &[u8] {
        (*self).cert_declaration()
    }

    fn pai(&self) -> &[u8] {
        (*self).pai()
    }

    fn dac(&self) -> &[u8] {
        (*self).dac()
    }

    fn dac_pub_key(&self) -> &CanonPkcPublicKey {
        (*self).dac_pub_key()
    }

    fn dac_priv_key(&self) -> &CanonPkcSecretKey {
        (*self).dac_priv_key()
    }
}
