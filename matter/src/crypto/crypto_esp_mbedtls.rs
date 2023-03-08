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

use log::error;

use crate::error::Error;

use super::CryptoKeyPair;

pub fn hkdf_sha256(_salt: &[u8], _ikm: &[u8], _info: &[u8], _key: &mut [u8]) -> Result<(), Error> {
    error!("This API should never get called");
    Ok(())
}

#[derive(Clone)]
pub struct Sha256 {}

impl Sha256 {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {})
    }

    pub fn update(&mut self, _data: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    pub fn finish(self, _digest: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }
}

pub struct HmacSha256 {}

impl HmacSha256 {
    pub fn new(_key: &[u8]) -> Result<Self, Error> {
        error!("This API should never get called");
        Ok(Self {})
    }

    pub fn update(&mut self, _data: &[u8]) -> Result<(), Error> {
        error!("This API should never get called");
        Ok(())
    }

    pub fn finish(self, _out: &mut [u8]) -> Result<(), Error> {
        error!("This API should never get called");
        Ok(())
    }
}

pub struct KeyPair {}

impl KeyPair {
    pub fn new() -> Result<Self, Error> {
        error!("This API should never get called");

        Ok(Self {})
    }

    pub fn new_from_components(_pub_key: &[u8], priv_key: &[u8]) -> Result<Self, Error> {
        error!("This API should never get called");

        Ok(Self {})
    }

    pub fn new_from_public(pub_key: &[u8]) -> Result<Self, Error> {
        error!("This API should never get called");

        Ok(Self {})
    }
}

impl CryptoKeyPair for KeyPair {
    fn get_private_key(&self, priv_key: &mut [u8]) -> Result<usize, Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn get_csr<'a>(&self, _out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn get_public_key(&self, _pub_key: &mut [u8]) -> Result<usize, Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn derive_secret(self, _peer_pub_key: &[u8], _secret: &mut [u8]) -> Result<usize, Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn sign_msg(&self, _msg: &[u8], _signature: &mut [u8]) -> Result<usize, Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn verify_msg(&self, _msg: &[u8], _signature: &[u8]) -> Result<(), Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
}

pub fn pbkdf2_hmac(pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) -> Result<(), Error> {
    error!("This API should never get called");

    Ok(())
}

pub fn encrypt_in_place(
    _key: &[u8],
    _nonce: &[u8],
    _ad: &[u8],
    _data: &mut [u8],
    _data_len: usize,
) -> Result<usize, Error> {
    Ok(0)
}

pub fn decrypt_in_place(
    _key: &[u8],
    _nonce: &[u8],
    _ad: &[u8],
    _data: &mut [u8],
) -> Result<usize, Error> {
    Ok(0)
}
