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

pub struct KeyPairDummy {}

impl KeyPairDummy {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {})
    }
}

impl CryptoKeyPair for KeyPairDummy {
    fn get_csr<'a>(&self, _out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn get_public_key(&self, _pub_key: &mut [u8]) -> Result<usize, Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn get_private_key(&self, _pub_key: &mut [u8]) -> Result<usize, Error> {
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
