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

//! A dummy crypto backend
//!
//! NOTE: The dummy backend _cannot_ be used for running `rs-matter`, even in test mode.
//! The moment any crypto operation is invoked, it will panic.
//!
//! The module has a limited use for measuring `rs-matter` flash and RAM footprint without
//! pulling in any crypto dependencies. Note that this module might be retired in future
//! and `rustcrypto` might be used as the default backend.

use crate::error::Error;
use crate::utils::rand::Rand;

#[allow(non_snake_case)]
pub struct CryptoSpake2(());

impl CryptoSpake2 {
    #[allow(non_snake_case)]
    pub fn new() -> Result<Self, Error> {
        Ok(Self(()))
    }

    pub fn set_w0_from_w0s(&mut self, _w0s: &[u8]) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn set_w1_from_w1s(&mut self, _w1s: &[u8]) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn set_w0(&mut self, _w0: &[u8]) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn set_w1(&mut self, _w1: &[u8]) -> Result<(), Error> {
        unimplemented!()
    }

    #[allow(non_snake_case)]
    pub fn set_L(&mut self, _l: &[u8]) -> Result<(), Error> {
        unimplemented!()
    }

    #[allow(non_snake_case)]
    #[allow(dead_code)]
    pub fn set_L_from_w1s(&mut self, _w1s: &[u8]) -> Result<(), Error> {
        unimplemented!()
    }

    #[allow(non_snake_case)]
    pub fn get_pB(&mut self, _pB: &mut [u8], _rand: Rand) -> Result<(), Error> {
        unimplemented!()
    }

    #[allow(non_snake_case)]
    pub fn get_TT_as_verifier(
        &mut self,
        _context: &[u8],
        _pA: &[u8],
        _pB: &[u8],
        _out: &mut [u8],
    ) -> Result<(), Error> {
        unimplemented!()
    }
}
