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

use crate::{
    error::{Error, ErrorCode},
    utils::rand::Rand,
};

#[allow(non_snake_case)]
pub struct CryptoSpake2 {}

impl CryptoSpake2 {
    #[allow(non_snake_case)]
    pub fn new() -> Result<Self, Error> {
        Ok(Self {})
    }

    // Computes w0 from w0s respectively
    pub fn set_w0_from_w0s(&mut self, _w0s: &[u8]) -> Result<(), Error> {
        Err(ErrorCode::Invalid.into())
    }

    pub fn set_w1_from_w1s(&mut self, _w1s: &[u8]) -> Result<(), Error> {
        Err(ErrorCode::Invalid.into())
    }

    pub fn set_w0(&mut self, _w0: &[u8]) -> Result<(), Error> {
        Err(ErrorCode::Invalid.into())
    }

    pub fn set_w1(&mut self, _w1: &[u8]) -> Result<(), Error> {
        Err(ErrorCode::Invalid.into())
    }

    #[allow(non_snake_case)]
    pub fn set_L(&mut self, _l: &[u8]) -> Result<(), Error> {
        Err(ErrorCode::Invalid.into())
    }

    #[allow(non_snake_case)]
    #[allow(dead_code)]
    pub fn set_L_from_w1s(&mut self, _w1s: &[u8]) -> Result<(), Error> {
        Err(ErrorCode::Invalid.into())
    }

    #[allow(non_snake_case)]
    pub fn get_pB(&mut self, _pB: &mut [u8], _rand: Rand) -> Result<(), Error> {
        Err(ErrorCode::Invalid.into())
    }

    #[allow(non_snake_case)]
    pub fn get_TT_as_verifier(
        &mut self,
        _context: &[u8],
        _pA: &[u8],
        _pB: &[u8],
        _out: &mut [u8],
    ) -> Result<(), Error> {
        Err(ErrorCode::Invalid.into())
    }
}
