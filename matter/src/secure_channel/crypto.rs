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

use crate::error::Error;

// This trait allows us to switch between crypto providers like OpenSSL and mbedTLS for Spake2
// Currently this is only validate for a verifier(responder)

// A verifier will typically do:
// Step 1: w0 and L
//      set_w0_from_w0s
//      set_L
// Step 2: get_pB
// Step 3: get_TT_as_verifier(pA)
// Step 4: Computation of cA and cB happens outside since it doesn't use either BigNum or EcPoint
pub trait CryptoSpake2 {
    fn new() -> Result<Self, Error>
    where
        Self: Sized;

    fn set_w0_from_w0s(&mut self, w0s: &[u8]) -> Result<(), Error>;
    fn set_w1_from_w1s(&mut self, w1s: &[u8]) -> Result<(), Error>;
    fn set_w0(&mut self, w0: &[u8]) -> Result<(), Error>;
    fn set_w1(&mut self, w1: &[u8]) -> Result<(), Error>;

    #[allow(non_snake_case)]
    fn set_L(&mut self, w1s: &[u8]) -> Result<(), Error>;
    #[allow(non_snake_case)]
    fn get_pB(&mut self, pB: &mut [u8]) -> Result<(), Error>;
    #[allow(non_snake_case)]
    fn get_TT_as_verifier(
        &mut self,
        context: &[u8],
        pA: &[u8],
        pB: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error>;
}
