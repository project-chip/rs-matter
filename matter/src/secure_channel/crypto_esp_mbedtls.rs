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
use crate::utils::rand::Rand;

const MATTER_M_BIN: [u8; 65] = [
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f, 0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac,
    0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d,
    0x20,
];
const MATTER_N_BIN: [u8; 65] = [
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49, 0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68,
    0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb,
    0xe7,
];

#[allow(non_snake_case)]

pub struct CryptoSpake2 {}

impl CryptoSpake2 {
    #[allow(non_snake_case)]
    pub fn new() -> Result<Self, Error> {
        Ok(Self {})
    }

    // Computes w0 from w0s respectively
    pub fn set_w0_from_w0s(&mut self, w0s: &[u8]) -> Result<(), Error> {
        // From the Matter Spec,
        //         w0 = w0s mod p
        //   where p is the order of the curve

        Ok(())
    }

    pub fn set_w1_from_w1s(&mut self, w1s: &[u8]) -> Result<(), Error> {
        // From the Matter Spec,
        //         w1 = w1s mod p
        //   where p is the order of the curve

        Ok(())
    }

    pub fn set_w0(&mut self, w0: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    pub fn set_w1(&mut self, w1: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    #[allow(non_snake_case)]
    #[allow(dead_code)]
    pub fn set_L(&mut self, w1s: &[u8]) -> Result<(), Error> {
        // From the Matter spec,
        //        L = w1 * P
        //    where P is the generator of the underlying elliptic curve
        Ok(())
    }

    #[allow(non_snake_case)]
    #[allow(dead_code)]
    pub fn set_L_from_w1s(&mut self, w1s: &[u8]) -> Result<(), Error> {
        // From the Matter spec,
        //        L = w1 * P
        //    where P is the generator of the underlying elliptic curve
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn get_pB(&mut self, pB: &mut [u8], _rand: Rand) -> Result<(), Error> {
        // From the SPAKE2+ spec (https://datatracker.ietf.org/doc/draft-bar-cfrg-spake2plus/)
        //   for y
        //   - select random y between 0 to p
        //   - Y = y*P + w0*N
        //   - pB = Y

        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn get_TT_as_verifier(
        &mut self,
        context: &[u8],
        pA: &[u8],
        pB: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::CryptoSpake2;
    use crate::secure_channel::spake2p_test_vectors::test_vectors::*;
    use openssl::bn::BigNum;
    use openssl::ec::{EcPoint, PointConversionForm};

    #[test]
    #[allow(non_snake_case)]
    fn test_get_X() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let x = BigNum::from_slice(&t.x).unwrap();
            c.set_w0(&t.w0).unwrap();
            let P = c.group.generator();

            let r = CryptoSpake2::do_add_mul(P, &x, &c.M, &c.w0, &c.group, &mut c.bn_ctx).unwrap();
            assert_eq!(
                t.X,
                r.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_Y() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let y = BigNum::from_slice(&t.y).unwrap();
            c.set_w0(&t.w0).unwrap();
            let P = c.group.generator();
            let r = CryptoSpake2::do_add_mul(P, &y, &c.N, &c.w0, &c.group, &mut c.bn_ctx).unwrap();
            assert_eq!(
                t.Y,
                r.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_prover() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let x = BigNum::from_slice(&t.x).unwrap();
            c.set_w0(&t.w0).unwrap();
            c.set_w1(&t.w1).unwrap();
            let Y = EcPoint::from_bytes(&c.group, &t.Y, &mut c.bn_ctx).unwrap();
            let (Z, V) = CryptoSpake2::get_ZV_as_prover(
                &c.w0,
                &c.w1,
                &mut c.N,
                &Y,
                &x,
                &c.order,
                &c.group,
                &mut c.bn_ctx,
            )
            .unwrap();

            assert_eq!(
                t.Z,
                Z.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
            assert_eq!(
                t.V,
                V.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_verifier() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let y = BigNum::from_slice(&t.y).unwrap();
            c.set_w0(&t.w0).unwrap();
            let X = EcPoint::from_bytes(&c.group, &t.X, &mut c.bn_ctx).unwrap();
            let L = EcPoint::from_bytes(&c.group, &t.L, &mut c.bn_ctx).unwrap();
            let (Z, V) = CryptoSpake2::get_ZV_as_verifier(
                &c.w0,
                &L,
                &mut c.M,
                &X,
                &y,
                &c.order,
                &c.group,
                &mut c.bn_ctx,
            )
            .unwrap();

            assert_eq!(
                t.Z,
                Z.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
            assert_eq!(
                t.V,
                V.to_bytes(&c.group, PointConversionForm::UNCOMPRESSED, &mut c.bn_ctx)
                    .unwrap()
                    .as_slice()
            );
        }
    }
}
