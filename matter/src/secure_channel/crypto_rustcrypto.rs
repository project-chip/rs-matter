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

use crypto_bigint::Encoding;
use crypto_bigint::U384;
use elliptic_curve::ops::*;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::Field;
use elliptic_curve::PrimeField;
use sha2::Digest;

use crate::error::Error;

use super::crypto::CryptoSpake2;

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

pub struct CryptoRustCrypto {
    xy: p256::Scalar,
    w0: p256::Scalar,
    w1: p256::Scalar,
    M: p256::EncodedPoint,
    N: p256::EncodedPoint,
    L: p256::EncodedPoint,
    pB: p256::EncodedPoint,
}

impl CryptoSpake2 for CryptoRustCrypto {
    #[allow(non_snake_case)]
    fn new() -> Result<Self, Error> {
        let M = p256::EncodedPoint::from_bytes(MATTER_M_BIN).unwrap();
        let N = p256::EncodedPoint::from_bytes(MATTER_N_BIN).unwrap();
        let L = p256::EncodedPoint::default();
        let pB = p256::EncodedPoint::default();

        Ok(CryptoRustCrypto {
            xy: p256::Scalar::ZERO,
            w0: p256::Scalar::ZERO,
            w1: p256::Scalar::ZERO,
            M,
            N,
            L,
            pB,
        })
    }

    // Computes w0 from w0s respectively
    fn set_w0_from_w0s(&mut self, w0s: &[u8]) -> Result<(), Error> {
        // From the Matter Spec,
        //         w0 = w0s mod p
        //   where p is the order of the curve
        let operand: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut expanded = [0u8; 384 / 8];
        expanded[16..].copy_from_slice(&operand);
        let big_operand = U384::from_be_slice(&expanded);
        let mut expanded = [0u8; 384 / 8];
        expanded[8..].copy_from_slice(w0s);
        let big_w0 = U384::from_be_slice(&expanded);
        let w0_res = big_w0.reduce(&big_operand).unwrap();
        let mut w0_out = [0u8; 32];
        w0_out.copy_from_slice(&w0_res.to_be_bytes()[16..]);

        let w0s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&w0_out),
        )
        .unwrap();
        // Scalar is module the curve's order by definition, no further op needed
        self.w0 = w0s;

        Ok(())
    }

    fn set_w1_from_w1s(&mut self, w1s: &[u8]) -> Result<(), Error> {
        // From the Matter Spec,
        //         w1 = w1s mod p
        //   where p is the order of the curve
        let operand: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut expanded = [0u8; 384 / 8];
        expanded[16..].copy_from_slice(&operand);
        let big_operand = U384::from_be_slice(&expanded);
        let mut expanded = [0u8; 384 / 8];
        expanded[8..].copy_from_slice(w1s);
        let big_w1 = U384::from_be_slice(&expanded);
        let w1_res = big_w1.reduce(&big_operand).unwrap();
        let mut w1_out = [0u8; 32];
        w1_out.copy_from_slice(&w1_res.to_be_bytes()[16..]);

        let w1s = p256::Scalar::from_repr(
            *elliptic_curve::generic_array::GenericArray::from_slice(&w1_out),
        )
        .unwrap();
        // Scalar is module the curve's order by definition, no further op needed
        self.w1 = w1s;

        Ok(())
    }

    fn set_w0(&mut self, w0: &[u8]) -> Result<(), Error> {
        self.w0 =
            p256::Scalar::from_repr(*elliptic_curve::generic_array::GenericArray::from_slice(w0))
                .unwrap();
        Ok(())
    }

    fn set_w1(&mut self, w1: &[u8]) -> Result<(), Error> {
        self.w1 =
            p256::Scalar::from_repr(*elliptic_curve::generic_array::GenericArray::from_slice(w1))
                .unwrap();
        Ok(())
    }

    #[allow(non_snake_case)]
    #[allow(dead_code)]
    fn set_L(&mut self, l: &[u8]) -> Result<(), Error> {
        self.L = p256::EncodedPoint::from_bytes(l).unwrap();
        Ok(())
    }

    fn set_L_from_w1s(&mut self, w1s: &[u8]) -> Result<(), Error> {
        // From the Matter spec,
        //        L = w1 * P
        //    where P is the generator of the underlying elliptic curve
        self.set_w1_from_w1s(w1s)?;
        self.L = (p256::AffinePoint::GENERATOR * self.w1).to_encoded_point(false);
        Ok(())
    }

    #[allow(non_snake_case)]
    fn get_pB(&mut self, pB: &mut [u8]) -> Result<(), Error> {
        // From the SPAKE2+ spec (https://datatracker.ietf.org/doc/draft-bar-cfrg-spake2plus/)
        //   for y
        //   - select random y between 0 to p
        //   - Y = y*P + w0*N
        //   - pB = Y
        let mut rng = rand::thread_rng();
        self.xy = p256::Scalar::random(&mut rng);

        let P = p256::AffinePoint::GENERATOR;
        let N = p256::AffinePoint::from_encoded_point(&self.N).unwrap();
        self.pB = Self::do_add_mul(P, self.xy, N, self.w0)?;
        let pB_internal = self.pB.as_bytes();
        pB.copy_from_slice(pB_internal);

        Ok(())
    }

    #[allow(non_snake_case)]
    fn get_TT_as_verifier(
        &mut self,
        context: &[u8],
        pA: &[u8],
        pB: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let mut TT = sha2::Sha256::new();
        // Context
        Self::add_to_tt(&mut TT, context)?;
        // 2 empty identifiers
        Self::add_to_tt(&mut TT, &[])?;
        Self::add_to_tt(&mut TT, &[])?;
        // M
        Self::add_to_tt(&mut TT, &MATTER_M_BIN)?;
        // N
        Self::add_to_tt(&mut TT, &MATTER_N_BIN)?;
        // X = pA
        Self::add_to_tt(&mut TT, pA)?;
        // Y = pB
        Self::add_to_tt(&mut TT, pB)?;

        let X = p256::EncodedPoint::from_bytes(pA).unwrap();
        let X = p256::AffinePoint::from_encoded_point(&X).unwrap();
        let L = p256::AffinePoint::from_encoded_point(&self.L).unwrap();
        let M = p256::AffinePoint::from_encoded_point(&self.M).unwrap();
        let (Z, V) = Self::get_ZV_as_verifier(self.w0, L, M, X, self.xy)?;

        // Z
        Self::add_to_tt(&mut TT, Z.as_bytes())?;
        // V
        Self::add_to_tt(&mut TT, V.as_bytes())?;
        // w0
        Self::add_to_tt(&mut TT, self.w0.to_bytes().to_vec().as_ref())?;

        let h = TT.finalize();
        out.copy_from_slice(h.as_slice());

        Ok(())
    }
}

impl CryptoRustCrypto {
    fn add_to_tt(tt: &mut sha2::Sha256, buf: &[u8]) -> Result<(), Error> {
        tt.update(buf.len().to_le_bytes());
        if !buf.is_empty() {
            tt.update(buf);
        }
        Ok(())
    }

    #[inline(always)]
    fn do_add_mul(
        a: p256::AffinePoint,
        b: p256::Scalar,
        c: p256::AffinePoint,
        d: p256::Scalar,
    ) -> Result<p256::EncodedPoint, Error> {
        Ok(((a * b) + (c * d)).to_encoded_point(false))
    }

    #[inline(always)]
    #[allow(non_snake_case)]
    #[allow(dead_code)]
    fn get_ZV_as_prover(
        w0: p256::Scalar,
        w1: p256::Scalar,
        N: p256::AffinePoint,
        Y: p256::AffinePoint,
        x: p256::Scalar,
    ) -> Result<(p256::EncodedPoint, p256::EncodedPoint), Error> {
        // As per the RFC, the operation here is:
        //   Z = h*x*(Y - w0*N)
        //   V = h*w1*(Y - w0*N)

        // We will follow the same sequence as in C++ SDK, under the assumption
        // that the same sequence works for all embedded platforms. So the step
        // of operations is:
        //    tmp = x*w0
        //    Z = x*Y + tmp*N (N is inverted to get the 'negative' effect)
        //    Z = h*Z (cofactor Mul)

        let mut tmp = x * w0;
        let N_neg = N.neg();
        let Z = CryptoRustCrypto::do_add_mul(Y, x, N_neg, tmp)?;
        // Cofactor for P256 is 1, so that is a No-Op

        tmp = w1 * w0;
        let V = CryptoRustCrypto::do_add_mul(Y, w1, N_neg, tmp)?;
        Ok((Z, V))
    }

    #[inline(always)]
    #[allow(non_snake_case)]
    #[allow(dead_code)]
    fn get_ZV_as_verifier(
        w0: p256::Scalar,
        L: p256::AffinePoint,
        M: p256::AffinePoint,
        X: p256::AffinePoint,
        y: p256::Scalar,
    ) -> Result<(p256::EncodedPoint, p256::EncodedPoint), Error> {
        // As per the RFC, the operation here is:
        //   Z = h*y*(X - w0*M)
        //   V = h*y*L

        // We will follow the same sequence as in C++ SDK, under the assumption
        // that the same sequence works for all embedded platforms. So the step
        // of operations is:
        //    tmp = y*w0
        //    Z = y*X + tmp*M (M is inverted to get the 'negative' effect)
        //    Z = h*Z (cofactor Mul)

        let tmp = y * w0;
        let M_neg = M.neg();
        let Z = CryptoRustCrypto::do_add_mul(X, y, M_neg, tmp)?;
        // Cofactor for P256 is 1, so that is a No-Op
        let V = (L * y).to_encoded_point(false);
        Ok((Z, V))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use elliptic_curve::sec1::FromEncodedPoint;

    use crate::secure_channel::crypto::CryptoSpake2;
    use crate::secure_channel::spake2p_test_vectors::test_vectors::*;

    #[test]
    #[allow(non_snake_case)]
    fn test_get_X() {
        for t in RFC_T {
            let mut c = CryptoRustCrypto::new().unwrap();
            let x = p256::Scalar::from_repr(
                *elliptic_curve::generic_array::GenericArray::from_slice(&t.x),
            )
            .unwrap();
            c.set_w0(&t.w0).unwrap();
            let P = p256::AffinePoint::GENERATOR;
            let M = p256::AffinePoint::from_encoded_point(&c.M).unwrap();
            let r: p256::EncodedPoint = CryptoRustCrypto::do_add_mul(P, x, M, c.w0).unwrap();
            assert_eq!(&t.X, r.as_bytes());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_Y() {
        for t in RFC_T {
            let mut c = CryptoRustCrypto::new().unwrap();
            let y = p256::Scalar::from_repr(
                *elliptic_curve::generic_array::GenericArray::from_slice(&t.y),
            )
            .unwrap();
            c.set_w0(&t.w0).unwrap();
            let P = p256::AffinePoint::GENERATOR;
            let N = p256::AffinePoint::from_encoded_point(&c.N).unwrap();
            let r = CryptoRustCrypto::do_add_mul(P, y, N, c.w0).unwrap();
            assert_eq!(&t.Y, r.as_bytes());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_prover() {
        for t in RFC_T {
            let mut c = CryptoRustCrypto::new().unwrap();
            let x = p256::Scalar::from_repr(
                *elliptic_curve::generic_array::GenericArray::from_slice(&t.x),
            )
            .unwrap();
            c.set_w0(&t.w0).unwrap();
            c.set_w1(&t.w1).unwrap();
            let Y = p256::EncodedPoint::from_bytes(t.Y).unwrap();
            let Y = p256::AffinePoint::from_encoded_point(&Y).unwrap();
            let N = p256::AffinePoint::from_encoded_point(&c.N).unwrap();
            let (Z, V) = CryptoRustCrypto::get_ZV_as_prover(c.w0, c.w1, N, Y, x).unwrap();

            assert_eq!(&t.Z, Z.as_bytes());
            assert_eq!(&t.V, V.as_bytes());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_verifier() {
        for t in RFC_T {
            let mut c = CryptoRustCrypto::new().unwrap();
            let y = p256::Scalar::from_repr(
                *elliptic_curve::generic_array::GenericArray::from_slice(&t.y),
            )
            .unwrap();
            c.set_w0(&t.w0).unwrap();
            let X = p256::EncodedPoint::from_bytes(t.X).unwrap();
            let X = p256::AffinePoint::from_encoded_point(&X).unwrap();
            let L = p256::EncodedPoint::from_bytes(t.L).unwrap();
            let L = p256::AffinePoint::from_encoded_point(&L).unwrap();
            let M = p256::AffinePoint::from_encoded_point(&c.M).unwrap();
            let (Z, V) = CryptoRustCrypto::get_ZV_as_verifier(c.w0, L, M, X, y).unwrap();

            assert_eq!(&t.Z, Z.as_bytes());
            assert_eq!(&t.V, V.as_bytes());
        }
    }
}
