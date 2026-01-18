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

use crate::crypto::{Crypto, CurvePoint, Digest, Scalar, UInt};
use crate::error::Error;

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
pub struct CryptoSpake2<'a, C: Crypto> {
    crypto: &'a C,
    xy: Option<C::Secp256r1Scalar<'a>>,
    w0: Option<C::Secp256r1Scalar<'a>>,
    w1: Option<C::Secp256r1Scalar<'a>>,
    M: C::Secp256r1Point<'a>,
    N: C::Secp256r1Point<'a>,
    L: Option<C::Secp256r1Point<'a>>,
    pB: Option<C::Secp256r1Point<'a>>,
}

impl<'a, C: Crypto> CryptoSpake2<'a, C> {
    #[allow(non_snake_case)]
    pub fn new(crypto: &'a C) -> Result<Self, Error> {
        let M = unwrap!(
            crypto.secpp256r1_point(&MATTER_M_BIN),
            "Failed to create M from bytes"
        );
        let N = unwrap!(
            crypto.secpp256r1_point(&MATTER_N_BIN),
            "Failed to create N from bytes"
        );

        Ok(Self {
            crypto,
            xy: None,
            w0: None,
            w1: None,
            M,
            N,
            L: None,
            pB: None,
        })
    }

    // Computes w0 from w0s respectively
    pub fn set_w0_from_w0s(&mut self, w0s: &[u8]) -> Result<(), Error> {
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
        let big_operand = self.crypto.uint384(&expanded).unwrap();
        let mut expanded = [0u8; 384 / 8];
        expanded[8..].copy_from_slice(w0s);
        let big_w0 = self.crypto.uint384(&expanded).unwrap();
        let w0 = big_w0.rem(&big_operand);
        let mut w0d = [0; 48];
        big_w0.dehydrate(&mut w0d).unwrap();
        // Scalar is module the curve's order by definition, no further op needed
        self.w0 = Some(self.crypto.secp256r1_scalar(&w0d[16..]).unwrap());

        Ok(())
    }

    pub fn set_w1_from_w1s(&mut self, w1s: &[u8]) -> Result<(), Error> {
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
        let big_operand = self.crypto.uint384(&expanded).unwrap();
        let mut expanded = [0u8; 384 / 8];
        expanded[8..].copy_from_slice(w1s);
        let big_w1 = self.crypto.uint384(&expanded).unwrap();
        let w1 = big_w1.rem(&big_operand);
        let mut w1d = [0; 48];
        big_w1.dehydrate(&mut w1d).unwrap();

        // Scalar is module the curve's order by definition, no further op needed
        self.w1 = Some(self.crypto.secp256r1_scalar(&w1d[16..]).unwrap());

        Ok(())
    }

    pub(crate) fn set_w0(&mut self, w0: &[u8; 32]) -> Result<(), Error> {
        self.w0 = Some(self.crypto.secp256r1_scalar(w0).unwrap());
        Ok(())
    }

    pub(crate) fn set_w1(&mut self, w1: &[u8; 32]) -> Result<(), Error> {
        self.w1 = Some(self.crypto.secp256r1_scalar(w1).unwrap());
        Ok(())
    }

    #[allow(non_snake_case)]
    #[allow(dead_code)]
    pub fn set_L(&mut self, l: &[u8]) -> Result<(), Error> {
        self.L = Some(self.crypto.secpp256r1_point(l).unwrap());
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn set_L_from_w1s(&mut self, w1s: &[u8]) -> Result<(), Error> {
        // From the Matter spec,
        //        L = w1 * P
        //    where P is the generator of the underlying elliptic curve
        self.set_w1_from_w1s(w1s)?;
        self.L = Some(
            self.crypto
                .secpp256r1_generator()
                .unwrap()
                .mul(self.w1.as_ref().unwrap()),
        );
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn get_pB(&mut self, pB: &mut [u8]) -> Result<(), Error> {
        // From the SPAKE2+ spec (https://datatracker.ietf.org/doc/draft-bar-cfrg-spake2plus/)
        //   for y
        //   - select random y between 0 to p
        //   - Y = y*P + w0*N
        //   - pB = Y
        let xy = self.crypto.secp256r1_scalar_random().unwrap();

        let a = self.crypto.secpp256r1_generator().unwrap().mul(&xy);
        let b = self.N.mul(self.w0.as_ref().unwrap());

        let pb = a.add(&b);

        pb.dehydrate(pB).unwrap();

        self.xy = Some(xy);
        self.pB = Some(pb);

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
        let mut TT = self.crypto.sha256().unwrap();

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

        let X = self.crypto.secpp256r1_point(pA)?;
        let (Z, V) = Self::get_ZV_as_verifier(
            self.w0.as_ref().unwrap(),
            self.L.as_ref().unwrap(),
            self.M.as_ref().unwrap(),
            &X,
            self.xy.as_ref().unwrap(),
        )?;

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

    fn add_to_tt(tt: &mut C::Sha256<'_>, buf: &[u8]) -> Result<(), Error> {
        tt.update(&(buf.len() as u64).to_le_bytes());
        if !buf.is_empty() {
            tt.update(buf);
        }
        Ok(())
    }

    // #[inline(always)]
    // fn do_add_mul(
    //     a: p256::AffinePoint,
    //     b: p256::Scalar,
    //     c: p256::AffinePoint,
    //     d: p256::Scalar,
    // ) -> Result<p256::EncodedPoint, Error> {
    //     Ok(((a * b) + (c * d)).to_encoded_point(false))
    // }

    #[inline(always)]
    #[allow(non_snake_case)]
    #[allow(dead_code)]
    fn get_ZV_as_prover<'t>(
        w0: &C::Secp256r1Scalar<'t>,
        w1: &C::Secp256r1Scalar<'t>,
        N: &C::Secp256r1Point<'t>,
        Y: &C::Secp256r1Point<'t>,
        x: &C::Secp256r1Scalar<'t>,
    ) -> Result<(C::Secp256r1Point<'t>, C::Secp256r1Point<'t>), Error> {
        // As per the RFC, the operation here is:
        //   Z = h*x*(Y - w0*N)
        //   V = h*w1*(Y - w0*N)

        // We will follow the same sequence as in C++ SDK, under the assumption
        // that the same sequence works for all embedded platforms. So the step
        // of operations is:
        //    tmp = x*w0
        //    Z = x*Y + tmp*N (N is inverted to get the 'negative' effect)
        //    Z = h*Z (cofactor Mul)

        let tmp = x.mul(w0);
        let N_neg = N.neg();

        let a = Y.mul(x);
        let b = N_neg.mul(&tmp);

        let Z = a.add(&b);
        // Cofactor for P256 is 1, so that is a No-Op

        let tmp = w1.mul(w0);
        let a = Y.mul(w1);
        let b = N_neg.mul(&tmp);

        let V = a.add(&b);
        Ok((Z, V))
    }

    #[inline(always)]
    #[allow(non_snake_case)]
    #[allow(dead_code)]
    fn get_ZV_as_verifier<'t>(
        w0: &C::Secp256r1Scalar<'t>,
        L: &C::Secp256r1Point<'t>,
        M: &C::Secp256r1Point<'t>,
        X: &C::Secp256r1Point<'t>,
        y: &C::Secp256r1Scalar<'t>,
    ) -> Result<(C::Secp256r1Point<'t>, C::Secp256r1Point<'t>), Error> {
        // As per the RFC, the operation here is:
        //   Z = h*y*(X - w0*M)
        //   V = h*y*L

        // We will follow the same sequence as in C++ SDK, under the assumption
        // that the same sequence works for all embedded platforms. So the step
        // of operations is:
        //    tmp = y*w0
        //    Z = y*X + tmp*M (M is inverted to get the 'negative' effect)
        //    Z = h*Z (cofactor Mul)

        let tmp = y.mul(w0);
        let M_neg = M.neg();
        let a = X.mul(y);
        let b = M_neg.mul(&tmp);

        let Z = a.add(&b);
        // Cofactor for P256 is 1, so that is a No-Op
        let V = L.mul(y);
        Ok((Z, V))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use elliptic_curve::sec1::FromEncodedPoint;

    use crate::sc::pake::spake2p::test_vectors::*;

    #[test]
    #[allow(non_snake_case)]
    fn test_get_X() {
        for t in RFC_T {
            let mut c = unwrap!(CryptoSpake2::new());
            let x = p256::Scalar::from_repr(
                *elliptic_curve::generic_array::GenericArray::from_slice(&t.x),
            )
            .unwrap();
            unwrap!(c.set_w0(&t.w0));
            let P = p256::AffinePoint::GENERATOR;
            let M = p256::AffinePoint::from_encoded_point(&c.M).unwrap();
            let r: p256::EncodedPoint = unwrap!(CryptoSpake2::do_add_mul(P, x, M, c.w0));
            assert_eq!(&t.X, r.as_bytes());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_Y() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let y = p256::Scalar::from_repr(
                *elliptic_curve::generic_array::GenericArray::from_slice(&t.y),
            )
            .unwrap();
            c.set_w0(&t.w0).unwrap();
            let P = p256::AffinePoint::GENERATOR;
            let N = p256::AffinePoint::from_encoded_point(&c.N).unwrap();
            let r = CryptoSpake2::do_add_mul(P, y, N, c.w0).unwrap();
            assert_eq!(&t.Y, r.as_bytes());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_prover() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let x = p256::Scalar::from_repr(
                *elliptic_curve::generic_array::GenericArray::from_slice(&t.x),
            )
            .unwrap();
            c.set_w0(&t.w0).unwrap();
            c.set_w1(&t.w1).unwrap();
            let Y = p256::EncodedPoint::from_bytes(t.Y).unwrap();
            let Y = p256::AffinePoint::from_encoded_point(&Y).unwrap();
            let N = p256::AffinePoint::from_encoded_point(&c.N).unwrap();
            let (Z, V) = CryptoSpake2::get_ZV_as_prover(c.w0, c.w1, N, Y, x).unwrap();

            assert_eq!(&t.Z, Z.as_bytes());
            assert_eq!(&t.V, V.as_bytes());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_verifier() {
        for t in RFC_T {
            let mut c = unwrap!(CryptoSpake2::new(), "Failed to create CryptoSpake2");
            let y = p256::Scalar::from_repr(
                *elliptic_curve::generic_array::GenericArray::from_slice(&t.y),
            )
            .unwrap();
            unwrap!(c.set_w0(&t.w0), "Failed to set w0");
            let X = unwrap!(
                p256::EncodedPoint::from_bytes(t.X),
                "Failed to create X from bytes"
            );
            let X = p256::AffinePoint::from_encoded_point(&X).unwrap();
            let L = unwrap!(
                p256::EncodedPoint::from_bytes(t.L),
                "Failed to create L from bytes"
            );
            let L = p256::AffinePoint::from_encoded_point(&L).unwrap();
            let M = p256::AffinePoint::from_encoded_point(&c.M).unwrap();
            let (Z, V) = unwrap!(
                CryptoSpake2::get_ZV_as_verifier(c.w0, L, M, X, y),
                "Failed to get ZV as verifier"
            );

            assert_eq!(&t.Z, Z.as_bytes());
            assert_eq!(&t.V, V.as_bytes());
        }
    }
}
