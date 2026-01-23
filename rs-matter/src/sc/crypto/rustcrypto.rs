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

use crate::crypto::{
    as_canon, as_canon_mut, CanonSecp256r1Point, CanonSecp256r1Scalar, Crypto, CurvePoint, Digest,
    Scalar, Sha256Hash, UInt, SECP256R1_CANON_SCALAR_LEN, SECP256R1_POINT_ZEROED, UINT384_ZEROED,
};
use crate::error::Error;

const MATTER_M_BIN: &CanonSecp256r1Point = &[
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f, 0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac,
    0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d,
    0x20,
];

const MATTER_N_BIN: &CanonSecp256r1Point = &[
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49, 0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68,
    0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb,
    0xe7,
];

#[allow(non_snake_case)]
pub struct CryptoSpake2<'a, C: Crypto> {
    crypto: &'a C,
    M: C::Secp256r1Point<'a>,
    N: C::Secp256r1Point<'a>,
    xy: Option<C::Secp256r1Scalar<'a>>,
    w0: Option<C::Secp256r1Scalar<'a>>,
    w1: Option<C::Secp256r1Scalar<'a>>,
    L: Option<C::Secp256r1Point<'a>>,
    pB: Option<C::Secp256r1Point<'a>>,
}

impl<'a, C: Crypto> CryptoSpake2<'a, C> {
    #[allow(non_snake_case)]
    pub fn new(crypto: &'a C) -> Result<Self, Error> {
        Ok(Self {
            crypto,
            M: crypto.secp256r1_point(MATTER_M_BIN)?,
            N: crypto.secp256r1_point(MATTER_N_BIN)?,
            xy: None,
            w0: None,
            w1: None,
            L: None,
            pB: None,
        })
    }

    // Computes w0 from w0s respectively
    pub fn set_w0_from_w0s(&mut self, w0s: &CanonSecp256r1Scalar) -> Result<(), Error> {
        // From the Matter Spec,
        //         w0 = w0s mod p
        //   where p is the order of the curve
        const OPERAND: &CanonSecp256r1Scalar = &[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];

        self.w0 = Some(self.rem(w0s, OPERAND)?);

        Ok(())
    }

    pub fn set_w1_from_w1s(&mut self, w1s: &CanonSecp256r1Scalar) -> Result<(), Error> {
        // From the Matter Spec,
        //         w1 = w1s mod p
        //   where p is the order of the curve
        const OPERAND: &CanonSecp256r1Scalar = &[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];

        self.w1 = Some(self.rem(w1s, OPERAND)?);

        Ok(())
    }

    fn rem(
        &self,
        value: &CanonSecp256r1Scalar,
        operand: &CanonSecp256r1Scalar,
    ) -> Result<C::Secp256r1Scalar<'a>, Error> {
        let value = self.expand(value)?;
        let operand = self.expand(operand)?;

        let result = value.rem(&operand).unwrap();
        let mut result_uint = UINT384_ZEROED;
        result.canon_into(&mut result_uint);

        let result_scalar: &CanonSecp256r1Scalar = unwrap!(as_canon(&result_uint[16..]));

        self.crypto.secp256r1_scalar(result_scalar)
    }

    fn expand(&self, scalar: &CanonSecp256r1Scalar) -> Result<C::UInt384<'a>, Error> {
        let mut operand_u384 = UINT384_ZEROED;
        let scalar_buf: &mut CanonSecp256r1Scalar = unwrap!(as_canon_mut(&mut operand_u384[16..]));
        scalar_buf.copy_from_slice(scalar);

        self.crypto.uint384(&operand_u384)
    }

    pub(crate) fn set_w0(&mut self, w0: &CanonSecp256r1Scalar) -> Result<(), Error> {
        self.w0 = Some(self.crypto.secp256r1_scalar(w0)?);
        Ok(())
    }

    pub(crate) fn set_w1(&mut self, w1: &CanonSecp256r1Scalar) -> Result<(), Error> {
        self.w1 = Some(self.crypto.secp256r1_scalar(w1)?);
        Ok(())
    }

    #[allow(non_snake_case)]
    #[allow(dead_code)]
    pub fn set_L(&mut self, l: &CanonSecp256r1Point) -> Result<(), Error> {
        self.L = Some(self.crypto.secp256r1_point(l)?);
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn set_L_from_w1s(&mut self, w1s: &CanonSecp256r1Scalar) -> Result<(), Error> {
        // From the Matter spec,
        //        L = w1 * P
        //    where P is the generator of the underlying elliptic curve
        self.set_w1_from_w1s(w1s)?;
        self.L = Some(
            self.crypto
                .secp256r1_generator()?
                .mul(unwrap!(self.w1.as_ref())),
        );
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn get_pB(&mut self, pB: &mut CanonSecp256r1Point) -> Result<(), Error> {
        // From the SPAKE2+ spec (https://datatracker.ietf.org/doc/draft-bar-cfrg-spake2plus/)
        //   for y
        //   - select random y between 0 to p
        //   - Y = y*P + w0*N
        //   - pB = Y
        let xy = self.crypto.secp256r1_scalar_random()?;

        let pb =
            self.crypto
                .secp256r1_generator()?
                .add_mul(&xy, &self.N, unwrap!(self.w0.as_ref()));

        pb.canon_into(pB);

        self.xy = Some(xy);
        self.pB = Some(pb);

        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn get_TT_as_verifier(
        &mut self,
        context: &[u8],
        pA: &CanonSecp256r1Point,
        pB: &CanonSecp256r1Point,
        out: &mut Sha256Hash,
    ) -> Result<(), Error> {
        let mut TT = self.crypto.sha256()?;

        // Context
        Self::add_to_tt(&mut TT, context);
        // 2 empty identifiers
        Self::add_to_tt(&mut TT, &[]);
        Self::add_to_tt(&mut TT, &[]);
        // M
        Self::add_to_tt(&mut TT, MATTER_M_BIN);
        // N
        Self::add_to_tt(&mut TT, MATTER_N_BIN);
        // X = pA
        Self::add_to_tt(&mut TT, pA);
        // Y = pB
        Self::add_to_tt(&mut TT, pB);

        let X = self.crypto.secp256r1_point(pA)?;
        let (Z, V) = ZV(self.crypto).verifier(
            unwrap!(self.w0.as_ref()),
            unwrap!(self.L.as_ref()),
            &self.M,
            &X,
            unwrap!(self.xy.as_ref()),
        );

        let mut point = SECP256R1_POINT_ZEROED;

        // Z
        Z.canon_into(&mut point);
        Self::add_to_tt(&mut TT, &point);
        // V
        V.canon_into(&mut point);
        Self::add_to_tt(&mut TT, &point);
        // w0
        let scalar: &mut CanonSecp256r1Scalar =
            unwrap!(as_canon_mut(&mut point[..SECP256R1_CANON_SCALAR_LEN]));
        unwrap!(self.w0.as_ref()).canon_into(scalar);
        Self::add_to_tt(&mut TT, scalar);

        TT.finish(out);

        Ok(())
    }

    fn add_to_tt(tt: &mut C::Sha256<'_>, data: &[u8]) {
        tt.update(&(data.len() as u64).to_le_bytes());
        if !data.is_empty() {
            tt.update(data);
        }
    }
}

struct ZV<'a, C: Crypto>(&'a C);

impl<'a, C: Crypto> ZV<'a, C> {
    #[inline(always)]
    #[allow(non_snake_case)]
    #[allow(dead_code)]
    fn verifier(
        &self,
        w0: &C::Secp256r1Scalar<'a>,
        L: &C::Secp256r1Point<'a>,
        M: &C::Secp256r1Point<'a>,
        X: &C::Secp256r1Point<'a>,
        y: &C::Secp256r1Scalar<'a>,
    ) -> (C::Secp256r1Point<'a>, C::Secp256r1Point<'a>) {
        // As per the RFC, the operation here is:
        //   Z = h*y*(X - w0*M)
        //   V = h*y*L

        // We will follow the same sequence as in C++ SDK, under the assumption
        // that the same sequence works for all embedded platforms. So the step
        // of operations is:
        //    tmp = y*w0
        //    Z = y*X + tmp*M (M is inverted to get the 'negative' effect)
        //    Z = h*Z (cofactor Mul)

        let Z = X.add_mul(y, &M.neg(), &y.mul(w0));

        // Cofactor for P256 is 1, so that is a No-Op

        let V = L.mul(y);

        (Z, V)
    }

    #[inline(always)]
    #[allow(non_snake_case)]
    #[allow(dead_code)]
    fn prover(
        &self,
        w0: &C::Secp256r1Scalar<'a>,
        w1: &C::Secp256r1Scalar<'a>,
        N: &C::Secp256r1Point<'a>,
        Y: &C::Secp256r1Point<'a>,
        x: &C::Secp256r1Scalar<'a>,
    ) -> (C::Secp256r1Point<'a>, C::Secp256r1Point<'a>) {
        // As per the RFC, the operation here is:
        //   Z = h*x*(Y - w0*N)
        //   V = h*w1*(Y - w0*N)

        // We will follow the same sequence as in C++ SDK, under the assumption
        // that the same sequence works for all embedded platforms. So the step
        // of operations is:
        //    tmp = x*w0
        //    Z = x*Y + tmp*N (N is inverted to get the 'negative' effect)
        //    Z = h*Z (cofactor Mul)

        let N_neg = N.neg();

        let Z = Y.add_mul(x, &N_neg, &x.mul(w0));

        // Cofactor for P256 is 1, so that is a No-Op

        let V = Y.add_mul(w1, &N_neg, &w1.mul(w0));

        (Z, V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{crypto::test_crypto, sc::pase::spake2p::test_vectors::*};

    #[test]
    #[allow(non_snake_case)]
    fn test_get_X() {
        for t in RFC_T {
            let crypto = test_crypto();
            let M = unwrap!(crypto.secp256r1_point(MATTER_M_BIN));
            let x = unwrap!(crypto.secp256r1_scalar(&t.x));
            let w0 = unwrap!(crypto.secp256r1_scalar(&t.w0));
            let P = unwrap!(crypto.secp256r1_generator());
            let r = P.add_mul(&x, &M, &w0);

            let mut point = SECP256R1_POINT_ZEROED;
            r.canon_into(&mut point);

            assert_eq!(&t.X, &point);
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_Y() {
        for t in RFC_T {
            let crypto = test_crypto();
            let M = unwrap!(crypto.secp256r1_point(MATTER_M_BIN));
            let y = unwrap!(crypto.secp256r1_scalar(&t.y));
            let w0 = unwrap!(crypto.secp256r1_scalar(&t.w0));
            let P = unwrap!(crypto.secp256r1_generator());
            let r = P.add_mul(&y, &M, &w0);

            let mut point = SECP256R1_POINT_ZEROED;
            r.canon_into(&mut point);

            assert_eq!(&t.Y, &point);
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_prover() {
        for t in RFC_T {
            let crypto = test_crypto();
            let N = unwrap!(crypto.secp256r1_point(MATTER_N_BIN));
            let x = unwrap!(crypto.secp256r1_scalar(&t.x));
            let y = unwrap!(crypto.secp256r1_point(&t.Y));
            let w0 = unwrap!(crypto.secp256r1_scalar(&t.w0));
            let w1 = unwrap!(crypto.secp256r1_scalar(&t.w1));

            let (Z, V) = ZV(&crypto).prover(&w0, &w1, &N, &y, &x);

            let mut point = SECP256R1_POINT_ZEROED;

            Z.canon_into(&mut point);
            assert_eq!(&t.Z, &point);

            V.canon_into(&mut point);
            assert_eq!(&t.V, &point);
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_verifier() {
        for t in RFC_T {
            let crypto = test_crypto();
            let M = unwrap!(crypto.secp256r1_point(MATTER_M_BIN));
            let x = unwrap!(crypto.secp256r1_point(&t.X));
            let y = unwrap!(crypto.secp256r1_scalar(&t.y));
            let w0 = unwrap!(crypto.secp256r1_scalar(&t.w0));
            let l = unwrap!(crypto.secp256r1_point(&t.L));
            let (Z, V) = ZV(&crypto).verifier(&w0, &l, &M, &x, &y);

            let mut point = SECP256R1_POINT_ZEROED;

            Z.canon_into(&mut point);
            assert_eq!(&t.Z, &point);

            V.canon_into(&mut point);
            assert_eq!(&t.V, &point);
        }
    }
}
