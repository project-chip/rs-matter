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

use alloc::sync::Arc;
use core::ops::{Mul, Sub};

use crate::{
    error::{Error, ErrorCode},
    utils::rand::Rand,
};

use mbedtls::{
    bignum::Mpi,
    ecp::EcPoint,
    hash::Md,
    pk::{EcGroup, EcGroupId, Pk},
    rng::{CtrDrbg, OsEntropy},
};

extern crate alloc;

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
pub struct CryptoSpake2 {
    group: EcGroup,
    order: Mpi,
    xy: Mpi,
    w0: Mpi,
    w1: Mpi,
    M: EcPoint,
    N: EcPoint,
    L: EcPoint,
    pB: EcPoint,
}

impl CryptoSpake2 {
    #[allow(non_snake_case)]
    pub fn new() -> Result<Self, Error> {
        let group = EcGroup::new(mbedtls::pk::EcGroupId::SecP256R1)?;
        let order = group.order()?;
        let M = EcPoint::from_binary(&group, &MATTER_M_BIN)?;
        let N = EcPoint::from_binary(&group, &MATTER_N_BIN)?;

        Ok(Self {
            group,
            order,
            xy: Mpi::new(0)?,
            M,
            N,
            w0: Mpi::new(0)?,
            w1: Mpi::new(0)?,
            L: EcPoint::new()?,
            pB: EcPoint::new()?,
        })
    }

    // Computes w0 from w0s respectively
    pub fn set_w0_from_w0s(&mut self, w0s: &[u8]) -> Result<(), Error> {
        // From the Matter Spec,
        //         w0 = w0s mod p
        //   where p is the order of the curve

        self.w0 = Mpi::from_binary(w0s)?;
        self.w0 = self.w0.modulo(&self.order)?;
        Ok(())
    }

    pub fn set_w1_from_w1s(&mut self, w1s: &[u8]) -> Result<(), Error> {
        // From the Matter Spec,
        //         w1 = w1s mod p
        //   where p is the order of the curve

        self.w1 = Mpi::from_binary(w1s)?;
        self.w1 = self.w1.modulo(&self.order)?;
        Ok(())
    }

    pub fn set_w0(&mut self, w0: &[u8]) -> Result<(), Error> {
        self.w0 = Mpi::from_binary(w0)?;
        Ok(())
    }

    pub fn set_w1(&mut self, w1: &[u8]) -> Result<(), Error> {
        self.w1 = Mpi::from_binary(w1)?;
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn set_L(&mut self, l: &[u8]) -> Result<(), Error> {
        self.L = EcPoint::from_binary(&self.group, l)?;
        Ok(())
    }

    #[allow(non_snake_case)]
    #[allow(dead_code)]
    pub fn set_L_from_w1s(&mut self, w1s: &[u8]) -> Result<(), Error> {
        let mut ctr_drbg: CtrDrbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;
        // From the Matter spec,
        //        L = w1 * P
        //    where P is the generator of the underlying elliptic curve
        self.set_w1_from_w1s(w1s)?;
        // TODO: rust-mbedtls doesn't yet accept the DRBG parameter
        self.L = self
            .group
            .generator()?
            .mul_with_rng(&mut self.group, &self.w1, &mut ctr_drbg)?;
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn get_pB(&mut self, pB: &mut [u8], _rand: Rand) -> Result<(), Error> {
        // From the SPAKE2+ spec (https://datatracker.ietf.org/doc/draft-bar-cfrg-spake2plus/)
        //   for y
        //   - select random y between 0 to p
        //   - Y = y*P + w0*N
        //   - pB = Y

        // A private key on this curve is a random number between 0 to p
        let mut ctr_drbg: CtrDrbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;
        self.xy = Pk::generate_ec(&mut ctr_drbg, EcGroupId::SecP256R1)?.ec_private()?;

        let P = self.group.generator()?;
        self.pB = EcPoint::muladd(&mut self.group, &P, &self.xy, &self.N, &self.w0)?;

        let pB_internal = self.pB.to_binary(&self.group, false)?;
        let pB_internal = pB_internal.as_slice();
        if pB_internal.len() != pB.len() {
            error!("pB length mismatch");
            Err(ErrorCode::Invalid)?;
        }
        pB.copy_from_slice(pB_internal);
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
        let mut TT = Md::new(mbedtls::hash::Type::Sha256)?;
        // context
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

        let X = EcPoint::from_binary(&self.group, pA)?;
        let (Z, V) = Self::get_ZV_as_verifier(
            &self.w0,
            &self.L,
            &self.M,
            &X,
            &self.xy,
            &self.order,
            &mut self.group,
        )?;

        // Z
        let tmp = Z.to_binary(&self.group, false)?;
        let tmp = tmp.as_slice();
        Self::add_to_tt(&mut TT, tmp)?;

        // V
        let tmp = V.to_binary(&self.group, false)?;
        let tmp = tmp.as_slice();
        Self::add_to_tt(&mut TT, tmp)?;

        // w0
        let tmp = self.w0.to_binary()?;
        let tmp = tmp.as_slice();
        Self::add_to_tt(&mut TT, tmp)?;

        TT.finish(out)?;
        Ok(())
    }

    fn add_to_tt(tt: &mut Md, buf: &[u8]) -> Result<(), Error> {
        let len_buf: [u8; 8] = (buf.len() as u64).to_le_bytes();
        tt.update(&len_buf)?;
        if !buf.is_empty() {
            tt.update(buf)?;
        }
        Ok(())
    }

    #[inline(always)]
    #[allow(non_snake_case)]
    #[allow(dead_code)]
    fn get_ZV_as_prover(
        w0: &Mpi,
        w1: &Mpi,
        N: &EcPoint,
        Y: &EcPoint,
        x: &Mpi,
        order: &Mpi,
        group: &mut EcGroup,
    ) -> Result<(EcPoint, EcPoint), Error> {
        // As per the RFC, the operation here is:
        //   Z = h*x*(Y - w0*N)
        //   V = h*w1*(Y - w0*N)

        // We will follow the same sequence as in C++ SDK, under the assumption
        // that the same sequence works for all embedded platforms. So the step
        // of operations is:
        //    tmp = x*w0
        //    Z = x*Y + tmp*N (N is inverted to get the 'negative' effect)
        //    Z = h*Z (cofactor Mul)

        let mut tmp = x.mul(w0)?;
        tmp = tmp.modulo(order)?;

        let inverted_N = Self::invert(group, N)?;
        let Z = EcPoint::muladd(group, Y, x, &inverted_N, &tmp)?;
        // Cofactor for P256 is 1, so that is a No-Op

        let mut tmp = w0.mul(w1)?;
        tmp = tmp.modulo(order)?;
        let V = EcPoint::muladd(group, Y, w1, &inverted_N, &tmp)?;
        Ok((Z, V))
    }

    #[inline(always)]
    #[allow(non_snake_case)]
    #[allow(dead_code)]
    fn get_ZV_as_verifier(
        w0: &Mpi,
        L: &EcPoint,
        M: &EcPoint,
        X: &EcPoint,
        y: &Mpi,
        order: &Mpi,
        group: &mut EcGroup,
    ) -> Result<(EcPoint, EcPoint), Error> {
        let mut ctr_drbg: CtrDrbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;

        // As per the RFC, the operation here is:
        //   Z = h*y*(X - w0*M)
        //   V = h*y*L

        // We will follow the same sequence as in C++ SDK, under the assumption
        // that the same sequence works for all embedded platforms. So the step
        // of operations is:
        //    tmp = y*w0
        //    Z = y*X + tmp*M (M is inverted to get the 'negative' effect)
        //    Z = h*Z (cofactor Mul)

        let mut tmp = y.mul(w0)?;
        tmp = tmp.modulo(order)?;

        let inverted_M = Self::invert(group, M)?;
        let Z = EcPoint::muladd(group, X, y, &inverted_M, &tmp)?;
        // Cofactor for P256 is 1, so that is a No-Op

        let V = L.mul_with_rng(group, y, &mut ctr_drbg)?;
        Ok((Z, V))
    }

    fn invert(group: &EcGroup, num: &EcPoint) -> Result<EcPoint, mbedtls::Error> {
        let p = group.p()?;
        let num_y = num.y()?;
        let inverted_num_y = p.sub(&num_y)?;
        EcPoint::from_components(num.x()?, inverted_num_y)
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoSpake2;
    use crate::sc::pake::spake2p::test_vectors::*;
    use mbedtls::bignum::Mpi;
    use mbedtls::ecp::EcPoint;

    #[test]
    #[allow(non_snake_case)]
    fn test_get_X() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let x = Mpi::from_binary(&t.x).unwrap();
            c.set_w0(&t.w0).unwrap();
            let P = c.group.generator().unwrap();

            let r = EcPoint::muladd(&mut c.group, &P, &x, &c.M, &c.w0).unwrap();
            assert_eq!(t.X, r.to_binary(&c.group, false).unwrap().as_slice());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_Y() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let y = Mpi::from_binary(&t.y).unwrap();
            c.set_w0(&t.w0).unwrap();
            let P = c.group.generator().unwrap();
            let r = EcPoint::muladd(&mut c.group, &P, &y, &c.N, &c.w0).unwrap();
            assert_eq!(t.Y, r.to_binary(&c.group, false).unwrap().as_slice());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_prover() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let x = Mpi::from_binary(&t.x).unwrap();
            c.set_w0(&t.w0).unwrap();
            c.set_w1(&t.w1).unwrap();
            let Y = EcPoint::from_binary(&c.group, &t.Y).unwrap();
            let (Z, V) =
                CryptoSpake2::get_ZV_as_prover(&c.w0, &c.w1, &c.N, &Y, &x, &c.order, &mut c.group)
                    .unwrap();

            assert_eq!(t.Z, Z.to_binary(&c.group, false).unwrap().as_slice());
            assert_eq!(t.V, V.to_binary(&c.group, false).unwrap().as_slice());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_get_ZV_as_verifier() {
        for t in RFC_T {
            let mut c = CryptoSpake2::new().unwrap();
            let y = Mpi::from_binary(&t.y).unwrap();
            c.set_w0(&t.w0).unwrap();
            let X = EcPoint::from_binary(&c.group, &t.X).unwrap();
            let L = EcPoint::from_binary(&c.group, &t.L).unwrap();
            let (Z, V) =
                CryptoSpake2::get_ZV_as_verifier(&c.w0, &L, &c.M, &X, &y, &c.order, &mut c.group)
                    .unwrap();

            assert_eq!(t.Z, Z.to_binary(&c.group, false).unwrap().as_slice());
            assert_eq!(t.V, V.to_binary(&c.group, false).unwrap().as_slice());
        }
    }
}
