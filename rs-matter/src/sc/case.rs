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

use core::{mem::MaybeUninit, num::NonZeroU8};

use crate::alloc;
use crate::cert::CertRef;
use crate::crypto::{
    CanonPkcSignature, CanonPkcSignatureRef, Crypto, CryptoSensitive, Hash, AEAD_CANON_KEY_LEN,
};
use crate::error::{Error, ErrorCode};
use crate::sc::case::nego::CaseP;
use crate::sc::{
    check_opcode, complete_with_status, sc_write, OpCode, SCStatusCodes, SessionParameters,
};
use crate::tlv::{get_root_node_struct, FromTLV, OctetStr, TLVElement, TLVTag, TLVWrite};
use crate::transport::exchange::Exchange;
use crate::transport::session::{NocCatIds, ReservedSession, SessionMode};
use crate::utils::init::{init, Init, InitMaybeUninit};

mod nego;

/// Sigma1 Request structure
#[derive(FromTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1, lifetime = "'a")]
struct Sigma1Req<'a> {
    /// The initiator's random value
    initiator_random: OctetStr<'a>,
    /// The initiator's session ID
    initiator_sessid: u16,
    /// The destination ID
    dest_id: OctetStr<'a>,
    /// The peer's public key
    peer_pub_key: OctetStr<'a>,
    /// Session parameters (optional)
    session_parameters: Option<SessionParameters>,
    /// Resumption ID (optional)
    resumption_id: Option<OctetStr<'a>>,
    /// Initiator Resume MIC (optional)
    initiator_resume_mic: Option<OctetStr<'a>>,
}

/// Sigma3 Decrypt structure
#[derive(FromTLV, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(start = 1, lifetime = "'a")]
struct Sigma3Decrypt<'a> {
    /// The initiator's Node Operational Certificate
    initiator_noc: OctetStr<'a>,
    /// The initiator's Intermediate Certificate Authority Certificate (optional)
    initiator_icac: Option<OctetStr<'a>>,
    /// The signature
    signature: OctetStr<'a>,
}

/// The CASE protocol handler
pub struct Case<'a, C: Crypto> {
    crypto: &'a C,
    /// The CASE session state
    casep: CaseP<'a, C>,
}

impl<'a, C: Crypto> Case<'a, C> {
    /// Create a new `Case` instance
    #[inline(always)]
    pub const fn new(crypto: &'a C) -> Self {
        Self {
            crypto,
            casep: CaseP::new(),
        }
    }

    /// Return an in-place initializer for `Case`
    pub fn init(crypto: &'a C) -> impl Init<Self> {
        init!(Self {
            crypto,
            casep <- CaseP::init(),
        })
    }

    /// Handle the CASE protocol exchange, where the other peer is the exchange initiator
    ///
    /// # Arguments
    /// - `exchange` - The exchange to handle the CASE protocol on
    pub async fn handle(&mut self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let session = ReservedSession::reserve(exchange.matter(), self.crypto).await?;

        self.handle_casesigma1(exchange).await?;

        exchange.recv_fetch().await?;

        self.handle_casesigma3(exchange, session).await?;

        exchange.acknowledge().await?;
        exchange.matter().notify_persist();

        Ok(())
    }

    /// Handle the CASE Sigma1 message
    ///
    /// # Arguments
    /// - `exchange` - The exchange to handle the CASE Sigma1 message on
    async fn handle_casesigma1(&mut self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        check_opcode(exchange, OpCode::CASESigma1)?;

        let req = Sigma1Req::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;

        let local_fabric_idx = exchange
            .matter()
            .fabric_mgr
            .borrow()
            .get_by_dest_id(self.crypto, req.initiator_random.0, req.dest_id.0)
            .map(|fabric| fabric.fab_idx());
        if local_fabric_idx.is_none() {
            error!("Fabric Index mismatch");
            complete_with_status(exchange, SCStatusCodes::NoSharedTrustRoots, &[]).await?;

            return Ok(());
        }

        let local_sessid = exchange
            .matter()
            .transport_mgr
            .session_mgr
            .borrow_mut()
            .get_next_sess_id();

        let mut our_random = MaybeUninit::<CryptoSensitive<32>>::uninit(); // TODO MEDIUM BUFFER
        let our_random = our_random.init_with(CryptoSensitive::init());

        let mut resumption_id = MaybeUninit::<CryptoSensitive<16>>::uninit(); // TODO MEDIUM BUFFER
        let resumption_id = resumption_id.init_with(CryptoSensitive::init());

        let mut tt_hash = MaybeUninit::<Hash>::uninit(); // TODO MEDIUM BUFFER
        let tt_hash = tt_hash.init_with(Hash::init());

        self.casep.start(
            self.crypto,
            req.initiator_sessid,
            local_sessid,
            unwrap!(local_fabric_idx).get(),
            req.peer_pub_key.0.try_into()?,
            exchange.rx()?.payload(),
            our_random,
            resumption_id,
            tt_hash,
        )?;

        trace!(
            "Destination ID matched to fabric index {}",
            self.casep.local_fabric_idx()
        );

        let mut tt_updated = false;
        exchange
            .send_with(|exchange, tw| {
                let fabric_mgr = exchange.matter().fabric_mgr.borrow();

                let fabric = NonZeroU8::new(self.casep.local_fabric_idx())
                    .and_then(|fabric_idx| fabric_mgr.get(fabric_idx));

                let Some(fabric) = fabric else {
                    return sc_write(tw, SCStatusCodes::NoSharedTrustRoots, &[]);
                };

                let mut signature = MaybeUninit::<CanonPkcSignature>::uninit(); // TODO MEDIUM BUFFER
                let signature = signature.init_with(CanonPkcSignature::init());

                // Use the remainder of the TX buffer as scratch space for computing the signature
                let sign_buf = tw.empty_as_mut_slice();

                self.casep
                    .compute_sigma2_signature(self.crypto, fabric, sign_buf, signature)?;

                tw.start_struct(&TLVTag::Anonymous)?;
                tw.str(&TLVTag::Context(1), our_random.access())?;
                tw.u16(&TLVTag::Context(2), local_sessid)?;
                tw.str(&TLVTag::Context(3), self.casep.our_pub_key().access())?;

                tw.str_cb(&TLVTag::Context(4), |buf| {
                    self.casep.sigma2_encrypt(
                        self.crypto,
                        fabric,
                        our_random.reference(),
                        tt_hash.reference(),
                        signature.reference(),
                        resumption_id.reference(),
                        buf,
                    )
                })?;
                tw.end_container()?;

                if !tt_updated {
                    self.casep.update_tt(tw.as_slice());
                    tt_updated = true;
                }

                Ok(Some(OpCode::CASESigma2.into()))
            })
            .await
    }

    /// Handle the CASE Sigma3 message
    ///
    /// # Arguments
    /// - `exchange` - The exchange to handle the CASE Sigma3 message on
    /// - `session` - The reserved session to complete upon successful CASE handshake
    async fn handle_casesigma3(
        &mut self,
        exchange: &mut Exchange<'_>,
        mut session: ReservedSession<'_>,
    ) -> Result<(), Error> {
        check_opcode(exchange, OpCode::CASESigma3)?;

        let status = {
            let fabric_mgr = exchange.matter().fabric_mgr.borrow();

            let fabric = NonZeroU8::new(self.casep.local_fabric_idx())
                .and_then(|fabric_idx| fabric_mgr.get(fabric_idx));
            if let Some(fabric) = fabric {
                let req = get_root_node_struct(exchange.rx()?.payload())?;
                let encrypted = req.structure()?.ctx(1)?.str()?;

                let mut decrypted = alloc!([0; 800]); // TODO LARGE BUFFER
                if encrypted.len() > decrypted.len() {
                    error!("Encrypted data too large");
                    Err(ErrorCode::BufferTooSmall)?;
                }

                let decrypted = &mut decrypted[..encrypted.len()];
                decrypted.copy_from_slice(encrypted);

                let len =
                    self.casep
                        .sigma3_decrypt(self.crypto, fabric.ipk().op_key(), decrypted)?;
                let decrypted = &decrypted[..len];
                let decrypted_req: Sigma3Decrypt<'_> =
                    Sigma3Decrypt::from_tlv(&get_root_node_struct(decrypted)?)?;

                let initiator_noc = CertRef::new(TLVElement::new(decrypted_req.initiator_noc.0));
                let initiator_icac = decrypted_req
                    .initiator_icac
                    .map(|icac| CertRef::new(TLVElement::new(icac.0)));

                let mut buf = alloc!([0; 800]); // TODO LARGE BUFFER
                let buf = &mut buf[..];
                if let Err(e) = self.casep.validate_certs(
                    self.crypto,
                    fabric,
                    &initiator_noc,
                    initiator_icac.as_ref(),
                    buf,
                ) {
                    error!("Certificate Chain doesn't match: {}", e);
                    SCStatusCodes::InvalidParameter
                } else if let Err(e) = self.casep.validate_sigma3_signature(
                    self.crypto,
                    decrypted_req.initiator_noc.0,
                    decrypted_req.initiator_icac.map(|a| a.0),
                    &initiator_noc,
                    CanonPkcSignatureRef::try_new(decrypted_req.signature.0)?,
                    buf,
                ) {
                    error!("Sigma3 Signature doesn't match: {}", e);
                    SCStatusCodes::InvalidParameter
                } else {
                    // Only now do we add this message to the TT Hash
                    let mut peer_catids: NocCatIds = Default::default();
                    initiator_noc.get_cat_ids(&mut peer_catids)?;
                    self.casep.update_tt(exchange.rx()?.payload());

                    let mut session_keys =
                        MaybeUninit::<CryptoSensitive<{ 3 * AEAD_CANON_KEY_LEN }>>::uninit(); // TODO MEDIM BUFFER
                    let session_keys = session_keys.init_with(CryptoSensitive::init());
                    self.casep.compute_session_keys(
                        self.crypto,
                        fabric.ipk().op_key(),
                        session_keys,
                    )?;

                    let peer_addr = exchange.with_session(|sess| Ok(sess.get_peer_addr()))?;

                    let (dec_key, remaining) = session_keys
                        .reference()
                        .split::<AEAD_CANON_KEY_LEN, { AEAD_CANON_KEY_LEN * 2 }>();
                    let (enc_key, att_challenge) =
                        remaining.split::<AEAD_CANON_KEY_LEN, AEAD_CANON_KEY_LEN>();

                    session.update(
                        fabric.node_id(),
                        initiator_noc.get_node_id()?,
                        self.casep.peer_sessid(),
                        self.casep.local_sessid(),
                        peer_addr,
                        SessionMode::Case {
                            // Unwrapping is safe, because if the fabric index was 0, we would not be in here
                            fab_idx: unwrap!(NonZeroU8::new(self.casep.local_fabric_idx())),
                            cat_ids: peer_catids,
                        },
                        Some(dec_key),
                        Some(enc_key),
                        Some(att_challenge),
                    )?;

                    // Complete the reserved session and thus make the `Session` instance
                    // immediately available for use by the system.
                    //
                    // We need to do this _before_ we send the response to the peer, or else we risk missing
                    // (dropping) the first messages the peer would send us on the newly-established session,
                    // as it might start using it right after it receives the response, while it is still marked
                    // as reserved.
                    session.complete();

                    SCStatusCodes::SessionEstablishmentSuccess
                }
            } else {
                SCStatusCodes::NoSharedTrustRoots
            }
        };

        complete_with_status(exchange, status, &[]).await
    }
}
