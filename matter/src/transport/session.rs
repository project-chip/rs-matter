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

use crate::data_model::sdm::noc::NocData;
use crate::utils::epoch::Epoch;
use crate::utils::rand::Rand;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::time::Duration;

use crate::{
    error::*,
    transport::{plain_hdr, proto_hdr},
    utils::writebuf::WriteBuf,
};
use log::{info, trace};

use super::dedup::RxCtrState;
use super::{network::Address, packet::Packet};

pub const MAX_CAT_IDS_PER_NOC: usize = 3;
pub type NocCatIds = [u32; MAX_CAT_IDS_PER_NOC];

const MATTER_AES128_KEY_SIZE: usize = 16;

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct CaseDetails {
    pub fab_idx: u8,
    pub cat_ids: NocCatIds,
}

impl CaseDetails {
    pub fn new(fab_idx: u8, cat_ids: &NocCatIds) -> Self {
        Self {
            fab_idx,
            cat_ids: *cat_ids,
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub enum SessionMode {
    // The Case session will capture the local fabric index
    Case(CaseDetails),
    Pase,
    #[default]
    PlainText,
}

pub struct Session {
    peer_addr: Address,
    local_nodeid: u64,
    peer_nodeid: Option<u64>,
    // I find the session initiator/responder role getting confused with exchange initiator/responder
    // So, we might keep this as enc_key and dec_key for now
    dec_key: [u8; MATTER_AES128_KEY_SIZE],
    enc_key: [u8; MATTER_AES128_KEY_SIZE],
    att_challenge: [u8; MATTER_AES128_KEY_SIZE],
    local_sess_id: u16,
    peer_sess_id: u16,
    msg_ctr: u32,
    rx_ctr_state: RxCtrState,
    mode: SessionMode,
    data: Option<NocData>,
    last_use: Duration,
}

#[derive(Debug)]
pub struct CloneData {
    pub dec_key: [u8; MATTER_AES128_KEY_SIZE],
    pub enc_key: [u8; MATTER_AES128_KEY_SIZE],
    pub att_challenge: [u8; MATTER_AES128_KEY_SIZE],
    local_sess_id: u16,
    peer_sess_id: u16,
    local_nodeid: u64,
    peer_nodeid: u64,
    peer_addr: Address,
    mode: SessionMode,
}

impl CloneData {
    pub fn new(
        local_nodeid: u64,
        peer_nodeid: u64,
        peer_sess_id: u16,
        local_sess_id: u16,
        peer_addr: Address,
        mode: SessionMode,
    ) -> CloneData {
        CloneData {
            dec_key: [0; MATTER_AES128_KEY_SIZE],
            enc_key: [0; MATTER_AES128_KEY_SIZE],
            att_challenge: [0; MATTER_AES128_KEY_SIZE],
            local_nodeid,
            peer_nodeid,
            peer_addr,
            peer_sess_id,
            local_sess_id,
            mode,
        }
    }
}

const MATTER_MSG_CTR_RANGE: u32 = 0x0fffffff;

impl Session {
    pub fn new(peer_addr: Address, peer_nodeid: Option<u64>, epoch: Epoch, rand: Rand) -> Self {
        Self {
            peer_addr,
            local_nodeid: 0,
            peer_nodeid,
            dec_key: [0; MATTER_AES128_KEY_SIZE],
            enc_key: [0; MATTER_AES128_KEY_SIZE],
            att_challenge: [0; MATTER_AES128_KEY_SIZE],
            peer_sess_id: 0,
            local_sess_id: 0,
            msg_ctr: Self::rand_msg_ctr(rand),
            rx_ctr_state: RxCtrState::new(0),
            mode: SessionMode::PlainText,
            data: None,
            last_use: epoch(),
        }
    }

    // A new encrypted session always clones from a previous 'new' session
    pub fn clone(clone_from: &CloneData, epoch: Epoch, rand: Rand) -> Session {
        Session {
            peer_addr: clone_from.peer_addr,
            local_nodeid: clone_from.local_nodeid,
            peer_nodeid: Some(clone_from.peer_nodeid),
            dec_key: clone_from.dec_key,
            enc_key: clone_from.enc_key,
            att_challenge: clone_from.att_challenge,
            local_sess_id: clone_from.local_sess_id,
            peer_sess_id: clone_from.peer_sess_id,
            msg_ctr: Self::rand_msg_ctr(rand),
            rx_ctr_state: RxCtrState::new(0),
            mode: clone_from.mode,
            data: None,
            last_use: epoch(),
        }
    }

    pub fn set_noc_data(&mut self, data: NocData) {
        self.data = Some(data);
    }

    pub fn clear_noc_data(&mut self) {
        self.data = None;
    }

    pub fn get_noc_data(&mut self) -> Option<&mut NocData> {
        self.data.as_mut()
    }

    pub fn take_noc_data(&mut self) -> Option<NocData> {
        self.data.take()
    }

    pub fn get_local_sess_id(&self) -> u16 {
        self.local_sess_id
    }

    #[cfg(test)]
    pub fn set_local_sess_id(&mut self, sess_id: u16) {
        self.local_sess_id = sess_id;
    }

    pub fn get_peer_sess_id(&self) -> u16 {
        self.peer_sess_id
    }

    pub fn get_peer_addr(&self) -> Address {
        self.peer_addr
    }

    pub fn is_encrypted(&self) -> bool {
        match self.mode {
            SessionMode::Case(_) | SessionMode::Pase => true,
            SessionMode::PlainText => false,
        }
    }

    pub fn get_peer_node_id(&self) -> Option<u64> {
        self.peer_nodeid
    }

    pub fn get_peer_cat_ids(&self) -> Option<&NocCatIds> {
        match &self.mode {
            SessionMode::Case(a) => Some(&a.cat_ids),
            _ => None,
        }
    }

    pub fn get_local_fabric_idx(&self) -> Option<u8> {
        match self.mode {
            SessionMode::Case(a) => Some(a.fab_idx),
            _ => None,
        }
    }

    pub fn get_session_mode(&self) -> SessionMode {
        self.mode
    }

    pub fn get_msg_ctr(&mut self) -> u32 {
        let ctr = self.msg_ctr;
        self.msg_ctr += 1;
        ctr
    }

    pub fn get_dec_key(&self) -> Option<&[u8]> {
        match self.mode {
            SessionMode::Case(_) | SessionMode::Pase => Some(&self.dec_key),
            SessionMode::PlainText => None,
        }
    }

    pub fn get_enc_key(&self) -> Option<&[u8]> {
        match self.mode {
            SessionMode::Case(_) | SessionMode::Pase => Some(&self.enc_key),
            SessionMode::PlainText => None,
        }
    }

    pub fn get_att_challenge(&self) -> &[u8] {
        &self.att_challenge
    }

    pub fn recv(&mut self, epoch: Epoch, rx: &mut Packet) -> Result<(), Error> {
        self.last_use = epoch();
        rx.proto_decode(self.peer_nodeid.unwrap_or_default(), self.get_dec_key())
    }

    pub fn pre_send(&mut self, tx: &mut Packet) -> Result<(), Error> {
        tx.plain.sess_id = self.get_peer_sess_id();
        tx.plain.ctr = self.get_msg_ctr();
        if self.is_encrypted() {
            tx.plain.sess_type = plain_hdr::SessionType::Encrypted;
        }
        Ok(())
    }

    // TODO: Most of this can now be moved into the 'Packet' module
    fn do_send(&mut self, epoch: Epoch, tx: &mut Packet) -> Result<(), Error> {
        self.last_use = epoch();
        tx.peer = self.peer_addr;

        // Generate encrypted header
        let mut tmp_buf = [0_u8; proto_hdr::max_proto_hdr_len()];
        let mut write_buf = WriteBuf::new(&mut tmp_buf);
        tx.proto.encode(&mut write_buf)?;
        tx.get_writebuf()?.prepend(write_buf.as_slice())?;

        // Generate plain-text header
        if self.mode == SessionMode::PlainText {
            if let Some(d) = self.peer_nodeid {
                tx.plain.set_dest_u64(d);
            }
        }
        let mut tmp_buf = [0_u8; plain_hdr::max_plain_hdr_len()];
        let mut write_buf = WriteBuf::new(&mut tmp_buf);
        tx.plain.encode(&mut write_buf)?;
        let plain_hdr_bytes = write_buf.as_slice();

        trace!("unencrypted packet: {:x?}", tx.as_mut_slice());
        let ctr = tx.plain.ctr;
        let enc_key = self.get_enc_key();
        if let Some(e) = enc_key {
            proto_hdr::encrypt_in_place(
                ctr,
                self.local_nodeid,
                plain_hdr_bytes,
                tx.get_writebuf()?,
                e,
            )?;
        }

        tx.get_writebuf()?.prepend(plain_hdr_bytes)?;
        trace!("Full encrypted packet: {:x?}", tx.as_mut_slice());
        Ok(())
    }

    fn rand_msg_ctr(rand: Rand) -> u32 {
        let mut buf = [0; 4];
        rand(&mut buf);
        u32::from_be_bytes(buf) & MATTER_MSG_CTR_RANGE
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer: {:?}, peer_nodeid: {:?}, local: {}, remote: {}, msg_ctr: {}, mode: {:?}, ts: {:?}",
            self.peer_addr,
            self.peer_nodeid,
            self.local_sess_id,
            self.peer_sess_id,
            self.msg_ctr,
            self.mode,
            self.last_use,
        )
    }
}

pub const MAX_SESSIONS: usize = 16;

pub struct SessionMgr {
    next_sess_id: u16,
    sessions: heapless::Vec<Option<Session>, MAX_SESSIONS>,
    epoch: Epoch,
    rand: Rand,
}

impl SessionMgr {
    #[inline(always)]
    pub fn new(epoch: Epoch, rand: Rand) -> Self {
        Self {
            sessions: heapless::Vec::new(),
            next_sess_id: 1,
            epoch,
            rand,
        }
    }

    pub fn mut_by_index(&mut self, index: usize) -> Option<&mut Session> {
        self.sessions.get_mut(index).and_then(Option::as_mut)
    }

    pub fn get_next_sess_id(&mut self) -> u16 {
        let mut next_sess_id: u16;
        loop {
            next_sess_id = self.next_sess_id;

            // Increment next sess id
            self.next_sess_id = self.next_sess_id.overflowing_add(1).0;
            if self.next_sess_id == 0 {
                self.next_sess_id = 1;
            }

            // Ensure the currently selected id doesn't match any existing session
            if self.get_with_id(next_sess_id).is_none() {
                break;
            }
        }
        next_sess_id
    }

    pub fn get_session_for_eviction(&self) -> Option<usize> {
        if self.sessions.len() == MAX_SESSIONS && self.get_empty_slot().is_none() {
            Some(self.get_lru())
        } else {
            None
        }
    }

    fn get_empty_slot(&self) -> Option<usize> {
        self.sessions.iter().position(|x| x.is_none())
    }

    fn get_lru(&self) -> usize {
        let mut lru_index = 0;
        let mut lru_ts = (self.epoch)();
        for (i, s) in self.sessions.iter().enumerate() {
            if let Some(s) = s {
                if s.last_use < lru_ts {
                    lru_ts = s.last_use;
                    lru_index = i;
                }
            }
        }
        lru_index
    }

    pub fn add(&mut self, peer_addr: Address, peer_nodeid: Option<u64>) -> Result<usize, Error> {
        let session = Session::new(peer_addr, peer_nodeid, self.epoch, self.rand);
        self.add_session(session)
    }

    /// This assumes that the higher layer has taken care of doing anything required
    /// as per the spec before the session is erased
    pub fn remove(&mut self, idx: usize) {
        self.sessions[idx] = None;
    }

    /// We could have returned a SessionHandle here. But the borrow checker doesn't support
    /// non-lexical lifetimes. This makes it harder for the caller of this function to take
    /// action in the error return path
    fn add_session(&mut self, session: Session) -> Result<usize, Error> {
        if let Some(index) = self.get_empty_slot() {
            self.sessions[index] = Some(session);
            Ok(index)
        } else if self.sessions.len() < MAX_SESSIONS {
            self.sessions
                .push(Some(session))
                .map_err(|_| ErrorCode::NoSpace)
                .unwrap();

            Ok(self.sessions.len() - 1)
        } else {
            Err(ErrorCode::NoSpace.into())
        }
    }

    pub fn clone_session(&mut self, clone_data: &CloneData) -> Result<usize, Error> {
        let session = Session::clone(clone_data, self.epoch, self.rand);
        self.add_session(session)
    }

    pub fn get(
        &self,
        sess_id: u16,
        peer_addr: Address,
        peer_nodeid: Option<u64>,
        is_encrypted: bool,
    ) -> Option<usize> {
        self.sessions.iter().position(|x| {
            if let Some(x) = x {
                let mut nodeid_matches = true;
                if x.peer_nodeid.is_some() && peer_nodeid.is_some() && x.peer_nodeid != peer_nodeid
                {
                    nodeid_matches = false;
                }
                x.local_sess_id == sess_id
                    && x.peer_addr == peer_addr
                    && x.is_encrypted() == is_encrypted
                    && nodeid_matches
            } else {
                false
            }
        })
    }

    pub fn get_with_id(&mut self, sess_id: u16) -> Option<SessionHandle> {
        let index = self
            .sessions
            .iter_mut()
            .position(|x| x.as_ref().map(|s| s.local_sess_id) == Some(sess_id))?;
        Some(self.get_session_handle(index))
    }

    fn get_or_add(
        &mut self,
        sess_id: u16,
        peer_addr: Address,
        peer_nodeid: Option<u64>,
        is_encrypted: bool,
    ) -> Result<usize, Error> {
        if let Some(index) = self.get(sess_id, peer_addr, peer_nodeid, is_encrypted) {
            Ok(index)
        } else if sess_id == 0 && !is_encrypted {
            // We must create a new session for this case
            info!("Creating new session");
            self.add(peer_addr, peer_nodeid)
        } else {
            Err(ErrorCode::NotFound.into())
        }
    }

    // We will try to get a session for this Packet. If no session exists, we will try to add one
    // If the session list is full we will return a None
    pub fn post_recv(&mut self, rx: &Packet) -> Result<usize, Error> {
        let sess_index = self.get_or_add(
            rx.plain.sess_id,
            rx.peer,
            rx.plain.get_src_u64(),
            rx.plain.is_encrypted(),
        )?;

        let session = self.sessions[sess_index].as_mut().unwrap();
        let is_encrypted = session.is_encrypted();
        let duplicate = session.rx_ctr_state.recv(rx.plain.ctr, is_encrypted);
        if duplicate {
            info!("Dropping duplicate packet");
            Err(ErrorCode::Duplicate.into())
        } else {
            Ok(sess_index)
        }
    }

    pub fn decode(&mut self, rx: &mut Packet) -> Result<(), Error> {
        // let network = self.network.as_ref().ok_or(ErrorCode::NoNetworkInterface)?;

        // let (len, src) = network.recv(rx.as_borrow_slice()).await?;
        // rx.get_parsebuf()?.set_len(len);
        // rx.peer = src;

        // info!("{} from src: {}", "Received".blue(), src);
        // trace!("payload: {:x?}", rx.as_borrow_slice());

        // Read unencrypted packet header
        rx.plain_hdr_decode()
    }

    pub fn send(&mut self, sess_idx: usize, tx: &mut Packet) -> Result<(), Error> {
        self.sessions[sess_idx]
            .as_mut()
            .ok_or(ErrorCode::NoSession)?
            .do_send(self.epoch, tx)?;

        // let network = self.network.as_ref().ok_or(Error::NoNetworkInterface)?;
        // let peer = proto_tx.peer;
        // network.send(proto_tx.as_borrow_slice(), peer).await?;
        // info!("Message Sent to {}", peer);

        Ok(())
    }

    pub fn get_session_handle(&mut self, sess_idx: usize) -> SessionHandle {
        SessionHandle {
            sess_mgr: self,
            sess_idx,
        }
    }
}

impl fmt::Display for SessionMgr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{{[")?;
        for s in self.sessions.iter().flatten() {
            writeln!(f, "{{ {}, }},", s)?;
        }
        write!(f, "], next_sess_id: {}", self.next_sess_id)?;
        write!(f, "}}")
    }
}

pub struct SessionHandle<'a> {
    pub(crate) sess_mgr: &'a mut SessionMgr,
    sess_idx: usize,
}

impl<'a> SessionHandle<'a> {
    pub fn session(&self) -> &Session {
        self.sess_mgr.sessions[self.sess_idx].as_ref().unwrap()
    }

    pub fn session_mut(&mut self) -> &mut Session {
        self.sess_mgr.sessions[self.sess_idx].as_mut().unwrap()
    }

    pub fn reserve_new_sess_id(&mut self) -> u16 {
        self.sess_mgr.get_next_sess_id()
    }

    pub fn send(&mut self, tx: &mut Packet) -> Result<(), Error> {
        self.sess_mgr.send(self.sess_idx, tx)
    }
}

impl<'a> Deref for SessionHandle<'a> {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        // There is no other option but to panic if this is None
        self.session()
    }
}

impl<'a> DerefMut for SessionHandle<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // There is no other option but to panic if this is None
        self.session_mut()
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        transport::network::Address,
        utils::{epoch::dummy_epoch, rand::dummy_rand},
    };

    use super::SessionMgr;

    #[test]
    fn test_next_sess_id_doesnt_reuse() {
        let mut sm = SessionMgr::new(dummy_epoch, dummy_rand);
        let sess_idx = sm.add(Address::default(), None).unwrap();
        let mut sess = sm.get_session_handle(sess_idx);
        sess.set_local_sess_id(1);
        assert_eq!(sm.get_next_sess_id(), 2);
        assert_eq!(sm.get_next_sess_id(), 3);
        let sess_idx = sm.add(Address::default(), None).unwrap();
        let mut sess = sm.get_session_handle(sess_idx);
        sess.set_local_sess_id(4);
        assert_eq!(sm.get_next_sess_id(), 5);
    }

    #[test]
    fn test_next_sess_id_overflows() {
        let mut sm = SessionMgr::new(dummy_epoch, dummy_rand);
        let sess_idx = sm.add(Address::default(), None).unwrap();
        let mut sess = sm.get_session_handle(sess_idx);
        sess.set_local_sess_id(1);
        assert_eq!(sm.get_next_sess_id(), 2);
        sm.next_sess_id = 65534;
        assert_eq!(sm.get_next_sess_id(), 65534);
        assert_eq!(sm.get_next_sess_id(), 65535);
        assert_eq!(sm.get_next_sess_id(), 2);
    }
}
