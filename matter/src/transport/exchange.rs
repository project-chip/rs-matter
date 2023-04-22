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

use colored::*;
use core::any::Any;
use core::fmt;
use core::time::Duration;
use log::{error, info, trace};

use crate::error::Error;
use crate::interaction_model::core::{ResumeReadReq, ResumeSubscribeReq};
use crate::secure_channel;
use crate::secure_channel::case::CaseSession;
use crate::utils::epoch::Epoch;
use crate::utils::rand::Rand;

use heapless::LinearMap;

use super::session::CloneData;
use super::{mrp::ReliableMessage, packet::Packet, session::SessionHandle, session::SessionMgr};

pub struct ExchangeCtx<'a> {
    pub exch: &'a mut Exchange,
    pub sess: SessionHandle<'a>,
    pub epoch: Epoch,
}

impl<'a> ExchangeCtx<'a> {
    pub fn send(&mut self, tx: &mut Packet) -> Result<(), Error> {
        self.exch.send(tx, &mut self.sess)
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
pub enum Role {
    #[default]
    Initiator = 0,
    Responder = 1,
}

#[derive(Debug, PartialEq, Default)]
enum State {
    /// The exchange is open and active
    #[default]
    Open,
    /// The exchange is closed, but keys are active since retransmissions/acks may be pending
    Close,
    /// The exchange is terminated, keys are destroyed, no communication can happen
    Terminate,
}

// Instead of just doing an Option<>, we create some special handling
// where the commonly used higher layer data store does't have to do a Box
#[derive(Default)]
pub enum DataOption {
    CaseSession(CaseSession),
    Time(Duration),
    SuspendedReadReq(ResumeReadReq),
    SuspendedSubscibeReq(ResumeSubscribeReq),
    #[default]
    None,
}

#[derive(Default)]
pub struct Exchange {
    id: u16,
    sess_idx: usize,
    role: Role,
    state: State,
    mrp: ReliableMessage,
    // Currently I see this primarily used in PASE and CASE. If that is the limited use
    // of this, we might move this into a separate data structure, so as not to burden
    // all 'exchanges'.
    data: DataOption,
}

impl Exchange {
    pub fn new(id: u16, sess_idx: usize, role: Role) -> Exchange {
        Exchange {
            id,
            sess_idx,
            role,
            state: State::Open,
            mrp: ReliableMessage::new(),
            ..Default::default()
        }
    }

    pub fn terminate(&mut self) {
        self.data = DataOption::None;
        self.state = State::Terminate;
    }

    pub fn close(&mut self) {
        self.data = DataOption::None;
        self.state = State::Close;
    }

    pub fn is_state_open(&self) -> bool {
        self.state == State::Open
    }

    pub fn is_purgeable(&self) -> bool {
        // No Users, No pending ACKs/Retrans
        self.state == State::Terminate || (self.state == State::Close && self.mrp.is_empty())
    }

    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn get_role(&self) -> Role {
        self.role
    }

    pub fn clear_data(&mut self) {
        self.data = DataOption::None;
    }

    pub fn set_case_session(&mut self, session: CaseSession) {
        self.data = DataOption::CaseSession(session);
    }

    pub fn get_case_session(&mut self) -> Option<&mut CaseSession> {
        if let DataOption::CaseSession(session) = &mut self.data {
            Some(session)
        } else {
            None
        }
    }

    pub fn take_case_session<T: Any>(&mut self) -> Option<CaseSession> {
        let old = core::mem::replace(&mut self.data, DataOption::None);
        if let DataOption::CaseSession(session) = old {
            Some(session)
        } else {
            self.data = old;
            None
        }
    }

    pub fn set_suspended_read_req(&mut self, req: ResumeReadReq) {
        self.data = DataOption::SuspendedReadReq(req);
    }

    pub fn take_suspended_read_req(&mut self) -> Option<ResumeReadReq> {
        let old = core::mem::replace(&mut self.data, DataOption::None);
        if let DataOption::SuspendedReadReq(req) = old {
            Some(req)
        } else {
            self.data = old;
            None
        }
    }

    pub fn set_suspended_subscribe_req(&mut self, req: ResumeSubscribeReq) {
        self.data = DataOption::SuspendedSubscibeReq(req);
    }

    pub fn take_suspended_subscribe_req(&mut self) -> Option<ResumeSubscribeReq> {
        let old = core::mem::replace(&mut self.data, DataOption::None);
        if let DataOption::SuspendedSubscibeReq(req) = old {
            Some(req)
        } else {
            self.data = old;
            None
        }
    }

    pub fn set_data_time(&mut self, expiry_ts: Option<Duration>) {
        if let Some(t) = expiry_ts {
            self.data = DataOption::Time(t);
        }
    }

    pub fn get_data_time(&self) -> Option<Duration> {
        match self.data {
            DataOption::Time(t) => Some(t),
            _ => None,
        }
    }

    pub(crate) fn send(
        &mut self,
        tx: &mut Packet,
        session: &mut SessionHandle,
    ) -> Result<(), Error> {
        if self.state == State::Terminate {
            info!("Skipping tx for terminated exchange {}", self.id);
            return Ok(());
        }

        trace!("payload: {:x?}", tx.as_mut_slice());
        info!(
            "{} with proto id: {} opcode: {}",
            "Sending".blue(),
            tx.get_proto_id(),
            tx.get_proto_opcode(),
        );

        tx.proto.exch_id = self.id;
        if self.role == Role::Initiator {
            tx.proto.set_initiator();
        }

        session.pre_send(tx)?;
        self.mrp.pre_send(tx)?;
        session.send(tx)
    }
}

impl fmt::Display for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "exch_id: {:?}, sess_index: {}, role: {:?}, mrp: {:?}, state: {:?}",
            self.id, self.sess_idx, self.role, self.mrp, self.state
        )
    }
}

pub fn get_role(is_initiator: bool) -> Role {
    if is_initiator {
        Role::Initiator
    } else {
        Role::Responder
    }
}

pub fn get_complementary_role(is_initiator: bool) -> Role {
    if is_initiator {
        Role::Responder
    } else {
        Role::Initiator
    }
}

const MAX_EXCHANGES: usize = 8;

pub struct ExchangeMgr {
    // keys: exch-id
    exchanges: LinearMap<u16, Exchange, MAX_EXCHANGES>,
    sess_mgr: SessionMgr,
    epoch: Epoch,
}

pub const MAX_MRP_ENTRIES: usize = 4;

impl ExchangeMgr {
    pub fn new(epoch: Epoch, rand: Rand) -> Self {
        Self {
            sess_mgr: SessionMgr::new(epoch, rand),
            exchanges: LinearMap::new(),
            epoch,
        }
    }

    pub fn get_sess_mgr(&mut self) -> &mut SessionMgr {
        &mut self.sess_mgr
    }

    pub fn _get_with_id(
        exchanges: &mut LinearMap<u16, Exchange, MAX_EXCHANGES>,
        exch_id: u16,
    ) -> Option<&mut Exchange> {
        exchanges.get_mut(&exch_id)
    }

    pub fn get_with_id(&mut self, exch_id: u16) -> Option<&mut Exchange> {
        ExchangeMgr::_get_with_id(&mut self.exchanges, exch_id)
    }

    fn _get(
        exchanges: &mut LinearMap<u16, Exchange, MAX_EXCHANGES>,
        sess_idx: usize,
        id: u16,
        role: Role,
        create_new: bool,
    ) -> Result<&mut Exchange, Error> {
        // I don't prefer that we scan the list twice here (once for contains_key and other)
        if !exchanges.contains_key(&(id)) {
            if create_new {
                // If an exchange doesn't exist, create a new one
                info!("Creating new exchange");
                let e = Exchange::new(id, sess_idx, role);
                if exchanges.insert(id, e).is_err() {
                    return Err(Error::NoSpace);
                }
            } else {
                return Err(Error::NoSpace);
            }
        }

        // At this point, we would either have inserted the record if 'create_new' was set
        // or it existed already
        if let Some(result) = exchanges.get_mut(&id) {
            if result.get_role() == role && sess_idx == result.sess_idx {
                Ok(result)
            } else {
                Err(Error::NoExchange)
            }
        } else {
            error!("This should never happen");
            Err(Error::NoSpace)
        }
    }

    /// The Exchange Mgr receive is like a big processing function
    pub fn recv(&mut self, rx: &mut Packet) -> Result<Option<ExchangeCtx>, Error> {
        // Get the session
        let index = self.sess_mgr.post_recv(rx)?;
        let mut session = self.sess_mgr.get_session_handle(index);

        // Decrypt the message
        session.recv(self.epoch, rx)?;

        // Get the exchange
        let exch = ExchangeMgr::_get(
            &mut self.exchanges,
            index,
            rx.proto.exch_id,
            get_complementary_role(rx.proto.is_initiator()),
            // We create a new exchange, only if the peer is the initiator
            rx.proto.is_initiator(),
        )?;

        // Message Reliability Protocol
        exch.mrp.recv(rx, self.epoch)?;

        if exch.is_state_open() {
            Ok(Some(ExchangeCtx {
                exch,
                sess: session,
                epoch: self.epoch,
            }))
        } else {
            // Instead of an error, we send None here, because it is likely that
            // we just processed an acknowledgement that cleared the exchange
            Ok(None)
        }
    }

    pub fn send(&mut self, exch_id: u16, tx: &mut Packet) -> Result<(), Error> {
        let exchange =
            ExchangeMgr::_get_with_id(&mut self.exchanges, exch_id).ok_or(Error::NoExchange)?;
        let mut session = self.sess_mgr.get_session_handle(exchange.sess_idx);
        exchange.send(tx, &mut session)
    }

    pub fn purge(&mut self) {
        let mut to_purge: LinearMap<u16, (), MAX_EXCHANGES> = LinearMap::new();

        for (exch_id, exchange) in self.exchanges.iter() {
            if exchange.is_purgeable() {
                let _ = to_purge.insert(*exch_id, ());
            }
        }
        for (exch_id, _) in to_purge.iter() {
            self.exchanges.remove(exch_id);
        }
    }

    pub fn pending_ack(&mut self) -> Option<u16> {
        self.exchanges
            .iter()
            .find(|(_, exchange)| exchange.mrp.is_ack_ready(self.epoch))
            .map(|(exch_id, _)| *exch_id)
    }

    pub fn evict_session(&mut self, tx: &mut Packet) -> Result<bool, Error> {
        if let Some(index) = self.sess_mgr.get_session_for_eviction() {
            info!("Sessions full, vacating session with index: {}", index);
            // If we enter here, we have an LRU session that needs to be reclaimed
            // As per the spec, we need to send a CLOSE here

            let mut session = self.sess_mgr.get_session_handle(index);
            secure_channel::common::create_sc_status_report(
                tx,
                secure_channel::common::SCStatusCodes::CloseSession,
                None,
            )?;

            if let Some((_, exchange)) =
                self.exchanges.iter_mut().find(|(_, e)| e.sess_idx == index)
            {
                // Send Close_session on this exchange, and then close the session
                // Should this be done for all exchanges?
                error!("Sending Close Session");
                exchange.send(tx, &mut session)?;
                // TODO: This wouldn't actually send it out, because 'transport' isn't owned yet.
            }

            let remove_exchanges: heapless::Vec<u16, MAX_EXCHANGES> = self
                .exchanges
                .iter()
                .filter_map(|(eid, e)| {
                    if e.sess_idx == index {
                        Some(*eid)
                    } else {
                        None
                    }
                })
                .collect();
            info!(
                "Terminating the following exchanges: {:?}",
                remove_exchanges
            );
            for exch_id in remove_exchanges {
                // Remove from exchange list
                self.exchanges.remove(&exch_id);
            }
            self.sess_mgr.remove(index);

            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn add_session(&mut self, clone_data: &CloneData) -> Result<SessionHandle, Error> {
        let sess_idx = self.sess_mgr.clone_session(clone_data)?;

        Ok(self.sess_mgr.get_session_handle(sess_idx))
    }
}

impl fmt::Display for ExchangeMgr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{{  Session Mgr: {},", self.sess_mgr)?;
        writeln!(f, "  Exchanges: [")?;
        for s in &self.exchanges {
            writeln!(f, "{{ {}, }},", s.1)?;
        }
        writeln!(f, "  ]")?;
        write!(f, "}}")
    }
}

#[cfg(test)]
#[allow(clippy::bool_assert_comparison)]
mod tests {
    use crate::{
        error::Error,
        transport::{
            network::Address,
            packet::{Packet, MAX_TX_BUF_SIZE},
            session::{CloneData, SessionMode, MAX_SESSIONS},
        },
        utils::{
            epoch::{dummy_epoch, sys_epoch},
            rand::dummy_rand,
        },
    };

    use super::{ExchangeMgr, Role};

    #[test]
    fn test_purge() {
        let mut mgr = ExchangeMgr::new(dummy_epoch, dummy_rand);
        let _ = ExchangeMgr::_get(&mut mgr.exchanges, 1, 2, Role::Responder, true).unwrap();
        let _ = ExchangeMgr::_get(&mut mgr.exchanges, 1, 3, Role::Responder, true).unwrap();

        mgr.purge();
        assert_eq!(
            ExchangeMgr::_get(&mut mgr.exchanges, 1, 2, Role::Responder, false).is_ok(),
            true
        );
        assert_eq!(
            ExchangeMgr::_get(&mut mgr.exchanges, 1, 3, Role::Responder, false).is_ok(),
            true
        );

        // Close e1
        let e1 = ExchangeMgr::_get(&mut mgr.exchanges, 1, 2, Role::Responder, false).unwrap();
        e1.close();
        mgr.purge();
        assert_eq!(
            ExchangeMgr::_get(&mut mgr.exchanges, 1, 2, Role::Responder, false).is_ok(),
            false
        );
        assert_eq!(
            ExchangeMgr::_get(&mut mgr.exchanges, 1, 3, Role::Responder, false).is_ok(),
            true
        );
    }

    fn get_clone_data(peer_sess_id: u16, local_sess_id: u16) -> CloneData {
        CloneData::new(
            12341234,
            43211234,
            peer_sess_id,
            local_sess_id,
            Address::default(),
            SessionMode::Pase,
        )
    }

    fn fill_sessions(mgr: &mut ExchangeMgr, count: usize) {
        let mut local_sess_id = 1;
        let mut peer_sess_id = 100;
        for _ in 1..count {
            let clone_data = get_clone_data(peer_sess_id, local_sess_id);
            match mgr.add_session(&clone_data) {
                Ok(s) => assert_eq!(peer_sess_id, s.get_peer_sess_id()),
                Err(Error::NoSpace) => break,
                _ => {
                    panic!("Couldn't, create session");
                }
            }
            local_sess_id += 1;
            peer_sess_id += 1;
        }
    }

    #[test]
    /// We purposefuly overflow the sessions
    /// and when the overflow happens, we confirm that
    /// - The sessions are evicted in LRU
    /// - The exchanges associated with those sessions are evicted too
    fn test_sess_evict() {
        let mut mgr = ExchangeMgr::new(sys_epoch, dummy_rand);

        fill_sessions(&mut mgr, MAX_SESSIONS + 1);
        // Sessions are now full from local session id 1 to 16

        // Create exchanges for sessions 2 (i.e. session index 1) and 3 (session index 2)
        //   Exchange IDs are 20 and 30 respectively
        let _ = ExchangeMgr::_get(&mut mgr.exchanges, 1, 20, Role::Responder, true).unwrap();
        let _ = ExchangeMgr::_get(&mut mgr.exchanges, 2, 30, Role::Responder, true).unwrap();

        // Confirm that session ids 1 to MAX_SESSIONS exists
        for i in 1..(MAX_SESSIONS + 1) {
            assert_eq!(mgr.sess_mgr.get_with_id(i as u16).is_none(), false);
        }
        // Confirm that the exchanges are around
        assert_eq!(mgr.get_with_id(20).is_none(), false);
        assert_eq!(mgr.get_with_id(30).is_none(), false);
        let mut old_local_sess_id = 1;
        let mut new_local_sess_id = 100;
        let mut new_peer_sess_id = 200;

        for i in 1..(MAX_SESSIONS + 1) {
            // Now purposefully overflow the sessions by adding another session
            let result = mgr.add_session(&get_clone_data(new_peer_sess_id, new_local_sess_id));
            assert!(matches!(result, Err(Error::NoSpace)));

            let mut buf = [0; MAX_TX_BUF_SIZE];
            let tx = &mut Packet::new_tx(&mut buf);
            let evicted = mgr.evict_session(tx).unwrap();
            assert!(evicted);

            let session = mgr
                .add_session(&get_clone_data(new_peer_sess_id, new_local_sess_id))
                .unwrap();
            assert_eq!(session.get_peer_sess_id(), new_peer_sess_id);

            // This should have evicted session with local sess_id
            assert_eq!(mgr.sess_mgr.get_with_id(old_local_sess_id).is_none(), true);

            new_local_sess_id += 1;
            new_peer_sess_id += 1;
            old_local_sess_id += 1;

            match i {
                1 => {
                    // Both exchanges should exist
                    assert_eq!(mgr.get_with_id(20).is_none(), false);
                    assert_eq!(mgr.get_with_id(30).is_none(), false);
                }
                2 => {
                    // Exchange 20 would have been evicted
                    assert_eq!(mgr.get_with_id(20).is_none(), true);
                    assert_eq!(mgr.get_with_id(30).is_none(), false);
                }
                3 => {
                    // Exchange 20 and 30 would have been evicted
                    assert_eq!(mgr.get_with_id(20).is_none(), true);
                    assert_eq!(mgr.get_with_id(30).is_none(), true);
                }
                _ => {}
            }
        }
        //        println!("Session mgr {}", mgr.sess_mgr);
    }
}
