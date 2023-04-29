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

use core::borrow::Borrow;
use core::cell::RefCell;

use log::info;

use crate::error::*;
use crate::fabric::FabricMgr;
use crate::mdns::MdnsMgr;
use crate::secure_channel::pake::PaseMgr;

use crate::secure_channel::common::PROTO_ID_SECURE_CHANNEL;
use crate::secure_channel::core::SecureChannel;
use crate::transport::mrp::ReliableMessage;
use crate::transport::{exchange, network::Address, packet::Packet};
use crate::utils::epoch::{Epoch, UtcCalendar};
use crate::utils::rand::Rand;

use super::proto_ctx::ProtoCtx;
use super::session::CloneData;

enum RecvState {
    New,
    OpenExchange,
    AddSession(CloneData),
    EvictSession,
    EvictSession2(CloneData),
    Ack,
}

pub enum RecvAction<'r, 'p> {
    Send(Address, &'r [u8]),
    Interact(ProtoCtx<'r, 'p>),
}

pub struct RecvCompletion<'r, 'a, 'p> {
    mgr: &'r mut TransportMgr<'a>,
    rx: Packet<'p>,
    tx: Packet<'p>,
    state: RecvState,
}

impl<'r, 'a, 'p> RecvCompletion<'r, 'a, 'p> {
    pub fn next_action(&mut self) -> Result<Option<RecvAction<'_, 'p>>, Error> {
        loop {
            // Polonius will remove the need for unsafe one day
            let this = unsafe { (self as *mut RecvCompletion).as_mut().unwrap() };

            if let Some(action) = this.maybe_next_action()? {
                return Ok(action);
            }
        }
    }

    fn maybe_next_action(&mut self) -> Result<Option<Option<RecvAction<'_, 'p>>>, Error> {
        self.mgr.exch_mgr.purge();
        self.tx.reset();

        let (state, next) = match core::mem::replace(&mut self.state, RecvState::New) {
            RecvState::New => {
                self.mgr.exch_mgr.get_sess_mgr().decode(&mut self.rx)?;
                (RecvState::OpenExchange, None)
            }
            RecvState::OpenExchange => match self.mgr.exch_mgr.recv(&mut self.rx) {
                Ok(Some(exch_ctx)) => {
                    if self.rx.get_proto_id() == PROTO_ID_SECURE_CHANNEL {
                        let mut proto_ctx = ProtoCtx::new(exch_ctx, &self.rx, &mut self.tx);

                        let (reply, clone_data) = self.mgr.secure_channel.handle(&mut proto_ctx)?;

                        let state = if let Some(clone_data) = clone_data {
                            RecvState::AddSession(clone_data)
                        } else {
                            RecvState::Ack
                        };

                        if reply {
                            if proto_ctx.send()? {
                                (
                                    state,
                                    Some(Some(RecvAction::Send(self.tx.peer, self.tx.as_slice()))),
                                )
                            } else {
                                (state, None)
                            }
                        } else {
                            (state, None)
                        }
                    } else {
                        let proto_ctx = ProtoCtx::new(exch_ctx, &self.rx, &mut self.tx);

                        (RecvState::Ack, Some(Some(RecvAction::Interact(proto_ctx))))
                    }
                }
                Ok(None) => (RecvState::Ack, None),
                Err(e) => match e.code() {
                    ErrorCode::Duplicate => (RecvState::Ack, None),
                    ErrorCode::NoSpace => (RecvState::EvictSession, None),
                    _ => Err(e)?,
                },
            },
            RecvState::AddSession(clone_data) => match self.mgr.exch_mgr.add_session(&clone_data) {
                Ok(_) => (RecvState::Ack, None),
                Err(e) => match e.code() {
                    ErrorCode::NoSpace => (RecvState::EvictSession2(clone_data), None),
                    _ => Err(e)?,
                },
            },
            RecvState::EvictSession => {
                if self.mgr.exch_mgr.evict_session(&mut self.tx)? {
                    (
                        RecvState::OpenExchange,
                        Some(Some(RecvAction::Send(self.tx.peer, self.tx.as_slice()))),
                    )
                } else {
                    (RecvState::EvictSession, None)
                }
            }
            RecvState::EvictSession2(clone_data) => {
                if self.mgr.exch_mgr.evict_session(&mut self.tx)? {
                    (
                        RecvState::AddSession(clone_data),
                        Some(Some(RecvAction::Send(self.tx.peer, self.tx.as_slice()))),
                    )
                } else {
                    (RecvState::EvictSession2(clone_data), None)
                }
            }
            RecvState::Ack => {
                if let Some(exch_id) = self.mgr.exch_mgr.pending_ack() {
                    info!("Sending MRP Standalone ACK for  exch {}", exch_id);

                    ReliableMessage::prepare_ack(exch_id, &mut self.tx);

                    if self.mgr.exch_mgr.send(exch_id, &mut self.tx)? {
                        (
                            RecvState::Ack,
                            Some(Some(RecvAction::Send(self.tx.peer, self.tx.as_slice()))),
                        )
                    } else {
                        (RecvState::Ack, None)
                    }
                } else {
                    (RecvState::Ack, Some(None))
                }
            }
        };

        self.state = state;
        Ok(next)
    }
}

enum NotifyState {}

pub enum NotifyAction<'r, 'p> {
    Send(&'r [u8]),
    Notify(ProtoCtx<'r, 'p>),
}

pub struct NotifyCompletion<'r, 'a, 'p> {
    // TODO
    _mgr: &'r mut TransportMgr<'a>,
    _rx: &'r mut Packet<'p>,
    _tx: &'r mut Packet<'p>,
    _state: NotifyState,
}

impl<'r, 'a, 'p> NotifyCompletion<'r, 'a, 'p> {
    pub fn next_action(&mut self) -> Result<Option<NotifyAction<'_, 'p>>, Error> {
        loop {
            // Polonius will remove the need for unsafe one day
            let this = unsafe { (self as *mut NotifyCompletion).as_mut().unwrap() };

            if let Some(action) = this.maybe_next_action()? {
                return Ok(action);
            }
        }
    }

    fn maybe_next_action(&mut self) -> Result<Option<Option<NotifyAction<'_, 'p>>>, Error> {
        Ok(Some(None)) // TODO: Future
    }
}

pub struct TransportMgr<'a> {
    exch_mgr: exchange::ExchangeMgr,
    secure_channel: SecureChannel<'a>,
}

impl<'a> TransportMgr<'a> {
    pub fn new<
        T: Borrow<RefCell<FabricMgr>>
            + Borrow<RefCell<PaseMgr>>
            + Borrow<RefCell<MdnsMgr<'a>>>
            + Borrow<Epoch>
            + Borrow<Rand>
            + Borrow<UtcCalendar>,
    >(
        matter: &'a T,
    ) -> Self {
        Self::wrap(
            SecureChannel::new(
                matter.borrow(),
                matter.borrow(),
                matter.borrow(),
                *matter.borrow(),
                *matter.borrow(),
            ),
            *matter.borrow(),
            *matter.borrow(),
        )
    }

    pub fn wrap(secure_channel: SecureChannel<'a>, epoch: Epoch, rand: Rand) -> Self {
        Self {
            exch_mgr: exchange::ExchangeMgr::new(epoch, rand),
            secure_channel,
        }
    }

    pub fn recv<'r, 'p>(
        &'r mut self,
        addr: Address,
        rx_buf: &'p mut [u8],
        tx_buf: &'p mut [u8],
    ) -> RecvCompletion<'r, 'a, 'p> {
        let mut rx = Packet::new_rx(rx_buf);
        let tx = Packet::new_tx(tx_buf);

        rx.peer = addr;

        RecvCompletion {
            mgr: self,
            rx,
            tx,
            state: RecvState::New,
        }
    }

    pub fn notify(&mut self, _tx: &mut Packet) -> Result<bool, Error> {
        Ok(false)
    }
}
