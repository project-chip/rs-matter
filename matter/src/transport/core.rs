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

use log::info;

use crate::{error::*, CommissioningData, Matter};

use crate::secure_channel::common::PROTO_ID_SECURE_CHANNEL;
use crate::secure_channel::core::SecureChannel;
use crate::transport::mrp::ReliableMessage;
use crate::transport::{exchange, network::Address, packet::Packet};

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
    transport: &'r mut Transport<'a>,
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
        self.transport.exch_mgr.purge();
        self.tx.reset();

        let (state, next) = match core::mem::replace(&mut self.state, RecvState::New) {
            RecvState::New => {
                self.transport
                    .exch_mgr
                    .get_sess_mgr()
                    .decode(&mut self.rx)?;
                (RecvState::OpenExchange, None)
            }
            RecvState::OpenExchange => match self.transport.exch_mgr.recv(&mut self.rx) {
                Ok(Some(exch_ctx)) => {
                    if self.rx.get_proto_id() == PROTO_ID_SECURE_CHANNEL {
                        let mut proto_ctx = ProtoCtx::new(exch_ctx, &self.rx, &mut self.tx);

                        let mut secure_channel = SecureChannel::new(self.transport.matter);

                        let (reply, clone_data) = secure_channel.handle(&mut proto_ctx)?;

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
            RecvState::AddSession(clone_data) => {
                match self.transport.exch_mgr.add_session(&clone_data) {
                    Ok(_) => (RecvState::Ack, None),
                    Err(e) => match e.code() {
                        ErrorCode::NoSpace => (RecvState::EvictSession2(clone_data), None),
                        _ => Err(e)?,
                    },
                }
            }
            RecvState::EvictSession => {
                if self.transport.exch_mgr.evict_session(&mut self.tx)? {
                    (
                        RecvState::OpenExchange,
                        Some(Some(RecvAction::Send(self.tx.peer, self.tx.as_slice()))),
                    )
                } else {
                    (RecvState::EvictSession, None)
                }
            }
            RecvState::EvictSession2(clone_data) => {
                if self.transport.exch_mgr.evict_session(&mut self.tx)? {
                    (
                        RecvState::AddSession(clone_data),
                        Some(Some(RecvAction::Send(self.tx.peer, self.tx.as_slice()))),
                    )
                } else {
                    (RecvState::EvictSession2(clone_data), None)
                }
            }
            RecvState::Ack => {
                if let Some(exch_id) = self.transport.exch_mgr.pending_ack() {
                    info!("Sending MRP Standalone ACK for  exch {}", exch_id);

                    ReliableMessage::prepare_ack(exch_id, &mut self.tx);

                    if self.transport.exch_mgr.send(exch_id, &mut self.tx)? {
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
    _transport: &'r mut Transport<'a>,
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

pub struct Transport<'a> {
    matter: &'a Matter<'a>,
    exch_mgr: exchange::ExchangeMgr,
}

impl<'a> Transport<'a> {
    #[inline(always)]
    pub fn new(matter: &'a Matter<'a>) -> Self {
        let epoch = matter.epoch;
        let rand = matter.rand;

        Self {
            matter,
            exch_mgr: exchange::ExchangeMgr::new(epoch, rand),
        }
    }

    pub fn matter(&self) -> &Matter<'a> {
        &self.matter
    }

    pub fn start(&mut self, dev_comm: CommissioningData, buf: &mut [u8]) -> Result<(), Error> {
        info!("Starting Matter transport");

        if self.matter().start_comissioning(dev_comm, buf)? {
            info!("Comissioning started");
        }

        Ok(())
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
            transport: self,
            rx,
            tx,
            state: RecvState::New,
        }
    }

    pub fn notify(&mut self, _tx: &mut Packet) -> Result<bool, Error> {
        Ok(false)
    }
}
