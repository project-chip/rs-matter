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
use crate::transport::{exchange, packet::Packet};
use crate::utils::epoch::Epoch;
use crate::utils::rand::Rand;

use super::proto_ctx::ProtoCtx;

#[derive(Copy, Clone, Eq, PartialEq)]
enum RecvState {
    New,
    OpenExchange,
    EvictSession,
    Ack,
}

pub enum RecvAction<'r, 'p> {
    Send(&'r [u8]),
    Interact(ProtoCtx<'r, 'p>),
}

pub struct RecvCompletion<'r, 'a, 'p> {
    mgr: &'r mut TransportMgr<'a>,
    rx: &'r mut Packet<'p>,
    tx: &'r mut Packet<'p>,
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

        match self.state {
            RecvState::New => {
                self.mgr.exch_mgr.get_sess_mgr().decode(self.rx)?;
                self.state = RecvState::OpenExchange;
                Ok(None)
            }
            RecvState::OpenExchange => match self.mgr.exch_mgr.recv(self.rx) {
                Ok(Some(exch_ctx)) => {
                    if self.rx.get_proto_id() == PROTO_ID_SECURE_CHANNEL {
                        let mut proto_ctx = ProtoCtx::new(exch_ctx, self.rx, self.tx);

                        if self.mgr.secure_channel.handle(&mut proto_ctx)? {
                            proto_ctx.send()?;

                            self.state = RecvState::Ack;
                            Ok(Some(Some(RecvAction::Send(self.tx.as_slice()))))
                        } else {
                            self.state = RecvState::Ack;
                            Ok(None)
                        }
                    } else {
                        let proto_ctx = ProtoCtx::new(exch_ctx, self.rx, self.tx);
                        self.state = RecvState::Ack;

                        Ok(Some(Some(RecvAction::Interact(proto_ctx))))
                    }
                }
                Ok(None) => {
                    self.state = RecvState::Ack;
                    Ok(None)
                }
                Err(Error::NoSpace) => {
                    self.state = RecvState::EvictSession;
                    Ok(None)
                }
                Err(err) => Err(err),
            },
            RecvState::EvictSession => {
                self.mgr.exch_mgr.evict_session(self.tx)?;
                self.state = RecvState::OpenExchange;
                Ok(Some(Some(RecvAction::Send(self.tx.as_slice()))))
            }
            RecvState::Ack => {
                if let Some(exch_id) = self.mgr.exch_mgr.pending_ack() {
                    info!("Sending MRP Standalone ACK for  exch {}", exch_id);

                    ReliableMessage::prepare_ack(exch_id, self.tx);

                    self.mgr.exch_mgr.send(exch_id, self.tx)?;
                    Ok(Some(Some(RecvAction::Send(self.tx.as_slice()))))
                } else {
                    Ok(Some(None))
                }
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
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
        T: Borrow<RefCell<FabricMgr>> + Borrow<RefCell<PaseMgr>> + Borrow<Epoch> + Borrow<Rand>,
    >(
        matter: &'a T,
        mdns_mgr: &'a RefCell<MdnsMgr<'a>>,
    ) -> Self {
        Self::wrap(
            SecureChannel::new(matter.borrow(), matter.borrow(), mdns_mgr, *matter.borrow()),
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
        rx: &'r mut Packet<'p>,
        tx: &'r mut Packet<'p>,
    ) -> RecvCompletion<'r, 'a, 'p> {
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

    // async fn handle_queue_msgs(&mut self) -> Result<(), Error> {
    //     if let Ok(msg) = self.rx_q.try_recv() {
    //         match msg {
    //             Msg::NewSession(clone_data) => {
    //                 // If a new session was created, add it
    //                 let _ = self
    //                     .exch_mgr
    //                     .add_session(&clone_data)
    //                     .await
    //                     .map_err(|e| error!("Error adding new session {:?}", e));
    //             }
    //             _ => {
    //                 error!("Queue Message Type not yet handled {:?}", msg);
    //             }
    //         }
    //     }
    //     Ok(())
    // }
}
