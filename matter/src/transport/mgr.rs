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

use async_channel::Receiver;
use boxslab::{BoxSlab, Slab};
use heapless::LinearMap;
use log::{debug, error, info};

use crate::error::*;

use crate::transport::mrp::ReliableMessage;
use crate::transport::packet::PacketPool;
use crate::transport::{exchange, packet::Packet, proto_demux, queue, session, udp};

use super::proto_demux::ProtoCtx;
use super::queue::Msg;

pub struct Mgr {
    exch_mgr: exchange::ExchangeMgr,
    proto_demux: proto_demux::ProtoDemux,
    rx_q: Receiver<Msg>,
}

impl Mgr {
    pub fn new() -> Result<Mgr, Error> {
        let mut sess_mgr = session::SessionMgr::new();
        let udp_transport = Box::new(udp::UdpListener::new()?);
        sess_mgr.add_network_interface(udp_transport)?;
        Ok(Mgr {
            proto_demux: proto_demux::ProtoDemux::new(),
            exch_mgr: exchange::ExchangeMgr::new(sess_mgr),
            rx_q: queue::WorkQ::init()?,
        })
    }

    // Allows registration of different protocols with the Transport/Protocol Demux
    pub fn register_protocol(
        &mut self,
        proto_id_handle: Box<dyn proto_demux::HandleProto>,
    ) -> Result<(), Error> {
        self.proto_demux.register(proto_id_handle)
    }

    fn send_to_exchange(
        &mut self,
        exch_id: u16,
        proto_tx: BoxSlab<PacketPool>,
    ) -> Result<(), Error> {
        self.exch_mgr.send(exch_id, proto_tx)
    }

    fn handle_rxtx(&mut self) -> Result<(), Error> {
        let result = self.exch_mgr.recv().map_err(|e| {
            error!("Error in recv: {:?}", e);
            e
        })?;

        if result.is_none() {
            // Nothing to process, return quietly
            return Ok(());
        }
        // result contains something worth processing, we can safely unwrap
        // as we already checked for none above
        let (rx, exch_ctx) = result.unwrap();

        debug!("Exchange is {:?}", exch_ctx.exch);
        let tx = Self::new_tx()?;

        let mut proto_ctx = ProtoCtx::new(exch_ctx, rx, tx);
        // Proto Dispatch
        match self.proto_demux.handle(&mut proto_ctx) {
            Ok(r) => {
                if let proto_demux::ResponseRequired::No = r {
                    // We need to send the Ack if reliability is enabled, in this case
                    return Ok(());
                }
            }
            Err(e) => {
                error!("Error in proto_demux {:?}", e);
                return Err(e);
            }
        }

        let ProtoCtx {
            exch_ctx,
            rx: _,
            tx,
        } = proto_ctx;

        // tx_ctx now contains the response payload, send the packet
        let exch_id = exch_ctx.exch.get_id();
        self.send_to_exchange(exch_id, tx).map_err(|e| {
            error!("Error in sending msg {:?}", e);
            e
        })?;

        Ok(())
    }

    fn handle_queue_msgs(&mut self) -> Result<(), Error> {
        if let Ok(msg) = self.rx_q.try_recv() {
            match msg {
                Msg::NewSession(clone_data) => {
                    // If a new session was created, add it
                    let _ = self
                        .exch_mgr
                        .add_session(&clone_data)
                        .map_err(|e| error!("Error adding new session {:?}", e));
                }
                _ => {
                    error!("Queue Message Type not yet handled {:?}", msg);
                }
            }
        }
        Ok(())
    }

    pub fn start(&mut self) -> Result<(), Error> {
        loop {
            // Handle network operations
            if self.handle_rxtx().is_err() {
                error!("Error in handle_rxtx");
                continue;
            }

            if self.handle_queue_msgs().is_err() {
                error!("Error in handle_queue_msg");
                continue;
            }

            // Handle any pending acknowledgement send
            let mut acks_to_send: LinearMap<u16, (), { exchange::MAX_MRP_ENTRIES }> =
                LinearMap::new();
            self.exch_mgr.pending_acks(&mut acks_to_send);
            for exch_id in acks_to_send.keys() {
                info!("Sending MRP Standalone ACK for  exch {}", exch_id);
                let mut proto_tx = match Self::new_tx() {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Error creating proto_tx {:?}", e);
                        break;
                    }
                };
                ReliableMessage::prepare_ack(*exch_id, &mut proto_tx);
                if let Err(e) = self.send_to_exchange(*exch_id, proto_tx) {
                    error!("Error in sending Ack {:?}", e);
                }
            }

            // Handle exchange purging
            //    This need not be done in each turn of the loop, maybe once in 5 times or so?
            self.exch_mgr.purge();

            info!("Exchange Mgr: {}", self.exch_mgr);
        }
    }

    fn new_tx() -> Result<BoxSlab<PacketPool>, Error> {
        Slab::<PacketPool>::try_new(Packet::new_tx()?).ok_or(Error::PacketPoolExhaust)
    }
}
