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

use std::sync::Once;

use async_channel::{bounded, Receiver, Sender};

use crate::error::Error;

use super::session::CloneData;

#[derive(Debug)]
pub enum Msg {
    Tx(),
    Rx(),
    NewSession(CloneData),
}

#[derive(Clone)]
pub struct WorkQ {
    tx: Sender<Msg>,
}

static mut G_WQ: Option<WorkQ> = None;
static INIT: Once = Once::new();

impl WorkQ {
    pub fn init() -> Result<Receiver<Msg>, Error> {
        let (tx, rx) = bounded::<Msg>(3);
        WorkQ::configure(tx);
        Ok(rx)
    }

    fn configure(tx: Sender<Msg>) {
        unsafe {
            INIT.call_once(|| {
                G_WQ = Some(WorkQ { tx });
            });
        }
    }

    pub fn get() -> Result<WorkQ, Error> {
        unsafe { G_WQ.as_ref().cloned().ok_or(Error::Invalid) }
    }

    pub fn sync_send(&self, msg: Msg) -> Result<(), Error> {
        smol::block_on(self.send(msg))
    }

    pub async fn send(&self, msg: Msg) -> Result<(), Error> {
        self.tx.send(msg).await.map_err(|e| e.into())
    }
}
