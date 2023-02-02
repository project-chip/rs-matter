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

use crate::{error::Error, transport::session::SessionMode};
use log::error;

#[derive(PartialEq)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
enum NocState {
    NocNotRecvd,
    // This is the local fabric index
    AddNocRecvd(u8),
    UpdateNocRecvd(u8),
}

#[derive(PartialEq)]
pub struct ArmedCtx {
    session_mode: SessionMode,
    timeout: u8,
    noc_state: NocState,
}

#[derive(PartialEq)]
pub enum State {
    Idle,
    Armed(ArmedCtx),
}

pub struct FailSafe {
    state: State,
}

impl FailSafe {
    pub const fn new() -> Self {
        Self { state: State::Idle }
    }

    pub fn arm(&mut self, timeout: u8, session_mode: SessionMode) -> Result<(), Error> {
        match &mut self.state {
            State::Idle => {
                self.state = State::Armed(ArmedCtx {
                    session_mode,
                    timeout,
                    noc_state: NocState::NocNotRecvd,
                })
            }
            State::Armed(c) => {
                if c.session_mode != session_mode {
                    return Err(Error::Invalid);
                }
                // re-arm
                c.timeout = timeout;
            }
        }
        Ok(())
    }

    pub fn disarm(&mut self, session_mode: SessionMode) -> Result<(), Error> {
        match &mut self.state {
            State::Idle => {
                error!("Received Fail-Safe Disarm without it being armed");
                return Err(Error::Invalid);
            }
            State::Armed(c) => {
                match c.noc_state {
                    NocState::NocNotRecvd => return Err(Error::Invalid),
                    NocState::AddNocRecvd(idx) | NocState::UpdateNocRecvd(idx) => {
                        if let SessionMode::Case(c) = session_mode {
                            if c.fab_idx != idx {
                                error!(
                                    "Received disarm in separate session from previous Add/Update NOC"
                                );
                                return Err(Error::Invalid);
                            }
                        } else {
                            error!("Received disarm in a non-CASE session");
                            return Err(Error::Invalid);
                        }
                    }
                }
                self.state = State::Idle;
            }
        }
        Ok(())
    }

    pub fn is_armed(&self) -> bool {
        self.state != State::Idle
    }

    pub fn record_add_noc(&mut self, fabric_index: u8) -> Result<(), Error> {
        match &mut self.state {
            State::Idle => Err(Error::Invalid),
            State::Armed(c) => {
                if c.noc_state == NocState::NocNotRecvd {
                    c.noc_state = NocState::AddNocRecvd(fabric_index);
                    Ok(())
                } else {
                    Err(Error::Invalid)
                }
            }
        }
    }

    pub fn allow_noc_change(&self) -> Result<bool, Error> {
        let allow = match &self.state {
            State::Idle => false,
            State::Armed(c) => c.noc_state == NocState::NocNotRecvd,
        };
        Ok(allow)
    }
}

impl Default for FailSafe {
    fn default() -> Self {
        Self::new()
    }
}
