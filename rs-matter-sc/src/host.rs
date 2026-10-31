/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
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

//! What the Secure Channel protocol needs from the node it runs in.

#[cfg(feature = "case-resumption")]
use crate::case::ResumableSessions;
use crate::error::{Error, ErrorCode};
use crate::fabric::Fabrics;
use crate::failsafe::FailSafe;
use crate::pase::Pase;
use crate::transport::exchange::Exchange;
use crate::transport::session::Sessions;
use crate::transport::TransportHost;
use rs_matter_node_core::rtc::Rtc;

/// The state of the node that the Secure Channel protocol works on, locked together.
pub struct ScState<'a> {
    /// All sessions
    pub sessions: &'a mut Sessions,
    /// All fabrics
    pub fabrics: &'a mut Fabrics,
    /// CASE session resumption cache
    #[cfg(feature = "case-resumption")]
    pub resumption: &'a mut ResumableSessions,
    /// The PASE session state
    pub pase: &'a mut Pase,
    /// The Failsafe state
    pub failsafe: &'a mut FailSafe,
    /// Real Time Clock state
    pub rtc: &'a mut Rtc,
}

/// What the Secure Channel protocol needs from the node it runs in, besides what
/// the transport needs. `Matter` implements it.
pub trait ScHost: TransportHost {
    /// Run `f` with the state the Secure Channel protocol works on.
    fn with_sc_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut ScState) -> R;
}

/// Resolves an [`Exchange`] against the state of the node.
pub(crate) trait ExchangeScExt {
    /// Run `f` with the state of `host`, or fail with [`ErrorCode::NoSession`]
    /// if the session of the exchange no longer exists.
    fn with_state<H, F, T>(&self, host: &H, f: F) -> Result<T, Error>
    where
        H: ScHost,
        F: FnOnce(&mut ScState) -> Result<T, Error>;
}

impl ExchangeScExt for Exchange<'_> {
    fn with_state<H, F, T>(&self, host: &H, f: F) -> Result<T, Error>
    where
        H: ScHost,
        F: FnOnce(&mut ScState) -> Result<T, Error>,
    {
        let id = self.id();

        host.with_sc_state(|state| {
            if state.sessions.get(id.session_id()).is_some() {
                f(state)
            } else {
                warn!("Exchange {}: No session", id);
                Err(ErrorCode::NoSession.into())
            }
        })
    }
}
