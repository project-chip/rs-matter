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

//! Resolving a transaction against the state of a [`Matter`] instance.

use crate::acl::Accessor;
use crate::dm::{NodeId, TransactionId};
use crate::error::{Error, ErrorCode};
use crate::transport::session::{Session, Sessions};
use crate::{Matter, MatterState};

/// Resolves a [`TransactionId`] against the session table and the state of a
/// [`Matter`] instance.
pub trait Transaction {
    /// Get the session associated with this transaction from the given sessions store.
    ///
    /// ATTENTION: This method will panic if the session is not found in the store, so make sure to only call it when you are sure the session exists.
    fn session<'a>(&self, sessions: &'a mut Sessions) -> &'a mut Session;

    /// The accessor of the session of the transaction.
    fn accessor<'a>(
        &self,
        matter: &'a Matter<'a>,
        aux_acl_enabled: bool,
    ) -> Result<Accessor<'a>, Error>;

    /// Run `f` with the state of `matter`, or fail with [`ErrorCode::NoSession`]
    /// if the session of the transaction no longer exists.
    fn with_state<'a, F, T>(&self, matter: &'a Matter<'a>, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut MatterState) -> Result<T, Error>;

    /// Like [`Self::with_state`], for a closure with an error type of its own.
    fn with_state_ex<'a, F, T, E>(&self, matter: &'a Matter<'a>, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut MatterState) -> Result<T, E>,
        E: From<Error>;

    /// The node ID of the peer of the session of the transaction, if the session
    /// has one.
    fn peer_node_id<'a>(&self, matter: &'a Matter<'a>) -> Result<Option<NodeId>, Error> {
        self.with_state(matter, |state| {
            Ok(self.session(state.sessions).get_peer_node_id())
        })
    }
}

impl Transaction for TransactionId {
    fn session<'a>(&self, sessions: &'a mut Sessions) -> &'a mut Session {
        unwrap!(sessions.get(self.session_id()))
    }

    fn accessor<'a>(
        &self,
        matter: &'a Matter<'a>,
        aux_acl_enabled: bool,
    ) -> Result<Accessor<'a>, Error> {
        self.with_state(matter, |state| {
            let sess = self.session(state.sessions);

            Ok(Accessor::for_session(sess, matter, aux_acl_enabled))
        })
    }

    fn with_state<'a, F, T>(&self, matter: &'a Matter<'a>, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut MatterState) -> Result<T, Error>,
    {
        self.with_state_ex(matter, f)
    }

    fn with_state_ex<'a, F, T, E>(&self, matter: &'a Matter<'a>, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut MatterState) -> Result<T, E>,
        E: From<Error>,
    {
        matter.with_state(|state| {
            if state.sessions.get(self.session_id()).is_some() {
                f(state)
            } else {
                warn!("Transaction {}: No session", self);
                Err(Error::from(ErrorCode::NoSession).into())
            }
        })
    }
}
