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

//! The CASE sessions being established, so that the initiators of a session to
//! the same node share one handshake instead of each running their own.

// Never used by a node that does not initiate CASE.
#![cfg_attr(feature = "case-responder-only", allow(dead_code))]

use core::num::NonZeroU8;

use crate::dm::NodeId;
use crate::error::{Error, ErrorCode};
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::MultiSignal;

#[cfg(not(feature = "case-responder-only"))]
use super::session::MAX_SESSIONS;

/// How many CASE sessions can be established at the same time with their
/// initiators sharing them. A handshake holds a session while it runs, so there
/// are rarely more of them than sessions. Further handshakes still run, but no
/// initiator can wait for them.
#[cfg(not(feature = "case-responder-only"))]
const MAX_CASE_SETUPS: usize = MAX_SESSIONS;
/// A node that does not initiate CASE keeps no setups, and a `Vec<_, 0>` costs
/// no RAM.
#[cfg(feature = "case-responder-only")]
const MAX_CASE_SETUPS: usize = 0;

/// The CASE sessions being established.
pub struct CaseSetups {
    /// All initiators waiting for a handshake wait on it.
    state: MultiSignal<State>,
}

impl CaseSetups {
    pub(crate) const fn new() -> Self {
        Self {
            state: MultiSignal::new(State {
                next_id: 0,
                setups: Vec::new(),
            }),
        }
    }

    pub(crate) fn init() -> impl Init<Self> {
        init!(Self {
            state <- MultiSignal::init(init!(State {
                next_id: 0,
                setups <- Vec::init(),
            })),
        })
    }

    /// Join the setup of a CASE session to the node if one is running, or else
    /// start a new one.
    pub fn enter(&self, fabric_idx: NonZeroU8, peer_node_id: NodeId) -> CaseSetupTurn<'_> {
        self.state.modify(|state| {
            let running = state.setups.iter_mut().find(|setup| {
                setup.fabric_idx == fabric_idx
                    && setup.peer_node_id == peer_node_id
                    && setup.failed.is_none()
            });

            if let Some(setup) = running {
                setup.waiters += 1;

                let waiter = CaseSetupWaiter {
                    state: &self.state,
                    id: setup.id,
                };

                return (false, CaseSetupTurn::Wait(waiter));
            }

            let id = state.next_id;
            state.next_id = state.next_id.wrapping_add(1);

            let tracked = state
                .setups
                .push(CaseSetup {
                    id,
                    fabric_idx,
                    peer_node_id,
                    waiters: 0,
                    failed: None,
                })
                .is_ok();

            let leader = CaseSetupLeader {
                state: &self.state,
                id: tracked.then_some(id),
                failed: None,
            };

            (false, CaseSetupTurn::Establish(leader))
        })
    }
}

/// What an initiator of a CASE session has to do.
pub enum CaseSetupTurn<'a> {
    /// Another initiator is establishing the session: wait for it.
    Wait(CaseSetupWaiter<'a>),
    /// Nobody is: establish it.
    Establish(CaseSetupLeader<'a>),
}

/// The initiator that establishes the session.
///
/// Dropping it ends the setup. The initiators waiting for it then get the
/// error recorded with [`Self::fail`], or else look for the session.
pub struct CaseSetupLeader<'a> {
    state: &'a MultiSignal<State>,
    /// `None` if there was no room to track the setup, so nobody waits for it.
    id: Option<u32>,
    failed: Option<ErrorCode>,
}

impl CaseSetupLeader<'_> {
    /// Record that the session could not be established.
    pub fn fail(&mut self, error: &Error) {
        self.failed = Some(error.code());
    }
}

impl Drop for CaseSetupLeader<'_> {
    fn drop(&mut self) {
        let Some(id) = self.id else {
            return;
        };

        let failed = self.failed;

        self.state.modify(|state| {
            let Some(index) = state.position(id) else {
                return (false, ());
            };

            let setup = &mut state.setups[index];
            let wake = setup.waiters > 0;

            match failed {
                // Kept until every waiter has taken the error.
                Some(code) if wake => setup.failed = Some(code),
                _ => {
                    state.setups.swap_remove(index);
                }
            }

            (wake, ())
        });
    }
}

/// An initiator waiting for another one to establish the session.
pub struct CaseSetupWaiter<'a> {
    state: &'a MultiSignal<State>,
    id: u32,
}

impl CaseSetupWaiter<'_> {
    /// Wait for the setup to end.
    ///
    /// Returns the error it failed with, or `Ok` if it succeeded or its
    /// initiator gave it up. In the latter case there is no session.
    pub async fn wait(&self) -> Result<(), Error> {
        let id = self.id;

        self.state
            .wait(
                |state| match state.setups.iter().find(|setup| setup.id == id) {
                    Some(setup) => setup.failed.map(|code| Err(code.into())),
                    None => Some(Ok(())),
                },
            )
            .await
    }
}

impl Drop for CaseSetupWaiter<'_> {
    fn drop(&mut self) {
        let id = self.id;

        self.state.modify(|state| {
            if let Some(index) = state.position(id) {
                let setup = &mut state.setups[index];
                setup.waiters -= 1;

                if setup.waiters == 0 && setup.failed.is_some() {
                    state.setups.swap_remove(index);
                }
            }

            (false, ())
        });
    }
}

struct State {
    next_id: u32,
    setups: Vec<CaseSetup, MAX_CASE_SETUPS>,
}

impl State {
    fn position(&self, id: u32) -> Option<usize> {
        self.setups.iter().position(|setup| setup.id == id)
    }
}

/// A CASE session being established to a node.
struct CaseSetup {
    /// Tells this setup apart from later ones to the same node.
    id: u32,
    fabric_idx: NonZeroU8,
    peer_node_id: NodeId,
    /// How many initiators wait for the setup to end.
    waiters: u16,
    /// Why the setup failed. Kept until every waiter has taken it.
    failed: Option<ErrorCode>,
}

#[cfg(all(test, not(feature = "case-responder-only")))]
mod tests {
    use core::future::Future;
    use core::num::NonZeroU8;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    use crate::error::{Error, ErrorCode};

    use super::{CaseSetupLeader, CaseSetupTurn, CaseSetupWaiter, CaseSetups};

    const FAB: NonZeroU8 = NonZeroU8::new(1).unwrap();
    const NODE: u64 = 0x1234;

    fn establish(setups: &CaseSetups, node: u64) -> CaseSetupLeader<'_> {
        match setups.enter(FAB, node) {
            CaseSetupTurn::Establish(leader) => leader,
            CaseSetupTurn::Wait(_) => panic!("expected to establish the session"),
        }
    }

    fn wait(setups: &CaseSetups, node: u64) -> CaseSetupWaiter<'_> {
        match setups.enter(FAB, node) {
            CaseSetupTurn::Wait(waiter) => waiter,
            CaseSetupTurn::Establish(_) => panic!("expected to wait for the session"),
        }
    }

    fn poll(waiter: &CaseSetupWaiter<'_>) -> Poll<Result<(), ErrorCode>> {
        let mut fut = pin!(waiter.wait());
        let mut cx = Context::from_waker(Waker::noop());

        fut.as_mut()
            .poll(&mut cx)
            .map(|result| result.map_err(|err| err.code()))
    }

    fn count(setups: &CaseSetups) -> usize {
        setups.state.access(|state| state.setups.len())
    }

    /// The second initiator to a node waits for the first, and finds the session
    /// once the first is done.
    #[test]
    fn second_initiator_waits_for_the_first() {
        let setups = CaseSetups::new();

        let leader = establish(&setups, NODE);
        let waiter = wait(&setups, NODE);

        assert_eq!(poll(&waiter), Poll::Pending);

        drop(leader);

        assert_eq!(poll(&waiter), Poll::Ready(Ok(())));

        drop(waiter);
        assert_eq!(count(&setups), 0);
    }

    /// Initiators to different nodes do not wait for each other.
    #[test]
    fn other_nodes_do_not_wait() {
        let setups = CaseSetups::new();

        let _first = establish(&setups, NODE);
        let _second = establish(&setups, NODE + 1);

        assert_eq!(count(&setups), 2);
    }

    /// A failure reaches every waiter, and the setup is forgotten once the last
    /// waiter is gone.
    #[test]
    fn failure_reaches_every_waiter() {
        let setups = CaseSetups::new();

        let mut leader = establish(&setups, NODE);
        let first = wait(&setups, NODE);
        let second = wait(&setups, NODE);

        leader.fail(&Error::from(ErrorCode::TxTimeout));
        drop(leader);

        assert_eq!(poll(&first), Poll::Ready(Err(ErrorCode::TxTimeout)));
        drop(first);
        assert_eq!(count(&setups), 1);

        assert_eq!(poll(&second), Poll::Ready(Err(ErrorCode::TxTimeout)));
        drop(second);
        assert_eq!(count(&setups), 0);
    }

    /// A failure nobody waits for is not kept.
    #[test]
    fn failure_without_waiters_is_not_kept() {
        let setups = CaseSetups::new();

        let mut leader = establish(&setups, NODE);
        leader.fail(&Error::from(ErrorCode::TxTimeout));
        drop(leader);

        assert_eq!(count(&setups), 0);
    }

    /// A new initiator does not take the failure of an earlier setup that its
    /// waiters have not taken yet, but starts a new one.
    #[test]
    fn new_initiator_does_not_take_an_old_failure() {
        let setups = CaseSetups::new();

        let mut leader = establish(&setups, NODE);
        let waiter = wait(&setups, NODE);

        leader.fail(&Error::from(ErrorCode::TxTimeout));
        drop(leader);

        let again = establish(&setups, NODE);

        assert_eq!(poll(&waiter), Poll::Ready(Err(ErrorCode::TxTimeout)));
        drop(waiter);

        drop(again);
        assert_eq!(count(&setups), 0);
    }

    /// When the initiator establishing the session gives up, its waiters see no
    /// failure: they look for the session, and one of them establishes it.
    #[test]
    fn given_up_setup_is_taken_over() {
        let setups = CaseSetups::new();

        let leader = establish(&setups, NODE);
        let waiter = wait(&setups, NODE);

        drop(leader);

        assert_eq!(poll(&waiter), Poll::Ready(Ok(())));
        drop(waiter);

        let _again = establish(&setups, NODE);
    }

    /// A waiter that gives up is no longer counted.
    #[test]
    fn waiter_that_gives_up_is_not_counted() {
        let setups = CaseSetups::new();

        let mut leader = establish(&setups, NODE);
        drop(wait(&setups, NODE));

        leader.fail(&Error::from(ErrorCode::TxTimeout));
        drop(leader);

        assert_eq!(count(&setups), 0);
    }
}
