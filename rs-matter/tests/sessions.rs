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

//! Transport session-table and exchange-slot limits.
//!
//! Two properties of the transport bookkeeping are proved here, using only the
//! public API (there is no public session-count accessor, so both are proved by
//! the observable success/failure of session and exchange allocation):
//!
//! - The session table is bounded at `MAX_SESSIONS`. Filling it while holding
//!   every session busy (each has a live initiator exchange) makes the next
//!   allocation fail with `NoSpaceSessions`; once the busy exchanges are
//!   released the sessions become evictable and further allocation succeeds
//!   again, so the table never grows past the cap — it recycles under LRU
//!   eviction instead.
//! - A single session is bounded at `MAX_EXCHANGES` concurrent exchanges.
//!   Opening that many without completing them makes the next `initiate` fail
//!   immediately with `NoSpaceExchanges` (it does not block); releasing one
//!   frees a slot and the following `initiate` succeeds.

#![cfg(all(feature = "std", feature = "async-io"))]

use core::num::NonZeroU8;

use embassy_futures::block_on;
use embassy_futures::select::{select, Either};

use rs_matter::crypto::test_only_crypto;
use rs_matter::dm::devices::test::{TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::{Address, NetworkReceive, NetworkSend, NoNetwork};
use rs_matter::transport::session::{
    NocCatIds, ReservedSession, SessionMode, MAX_EXCHANGES, MAX_SESSIONS,
};
use rs_matter::Matter;

use crate::common::init_env_logger;

#[allow(dead_code)]
mod common;

const REMOTE_NODE_ID: u64 = 0xAA;
const LOCAL_NODE_ID: u64 = 0xBB;

/// Filling the session table while every session stays busy hits the cap, and
/// releasing the busy exchanges lets eviction recycle slots so the table never
/// exceeds `MAX_SESSIONS`.
#[test]
fn test_session_table_capped_and_recycled() {
    init_env_logger();

    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);
    let crypto = test_only_crypto();

    // Evicting a session hands a closing status report to the transport, and
    // the next eviction waits for that packet to leave the TX buffer, so the
    // transport loop has to run alongside the test flow. It sends into the
    // void: nothing in this test needs a peer.
    let transport = matter.run(&crypto, NullSend, NullRecv, NoNetwork);

    let flow = async {
        // Fill the table to the cap, keeping each session busy with a live
        // initiator exchange so none of them can be evicted.
        let mut held = std::vec::Vec::new();
        for _ in 0..MAX_SESSIONS {
            let exchange = Exchange::initiate_plaintext(&matter, &crypto, Address::new())
                .await
                .expect("plaintext session allocation should succeed below the cap");
            held.push(exchange);
        }

        // The table is full and nothing is evictable (every session has a live
        // exchange), so the next allocation must fail with `NoSpaceSessions`.
        let over_cap = Exchange::initiate_plaintext(&matter, &crypto, Address::new()).await;
        let outcome = over_cap.as_ref().map(|_| ()).map_err(|e| e.code());
        assert!(
            matches!(outcome, Err(ErrorCode::NoSpaceSessions)),
            "expected NoSpaceSessions once the table is full and busy, got {outcome:?}"
        );
        drop(over_cap);

        // Release the busy exchanges. The sessions remain in the table but are
        // now idle and therefore evictable.
        drop(held);

        // Further allocations succeed by evicting the LRU idle session each
        // time - proof the table recycles at the cap rather than growing past it.
        for _ in 0..MAX_SESSIONS + 3 {
            let exchange = Exchange::initiate_plaintext(&matter, &crypto, Address::new())
                .await
                .expect("allocation should succeed by evicting an idle session");
            drop(exchange);
        }

        Ok::<_, Error>(())
    };

    match block_on(select(transport, flow)) {
        Either::First(result) => panic!("transport exited prematurely: {result:?}"),
        Either::Second(result) => result.unwrap(),
    }
}

/// Opening `MAX_EXCHANGES` exchanges on one CASE session exhausts its exchange
/// slots; the next `initiate` fails immediately, and releasing one frees a slot.
#[test]
fn test_exchange_slots_exhausted_and_released() {
    init_env_logger();

    let matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0);

    // A single fabric so the installed CASE session has a valid fabric index.
    matter.with_state(|state| {
        state.fabrics.add_with_post_init(|_| Ok(())).unwrap();
    });
    let fab_idx = NonZeroU8::new(1).unwrap();

    // Install a keyless CASE-shaped session towards the peer so that
    // `Exchange::initiate` reuses it (no networking / mDNS resolve involved).
    install_case_session(&matter, fab_idx);

    // Open `MAX_EXCHANGES` exchanges on that session without completing them.
    let mut held = std::vec::Vec::new();
    for _ in 0..MAX_EXCHANGES {
        let exchange = block_on(Exchange::initiate(
            &matter,
            test_only_crypto(),
            fab_idx,
            REMOTE_NODE_ID,
        ))
        .expect("exchange allocation should succeed below the per-session cap");
        held.push(exchange);
    }

    // The next one must fail immediately — `initiate` does not block waiting for
    // a slot to free up.
    let over_cap = block_on(Exchange::initiate(
        &matter,
        test_only_crypto(),
        fab_idx,
        REMOTE_NODE_ID,
    ));
    let outcome = over_cap.as_ref().map(|_| ()).map_err(|e| e.code());
    assert!(
        matches!(outcome, Err(ErrorCode::NoSpaceExchanges)),
        "expected NoSpaceExchanges once all exchange slots are taken, got {outcome:?}"
    );

    // Release one exchange, freeing its slot.
    held.pop();

    // The pending allocation now succeeds.
    block_on(Exchange::initiate(
        &matter,
        test_only_crypto(),
        fab_idx,
        REMOTE_NODE_ID,
    ))
    .expect("a released exchange slot should be reusable");
}

/// Pre-install a keyless CASE-shaped session towards [`REMOTE_NODE_ID`], mirroring
/// the helper in `tests/mrp.rs`, so `Exchange::initiate` finds and reuses it.
fn install_case_session(matter: &Matter<'_>, fab_idx: NonZeroU8) {
    let mut session = ReservedSession::reserve_now(matter, test_only_crypto()).unwrap();

    session
        .update(
            LOCAL_NODE_ID,
            REMOTE_NODE_ID,
            1,
            1,
            Address::new(),
            SessionMode::Case {
                fab_idx,
                cat_ids: NocCatIds::default(),
            },
            None,
            None,
            None,
            None,
        )
        .unwrap();

    session.complete();
}

/// A network that swallows everything the transport sends.
struct NullSend;

impl NetworkSend for NullSend {
    async fn send_to(&mut self, _data: &[u8], _addr: Address) -> Result<(), Error> {
        Ok(())
    }
}

/// A network on which nothing ever arrives.
struct NullRecv;

impl NetworkReceive for NullRecv {
    async fn wait_available(&mut self) -> Result<(), Error> {
        core::future::pending().await
    }

    async fn recv_from(&mut self, _buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        core::future::pending().await
    }
}
