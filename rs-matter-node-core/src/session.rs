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

//! What the node state needs to know about sessions: who is on the other end of
//! a session and how many sessions there are. The sessions themselves are in
//! `rs-matter-node`.

use core::num::NonZeroU8;

use cfg_if::cfg_if;

use crate::fabric::MAX_FABRICS;

pub const MAX_CAT_IDS_PER_NOC: usize = 3;
pub type NocCatIds = [u32; MAX_CAT_IDS_PER_NOC];

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SessionMode {
    // The Case session will capture the local fabric index
    // and the local fabric index
    Case {
        fab_idx: NonZeroU8,
        cat_ids: NocCatIds,
    },
    // The Pase session always starts with a fabric index of 0
    // (i.e. no fabric) but will be upgraded to the actual fabric index
    // once AddNOC or UpdateNOC is received
    Pase {
        fab_idx: u8,
    },
    // A group session used for group (multicast) messaging.
    Group {
        fab_idx: NonZeroU8,
        group_id: u16,
    },
    #[default]
    PlainText,
}

impl SessionMode {
    pub fn fab_idx(&self) -> u8 {
        match self {
            SessionMode::Case { fab_idx, .. } => fab_idx.get(),
            SessionMode::Pase { fab_idx, .. } => *fab_idx,
            SessionMode::Group { fab_idx, .. } => fab_idx.get(),
            SessionMode::PlainText => 0,
        }
    }
}

cfg_if! {
    if #[cfg(feature = "max-sessions-64")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 64;
    } else if #[cfg(feature = "max-sessions-32")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 32;
    } else if #[cfg(feature = "max-sessions-16")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 16;
    } else if #[cfg(feature = "max-sessions-8")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 8;
    } else if #[cfg(feature = "max-sessions-7")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 7;
    } else if #[cfg(feature = "max-sessions-6")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 6;
    } else if #[cfg(feature = "max-sessions-5")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 5;
    } else if #[cfg(feature = "max-sessions-4")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 4;
    } else if #[cfg(feature = "max-sessions-3")] {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 3;
    } else {
        /// Max number of supported sessions
        pub const MAX_SESSIONS: usize = 16;
    }
}

/// The CASE sessions each fabric is guaranteed, as advertised in
/// `CapabilityMinima.CaseSessionsPerFabric`.
///
/// A fabric may use more while the session table has room. Making room in a
/// full table evicts a CASE session of a fabric within this share only when no
/// other session can be evicted.
pub const CASE_SESSIONS_PER_FABRIC: usize = MAX_SESSIONS / MAX_FABRICS;
