/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

use core::cell::Cell;
use core::fmt;

use crate::im::{CmdPath, CmdStatus, IMStatusCode};

use super::{Access, ClusterId, CmdId, EndptId};

/// A type modeling the command meta-data in the Matter data model.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Command {
    /// The ID of the command
    pub id: CmdId,
    /// The ID of the response command, if any
    pub resp_id: Option<CmdId>,
    /// The access control for the command
    pub access: Access,
}

impl Command {
    /// Creates a new command with the given ID, response command ID, and access control.
    pub const fn new(id: CmdId, resp_id: Option<CmdId>, access: Access) -> Self {
        Self {
            id,
            resp_id,
            access,
        }
    }
}

impl core::fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// A macro to generate the commands for a cluster.
#[allow(unused_macros)]
#[macro_export]
macro_rules! commands {
    ($($cmd:expr $(,)?)*) => {
        &[
            $($cmd,)*
        ]
    }
}

/// A macro to generate a `TryFrom` implementation for a command enum.
#[allow(unused_macros)]
#[macro_export]
macro_rules! command_enum {
    ($en:ty) => {
        impl core::convert::TryFrom<$crate::dm::CmdId> for $en {
            type Error = $crate::error::Error;

            fn try_from(id: $crate::dm::CmdId) -> Result<Self, Self::Error> {
                <$en>::from_repr(id).ok_or_else(|| $crate::error::ErrorCode::CommandNotFound.into())
            }
        }
    };
}

/// The `CmdDetails` type captures all necessary information to perform an Attribute Read operation
///
/// This type is built by the Data Model during the expansion of the commands in the `Invoke` IM action
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CmdDetails {
    /// The concrete (expanded) endpoint ID
    pub endpoint_id: EndptId,
    /// The concrete (expanded) cluster ID
    pub cluster_id: ClusterId,
    /// The concrete (expanded) command ID
    pub cmd_id: CmdId,
    /// The fabric index associated with this request
    pub fab_idx: u8,
    /// Whether the original command was a wildcard one
    pub wildcard: bool,
    /// The CommandRef from the originating `CommandDataIB`, if any.
    /// Echoed back in the response so the requester can correlate batched invokes.
    pub command_ref: Option<u16>,
    /// Cluster-specific status to stamp into the response `StatusIB.clusterStatus`
    /// when the handler returns `Err`. `0` means "no cluster status" (the
    /// reserved `kSuccess` value in Matter cluster-status enums).
    ///
    /// Cluster handlers set this via `InvokeContext::set_cluster_status`
    /// before returning an error. Stored here as a `Cell<u8>` rather than
    /// on `Error` so that `Result<T, Error>` keeps its compact 1-byte error
    /// payload across the codebase.
    pub cluster_status: Cell<u8>,
}

impl CmdDetails {
    /// Construct a new `CmdDetails`. Initializes `cluster_status` to `0`
    /// (no cluster-specific status to report).
    pub const fn new(
        endpoint_id: EndptId,
        cluster_id: ClusterId,
        cmd_id: CmdId,
        fab_idx: u8,
        wildcard: bool,
        command_ref: Option<u16>,
    ) -> Self {
        Self {
            endpoint_id,
            cluster_id,
            cmd_id,
            fab_idx,
            wildcard,
            command_ref,
            cluster_status: Cell::new(0),
        }
    }

    /// Stamp a cluster-specific status code onto this invoke. The value is
    /// echoed in `StatusIB.clusterStatus` when the handler returns `Err`.
    /// `0` is treated as "none" (Matter reserves it for `kSuccess`).
    pub fn set_cluster_status(&self, cluster_status: u8) {
        self.cluster_status.set(cluster_status);
    }

    /// The currently stashed cluster-specific status, if any.
    pub fn cluster_status(&self) -> Option<u16> {
        match self.cluster_status.get() {
            0 => None,
            n => Some(n as u16),
        }
    }
}

impl CmdDetails {
    /// Return the path with which this command invocation request
    /// should be replied, for the case where the command generates a simple
    /// status message as opposed to a true command reply.
    pub const fn reply_path(&self) -> CmdPath {
        CmdPath::new(
            Some(self.endpoint_id),
            Some(self.cluster_id),
            Some(self.cmd_id),
        )
    }

    pub fn status(&self, status: IMStatusCode) -> Option<CmdStatus> {
        if self.should_report(status) {
            Some(CmdStatus::new(
                CmdPath::new(
                    Some(self.endpoint_id),
                    Some(self.cluster_id),
                    Some(self.cmd_id),
                ),
                status,
                self.cluster_status(),
                self.command_ref,
            ))
        } else {
            None
        }
    }

    const fn should_report(&self, status: IMStatusCode) -> bool {
        !self.wildcard
            || !matches!(
                status,
                IMStatusCode::UnsupportedEndpoint
                    | IMStatusCode::UnsupportedCluster
                    | IMStatusCode::UnsupportedAttribute
                    | IMStatusCode::UnsupportedCommand
                    | IMStatusCode::UnsupportedAccess
                    | IMStatusCode::UnsupportedRead
                    | IMStatusCode::UnsupportedWrite
            )
    }
}
