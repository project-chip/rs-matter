use core::fmt;

use crate::im::{CmdPath, CmdStatus, IMStatusCode};

use super::{Access, ClusterId, CmdDataTracker, CmdId, EndptId, Node};

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

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CmdDetails<'a> {
    pub node: &'a Node<'a>,
    pub endpoint_id: EndptId,
    pub cluster_id: ClusterId,
    pub cmd_id: CmdId,
    pub wildcard: bool,
}

impl CmdDetails<'_> {
    pub fn path(&self) -> CmdPath {
        CmdPath::new(
            Some(self.endpoint_id),
            Some(self.cluster_id),
            Some(self.cmd_id),
        )
    }

    pub fn success(&self, tracker: &CmdDataTracker) -> Option<CmdStatus> {
        if tracker.needs_status() {
            self.status(IMStatusCode::Success)
        } else {
            None
        }
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
                0,
            ))
        } else {
            None
        }
    }

    fn should_report(&self, status: IMStatusCode) -> bool {
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
