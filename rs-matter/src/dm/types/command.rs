use core::fmt;

use crate::im::{CmdPath, CmdStatus, IMStatusCode};

use super::{Access, ClusterId, CmdId, EndptId, Node};

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
pub struct CmdDetails<'a> {
    /// The node meta-data
    pub node: &'a Node<'a>,
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
}

impl CmdDetails<'_> {
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

    pub const fn status(&self, status: IMStatusCode) -> Option<CmdStatus> {
        if self.should_report(status) {
            Some(CmdStatus::new(
                CmdPath::new(
                    Some(self.endpoint_id),
                    Some(self.cluster_id),
                    Some(self.cmd_id),
                ),
                status,
                None,
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
