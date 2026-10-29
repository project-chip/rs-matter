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

//! The `Accessor`: the access control checks of an operation against the fabric
//! table of a `Matter` instance. The ACL itself is in `rs-matter-node-core`.

use core::ops::Deref;

use crate::dm::{AuxAclCheck, EndptId, NodeId, OperationContext};
use crate::error::Error;
use crate::transport::session::Session;
use crate::Matter;
use crate::Transaction as _;

pub use rs_matter_node_core::acl::*;

/// The Accessor Object
pub struct Accessor<'a> {
    /// Who the accessor is
    subject: SubjectDescriptor,
    // Necessary so as to get access to the fabric manager to perform the access check in `Accessor::allow()`
    // as well as for a few other ACL related operations.
    matter: &'a Matter<'a>,
}

impl<'a> Accessor<'a> {
    /// Create a new Accessor object for the session an operation arrived on
    pub fn for_operation(
        ctx: impl OperationContext,
        matter: &'a Matter<'a>,
    ) -> Result<Self, Error> {
        ctx.transaction_id()
            .accessor(matter, ctx.metadata().aux_acl_enabled())
    }

    /// Create a new Accessor object for the given session
    pub fn for_session(session: &Session, matter: &'a Matter<'a>, aux_acl_enabled: bool) -> Self {
        Self {
            subject: SubjectDescriptor::for_session(
                session.get_session_mode(),
                session.get_peer_node_id(),
                aux_acl_enabled,
            ),
            matter,
        }
    }

    /// Create a new Accessor object
    ///
    /// # Arguments
    /// - `fab_idx`: The fabric index of the accessor (0 means no fabric index)
    /// - `aux_acl_enabled`: Whether AUX ACL was enabled at the time this accessor was instantiated
    /// - `subjects`: The subjects of the accessor
    /// - `auth_mode`: The auth mode of the accessor
    /// - `matter`: The Matter instance
    pub const fn new(
        fab_idx: u8,
        aux_acl_enabled: bool,
        subjects: AccessorSubjects,
        auth_mode: Option<AuthMode>,
        matter: &'a Matter<'a>,
    ) -> Self {
        Self {
            subject: SubjectDescriptor::new(fab_idx, aux_acl_enabled, subjects, auth_mode),
            matter,
        }
    }

    /// Check if the access request is allowed
    ///
    /// This checks all the ACL list to identify if any of the ACLs provides the
    /// _accessor_ the necessary privileges to access the target as per its
    /// permissions
    pub fn allow(&self, req: &AccessReq<'_>) -> bool {
        self.matter.with_state(|state| req.allow(state.fabrics))
    }

    /// Return whether the given endpoint is accessible for this accessor.
    ///
    /// For group sessions, only endpoints that are members of the group are accessible.
    /// For all other session types, all endpoints are accessible.
    pub fn is_endpoint_accessible(&self, endpoint_id: EndptId) -> bool {
        // Only a group session needs the fabric table.
        if self.subject.auth_mode() != Some(AuthMode::Group) {
            return true;
        }

        self.matter.with_state(|state| {
            self.subject
                .is_endpoint_accessible(endpoint_id, state.fabrics)
        })
    }

    /// Return the Operational Node ID of the accessor, if any
    pub fn node_id(&self) -> Option<NodeId> {
        let fab_idx = self.subject.fab_idx().ok()?;

        self.matter
            .with_state(|state| state.fabrics.get(fab_idx).map(|fabric| fabric.node_id()))
    }
}

impl Deref for Accessor<'_> {
    type Target = SubjectDescriptor;

    fn deref(&self) -> &Self::Target {
        &self.subject
    }
}
