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

//! This module contains the implementation of the Groupcast cluster (provisional
//! in Matter 1.6) and its handler.
//!
//! The Groupcast cluster is the unified replacement of the legacy Groups +
//! Group Key Management flow. It deliberately owns NO state of its own:
//! - group memberships live in the per-fabric group table (shared with the
//!   legacy Groups cluster, so legacy- and Groupcast-managed groups coexist
//!   and group-addressed RX processing needs no changes);
//! - group keys are ordinary Group Key Management key sets (`KeySetID` ==
//!   `GroupKeySetID`), so key sets created via [`JoinGroup`] are visible to -
//!   and manageable by - the Group Key Management cluster, and vice versa;
//! - the `Membership` attribute is a live join of the group table and the
//!   group-key map: a membership whose group has no key-set mapping reports
//!   [`KEY_SET_ID_INVALID`];
//! - `UsedMcastAddrCount` is a live count of the distinct multicast addresses
//!   implied by the memberships' address policies.

use core::num::NonZeroU8;

use embassy_futures::select::select;
use embassy_time::{Duration, Instant, Timer};

use crate::acl::AccessReq;
use crate::dm::clusters::acl::notify_auxiliary_access_updated;
use crate::dm::{
    Access, ArrayAttributeRead, Cluster, Dataver, EndptId, HandlerContext, InvokeContext,
    LifecycleOp, Metadata, ReadContext,
};
use crate::error::{Error, ErrorCode};
use crate::fabric::{Fabric, FabricPersist, Fabrics, MAX_GROUPS_PER_FABRIC};
use crate::group_keys::{GroupEpochKeyEntry, GroupKeySet};
use crate::im::{FabricIndex, GenericPath};
use crate::tlv::TLVBuilderParent;
use crate::utils::cell::RefCell;
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;
use crate::with;

pub use crate::dm::clusters::decl::groupcast::*;

use super::decl::group_key_management::GroupKeySecurityPolicyEnum;

/// The value the `Membership` attribute's `KeySetID` field reports for a
/// group that currently has no key-set mapping (e.g. after the Group Key
/// Management cluster's `GroupKeyMap` was rewritten without it).
pub const KEY_SET_ID_INVALID: u16 = 0xFFFF;

/// The value of the `MaxMembershipCount` attribute: the node-wide maximum
/// number of distinct group IDs across all fabrics.
///
/// Per the Matter Core spec, the per-fabric limit is half of this - which is
/// exactly the per-fabric group-table capacity - and the spec minimum for
/// this attribute is 10, so a Groupcast-enabled node should be built with
/// `max-groups-per-fabric-5` or larger.
pub const MAX_MEMBERSHIP_COUNT: u16 = (2 * MAX_GROUPS_PER_FABRIC) as u16;

/// The value of the `MaxMcastAddrCount` attribute.
///
/// Per the Matter Core spec, when the `PerGroup` feature is supported this
/// SHOULD equal `MaxMembershipCount` (and SHALL be at least 4).
pub const MAX_MCAST_ADDR_COUNT: u16 = MAX_MEMBERSHIP_COUNT;

/// Max endpoints in a single `JoinGroup` / `LeaveGroup` command (Matter Core
/// spec constraint).
const MAX_CMD_ENDPOINTS: usize = 20;

/// `GroupcastTesting` duration bounds and fallback (Matter Core spec).
const TESTING_SECS_MIN: u16 = 10;
const TESTING_SECS_MAX: u16 = 1200;
const TESTING_SECS_FALLBACK: u16 = 60;

/// Return the `Groupcast` cluster metadata for the given feature combination.
///
/// Note that the command set is served in full; on a composition without the
/// `Listener` feature, `ConfigureAuxiliaryACL` (conformance `LN`) should be
/// excluded by the application via a custom `with_cmds` filter.
pub const fn cluster(features: Feature) -> Cluster<'static> {
    FULL_CLUSTER
        .with_attrs(with!(required))
        .with_cmds(with!(all))
        .with_features(features.bits())
}

/// The state of an ongoing `GroupcastTesting` test session.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct Testing {
    /// The fabric that armed the testing mode (`FabricUnderTest`).
    fab_idx: NonZeroU8,
    /// The test operation being executed.
    #[allow(unused)]
    operation: GroupcastTestingEnum,
    /// When the testing mode auto-expires.
    deadline: Instant,
}

/// The system implementation of a handler for the Groupcast Matter cluster.
pub struct GroupcastHandler {
    dataver: Dataver,
    features: Feature,
    testing: Mutex<RefCell<Option<Testing>>>,
    testing_changed: Notification,
}

impl GroupcastHandler {
    /// Create a new instance of `GroupcastHandler` with the given `Dataver`
    /// and feature combination.
    ///
    /// `features` must match the features advertised by the cluster metadata
    /// this handler is composed with (see [`cluster`]) - it drives the
    /// feature-conditional command validation.
    pub const fn new(dataver: Dataver, features: Feature) -> Self {
        Self {
            dataver,
            features,
            testing: Mutex::new(RefCell::new(None)),
            testing_changed: Notification::new(),
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    fn listener(&self) -> bool {
        self.features.contains(Feature::LISTENER)
    }

    fn sender(&self) -> bool {
        self.features.contains(Feature::SENDER)
    }

    fn per_group(&self) -> bool {
        self.features.contains(Feature::PER_GROUP)
    }

    /// The number of distinct multicast addresses used by the group
    /// memberships across all fabrics: one per `PerGroup`-policy group
    /// (including legacy Groups-cluster entries, which behave as `PerGroup`),
    /// plus the IANA-assigned address if at least one group uses it.
    fn used_mcast_addrs(fabrics: &Fabrics) -> u16 {
        let mut iana = false;
        let mut count = 0;

        for fabric in fabrics.iter() {
            for entry in fabric.groups().iter() {
                match entry.effective_mcast_policy() {
                    MulticastAddrPolicyEnum::IanaAddr => iana = true,
                    MulticastAddrPolicyEnum::PerGroup => count += 1,
                }
            }
        }

        count + iana as u16
    }

    /// The number of distinct group IDs across all fabrics.
    fn total_group_count(fabrics: &Fabrics) -> usize {
        fabrics
            .iter()
            .map(|fabric| fabric.groups().group_count())
            .sum()
    }

    /// Whether the invoking client has been granted the `Administer`
    /// privilege on this cluster (required for the `UseAuxiliaryACL` field
    /// of `JoinGroup`, which is otherwise a `Manage`-privilege command).
    fn accessor_is_admin(&self, ctx: &impl InvokeContext) -> Result<bool, Error> {
        let accessor = ctx.exchange().accessor()?;
        let cmd = ctx.cmd();

        let path = GenericPath::new(
            Some(cmd.endpoint_id),
            Some(cmd.cluster_id),
            Some(cmd.cmd_id),
        );

        let mut req = AccessReq::new(&accessor, path, Access::WRITE);
        req.set_target_perms(Access::WRITE | Access::NEED_ADMIN);

        Ok(req.allow())
    }

    /// The node ID of the invoking peer (for the `AuxiliaryAccessUpdated`
    /// event's `AdminNodeID` field).
    fn peer_node_id(ctx: &impl InvokeContext) -> Option<u64> {
        ctx.exchange()
            .with_state(|state| {
                Ok::<_, Error>(
                    ctx.exchange()
                        .id()
                        .session(&mut state.sessions)
                        .get_peer_node_id(),
                )
            })
            .unwrap_or(None)
    }

    /// Validate that every endpoint in `endpoints` exists on the node and is
    /// not the root endpoint.
    fn check_endpoints(ctx: &impl InvokeContext, endpoints: &[EndptId]) -> Result<(), Error> {
        ctx.metadata().access(|node| {
            for endpoint in endpoints {
                if *endpoint == 0 || node.endpoint(*endpoint).is_none() {
                    return Err(ErrorCode::EndpointNotFound.into());
                }
            }

            Ok(())
        })
    }

    /// Create the Group Key Management key set which `JoinGroup` /
    /// `UpdateGroupKey` auto-create when their `Key` field is provided:
    /// `TrustFirst` policy, `EpochKey0` = the input key, `EpochStartTime0` = 1.
    fn make_key_set(key_set_id: u16, key: &[u8]) -> Result<GroupKeySet, Error> {
        let mut key0 = GroupEpochKeyEntry {
            epoch_key: Default::default(),
            epoch_start_time: 1,
        };
        key0.epoch_key
            .try_load_from_slice(key)
            .map_err(|_| ErrorCode::ConstraintError)?;

        let mut entry = GroupKeySet {
            group_key_set_id: key_set_id,
            group_key_security_policy: GroupKeySecurityPolicyEnum::TrustFirst as u8,
            ..Default::default()
        };
        unwrap!(entry.epoch_keys.push(key0).map_err(|_| ()));

        Ok(entry)
    }

    /// Bind `key_set_id` (creating it from `key` if provided) to `group_id`
    /// on the given fabric, per the shared key rules of `JoinGroup` and
    /// `UpdateGroupKey`:
    /// - `key` provided + key set exists -> `AlreadyExists`;
    /// - `key` omitted + key set missing -> `NotFound`.
    fn bind_key_set(
        fabric: &mut Fabric,
        group_id: u16,
        key_set_id: u16,
        key: Option<&[u8]>,
    ) -> Result<(), Error> {
        if let Some(key) = key {
            if fabric.groups().key_set_get(key_set_id).is_some() {
                return Err(ErrorCode::AlreadyExists.into());
            }

            fabric
                .groups_mut()
                .key_set_add(Self::make_key_set(key_set_id, key)?)?;
        } else if fabric.groups().key_set_get(key_set_id).is_none() {
            return Err(ErrorCode::NotFound.into());
        }

        fabric.groups_mut().key_map_set_group(group_id, key_set_id)
    }

    /// Serialize one `Membership` list entry.
    fn build_membership<P: TLVBuilderParent>(
        listener: bool,
        fabric: &Fabric,
        entry: &crate::fabric::GroupEndpointMapping,
        builder: MembershipStructBuilder<P>,
    ) -> Result<P, Error> {
        let key_set_id = fabric
            .groups()
            .key_map_get(entry.group_id)
            .unwrap_or(KEY_SET_ID_INVALID);

        builder
            .group_id(entry.group_id)?
            .endpoints()?
            .with_some_if(listener, |mut builder| {
                for endpoint in &entry.endpoints {
                    builder = builder.push(endpoint)?;
                }

                builder.end()
            })?
            .key_set_id(Some(key_set_id))?
            .has_auxiliary_acl(listener.then(|| entry.has_aux_acl()))?
            .mcast_addr_policy(entry.effective_mcast_policy())?
            .fabric_index(Some(fabric.fab_idx().get()))?
            .end()
    }

    /// Common tail of the state-mutating commands: persist the fabric
    /// (unless the failsafe is armed for it, in which case the commissioning
    /// completion persists), bump the dataver and notify subscribers.
    fn changed(&self, ctx: &impl InvokeContext, fab_idx: NonZeroU8) -> Result<(), Error> {
        let mut persist = FabricPersist::new(ctx.kv());

        ctx.exchange().with_state(|state| {
            if !state.failsafe.is_armed_for(fab_idx.get()) {
                let fabric = state.fabrics.fabric(fab_idx)?;
                persist.store(fabric)?;
            }

            Ok::<_, Error>(())
        })?;

        persist.run()?;

        // Reconcile the joined multicast addresses with the new memberships
        ctx.exchange().matter().transport().notify_groups_changed();

        self.dataver_changed();
        ctx.notify_own_endpoint_changed();

        Ok(())
    }
}

impl ClusterHandler for GroupcastHandler {
    const CLUSTER: Cluster<'static> = cluster(
        Feature::LISTENER
            .union(Feature::SENDER)
            .union(Feature::PER_GROUP),
    );

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn lifecycle(&self, _ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        if matches!(op, LifecycleOp::Startup) {
            // Per the Matter Core spec, `FabricUnderTest` is zero when the
            // server initializes - testing mode does not survive a reboot.
            self.testing.lock(|testing| *testing.borrow_mut() = None);
        }

        Ok(())
    }

    async fn run(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        // Expire the `GroupcastTesting` mode when its deadline passes,
        // reporting the `FabricUnderTest` change to subscribers.
        loop {
            let deadline = self
                .testing
                .lock(|testing| testing.borrow().as_ref().map(|t| t.deadline));

            match deadline {
                Some(deadline) => {
                    if Instant::now() >= deadline {
                        self.testing.lock(|testing| *testing.borrow_mut() = None);

                        self.dataver_changed();
                        ctx.notify_attr_changed(
                            crate::dm::endpoints::ROOT_ENDPOINT_ID,
                            Self::CLUSTER.id,
                            AttributeId::FabricUnderTest as _,
                        );
                    } else {
                        select(Timer::at(deadline), self.testing_changed.wait()).await;
                    }
                }
                None => self.testing_changed.wait().await,
            }
        }
    }

    fn membership<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<MembershipStructArrayBuilder<P>, MembershipStructBuilder<P>>,
    ) -> Result<P, Error> {
        let listener = self.listener();

        ctx.exchange().with_state(|state| {
            let attr = ctx.attr();

            let mut entries = state
                .fabrics
                .iter()
                .filter(|fabric| !attr.fab_filter || fabric.fab_idx().get() == attr.fab_idx)
                .flat_map(|fabric| fabric.groups().iter().map(move |entry| (fabric, entry)));

            match builder {
                ArrayAttributeRead::ReadAll(mut builder) => {
                    for (fabric, entry) in entries {
                        builder = Self::build_membership(listener, fabric, entry, builder.push()?)?;
                    }

                    builder.end()
                }
                ArrayAttributeRead::ReadOne(index, builder) => {
                    let Some((fabric, entry)) = entries.nth(index as usize) else {
                        return Err(ErrorCode::ConstraintError.into());
                    };

                    Self::build_membership(listener, fabric, entry, builder)
                }
                ArrayAttributeRead::ReadNone(builder) => builder.end(),
            }
        })
    }

    fn max_membership_count(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(MAX_MEMBERSHIP_COUNT)
    }

    fn max_mcast_addr_count(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(MAX_MCAST_ADDR_COUNT)
    }

    fn used_mcast_addr_count(&self, ctx: impl ReadContext) -> Result<u16, Error> {
        ctx.exchange()
            .with_state(|state| Ok(Self::used_mcast_addrs(&state.fabrics)))
    }

    fn fabric_under_test(&self, _ctx: impl ReadContext) -> Result<FabricIndex, Error> {
        Ok(self.testing.lock(|testing| {
            testing
                .borrow()
                .as_ref()
                // Lazily treat an expired-but-not-yet-swept testing mode as
                // disabled (the `run` loop sweeps and notifies shortly after)
                .filter(|t| Instant::now() < t.deadline)
                .map(|t| t.fab_idx.get())
                .unwrap_or(0)
        }))
    }

    fn handle_join_group(
        &self,
        ctx: impl InvokeContext,
        request: JoinGroupRequest<'_>,
    ) -> Result<(), Error> {
        let group_id = request.group_id()?;
        if group_id == 0 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let key_set_id = request.key_set_id()?;
        if key_set_id == 0 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let key = request.key()?;
        if let Some(key) = &key {
            if key.0.len() != 16 {
                return Err(ErrorCode::ConstraintError.into());
            }
        }

        let mut endpoints = Vec::<EndptId, MAX_CMD_ENDPOINTS>::new();
        for endpoint in &request.endpoints()? {
            endpoints
                .push(endpoint?)
                .map_err(|_| ErrorCode::ConstraintError)?;
        }

        let use_auxiliary_acl = request.use_auxiliary_acl()?;
        let replace_endpoints = request.replace_endpoints()?;
        let mcast_addr_policy = request.mcast_addr_policy()?;

        if endpoints.is_empty() {
            // A sender-only join needs the Sender feature
            if !self.sender() {
                return Err(ErrorCode::ConstraintError.into());
            }
        } else {
            // A listener join needs the Listener feature
            if !self.listener() {
                return Err(ErrorCode::ConstraintError.into());
            }

            Self::check_endpoints(&ctx, &endpoints)?;
        }

        // `UseAuxiliaryACL` and `ReplaceEndpoints` are Listener-conformant
        // fields
        if !self.listener() && (use_auxiliary_acl.is_some() || replace_endpoints.is_some()) {
            return Err(ErrorCode::ConstraintError.into());
        }

        if matches!(mcast_addr_policy, Some(MulticastAddrPolicyEnum::PerGroup)) && !self.per_group()
        {
            return Err(ErrorCode::ConstraintError.into());
        }

        // The `UseAuxiliaryACL` field requires the `Administer` privilege
        // (the command itself needs just `Manage`)
        if use_auxiliary_acl.is_some() && !self.accessor_is_admin(&ctx)? {
            return Err(ErrorCode::UnsupportedAccess.into());
        }

        let fab_idx = ctx.exchange().accessor()?.fab_idx()?;
        let peer_node_id = Self::peer_node_id(&ctx);

        let aux_changed = ctx.exchange().with_state(|state| {
            let is_new = state
                .fabrics
                .fabric(fab_idx)?
                .groups()
                .get(group_id)
                .is_none();

            if is_new {
                // Capacity: per-fabric first, then node-wide
                if state.fabrics.fabric(fab_idx)?.groups().group_count() >= MAX_GROUPS_PER_FABRIC
                    || Self::total_group_count(&state.fabrics) >= MAX_MEMBERSHIP_COUNT as usize
                {
                    return Err(ErrorCode::ResourceExhausted.into());
                }

                // Multicast address capacity: a new `PerGroup` group needs a
                // new address; a new IANA-policy group needs one only if the
                // IANA address is not in use yet
                let used = Self::used_mcast_addrs(&state.fabrics);
                let needs_addr =
                    match mcast_addr_policy.unwrap_or(MulticastAddrPolicyEnum::IanaAddr) {
                        MulticastAddrPolicyEnum::PerGroup => true,
                        MulticastAddrPolicyEnum::IanaAddr => !state.fabrics.iter().any(|fabric| {
                            fabric.groups().iter().any(|e| {
                                matches!(
                                    e.effective_mcast_policy(),
                                    MulticastAddrPolicyEnum::IanaAddr
                                )
                            })
                        }),
                    };
                if needs_addr && used >= MAX_MCAST_ADDR_COUNT {
                    return Err(ErrorCode::ResourceExhausted.into());
                }
            }

            let fabric = state.fabrics.fabric_mut(fab_idx)?;

            Self::bind_key_set(fabric, group_id, key_set_id, key.as_ref().map(|k| k.0))?;

            fabric.groups_mut().groupcast_join(
                group_id,
                &endpoints,
                replace_endpoints.unwrap_or(false),
                mcast_addr_policy,
            )?;

            // Apply the `ConfigureAuxiliaryACL` effect, if requested. Per the
            // Matter Core spec, failures here are ignored, leaving the effect
            // of the prior successful steps unchanged.
            let mut aux_changed = false;
            if let Some(use_auxiliary_acl) = use_auxiliary_acl {
                let groups = fabric.groups_mut();
                if groups.set_has_aux_acl(group_id, use_auxiliary_acl) {
                    aux_changed = !groups
                        .get(group_id)
                        .map(|e| e.endpoints.is_empty())
                        .unwrap_or(true);
                }
            }

            Ok::<_, Error>(aux_changed)
        })?;

        self.changed(&ctx, fab_idx)?;

        if aux_changed {
            // Best-effort: the join has already been committed
            if let Err(e) = notify_auxiliary_access_updated(&ctx, peer_node_id, fab_idx) {
                warn!("Failed to notify the auxiliary ACL change: {:?}", e);
            }
        }

        Ok(())
    }

    fn handle_leave_group<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: LeaveGroupRequest<'_>,
        response: LeaveGroupResponseBuilder<P>,
    ) -> Result<P, Error> {
        let group_id = request.group_id()?;

        let mut endpoints = None;
        if let Some(req_endpoints) = request.endpoints()? {
            let mut list = Vec::<EndptId, MAX_CMD_ENDPOINTS>::new();
            for endpoint in &req_endpoints {
                list.push(endpoint?)
                    .map_err(|_| ErrorCode::ConstraintError)?;
            }

            endpoints = Some(list);
        }

        let fab_idx = ctx.exchange().accessor()?.fab_idx()?;
        let peer_node_id = Self::peer_node_id(&ctx);
        let sender = self.sender();

        // The endpoints that were actually removed, reported via the
        // response (empty for the leave-all form)
        let mut removed = Vec::<EndptId, MAX_CMD_ENDPOINTS>::new();

        let aux_changed = ctx.exchange().with_state(|state| {
            let fabric = state.fabrics.fabric_mut(fab_idx)?;

            let mut aux_changed = false;

            let mut remove_group = |groups: &mut crate::fabric::Groups, group_id: u16| {
                if let Some(entry) = groups.get(group_id) {
                    aux_changed |= entry.has_aux_acl() && !entry.endpoints.is_empty();
                }

                groups.groupcast_remove(group_id);
                groups.key_map_remove_group(group_id);
            };

            if group_id == 0 {
                // Leave all groups of the fabric
                if fabric.groups().group_count() == 0 {
                    return Err(ErrorCode::NotFound.into());
                }

                let mut group_ids = Vec::<u16, MAX_GROUPS_PER_FABRIC>::new();
                for entry in fabric.groups().iter() {
                    unwrap!(group_ids.push(entry.group_id).map_err(|_| ()));
                }

                for group_id in group_ids {
                    remove_group(fabric.groups_mut(), group_id);
                }
            } else {
                if fabric.groups().get(group_id).is_none() {
                    return Err(ErrorCode::NotFound.into());
                }

                match &endpoints {
                    Some(endpoints) => {
                        // Partial leave: remove the listed endpoints
                        let entry = unwrap!(fabric.groups_mut().get_mut(group_id));

                        for endpoint in endpoints {
                            let before = entry.endpoints.len();
                            entry.endpoints.retain(|ep| ep != endpoint);
                            if entry.endpoints.len() < before {
                                unwrap!(removed.push(*endpoint).map_err(|_| ()));
                            }
                        }

                        let empty = entry.endpoints.is_empty();
                        if !removed.is_empty() && entry.has_aux_acl() {
                            aux_changed = true;
                        }

                        // A membership left with no endpoints is removed
                        // entirely - unless the device is (also) a Sender,
                        // where it lives on as a sender-only membership
                        if empty && !sender {
                            fabric.groups_mut().groupcast_remove(group_id);
                            fabric.groups_mut().key_map_remove_group(group_id);
                        }
                    }
                    None => {
                        // Full leave
                        if let Some(entry) = fabric.groups().get(group_id) {
                            for endpoint in &entry.endpoints {
                                unwrap!(removed.push(*endpoint).map_err(|_| ()));
                            }
                        }

                        remove_group(fabric.groups_mut(), group_id);
                    }
                }
            }

            Ok::<_, Error>(aux_changed)
        })?;

        self.changed(&ctx, fab_idx)?;

        if aux_changed {
            if let Err(e) = notify_auxiliary_access_updated(&ctx, peer_node_id, fab_idx) {
                warn!("Failed to notify the auxiliary ACL change: {:?}", e);
            }
        }

        let mut builder = response.group_id(group_id)?.endpoints()?;
        for endpoint in &removed {
            builder = builder.push(endpoint)?;
        }

        builder.end()?.end()
    }

    fn handle_update_group_key(
        &self,
        ctx: impl InvokeContext,
        request: UpdateGroupKeyRequest<'_>,
    ) -> Result<(), Error> {
        let group_id = request.group_id()?;
        if group_id == 0 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let key_set_id = request.key_set_id()?;
        if key_set_id == 0 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let key = request.key()?;
        if let Some(key) = &key {
            if key.0.len() != 16 {
                return Err(ErrorCode::ConstraintError.into());
            }
        }

        let fab_idx = ctx.exchange().accessor()?.fab_idx()?;

        ctx.exchange().with_state(|state| {
            let fabric = state.fabrics.fabric_mut(fab_idx)?;

            if fabric.groups().get(group_id).is_none() {
                return Err(ErrorCode::NotFound.into());
            }

            Self::bind_key_set(fabric, group_id, key_set_id, key.as_ref().map(|k| k.0))
        })?;

        self.changed(&ctx, fab_idx)
    }

    fn handle_configure_auxiliary_acl(
        &self,
        ctx: impl InvokeContext,
        request: ConfigureAuxiliaryACLRequest<'_>,
    ) -> Result<(), Error> {
        let group_id = request.group_id()?;
        let use_auxiliary_acl = request.use_auxiliary_acl()?;

        let fab_idx = ctx.exchange().accessor()?.fab_idx()?;
        let peer_node_id = Self::peer_node_id(&ctx);

        let aux_changed = ctx.exchange().with_state(|state| {
            let fabric = state.fabrics.fabric_mut(fab_idx)?;

            if fabric.groups().get(group_id).is_none() {
                return Err(ErrorCode::NotFound.into());
            }

            let groups = fabric.groups_mut();
            let changed = groups.set_has_aux_acl(group_id, use_auxiliary_acl);

            // The `AuxiliaryACL` attribute only changes if the group has
            // endpoints to grant access to (a sender-only membership
            // generates no entries)
            Ok::<_, Error>(
                changed
                    && !groups
                        .get(group_id)
                        .map(|e| e.endpoints.is_empty())
                        .unwrap_or(true),
            )
        })?;

        self.changed(&ctx, fab_idx)?;

        if aux_changed {
            if let Err(e) = notify_auxiliary_access_updated(&ctx, peer_node_id, fab_idx) {
                warn!("Failed to notify the auxiliary ACL change: {:?}", e);
            }
        }

        Ok(())
    }

    fn handle_groupcast_testing(
        &self,
        ctx: impl InvokeContext,
        request: GroupcastTestingRequest<'_>,
    ) -> Result<(), Error> {
        let operation = request.test_operation()?;
        let duration_secs = request.duration_seconds()?.unwrap_or(TESTING_SECS_FALLBACK);

        if !(TESTING_SECS_MIN..=TESTING_SECS_MAX).contains(&duration_secs) {
            return Err(ErrorCode::ConstraintError.into());
        }

        match operation {
            GroupcastTestingEnum::DisableTesting => {
                self.testing.lock(|testing| *testing.borrow_mut() = None);
            }
            GroupcastTestingEnum::EnableListenerTesting => {
                if !self.listener() {
                    return Err(ErrorCode::ConstraintError.into());
                }

                let fab_idx = ctx.exchange().accessor()?.fab_idx()?;
                self.testing.lock(|testing| {
                    *testing.borrow_mut() = Some(Testing {
                        fab_idx,
                        operation,
                        deadline: Instant::now() + Duration::from_secs(duration_secs as _),
                    })
                });
            }
            GroupcastTestingEnum::EnableSenderTesting => {
                if !self.sender() {
                    return Err(ErrorCode::ConstraintError.into());
                }

                let fab_idx = ctx.exchange().accessor()?.fab_idx()?;
                self.testing.lock(|testing| {
                    *testing.borrow_mut() = Some(Testing {
                        fab_idx,
                        operation,
                        deadline: Instant::now() + Duration::from_secs(duration_secs as _),
                    })
                });
            }
        }

        // Rearm the expiry timer in `run` and report `FabricUnderTest`
        self.testing_changed.notify();
        self.dataver_changed();
        ctx.notify_own_endpoint_changed();

        Ok(())
    }
}
