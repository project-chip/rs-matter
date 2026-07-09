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

//! The ICD Management cluster.
//!
//! An Intermittently Connected Device (ICD) hosts this cluster so clients can
//! register to receive Check-In notifications when their subscription is lost.
//! This module currently provides the persistent registration store
//! ([`RegisteredClients`]); the cluster handler is layered on top of it.

use core::num::NonZeroU8;

use crate::crypto::CanonAeadKey;
use crate::dm::{ArrayAttributeRead, Cluster, Dataver, HandlerContext, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::fabric::MAX_FABRICS;
use crate::persist::{KvBlobStore, Persist, ICD_REGISTERED_CLIENTS_KEY};
use crate::sc::checkin::CheckInCounter;
use crate::tlv::{FromTLV, TLVBuilderParent, TLVElement, ToTLV};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;
use crate::with;

pub use crate::dm::clusters::decl::icd_management::*;

/// The maximum number of clients that can register per fabric — the value
/// reported by the cluster's `ClientsSupportedPerFabric` attribute.
///
/// The spec floor is 1. One entry per fabric is enough for the common case (a
/// single controller ecosystem monitoring the device); raise it if a fabric
/// needs several independent Check-In clients.
pub const CLIENTS_PER_FABRIC: usize = 1;

/// The total capacity of the registration store, across all fabrics.
pub const MAX_REGISTERED_CLIENTS: usize = CLIENTS_PER_FABRIC * MAX_FABRICS;

/// A single client registration (one entry of the `RegisteredClients` list).
///
/// Fabric-scoped: an entry belongs to the fabric it was registered on and is
/// only ever matched, replaced or removed within that fabric.
#[derive(Debug, Clone, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MonitoringRegistration {
    /// The fabric this registration belongs to.
    pub fab_idx: NonZeroU8,
    /// The node to which Check-In messages are sent.
    pub check_in_node_id: u64,
    /// The subject whose active subscription suppresses Check-Ins for this entry.
    pub monitored_subject: u64,
    /// The client's type (permanent or ephemeral).
    pub client_type: ClientTypeEnum,
    /// The shared symmetric key used to encrypt this client's Check-In messages.
    ///
    /// Write-only from the outside: it is provided at registration and used to
    /// build Check-In messages, but never read back as an attribute.
    pub key: CanonAeadKey,
}

/// The persistent, fabric-scoped store of client registrations, backing the ICD
/// Management cluster's `RegisteredClients` attribute.
///
/// Self-contained (it owns its entries and persists them as a single TLV blob
/// under [`ICD_REGISTERED_CLIENTS_KEY`]); it does not touch the core fabric
/// state. [`wait_changed`](Self::wait_changed) signals the application when the
/// set changes so it can react (e.g. re-arm its Check-In logic).
pub struct RegisteredClients {
    clients: Mutex<RefCell<Vec<MonitoringRegistration, MAX_REGISTERED_CLIENTS>>>,
    changed: Notification,
}

impl RegisteredClients {
    /// Create an empty store. Prefer [`init`](Self::init) for a large capacity.
    pub const fn new() -> Self {
        Self {
            clients: Mutex::new(RefCell::new(Vec::new())),
            changed: Notification::new(),
        }
    }

    /// An in-place initializer for an empty store.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            clients <- Mutex::init(RefCell::init(Vec::init())),
            changed: Notification::new(),
        })
    }

    /// Re-hydrate the registrations from `store`. Call once at startup, before
    /// exposing the data model.
    pub fn load<S: KvBlobStore>(&self, mut store: S, buf: &mut [u8]) -> Result<(), Error> {
        let Some(data) = store.load(ICD_REGISTERED_CLIENTS_KEY, buf)? else {
            self.clients.lock(|cell| cell.borrow_mut().clear());
            return Ok(());
        };

        let loaded = Vec::from_tlv(&TLVElement::new(data))?;
        self.clients.lock(|cell| *cell.borrow_mut() = loaded);

        Ok(())
    }

    /// Persist the current registrations to `ctx.kv()`.
    pub fn store_persist<C: HandlerContext>(&self, ctx: &C) -> Result<(), Error> {
        let mut persist = Persist::new(ctx.kv());

        self.clients
            .lock(|cell| persist.store_tlv(ICD_REGISTERED_CLIENTS_KEY, &*cell.borrow()))?;

        persist.run()
    }

    /// The total number of registrations across all fabrics.
    pub fn len(&self) -> usize {
        self.clients.lock(|cell| cell.borrow().len())
    }

    /// Whether there are no registrations.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The number of registrations on `fab_idx`.
    pub fn fabric_len(&self, fab_idx: NonZeroU8) -> usize {
        self.clients.lock(|cell| {
            cell.borrow()
                .iter()
                .filter(|c| c.fab_idx == fab_idx)
                .count()
        })
    }

    /// Register a client, or update the existing registration with the same
    /// `(fab_idx, check_in_node_id)`.
    ///
    /// Returns `Err(ResourceExhausted)` if a *new* entry would exceed the
    /// per-fabric limit ([`CLIENTS_PER_FABRIC`]).
    pub fn set(&self, registration: MonitoringRegistration) -> Result<(), Error> {
        self.clients.lock(|cell| -> Result<(), Error> {
            let mut clients = cell.borrow_mut();

            if let Some(existing) = clients.iter_mut().find(|c| {
                c.fab_idx == registration.fab_idx
                    && c.check_in_node_id == registration.check_in_node_id
            }) {
                *existing = registration;
            } else {
                if clients
                    .iter()
                    .filter(|c| c.fab_idx == registration.fab_idx)
                    .count()
                    >= CLIENTS_PER_FABRIC
                {
                    Err(ErrorCode::ResourceExhausted)?;
                }
                clients
                    .push(registration)
                    .map_err(|_| ErrorCode::ResourceExhausted)?;
            }

            Ok(())
        })?;

        self.changed.notify();

        Ok(())
    }

    /// Remove the registration for `(fab_idx, check_in_node_id)`.
    ///
    /// Returns `Err(NotFound)` if there is no such registration.
    pub fn remove(&self, fab_idx: NonZeroU8, check_in_node_id: u64) -> Result<(), Error> {
        let removed = self.clients.lock(|cell| {
            let mut clients = cell.borrow_mut();
            let before = clients.len();
            clients.retain(|c| !(c.fab_idx == fab_idx && c.check_in_node_id == check_in_node_id));
            clients.len() != before
        });

        if !removed {
            Err(ErrorCode::NotFound)?;
        }

        self.changed.notify();

        Ok(())
    }

    /// Drop every registration belonging to `fab_idx`.
    ///
    /// Call when a fabric is removed. Returns whether anything was removed.
    pub fn remove_fabric(&self, fab_idx: NonZeroU8) -> bool {
        let removed = self.clients.lock(|cell| {
            let mut clients = cell.borrow_mut();
            let before = clients.len();
            clients.retain(|c| c.fab_idx != fab_idx);
            clients.len() != before
        });

        if removed {
            self.changed.notify();
        }

        removed
    }

    /// Look up a registration by `(fab_idx, check_in_node_id)` and, if found, run
    /// `f` with it while the store lock is held.
    ///
    /// The closure runs under the lock, so it must not re-enter the store; copy
    /// out what is needed and do the rest afterwards.
    pub fn with<R>(
        &self,
        fab_idx: NonZeroU8,
        check_in_node_id: u64,
        f: impl FnOnce(&MonitoringRegistration) -> R,
    ) -> Option<R> {
        self.clients.lock(|cell| {
            cell.borrow()
                .iter()
                .find(|c| c.fab_idx == fab_idx && c.check_in_node_id == check_in_node_id)
                .map(f)
        })
    }

    /// Run `f` over every registration (optionally filtered to `fab_filter`)
    /// while the store lock is held.
    pub fn for_each(
        &self,
        fab_filter: Option<NonZeroU8>,
        mut f: impl FnMut(&MonitoringRegistration) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.clients.lock(|cell| {
            for c in cell
                .borrow()
                .iter()
                .filter(|c| fab_filter.is_none_or(|f| c.fab_idx == f))
            {
                f(c)?;
            }

            Ok(())
        })
    }

    /// Wait until the set of registrations changes.
    pub async fn wait_changed(&self) {
        self.changed.wait().await;
    }
}

impl Default for RegisteredClients {
    fn default() -> Self {
        Self::new()
    }
}

/// The timing parameters an ICD advertises through the cluster's mandatory
/// mode-duration / threshold attributes.
///
/// These describe the device's own power-management behavior; the application
/// supplies them.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IcdModeConfig {
    /// Maximum time (seconds) the device may stay in idle mode. Must not be
    /// smaller than `active_mode_duration_ms` converted to seconds.
    pub idle_mode_duration_s: u32,
    /// Minimum time (milliseconds) the device stays active after leaving idle.
    pub active_mode_duration_ms: u32,
    /// Minimum time (milliseconds) the device stays active after network
    /// activity. Also the ICD Check-In application data.
    pub active_mode_threshold_ms: u16,
}

/// The server-side handler for the ICD Management cluster.
///
/// Backed by the shared [`RegisteredClients`] store and [`CheckInCounter`]: the
/// registration commands mutate the store, and the ICD Counter reported to
/// clients comes from the counter. Only the Check-In Protocol subset is
/// implemented — the mode-duration / threshold attributes plus the
/// `RegisteredClients` / `ICDCounter` / `ClientsSupportedPerFabric` attributes
/// and the `RegisterClient` / `UnregisterClient` / `StayActiveRequest` commands.
pub struct IcdMgmtHandler<'a> {
    dataver: Dataver,
    clients: &'a RegisteredClients,
    counter: &'a CheckInCounter,
    mode: IcdModeConfig,
}

impl<'a> IcdMgmtHandler<'a> {
    /// Create a handler backed by the shared registration store and Check-In
    /// counter, advertising the given mode timings.
    pub const fn new(
        dataver: Dataver,
        clients: &'a RegisteredClients,
        counter: &'a CheckInCounter,
        mode: IcdModeConfig,
    ) -> Self {
        Self {
            dataver,
            clients,
            counter,
            mode,
        }
    }

    /// Adapt this handler to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }

    /// The accessing fabric of the current command.
    fn cmd_fabric(ctx: &impl InvokeContext) -> Result<NonZeroU8, Error> {
        ctx.exchange().accessor()?.fab_idx()
    }
}

impl ClusterHandler for IcdMgmtHandler<'_> {
    // Advertise the mandatory attributes plus the Check-In Protocol optionals we
    // serve; the other optionals stay hidden.
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required;
        AttributeId::RegisteredClients
            | AttributeId::ICDCounter
            | AttributeId::ClientsSupportedPerFabric));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn idle_mode_duration(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.mode.idle_mode_duration_s)
    }

    fn active_mode_duration(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.mode.active_mode_duration_ms)
    }

    fn active_mode_threshold(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(self.mode.active_mode_threshold_ms)
    }

    fn clients_supported_per_fabric(&self, _ctx: impl ReadContext) -> Result<u16, Error> {
        Ok(CLIENTS_PER_FABRIC as u16)
    }

    fn icd_counter(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        Ok(self.counter.next())
    }

    fn registered_clients<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            MonitoringRegistrationStructArrayBuilder<P>,
            MonitoringRegistrationStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        let attr = ctx.attr();
        let fab_filter = attr
            .fab_filter
            .then(|| NonZeroU8::new(attr.fab_idx).ok_or(ErrorCode::UnsupportedAccess))
            .transpose()?;

        self.clients.clients.lock(|cell| {
            let clients = cell.borrow();
            let mut iter = clients
                .iter()
                .filter(|c| fab_filter.is_none_or(|f| c.fab_idx == f));

            match builder {
                ArrayAttributeRead::ReadAll(mut array) => {
                    for c in iter {
                        array = array
                            .push()?
                            .check_in_node_id(Some(c.check_in_node_id))?
                            .monitored_subject(Some(c.monitored_subject))?
                            .client_type(Some(c.client_type))?
                            .fabric_index(Some(c.fab_idx.get()))?
                            .end()?;
                    }
                    array.end()
                }
                ArrayAttributeRead::ReadOne(index, item) => {
                    let Some(c) = iter.nth(index as usize) else {
                        return Err(ErrorCode::ConstraintError.into());
                    };
                    item.check_in_node_id(Some(c.check_in_node_id))?
                        .monitored_subject(Some(c.monitored_subject))?
                        .client_type(Some(c.client_type))?
                        .fabric_index(Some(c.fab_idx.get()))?
                        .end()
                }
                ArrayAttributeRead::ReadNone(array) => array.end(),
            }
        })
    }

    fn handle_register_client<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: RegisterClientRequest<'_>,
        response: RegisterClientResponseBuilder<P>,
    ) -> Result<P, Error> {
        let fab_idx = Self::cmd_fabric(&ctx)?;

        let key = request.key()?;
        let mut icd_key = CanonAeadKey::new();
        icd_key.try_load_from_slice(key.0)?;

        self.clients.set(MonitoringRegistration {
            fab_idx,
            check_in_node_id: request.check_in_node_id()?,
            monitored_subject: request.monitored_subject()?,
            client_type: request.client_type()?,
            key: icd_key,
        })?;

        self.clients.store_persist(&ctx)?;
        ctx.notify_own_cluster_changed();

        // The client stores this as its starting Check-In counter reference.
        response.icd_counter(self.counter.next())?.end()
    }

    fn handle_unregister_client(
        &self,
        ctx: impl InvokeContext,
        request: UnregisterClientRequest<'_>,
    ) -> Result<(), Error> {
        let fab_idx = Self::cmd_fabric(&ctx)?;

        self.clients.remove(fab_idx, request.check_in_node_id()?)?;

        self.clients.store_persist(&ctx)?;
        ctx.notify_own_cluster_changed();

        Ok(())
    }

    fn handle_stay_active_request<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        request: StayActiveRequestRequest<'_>,
        response: StayActiveResponseBuilder<P>,
    ) -> Result<P, Error> {
        // We have no separate "active mode" to extend, so we honor no more than
        // the requested duration (a device MAY promise less).
        let promised = request.stay_active_duration()?;

        response.promised_active_duration(promised)?.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fab(i: u8) -> NonZeroU8 {
        NonZeroU8::new(i).unwrap()
    }

    fn reg(fab: u8, node: u64) -> MonitoringRegistration {
        MonitoringRegistration {
            fab_idx: NonZeroU8::new(fab).unwrap(),
            check_in_node_id: node,
            monitored_subject: node,
            client_type: ClientTypeEnum::Permanent,
            key: CanonAeadKey::new(),
        }
    }

    #[test]
    fn set_adds_and_updates() {
        let clients = RegisteredClients::new();

        clients.set(reg(1, 100)).unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients.fabric_len(fab(1)), 1);

        // Same (fabric, node) -> update in place, not a second entry.
        let mut updated = reg(1, 100);
        updated.monitored_subject = 999;
        clients.set(updated).unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(
            clients.with(fab(1), 100, |r| r.monitored_subject),
            Some(999)
        );
    }

    #[test]
    fn per_fabric_limit_is_enforced_independently() {
        let clients = RegisteredClients::new();

        // One client per fabric fits (CLIENTS_PER_FABRIC == 1).
        clients.set(reg(1, 100)).unwrap();
        clients.set(reg(2, 200)).unwrap();
        assert_eq!(clients.len(), 2);

        // A *second* client on fabric 1 exceeds the per-fabric limit...
        assert!(clients.set(reg(1, 101)).is_err());
        assert_eq!(clients.fabric_len(fab(1)), 1);

        // ...but updating the existing fabric-1 client still works.
        clients.set(reg(1, 100)).unwrap();
        assert_eq!(clients.fabric_len(fab(1)), 1);
    }

    #[test]
    fn remove_and_remove_fabric() {
        let clients = RegisteredClients::new();
        clients.set(reg(1, 100)).unwrap();
        clients.set(reg(2, 200)).unwrap();

        assert!(clients.remove(fab(1), 999).is_err()); // no such node
        clients.remove(fab(1), 100).unwrap();
        assert_eq!(clients.len(), 1);

        // Removing a fabric drops only its entries.
        assert!(clients.remove_fabric(fab(2)));
        assert!(clients.is_empty());
        assert!(!clients.remove_fabric(fab(2))); // nothing left
    }

    #[test]
    fn for_each_honors_the_fabric_filter() {
        let clients = RegisteredClients::new();
        clients.set(reg(1, 100)).unwrap();
        clients.set(reg(2, 200)).unwrap();

        let mut all = alloc::vec::Vec::new();
        clients
            .for_each(None, |r| {
                all.push(r.check_in_node_id);
                Ok(())
            })
            .unwrap();
        all.sort_unstable();
        assert_eq!(all, [100, 200]);

        let mut only_fab1 = alloc::vec::Vec::new();
        clients
            .for_each(Some(fab(1)), |r| {
                only_fab1.push(r.check_in_node_id);
                Ok(())
            })
            .unwrap();
        assert_eq!(only_fab1, [100]);
    }
}
