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

//! The OTA Software Update Requestor cluster.
//!
//! The device hosts the cluster (server role) so an Administrator can configure
//! its provider list and observe its update state. Rather than a ready-made
//! update loop, this exposes the building blocks and leaves the policy (when to
//! check, how to download and apply) to the application:
//!
//! - [`Providers`] keeps the persistent, fabric-scoped `DefaultOTAProviders` list
//!   (at most one entry per fabric) plus a transient cache of providers learned
//!   via `AnnounceOTAProvider`; [`Providers::wait_changed`] lets the app react.
//! - [`Provider::query`] asks one provider whether a newer image is available.
//! - [`OtaState`] holds the reported update state; [`OtaState::initiate_update`]
//!   is an RAII session the app uses to report progress, which emits the
//!   `StateTransition` and `DownloadError` events. The `VersionApplied` event
//!   comes at startup, when the node runs another version than at its last.
//! - [`parse_bdx_url`] turns a `bdx://` image URI into a `(node, file-designator)`
//!   pair for a BDX download via [`Exchange::download`](crate::bdx::BdxDownloadInitiator::download).
//! - [`OtaImageHeader::load`](crate::ota::OtaImageHeader::load) reads the
//!   downloaded image's header.

use core::num::NonZeroU8;

use crate::crypto::Crypto;
use crate::dm::{
    ArrayAttributeRead, ArrayAttributeWrite, AttrChangeNotifier, Cluster, Dataver, EventEmitter,
    HandlerContext, InvokeContext, LifecycleOp, ReadContext, WriteContext,
};
use crate::dm::{AttrId, EndptId, NodeId};
use crate::error::{Error, ErrorCode};
use crate::fabric::MAX_FABRICS;
use crate::persist::{
    KvBlobStore, KvBlobStoreAccess, Persist, OTA_PROVIDERS_KEY, RUNNING_VERSION_KEY,
};
use crate::tlv::{FromTLV, Nullable, Octets, TLVArray, TLVBuilderParent, ToTLV};
use crate::transport::exchange::Exchange;
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init};
use crate::utils::storage::Vec;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;
use crate::with;
use crate::Matter;

pub use crate::dm::clusters::decl::ota_software_update_requestor::*;

use crate::dm::clusters::decl::ota_software_update_provider::{
    ApplyUpdateActionEnum, DownloadProtocolEnum, OtaSoftwareUpdateProviderClient,
    QueryImageResponse,
};
use crate::dm::clusters::ota_prov::OtaApplyOutcome;

/// The number of transient providers (learned via `AnnounceOTAProvider`) cached
/// at once. These are one-shot hints, deduplicated by `(fabric, node)`; the
/// oldest is evicted when the cache is full.
const ANNOUNCED_PROVIDERS: usize = 4;

/// One OTA Provider, scoped to the fabric that registered (or announced) it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Provider {
    /// The fabric this provider belongs to.
    pub fab_idx: NonZeroU8,
    /// The provider node's id.
    pub node_id: NodeId,
    /// The endpoint on the provider node hosting the OTA Provider cluster.
    pub endpoint: EndptId,
}

impl Provider {
    /// Ask this provider whether a software image newer than `current_version`
    /// (defaulting to this device's `sw_ver` from `BasicInfoConfig` when `None`)
    /// is available, advertising the given download `protocols`.
    ///
    /// The request's `VendorID`, `ProductID`, `SoftwareVersion` and
    /// `HardwareVersion` are taken from the node's [`BasicInfoConfig`], and
    /// `Location` from the configured Basic Information settings - the spec
    /// requires each to equal the corresponding Basic Information cluster
    /// attribute. `requestor_can_consent` declares whether this requestor can
    /// obtain user consent on its own (via built-in UI); pass `true` only if so,
    /// as it lets the provider delegate consent (see [`OtaImagesRegistry`]).
    ///
    /// Opens a CASE exchange to the provider, sends `QueryImage`, and invokes `f`
    /// with the [`QueryImageResponse`] *before* the exchange is released - so `f`
    /// reads `image_uri`/`software_version`/`update_token` straight off the RX
    /// buffer without copying them onto the stack. `f`'s return value is returned.
    ///
    /// `query` does not interpret the response (it checks neither `status` nor the
    /// returned version); that is left to `f`. On a `bdx://` `image_uri`, use
    /// [`parse_bdx_url`] + [`Exchange::download`](crate::bdx::BdxDownloadInitiator::download) to fetch.
    ///
    /// [`BasicInfoConfig`]: crate::dm::clusters::basic_info::BasicInfoConfig
    /// [`OtaImagesRegistry`]: crate::dm::clusters::ota_prov::OtaImagesRegistry
    pub async fn query<C, F, R>(
        &self,
        matter: &Matter<'_>,
        crypto: C,
        protocols: &[DownloadProtocolEnum],
        current_version: Option<u32>,
        requestor_can_consent: bool,
        f: F,
    ) -> Result<R, Error>
    where
        C: Crypto,
        F: FnOnce(&QueryImageResponse<'_>) -> Result<R, Error>,
    {
        let dev = matter.dev_det();
        let version = current_version.unwrap_or(dev.sw_ver);

        // `Location`, per spec, mirrors the Basic Information cluster Location
        // attribute (a 2-char region code) when one is configured. Copy it out so
        // the state lock is not held across the exchange.
        let location = matter.with_state(|state| state.basic_info_settings.location.clone());
        let location = location.as_deref();

        let exchange = Exchange::initiate(matter, crypto, self.fab_idx, self.node_id).await?;

        let handle = exchange
            .ota_software_update_provider()
            .query_image(self.endpoint, |b| {
                let mut protos = b
                    .vendor_id(dev.vid)?
                    .product_id(dev.pid)?
                    .software_version(version)?
                    .protocols_supported()?;
                for proto in protocols {
                    protos = protos.push(proto)?;
                }
                protos
                    .end()?
                    .hardware_version(Some(dev.hw_ver))?
                    .location(location)?
                    .requestor_can_consent(Some(requestor_can_consent))?
                    .metadata_for_provider(None)?
                    .end()
            })
            .await?;

        // Hand the response to `f` while it is still valid (borrows the RX buffer),
        // then release the exchange.
        let result = {
            let response = handle.response()?;
            f(&response)
        };

        handle.complete().await?;

        result
    }

    /// Ask this provider how to apply the already-downloaded image identified by
    /// `update_token` (the `UpdateToken` from the provider's
    /// [`QueryImageResponse`]), which upgrades to `new_version`.
    ///
    /// Opens a CASE exchange and sends `ApplyUpdateRequest`. The returned
    /// [`OtaApplyOutcome`] is the provider's decision: [`Proceed`] (apply, after
    /// its delay), [`Await`] (wait the delay and call this again), or
    /// [`Discontinue`] (discard the image).
    ///
    /// [`Proceed`]: OtaApplyOutcome::Proceed
    /// [`Await`]: OtaApplyOutcome::Await
    /// [`Discontinue`]: OtaApplyOutcome::Discontinue
    pub async fn apply_update<C>(
        &self,
        matter: &Matter<'_>,
        crypto: C,
        update_token: &[u8],
        new_version: u32,
    ) -> Result<OtaApplyOutcome, Error>
    where
        C: Crypto,
    {
        let exchange = Exchange::initiate(matter, crypto, self.fab_idx, self.node_id).await?;

        let handle = exchange
            .ota_software_update_provider()
            .apply_update_request(self.endpoint, |b| {
                b.update_token(Octets(update_token))?
                    .new_version(new_version)?
                    .end()
            })
            .await?;

        let outcome = {
            let response = handle.response()?;
            let delay_secs = response.delayed_action_time()?;

            match response.action()? {
                ApplyUpdateActionEnum::Proceed => OtaApplyOutcome::Proceed { delay_secs },
                ApplyUpdateActionEnum::AwaitNextAction => OtaApplyOutcome::Await { delay_secs },
                ApplyUpdateActionEnum::Discontinue => OtaApplyOutcome::Discontinue,
            }
        };

        handle.complete().await?;

        Ok(outcome)
    }

    /// Tell this provider that the image identified by `update_token` has been
    /// applied, now running `software_version`. Opens a CASE exchange and sends
    /// `NotifyUpdateApplied`; there is no response payload.
    pub async fn notify_applied<C>(
        &self,
        matter: &Matter<'_>,
        crypto: C,
        update_token: &[u8],
        software_version: u32,
    ) -> Result<(), Error>
    where
        C: Crypto,
    {
        let exchange = Exchange::initiate(matter, crypto, self.fab_idx, self.node_id).await?;

        exchange
            .ota_software_update_provider()
            .notify_update_applied(self.endpoint, |b| {
                b.update_token(Octets(update_token))?
                    .software_version(software_version)?
                    .end()
            })
            .await
    }
}

/// The OTA Requestor's provider registry: the persistent, fabric-scoped
/// `DefaultOTAProviders` list (at most one entry per fabric) and a transient
/// cache of providers learned via `AnnounceOTAProvider`.
///
/// Modeled on the Binding cluster's registry: the default list is persisted as a
/// single TLV blob under [`OTA_PROVIDERS_KEY`]; announced providers are never
/// persisted. [`wait_changed`](Self::wait_changed) signals the application when
/// the set changes (an admin write or an announcement).
pub struct Providers {
    state: Mutex<RefCell<ProvidersState>>,
    changed: Notification,
}

struct ProvidersState {
    /// The persisted `DefaultOTAProviders` list - at most one entry per fabric.
    default: Vec<Provider, MAX_FABRICS>,
    /// Transient providers learned via `AnnounceOTAProvider` (not persisted).
    announced: Vec<Provider, ANNOUNCED_PROVIDERS>,
}

impl ProvidersState {
    fn init() -> impl Init<Self> {
        init!(Self {
            default <- Vec::init(),
            announced <- Vec::init(),
        })
    }
}

impl Providers {
    /// Create an empty registry. Prefer [`Self::init`] for a large `MAX_FABRICS`.
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(ProvidersState {
                default: Vec::new(),
                announced: Vec::new(),
            })),
            changed: Notification::new(),
        }
    }

    /// An in-place initializer for an empty registry.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            state <- Mutex::init(RefCell::init(ProvidersState::init())),
            changed <- Notification::init(),
        })
    }

    /// Re-hydrate the default provider list from `store`.
    ///
    /// Called on startup via the [`LifecycleOp::Startup`] lifecycle operation
    /// delivered to the [`OtaRequestorHandler`] borrowing this registry.
    fn load_persist<S: KvBlobStoreAccess>(&self, kv: S) -> Result<(), Error> {
        let Some(loaded) =
            Persist::new(kv).load_tlv::<Vec<Provider, MAX_FABRICS>>(OTA_PROVIDERS_KEY)?
        else {
            self.state.lock(|cell| cell.borrow_mut().default.clear());
            return Ok(());
        };

        self.state.lock(|cell| cell.borrow_mut().default = loaded);

        info!("Loaded OTA provider entries from storage");

        Ok(())
    }

    /// Reset the registry - both the persisted default provider list and the
    /// transient announced-provider cache - and remove the persisted blob from
    /// `store` (under [`OTA_PROVIDERS_KEY`]).
    ///
    /// Called on factory reset via the [`LifecycleOp::FactoryReset`] lifecycle
    /// operation delivered to the [`OtaRequestorHandler`] borrowing this registry.
    fn reset_persist<S: KvBlobStore>(&self, mut store: S, buf: &mut [u8]) -> Result<(), Error> {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();

            state.default.clear();
            state.announced.clear();
        });

        store.remove(OTA_PROVIDERS_KEY, buf)
    }

    /// Drop the default and announced providers belonging to `fab_idx`,
    /// returning whether anything was removed. Signals
    /// [`wait_changed`](Self::wait_changed) when so.
    ///
    /// Called on fabric removal via the [`LifecycleOp::FabricRemoval`]
    /// lifecycle operation delivered to the [`OtaRequestorHandler`] borrowing
    /// this registry. Idempotent.
    fn remove_for_fabric(&self, fab_idx: NonZeroU8) -> bool {
        let removed = self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            let before = state.default.len() + state.announced.len();

            state.default.retain(|provider| provider.fab_idx != fab_idx);
            state
                .announced
                .retain(|provider| provider.fab_idx != fab_idx);

            state.default.len() + state.announced.len() < before
        });

        if removed {
            self.changed.notify();
        }

        removed
    }

    /// Persist the default provider list to `ctx.kv()`.
    fn store_persist<C: HandlerContext>(&self, ctx: &C) -> Result<(), Error> {
        let mut persist = Persist::new(ctx.kv());

        self.state.lock(|cell| {
            let state = cell.borrow();
            persist.store_tlv(OTA_PROVIDERS_KEY, &state.default)
        })?;

        persist.run()
    }

    /// The number of configured default providers (across all fabrics).
    pub fn len(&self) -> usize {
        self.state.lock(|cell| cell.borrow().default.len())
    }

    /// Whether there are no configured default providers.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The `index`-th default provider, cloned out so the registry lock is not
    /// held across the caller's subsequent (likely `async`) work.
    pub fn get(&self, index: usize) -> Option<Provider> {
        self.state
            .lock(|cell| cell.borrow().default.get(index).copied())
    }

    /// The number of cached announced providers.
    pub fn announced_len(&self) -> usize {
        self.state.lock(|cell| cell.borrow().announced.len())
    }

    /// The `index`-th announced provider, cloned out.
    pub fn announced(&self, index: usize) -> Option<Provider> {
        self.state
            .lock(|cell| cell.borrow().announced.get(index).copied())
    }

    /// Drop all cached announced providers (e.g. once the app has queried them).
    pub fn clear_announced(&self) {
        self.state.lock(|cell| cell.borrow_mut().announced.clear());
    }

    /// Atomically remove and return all cached announced providers.
    ///
    /// Prefer this to iterating [`announced`](Self::announced) and then calling
    /// [`clear_announced`](Self::clear_announced) in an update loop: providers
    /// learned via `AnnounceOTAProvider` *while the loop is busy* processing this
    /// batch land in a fresh `announced` set (and re-arm [`wait_changed`](Self::wait_changed))
    /// instead of being discarded unprocessed by a trailing clear.
    pub fn take_announced(&self) -> Vec<Provider, ANNOUNCED_PROVIDERS> {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            let taken = state.announced.clone();
            state.announced.clear();
            taken
        })
    }

    /// Wait until the provider set changes (a `DefaultOTAProviders` write or an
    /// `AnnounceOTAProvider` command).
    ///
    /// Single waiter: the application's update loop.
    pub async fn wait_changed(&self) {
        self.changed.wait().await;
    }

    /// Replace the (single) default provider for `fab_idx` with `provider`, or
    /// clear it when `None`.
    fn replace_default<C: WriteContext>(
        &self,
        ctx: &C,
        fab_idx: NonZeroU8,
        provider: Option<Provider>,
    ) -> Result<(), Error> {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.default.retain(|p| p.fab_idx != fab_idx);
            if let Some(provider) = provider {
                state
                    .default
                    .push(provider)
                    .map_err(|_| ErrorCode::ResourceExhausted)?;
            }
            Ok::<_, Error>(())
        })?;

        self.changed.notify();

        self.store_persist(ctx)
    }

    /// Add a default provider for `fab_idx`, failing with `CONSTRAINT_ERROR` if it
    /// already has one (at most one entry per fabric).
    fn add_default<C: WriteContext>(
        &self,
        ctx: &C,
        fab_idx: NonZeroU8,
        provider: Provider,
    ) -> Result<(), Error> {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if state.default.iter().any(|p| p.fab_idx == fab_idx) {
                return Err(ErrorCode::ConstraintError.into());
            }
            state
                .default
                .push(provider)
                .map_err(|_| ErrorCode::ResourceExhausted)?;
            Ok::<_, Error>(())
        })?;

        self.changed.notify();

        self.store_persist(ctx)
    }

    /// Cache a transient provider learned via `AnnounceOTAProvider` and wake any
    /// waiter. Deduplicated by `(fabric, node)`; the oldest is evicted if full.
    fn add_announced(&self, provider: Provider) {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state
                .announced
                .retain(|p| !(p.fab_idx == provider.fab_idx && p.node_id == provider.node_id));
            if state.announced.is_full() {
                state.announced.remove(0);
            }
            // Cannot fail: we just made room.
            let _ = state.announced.push(provider);
        });

        self.changed.notify();
    }

    /// Render the (fabric-filtered) default list into the attribute builder.
    fn render<P: TLVBuilderParent>(
        &self,
        fab_filter: Option<NonZeroU8>,
        builder: ArrayAttributeRead<ProviderLocationArrayBuilder<P>, ProviderLocationBuilder<P>>,
    ) -> Result<P, Error> {
        self.state.lock(|cell| {
            let state = cell.borrow();
            let mut iter = state
                .default
                .iter()
                .filter(|p| fab_filter.is_none_or(|f| p.fab_idx == f));

            match builder {
                ArrayAttributeRead::ReadAll(mut array) => {
                    for p in iter {
                        array = array
                            .push()?
                            .provider_node_id(p.node_id)?
                            .endpoint(p.endpoint)?
                            .fabric_index(Some(p.fab_idx.get()))?
                            .end()?;
                    }
                    array.end()
                }
                ArrayAttributeRead::ReadOne(index, item) => {
                    let Some(p) = iter.nth(index as usize) else {
                        return Err(ErrorCode::ConstraintError.into());
                    };
                    item.provider_node_id(p.node_id)?
                        .endpoint(p.endpoint)?
                        .fabric_index(Some(p.fab_idx.get()))?
                        .end()
                }
                ArrayAttributeRead::ReadNone(array) => array.end(),
            }
        })
    }
}

impl Default for Providers {
    fn default() -> Self {
        Self::new()
    }
}

/// The OTA Requestor's reported update state: the `UpdateState`,
/// `UpdateStateProgress` and `UpdatePossible` attributes.
///
/// Held separately from [`Providers`] because it is transient runtime state, not
/// configuration. The application reports progress through an [`OtaUpdate`]
/// session obtained from [`initiate_update`](Self::initiate_update).
///
/// Because progress is reported from the application's own update loop (outside
/// any cluster-handler `ctx`), the reporting calls take the data model's
/// [`AttrChangeNotifier`] (typically the `InteractionModel`) so each change bumps the
/// cluster's data version and wakes subscribers. It is passed in rather than
/// stored because the `InteractionModel` is constructed *after* this state (it borrows
/// it), so there is never a moment at which it could be stored here.
pub struct OtaState {
    endpoint_id: EndptId,
    reported: Mutex<RefCell<Reported>>,
}

struct Reported {
    update_state: UpdateStateEnum,
    progress: Option<u8>,
    update_possible: bool,
    /// The version the update under way installs, once known.
    target_version: Option<u32>,
}

impl OtaState {
    /// Create idle, update-possible state for the endpoint hosting the OTA
    /// Requestor cluster (the one whose [`OtaRequestorHandler`] reads this state),
    /// so change notifications target the right cluster instance.
    pub const fn new(endpoint_id: EndptId) -> Self {
        Self {
            endpoint_id,
            reported: Mutex::new(RefCell::new(Reported {
                update_state: UpdateStateEnum::Idle,
                progress: None,
                update_possible: true,
                target_version: None,
            })),
        }
    }

    /// Set the `UpdatePossible` attribute (e.g. `false` when the battery is too
    /// low to apply an update), notifying `notifier` of the change.
    pub fn set_update_possible(&self, notifier: &dyn AttrChangeNotifier, possible: bool) {
        self.reported
            .lock(|cell| cell.borrow_mut().update_possible = possible);

        self.notify(notifier, AttributeId::UpdatePossible as _);
    }

    fn update_state(&self) -> UpdateStateEnum {
        self.reported.lock(|cell| cell.borrow().update_state)
    }

    fn progress(&self) -> Option<u8> {
        self.reported.lock(|cell| cell.borrow().progress)
    }

    fn update_possible(&self) -> bool {
        self.reported.lock(|cell| cell.borrow().update_possible)
    }

    /// Update the reported `UpdateState`/`UpdateStateProgress` and notify; a
    /// change of state emits the `StateTransition` event, for `reason`.
    fn report(
        &self,
        ctx: impl AttrChangeNotifier + EventEmitter,
        state: UpdateStateEnum,
        progress: Option<u8>,
        reason: ChangeReasonEnum,
    ) {
        let (previous, target) = self.reported.lock(|cell| {
            let mut reported = cell.borrow_mut();
            let previous = reported.update_state;
            reported.update_state = state;
            reported.progress = progress;
            let target = reported.target_version;
            if state == UpdateStateEnum::Idle {
                reported.target_version = None;
            }

            (previous, target)
        });

        // Both `UpdateState` and `UpdateStateProgress` changed; a single
        // cluster-level notification bumps the data version once and re-reports
        // any subscriber interested in either attribute.
        ctx.notify_cluster_changed(self.endpoint_id, FULL_CLUSTER.id);

        if previous != state {
            // The version is that of the operation under way, if any.
            let target = target.filter(|_| {
                matches!(
                    state,
                    UpdateStateEnum::Downloading
                        | UpdateStateEnum::Applying
                        | UpdateStateEnum::RollingBack
                )
            });

            let emitted = StateTransition::emit_for(ctx, self.endpoint_id, |event| {
                event
                    .previous_state(previous)?
                    .new_state(state)?
                    .reason(reason)?
                    .target_software_version(Nullable::new(target))?
                    .end()
            });

            if let Err(e) = emitted {
                warn!("Failed to emit StateTransition: {:?}", e);
            }
        }
    }

    fn set_target_version(&self, version: u32) {
        self.reported
            .lock(|cell| cell.borrow_mut().target_version = Some(version));
    }

    fn download_failed(
        &self,
        ctx: impl EventEmitter,
        bytes_downloaded: u64,
        platform_code: Option<i64>,
    ) {
        let (version, progress) = self.reported.lock(|cell| {
            let reported = cell.borrow();
            (reported.target_version, reported.progress)
        });

        let emitted = DownloadError::emit_for(ctx, self.endpoint_id, |event| {
            event
                .software_version(version.unwrap_or(0))?
                .bytes_downloaded(bytes_downloaded)?
                .progress_percent(Nullable::new(progress))?
                .platform_code(Nullable::new(platform_code))?
                .end()
        });

        if let Err(e) = emitted {
            warn!("Failed to emit DownloadError: {:?}", e);
        }
    }

    /// Notify the data model that `attr_id` of this cluster instance changed.
    fn notify(&self, notifier: &dyn AttrChangeNotifier, attr_id: AttrId) {
        notifier.notify_attr_changed(self.endpoint_id, FULL_CLUSTER.id, attr_id);
    }

    /// Begin an update session, reporting changes and emitting events through
    /// `ctx` (typically the `InteractionModel`). The returned [`OtaUpdate`]
    /// reports progress; on [`complete`](OtaUpdate::complete) - or if dropped
    /// without it, a failure - the reported state returns to `Idle`
    /// (`UpdateStateEnum` has no dedicated failure value).
    pub fn initiate_update<E>(&self, ctx: E) -> OtaUpdate<'_, E>
    where
        E: AttrChangeNotifier + EventEmitter,
    {
        OtaUpdate {
            state: self,
            ctx,
            done: false,
        }
    }
}

/// An in-progress update session (RAII). Report progress with
/// [`querying`](Self::querying) / [`downloading`](Self::downloading) /
/// [`applying`](Self::applying) / [`report`](Self::report); call
/// [`complete`](Self::complete) when done. Dropping it without `complete` reverts
/// the reported state to `Idle`, so an aborted update never leaves the cluster
/// stuck mid-transfer.
///
/// Each change of state emits the `StateTransition` event; name the version
/// being installed with [`set_target_version`](Self::set_target_version) once
/// a provider offers it.
pub struct OtaUpdate<'a, E>
where
    E: AttrChangeNotifier + EventEmitter,
{
    state: &'a OtaState,
    ctx: E,
    done: bool,
}

impl<E> OtaUpdate<'_, E>
where
    E: AttrChangeNotifier + EventEmitter,
{
    /// Report `Querying`.
    pub fn querying(&self) {
        self.report(UpdateStateEnum::Querying, None);
    }

    /// Note the software version this update installs, as the provider
    /// offered it.
    pub fn set_target_version(&self, version: u32) {
        self.state.set_target_version(version);
    }

    /// Report `Downloading` at the given percent (`None` if unknown).
    pub fn downloading(&self, percent: Option<u8>) {
        self.report(UpdateStateEnum::Downloading, percent);
    }

    /// Report that the download failed after `bytes_downloaded` bytes, why as
    /// the platform has it in `platform_code`: the `DownloadError` event.
    pub fn download_failed(&self, bytes_downloaded: u64, platform_code: Option<i64>) {
        self.state
            .download_failed(&self.ctx, bytes_downloaded, platform_code);
    }

    /// Report `Applying`.
    pub fn applying(&self) {
        self.report(UpdateStateEnum::Applying, None);
    }

    /// Report an arbitrary `state` and `progress`.
    pub fn report(&self, state: UpdateStateEnum, progress: Option<u8>) {
        let reason = match state {
            UpdateStateEnum::DelayedOnQuery | UpdateStateEnum::DelayedOnApply => {
                ChangeReasonEnum::DelayByProvider
            }
            _ => ChangeReasonEnum::Success,
        };

        self.state.report(&self.ctx, state, progress, reason);
    }

    /// Finish the session, returning the reported state to `Idle`.
    pub fn complete(mut self) {
        self.state.report(
            &self.ctx,
            UpdateStateEnum::Idle,
            None,
            ChangeReasonEnum::Success,
        );
        self.done = true;
    }
}

impl<E> Drop for OtaUpdate<'_, E>
where
    E: AttrChangeNotifier + EventEmitter,
{
    fn drop(&mut self) {
        if !self.done {
            // Abandoned mid-update: revert to Idle.
            self.state.report(
                &self.ctx,
                UpdateStateEnum::Idle,
                None,
                ChangeReasonEnum::Failure,
            );
        }
    }
}

/// The server-side handler for the OTA Software Update Requestor cluster.
pub struct OtaRequestorHandler<'a> {
    dataver: Dataver,
    providers: &'a Providers,
    state: &'a OtaState,
}

impl<'a> OtaRequestorHandler<'a> {
    /// Create a handler backed by the shared [`Providers`] registry and
    /// [`OtaState`].
    pub const fn new(dataver: Dataver, providers: &'a Providers, state: &'a OtaState) -> Self {
        Self {
            dataver,
            providers,
            state,
        }
    }

    /// Emit the `VersionApplied` event if the node runs another software
    /// version than at its last boot - however it got it - and note the one
    /// it runs.
    fn note_running_version(&self, ctx: &impl HandlerContext) -> Result<(), Error> {
        let dev = ctx.matter().dev_det();

        // An unreadable version counts as none: there is no telling an update happened
        let last = Persist::new(ctx.kv()).load_tlv::<u32>(RUNNING_VERSION_KEY)?;

        if last == Some(dev.sw_ver) {
            return Ok(());
        }

        // Not on a first boot: there is no version it was updated from.
        if last.is_some() {
            let emitted = VersionApplied::emit_for(ctx, self.state.endpoint_id, |event| {
                event
                    .software_version(dev.sw_ver)?
                    .product_id(dev.pid)?
                    .end()
            });

            if let Err(e) = emitted {
                warn!("Failed to emit VersionApplied: {:?}", e);
            }
        }

        let mut persist = Persist::new(ctx.kv());
        persist.store_tlv(RUNNING_VERSION_KEY, dev.sw_ver)?;
        persist.run()
    }

    /// Adapt this handler to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for OtaRequestorHandler<'_> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn lifecycle(&self, ctx: impl HandlerContext, op: LifecycleOp) -> Result<(), Error> {
        match op {
            LifecycleOp::Startup => {
                self.providers.load_persist(ctx.kv())?;

                self.note_running_version(&ctx)
            }
            LifecycleOp::FactoryReset => ctx.kv().access(|mut store, buf| {
                let result = self.providers.reset_persist(&mut store, buf);

                result.and(store.remove(RUNNING_VERSION_KEY, buf))
            }),
            LifecycleOp::FailSafeCommit | LifecycleOp::FailSafeExpiry => Ok(()),
            LifecycleOp::FabricRemoval { fab_idx } => {
                if self.providers.remove_for_fabric(fab_idx) {
                    self.providers.store_persist(&ctx)?;
                }

                Ok(())
            }
        }
    }

    fn default_ota_providers<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<ProviderLocationArrayBuilder<P>, ProviderLocationBuilder<P>>,
    ) -> Result<P, Error> {
        let attr = ctx.attr();
        let fab_filter = if attr.fab_filter {
            Some(NonZeroU8::new(attr.fab_idx).ok_or(ErrorCode::UnsupportedAccess)?)
        } else {
            None
        };

        self.providers.render(fab_filter, builder)
    }

    fn update_possible(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        Ok(self.state.update_possible())
    }

    fn update_state(&self, _ctx: impl ReadContext) -> Result<UpdateStateEnum, Error> {
        Ok(self.state.update_state())
    }

    fn update_state_progress(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        Ok(self
            .state
            .progress()
            .map(Nullable::some)
            .unwrap_or_else(Nullable::none))
    }

    fn set_default_ota_providers(
        &self,
        ctx: impl WriteContext,
        value: ArrayAttributeWrite<TLVArray<'_, ProviderLocation<'_>>, ProviderLocation<'_>>,
    ) -> Result<(), Error> {
        // Fabric-scoped writes require a valid accessing fabric.
        let fab_idx = NonZeroU8::new(ctx.attr().fab_idx).ok_or(ErrorCode::UnsupportedAccess)?;

        let to_provider = |loc: &ProviderLocation<'_>| -> Result<Provider, Error> {
            Ok(Provider {
                fab_idx,
                node_id: loc.provider_node_id()?,
                endpoint: loc.endpoint()?,
            })
        };

        match value {
            // At most one entry per fabric: a replacement list may carry zero or
            // one entry; more than one is a `CONSTRAINT_ERROR`.
            ArrayAttributeWrite::Replace(list) => {
                let mut iter = list.iter();
                let first = iter.next().transpose()?;
                if iter.next().is_some() {
                    return Err(ErrorCode::ConstraintError.into());
                }

                // Parse before mutating, so a malformed entry leaves the existing
                // default intact.
                let parsed = first.map(|loc| to_provider(&loc)).transpose()?;
                self.providers.replace_default(&ctx, fab_idx, parsed)?;
            }
            // Adding a second entry for a fabric would exceed the one-per-fabric
            // limit; reject it.
            ArrayAttributeWrite::Add(loc) => {
                self.providers
                    .add_default(&ctx, fab_idx, to_provider(&loc)?)?;
            }
            // Per-index update/remove on a fabric-scoped list are converted to
            // `InvalidAction` by the framework; reject defensively.
            ArrayAttributeWrite::Update(_, _) | ArrayAttributeWrite::Remove(_) => {
                return Err(ErrorCode::InvalidAction.into());
            }
        }

        // Notify subscribers of the changed attribute (also bumps the dataver).
        ctx.notify_changed();

        Ok(())
    }

    fn handle_announce_ota_provider(
        &self,
        ctx: impl InvokeContext,
        request: AnnounceOTAProviderRequest<'_>,
    ) -> Result<(), Error> {
        let fab_idx = NonZeroU8::new(ctx.cmd().fab_idx).ok_or(ErrorCode::UnsupportedAccess)?;

        let provider = Provider {
            fab_idx,
            node_id: request.provider_node_id()?,
            endpoint: request.endpoint()?,
        };

        // Per spec, an announced provider is a transient hint and SHALL NOT be
        // added to `DefaultOTAProviders`; cache it separately and wake the app.
        self.providers.add_announced(provider);

        Ok(())
    }
}

/// Parse a `bdx://<node-id>/<file-designator>` image URI into its `(node id, file
/// designator)` pair. The node id is hex-encoded, as minted by an OTA Provider's
/// `QueryImage` response.
pub fn parse_bdx_url(url: &str) -> Result<(NodeId, &str), Error> {
    let rest = url.strip_prefix("bdx://").ok_or(ErrorCode::InvalidData)?;
    let (node, fd) = rest.split_once('/').ok_or(ErrorCode::InvalidData)?;
    if fd.is_empty() {
        // A BDX transfer needs a non-empty file designator to identify the file.
        return Err(ErrorCode::InvalidData.into());
    }
    let node_id = u64::from_str_radix(node, 16).map_err(|_| ErrorCode::InvalidData)?;

    Ok((node_id, fd))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::dm::clusters::app::test_util::RecordingEvents;
    use crate::im::EventData;

    use super::*;

    /// Field `tag` of `event`, unless null.
    fn field(event: &EventData<'_>, tag: u8) -> Option<i64> {
        let field = event.data.structure().unwrap().ctx(tag).unwrap();
        field.null().is_err().then(|| {
            field
                .u64()
                .map(|v| v as i64)
                .or_else(|_| field.i64())
                .unwrap()
        })
    }

    /// The event ID of `event`, and its fields `0..fields`.
    fn event(event: &EventData<'_>, fields: u8) -> (u32, Vec<Option<i64>, 4>) {
        (
            event.path.event.unwrap(),
            (0..fields).map(|tag| field(event, tag)).collect(),
        )
    }

    const IDLE: i64 = UpdateStateEnum::Idle as i64;
    const QUERYING: i64 = UpdateStateEnum::Querying as i64;
    const DOWNLOADING: i64 = UpdateStateEnum::Downloading as i64;
    const SUCCESS: i64 = ChangeReasonEnum::Success as i64;
    const FAILURE: i64 = ChangeReasonEnum::Failure as i64;

    #[test]
    fn an_update_reports_its_transitions_and_download_error() {
        let events = RecordingEvents::default();
        let state = OtaState::new(1);

        {
            let update = state.initiate_update(&events);
            update.querying();
            update.set_target_version(7);
            update.downloading(Some(0));
            // Progress alone is no transition.
            update.downloading(Some(50));
            update.download_failed(1024, Some(-3));
            // Dropped: a failure.
        }

        events.with_events(|emitted| {
            let transition = EventId::StateTransition as u32;
            let error = EventId::DownloadError as u32;

            assert_eq!(emitted.len(), 4);
            assert_eq!(
                event(&emitted[0], 4),
                (
                    transition,
                    Vec::from_slice(&[Some(IDLE), Some(QUERYING), Some(SUCCESS), None]).unwrap()
                )
            );
            assert_eq!(
                event(&emitted[1], 4),
                (
                    transition,
                    Vec::from_slice(&[Some(QUERYING), Some(DOWNLOADING), Some(SUCCESS), Some(7)])
                        .unwrap()
                )
            );
            assert_eq!(
                event(&emitted[2], 4),
                (
                    error,
                    Vec::from_slice(&[Some(7), Some(1024), Some(50), Some(-3)]).unwrap()
                )
            );
            assert_eq!(
                event(&emitted[3], 4),
                (
                    transition,
                    Vec::from_slice(&[Some(DOWNLOADING), Some(IDLE), Some(FAILURE), None]).unwrap()
                )
            );
        });
    }

    #[test]
    fn a_completed_update_ends_in_success() {
        let events = RecordingEvents::default();
        let state = OtaState::new(1);

        let update = state.initiate_update(&events);
        update.querying();
        update.complete();

        events.with_events(|emitted| {
            assert_eq!(emitted.len(), 2);
            assert_eq!(field(&emitted[1], 1), Some(IDLE));
            assert_eq!(field(&emitted[1], 2), Some(SUCCESS));
        });
    }

    #[test]
    fn parse_bdx_url_extracts_node_and_fd() {
        let (node, fd) = parse_bdx_url("bdx://00112233AABBCCDD/my-firmware.ota").unwrap();
        assert_eq!(node, 0x0011_2233_AABB_CCDD);
        assert_eq!(fd, "my-firmware.ota");

        assert!(parse_bdx_url("https://example.com/x").is_err());
        assert!(parse_bdx_url("bdx://nodeid-no-slash").is_err());
        assert!(parse_bdx_url("bdx://zzzz/fd").is_err());
    }

    #[test]
    fn announced_dedup_evict_and_clear() {
        let providers = Providers::new();
        let provider = |node| Provider {
            fab_idx: NonZeroU8::new(1).unwrap(),
            node_id: node,
            endpoint: 0,
        };

        // Deduplicated by (fabric, node).
        providers.add_announced(provider(0xaa));
        providers.add_announced(provider(0xaa));
        assert_eq!(providers.announced_len(), 1);

        // Capacity-bounded: the oldest is evicted.
        for n in 0..(ANNOUNCED_PROVIDERS as u64 + 2) {
            providers.add_announced(provider(0x100 + n));
        }
        assert_eq!(providers.announced_len(), ANNOUNCED_PROVIDERS);

        providers.clear_announced();
        assert_eq!(providers.announced_len(), 0);
    }
}
