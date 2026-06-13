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

//! The OTA Software Update Requestor cluster, plus a driver that performs the
//! actual update: it polls the configured OTA Providers, downloads a newer
//! image over BDX, and hands it to a user-supplied [`OtaTarget`] to apply.
//!
//! The device hosts the OTA Requestor cluster (server role) so a Commissioner
//! can populate its provider list and observe its update state, and acts as a
//! client of the OTA Provider cluster on the provider node.

use core::cell::{Cell, RefCell};
use core::num::NonZeroU8;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use crate::bdx::BdxPull;
use crate::crypto::Crypto;
use crate::dm::{
    ArrayAttributeRead, ArrayAttributeWrite, Cluster, Dataver, InvokeContext, ReadContext,
    WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::im::EndptId;
use crate::tlv::{Nullable, Octets, TLVArray, TLVBuilderParent};
use crate::transport::exchange::Exchange;
use crate::utils::sync::Notification;
use crate::with;
use crate::Matter;

pub use crate::dm::clusters::decl::ota_software_update_requestor::*;

use crate::dm::clusters::decl::ota_software_update_provider::{
    ApplyUpdateActionEnum, DownloadProtocolEnum, OtaSoftwareUpdateProviderClient, StatusEnum,
};

/// The maximum number of OTA Provider entries kept (one per fabric, by default).
pub const MAX_PROVIDERS: usize = 4;

/// The largest BDX block we are willing to receive over a non-TCP transport.
const MAX_BLOCK_SIZE: u16 = 1024;

/// How often the driver polls its providers when otherwise idle (an hour). The
/// spec forbids querying a given provider more than once every 120 seconds; an
/// `AnnounceOTAProvider` command triggers an immediate, out-of-band check.
const POLL_INTERVAL: Duration = Duration::from_secs(3600);

/// A device-specific sink and applier for a downloaded OTA image.
///
/// The driver calls [`begin`](Self::begin) once a newer image is available,
/// then [`write`](Self::write) for each downloaded chunk (in order), and finally
/// [`apply`](Self::apply) to activate it (typically by marking a new firmware
/// slot bootable and rebooting).
pub trait OtaTarget {
    /// The currently running software version. Used as the `QueryImage`
    /// baseline; only strictly newer versions are downloaded.
    fn current_version(&self) -> u32;

    /// Begin receiving a new image of the given `version`. A previous,
    /// incomplete download (if any) should be discarded.
    async fn begin(&mut self, version: u32) -> Result<(), Error>;

    /// Store a chunk of the image at `offset` bytes from its start.
    async fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), Error>;

    /// The whole image has been received and authorized; activate it. If this
    /// returns (rather than rebooting), the driver reports the update applied.
    async fn apply(&mut self) -> Result<(), Error>;
}

/// One OTA Provider, scoped to the fabric that registered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Provider {
    fab_idx: u8,
    node_id: u64,
    endpoint: EndptId,
}

/// State shared between the OTA Requestor cluster handler and the driver: the
/// provider list (the `DefaultOTAProviders` attribute, augmented by
/// `AnnounceOTAProvider`), the reported update state, and a trigger the handler
/// raises to make the driver query immediately.
pub struct OtaState {
    providers: RefCell<heapless::Vec<Provider, MAX_PROVIDERS>>,
    update_state: Cell<UpdateStateEnum>,
    progress: Cell<Option<u8>>,
    trigger: Notification,
}

impl Default for OtaState {
    fn default() -> Self {
        Self::new()
    }
}

impl OtaState {
    /// Create empty OTA state (no providers, `Idle`).
    pub fn new() -> Self {
        Self {
            providers: RefCell::new(heapless::Vec::new()),
            update_state: Cell::new(UpdateStateEnum::Idle),
            progress: Cell::new(None),
            trigger: Notification::new(),
        }
    }

    fn set_state(&self, state: UpdateStateEnum, progress: Option<u8>) {
        self.update_state.set(state);
        self.progress.set(progress);
    }

    /// Insert/replace the single provider for `fab_idx`.
    fn set_provider(&self, provider: Provider) {
        let mut providers = self.providers.borrow_mut();
        providers.retain(|p| p.fab_idx != provider.fab_idx);
        // Best-effort: drop the entry if the (per-fabric) table is somehow full.
        let _ = providers.push(provider);
    }
}

/// The server-side handler for the OTA Software Update Requestor cluster.
pub struct OtaRequestorHandler<'a> {
    dataver: Dataver,
    state: &'a OtaState,
}

impl<'a> OtaRequestorHandler<'a> {
    /// Create a new handler backed by the given shared [`OtaState`].
    pub const fn new(dataver: Dataver, state: &'a OtaState) -> Self {
        Self { dataver, state }
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

    fn default_ota_providers<P: TLVBuilderParent>(
        &self,
        ctx: impl ReadContext,
        builder: ArrayAttributeRead<ProviderLocationArrayBuilder<P>, ProviderLocationBuilder<P>>,
    ) -> Result<P, Error> {
        let attr = ctx.attr();
        let providers = self.state.providers.borrow();
        let mut iter = providers
            .iter()
            .filter(|p| !attr.fab_filter || p.fab_idx == attr.fab_idx);

        match builder {
            ArrayAttributeRead::ReadAll(mut builder) => {
                for p in iter {
                    builder = builder
                        .push()?
                        .provider_node_id(p.node_id)?
                        .endpoint(p.endpoint)?
                        .fabric_index(Some(p.fab_idx))?
                        .end()?;
                }
                builder.end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let Some(p) = iter.nth(index as usize) else {
                    return Err(ErrorCode::ConstraintError.into());
                };
                builder
                    .provider_node_id(p.node_id)?
                    .endpoint(p.endpoint)?
                    .fabric_index(Some(p.fab_idx))?
                    .end()
            }
            ArrayAttributeRead::ReadNone(builder) => builder.end(),
        }
    }

    fn update_possible(&self, _ctx: impl ReadContext) -> Result<bool, Error> {
        Ok(true)
    }

    fn update_state(&self, _ctx: impl ReadContext) -> Result<UpdateStateEnum, Error> {
        Ok(self.state.update_state.get())
    }

    fn update_state_progress(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        Ok(self
            .state
            .progress
            .get()
            .map(Nullable::some)
            .unwrap_or_else(Nullable::none))
    }

    fn set_default_ota_providers(
        &self,
        ctx: impl WriteContext,
        value: ArrayAttributeWrite<TLVArray<'_, ProviderLocation<'_>>, ProviderLocation<'_>>,
    ) -> Result<(), Error> {
        // `DefaultOTAProviders` is fabric-scoped: a write only affects the
        // accessing fabric's (single) entry.
        let fab_idx = ctx.attr().fab_idx;

        let to_provider = |loc: &ProviderLocation<'_>| -> Result<Provider, Error> {
            Ok(Provider {
                fab_idx,
                node_id: loc.provider_node_id()?,
                endpoint: loc.endpoint()?,
            })
        };

        match value {
            ArrayAttributeWrite::Replace(list) => {
                self.state
                    .providers
                    .borrow_mut()
                    .retain(|p| p.fab_idx != fab_idx);
                for loc in list.iter() {
                    self.state.set_provider(to_provider(&loc?)?);
                }
            }
            ArrayAttributeWrite::Add(loc) | ArrayAttributeWrite::Update(_, loc) => {
                self.state.set_provider(to_provider(&loc)?);
            }
            ArrayAttributeWrite::Remove(_) => {
                self.state
                    .providers
                    .borrow_mut()
                    .retain(|p| p.fab_idx != fab_idx);
            }
        }

        // Bump the dataver and notify subscribers of the changed attribute.
        ctx.notify_changed();

        Ok(())
    }

    fn handle_announce_ota_provider(
        &self,
        ctx: impl InvokeContext,
        request: AnnounceOTAProviderRequest<'_>,
    ) -> Result<(), Error> {
        let provider = Provider {
            fab_idx: ctx.cmd().fab_idx,
            node_id: request.provider_node_id()?,
            endpoint: request.endpoint()?,
        };

        self.state.set_provider(provider);
        // The command mutated `DefaultOTAProviders` (on this same cluster); notify.
        ctx.notify_own_attr_changed(AttributeId::DefaultOTAProviders as _);
        // Wake the driver to query this provider out-of-band.
        self.state.trigger.notify();

        Ok(())
    }
}

/// Pull the BDX file designator out of a `bdx://<node-id>/<file-designator>` URI.
fn bdx_file_designator(uri: &str) -> Result<&str, Error> {
    uri.strip_prefix("bdx://")
        .and_then(|rest| rest.split_once('/'))
        .map(|(_node, fd)| fd)
        .ok_or_else(|| ErrorCode::InvalidData.into())
}

/// The OTA Requestor driver: drives the query/download/apply flow against the
/// providers in the shared [`OtaState`], delegating image handling to an
/// [`OtaTarget`]. Run [`run`](Self::run) as a long-lived task.
pub struct OtaRequestor<'a, C, T> {
    matter: &'a Matter<'a>,
    state: &'a OtaState,
    crypto: C,
    target: T,
    vendor_id: u16,
    product_id: u16,
}

impl<'a, C, T> OtaRequestor<'a, C, T>
where
    C: Crypto,
    T: OtaTarget,
{
    /// Create a new driver.
    pub const fn new(
        matter: &'a Matter<'a>,
        state: &'a OtaState,
        crypto: C,
        target: T,
        vendor_id: u16,
        product_id: u16,
    ) -> Self {
        Self {
            matter,
            state,
            crypto,
            target,
            vendor_id,
            product_id,
        }
    }

    /// Run the driver forever: poll periodically, or immediately whenever an
    /// `AnnounceOTAProvider` command arrives.
    pub async fn run(&mut self) -> Result<(), Error> {
        loop {
            match select(self.state.trigger.wait(), Timer::after(POLL_INTERVAL)).await {
                Either::First(()) | Either::Second(()) => {}
            }

            if let Err(e) = self.check_for_update().await {
                warn!("OTA: update cycle failed: {:?}", e);
            }

            self.state.set_state(UpdateStateEnum::Idle, None);
        }
    }

    /// Run a single query/download/apply cycle across all known providers,
    /// stopping at the first one that yields and applies an update.
    pub async fn check_for_update(&mut self) -> Result<(), Error> {
        let providers: heapless::Vec<Provider, MAX_PROVIDERS> =
            self.state.providers.borrow().clone();

        for provider in providers {
            match self.try_provider(&provider).await {
                Ok(true) => return Ok(()),
                Ok(false) => continue,
                Err(e) => {
                    warn!("OTA: provider 0x{:016x} failed: {:?}", provider.node_id, e);
                    continue;
                }
            }
        }

        Ok(())
    }

    /// Try to obtain and apply an update from a single provider. Returns
    /// `Ok(true)` if an image was downloaded and applied.
    async fn try_provider(&mut self, provider: &Provider) -> Result<bool, Error> {
        let fab_idx = NonZeroU8::new(provider.fab_idx).ok_or(ErrorCode::Invalid)?;

        // 1. QueryImage.
        self.state.set_state(UpdateStateEnum::Querying, None);

        let exchange =
            Exchange::initiate(self.matter, &self.crypto, fab_idx, provider.node_id).await?;

        let handle = exchange
            .ota_software_update_provider()
            .query_image(provider.endpoint, |b| {
                b.vendor_id(self.vendor_id)?
                    .product_id(self.product_id)?
                    .software_version(self.target.current_version())?
                    .protocols_supported()?
                    .push(&DownloadProtocolEnum::BDXSynchronous)?
                    .end()?
                    .hardware_version(None)?
                    .location(None)?
                    .requestor_can_consent(None)?
                    .metadata_for_provider(None)?
                    .end()
            })
            .await?;

        // Extract everything we need into owned storage before releasing the
        // response (its fields borrow the exchange RX buffer), so the borrow
        // ends before we `complete()` (and consume) the handle.
        let mut file_designator = heapless::String::<128>::new();
        let mut update_token = heapless::Vec::<u8, 32>::new();
        let new_version = {
            let resp = handle.response()?;

            let available = resp.status()? == StatusEnum::UpdateAvailable;
            let version = resp.software_version()?;

            match version {
                Some(version) if available && version > self.target.current_version() => {
                    let uri = resp.image_uri()?.ok_or(ErrorCode::InvalidData)?;
                    file_designator
                        .push_str(bdx_file_designator(uri)?)
                        .map_err(|_| ErrorCode::NoSpace)?;

                    if let Some(token) = resp.update_token()? {
                        update_token
                            .extend_from_slice(token.0)
                            .map_err(|_| ErrorCode::NoSpace)?;
                    }

                    Some(version)
                }
                _ => None,
            }
        };

        handle.complete().await?;

        let Some(new_version) = new_version else {
            return Ok(false);
        };

        // 2. Download the image over BDX.
        self.state.set_state(UpdateStateEnum::Downloading, Some(0));
        self.target.begin(new_version).await?;

        let bdx_exchange =
            Exchange::initiate(self.matter, &self.crypto, fab_idx, provider.node_id).await?;
        let mut reader = bdx_exchange.pull(file_designator.as_bytes()).await?;

        let total = reader.len();
        let mut received = 0u64;
        let mut buf = [0u8; MAX_BLOCK_SIZE as usize];

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            self.target.write(received, &buf[..n]).await?;
            received += n as u64;

            // Report progress for a definite-length transfer.
            if let Some(total) = total.filter(|total| *total > 0) {
                let percent = (received.min(total) * 100 / total) as u8;
                self.state.progress.set(Some(percent));
            }
        }

        // 3. ApplyUpdateRequest - ask the provider for permission to apply.
        let exchange =
            Exchange::initiate(self.matter, &self.crypto, fab_idx, provider.node_id).await?;
        let handle = exchange
            .ota_software_update_provider()
            .apply_update_request(provider.endpoint, |b| {
                b.update_token(Octets(&update_token))?
                    .new_version(new_version)?
                    .end()
            })
            .await?;

        let action = {
            let resp = handle.response()?;
            resp.action()?
        };

        handle.complete().await?;

        if !matches!(action, ApplyUpdateActionEnum::Proceed) {
            // Provider asked us to wait or to discontinue; try again later.
            return Ok(false);
        }

        // 4. Apply (typically reboots into the new image).
        self.state.set_state(UpdateStateEnum::Applying, None);
        self.target.apply().await?;

        // 5. NotifyUpdateApplied (only reached if `apply` did not reboot).
        let exchange =
            Exchange::initiate(self.matter, &self.crypto, fab_idx, provider.node_id).await?;
        exchange
            .ota_software_update_provider()
            .notify_update_applied(provider.endpoint, |b| {
                b.update_token(Octets(&update_token))?
                    .software_version(new_version)?
                    .end()
            })
            .await?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bdx_uri() {
        assert_eq!(
            bdx_file_designator("bdx://00112233AABBCCDD/my-firmware.ota").unwrap(),
            "my-firmware.ota"
        );
        assert!(bdx_file_designator("https://example.com/x").is_err());
        assert!(bdx_file_designator("bdx://nodeid-no-slash").is_err());
    }

    #[test]
    fn provider_is_per_fabric() {
        let state = OtaState::new();
        state.set_provider(Provider {
            fab_idx: 1,
            node_id: 0xaa,
            endpoint: 0,
        });
        state.set_provider(Provider {
            fab_idx: 1,
            node_id: 0xbb,
            endpoint: 0,
        });
        state.set_provider(Provider {
            fab_idx: 2,
            node_id: 0xcc,
            endpoint: 0,
        });

        let providers = state.providers.borrow();
        // Fabric 1 keeps only the latest (0xbb); fabric 2 is separate.
        assert_eq!(providers.len(), 2);
        assert!(providers
            .iter()
            .any(|p| p.fab_idx == 1 && p.node_id == 0xbb));
        assert!(providers
            .iter()
            .any(|p| p.fab_idx == 2 && p.node_id == 0xcc));
    }
}
