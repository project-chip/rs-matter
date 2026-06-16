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

//! The OTA Software Update Provider cluster, plus a BDX handler that streams the
//! offered image to requestors.
//!
//! The node hosts the OTA Provider cluster (server role): it answers
//! `QueryImage` with the location of a newer image (a `bdx://` URI), authorizes
//! the apply via `ApplyUpdateRequest`, and notes completion via
//! `NotifyUpdateApplied`. The image bytes are served over BDX by
//! [`OtaBdxHandler`], a [`BdxHandler`] that the application wraps in a
//! [`Bdx`](crate::bdx::Bdx) handler and chains into its responder for the BDX
//! protocol. The two delegate to separate user-supplied sources - the cluster
//! handler to an [`OtaImagesRegistry`] (which image to offer), the BDX handler to
//! an [`OtaImages`] (the image bytes) - so either can be used on its own.
//!
//! Update *policy* - including whether a user must consent before an image is
//! applied - lives in those user implementations, not here: the registry decides
//! per query (see [`OtaImagesRegistry::query`] and
//! [`OtaImageMeta::user_consent_needed`]), and consent can be layered onto an
//! existing registry (e.g. the [`dcl`] sample) with a thin wrapping proxy.

use core::fmt::Write as _;
use core::num::NonZeroU8;

use crate::bdx::{BdxHandler, BdxResponder, BdxStatus};
use crate::dm::{Cluster, Dataver, InvokeContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::{Octets, TLVBuilderParent};
use crate::transport::exchange::MAX_EXCHANGE_RX_BUF_SIZE;
use crate::utils::storage::pooled::BufferAccess;
use crate::with;

/// The buffer an [`OtaBdxHandler`] stages each BDX block in.
///
/// Re-exported from the [`bdx`](crate::bdx) module, where it now lives, so an
/// application can size a [`PooledBuffers`] pool for the OTA BDX handler without
/// reaching into the BDX module directly.
///
/// [`PooledBuffers`]: crate::utils::storage::pooled::PooledBuffers
pub use crate::bdx::BdxBuffer;

pub use crate::dm::clusters::decl::ota_software_update_provider::*;

/// A sample [`OtaImagesRegistry`] + [`OtaImages`] implementation backed by the
/// CSA-IOT Distributed Compliance Ledger and a CDN, over a pluggable HTTPS client.
#[cfg(feature = "ota-dcl")]
pub mod dcl;

/// The maximum supported BDX file designator length.
const MAX_FILE_DESIGNATOR: usize = 128;

/// Metadata describing an OTA image that a provider is willing to offer.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OtaImageMeta<'a> {
    /// The version of the offered image. Must be newer than the requestor's.
    pub version: u32,
    /// The BDX file designator that identifies this image when downloaded.
    pub file_designator: &'a str,
    /// The opaque `UpdateToken` (8..=32 bytes) the provider assigns to this offer.
    /// The requestor echoes it verbatim on `ApplyUpdateRequest` /
    /// `NotifyUpdateApplied`, where it is handed back to
    /// [`OtaImagesRegistry::apply`] - so a registry can use it to correlate the
    /// apply/notify phase with this query (e.g. an image id, or a key into its own
    /// per-flow state). It is *not* used for the download (that's the
    /// [`file_designator`](Self::file_designator) carried in the `bdx://` URL).
    pub update_token: &'a [u8],
    /// The total image size in bytes, if known (enables a definite-length
    /// transfer and download-progress reporting on the requestor).
    pub size: Option<u64>,
    /// Whether the requestor must obtain user consent before applying this image.
    /// Surfaced to the requestor as `UserConsentNeeded` in the `QueryImage`
    /// response. See [`OtaImagesRegistry::query`] for how this interacts with the
    /// requestor's `requestor_can_consent` capability - consent *policy* is the
    /// registry's to decide.
    pub user_consent_needed: bool,
}

/// The outcome of an [`OtaImagesRegistry::query`] - the three `QueryImage`
/// responses an OTA Requestor acts on (per the Matter spec).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OtaQueryOutcome<'a> {
    /// An applicable image is available; offer it. Maps to `Status =
    /// UpdateAvailable`.
    Available(OtaImageMeta<'a>),
    /// The provider may have an update but cannot answer definitively yet - e.g.
    /// it is still determining availability, or awaiting user consent it obtains
    /// itself. Maps to `Status = Busy`: the requestor retries the *same* provider
    /// after at least `delay_secs` (never sooner than the spec's 120-second floor).
    Busy {
        /// Minimum seconds before the requestor re-queries (`DelayedActionTime`).
        delay_secs: u32,
    },
    /// Definitely no update is available. Maps to `Status = NotAvailable`: the
    /// requestor may instead try a different provider.
    NotAvailable,
}

/// How the OTA Requestor should proceed with applying an already-downloaded
/// image, returned from [`OtaImagesRegistry::apply`] in response to
/// `ApplyUpdateRequest` (per the Matter spec).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OtaApplyOutcome {
    /// Apply now, or after `delay_secs`. Maps to `Action = Proceed`.
    Proceed {
        /// Seconds to wait before applying (`DelayedActionTime`; `0` = at once).
        delay_secs: u32,
    },
    /// Not yet: the requestor waits `delay_secs` and re-sends `ApplyUpdateRequest`
    /// - e.g. provider-side user consent is still pending. Maps to `Action =
    /// AwaitNextAction` (the requestor enforces a 120-second floor).
    Await {
        /// Seconds to wait before asking again (`DelayedActionTime`).
        delay_secs: u32,
    },
    /// Rescind the image; the requestor should discard it. Maps to `Action =
    /// Discontinue`.
    Discontinue,
}

/// A device-specific registry of OTA images: it decides which image (if any) to
/// offer a querying requestor, and authorizes applying it. Used by
/// [`OtaProviderHandler`].
///
/// # User consent
///
/// Update *policy*, including user consent, lives here, not in the cluster
/// handler. The Matter spec lets a provider obtain consent before offering an
/// image and/or before letting the requestor apply it; a registry expresses that
/// at two points (no consent is ever gated during the BDX transfer itself):
///
/// - **Delegation** - when the requestor can prompt the user
///   (`requestor_can_consent`), [`query`](Self::query) may offer the image with
///   [`OtaImageMeta::user_consent_needed`] set, and the requestor prompts before
///   downloading.
/// - **Provider-side, at query** - while the provider obtains consent itself,
///   [`query`](Self::query) returns [`OtaQueryOutcome::Busy`] so the requestor retries
///   later (do *not* return [`OtaQueryOutcome::NotAvailable`] - that means "no update").
/// - **Provider-side, at apply** - [`apply`](Self::apply) returns
///   [`OtaApplyOutcome::Await`] until consent is granted, then [`OtaApplyOutcome::Proceed`].
///
/// A common way to add consent on top of an existing registry (e.g. the [`dcl`]
/// sample) is a thin proxy that wraps it and overrides these decisions.
pub trait OtaImagesRegistry {
    /// Decide what to offer a requestor querying for an image newer than
    /// `current_version` for `(vendor_id, product_id)`: [`OtaQueryOutcome::Available`]
    /// with the image to offer, [`OtaQueryOutcome::Busy`] to retry later (e.g. consent
    /// pending), or [`OtaQueryOutcome::NotAvailable`].
    ///
    /// `requestor_can_consent` reports whether the requestor can obtain user
    /// consent itself; set [`OtaImageMeta::user_consent_needed`] to delegate
    /// consent to it (only meaningful when it can). See the [trait
    /// docs](OtaImagesRegistry#user-consent).
    ///
    /// The returned [`OtaImageMeta::file_designator`] is written into (and
    /// borrows) `designator_buf`, so a registry can mint a designator computed at
    /// runtime rather than being limited to `'static` strings.
    async fn query<'b>(
        &self,
        vendor_id: u16,
        product_id: u16,
        current_version: u32,
        requestor_can_consent: bool,
        designator_buf: &'b mut [u8],
    ) -> OtaQueryOutcome<'b>;

    /// Authorize the requestor to apply the already-downloaded image, upgrading to
    /// `new_version`. `update_token` is the exact [`OtaImageMeta::update_token`]
    /// this registry assigned in [`query`](Self::query) and the requestor echoed
    /// back, so the registry can correlate this call with that offer.
    ///
    /// The default authorizes an immediate apply. Override it to defer (e.g. until
    /// provider-side consent is granted, with [`OtaApplyOutcome::Await`]) or to rescind a
    /// previously offered image ([`OtaApplyOutcome::Discontinue`]).
    async fn apply(&self, _update_token: &[u8], _new_version: u32) -> OtaApplyOutcome {
        OtaApplyOutcome::Proceed { delay_secs: 0 }
    }
}

impl<T> OtaImagesRegistry for &T
where
    T: OtaImagesRegistry,
{
    async fn query<'b>(
        &self,
        vendor_id: u16,
        product_id: u16,
        current_version: u32,
        requestor_can_consent: bool,
        designator_buf: &'b mut [u8],
    ) -> OtaQueryOutcome<'b> {
        T::query(
            self,
            vendor_id,
            product_id,
            current_version,
            requestor_can_consent,
            designator_buf,
        )
        .await
    }

    async fn apply(&self, update_token: &[u8], new_version: u32) -> OtaApplyOutcome {
        T::apply(self, update_token, new_version).await
    }
}

/// The image bytes behind a BDX file designator: looked up and streamed during a
/// download. Used by [`OtaBdxHandler`].
pub trait OtaImages {
    /// The total size of the image identified by `file_designator`. `None` means
    /// the designator is unknown and the BDX transfer is rejected
    /// (`FileDesignatorUnknown`).
    async fn size(&self, file_designator: &[u8]) -> Option<u64>;

    /// Read up to `buf.len()` bytes of the image identified by `file_designator`
    /// at `offset`, returning the number of bytes read (`0` marks the end). An
    /// unknown designator should return an error.
    async fn read(
        &self,
        file_designator: &[u8],
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Error>;
}

impl<T> OtaImages for &T
where
    T: OtaImages,
{
    async fn size(&self, file_designator: &[u8]) -> Option<u64> {
        T::size(self, file_designator).await
    }

    async fn read(
        &self,
        file_designator: &[u8],
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        T::read(self, file_designator, offset, buf).await
    }
}

/// The valid `UpdateToken` length range, per the Matter spec.
const UPDATE_TOKEN_LEN: core::ops::RangeInclusive<usize> = 8..=32;

/// The server-side handler for the OTA Software Update Provider cluster.
pub struct OtaProviderHandler<I> {
    dataver: Dataver,
    images: I,
}

impl<I> OtaProviderHandler<I> {
    /// Create a new handler backed by the given image registry.
    pub const fn new(dataver: Dataver, images: I) -> Self {
        Self { dataver, images }
    }

    /// Adapt this handler to the generic `rs-matter` `AsyncHandler` trait.
    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }
}

impl<I: OtaImagesRegistry> ClusterAsyncHandler for OtaProviderHandler<I> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn handle_query_image<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: QueryImageRequest<'_>,
        response: QueryImageResponseBuilder<P>,
    ) -> Result<P, Error> {
        let vendor_id = request.vendor_id()?;
        let product_id = request.product_id()?;
        let current_version = request.software_version()?;
        // Absent means the requestor cannot obtain user consent on its own.
        let requestor_can_consent = request.requestor_can_consent()?.unwrap_or(false);

        let mut designator_buf = [0u8; MAX_FILE_DESIGNATOR];
        let image = match self
            .images
            .query(
                vendor_id,
                product_id,
                current_version,
                requestor_can_consent,
                &mut designator_buf,
            )
            .await
        {
            OtaQueryOutcome::Available(image) => image,
            // The provider may have an update but isn't ready (e.g. consent
            // pending); tell the requestor to retry the same provider later.
            OtaQueryOutcome::Busy { delay_secs } => {
                return response
                    .status(StatusEnum::Busy)?
                    .delayed_action_time(Some(delay_secs))?
                    .image_uri(None)?
                    .software_version(None)?
                    .software_version_string(None)?
                    .update_token(None)?
                    .user_consent_needed(None)?
                    .metadata_for_requestor(None)?
                    .end();
            }
            // No applicable image (already up to date).
            OtaQueryOutcome::NotAvailable => {
                return response
                    .status(StatusEnum::NotAvailable)?
                    .delayed_action_time(None)?
                    .image_uri(None)?
                    .software_version(None)?
                    .software_version_string(None)?
                    .update_token(None)?
                    .user_consent_needed(None)?
                    .metadata_for_requestor(None)?
                    .end();
            }
        };

        // The download URI points at this node (on the accessing fabric) and
        // carries the file designator as its path.
        let fab_idx = NonZeroU8::new(ctx.cmd().fab_idx).ok_or(ErrorCode::Invalid)?;
        let node_id = ctx
            .exchange()
            .with_state(|state| Ok(state.fabrics.fabric(fab_idx)?.node_id()))?;

        let mut uri = heapless::String::<200>::new();
        write!(uri, "bdx://{:016X}/{}", node_id, image.file_designator)
            .map_err(|_| ErrorCode::NoSpace)?;

        let mut version_str = heapless::String::<16>::new();
        write!(version_str, "{}", image.version).map_err(|_| ErrorCode::NoSpace)?;

        // The registry owns the (opaque) update token; enforce the spec's bound.
        if !UPDATE_TOKEN_LEN.contains(&image.update_token.len()) {
            return Err(ErrorCode::ConstraintError.into());
        }

        response
            .status(StatusEnum::UpdateAvailable)?
            .delayed_action_time(None)?
            .image_uri(Some(uri.as_str()))?
            .software_version(Some(image.version))?
            .software_version_string(Some(version_str.as_str()))?
            .update_token(Some(Octets(image.update_token)))?
            // Consent policy is the registry's; forward its decision verbatim.
            .user_consent_needed(Some(image.user_consent_needed))?
            .metadata_for_requestor(None)?
            .end()
    }

    async fn handle_apply_update_request<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        request: ApplyUpdateRequestRequest<'_>,
        response: ApplyUpdateResponseBuilder<P>,
    ) -> Result<P, Error> {
        let update_token = request.update_token()?;
        let new_version = request.new_version()?;

        // The registry owns apply policy (e.g. deferring until consent is granted).
        let (action, delay) = match self.images.apply(update_token.0, new_version).await {
            OtaApplyOutcome::Proceed { delay_secs } => (ApplyUpdateActionEnum::Proceed, delay_secs),
            OtaApplyOutcome::Await { delay_secs } => {
                (ApplyUpdateActionEnum::AwaitNextAction, delay_secs)
            }
            OtaApplyOutcome::Discontinue => (ApplyUpdateActionEnum::Discontinue, 0),
        };

        response.action(action)?.delayed_action_time(delay)?.end()
    }

    async fn handle_notify_update_applied(
        &self,
        _ctx: impl InvokeContext,
        _request: NotifyUpdateAppliedRequest<'_>,
    ) -> Result<(), Error> {
        // Stateless provider: nothing to clean up.
        Ok(())
    }
}

/// A [`BdxHandler`] that serves OTA images. Wrap it in a [`Bdx`](crate::bdx::Bdx)
/// handler and chain that into your responder for the BDX protocol, so requestors
/// can download the image advertised by the OTA Provider cluster's `QueryImage`
/// response.
///
/// Given the exchange handler for the rest of your protocols (e.g. the default
/// Interaction Model + Secure Channel chain), add BDX with
/// [`ExchangeHandler::chain`](crate::respond::ExchangeHandler::chain):
///
/// ```ignore
/// use rs_matter::bdx::{Bdx, PROTO_ID_BDX};
/// use rs_matter::dm::clusters::ota_provider::BdxBuffer;
/// use rs_matter::respond::Responder;
/// use rs_matter::utils::storage::pooled::PooledBuffers;
///
/// // One staging buffer per concurrent download (here: two).
/// let buffers = PooledBuffers::<2, BdxBuffer>::new(0);
/// let bdx = Bdx::new(OtaBdxHandler::new(&buffers, &images));
/// let handler = im_and_sc_handler.chain(PROTO_ID_BDX, bdx);
/// let responder = Responder::new("ota-provider", handler, matter, 0);
/// ```
pub struct OtaBdxHandler<B, I> {
    buffers: B,
    images: I,
}

impl<B, I> OtaBdxHandler<B, I> {
    /// Create a new BDX image handler backed by the given image data source.
    ///
    /// `buffers` is a [`BufferAccess`] pool ([`BdxBuffer`]-sized): one buffer is
    /// leased per in-flight download to stage the BDX blocks (the image bytes are
    /// read straight into it), so the pool's size caps how many downloads run
    /// concurrently. When the pool is exhausted, further downloads are rejected
    /// with [`ResponderBusy`](BdxStatus::ResponderBusy).
    pub const fn new(buffers: B, images: I) -> Self {
        Self { buffers, images }
    }
}

impl<B, I: OtaImages> OtaBdxHandler<B, I> {
    /// Fill `buf` from the image `fd` starting at `offset`, looping until it is
    /// full or the image ends, so that only the final block of a transfer is ever
    /// short. Returns the number of bytes read (`< buf.len()` only at end-of-image).
    async fn fill(&self, fd: &[u8], offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let mut filled = 0;

        while filled < buf.len() {
            // `checked_add`: a buggy `OtaImages::size` could let a peer's
            // start offset sit near `u64::MAX`, where `offset + filled` overflows.
            let read_offset = offset
                .checked_add(filled as u64)
                .ok_or(ErrorCode::Invalid)?;
            let n = self
                .images
                .read(fd, read_offset, &mut buf[filled..])
                .await?;
            if n == 0 {
                break;
            }
            // Guard a misbehaving `OtaImages::read` that reports reading more than
            // the slice it was handed - otherwise `filled` overruns `buf` and the
            // next `&mut buf[filled..]` panics.
            if n > buf.len() - filled {
                return Err(ErrorCode::Invalid.into());
            }

            filled += n;
        }

        Ok(filled)
    }
}

impl<B, I> BdxHandler for OtaBdxHandler<B, I>
where
    B: BufferAccess<BdxBuffer>,
    I: OtaImages,
{
    async fn handles(&self, responder: &BdxResponder<'_>) -> bool {
        // We only serve downloads, and only of images we actually have.
        matches!(responder, BdxResponder::Download(_))
            && self.images.size(responder.fd()).await.is_some()
    }

    async fn handle(&self, responder: BdxResponder<'_>) -> Result<(), Error> {
        // We only handle downloads; anything else is rejected.
        let responder = match responder {
            BdxResponder::Download(responder) => responder,
            other => return other.reject(BdxStatus::FileDesignatorUnknown).await,
        };

        // Copy the requested designator out (the held init is released by
        // `reply`/`reject`), and reject anything we don't have.
        let mut fd = heapless::Vec::<u8, MAX_FILE_DESIGNATOR>::new();
        if fd.extend_from_slice(responder.fd()).is_err() {
            return responder.reject(BdxStatus::FileDesignatorUnknown).await;
        }

        let Some(size) = self.images.size(&fd).await else {
            return responder.reject(BdxStatus::FileDesignatorUnknown).await;
        };

        // Honor a requested resume offset: send from there, advertising only the
        // remaining bytes. An offset past the end cannot be served.
        let start_offset = responder.start_offset();
        if start_offset > size {
            return responder.reject(BdxStatus::StartOffsetNotSupported).await;
        }
        let remaining = size - start_offset;

        // Lease a staging buffer for the duration of this transfer; if the pool is
        // exhausted, tell the peer we are busy so it can retry later.
        let Some(mut buf) = self.buffers.get().await else {
            return responder.reject(BdxStatus::ResponderBusy).await;
        };

        // Expose the whole buffer as the writer's block-staging slice (its length
        // caps the block size, which the BDX layer further clamps to the TX limit).
        unwrap!(buf.resize_default(MAX_EXCHANGE_RX_BUF_SIZE));

        // Hand it to the writer, which sends each block straight out of it - the
        // image bytes are read directly into the writer's block buffer, no copy.
        let mut writer = responder.reply(buf.as_mut_slice(), Some(remaining)).await?;

        let mut offset = start_offset;

        loop {
            let n = self.fill(&fd, offset, writer.block_buf()).await?;
            if n == 0 {
                break;
            }

            writer.commit(n).await?;

            offset += n as u64;
        }

        writer.finish().await
    }
}
