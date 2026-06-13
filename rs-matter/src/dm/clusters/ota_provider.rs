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

//! The OTA Software Update Provider cluster, plus a BDX server that streams the
//! offered image to requestors.
//!
//! The node hosts the OTA Provider cluster (server role): it answers
//! `QueryImage` with the location of a newer image (a `bdx://` URI), authorizes
//! the apply via `ApplyUpdateRequest`, and notes completion via
//! `NotifyUpdateApplied`. The image bytes are served over BDX by
//! [`OtaBdxServer`], a [`BdxServer`] that the application wraps in a
//! [`Bdx`](crate::bdx::Bdx) handler and chains into its responder for the BDX
//! protocol. Both delegate to a user-supplied [`OtaImages`] catalogue.

use core::fmt::Write as _;
use core::num::NonZeroU8;

use crate::bdx::{BdxPullResponder, BdxServer, BdxStatus};
use crate::dm::{Cluster, Dataver, InvokeContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::{Octets, TLVBuilderParent};
use crate::with;

pub use crate::dm::clusters::decl::ota_software_update_provider::*;

/// The largest BDX block the server will send over a non-TCP transport.
const MAX_BLOCK_SIZE: usize = 1024;

/// The maximum supported BDX file designator length.
const MAX_FILE_DESIGNATOR: usize = 128;

/// A descriptor for an OTA image that a provider is willing to serve.
pub struct OtaImage<'a> {
    /// The version of the offered image. Must be newer than the requestor's.
    pub version: u32,
    /// The BDX file designator that identifies this image when downloaded.
    pub file_designator: &'a str,
    /// The total image size in bytes, if known (enables a definite-length
    /// transfer and download-progress reporting on the requestor).
    pub size: Option<u64>,
}

/// A device-specific catalogue of OTA images served to requestors.
pub trait OtaImages {
    /// Decide whether an image strictly newer than `current_version` is
    /// available for the querying `(vendor_id, product_id)`, returning its
    /// descriptor if so.
    fn query(&self, vendor_id: u16, product_id: u16, current_version: u32) -> Option<OtaImage<'_>>;

    /// The total size of the image identified by `file_designator`. `None` means
    /// the designator is unknown and the BDX transfer is rejected
    /// (`FileDesignatorUnknown`).
    fn size(&self, file_designator: &[u8]) -> Option<u64>;

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

/// The server-side handler for the OTA Software Update Provider cluster.
pub struct OtaProviderHandler<'a, I> {
    dataver: Dataver,
    images: &'a I,
}

impl<'a, I> OtaProviderHandler<'a, I> {
    /// Create a new handler backed by the given image catalogue.
    pub const fn new(dataver: Dataver, images: &'a I) -> Self {
        Self { dataver, images }
    }

    /// Adapt this handler to the generic `rs-matter` `Handler` trait.
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl<I: OtaImages> ClusterHandler for OtaProviderHandler<'_, I> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn handle_query_image<P: TLVBuilderParent>(
        &self,
        ctx: impl InvokeContext,
        request: QueryImageRequest<'_>,
        response: QueryImageResponseBuilder<P>,
    ) -> Result<P, Error> {
        let vendor_id = request.vendor_id()?;
        let product_id = request.product_id()?;
        let current_version = request.software_version()?;

        let Some(image) = self.images.query(vendor_id, product_id, current_version) else {
            // No applicable image (already up to date).
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

        response
            .status(StatusEnum::UpdateAvailable)?
            .delayed_action_time(None)?
            .image_uri(Some(uri.as_str()))?
            .software_version(Some(image.version))?
            .software_version_string(Some(version_str.as_str()))?
            // The update token is opaque to the requestor; the file designator
            // (which the requestor sends back on the BDX transfer) suffices.
            .update_token(Some(Octets(image.file_designator.as_bytes())))?
            .user_consent_needed(Some(false))?
            .metadata_for_requestor(None)?
            .end()
    }

    fn handle_apply_update_request<P: TLVBuilderParent>(
        &self,
        _ctx: impl InvokeContext,
        _request: ApplyUpdateRequestRequest<'_>,
        response: ApplyUpdateResponseBuilder<P>,
    ) -> Result<P, Error> {
        // Authorize the requestor to apply the update immediately.
        response
            .action(ApplyUpdateActionEnum::Proceed)?
            .delayed_action_time(0)?
            .end()
    }

    fn handle_notify_update_applied(
        &self,
        _ctx: impl InvokeContext,
        _request: NotifyUpdateAppliedRequest<'_>,
    ) -> Result<(), Error> {
        // Stateless provider: nothing to clean up.
        Ok(())
    }
}

/// A [`BdxServer`] that serves OTA images. Wrap it in a [`Bdx`](crate::bdx::Bdx)
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
/// use rs_matter::respond::Responder;
///
/// let bdx = Bdx::new(OtaBdxServer::new(&images));
/// let handler = im_and_sc_handler.chain(PROTO_ID_BDX, bdx);
/// let responder = Responder::new("ota-provider", handler, matter, 0);
/// ```
pub struct OtaBdxServer<'a, I> {
    images: &'a I,
}

impl<'a, I> OtaBdxServer<'a, I> {
    /// Create a new BDX image server backed by the given catalogue.
    pub const fn new(images: &'a I) -> Self {
        Self { images }
    }
}

impl<I: OtaImages> BdxServer for OtaBdxServer<'_, I> {
    fn serves(&self, fd: &[u8]) -> bool {
        self.images.size(fd).is_some()
    }

    async fn serve(&self, responder: BdxPullResponder<'_>) -> Result<(), Error> {
        // Copy the requested designator out (the held init is released by
        // `reply`/`reject`), and reject anything we don't have.
        let mut fd = heapless::Vec::<u8, MAX_FILE_DESIGNATOR>::new();
        if fd.extend_from_slice(responder.fd()).is_err() {
            return responder.reject(BdxStatus::FileDesignatorUnknown).await;
        }

        let Some(size) = self.images.size(&fd) else {
            return responder.reject(BdxStatus::FileDesignatorUnknown).await;
        };

        // Accept (advertising the definite length) and stream the image. The
        // writer stages each block in `wbuf`; `buf` holds the chunk read from the
        // image source before it is handed to the writer.
        let mut wbuf = [0u8; MAX_BLOCK_SIZE];
        let mut writer = responder.reply(&mut wbuf, Some(size)).await?;

        let mut buf = [0u8; MAX_BLOCK_SIZE];
        let mut offset = 0u64;

        loop {
            let n = self.images.read(&fd, offset, &mut buf).await?;
            if n == 0 {
                break;
            }

            let mut chunk = &buf[..n];
            while !chunk.is_empty() {
                let written = writer.write(chunk).await?;
                chunk = &chunk[written..];
            }

            offset += n as u64;
        }

        writer.finish().await
    }
}
