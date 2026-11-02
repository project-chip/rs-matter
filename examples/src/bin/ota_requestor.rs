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

//! An example Matter device that acts as an OTA Software Update Requestor.
//!
//! It hosts the OTA Requestor cluster (so a Commissioner can populate its
//! `DefaultOTAProviders` list or send `AnnounceOTAProvider`) and runs an
//! application-defined update loop built from the cluster's building blocks:
//! [`Providers::wait_changed`] to react to changes, [`Provider::query`] to ask a
//! provider for an update, [`parse_bdx_url`] + [`Exchange::download`] to download it
//! over BDX, [`OtaImageHeader::load`] to read the image's header, and
//! [`OtaState`] to report progress.
//!
//! The loop lives in the `run` method of a handler that serves no cluster
//! ([`OtaUpdater`]), chained next to the OTA Requestor cluster. `run` receives
//! everything the loop needs from the Interaction Model: crypto, the KV store,
//! and the notification of attribute changes and events. The same recipe fits
//! any background job that needs these.
//!
//! The image is checked (header, payload size and digest) but not installed; a
//! real device writes the payload to a spare slot and reboots into it.

use core::future::Future;
use core::pin::pin;

use log::{info, warn};

use rand::rngs::StdRng;
use rand::Rng;

use rs_matter::bdx::BdxDownloadInitiator;
use rs_matter::crypto::{default_crypto, Crypto, CryptoSensitive, Digest};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::ota_prov::{DownloadProtocolEnum, OtaApplyOutcome, StatusEnum};
use rs_matter::dm::clusters::ota_req::{
    parse_bdx_url, ClusterHandler as _, OtaRequestorHandler, OtaState, Provider, Providers,
};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_OTA_REQUESTOR;
use rs_matter::dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::{
    Async, DataModel, Dataver, EmptyHandler, Endpoint, Handler, HandlerContext, MatchContext, Node,
    NonBlockingHandler, ReadContext, ReadReply,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::ota::{OtaImageHeader, OTA_IMAGE_DIGEST_SHA256};
use rs_matter::persist::DirKvBlobStore;
use rs_matter::sc::ExchangeInitiator as _;
use rs_matter::transport::exchange::Exchange;
use rs_matter::utils::futures::select;
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::sync::{IfMutex, MaybeSend};
use rs_matter::utils::timers::{Duration, Timer};
use rs_matter::{clusters, devices, root_endpoint, Matter};

use rs_matter::stack::eth::EthMatterStack;
use rs_matter::stack::net::std::StdNetStack;

use static_cell::StaticCell;

#[path = "../common/mdns.rs"]
mod mdns;

/// How often the update loop polls its providers when otherwise idle (an hour).
/// A `DefaultOTAProviders` write or an `AnnounceOTAProvider` command wakes it
/// sooner via [`Providers::wait_changed`].
const POLL_INTERVAL: Duration = Duration::from_secs(3600);

/// The download protocols this requestor supports (BDX only, here).
const PROTOCOLS: &[DownloadProtocolEnum] = &[DownloadProtocolEnum::BDXSynchronous];

/// The longest image URI this device takes.
const MAX_URI_LEN: usize = 256;

/// The longest update token, per the OTA Software Update Provider cluster.
const MAX_TOKEN_LEN: usize = 32;

/// Enough to hold the header of any valid image.
const MAX_HEADER_LEN: usize = 512;

/// The size of the chunks the image payload is read in.
const CHUNK_LEN: usize = 1024;

/// The size of the buffers of the update loop.
const SCRATCH_LEN: usize = MAX_URI_LEN + MAX_TOKEN_LEN + MAX_HEADER_LEN + CHUNK_LEN;

/// The bump allocator size of the stack, in bytes.
///
/// If it is not enough, the stack panics while it starts. The futures of an
/// unoptimized build are much bigger than those of an optimized one.
const BUMP_SIZE: usize = 36 * 1024;

/// The stack is allocated statically to avoid program stack blowups.
static MATTER_STACK: StaticCell<EthMatterStack<BUMP_SIZE, ()>> = StaticCell::new();

/// The buffers of the update loop, kept out of its future.
static OTA_SCRATCH: StaticCell<IfMutex<[u8; SCRATCH_LEN]>> = StaticCell::new();

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let stack = MATTER_STACK.uninit().init_with(EthMatterStack::init(
        &TEST_DEV_DET,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
    ));

    // Persistence
    let mut store = DirKvBlobStore::new_default();

    // Create the crypto instance
    let crypto = default_crypto(rand::make_rng::<StdRng>(), DAC_PRIVKEY);

    let rand = crypto.rand()?;

    // Re-hydrate the persisted state. If the device is not commissioned yet, this also
    // prints the QR text and code to the console and enables basic commissioning.
    futures_lite::future::block_on(stack.startup(&crypto, &mut store))?;

    // Bind the KV access object (the KV scratch buffer lives in `Matter`).
    let kv = stack.kv(store);

    // The OTA Requestor's transient, reported update state, for the cluster on endpoint 1
    // (see `NODE`).
    let ota_state = OtaState::new(1);

    // The OTA Requestor's persistent provider list, re-hydrated by the cluster on startup.
    let providers = Providers::new();

    let scratch = OTA_SCRATCH.init(IfMutex::new([0; SCRATCH_LEN]));

    // Run the stack, which adds the operational network clusters of endpoint 0 by itself
    let matter = pin!(stack.run_preex(
        // The UDP sockets of the node
        StdNetStack::new(),
        // The network interfaces of the host
        SysNetifs,
        // No Ethernet diagnostics to report
        &(),
        mdns::create_mdns(),
        &crypto,
        data_model(stack.matter(), rand, &providers, &ota_state, scratch),
        kv,
        // No user task to run
        (),
    ));

    // Run with a simple `block_on`. Any local executor would do.
    futures_lite::future::block_on(matter)
}

/// The Node meta-data: a root node plus an OTA Requestor endpoint.
const NODE: Node<'static> = Node {
    endpoints: &[
        root_endpoint!(eth),
        Endpoint::new(
            1,
            devices!(DEV_TYPE_OTA_REQUESTOR),
            clusters!(desc::DescHandler::CLUSTER, OtaRequestorHandler::CLUSTER),
        ),
    ],
};

/// The Data Model handler: the root endpoint 0 handler, the OTA Requestor cluster
/// (and its descriptor) on endpoint 1, and the update loop.
fn data_model<'a>(
    matter: &'a Matter<'a>,
    mut rand: impl Rng + Copy,
    providers: &'a Providers,
    ota_state: &'a OtaState,
    scratch: &'a IfMutex<[u8; SCRATCH_LEN]>,
) -> impl DataModel + 'a {
    (
        NODE,
        EmptyHandler
            .chain(
                |e, _| e == ROOT_ENDPOINT_ID,
                Async(EthMatterStack::<0, ()>::root_handler(matter, &(), rand)),
            )
            .chain(
                |e, c| e == 1 && c == desc::DescHandler::CLUSTER.id,
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                |e, c| e == 1 && c == OtaRequestorHandler::CLUSTER.id,
                Async(
                    OtaRequestorHandler::new(
                        Dataver::new_rand(&mut rand),
                        matter,
                        providers,
                        ota_state,
                    )
                    .adapt(),
                ),
            )
            // It serves no cluster, so it matches nothing; only its `run` matters.
            .chain(
                |_, _| false,
                Async(OtaUpdater {
                    matter,
                    providers,
                    state: ota_state,
                    scratch,
                }),
            ),
    )
}

/// The application's OTA update loop, as a handler that only has a `run` method.
///
/// `run` must not return, as that would stop the node, so a failed update is only
/// logged. It also restarts whenever the Interaction Model is rebuilt, which the
/// stack does when it switches the radio between BLE and the operational network.
/// So everything it needs across a restart lives outside of its future.
struct OtaUpdater<'a> {
    matter: &'a Matter<'a>,
    providers: &'a Providers,
    state: &'a OtaState,
    scratch: &'a IfMutex<[u8; SCRATCH_LEN]>,
}

impl OtaUpdater<'_> {
    /// Whenever the provider set changes (or periodically), try each known provider
    /// until one yields an applied update.
    async fn run_updates(&self, ctx: impl HandlerContext) -> Result<(), Error> {
        let mut scratch = self.scratch.lock().await;

        loop {
            // React to provider-set changes (a `DefaultOTAProviders` write or an
            // `AnnounceOTAProvider` command), or poll periodically.
            select(self.providers.wait_changed(), Timer::after(POLL_INTERVAL)).await;

            // Try the configured defaults first, then the transient announced ones.
            // Drain the announced set up front (one-shot hints): anything announced
            // while this pass is busy is preserved for the next pass, not lost to a
            // trailing clear.
            let n_default = self.providers.len();
            let announced = self.providers.take_announced();

            let defaults = (0..n_default).filter_map(|i| self.providers.get(i));
            for provider in defaults.chain(announced.iter().copied()) {
                match self.try_update(&ctx, &provider, &mut *scratch).await {
                    Ok(true) => info!("OTA: update applied"),
                    Ok(false) => {}
                    Err(e) => warn!("OTA: provider 0x{:016x} failed: {e:?}", provider.node_id),
                }
            }
        }
    }

    /// Query a single provider and, if it offers a newer image, download and "apply"
    /// it. Returns `Ok(true)` if an update was applied.
    async fn try_update(
        &self,
        ctx: &impl HandlerContext,
        provider: &Provider,
        scratch: &mut [u8],
    ) -> Result<bool, Error> {
        let matter = self.matter;

        let dev = matter.dev_det();

        let (uri_buf, scratch) = scratch.split_at_mut(MAX_URI_LEN);
        let (token_buf, scratch) = scratch.split_at_mut(MAX_TOKEN_LEN);
        let (header_buf, chunk_buf) = scratch.split_at_mut(MAX_HEADER_LEN);

        // Report progress for the duration of this attempt; if we bail out (or error)
        // the session reverts the reported state to `Idle` on drop.
        let update = self.state.initiate_update(ctx);
        update.querying();

        // Ask the provider. The closure inspects the response off the RX buffer and
        // copies out just the image URI (the response is gone once `query` returns).
        // This headless example has no UI to prompt a user, so it cannot consent.
        let found = provider
            .query(
                matter,
                ctx.crypto(),
                PROTOCOLS,
                Some(dev.sw_ver),
                false,
                |resp| {
                    let available = resp.status()? == StatusEnum::UpdateAvailable;
                    let Some(version) = resp.software_version()? else {
                        return Ok(None);
                    };
                    if !available || version <= dev.sw_ver {
                        return Ok(None);
                    }

                    // Copy out the image URI and the update token (both borrow the RX
                    // buffer, which is gone once `query` returns). The token is opaque and
                    // must be echoed back on ApplyUpdateRequest / NotifyUpdateApplied.
                    let uri = resp.image_uri()?.ok_or(ErrorCode::InvalidData)?.as_bytes();
                    uri_buf
                        .get_mut(..uri.len())
                        .ok_or(ErrorCode::NoSpace)?
                        .copy_from_slice(uri);

                    let token = resp.update_token()?.ok_or(ErrorCode::InvalidData)?.0;
                    token_buf
                        .get_mut(..token.len())
                        .ok_or(ErrorCode::NoSpace)?
                        .copy_from_slice(token);

                    Ok(Some((version, uri.len(), token.len())))
                },
            )
            .await?;

        let Some((version, uri_len, token_len)) = found else {
            return Ok(false);
        };
        update.set_target_version(version);
        let update_token = &token_buf[..token_len];

        let uri = core::str::from_utf8(&uri_buf[..uri_len]).map_err(|_| ErrorCode::InvalidData)?;
        let (node_id, fd) = parse_bdx_url(uri)?;

        info!("OTA: downloading version {version} from node 0x{node_id:016x} ({fd})");
        update.downloading(Some(0));

        // Download the image over BDX from the node named in the URL.
        let exchange = Exchange::initiate(matter, ctx.crypto(), provider.fab_idx, node_id).await?;
        let mut reader = exchange.download(fd.as_bytes(), None).await?;

        // Check the header before taking any of the payload.
        let header = OtaImageHeader::load(&mut reader, header_buf).await?;

        if !header.is_for_product(dev.vid, dev.pid)
            || header.software_version != version
            || !header.is_update_for(dev.sw_ver)
            || header.image_digest_type != OTA_IMAGE_DIGEST_SHA256
        {
            warn!("OTA: the downloaded image is not the offered update for this device");
            return Ok(false);
        }

        // Take the payload, hashing it on the way.
        let crypto = ctx.crypto();
        let mut hasher = crypto.hash()?;
        let mut received = 0u64;

        while received < header.payload_size {
            let len = (header.payload_size - received).min(chunk_buf.len() as u64) as usize;
            let n = reader.read(&mut chunk_buf[..len]).await?;
            if n == 0 {
                // The transfer ended before the payload did.
                return Err(ErrorCode::InvalidData.into());
            }

            // A real device writes `&chunk_buf[..n]` to a spare firmware slot here.
            hasher.update(&chunk_buf[..n])?;
            received += n as u64;

            // `u128` so an absurd `PayloadSize` can't overflow.
            update.downloading(Some(
                (received as u128 * 100 / header.payload_size as u128) as u8,
            ));
        }

        // Nothing may follow the payload; reading to the end completes the transfer.
        if reader.read(chunk_buf).await? != 0 {
            return Err(ErrorCode::InvalidData.into());
        }

        // Only a payload matching its digest may be applied.
        let mut digest = CryptoSensitive::new();
        hasher.finish(&mut digest)?;
        if digest.access().as_slice() != header.image_digest.0 {
            warn!("OTA: the downloaded payload does not match its digest; discarding");
            return Ok(false);
        }

        info!("OTA: downloaded {received} bytes of payload, digest OK");

        // Ask the provider for permission to apply (its consent / scheduling gate).
        match provider
            .apply_update(matter, ctx.crypto(), update_token, version)
            .await?
        {
            OtaApplyOutcome::Proceed { delay_secs } => {
                if delay_secs > 0 {
                    info!("OTA: provider asked to wait {delay_secs}s before applying");
                    // A real device would wait `delay_secs` before applying.
                }
            }
            OtaApplyOutcome::Await { delay_secs } => {
                info!("OTA: apply deferred by provider ({delay_secs}s); will retry later");
                return Ok(false);
            }
            OtaApplyOutcome::Discontinue => {
                info!("OTA: provider rescinded the image; discarding");
                return Ok(false);
            }
        }

        info!("OTA: applying version {version}");
        update.applying();

        // A real device does not notify here. It saves the provider, the token and the
        // version, restarts into the new image, confirms the image once it is healthy,
        // and only then notifies. This example does not restart, so it notifies right away.
        provider
            .notify_applied(matter, ctx.crypto(), update_token, version)
            .await?;

        update.complete();

        Ok(true)
    }
}

impl Handler for OtaUpdater<'_> {
    fn read(&self, _ctx: impl ReadContext, _reply: impl ReadReply) -> Result<(), Error> {
        Err(ErrorCode::AttributeNotFound.into())
    }

    fn bump_dataver(&self, _ctx: impl MatchContext) {}

    fn run(&self, ctx: impl HandlerContext) -> impl Future<Output = Result<(), Error>> + MaybeSend {
        self.run_updates(ctx)
    }
}

impl NonBlockingHandler for OtaUpdater<'_> {}
