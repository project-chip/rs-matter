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
//! over BDX, and [`OtaState`] to report progress.
//!
//! The image handling is stubbed out (the downloaded bytes are just counted). A
//! real device would write them to a spare firmware slot and reboot into it.

use core::pin::pin;

use std::net::UdpSocket;

use embassy_futures::select::{select, select4};
use embassy_time::{Duration, Timer};

use log::{info, warn};

use rand::RngCore;

use rs_matter::bdx::BdxDownloadInitiator;
use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::desc::{self, ClusterHandler as _};
use rs_matter::dm::clusters::ota_prov::{DownloadProtocolEnum, OtaApplyOutcome, StatusEnum};
use rs_matter::dm::clusters::ota_req::{
    parse_bdx_url, ClusterHandler as _, OtaRequestorHandler, OtaState, Provider, Providers,
};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::dm::devices::DEV_TYPE_OTA_REQUESTOR;
use rs_matter::dm::endpoints;
use rs_matter::dm::networks::eth::EthNetwork;
use rs_matter::dm::networks::SysNetifs;
use rs_matter::dm::IMBuffer;
use rs_matter::dm::{
    Async, AttrChangeNotifier, DataModel, DataModelHandler, Dataver, Endpoint, EpClMatcher,
    EthDataModelState, Node,
};
use rs_matter::error::{Error, ErrorCode};
use rs_matter::pairing::qr::QrTextType;
use rs_matter::pairing::DiscoveryCapabilities;
use rs_matter::persist::{DirKvBlobStore, SharedKvBlobStore};
use rs_matter::respond::DefaultResponder;
use rs_matter::sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::MATTER_SOCKET_BIND_ADDR;
use rs_matter::utils::select::Coalesce;
use rs_matter::utils::storage::pooled::PooledBuffers;
use rs_matter::{clusters, devices, root_endpoint, Matter, MATTER_PORT};

#[path = "../common/mdns.rs"]
mod mdns;

/// The currently running software version of this device. Only strictly newer
/// images are downloaded.
const SOFTWARE_VERSION: u32 = 1;

/// How often the update loop polls its providers when otherwise idle (an hour).
/// A `DefaultOTAProviders` write or an `AnnounceOTAProvider` command wakes it
/// sooner via [`Providers::wait_changed`].
const POLL_INTERVAL: Duration = Duration::from_secs(3600);

/// The download protocols this requestor supports (BDX only, here).
const PROTOCOLS: &[DownloadProtocolEnum] = &[DownloadProtocolEnum::BDXSynchronous];

fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug"),
    );

    let mut matter = Matter::new(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, MATTER_PORT);

    // Persistence
    let mut kv_buf = [0u8; 4096];
    let mut kv = DirKvBlobStore::new_default();
    futures_lite::future::block_on(matter.load_persist(&mut kv, &mut kv_buf))?;

    // The OTA Requestor's persistent provider list, re-hydrated from storage.
    let providers = Providers::new();
    futures_lite::future::block_on(providers.load_persist(&mut kv, &mut kv_buf))?;

    // The OTA Requestor's transient, reported update state, for the cluster on
    // endpoint 1 (see `NODE`). State changes are pushed to subscribers via the
    // data model's change-notifier (the `DataModel`, passed to the OTA loop below).
    let ota_state = OtaState::new(1);

    let buffers = PooledBuffers::<10, IMBuffer>::new(0);

    // Create the data model state (subscriptions, events, network store) and load
    // the persisted event counter.
    let mut state: EthDataModelState = EthDataModelState::new(EthNetwork::new_default());
    futures_lite::future::block_on(state.load_persist(&mut kv, &mut kv_buf))?;

    let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);

    let rand = crypto.rand()?;

    let dm = DataModel::new(
        &matter,
        &crypto,
        &buffers,
        dm_handler(rand, &providers, &ota_state),
        SharedKvBlobStore::new(kv, kv_buf),
        &state,
    );

    let responder = DefaultResponder::new(&dm);
    let mut respond = pin!(responder.run::<4, 4>());
    let mut dm_job = pin!(dm.run());

    let socket = async_io::Async::<UdpSocket>::bind(MATTER_SOCKET_BIND_ADDR)?;

    let mut mdns = pin!(mdns::run_mdns(&matter, &crypto));
    let mut transport = pin!(matter.run(&crypto, &socket, &socket, &socket));

    // The application's OTA update loop, built from the cluster's building blocks.
    // The OTA loop shares the same crypto by reference (`&T: Crypto`), initiating
    // its own CASE exchanges to the provider.
    let ota_job = pin!(run_ota(&matter, &crypto, &providers, &ota_state, &dm));

    if !matter.is_commissioned() {
        matter.print_standard_qr_text(DiscoveryCapabilities::IP)?;
        matter.print_standard_qr_code(QrTextType::Unicode, DiscoveryCapabilities::IP)?;

        matter.open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, &crypto, &())?;
    }

    // Combine the Matter stack (transport, mDNS, responder, data model) with the
    // OTA loop into a single task.
    let matter_job = select4(&mut transport, &mut mdns, &mut respond, &mut dm_job).coalesce();
    let all = select(matter_job, ota_job).coalesce();

    futures_lite::future::block_on(all)
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

/// The Data Model handler: the root endpoint 0 handler plus the OTA Requestor
/// cluster (and its descriptor) on endpoint 1.
fn dm_handler<'a>(
    mut rand: impl RngCore + Copy,
    providers: &'a Providers,
    ota_state: &'a OtaState,
) -> impl DataModelHandler + 'a {
    (
        NODE,
        endpoints::EthSysHandlerBuilder::new()
            .netif_diag(&SysNetifs)
            .build(rand)
            .chain(
                EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
                Async(desc::DescHandler::new(Dataver::new_rand(&mut rand)).adapt()),
            )
            .chain(
                EpClMatcher::new(Some(1), Some(OtaRequestorHandler::CLUSTER.id)),
                Async(
                    OtaRequestorHandler::new(Dataver::new_rand(&mut rand), providers, ota_state)
                        .adapt(),
                ),
            ),
    )
}

/// The application's OTA update loop: whenever the provider set changes (or
/// periodically), try each known provider until one yields an applied update.
async fn run_ota(
    matter: &Matter<'_>,
    crypto: impl Crypto,
    providers: &Providers,
    ota_state: &OtaState,
    notifier: &dyn AttrChangeNotifier,
) -> Result<(), Error> {
    loop {
        // React to provider-set changes (a `DefaultOTAProviders` write or an
        // `AnnounceOTAProvider` command), or poll periodically.
        select(providers.wait_changed(), Timer::after(POLL_INTERVAL)).await;

        // Try the configured defaults first, then the transient announced ones.
        // Drain the announced set up front (one-shot hints): anything announced
        // while this pass is busy is preserved for the next pass, not lost to a
        // trailing clear.
        let n_default = providers.len();
        let announced = providers.take_announced();

        let defaults = (0..n_default).filter_map(|i| providers.get(i));
        for provider in defaults.chain(announced.iter().copied()) {
            match try_update(matter, &crypto, &provider, ota_state, notifier).await {
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
    matter: &Matter<'_>,
    crypto: &impl Crypto,
    provider: &Provider,
    ota_state: &OtaState,
    notifier: &dyn AttrChangeNotifier,
) -> Result<bool, Error> {
    // Report progress for the duration of this attempt; if we bail out (or error)
    // the session reverts the reported state to `Idle` on drop.
    let update = ota_state.initiate_update(notifier);
    update.querying();

    // Ask the provider. The closure inspects the response off the RX buffer and
    // copies out just the image URI (the response is gone once `query` returns).
    let mut uri_buf = [0u8; 256];
    let mut token_buf = [0u8; 32];
    // This headless example has no UI to prompt a user, so it cannot consent.
    let found = provider
        .query(
            matter,
            crypto,
            PROTOCOLS,
            Some(SOFTWARE_VERSION),
            false,
            |resp| {
                let available = resp.status()? == StatusEnum::UpdateAvailable;
                let Some(version) = resp.software_version()? else {
                    return Ok(None);
                };
                if !available || version <= SOFTWARE_VERSION {
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
    let update_token = &token_buf[..token_len];

    let uri = core::str::from_utf8(&uri_buf[..uri_len]).map_err(|_| ErrorCode::InvalidData)?;
    let (node_id, fd) = parse_bdx_url(uri)?;

    info!("OTA: downloading version {version} from node 0x{node_id:016x} ({fd})");
    update.downloading(Some(0));

    // Download the image over BDX from the node named in the URL.
    let exchange = Exchange::initiate(matter, crypto, provider.fab_idx, node_id).await?;
    let mut reader = exchange.download(fd.as_bytes(), None).await?;

    let total = reader.len();
    let mut received = 0u64;
    let mut buf = [0u8; 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        // A real device writes `&buf[..n]` to a spare firmware slot here.
        received += n as u64;

        if let Some(total) = total.filter(|t| *t > 0) {
            // `u128` so an absurd provider-advertised `total` can't overflow.
            update.downloading(Some(
                (received.min(total) as u128 * 100 / total as u128) as u8,
            ));
        }
    }

    info!("OTA: downloaded {received} bytes");

    // Ask the provider for permission to apply (its consent / scheduling gate).
    match provider
        .apply_update(matter, crypto, update_token, version)
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
    // A real device activates the new image and reboots here.

    // Report completion to the provider.
    provider
        .notify_applied(matter, crypto, update_token, version)
        .await?;

    update.complete();

    Ok(true)
}
