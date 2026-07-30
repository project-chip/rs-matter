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

//! A `NetCtl`, `WirelessDiag`, `ThreadDiag` and `NetChangeNotif` implementation
//! based on the OpenThread Border Router (`otbr-agent`) D-Bus API.

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use zbus::Connection;

use crate::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetworkScanInfo, NetworkType, WirelessCreds,
};
use crate::dm::clusters::thread_diag::{NeighborTable, RoutingRoleEnum, ThreadDiag};
use crate::dm::clusters::wifi_diag::WirelessDiag;
use crate::dm::networks::NetChangeNotif;
use crate::error::Error;
use crate::utils::sync::{blocking, DynBase};
use crate::utils::zbus_proxies::openthread::border_router::{
    BorderRouterProxy, LeaderData, NeighborEntry,
};

extern crate alloc;

/// A `NetCtl`, `WirelessDiag`, `ThreadDiag` and `NetChangeNotif`
/// implementation based on the `otbr-agent` (OpenThread Border Router)
/// service.
///
/// Suitable for use with embedded Linux devices that run `otbr-agent` over
/// D-Bus — the same integration shape CHIP's own Linux platform uses. The
/// agent owns the 802.15.4 radio and the whole Thread stack, and surfaces the
/// Thread network to the kernel as a TUN interface; Matter's own UDP traffic
/// therefore flows through the ordinary OS network stack, and this type only
/// drives *control*: dataset provisioning, attach/detach and diagnostics.
///
/// The current implementation targets the agent's default `wpan0` interface
/// (D-Bus service name `io.openthread.BorderRouter.wpan0`).
pub struct OtbrCtl<'a> {
    connection: &'a Connection,
    /// The last observed network state, so that the non-async
    /// `WirelessDiag` / `ThreadDiag` getters can answer without D-Bus
    /// round-trips. See [`OtbrCtl::refresh`].
    state: blocking::Mutex<RefCell<OtbrState>>,
}

impl<'a> OtbrCtl<'a> {
    const CONNECT_TIMEOUT_SECS: u64 = 30;

    /// Create a new `OtbrCtl` instance.
    ///
    /// # Arguments
    /// * `connection` - A reference to the D-Bus connection where the
    ///   `otbr-agent` service lives (usually the system bus).
    pub const fn new(connection: &'a Connection) -> Self {
        Self {
            connection,
            state: blocking::Mutex::new(RefCell::new(OtbrState::new())),
        }
    }

    /// Return a reference to the D-Bus connection.
    pub const fn connection(&self) -> &Connection {
        self.connection
    }

    async fn proxy(&self) -> Result<BorderRouterProxy<'a>, zbus::Error> {
        // Property caching MUST be off: zbus populates its cache with
        // `Properties.GetAll`, and `otbr-agent`'s `GetAll` fails wholesale as
        // soon as one of its getters is a `NotImplemented` stub (NAT64,
        // ephemeral-key & friends, depending on build flags). Uncached
        // proxies issue a direct `Get` per read, which the agent serves
        // fine. (The agent never emits `PropertiesChanged` either, so the
        // cache could not have been kept coherent anyway.)
        BorderRouterProxy::builder(self.connection)
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
    }

    /// Map an otbr `DeviceRole` property value onto the Matter routing-role
    /// enum.
    fn role_from_str(role: &str) -> RoutingRoleEnum {
        match role {
            "child" => RoutingRoleEnum::EndDevice,
            "router" => RoutingRoleEnum::Router,
            "leader" => RoutingRoleEnum::Leader,
            "detached" => RoutingRoleEnum::Unassigned,
            // "disabled", or anything unexpected
            _ => RoutingRoleEnum::Unspecified,
        }
    }

    /// Whether the given role means "attached to a Thread network".
    fn role_attached(role: RoutingRoleEnum) -> bool {
        matches!(
            role,
            RoutingRoleEnum::EndDevice
                | RoutingRoleEnum::SleepyEndDevice
                | RoutingRoleEnum::REED
                | RoutingRoleEnum::Router
                | RoutingRoleEnum::Leader
        )
    }

    /// Re-read the network state off the running agent, update the cache, and
    /// return `(role_changed, attached)`.
    ///
    /// The cache exists because the `WirelessDiag` / `ThreadDiag` getters are
    /// synchronous by design (they run inside attribute-read handling) and
    /// must not block on D-Bus round-trips. It is refreshed on every
    /// (re)connect and by the `NetChangeNotif` polling loop, so the served
    /// values are at most one poll period old.
    async fn refresh(&self) -> Result<(bool, bool), zbus::Error> {
        let proxy = self.proxy().await?;

        // The role is the load-bearing part (connectivity status and change
        // detection); a failure to fetch it fails the refresh. Failures of
        // the individual diagnostics properties below merely degrade that
        // value to "unknown".
        let role = Self::role_from_str(&proxy.device_role().await?);

        let state = OtbrState {
            role,
            channel: proxy.channel().await.ok(),
            network_name: proxy.network_name().await.ok(),
            pan_id: proxy.pan_id().await.ok(),
            ext_pan_id: proxy.ext_pan_id().await.ok(),
            ext_address: proxy.extended_address().await.ok(),
            rloc16: proxy.rloc16().await.ok(),
            leader_data: proxy.leader_data().await.ok(),
            neighbors: proxy
                .neighbor_table()
                .await
                .map(|entries| entries.iter().map(neighbor_table_entry).collect())
                .unwrap_or_default(),
        };

        Ok(self.state.lock(|cached| {
            let mut cached = cached.borrow_mut();

            let changed = cached.role != state.role;
            *cached = state;

            (changed, Self::role_attached(role))
        }))
    }
}

impl NetCtl for OtbrCtl<'_> {
    fn net_type(&self) -> NetworkType {
        NetworkType::Thread
    }

    async fn scan<F>(&self, network: Option<&[u8]>, mut f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>,
    {
        let proxy = self.proxy().await.map_err(Error::from)?;

        let results = proxy.scan().await.map_err(Error::from)?;

        for result in &results {
            // A directed Thread scan filters on the Extended PAN ID
            // (big-endian octets, as carried in the cluster's `NetworkID`).
            if let Some(network) = network {
                if network != result.ext_panid.to_be_bytes() {
                    continue;
                }
            }

            f(&NetworkScanInfo::Thread {
                pan_id: result.panid,
                ext_pan_id: result.ext_panid,
                network_name: &result.network_name,
                channel: result.channel as u16,
                version: result.version,
                ext_addr: &result.ext_address.to_be_bytes(),
                rssi: result.rssi.clamp(i8::MIN as i16, i8::MAX as i16) as i8,
                lqi: result.lqi,
            })?;
        }

        Ok(())
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        let WirelessCreds::Thread { dataset_tlv } = creds else {
            return Err(NetCtlError::Other(
                crate::error::ErrorCode::InvalidAction.into(),
            ));
        };

        let proxy = self.proxy().await.map_err(Error::from)?;

        // `AttachAllNodesTo` is the one attach verb whose D-Bus reply arrives
        // only once the attach has actually completed, and it handles the two
        // states we want on its own: same-dataset-as-local just (re)starts
        // the stack, and a dataset-less agent gets the dataset provisioned
        // and attaches directly. The one state to avoid is "has a DIFFERENT
        // dataset": there it stages a whole-mesh pending-dataset migration
        // with a 300 s delay timer (it is built for migrating meshes, not
        // for switching a single node). This node is a single device, so
        // wipe the Thread state first and take the direct path.
        //
        // `FactoryReset` (detach + erase Thread persistent info, in-process)
        // rather than the more natural-sounding `LeaveNetwork`, because the
        // latter *exits the agent process* (expecting a service manager to
        // restart it). And not `SetActiveDatasetTlvs` + `Attach`, because the
        // agent's property-`Set` machinery rejects standard D-Bus clients.
        let same = proxy
            .active_dataset_tlvs()
            .await
            .map(|active| active == *dataset_tlv)
            .unwrap_or(false);

        if !same {
            proxy.factory_reset().await.map_err(Error::from)?;
        }

        let connect = proxy.attach_all_nodes_to(dataset_tlv);
        let timeout = Timer::after(Duration::from_secs(Self::CONNECT_TIMEOUT_SECS));

        match select(connect, timeout).await {
            Either::First(result) => {
                result.map_err(Error::from)?;
            }
            Either::Second(_) => {
                error!(
                    "Attaching to the Thread network timed out after {}s",
                    Self::CONNECT_TIMEOUT_SECS
                );
                return Err(NetCtlError::OtherConnectionFailure);
            }
        }

        let _ = self.refresh().await;
        info!("Attached to Thread network");

        Ok(())
    }
}

impl DynBase for OtbrCtl<'_> {}

impl WirelessDiag for OtbrCtl<'_> {
    fn connected(&self) -> Result<bool, Error> {
        Ok(self
            .state
            .lock(|state| Self::role_attached(state.borrow().role)))
    }
}

// All getters answer from the cache - see `OtbrCtl::refresh`.
impl ThreadDiag for OtbrCtl<'_> {
    fn channel(&self) -> Result<Option<u16>, Error> {
        Ok(self.state.lock(|state| state.borrow().channel))
    }

    fn routing_role(&self) -> Result<Option<RoutingRoleEnum>, Error> {
        Ok(Some(self.state.lock(|state| state.borrow().role)))
    }

    fn network_name(
        &self,
        f: &mut dyn FnMut(Option<&str>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.state
            .lock(|state| f(state.borrow().network_name.as_deref()))
    }

    fn pan_id(&self) -> Result<Option<u16>, Error> {
        Ok(self.state.lock(|state| state.borrow().pan_id))
    }

    fn extended_pan_id(&self) -> Result<Option<u64>, Error> {
        Ok(self.state.lock(|state| state.borrow().ext_pan_id))
    }

    fn ext_address(&self) -> Result<Option<u64>, Error> {
        Ok(self.state.lock(|state| state.borrow().ext_address))
    }

    fn rloc_16(&self) -> Result<Option<u16>, Error> {
        Ok(self.state.lock(|state| state.borrow().rloc16))
    }

    fn partition_id(&self) -> Result<Option<u32>, Error> {
        Ok(self
            .state
            .lock(|state| state.borrow().leader_data.map(|data| data.partition_id)))
    }

    fn weighting(&self) -> Result<Option<u16>, Error> {
        Ok(self
            .state
            .lock(|state| state.borrow().leader_data.map(|data| data.weighting as u16)))
    }

    fn data_version(&self) -> Result<Option<u16>, Error> {
        Ok(self.state.lock(|state| {
            state
                .borrow()
                .leader_data
                .map(|data| data.data_version as u16)
        }))
    }

    fn stable_data_version(&self) -> Result<Option<u16>, Error> {
        Ok(self.state.lock(|state| {
            state
                .borrow()
                .leader_data
                .map(|data| data.stable_data_version as u16)
        }))
    }

    fn leader_router_id(&self) -> Result<Option<u8>, Error> {
        Ok(self
            .state
            .lock(|state| state.borrow().leader_data.map(|data| data.leader_router_id)))
    }

    fn neighbor_table(
        &self,
        f: &mut dyn FnMut(&NeighborTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.state.lock(|state| {
            for entry in &state.borrow().neighbors {
                f(entry)?;
            }

            Ok(())
        })
    }
}

impl NetChangeNotif for OtbrCtl<'_> {
    async fn wait_changed(&self) {
        // Polling, not `receive_device_role_changed`: the agent's hand-rolled
        // properties implementation never emits `PropertiesChanged`, so a
        // property stream would simply never fire.
        const POLL_PERIOD_SECS: u64 = 5;

        loop {
            Timer::after(Duration::from_secs(POLL_PERIOD_SECS)).await;

            match self.refresh().await {
                Ok((true, _)) => break,
                Ok((false, _)) => {}
                Err(e) => error!("Failed to refresh device role: {:?}", e),
            }
        }
    }
}

/// The cached network state served by the synchronous `WirelessDiag` /
/// `ThreadDiag` getters. Refreshed off the running agent by
/// [`OtbrCtl::refresh`]; `None` values mean the corresponding property could
/// not be fetched (yet).
#[derive(Debug, Clone)]
struct OtbrState {
    role: RoutingRoleEnum,
    channel: Option<u16>,
    network_name: Option<String>,
    pan_id: Option<u16>,
    ext_pan_id: Option<u64>,
    ext_address: Option<u64>,
    rloc16: Option<u16>,
    leader_data: Option<LeaderData>,
    neighbors: Vec<NeighborTable>,
}

impl OtbrState {
    const fn new() -> Self {
        Self {
            role: RoutingRoleEnum::Unspecified,
            channel: None,
            network_name: None,
            pan_id: None,
            ext_pan_id: None,
            ext_address: None,
            rloc16: None,
            leader_data: None,
            neighbors: Vec::new(),
        }
    }
}

/// Map an otbr neighbor-table entry onto the Matter diagnostics one.
fn neighbor_table_entry(entry: &NeighborEntry) -> NeighborTable {
    /// otbr reports error rates scaled to `0xFFFF == 100%`; the cluster wants
    /// integer percent.
    fn error_rate_percent(rate: u16) -> u8 {
        (rate as u32 * 100 / u16::MAX as u32) as u8
    }

    /// otbr reports RSSI as an unsigned byte carrying an `int8_t`;
    /// `127` is OpenThread's "unknown RSSI" marker.
    fn rssi(raw: u8) -> Option<i8> {
        let rssi = raw as i8;

        (rssi != i8::MAX).then_some(rssi)
    }

    NeighborTable {
        ext_address: entry.ext_address,
        age: entry.age,
        rloc16: entry.rloc16,
        link_frame_counter: entry.link_frame_counter,
        mle_frame_counter: entry.mle_frame_counter,
        lqi: entry.link_quality_in,
        average_rssi: rssi(entry.average_rssi),
        last_rssi: rssi(entry.last_rssi),
        frame_error_rate: error_rate_percent(entry.frame_error_rate),
        message_error_rate: error_rate_percent(entry.message_error_rate),
        rx_on_when_idle: entry.rx_on_when_idle,
        full_thread_device: entry.full_thread_device,
        full_network_data: entry.full_network_data,
        is_child: entry.is_child,
    }
}
