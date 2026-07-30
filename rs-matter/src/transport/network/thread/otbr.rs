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

use core::cell::RefCell;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};
use futures_lite::future::block_on;

use zbus::Connection;

use crate::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetworkScanInfo, NetworkType, WirelessCreds,
};
use crate::dm::clusters::thread_diag::{NeighborTable, RoutingRoleEnum, ThreadDiag};
use crate::dm::clusters::wifi_diag::WirelessDiag;
use crate::dm::networks::NetChangeNotif;
use crate::error::Error;
use crate::utils::sync::{blocking, DynBase};
use crate::utils::zbus_proxies::openthread::border_router::{BorderRouterProxy, NeighborEntry};

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
    /// The last observed device role, so that the non-async
    /// `WirelessDiag::connected` can answer without a D-Bus round-trip.
    role: blocking::Mutex<RefCell<RoutingRoleEnum>>,
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
            role: blocking::Mutex::new(RefCell::new(RoutingRoleEnum::Unspecified)),
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

    /// Re-read the device role, update the cache, and return
    /// `(changed, attached)`.
    async fn refresh_role(&self) -> Result<(bool, bool), zbus::Error> {
        let role = Self::role_from_str(&self.proxy().await?.device_role().await?);

        Ok(self.role.lock(|cached| {
            let mut cached = cached.borrow_mut();

            let changed = *cached != role;
            *cached = role;

            (changed, Self::role_attached(role))
        }))
    }

    /// Run a (quick) D-Bus call from a non-async context.
    ///
    /// Used by the `ThreadDiag` getters, which are synchronous by design
    /// (they run inside attribute-read handling). The agent answers on a
    /// local Unix socket, so each call is a sub-millisecond round-trip;
    /// zbus's internal executor runs on its own thread, which makes blocking
    /// here deadlock-free.
    fn call_blocking<R>(
        &self,
        f: impl AsyncFnOnce(&BorderRouterProxy<'a>) -> Result<R, zbus::Error>,
    ) -> Result<R, Error> {
        Ok(block_on(async { f(&self.proxy().await?).await })?)
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

        let _ = self.refresh_role().await;
        info!("Attached to Thread network");

        Ok(())
    }
}

impl DynBase for OtbrCtl<'_> {}

impl WirelessDiag for OtbrCtl<'_> {
    fn connected(&self) -> Result<bool, Error> {
        Ok(self.role.lock(|role| Self::role_attached(*role.borrow())))
    }
}

impl ThreadDiag for OtbrCtl<'_> {
    fn channel(&self) -> Result<Option<u16>, Error> {
        self.call_blocking(async |proxy| proxy.channel().await)
            .map(Some)
    }

    fn routing_role(&self) -> Result<Option<RoutingRoleEnum>, Error> {
        let role = self.call_blocking(async |proxy| proxy.device_role().await)?;

        Ok(Some(Self::role_from_str(&role)))
    }

    fn network_name(
        &self,
        f: &mut dyn FnMut(Option<&str>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let name = self.call_blocking(async |proxy| proxy.network_name().await)?;

        f(Some(&name))
    }

    fn pan_id(&self) -> Result<Option<u16>, Error> {
        self.call_blocking(async |proxy| proxy.pan_id().await)
            .map(Some)
    }

    fn extended_pan_id(&self) -> Result<Option<u64>, Error> {
        self.call_blocking(async |proxy| proxy.ext_pan_id().await)
            .map(Some)
    }

    fn ext_address(&self) -> Result<Option<u64>, Error> {
        self.call_blocking(async |proxy| proxy.extended_address().await)
            .map(Some)
    }

    fn rloc_16(&self) -> Result<Option<u16>, Error> {
        self.call_blocking(async |proxy| proxy.rloc16().await)
            .map(Some)
    }

    fn partition_id(&self) -> Result<Option<u32>, Error> {
        self.call_blocking(async |proxy| proxy.leader_data().await)
            .map(|data| Some(data.partition_id))
    }

    fn weighting(&self) -> Result<Option<u16>, Error> {
        self.call_blocking(async |proxy| proxy.leader_data().await)
            .map(|data| Some(data.weighting as u16))
    }

    fn data_version(&self) -> Result<Option<u16>, Error> {
        self.call_blocking(async |proxy| proxy.leader_data().await)
            .map(|data| Some(data.data_version as u16))
    }

    fn stable_data_version(&self) -> Result<Option<u16>, Error> {
        self.call_blocking(async |proxy| proxy.leader_data().await)
            .map(|data| Some(data.stable_data_version as u16))
    }

    fn leader_router_id(&self) -> Result<Option<u8>, Error> {
        self.call_blocking(async |proxy| proxy.leader_data().await)
            .map(|data| Some(data.leader_router_id))
    }

    fn neighbor_table(
        &self,
        f: &mut dyn FnMut(&NeighborTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let entries = self.call_blocking(async |proxy| proxy.neighbor_table().await)?;

        for entry in &entries {
            f(&neighbor_table_entry(entry))?;
        }

        Ok(())
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

            match self.refresh_role().await {
                Ok((true, _)) => break,
                Ok((false, _)) => {}
                Err(e) => error!("Failed to refresh device role: {:?}", e),
            }
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
