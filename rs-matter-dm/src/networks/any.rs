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

//! A networks store, a network controller and diagnostics for a node that runs
//! Ethernet, Wifi or Thread, chosen at runtime.
//!
//! They are the same types whatever the network, so a data model handler built
//! from them (see `endpoints::any_net_handler`) is compiled once.

use core::ptr::addr_of_mut;

use crate::dm::clusters::eth_diag::{EthDiag, PHYRateEnum};
use crate::dm::clusters::net_comm::{
    NetCtl, NetCtlError, NetworkScanInfo, NetworkType, Networks, NetworksError,
    ThreadCapabilitiesBitmap, WiFiBandEnum, WirelessCreds,
};
use crate::dm::clusters::thread_diag::{
    MacCounters, MleCounters, NeighborTable, NetworkFaultEnum, OperationalDatasetComponents,
    RouteTable, RoutingRoleEnum, SecurityPolicy, ThreadDiag,
};
use crate::dm::clusters::wifi_diag::{SecurityTypeEnum, WiFiVersionEnum, WifiDiag, WirelessDiag};
use crate::error::{Error, ErrorCode};
use crate::tlv::{Nullable, TLVTag, TLVWrite, ToTLV};
use crate::utils::init::{init_from_closure, Init};
use crate::utils::storage::WriteBuf;
use crate::utils::sync::MaybeSend;

use super::eth::{EthNetCtl, EthNetwork};
use super::wireless::{
    Thread, ThreadNetworks, WifiNetworks, WirelessNetworks, DEFAULT_MAX_NETWORKS,
};
use super::NetChangeNotif;

/// Run `$body` on the store or controller of the variant `$self` holds.
macro_rules! dispatch {
    ($self:expr, $inner:ident => $body:expr) => {
        match $self {
            Self::Eth($inner) => $body,
            Self::Wifi($inner) => $body,
            Self::Thread($inner) => $body,
        }
    };
}

/// Diagnostics getters that answer `ClusterNotFound`.
macro_rules! not_found {
    ($($name:ident -> $ret:ty;)*) => {
        $(
            fn $name(&self) -> Result<$ret, Error> {
                Err(ErrorCode::ClusterNotFound.into())
            }
        )*
    };
}

/// [`not_found`], for the getters that take a callback.
macro_rules! not_found_with {
    ($($name:ident($arg:ty);)*) => {
        $(
            #[allow(clippy::type_complexity)]
            fn $name(&self, _f: &mut dyn FnMut($arg) -> Result<(), Error>) -> Result<(), Error> {
                Err(ErrorCode::ClusterNotFound.into())
            }
        )*
    };
}

/// Diagnostics getters forwarded to the `$active` variant's controller; the other
/// variants answer `ClusterNotFound`.
macro_rules! forward {
    ($active:ident: $($name:ident -> $ret:ty;)*) => {
        $(
            fn $name(&self) -> Result<$ret, Error> {
                match self {
                    Self::$active(ctl) => ctl.$name(),
                    _ => Err(ErrorCode::ClusterNotFound.into()),
                }
            }
        )*
    };
}

/// [`forward`], for the getters that take a callback.
macro_rules! forward_with {
    ($active:ident: $($name:ident($arg:ty);)*) => {
        $(
            #[allow(clippy::type_complexity)]
            fn $name(&self, f: &mut dyn FnMut($arg) -> Result<(), Error>) -> Result<(), Error> {
                match self {
                    Self::$active(ctl) => ctl.$name(f),
                    _ => Err(ErrorCode::ClusterNotFound.into()),
                }
            }
        )*
    };
}

/// A networks store for Ethernet, Wifi or Thread, whichever the node runs.
///
/// It remembers its network type: `load` takes the type of the saved store, and an
/// Ethernet store, which has no networks to save, saves its type alone. Until
/// something is loaded, `set_net_type` picks the type.
#[repr(u8)]
pub enum AnyNetworks<const N: usize = DEFAULT_MAX_NETWORKS> {
    Eth(EthNetwork<'static>) = 0,
    Wifi(WifiNetworks<N>) = 1,
    Thread(ThreadNetworks<N>) = 2,
}

impl<const N: usize> AnyNetworks<N> {
    // The discriminants of the variants.
    const ETH: u8 = 0;
    const WIFI: u8 = 1;
    const THREAD: u8 = 2;

    /// Create an empty store for `net_type` networks.
    pub const fn new(net_type: NetworkType) -> Self {
        match net_type {
            NetworkType::Ethernet => Self::Eth(EthNetwork::new_default()),
            NetworkType::Wifi => Self::Wifi(WifiNetworks::new()),
            NetworkType::Thread => Self::Thread(ThreadNetworks::new()),
        }
    }

    /// Return an in-place initializer for an empty store for `net_type` networks.
    pub fn init(net_type: NetworkType) -> impl Init<Self> {
        // SAFETY: each arm initializes a whole variant (see `init_variant`).
        unsafe {
            init_from_closure(move |slot: *mut Self| {
                match net_type {
                    NetworkType::Ethernet => Self::init_variant(
                        slot,
                        Self::ETH,
                        init_from_closure(|eth: *mut EthNetwork<'static>| {
                            eth.write(EthNetwork::new_default());
                            Ok(())
                        }),
                    ),
                    NetworkType::Wifi => {
                        Self::init_variant(slot, Self::WIFI, WifiNetworks::<N>::init())
                    }
                    NetworkType::Thread => {
                        Self::init_variant(slot, Self::THREAD, ThreadNetworks::<N>::init())
                    }
                }

                Ok(())
            })
        }
    }

    /// Make it an empty store for `net_type` networks, unless it is one already.
    pub fn set_net_type(&mut self, net_type: NetworkType) {
        if self.kind() == net_type {
            return;
        }

        let slot: *mut Self = self;

        // SAFETY: the old store is dropped, and the new one initialized in its place.
        // Neither can panic.
        unsafe {
            core::ptr::drop_in_place(slot);

            Self::init(net_type)
                .__init(slot)
                .unwrap_or_else(|never| match never {});
        }
    }

    /// The type of the networks the store is for.
    fn kind(&self) -> NetworkType {
        match self {
            Self::Eth(_) => NetworkType::Ethernet,
            Self::Wifi(_) => NetworkType::Wifi,
            Self::Thread(_) => NetworkType::Thread,
        }
    }

    /// Write `tag` and initialize the store with `init` after it, in `slot`.
    ///
    /// # Safety
    ///
    /// `slot` must be valid for writes, and `tag` must be the variant's whose store
    /// `init` initializes. A `#[repr(u8)]` enum is laid out as its variants, each a
    /// `#[repr(C)]` struct of the tag followed by the fields, so this initializes
    /// that variant.
    unsafe fn init_variant<T, I>(slot: *mut Self, tag: u8, init: I)
    where
        I: Init<T>,
    {
        #[repr(C)]
        struct Variant<T> {
            tag: u8,
            networks: T,
        }

        let variant = slot.cast::<Variant<T>>();

        addr_of_mut!((*variant).tag).write(tag);

        init.__init(addr_of_mut!((*variant).networks))
            .unwrap_or_else(|never| match never {});
    }
}

impl<const N: usize> Networks for AnyNetworks<N> {
    fn max_networks(&self) -> Result<u8, Error> {
        dispatch!(self, networks => Networks::max_networks(networks))
    }

    fn networks(&self, f: &mut dyn FnMut(&[u8]) -> Result<(), Error>) -> Result<(), Error> {
        dispatch!(self, networks => Networks::networks(networks, f))
    }

    fn creds(
        &self,
        network_id: &[u8],
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<u8, NetworksError> {
        dispatch!(self, networks => Networks::creds(networks, network_id, f))
    }

    fn next_creds(
        &self,
        last_network_id: Option<&[u8]>,
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        dispatch!(self, networks => Networks::next_creds(networks, last_network_id, f))
    }

    fn enabled(&self) -> Result<bool, Error> {
        dispatch!(self, networks => Networks::enabled(networks))
    }

    fn set_enabled(&mut self, enabled: bool) -> Result<(), Error> {
        dispatch!(self, networks => Networks::set_enabled(networks, enabled))
    }

    fn add_or_update(&mut self, creds: &WirelessCreds<'_>) -> Result<u8, NetworksError> {
        dispatch!(self, networks => Networks::add_or_update(networks, creds))
    }

    fn reorder(&mut self, index: u8, network_id: &[u8]) -> Result<u8, NetworksError> {
        dispatch!(self, networks => Networks::reorder(networks, index, network_id))
    }

    fn remove(&mut self, network_id: &[u8]) -> Result<u8, NetworksError> {
        dispatch!(self, networks => Networks::remove(networks, network_id))
    }

    fn managed(&self) -> Result<bool, Error> {
        dispatch!(self, networks => Networks::managed(networks))
    }

    fn set_managed(&mut self, managed: bool) -> Result<(), Error> {
        dispatch!(self, networks => Networks::set_managed(networks, managed))
    }

    fn reset(&mut self) -> Result<(), Error> {
        dispatch!(self, networks => Networks::reset(networks))
    }

    fn load(&mut self, data: &[u8]) -> Result<(), Error> {
        if let Some(net_type) = WirelessNetworks::<N, Thread>::stored_net_type(data)? {
            self.set_net_type(net_type);
        }

        dispatch!(self, networks => Networks::load(networks, data))
    }

    fn save(&self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        match self {
            Self::Eth(_) => {
                let mut wb = WriteBuf::new(buf);

                wb.start_struct(&TLVTag::Anonymous)?;
                WirelessNetworks::<N, Thread>::net_type_tag(NetworkType::Ethernet)
                    .to_tlv(&TLVTag::Context(3), &mut wb)?;
                wb.end_container()?;

                Ok(Some(wb.get_tail()))
            }
            Self::Wifi(networks) => Networks::save(networks, buf),
            Self::Thread(networks) => Networks::save(networks, buf),
        }
    }

    fn net_type(&self) -> Option<NetworkType> {
        Some(self.kind())
    }
}

/// A network controller for Ethernet, Wifi (`W`) or Thread (`T`), whichever the
/// node runs.
///
/// It serves the Wifi and the Thread diagnostics; those of a network that is not
/// running answer `ClusterNotFound`.
pub enum AnyNetCtl<'a, W, T> {
    Eth(EthNetCtl<'a>),
    Wifi(W),
    Thread(T),
}

impl<W, T> NetCtl for AnyNetCtl<'_, W, T>
where
    W: NetCtl,
    T: NetCtl,
{
    fn net_type(&self) -> NetworkType {
        dispatch!(self, ctl => ctl.net_type())
    }

    fn connect_max_time_seconds(&self) -> u8 {
        dispatch!(self, ctl => ctl.connect_max_time_seconds())
    }

    fn scan_max_time_seconds(&self) -> u8 {
        dispatch!(self, ctl => ctl.scan_max_time_seconds())
    }

    fn supported_wifi_bands<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnMut(WiFiBandEnum) -> Result<(), Error>,
    {
        dispatch!(self, ctl => ctl.supported_wifi_bands(f))
    }

    fn supported_thread_features(&self) -> ThreadCapabilitiesBitmap {
        dispatch!(self, ctl => ctl.supported_thread_features())
    }

    fn thread_version(&self) -> u16 {
        dispatch!(self, ctl => ctl.thread_version())
    }

    fn set_enabled(&self, enabled: bool) -> Result<(), Error> {
        dispatch!(self, ctl => ctl.set_enabled(enabled))
    }

    async fn scan<F>(&self, network: Option<&[u8]>, f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error> + MaybeSend,
    {
        dispatch!(self, ctl => ctl.scan(network, f).await)
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        dispatch!(self, ctl => ctl.connect(creds).await)
    }
}

impl<W, T> NetChangeNotif for AnyNetCtl<'_, W, T>
where
    W: NetChangeNotif,
    T: NetChangeNotif,
{
    async fn wait_changed(&self) {
        dispatch!(self, ctl => ctl.wait_changed().await)
    }
}

impl<W, T> WirelessDiag for AnyNetCtl<'_, W, T>
where
    W: WirelessDiag,
    T: WirelessDiag,
{
    fn connected(&self) -> Result<bool, Error> {
        dispatch!(self, ctl => ctl.connected())
    }
}

impl<W, T> ThreadDiag for AnyNetCtl<'_, W, T>
where
    W: WirelessDiag,
    T: ThreadDiag,
{
    forward! {
        Thread:
        channel -> Option<u16>;
        routing_role -> Option<RoutingRoleEnum>;
        pan_id -> Option<u16>;
        extended_pan_id -> Option<u64>;
        partition_id -> Option<u32>;
        weighting -> Option<u16>;
        data_version -> Option<u16>;
        stable_data_version -> Option<u16>;
        leader_router_id -> Option<u8>;
        ext_address -> Option<u64>;
        rloc_16 -> Option<u16>;
        security_policy -> Option<SecurityPolicy>;
        overrun_count -> u64;
        reset_counts -> ();
        active_timestamp -> Option<u64>;
        pending_timestamp -> Option<u64>;
        delay -> Option<u32>;
    }

    forward_with! {
        Thread:
        network_name(Option<&str>);
        mesh_local_prefix(Option<&[u8]>);
        neighbor_table(&NeighborTable);
        route_table(&RouteTable);
        channel_page0_mask(Option<&[u8]>);
        operational_dataset_components(Option<&OperationalDatasetComponents>);
        active_network_faults_list(NetworkFaultEnum);
        mac_counters(Option<&MacCounters>);
        mle_counters(Option<&MleCounters>);
    }
}

impl<W, T> WifiDiag for AnyNetCtl<'_, W, T>
where
    W: WifiDiag,
    T: WirelessDiag,
{
    forward! {
        Wifi:
        security_type -> Nullable<SecurityTypeEnum>;
        wi_fi_version -> Nullable<WiFiVersionEnum>;
        channel_number -> Nullable<u16>;
        rssi -> Nullable<i8>;
        beacon_lost_count -> Nullable<u32>;
        beacon_rx_count -> Nullable<u32>;
        packet_multicast_rx_count -> Nullable<u32>;
        packet_multicast_tx_count -> Nullable<u32>;
        packet_unicast_rx_count -> Nullable<u32>;
        packet_unicast_tx_count -> Nullable<u32>;
        current_max_rate -> Nullable<u64>;
        overrun_count -> Nullable<u64>;
        reset_counts -> ();
    }

    forward_with! {
        Wifi:
        bssid(Option<&[u8]>);
    }
}

/// The diagnostics of a network the node does not run: every attribute answers
/// `ClusterNotFound`.
pub struct InactiveDiag;

impl WirelessDiag for InactiveDiag {
    not_found! {
        connected -> bool;
    }
}

impl ThreadDiag for InactiveDiag {
    not_found! {
        channel -> Option<u16>;
        routing_role -> Option<RoutingRoleEnum>;
        pan_id -> Option<u16>;
        extended_pan_id -> Option<u64>;
        partition_id -> Option<u32>;
        weighting -> Option<u16>;
        data_version -> Option<u16>;
        stable_data_version -> Option<u16>;
        leader_router_id -> Option<u8>;
        ext_address -> Option<u64>;
        rloc_16 -> Option<u16>;
        security_policy -> Option<SecurityPolicy>;
        overrun_count -> u64;
        reset_counts -> ();
        active_timestamp -> Option<u64>;
        pending_timestamp -> Option<u64>;
        delay -> Option<u32>;
    }

    not_found_with! {
        network_name(Option<&str>);
        mesh_local_prefix(Option<&[u8]>);
        neighbor_table(&NeighborTable);
        route_table(&RouteTable);
        channel_page0_mask(Option<&[u8]>);
        operational_dataset_components(Option<&OperationalDatasetComponents>);
        active_network_faults_list(NetworkFaultEnum);
        mac_counters(Option<&MacCounters>);
        mle_counters(Option<&MleCounters>);
    }
}

impl WifiDiag for InactiveDiag {
    not_found! {
        security_type -> Nullable<SecurityTypeEnum>;
        wi_fi_version -> Nullable<WiFiVersionEnum>;
        channel_number -> Nullable<u16>;
        rssi -> Nullable<i8>;
        beacon_lost_count -> Nullable<u32>;
        beacon_rx_count -> Nullable<u32>;
        packet_multicast_rx_count -> Nullable<u32>;
        packet_multicast_tx_count -> Nullable<u32>;
        packet_unicast_rx_count -> Nullable<u32>;
        packet_unicast_tx_count -> Nullable<u32>;
        current_max_rate -> Nullable<u64>;
        overrun_count -> Nullable<u64>;
        reset_counts -> ();
    }

    not_found_with! {
        bssid(Option<&[u8]>);
    }
}

impl EthDiag for InactiveDiag {
    not_found! {
        phy_rate -> Option<PHYRateEnum>;
        full_duplex -> Option<bool>;
        carrier_detect -> Option<bool>;
        time_since_reset -> u64;
        packet_rx_count -> u64;
        packet_tx_count -> u64;
        tx_err_count -> u64;
        collision_count -> u64;
        overrun_count -> u64;
        reset_counts -> ();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use core::mem::MaybeUninit;

    use crate::utils::init::InitMaybeUninit;

    use super::*;

    fn count(networks: &AnyNetworks<2>) -> usize {
        let mut count = 0;

        Networks::networks(networks, &mut |_| {
            count += 1;
            Ok(())
        })
        .unwrap();

        count
    }

    #[test]
    fn init_in_place() {
        let mut slot = MaybeUninit::<AnyNetworks<2>>::uninit();
        let networks = slot.init_with(AnyNetworks::init(NetworkType::Wifi));

        assert_eq!(networks.net_type(), Some(NetworkType::Wifi));
        assert_eq!(networks.max_networks().unwrap(), 2);
        assert_eq!(count(networks), 0);
    }

    #[test]
    fn set_net_type_starts_empty() {
        let mut networks = AnyNetworks::<2>::new(NetworkType::Wifi);

        networks
            .add_or_update(&WirelessCreds::Wifi {
                ssid: b"home",
                pass: b"password",
            })
            .unwrap();

        networks.set_net_type(NetworkType::Wifi);
        assert_eq!(count(&networks), 1);

        networks.set_net_type(NetworkType::Thread);
        assert_eq!(networks.net_type(), Some(NetworkType::Thread));
        assert_eq!(count(&networks), 0);
    }

    #[test]
    fn ethernet_remembers_its_type() {
        let mut buf = [0; 64];
        let len = AnyNetworks::<2>::new(NetworkType::Ethernet)
            .save(&mut buf)
            .unwrap()
            .unwrap();

        assert_eq!(
            WirelessNetworks::<2, Thread>::stored_net_type(&buf[..len]).unwrap(),
            Some(NetworkType::Ethernet)
        );

        let mut networks = AnyNetworks::<2>::new(NetworkType::Thread);
        networks.load(&buf[..len]).unwrap();

        assert_eq!(networks.net_type(), Some(NetworkType::Ethernet));
        assert_eq!(networks.max_networks().unwrap(), 1);
    }

    #[test]
    fn load_takes_the_saved_type() {
        let mut wifi = AnyNetworks::<2>::new(NetworkType::Wifi);

        wifi.add_or_update(&WirelessCreds::Wifi {
            ssid: b"home",
            pass: b"password",
        })
        .unwrap();

        let mut buf = [0; 256];
        let len = wifi.save(&mut buf).unwrap().unwrap();

        let mut networks = AnyNetworks::<2>::new(NetworkType::Thread);
        networks.load(&buf[..len]).unwrap();

        assert_eq!(networks.net_type(), Some(NetworkType::Wifi));
        assert_eq!(count(&networks), 1);
    }
}
