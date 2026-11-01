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

use core::marker::PhantomData;
use core::pin::pin;

use rs_matter_crypto::Crypto;
use rs_matter_dm::clusters::gen_diag::{GenDiag, NetifDiag};
use rs_matter_dm::clusters::net_comm::{
    self, remove_networks, NetCtlError, NetworkType, Networks, WirelessCreds,
};
use rs_matter_dm::clusters::wifi_diag::WirelessDiag;
use rs_matter_dm::clusters::{thread_diag, wifi_diag};
use rs_matter_dm::networks::wireless::{NetCtlState, WirelessNetwork, WirelessNetworks};
use rs_matter_dm::networks::NetChangeNotif;
use rs_matter_dm_core::persist::{KvBlobStore, NETWORKS_KEY};
use rs_matter_dm_core::DataModel;
use rs_matter_pairing::DiscoveryCapabilities;
use rs_matter_sc::pase::CommWindowState;
use rs_matter_transport::network::btp::{AdvData, Btp};
use rs_matter_transport::network::NoNetwork;
use rs_matter_utils::cell::RefCell;
use rs_matter_utils::error::Error;
use rs_matter_utils::futures::{select, select3, select4, Coalesce};
use rs_matter_utils::init::{init, Init};
use rs_matter_utils::sync::{blocking, IfMutex, MaybeSend, MaybeSendSync};
use rs_matter_utils::timers::{Duration, Timer};

use crate::ble::GattPeripheral;
use crate::mdns::Mdns;
use crate::net::NetStack;
use crate::network::{Embedding, Network};
use crate::private::Sealed;
use crate::{pin_alloc, DummyAttrNotifier, MatterStack};

pub use gatt::*;
pub use thread::*;
pub use wifi::*;

mod gatt;
mod thread;
mod wifi;

/// The number of networks of the default wireless networks store.
pub const MAX_WIRELESS_NETWORKS: usize = 2;

/// A type alias for a Matter stack running over either Wifi or Thread (and BLE, during commissioning).
///
/// `S` is the networks store of the Wifi or Thread interface.
pub type WirelessMatterStack<
    'a,
    const B: usize,
    T,
    E = (),
    S = WirelessNetworks<MAX_WIRELESS_NETWORKS, T>,
> = MatterStack<'a, B, WirelessBle<T, E, S>>;

/// An implementation of the `Network` trait for a Matter stack running over
/// BLE during commissioning, and then over either WiFi or Thread when operating.
///
/// The supported commissioning is either concurrent or non-concurrent (as per the Matter Core spec),
/// where one over the other is decided at runtime with the concrete wireless implementation
/// (`WirelessCoex` or `Wireless` + `Gatt`).
///
/// Non-concurrent commissioning means that the device - at any point in time - either runs Bluetooth
/// or Wifi/Thread, but not both.
///
/// This is done to save memory and to avoid the usage of BLE+Wifi/Thread co-exist drivers on
/// devices which share a single wireless radio for both BLE and Wifi/Thread.
///
/// `T` selects the operational network (`wireless::Wifi` or `wireless::Thread`) and
/// `S` is the networks store of its interface - any `Networks` implementation, by
/// default `WirelessNetworks` with `MAX_WIRELESS_NETWORKS` networks.
pub struct WirelessBle<T, E = (), S = WirelessNetworks<MAX_WIRELESS_NETWORKS, T>>
where
    T: WirelessNetwork,
{
    btp: Btp,
    net_state: blocking::Mutex<RefCell<NetCtlState>>,
    /// The networks store of the operational network interface.
    ///
    /// `run` holds it locked throughout and lends it, as `&mut`, to the Network
    /// Commissioning handler of each phase, so that the handler is its only
    /// user meanwhile.
    networks: IfMutex<S>,
    embedding: E,
    _network: PhantomData<fn() -> T>,
}

impl<T, S, E> WirelessBle<T, E, S>
where
    T: WirelessNetwork,
    S: Embedding,
    E: Embedding,
{
    /// Creates a new instance of the `WirelessBle` network type.
    pub const fn new() -> Self {
        Self {
            btp: Btp::new(),
            net_state: NetCtlState::new_with_mutex(),
            networks: IfMutex::new(S::INIT),
            embedding: E::INIT,
            _network: PhantomData,
        }
    }

    /// Return an in-place initializer for the `WirelessBle` network type.
    pub fn init() -> impl Init<Self> {
        init!(Self {
            btp <- Btp::init(),
            net_state <- NetCtlState::init_with_mutex(),
            networks <- IfMutex::init(S::init()),
            embedding <- E::init(),
            _network: PhantomData,
        })
    }
}

impl<const N: usize, T> Embedding for WirelessNetworks<N, T>
where
    T: WirelessNetwork + MaybeSendSync,
{
    const INIT: Self = Self::new();

    fn init() -> impl Init<Self> {
        WirelessNetworks::init()
    }
}

/// A composite wireless network controller that is the SAME concrete type during
/// both the (BLE) commissioning phase and the operational (Thread/Wifi) phase.
///
/// This exists purely to avoid building two structurally-different Matter handler
/// chains per device. `InteractionModel::handle` and every generated cluster handler
/// adaptor are monomorphized over the whole handler-chain tuple type; if the
/// net-ctl slot has a different type per phase, the entire dispatch tree is
/// compiled twice (~tens of KiB of duplicated `.text` on embedded targets).
///
/// By using `WirelessNetCtl<Q>` in *both* phases — `Commissioning` before the
/// operational controller exists, `Operational(&Q)` afterwards — the chain type
/// is identical across phases and the dispatch tree monomorphizes once.
///
/// The `Commissioning` variant reproduces the behavior of the former
/// `NoopWirelessNetCtl`: `scan` errors with `InvalidAction`, `connect` only
/// checks the creds match the network type, and every diag returns its default.
/// It refuses to disable the interface being commissioned.
/// The `Operational` variant delegates to the real controller `Q`.
///
/// `Q` is named identically at every phase via the wireless driver's associated
/// net-ctl type (see the `Thread`/`Gatt` driver traits), so even the
/// commissioning phase — which has no controller value — can still name the type.
pub enum WirelessNetCtl<'a, Q> {
    /// Commissioning phase: no operational controller yet (BLE only).
    Commissioning(NetworkType),
    /// Operational phase: delegate to the real controller.
    Operational(&'a Q),
}

impl<Q> net_comm::NetCtl for WirelessNetCtl<'_, Q>
where
    Q: net_comm::NetCtl,
{
    fn net_type(&self) -> NetworkType {
        match self {
            Self::Commissioning(net_type) => *net_type,
            Self::Operational(q) => q.net_type(),
        }
    }

    fn connect_max_time_seconds(&self) -> u8 {
        match self {
            Self::Commissioning(_) => 0,
            Self::Operational(q) => q.connect_max_time_seconds(),
        }
    }

    fn scan_max_time_seconds(&self) -> u8 {
        match self {
            Self::Commissioning(_) => 0,
            Self::Operational(q) => q.scan_max_time_seconds(),
        }
    }

    fn supported_wifi_bands<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnMut(net_comm::WiFiBandEnum) -> Result<(), Error>,
    {
        match self {
            Self::Commissioning(_) => Ok(()),
            Self::Operational(q) => q.supported_wifi_bands(f),
        }
    }

    fn supported_thread_features(&self) -> net_comm::ThreadCapabilitiesBitmap {
        match self {
            Self::Commissioning(_) => net_comm::ThreadCapabilitiesBitmap::empty(),
            Self::Operational(q) => q.supported_thread_features(),
        }
    }

    fn thread_version(&self) -> u16 {
        match self {
            Self::Commissioning(_) => 0,
            Self::Operational(q) => q.thread_version(),
        }
    }

    fn set_enabled(&self, enabled: bool) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) if enabled => Ok(()),
            Self::Commissioning(_) => Err(rs_matter_utils::error::ErrorCode::InvalidAction.into()),
            Self::Operational(q) => q.set_enabled(enabled),
        }
    }

    async fn scan<F>(&self, network: Option<&[u8]>, f: F) -> Result<(), NetCtlError>
    where
        F: FnMut(&net_comm::NetworkScanInfo) -> Result<(), Error> + MaybeSend,
    {
        match self {
            // Matches the former `NoopWirelessNetCtl::scan`.
            Self::Commissioning(_) => Err(NetCtlError::Other(
                rs_matter_utils::error::ErrorCode::InvalidAction.into(),
            )),
            Self::Operational(q) => q.scan(network, f).await,
        }
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetCtlError> {
        match self {
            // Matches the former `NoopWirelessNetCtl::connect`.
            Self::Commissioning(net_type) => Ok(net_type.check_creds(creds)?),
            Self::Operational(q) => q.connect(creds).await,
        }
    }
}

impl<Q> NetChangeNotif for WirelessNetCtl<'_, Q>
where
    Q: NetChangeNotif,
{
    async fn wait_changed(&self) {
        match self {
            Self::Commissioning(_) => core::future::pending().await,
            Self::Operational(q) => q.wait_changed().await,
        }
    }
}

impl<Q> WirelessDiag for WirelessNetCtl<'_, Q>
where
    Q: WirelessDiag,
{
    fn connected(&self) -> Result<bool, Error> {
        match self {
            Self::Commissioning(_) => Ok(false),
            Self::Operational(q) => q.connected(),
        }
    }
}

// For `WifiDiag`/`ThreadDiag`, the `Commissioning` variant reproduces each
// method's trait default (matching the former `NoopWirelessNetCtl`, which impl'd
// both traits empty), and the `Operational` variant delegates to the real
// controller. The defaults are: `Ok(None)` for the scalar accessors, `Ok(())` /
// `f(None)` for the closure-based accessors, and `Nullable::none()` for the
// `WifiDiag` nullable accessors, `Ok(0)` for the `ThreadDiag` overrun count — kept in sync
// with rs-matter's trait defaults.
impl<Q> wifi_diag::WifiDiag for WirelessNetCtl<'_, Q>
where
    Q: wifi_diag::WifiDiag,
{
    fn bssid(&self, f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => f(None),
            Self::Operational(q) => q.bssid(f),
        }
    }

    fn security_type(&self) -> Result<rs_matter_tlv::Nullable<wifi_diag::SecurityTypeEnum>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.security_type(),
        }
    }

    fn wi_fi_version(&self) -> Result<rs_matter_tlv::Nullable<wifi_diag::WiFiVersionEnum>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.wi_fi_version(),
        }
    }

    fn channel_number(&self) -> Result<rs_matter_tlv::Nullable<u16>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.channel_number(),
        }
    }

    fn rssi(&self) -> Result<rs_matter_tlv::Nullable<i8>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.rssi(),
        }
    }
    fn beacon_lost_count(&self) -> Result<rs_matter_tlv::Nullable<u32>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.beacon_lost_count(),
        }
    }
    fn beacon_rx_count(&self) -> Result<rs_matter_tlv::Nullable<u32>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.beacon_rx_count(),
        }
    }
    fn packet_multicast_rx_count(&self) -> Result<rs_matter_tlv::Nullable<u32>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.packet_multicast_rx_count(),
        }
    }
    fn packet_multicast_tx_count(&self) -> Result<rs_matter_tlv::Nullable<u32>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.packet_multicast_tx_count(),
        }
    }
    fn packet_unicast_rx_count(&self) -> Result<rs_matter_tlv::Nullable<u32>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.packet_unicast_rx_count(),
        }
    }
    fn packet_unicast_tx_count(&self) -> Result<rs_matter_tlv::Nullable<u32>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.packet_unicast_tx_count(),
        }
    }
    fn current_max_rate(&self) -> Result<rs_matter_tlv::Nullable<u64>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.current_max_rate(),
        }
    }
    fn overrun_count(&self) -> Result<rs_matter_tlv::Nullable<u64>, Error> {
        match self {
            Self::Commissioning(_) => Ok(rs_matter_tlv::Nullable::none()),
            Self::Operational(q) => q.overrun_count(),
        }
    }
    fn reset_counts(&self) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => Ok(()),
            Self::Operational(q) => q.reset_counts(),
        }
    }
}

impl<Q> thread_diag::ThreadDiag for WirelessNetCtl<'_, Q>
where
    Q: thread_diag::ThreadDiag,
{
    fn channel(&self) -> Result<Option<u16>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.channel(),
        }
    }
    fn routing_role(&self) -> Result<Option<thread_diag::RoutingRoleEnum>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.routing_role(),
        }
    }
    fn network_name(
        &self,
        f: &mut dyn FnMut(Option<&str>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => f(None),
            Self::Operational(q) => q.network_name(f),
        }
    }
    fn pan_id(&self) -> Result<Option<u16>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.pan_id(),
        }
    }
    fn extended_pan_id(&self) -> Result<Option<u64>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.extended_pan_id(),
        }
    }
    fn mesh_local_prefix(
        &self,
        f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => f(None),
            Self::Operational(q) => q.mesh_local_prefix(f),
        }
    }
    fn neighbor_table(
        &self,
        f: &mut dyn FnMut(&thread_diag::NeighborTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => Ok(()),
            Self::Operational(q) => q.neighbor_table(f),
        }
    }
    fn route_table(
        &self,
        f: &mut dyn FnMut(&thread_diag::RouteTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => Ok(()),
            Self::Operational(q) => q.route_table(f),
        }
    }
    fn partition_id(&self) -> Result<Option<u32>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.partition_id(),
        }
    }
    fn weighting(&self) -> Result<Option<u16>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.weighting(),
        }
    }
    fn data_version(&self) -> Result<Option<u16>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.data_version(),
        }
    }
    fn stable_data_version(&self) -> Result<Option<u16>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.stable_data_version(),
        }
    }
    fn leader_router_id(&self) -> Result<Option<u8>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.leader_router_id(),
        }
    }
    fn ext_address(&self) -> Result<Option<u64>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.ext_address(),
        }
    }
    fn rloc_16(&self) -> Result<Option<u16>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.rloc_16(),
        }
    }
    fn security_policy(&self) -> Result<Option<thread_diag::SecurityPolicy>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.security_policy(),
        }
    }
    fn channel_page0_mask(
        &self,
        f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => f(None),
            Self::Operational(q) => q.channel_page0_mask(f),
        }
    }
    fn operational_dataset_components(
        &self,
        f: &mut dyn FnMut(Option<&thread_diag::OperationalDatasetComponents>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => f(None),
            Self::Operational(q) => q.operational_dataset_components(f),
        }
    }
    fn active_network_faults_list(
        &self,
        f: &mut dyn FnMut(thread_diag::NetworkFaultEnum) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => Ok(()),
            Self::Operational(q) => q.active_network_faults_list(f),
        }
    }
    fn mac_counters(
        &self,
        f: &mut dyn FnMut(Option<&thread_diag::MacCounters>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => f(None),
            Self::Operational(q) => q.mac_counters(f),
        }
    }
    fn mle_counters(
        &self,
        f: &mut dyn FnMut(Option<&thread_diag::MleCounters>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => f(None),
            Self::Operational(q) => q.mle_counters(f),
        }
    }
    fn overrun_count(&self) -> Result<u64, Error> {
        match self {
            Self::Commissioning(_) => Ok(0),
            Self::Operational(q) => q.overrun_count(),
        }
    }
    fn reset_counts(&self) -> Result<(), Error> {
        match self {
            Self::Commissioning(_) => Ok(()),
            Self::Operational(q) => q.reset_counts(),
        }
    }
    fn active_timestamp(&self) -> Result<Option<u64>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.active_timestamp(),
        }
    }
    fn pending_timestamp(&self) -> Result<Option<u64>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.pending_timestamp(),
        }
    }
    fn delay(&self) -> Result<Option<u32>, Error> {
        match self {
            Self::Commissioning(_) => Ok(None),
            Self::Operational(q) => q.delay(),
        }
    }
}

impl<T, S, E> Default for WirelessBle<T, E, S>
where
    T: WirelessNetwork,
    S: Embedding,
    E: Embedding,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, S, E> Sealed for WirelessBle<T, E, S>
where
    T: WirelessNetwork,
    S: Embedding,
    E: Embedding,
{
}

impl<T, S, E> Network for WirelessBle<T, E, S>
where
    T: WirelessNetwork,
    S: Embedding,
    E: Embedding,
{
    const INIT: Self = Self::new();

    type Embedding<'a>
        = E
    where
        Self: 'a;

    fn init() -> impl Init<Self> {
        WirelessBle::init()
    }

    fn discovery_capabilities(&self) -> DiscoveryCapabilities {
        DiscoveryCapabilities::BLE
    }

    fn embedding(&self) -> &Self::Embedding<'_> {
        &self.embedding
    }
}

impl<const B: usize, T, NW, E> MatterStack<'_, B, WirelessBle<T, E, NW>>
where
    T: WirelessNetwork,
    NW: Networks + Embedding,
    E: Embedding,
{
    /// Reset the Matter instance to the factory defaults by removing all fabrics and basic info settings
    ///
    /// `handler` is the same data model handler that is passed to `run`: the
    /// Interaction Model broadcasts a `FactoryReset` lifecycle op to it, so
    /// cluster handlers owning persisted state of their own can drop it too.
    pub async fn reset<C, H, S>(&self, crypto: C, handler: H, store: S) -> Result<(), Error>
    where
        C: Crypto,
        H: DataModel,
        S: KvBlobStore + MaybeSend,
    {
        let kv = self.matter.kv(store);

        self.matter.factory_reset(&kv)?;

        // The stack's Network Commissioning handler is not part of `handler`,
        // so the `FactoryReset` broadcast below does not reach its networks
        // store (the commissioned Wifi/Thread credentials): reset it here.
        remove_networks(&mut *self.network.networks.lock().await, NETWORKS_KEY, &kv)?;

        // Reset the events counter so we don't carry a stale watermark across a
        // factory reset (Matter Core spec R1.5.1, §7.14.1.1).
        self.im(crypto, handler, &kv).factory_reset().await
    }

    /// Run the startup sequence of the stack: re-hydrate the persisted state and
    /// open the basic communication window if the device is not commissioned yet.
    ///
    /// This is the `Matter`-level half of the startup (fabrics, basic info, RTC,
    /// sessions). The Interaction Model half - the events watermark, the networks
    /// store and the persisted subscriptions - is re-hydrated by `run`, because
    /// `InteractionModel::startup` has to run on the very Interaction Model
    /// instance that is then run: a resumed subscription borrows that instance's
    /// IM buffers, and constructing an `InteractionModel` clears the
    /// subscriptions table.
    pub async fn startup<C, S>(&self, crypto: C, store: S) -> Result<(), Error>
    where
        C: Crypto,
        S: KvBlobStore + MaybeSend,
    {
        let kv = self.matter.kv(store);

        self.matter.startup(&kv)?;

        if !self.matter().has_fabrics() {
            info!("Device is not commissioned yet, opening commissioning window...");

            self.open_basic_comm_window(crypto, &DummyAttrNotifier)?;
        } else {
            info!("Device is already commissioned");
        }

        Ok(())
    }

    /// Run the concurrent (BLE + Wireless) commissioning transport.
    ///
    /// The operational wireless connection manager is no longer run here; it is
    /// driven by the data model engine (`InteractionModel::run`), which was built
    /// with the operational `net_ctl` and the stack's networks store. This method
    /// therefore only runs the BTP coexistence transport.
    async fn run_net_coex<C, S, N, D, G>(
        &self,
        crypto: &C,
        net_stack: &S,
        netif: &N,
        mdns: &mut D,
        gatt: &mut G,
    ) -> Result<(), Error>
    where
        C: Crypto,
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        D: Mdns,
        G: GattPeripheral,
    {
        self.run_btp_coex(crypto, net_stack, netif, mdns, gatt)
            .await
    }

    async fn run_btp_coex<C, S, N, D, P>(
        &self,
        crypto: &C,
        net_stack: &S,
        netif: &N,
        mdns: &mut D,
        peripheral: &mut P,
    ) -> Result<(), Error>
    where
        C: Crypto,
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        D: Mdns,
        P: GattPeripheral,
    {
        info!("BLE driver started");

        info!("Running in concurrent commissioning mode (BLE and Wireless)");

        let adv_data = AdvData::new(
            self.matter().dev_det(),
            self.matter().dev_comm().discriminator,
        );

        let mut btp_task = pin_alloc!(
            self.bump,
            self.run_gatt_while_ble_commissionable(peripheral, &adv_data)
        );

        let mut net_task = pin_alloc!(
            self.bump,
            self.run_oper_net(
                crypto,
                net_stack,
                0, // TODO
                core::future::pending(),
                Some((&self.network.btp, &self.network.btp))
            )
        );

        let mut mdns_task = pin_alloc!(
            self.bump,
            self.run_oper_netif_mdns(crypto, net_stack, netif, mdns)
        );

        select3(&mut btp_task, &mut net_task, &mut mdns_task)
            .coalesce()
            .await
    }

    async fn run_btp<C, P>(&self, crypto: &C, mut peripheral: P) -> Result<(), Error>
    where
        C: Crypto,
        P: GattPeripheral,
    {
        info!("BLE driver started");

        info!("Running in non-concurrent commissioning mode (BLE only)");

        let adv_data = AdvData::new(
            self.matter().dev_det(),
            self.matter().dev_comm().discriminator,
        );

        let mut btp_task = pin_alloc!(
            self.bump,
            peripheral.run(&self.network.btp, "BT", &adv_data)
        );

        let mut net_task =
            pin!(self.run_transport_net(crypto, &self.network.btp, &self.network.btp, NoNetwork));

        // The window this phase is advertising can also simply go away - it expires, or an
        // administrator revokes it - without the commissioner ever getting as far as handing
        // over the network credentials. Then there is nothing left to advertise, and BLE
        // should stop rather than keep the peripheral up for a window that no longer exists.
        let mut comm_window_task = pin!(async {
            self.wait_comm_window(|state| !state.is_open_on_all_transports())
                .await;

            Ok(())
        });

        let mut oper_net_act_task = pin!(async {
            NetCtlState::wait_prov_ready(&self.network.net_state, &self.network.btp).await;

            // TODO: Workaround for a bug in the `esp-wifi` BLE stack:
            // ====================== PANIC ======================
            // panicked at /home/ivan/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/esp-wifi-0.12.0/src/ble/npl.rs:914:9:
            // timed eventq_get not yet supported - go implement it!
            Timer::after(Duration::from_secs(2)).await;

            Ok(())
        });

        select4(
            &mut btp_task,
            &mut net_task,
            &mut oper_net_act_task,
            &mut comm_window_task,
        )
        .coalesce()
        .await
    }

    /// Run the GATT peripheral (and with it the BTP transport), but only for as long as the
    /// device is actually commissionable over BLE. Never returns, unless the peripheral itself
    /// fails.
    async fn run_gatt_while_ble_commissionable<P>(
        &self,
        peripheral: &mut P,
        adv_data: &AdvData,
    ) -> Result<(), Error>
    where
        P: GattPeripheral,
    {
        loop {
            // BLE carries a window the device opened for itself - initial commissioning.
            // A window re-opened by an administrator over CASE (`opener: Some`) is advertised
            // on the operational IP network alone, so the peripheral stays down for it.
            //
            // The opener is part of the window state, so one read answers both "is a window
            // open" and "is it ours". It also does not change while the window is open - in
            // particular the fabric that appears at `AddNOC`, in the middle of the very
            // commissioning this peripheral is carrying, leaves it `None`.
            let state = self.wait_comm_window(CommWindowState::is_open).await;

            if !state.is_open_on_all_transports() {
                info!("Commissioning window opened over CASE; BLE peripheral not started");

                self.wait_comm_window(|state| !state.is_open()).await;

                continue;
            }

            info!("Commissioning window opened; BLE peripheral started");

            {
                let mut peripheral_task = pin!(peripheral.run(&self.network.btp, "BT", adv_data));
                let mut closed_task = pin!(async {
                    self.wait_comm_window(|state| !state.is_open()).await;
                    Ok(())
                });

                select(&mut peripheral_task, &mut closed_task)
                    .coalesce()
                    .await?;
            } // <- dropping the peripheral future here is what stops BLE

            info!("Commissioning window closed; BLE peripheral stopped");
        }
    }

    /// Resolve once a commissioning window that has to be advertised on every transport
    /// *appears* - i.e. once the radio is needed for BLE again.
    ///
    /// A window that is already open on entry does not count. The non-concurrent BLE -> wireless
    /// handover happens with the window still open - it is closed by `CommissioningComplete`,
    /// which the commissioner sends over the operational network, after the handover - so
    /// treating the current window as an event would bounce the radio straight back to BLE in
    /// the middle of the commissioning it is there to finish. Hence: let the current window go
    /// away first, and only then wait for the next one. When nothing is open on entry - every
    /// case other than that handover - the first wait resolves on its first poll.
    async fn wait_next_comm_window(&self) {
        self.wait_comm_window(|state| !state.is_open_on_all_transports())
            .await;
        self.wait_comm_window(CommWindowState::is_open_on_all_transports)
            .await;
    }

    /// Forget the outcome of the last `NetworkCommissioning` scan / connect.
    ///
    /// The BLE phase of non-concurrent commissioning ends when `NetCtlState` reports that the
    /// commissioner has handed the network credentials over, and that verdict is sticky: nothing
    /// clears it, it is only ever overwritten by the next scan / connect. Clearing it as the BLE
    /// phase starts scopes it to the commissioning attempt that this window represents. Without
    /// it, a device commissioned earlier in this same boot would leave a freshly entered BLE
    /// phase again after one poll interval, on the strength of a verdict from the previous
    /// commissioning.
    fn reset_net_ctl_state(&self) {
        self.network.net_state.lock(|state| {
            let mut state = state.borrow_mut();

            state.network_id.clear();
            state.networking_status = None;
            state.connect_error_value = None;
        });
    }

    /// Resolve once `until` accepts the current commissioning window state, and return that
    /// state - so a caller that needs more than the predicate (typically the window's opener)
    /// does not have to read it a second time.
    async fn wait_comm_window<F>(&self, until: F) -> CommWindowState
    where
        F: Fn(&CommWindowState) -> bool,
    {
        loop {
            // Subscribe before reading the state, so that a change in between is not missed
            let changed = self.matter().transport().wait_comm_window_changed();

            let state = self.matter().comm_window_state();

            if until(&state) {
                break state;
            }

            changed.await;
        }
    }
}

/// A utility type for running a wireless task with a pre-existing wireless interface
/// rather than bringing up / tearing down the wireless interface for the task.
///
/// This utility can only be used with hardware that implements wireless coexist mode
/// (i.e. the Thread/Wifi interface as well as the BLE GATT peripheral are available at the same time).
pub struct PreexistingWireless<S, N, C, M, G> {
    pub(crate) net_stack: S,
    pub(crate) netif: N,
    pub(crate) net_ctl: C,
    pub(crate) mdns: M,
    pub(crate) gatt: G,
}

impl<S, N, C, M, G> PreexistingWireless<S, N, C, M, G> {
    /// Create a new `PreexistingWireless` instance with the given network stack,
    /// network interface, network controller and GATT peripheral.
    pub const fn new(net_stack: S, netif: N, net_ctl: C, mdns: M, gatt: G) -> Self {
        Self {
            net_stack,
            netif,
            net_ctl,
            mdns,
            gatt,
        }
    }
}

pub(crate) struct MatterStackWirelessTask<'a, const B: usize, T, S, E, C, H, K, U, Q>
where
    T: WirelessNetwork,
    S: Embedding,
    E: Embedding,
{
    stack: &'a MatterStack<'a, B, WirelessBle<T, E, S>>,
    gen_diag: &'a dyn GenDiag,
    networks: &'a mut S,
    crypto: C,
    handler: H,
    kv: K,
    user_task: U,
    _net_ctl: PhantomData<fn() -> Q>,
}
