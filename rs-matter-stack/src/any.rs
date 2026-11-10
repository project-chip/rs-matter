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

//! Running the stack over Ethernet, Wifi or Thread, whichever the driver runs.
//!
//! The data model handler of these run methods is the same type on all three networks,
//! so a node that picks its network at runtime compiles the Interaction Model and the
//! cluster handlers once.

use core::future::Future;
use core::marker::PhantomData;
use core::pin::pin;

use rs_matter_crypto::Crypto;
use rs_matter_dm::clusters::eth_diag::EthDiag;
use rs_matter_dm::clusters::gen_diag::{GenDiag, NetifDiag};
use rs_matter_dm::clusters::net_comm::{
    NetCtl, NetCtlStatus, NetworkCommissioningStatusEnum, NetworkType, Networks,
};
use rs_matter_dm::clusters::thread_diag::ThreadDiag;
use rs_matter_dm::clusters::wifi_diag::{WifiDiag, WirelessDiag};
use rs_matter_dm::endpoints::any_net_handler;
use rs_matter_dm::networks::any::{AnyNetCtl, AnyNetworks, InactiveDiag};
use rs_matter_dm::networks::eth::{EthNetCtl, EthNetwork};
use rs_matter_dm::networks::wireless::{
    connect_once, NetCtlWithStatusImpl, Thread, WirelessNetworks, MAX_CREDS_SIZE,
};
use rs_matter_dm::networks::NetChangeNotif;
use rs_matter_dm_core::persist::{KvBlobStore, KvBlobStoreAccess, NETWORKS_KEY};
use rs_matter_dm_core::DataModel;
use rs_matter_transport::network::btp::Btp;
use rs_matter_transport::network::NoNetwork;
use rs_matter_utils::error::{Error, ErrorCode};
use rs_matter_utils::futures::{select, select3, select4, Coalesce};
use rs_matter_utils::sync::MaybeSend;

use crate::ble::GattPeripheral;
use crate::eth::{EthernetDriver, EthernetTask};
use crate::mdns::Mdns;
use crate::net::NetStack;
use crate::network::{AnyStackNetwork, Embedding, StackNetwork};
use crate::wireless::{
    GattDriver, GattTask, MatterStackWirelessTask, ThreadCoexDriver, ThreadCoexTask, ThreadDriver,
    ThreadTask, UntilBleCommWindow, WifiCoexDriver, WifiCoexTask, WifiDriver, WifiTask,
    WirelessNetCtl,
};
use crate::{alloc_init, pin_alloc, MatterStack, RunOptions, UserTask};

/// A driver for Ethernet, Wifi or Thread, whichever it runs.
///
/// The stack runs it through the driver trait of that network, which each run method
/// names in its bounds. It hands the handler the controller the driver gives it, as an
/// `AnyNetCtl` of `WifiCtl` and `ThreadCtl`, so that the data model handler is the same
/// type on all three networks and is compiled once. So these must be the types the Wifi
/// and Thread drivers hand the stack.
pub trait AnyDriver: MaybeSend {
    /// The network controller the Wifi driver hands the stack.
    type WifiCtl<'a>: NetCtl + WifiDiag + NetChangeNotif
    where
        Self: 'a;

    /// The network controller the Thread driver hands the stack.
    type ThreadCtl<'a>: NetCtl + ThreadDiag + NetChangeNotif
    where
        Self: 'a;

    /// The network the driver runs.
    fn net_type(&self) -> NetworkType;
}

impl<T> AnyDriver for &mut T
where
    T: AnyDriver,
{
    type WifiCtl<'a>
        = T::WifiCtl<'a>
    where
        Self: 'a;

    type ThreadCtl<'a>
        = T::ThreadCtl<'a>
    where
        Self: 'a;

    fn net_type(&self) -> NetworkType {
        (**self).net_type()
    }
}

/// A driver for Ethernet (`E`), Wifi (`W`) or Thread (`T`), whichever the node runs.
///
/// The controller types of its Wifi and Thread drivers are their `WifiDriver` and
/// `ThreadDriver` ones, so those must also be what their coex runs hand the stack. `E` is
/// `NoEthernet` for a node without Ethernet.
pub enum AnyNetDriver<E, W, T> {
    Eth(E),
    Wifi(W),
    Thread(T),
}

impl<E, W, T> AnyDriver for AnyNetDriver<E, W, T>
where
    E: MaybeSend,
    W: WifiDriver,
    T: ThreadDriver,
{
    type WifiCtl<'a>
        = W::NetCtl<'a>
    where
        Self: 'a;

    type ThreadCtl<'a>
        = T::NetCtl<'a>
    where
        Self: 'a;

    fn net_type(&self) -> NetworkType {
        match self {
            Self::Eth(_) => NetworkType::Ethernet,
            Self::Wifi(_) => NetworkType::Wifi,
            Self::Thread(_) => NetworkType::Thread,
        }
    }
}

impl<E, W, T> EthernetDriver for AnyNetDriver<E, W, T>
where
    E: EthernetDriver,
    W: MaybeSend,
    T: MaybeSend,
{
    async fn run<A>(&mut self, task: A) -> Result<(), Error>
    where
        A: EthernetTask,
    {
        match self {
            Self::Eth(driver) => EthernetDriver::run(driver, task).await,
            _ => Err(ErrorCode::InvalidAction.into()),
        }
    }
}

impl<E, W, T> WifiCoexDriver for AnyNetDriver<E, W, T>
where
    E: MaybeSend,
    W: WifiCoexDriver,
    T: MaybeSend,
{
    async fn run<A>(&mut self, task: A) -> Result<(), Error>
    where
        A: WifiCoexTask,
    {
        match self {
            Self::Wifi(driver) => WifiCoexDriver::run(driver, task).await,
            _ => Err(ErrorCode::InvalidAction.into()),
        }
    }
}

impl<E, W, T> ThreadCoexDriver for AnyNetDriver<E, W, T>
where
    E: MaybeSend,
    W: MaybeSend,
    T: ThreadCoexDriver,
{
    async fn run<A>(&mut self, task: A) -> Result<(), Error>
    where
        A: ThreadCoexTask,
    {
        match self {
            Self::Thread(driver) => ThreadCoexDriver::run(driver, task).await,
            _ => Err(ErrorCode::InvalidAction.into()),
        }
    }
}

impl<E, W, T> WifiDriver for AnyNetDriver<E, W, T>
where
    E: MaybeSend,
    W: WifiDriver,
    T: MaybeSend,
{
    type NetCtl<'a>
        = W::NetCtl<'a>
    where
        Self: 'a;

    async fn run<A>(&mut self, task: A) -> Result<(), Error>
    where
        A: WifiTask,
    {
        match self {
            Self::Wifi(driver) => WifiDriver::run(driver, task).await,
            _ => Err(ErrorCode::InvalidAction.into()),
        }
    }
}

impl<E, W, T> ThreadDriver for AnyNetDriver<E, W, T>
where
    E: MaybeSend,
    W: MaybeSend,
    T: ThreadDriver,
{
    type NetCtl<'a>
        = T::NetCtl<'a>
    where
        Self: 'a;

    async fn run<A>(&mut self, task: A) -> Result<(), Error>
    where
        A: ThreadTask,
    {
        match self {
            Self::Thread(driver) => ThreadDriver::run(driver, task).await,
            _ => Err(ErrorCode::InvalidAction.into()),
        }
    }
}

impl<E, W, T> GattDriver for AnyNetDriver<E, W, T>
where
    E: MaybeSend,
    W: GattDriver,
    T: GattDriver,
{
    async fn run<A>(&mut self, task: A) -> Result<(), Error>
    where
        A: GattTask,
    {
        match self {
            Self::Wifi(driver) => GattDriver::run(driver, task).await,
            Self::Thread(driver) => GattDriver::run(driver, task).await,
            Self::Eth(_) => Err(ErrorCode::InvalidAction.into()),
        }
    }
}

/// The controller type the handler of an `AnyDriver`'s network is built with.
type AnyCtl<'a, W> = AnyNetCtl<'a, <W as AnyDriver>::WifiCtl<'a>, <W as AnyDriver>::ThreadCtl<'a>>;

impl<const B: usize, S, E> MatterStack<'_, B, S, E>
where
    S: AnyStackNetwork,
    E: Embedding,
{
    /// Run the Matter stack over Ethernet, Wifi or Thread, whichever `driver` runs: on
    /// Wifi and Thread with BLE alongside it, for concurrent commissioning; on Ethernet
    /// over the IP network alone.
    ///
    /// The networks store must be for the network the driver runs, if it knows its type.
    ///
    /// # Arguments
    /// - `driver` - a user-provided `AnyDriver` implementation
    /// - `crypto` - a user-provided `Crypto` implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation
    /// - `options` - the optional settings: `()` for the defaults, a `UserTask`, or an `Options`
    pub async fn run<W, C, H, K, O>(
        &self,
        mut driver: W,
        crypto: C,
        handler: H,
        kv: K,
        options: O,
    ) -> Result<(), Error>
    where
        W: AnyDriver + EthernetDriver + ThreadCoexDriver + WifiCoexDriver,
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
        O: RunOptions,
    {
        let _lock = self.run_lock.lock().await;

        // Lent to the Network Commissioning handler
        let mut networks = self.networks.lock().await;

        let net_type = check_net_type(&*networks, driver.net_type())?;

        info!("Matter Stack memory: {}b", core::mem::size_of_val(self));

        // Since this is the last code executed in the method, resetting the allocator should be safe
        // because all boxes returned by it should be dropped by then
        let _defer = scopeguard::guard((), |_| unsafe {
            self.bump.reset();
        });

        self.matter().reset_transport()?;

        let (gen_diag, user) = options.into_parts();

        let btp = (net_type != NetworkType::Ethernet).then(|| alloc_init!(self.bump, Btp::init()));

        let net_task = pin_alloc!(
            self.bump,
            self.any_task(
                &mut networks,
                btp.as_deref(),
                &mut driver,
                net_type,
                crypto,
                handler,
                kv,
                &gen_diag,
                user
            )
        );

        net_task.await
    }

    /// Run the Matter stack over Ethernet, Wifi or Thread, whichever `driver` runs: on
    /// Wifi and Thread with BLE while a commissioning window is open, and then the
    /// operational network, for non-concurrent commissioning; on Ethernet over the IP
    /// network alone.
    ///
    /// The networks store must be for the network the driver runs, if it knows its type.
    ///
    /// # Arguments
    /// - `driver` - a user-provided `AnyDriver` implementation
    /// - `crypto` - a user-provided `Crypto` implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation
    /// - `options` - the optional settings: `()` for the defaults, a `UserTask`, or an `Options`
    pub async fn run_no_coex<W, C, H, K, O>(
        &self,
        driver: W,
        crypto: C,
        handler: H,
        kv: K,
        options: O,
    ) -> Result<(), Error>
    where
        W: AnyDriver + EthernetDriver + GattDriver + ThreadDriver + WifiDriver,
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
        O: RunOptions,
    {
        let _lock = self.run_lock.lock().await;

        // Lent to the Network Commissioning handler of each phase
        let mut networks = self.networks.lock().await;

        let net_type = check_net_type(&*networks, driver.net_type())?;

        info!("Matter Stack memory: {}b", core::mem::size_of_val(self));

        // Since this is the last code executed in the method, resetting the allocator should be safe
        // because all boxes returned by it should be dropped by then
        let _defer = scopeguard::guard((), |_| unsafe {
            self.bump.reset();
        });

        self.matter().reset_transport()?;

        let (gen_diag, user) = options.into_parts();

        let btp = (net_type != NetworkType::Ethernet).then(|| alloc_init!(self.bump, Btp::init()));

        let net_task = pin_alloc!(
            self.bump,
            self.any_no_coex_task(
                &mut networks,
                btp.as_deref(),
                driver,
                net_type,
                crypto,
                handler,
                kv,
                &gen_diag,
                user
            )
        );

        net_task.await
    }

    /// Run the Matter stack over Ethernet, Wifi or Thread, whichever `driver` runs,
    /// without BLE.
    ///
    /// This is meant for a commissioned device. A commissioning window is advertised over
    /// the operational network only, so an uncommissioned device on Wifi or Thread can only
    /// be commissioned if its interface is connected by other means.
    ///
    /// The networks store must be for the network the driver runs, if it knows its type.
    ///
    /// # Arguments
    /// - `driver` - a user-provided `AnyDriver` implementation
    /// - `crypto` - a user-provided `Crypto` implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation
    /// - `options` - the optional settings: `()` for the defaults, a `UserTask`, or an `Options`
    pub async fn run_oper<W, C, H, K, O>(
        &self,
        mut driver: W,
        crypto: C,
        handler: H,
        kv: K,
        options: O,
    ) -> Result<(), Error>
    where
        W: AnyDriver + EthernetDriver + ThreadDriver + WifiDriver,
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
        O: RunOptions,
    {
        let _lock = self.run_lock.lock().await;

        // Lent to the Network Commissioning handler
        let mut networks = self.networks.lock().await;

        let net_type = check_net_type(&*networks, driver.net_type())?;

        info!("Matter Stack memory: {}b", core::mem::size_of_val(self));

        if !self.matter().has_fabrics() && net_type != NetworkType::Ethernet {
            warn!("Device is not commissioned; without BLE it is reachable only if its network is connected by other means");
        }

        // Since this is the last code executed in the method, resetting the allocator should be safe
        // because all boxes returned by it should be dropped by then
        let _defer = scopeguard::guard((), |_| unsafe {
            self.bump.reset();
        });

        self.matter().reset_transport()?;

        let (gen_diag, user) = options.into_parts();

        let net_task = pin_alloc!(
            self.bump,
            self.any_oper_task(
                &mut networks,
                &mut driver,
                net_type,
                crypto,
                handler,
                kv,
                &gen_diag,
                user
            )
        );

        net_task.await
    }

    #[allow(clippy::too_many_arguments)]
    fn any_task<'t, W, C, H, K, U>(
        &'t self,
        networks: &'t mut S::Store,
        btp: Option<&'t Btp>,
        driver: &'t mut W,
        net_type: NetworkType,
        crypto: C,
        handler: H,
        kv: K,
        gen_diag: &'t dyn GenDiag,
        user: U,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        W: AnyDriver + EthernetDriver + ThreadCoexDriver + WifiCoexDriver + 't,
        C: Crypto + 't,
        H: DataModel + 't,
        K: KvBlobStoreAccess + 't,
        U: UserTask + 't,
    {
        let task = MatterStackWirelessTask::<'_, _, AnyNetwork, _, _, _, _, _, _, AnyCtl<'t, W>> {
            stack: self,
            gen_diag,
            networks,
            net_type,
            btp,
            crypto,
            handler,
            kv,
            user_task: user,
            _network: PhantomData,
            _net_ctl: PhantomData,
        };

        async move {
            match net_type {
                NetworkType::Ethernet => EthernetDriver::run(driver, task).await,
                NetworkType::Wifi => WifiCoexDriver::run(driver, task).await,
                NetworkType::Thread => ThreadCoexDriver::run(driver, task).await,
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn any_no_coex_task<'t, W, C, H, K, U>(
        &'t self,
        networks: &'t mut S::Store,
        btp: Option<&'t Btp>,
        mut driver: W,
        net_type: NetworkType,
        crypto: C,
        handler: H,
        kv: K,
        gen_diag: &'t dyn GenDiag,
        mut user: U,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        W: AnyDriver + EthernetDriver + GattDriver + ThreadDriver + WifiDriver + 't,
        C: Crypto + 't,
        H: DataModel + 't,
        K: KvBlobStoreAccess + 't,
        U: UserTask + 't,
    {
        async move {
            if net_type == NetworkType::Ethernet {
                return EthernetDriver::run(
                    &mut driver,
                    MatterStackWirelessTask::<'_, _, AnyNetwork, _, _, _, _, _, _, AnyCtl<'_, W>> {
                        stack: self,
                        gen_diag,
                        networks: &mut *networks,
                        net_type,
                        btp,
                        crypto: &crypto,
                        handler: &handler,
                        kv: &kv,
                        user_task: &mut user,
                        _network: PhantomData,
                        _net_ctl: PhantomData,
                    },
                )
                .await;
            }

            loop {
                // BLE carries a commissioning window that the device opened for itself; one that an
                // administrator re-opened over CASE is advertised over the operational IP network
                // alone.
                if self
                    .matter()
                    .comm_window_state()
                    .is_open_on_all_transports()
                {
                    self.reset_net_ctl_state();

                    GattDriver::run(
                        &mut driver,
                        MatterStackWirelessTask::<
                            '_,
                            _,
                            AnyNetwork,
                            _,
                            _,
                            _,
                            _,
                            _,
                            _,
                            AnyCtl<'_, W>,
                        > {
                            stack: self,
                            gen_diag,
                            networks: &mut *networks,
                            net_type,
                            btp,
                            crypto: &crypto,
                            handler: &handler,
                            kv: &kv,
                            user_task: &mut user,
                            _network: PhantomData,
                            _net_ctl: PhantomData,
                        },
                    )
                    .await?;
                }

                let task = UntilBleCommWindow {
                    stack: self,
                    task: MatterStackWirelessTask::<
                        '_,
                        _,
                        AnyNetwork,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        AnyCtl<'_, W>,
                    > {
                        stack: self,
                        gen_diag,
                        networks: &mut *networks,
                        net_type,
                        btp,
                        crypto: &crypto,
                        handler: &handler,
                        kv: &kv,
                        user_task: &mut user,
                        _network: PhantomData,
                        _net_ctl: PhantomData,
                    },
                };

                if net_type == NetworkType::Wifi {
                    WifiDriver::run(&mut driver, task).await?;
                } else {
                    ThreadDriver::run(&mut driver, task).await?;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn any_oper_task<'t, W, C, H, K, U>(
        &'t self,
        networks: &'t mut S::Store,
        driver: &'t mut W,
        net_type: NetworkType,
        crypto: C,
        handler: H,
        kv: K,
        gen_diag: &'t dyn GenDiag,
        user: U,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        W: AnyDriver + EthernetDriver + ThreadDriver + WifiDriver + 't,
        C: Crypto + 't,
        H: DataModel + 't,
        K: KvBlobStoreAccess + 't,
        U: UserTask + 't,
    {
        // There is no BLE phase, and the task is not wrapped in `UntilBleCommWindow`, so it
        // never hands the radio over.
        let task = MatterStackWirelessTask::<'_, _, AnyNetwork, _, _, _, _, _, _, AnyCtl<'t, W>> {
            stack: self,
            gen_diag,
            networks,
            net_type,
            btp: None,
            crypto,
            handler,
            kv,
            user_task: user,
            _network: PhantomData,
            _net_ctl: PhantomData,
        };

        async move {
            match net_type {
                NetworkType::Ethernet => EthernetDriver::run(driver, task).await,
                NetworkType::Wifi => WifiDriver::run(driver, task).await,
                NetworkType::Thread => ThreadDriver::run(driver, task).await,
            }
        }
    }
}

impl<const B: usize, const N: usize, S, E> MatterStack<'_, B, S, E>
where
    S: StackNetwork<Store = AnyNetworks<N>>,
    E: Embedding,
{
    /// Pick the network to run: the one the saved networks are for, or `default` if none
    /// are saved, as the node was never commissioned or was reset since. The networks
    /// store is set to it, so build the driver for the network returned.
    ///
    /// # Arguments
    /// - `store` - the BLOB store the networks are saved in
    /// - `buf` - a scratch buffer for loading the saved networks
    /// - `default` - the network to run if none are saved
    pub async fn select_net_type<K>(
        &self,
        store: K,
        buf: &mut [u8],
        default: NetworkType,
    ) -> Result<NetworkType, Error>
    where
        K: KvBlobStore,
    {
        let net_type = WirelessNetworks::<N, Thread>::persisted_net_type(store, NETWORKS_KEY, buf)
            .await?
            .unwrap_or(default);

        self.networks(|networks| networks.set_net_type(net_type))
            .await;

        Ok(net_type)
    }
}

/// The marker of the stack's tasks that run Ethernet, Wifi or Thread, whichever the
/// driver runs.
pub(crate) struct AnyNetwork;

impl<'a, const B: usize, S, E, C, H, K, X, Z>
    MatterStackWirelessTask<'a, B, AnyNetwork, S, E, C, H, K, X, Z>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
{
    /// Run Wifi or Thread with BLE alongside it.
    #[allow(clippy::too_many_arguments)]
    async fn run_coex<T, N, Q, D, G>(
        &mut self,
        net_stack: T,
        netif: N,
        net_ctl: &Q,
        wifi_diag: &dyn WifiDiag,
        thread_diag: &dyn ThreadDiag,
        mut mdns: D,
        mut gatt: G,
    ) -> Result<(), Error>
    where
        T: NetStack,
        N: NetifDiag + NetChangeNotif,
        Q: NetCtl + NetCtlStatus + WirelessDiag + NetChangeNotif,
        D: Mdns,
        G: GattPeripheral,
    {
        // The Network Commissioning handler drives the maintenance `WirelessMgr`
        // with the operational `net_ctl`; `run_net_coex` only runs the BTP coex
        // transport.
        let combined = any_net_handler(
            &self.stack.matter,
            &true,
            self.gen_diag,
            &netif,
            &InactiveDiag,
            wifi_diag,
            thread_diag,
            &mut *self.networks,
            net_ctl,
            &self.handler,
            self.crypto.weak_rand()?,
        );
        let im = self
            .stack
            .im(&self.crypto, (&self.handler, combined), &self.kv);

        let stack = &self.stack;
        let bump = &stack.bump;

        let mut net_task = pin_alloc!(
            bump,
            stack.run_net_coex(
                unwrap!(self.btp),
                &self.crypto,
                &net_stack,
                &netif,
                &mut mdns,
                &mut gatt
            )
        );

        let mut im_task = pin_alloc!(bump, self.stack.run_im_with_bump(&im));

        let mut user_task = pin_alloc!(bump, self.user_task.run(&net_stack, &netif));

        select3(&mut net_task, &mut im_task, &mut user_task)
            .coalesce()
            .await
    }

    /// Run Wifi or Thread without BLE: after the BLE phase of non-concurrent
    /// commissioning, or with BLE off altogether.
    async fn run_oper<T, N, Q, D>(
        &mut self,
        net_stack: T,
        netif: N,
        net_ctl: &Q,
        wifi_diag: &dyn WifiDiag,
        thread_diag: &dyn ThreadDiag,
        mut mdns: D,
    ) -> Result<(), Error>
    where
        T: NetStack,
        N: NetifDiag + NetChangeNotif,
        Q: NetCtl + NetCtlStatus + WirelessDiag + NetChangeNotif,
        D: Mdns,
    {
        // In non-concurrent commissioning the commissioner's `ConnectNetwork` arrives
        // while the operational network cannot run yet, so the connect is deferred to
        // here, before commissioning completes. The handler's connection manager only
        // connects once the device is commissioned. `is_prov_ready()` is true only in
        // this pending case.
        let deferred_connect_id = self.stack.net_state.lock(|state| {
            let state = state.borrow();
            state.is_prov_ready().then(|| state.network_id.clone())
        });

        if let Some(network_id) = deferred_connect_id {
            info!("Non-concurrent commissioning: performing the deferred connect");

            let mut buf = [0u8; MAX_CREDS_SIZE];

            connect_once(&mut *self.networks, net_ctl, &network_id, &mut buf).await?;
        }

        // The Network Commissioning handler drives the maintenance `WirelessMgr`
        // with the operational `net_ctl`.
        let combined = any_net_handler(
            &self.stack.matter,
            &false,
            self.gen_diag,
            &netif,
            &InactiveDiag,
            wifi_diag,
            thread_diag,
            &mut *self.networks,
            net_ctl,
            &self.handler,
            self.crypto.weak_rand()?,
        );
        let im = self
            .stack
            .im(&self.crypto, (&self.handler, combined), &self.kv);

        let stack = &self.stack;

        let mut net_task = pin!(stack.run_oper_net(
            &self.crypto,
            &net_stack,
            0, // TODO
            core::future::pending(),
            Option::<(NoNetwork, NoNetwork)>::None
        ));

        let mut mdns_task =
            pin!(stack.run_oper_netif_mdns(&self.crypto, &net_stack, &netif, &mut mdns));

        let mut im_task = pin!(self.stack.run_im(&im));

        let mut user_task = pin!(self.user_task.run(&net_stack, &netif));

        select4(&mut net_task, &mut mdns_task, &mut im_task, &mut user_task)
            .coalesce()
            .await
    }
}

impl<'a, 'n, const B: usize, S, E, C, H, K, X, WQ, TQ> ThreadCoexTask
    for MatterStackWirelessTask<'a, B, AnyNetwork, S, E, C, H, K, X, AnyNetCtl<'n, WQ, TQ>>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
    WQ: NetCtl + WifiDiag + NetChangeNotif,
    TQ: NetCtl + ThreadDiag + NetChangeNotif,
{
    async fn run<T, N, Q, D, G>(
        &mut self,
        net_stack: T,
        netif: N,
        net_ctl: Q,
        mdns: D,
        gatt: G,
    ) -> Result<(), Error>
    where
        T: NetStack,
        N: NetifDiag + NetChangeNotif,
        Q: NetCtl + ThreadDiag + NetChangeNotif,
        D: Mdns,
        G: GattPeripheral,
    {
        info!("Thread and BLE drivers started");

        let ctl = AnyNetCtl::<WQ, Q>::Thread(net_ctl);
        let net_ctl =
            NetCtlWithStatusImpl::new(&self.stack.net_state, WirelessNetCtl::Operational(&ctl));

        self.run_coex(
            net_stack,
            netif,
            &net_ctl,
            &InactiveDiag,
            &net_ctl,
            mdns,
            gatt,
        )
        .await
    }
}

impl<'a, 'n, const B: usize, S, E, C, H, K, X, WQ, TQ> WifiCoexTask
    for MatterStackWirelessTask<'a, B, AnyNetwork, S, E, C, H, K, X, AnyNetCtl<'n, WQ, TQ>>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
    WQ: NetCtl + WifiDiag + NetChangeNotif,
    TQ: NetCtl + ThreadDiag + NetChangeNotif,
{
    async fn run<T, N, Q, D, G>(
        &mut self,
        net_stack: T,
        netif: N,
        net_ctl: Q,
        mdns: D,
        gatt: G,
    ) -> Result<(), Error>
    where
        T: NetStack,
        N: NetifDiag + NetChangeNotif,
        Q: NetCtl + WifiDiag + NetChangeNotif,
        D: Mdns,
        G: GattPeripheral,
    {
        info!("Wifi and BLE drivers started");

        let ctl = AnyNetCtl::<Q, TQ>::Wifi(net_ctl);
        let net_ctl =
            NetCtlWithStatusImpl::new(&self.stack.net_state, WirelessNetCtl::Operational(&ctl));

        self.run_coex(
            net_stack,
            netif,
            &net_ctl,
            &net_ctl,
            &InactiveDiag,
            mdns,
            gatt,
        )
        .await
    }
}

impl<'a, 'n, const B: usize, S, E, C, H, K, X, WQ, TQ> ThreadTask
    for MatterStackWirelessTask<'a, B, AnyNetwork, S, E, C, H, K, X, AnyNetCtl<'n, WQ, TQ>>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
    WQ: NetCtl + WifiDiag + NetChangeNotif,
    TQ: NetCtl + ThreadDiag + NetChangeNotif,
{
    async fn run<T, N, Q, D>(
        &mut self,
        net_stack: T,
        netif: N,
        net_ctl: Q,
        mdns: D,
    ) -> Result<(), Error>
    where
        T: NetStack,
        N: NetifDiag + NetChangeNotif,
        Q: NetCtl + ThreadDiag + NetChangeNotif,
        D: Mdns,
    {
        info!("Thread driver started");

        let ctl = AnyNetCtl::<WQ, Q>::Thread(net_ctl);
        let net_ctl =
            NetCtlWithStatusImpl::new(&self.stack.net_state, WirelessNetCtl::Operational(&ctl));

        self.run_oper(net_stack, netif, &net_ctl, &InactiveDiag, &net_ctl, mdns)
            .await
    }
}

impl<'a, 'n, const B: usize, S, E, C, H, K, X, WQ, TQ> WifiTask
    for MatterStackWirelessTask<'a, B, AnyNetwork, S, E, C, H, K, X, AnyNetCtl<'n, WQ, TQ>>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
    WQ: NetCtl + WifiDiag + NetChangeNotif,
    TQ: NetCtl + ThreadDiag + NetChangeNotif,
{
    async fn run<T, N, Q, D>(
        &mut self,
        net_stack: T,
        netif: N,
        net_ctl: Q,
        mdns: D,
    ) -> Result<(), Error>
    where
        T: NetStack,
        N: NetifDiag + NetChangeNotif,
        Q: NetCtl + WifiDiag + NetChangeNotif,
        D: Mdns,
    {
        info!("Wifi driver started");

        let ctl = AnyNetCtl::<Q, TQ>::Wifi(net_ctl);
        let net_ctl =
            NetCtlWithStatusImpl::new(&self.stack.net_state, WirelessNetCtl::Operational(&ctl));

        self.run_oper(net_stack, netif, &net_ctl, &net_ctl, &InactiveDiag, mdns)
            .await
    }
}

impl<'a, 'n, const B: usize, S, E, C, H, K, X, WQ, TQ> EthernetTask
    for MatterStackWirelessTask<'a, B, AnyNetwork, S, E, C, H, K, X, AnyNetCtl<'n, WQ, TQ>>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
    WQ: NetCtl + WifiDiag + NetChangeNotif,
    TQ: NetCtl + ThreadDiag + NetChangeNotif,
{
    async fn run<N, I, D, M>(
        &mut self,
        net_stack: N,
        netif: I,
        eth_diag: D,
        mut mdns: M,
    ) -> Result<(), Error>
    where
        N: NetStack,
        I: NetifDiag + NetChangeNotif,
        D: EthDiag,
        M: Mdns,
    {
        info!("Ethernet driver started");

        // The wired interface is up whenever the node runs, as `EthNetCtl` reports it.
        self.stack.net_state.lock(|state| {
            let mut state = state.borrow_mut();

            state.network_id.clear();
            unwrap!(state
                .network_id
                .extend_from_slice(EthNetwork::DEFAULT_ID.as_bytes()));
            state.networking_status = Some(NetworkCommissioningStatusEnum::Success);
            state.connect_error_value = None;
        });

        let ctl = AnyNetCtl::<WQ, TQ>::Eth(EthNetCtl::new_default());
        let net_ctl =
            NetCtlWithStatusImpl::new(&self.stack.net_state, WirelessNetCtl::Operational(&ctl));

        let combined = any_net_handler(
            &self.stack.matter,
            &false,
            self.gen_diag,
            &netif,
            &eth_diag,
            &InactiveDiag,
            &InactiveDiag,
            &mut *self.networks,
            &net_ctl,
            &self.handler,
            self.crypto.weak_rand()?,
        );
        let im = self
            .stack
            .im(&self.crypto, (&self.handler, combined), &self.kv);

        let mut net_task = pin_alloc!(
            self.stack.bump,
            self.stack.run_oper_net(
                &self.crypto,
                &net_stack,
                0, // TODO
                core::future::pending(),
                Option::<(NoNetwork, NoNetwork)>::None,
            )
        );

        let mut mdns_task = pin_alloc!(
            self.stack.bump,
            self.stack
                .run_oper_netif_mdns(&self.crypto, &net_stack, &netif, &mut mdns)
        );

        let mut im_task = pin_alloc!(self.stack.bump, self.stack.run_im_with_bump(&im));

        let mut user_task = pin_alloc!(self.stack.bump, self.user_task.run(&net_stack, &netif));

        select4(&mut net_task, &mut mdns_task, &mut im_task, &mut user_task)
            .coalesce()
            .await
    }
}

impl<'a, 'n, const B: usize, S, E, C, H, K, X, WQ, TQ> GattTask
    for MatterStackWirelessTask<'a, B, AnyNetwork, S, E, C, H, K, X, AnyNetCtl<'n, WQ, TQ>>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: MaybeSend,
    WQ: NetCtl + WifiDiag + NetChangeNotif,
    TQ: NetCtl + ThreadDiag + NetChangeNotif,
{
    async fn run<P>(&mut self, peripheral: P) -> Result<(), Error>
    where
        P: GattPeripheral,
    {
        let net_ctl = NetCtlWithStatusImpl::new(
            &self.stack.net_state,
            WirelessNetCtl::<AnyNetCtl<'n, WQ, TQ>>::Commissioning(self.net_type),
        );

        let (wifi_diag, thread_diag): (&dyn WifiDiag, &dyn ThreadDiag) =
            if self.net_type == NetworkType::Wifi {
                (&net_ctl, &InactiveDiag)
            } else {
                (&InactiveDiag, &net_ctl)
            };

        // No netif during the BLE phase; the operational network clusters are chained
        // on top of the user's handler with the commissioning net-ctl, and re-chained
        // with the operational one once Wifi or Thread is up.
        let combined = any_net_handler(
            &self.stack.matter,
            &false,
            self.gen_diag,
            &(),
            &InactiveDiag,
            wifi_diag,
            thread_diag,
            &mut *self.networks,
            &net_ctl,
            &self.handler,
            self.crypto.weak_rand()?,
        );
        let im = self
            .stack
            .im(&self.crypto, (&self.handler, combined), &self.kv);

        let mut btp_task = pin!(self
            .stack
            .run_btp(unwrap!(self.btp), &self.crypto, peripheral));

        let mut im_task = pin!(self.stack.run_im(&im));

        select(&mut btp_task, &mut im_task).coalesce().await
    }
}

/// Return `net_type`, the network the driver runs, unless the networks store is for
/// another network.
fn check_net_type<S>(networks: &S, net_type: NetworkType) -> Result<NetworkType, Error>
where
    S: Networks,
{
    match networks.net_type() {
        Some(stored) if stored != net_type => {
            error!(
                "The driver runs {:?}, but the networks store is for {:?}",
                net_type, stored
            );

            Err(ErrorCode::InvalidAction.into())
        }
        _ => Ok(net_type),
    }
}
