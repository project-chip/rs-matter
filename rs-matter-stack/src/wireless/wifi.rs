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

use core::future::Future;
use core::marker::PhantomData;
use core::pin::pin;

use rs_matter_crypto::Crypto;
use rs_matter_dm::clusters::gen_diag::{GenDiag, NetifDiag};
use rs_matter_dm::clusters::net_comm::{NetCtl, NetworkType, Networks};
use rs_matter_dm::clusters::wifi_diag::WifiDiag;
use rs_matter_dm::endpoints::wifi_net_handler;
use rs_matter_dm::networks::wireless::{
    self, connect_once, NetCtlWithStatusImpl, NoopWirelessNetCtl, WifiNetworks, MAX_CREDS_SIZE,
};
use rs_matter_dm::networks::NetChangeNotif;
use rs_matter_dm::root_endpoint;
use rs_matter_dm_core::persist::KvBlobStoreAccess;
use rs_matter_dm_core::{DataModel, Endpoint};
use rs_matter_transport::network::NoNetwork;
use rs_matter_utils::error::Error;
use rs_matter_utils::futures::{select, select3, select4, Coalesce};
use rs_matter_utils::sync::MaybeSend;

use crate::mdns::Mdns;
use crate::net::NetStack;
use crate::network::Embedding;
use crate::wireless::{
    GattPeripheral, MatterStackWirelessTask, WirelessNetCtl, MAX_WIRELESS_NETWORKS,
};
use crate::{pin_alloc, RunOptions, UserTask};

use super::{GattDriver, GattTask, PreexistingWireless, WirelessMatterStack};

/// A type alias for a Matter stack running over Wifi (and BLE, during commissioning).
///
/// `S` is the networks store of the Wifi interface.
pub type WifiMatterStack<'a, const B: usize, E = (), S = WifiNetworks<MAX_WIRELESS_NETWORKS>> =
    WirelessMatterStack<'a, B, wireless::Wifi, E, S>;

impl<const B: usize, S, E> WirelessMatterStack<'_, B, wireless::Wifi, E, S>
where
    S: Networks + Embedding,
    E: Embedding,
{
    /// Run the Matter stack for an already pre-established wireless network where the BLE and the Wifi stacks can co-exist.
    ///
    /// # Arguments
    /// - `net_stack` - a user-provided `NetStack` implementation
    /// - `netif` - a user-provided `Netif` implementation
    /// - `controller` - a user-provided `Controller` implementation
    /// - `mdns` - a user-provided `Mdns` implementation
    /// - `gatt` - a user-provided `GattPeripheral` implementation
    /// - `crypto` - a user-provided `Crypto` implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation
    /// - `options` - the optional settings: `()` for the defaults, a `UserTask`, or an `Options`
    #[allow(clippy::too_many_arguments)]
    pub fn run_preex<'t, U, N, Q, D, G, C, H, K, O>(
        &'t self,
        net_stack: U,
        netif: N,
        net_ctl: Q,
        mdns: D,
        gatt: G,
        crypto: C,
        handler: H,
        kv: K,
        options: O,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        U: NetStack + 't,
        N: NetifDiag + NetChangeNotif + 't,
        Q: NetCtl + WifiDiag + NetChangeNotif + 't,
        D: Mdns + 't,
        G: GattPeripheral + 't,
        C: Crypto + 't,
        H: DataModel + 't,
        K: KvBlobStoreAccess + 't,
        O: RunOptions + 't,
    {
        self.run_coex(
            PreexistingWireless::new(net_stack, netif, net_ctl, mdns, gatt),
            crypto,
            handler,
            kv,
            options,
        )
    }

    /// Run the Matter stack for a wireless network where the BLE and the Wifi stacks can co-exist.
    ///
    /// # Arguments
    /// - `wifi` - a user-provided `WifiCoex` implementation
    /// - `crypto` - a user-provided `Crypto` implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation
    /// - `options` - the optional settings: `()` for the defaults, a `UserTask`, or an `Options`
    pub async fn run_coex<W, C, H, K, O>(
        &self,
        mut wifi: W,
        crypto: C,
        handler: H,
        kv: K,
        options: O,
    ) -> Result<(), Error>
    where
        W: WifiCoexDriver,
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
        O: RunOptions,
    {
        let _lock = self.run_lock.lock().await;

        // Lent to the Network Commissioning handler of each phase
        let mut networks = self.network.networks.lock().await;

        info!("Matter Stack memory: {}b", core::mem::size_of_val(self));

        // Since this is the last code executed in the method, resetting the allocator should be safe
        // because all boxes returned by it should be dropped by then
        let _defer = scopeguard::guard((), |_| unsafe {
            self.bump.reset();
        });

        self.matter().reset_transport()?;

        let (gen_diag, user) = options.into_parts();

        let net_task = pin_alloc!(
            self.bump,
            self.run_wifi_coex(
                &mut networks,
                &mut wifi,
                crypto,
                handler,
                kv,
                &gen_diag,
                user
            )
        );

        net_task.await
    }

    /// Run the Matter stack for a wireless network where the BLE and the Wifi stacks cannot co-exist.
    ///
    /// # Arguments
    /// - `wifi` - a user-provided `Wifi` + `Gatt` implementation
    /// - `crypto` - a user-provided `Crypto` implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation
    /// - `options` - the optional settings: `()` for the defaults, a `UserTask`, or an `Options`
    pub async fn run<W, C, H, K, O>(
        &self,
        wifi: W,
        crypto: C,
        handler: H,
        kv: K,
        options: O,
    ) -> Result<(), Error>
    where
        W: WifiDriver + GattDriver,
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
        O: RunOptions,
    {
        let _lock = self.run_lock.lock().await;

        // Lent to the Network Commissioning handler of each phase
        let mut networks = self.network.networks.lock().await;

        info!("Matter Stack memory: {}b", core::mem::size_of_val(self));

        // Since this is the last code executed in the method, resetting the allocator should be safe
        // because all boxes returned by it should be dropped by then
        let _defer = scopeguard::guard((), |_| unsafe {
            self.bump.reset();
        });

        self.matter().reset_transport()?;

        let (gen_diag, user) = options.into_parts();

        let net_task = pin_alloc!(
            self.bump,
            self.run_wifi(&mut networks, wifi, crypto, handler, kv, &gen_diag, user)
        );

        net_task.await
    }

    #[allow(clippy::too_many_arguments)]
    fn run_wifi_coex<'t, W, C, H, K, U>(
        &'t self,
        networks: &'t mut S,
        wifi: &'t mut W,
        crypto: C,
        handler: H,
        kv: K,
        gen_diag: &'t dyn GenDiag,
        user: U,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        W: WifiCoexDriver,
        C: Crypto + 't,
        H: DataModel + 't,
        K: KvBlobStoreAccess + 't,
        U: UserTask + 't,
    {
        // The coex task never builds a `WirelessNetCtl` chain via `Q`, so its
        // phantom net-ctl type is an irrelevant placeholder.
        // `&kv` is also lent to the driver so it can persist its own state.
        wifi.run(
            MatterStackWirelessTask::<'_, _, _, _, _, _, _, _, _, NoopWirelessNetCtl> {
                stack: self,
                gen_diag,
                networks,
                crypto,
                handler,
                kv,
                user_task: user,
                _net_ctl: PhantomData,
            },
        )
    }

    #[allow(clippy::manual_async_fn, clippy::too_many_arguments)]
    fn run_wifi<'t, W, C, H, K, U>(
        &'t self,
        networks: &'t mut S,
        mut wifi: W,
        crypto: C,
        handler: H,
        kv: K,
        gen_diag: &'t dyn GenDiag,
        mut user: U,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        W: WifiDriver + GattDriver + 't,
        C: Crypto + 't,
        H: DataModel + 't,
        K: KvBlobStoreAccess + 't,
        U: UserTask + 't,
    {
        async move {
            loop {
                // BLE carries a commissioning window that the device opened for itself; one that an
                // administrator re-opened over CASE is advertised over the operational IP network
                // alone. Deliberately not `has_fabrics`: a commissioned device that re-opens a basic
                // window has to become reachable over BLE again, and an uncommissioned one whose
                // window has expired has nothing left to advertise.
                if self
                    .matter()
                    .comm_window_state()
                    .is_open_on_all_transports()
                {
                    self.reset_net_ctl_state();

                    GattDriver::run(
                        &mut wifi,
                        MatterStackWirelessTask::<
                            '_,
                            _,
                            _,
                            _,
                            _,
                            _,
                            _,
                            _,
                            _,
                            <W as WifiDriver>::NetCtl<'_>,
                        > {
                            stack: self,
                            gen_diag,
                            networks: &mut *networks,
                            crypto: &crypto,
                            handler: &handler,
                            kv: &kv,
                            user_task: &mut user,
                            _net_ctl: PhantomData,
                        },
                    )
                    .await?;
                }

                WifiDriver::run(
                    &mut wifi,
                    MatterStackWirelessTask::<
                        '_,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        <W as WifiDriver>::NetCtl<'_>,
                    > {
                        stack: self,
                        gen_diag,
                        networks: &mut *networks,
                        crypto: &crypto,
                        handler: &handler,
                        kv: &kv,
                        user_task: &mut user,
                        _net_ctl: PhantomData,
                    },
                )
                .await?;
            }
        }
    }

    /// Return a metadata for the root (Endpoint 0) of the Matter Node
    /// configured for BLE+Wifi network.
    pub const fn root_endpoint() -> Endpoint<'static> {
        const ENDPOINT: Endpoint<'static> = root_endpoint!(wifi);

        ENDPOINT
    }
}

/// A trait representing a task that needs access to the operational wireless interface (Wifi or Thread)
/// (Netif, UDP stack and Wireless controller) to perform its work.
pub trait WifiTask: MaybeSend {
    /// Run the task with the given network stack, network interface, wireless controller and mDNS
    fn run<S, N, C, M>(
        &mut self,
        net_stack: S,
        netif: N,
        net_ctl: C,
        mdns: M,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        C: NetCtl + WifiDiag + NetChangeNotif,
        M: Mdns;
}

impl<T> WifiTask for &mut T
where
    T: WifiTask,
{
    fn run<S, N, C, M>(
        &mut self,
        net_stack: S,
        netif: N,
        net_ctl: C,
        mdns: M,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        C: NetCtl + WifiDiag + NetChangeNotif,
        M: Mdns,
    {
        T::run(*self, net_stack, netif, net_ctl, mdns)
    }
}

/// A trait for running a task within a context where the wireless interface is initialized and operable
pub trait WifiDriver: MaybeSend {
    /// The Wifi network controller type this driver produces in its operational
    /// phase. Naming it here lets the commissioning and operational handler chains
    /// be built with the SAME `WirelessNetCtl<Self::NetCtl<'_>>` net-ctl type,
    /// yielding a single handler-chain monomorphization. The bound is Wifi's own
    /// (`WifiDiag`) — a Wifi controller is never asked to be a Thread one.
    type NetCtl<'a>: NetCtl + WifiDiag + NetChangeNotif
    where
        Self: 'a;

    /// Setup the radio to operate in wireless (Wifi or Thread) mode
    /// and run the given task.
    fn run<T>(&mut self, task: T) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        T: WifiTask;
}

impl<T> WifiDriver for &mut T
where
    T: WifiDriver,
{
    type NetCtl<'a>
        = T::NetCtl<'a>
    where
        Self: 'a;

    fn run<A>(&mut self, task: A) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        A: WifiTask,
    {
        T::run(self, task)
    }
}

/// A trait representing a task that needs access to the operational wireless interface (Wifi or Thread)
/// as well as to the commissioning BTP GATT peripheral.
///
/// Typically, tasks performing the Matter concurrent commissioning workflow will implement this trait.
pub trait WifiCoexTask: MaybeSend {
    /// Run the task with the given network stack, network interface, wireless controller and mDNS
    fn run<S, N, C, M, G>(
        &mut self,
        net_stack: S,
        netif: N,
        net_ctl: C,
        mdns: M,
        gatt: G,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        C: NetCtl + WifiDiag + NetChangeNotif,
        M: Mdns,
        G: GattPeripheral;
}

impl<T> WifiCoexTask for &mut T
where
    T: WifiCoexTask,
{
    fn run<S, N, C, M, G>(
        &mut self,
        net_stack: S,
        netif: N,
        net_ctl: C,
        mdns: M,
        gatt: G,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        C: NetCtl + WifiDiag + NetChangeNotif,
        M: Mdns,
        G: GattPeripheral,
    {
        T::run(*self, net_stack, netif, net_ctl, mdns, gatt)
    }
}

/// A trait for running a task within a context where both the wireless interface (Thread or Wifi)
/// is initialized and operable, as well as the BLE GATT peripheral is also operable.
///
/// Typically, tasks performing the Matter concurrent commissioning workflow will ran by implementations
/// of this trait.
pub trait WifiCoexDriver: MaybeSend {
    /// Setup the radio to operate in wireless coexist mode (Wifi or Thread + BLE)
    /// and run the given task.
    fn run<T>(&mut self, task: T) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        T: WifiCoexTask;
}

impl<T> WifiCoexDriver for &mut T
where
    T: WifiCoexDriver,
{
    fn run<A>(&mut self, task: A) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        A: WifiCoexTask,
    {
        T::run(self, task)
    }
}

impl<S, N, C, M, P> WifiDriver for PreexistingWireless<S, N, C, M, P>
where
    P: MaybeSend,
    S: NetStack,
    N: NetifDiag + NetChangeNotif,
    C: NetCtl + WifiDiag + NetChangeNotif,
    M: Mdns,
{
    // The task receives `&self.net_ctl` (a `&C`), so the chain net-ctl type is
    // `&'a C` (which satisfies the bounds via the blanket `impl Trait for &T`).
    type NetCtl<'a>
        = &'a C
    where
        Self: 'a;

    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: WifiTask,
    {
        task.run(&self.net_stack, &self.netif, &self.net_ctl, &mut self.mdns)
            .await
    }
}

impl<S, N, C, M, P> WifiCoexDriver for PreexistingWireless<S, N, C, M, P>
where
    S: NetStack,
    N: NetifDiag + NetChangeNotif,
    C: NetCtl + WifiDiag + NetChangeNotif,
    M: Mdns,
    P: GattPeripheral,
{
    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: WifiCoexTask,
    {
        task.run(
            &self.net_stack,
            &self.netif,
            &self.net_ctl,
            &mut self.mdns,
            &mut self.gatt,
        )
        .await
    }
}

impl<'a, const B: usize, S, E, C, H, K, U, Q> GattTask
    for MatterStackWirelessTask<'a, B, wireless::Wifi, S, E, C, H, K, U, Q>
where
    S: Networks + Embedding,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    U: MaybeSend,
    Q: NetCtl + WifiDiag + NetChangeNotif,
{
    async fn run<P>(&mut self, peripheral: P) -> Result<(), Error>
    where
        P: GattPeripheral,
    {
        let net_ctl = NetCtlWithStatusImpl::new(
            &self.stack.network.net_state,
            WirelessNetCtl::<Q>::Commissioning(NetworkType::Wifi),
        );

        // No netif during the BLE phase; the operational network clusters
        // are chained on top of the user's handler with the commissioning
        // net-ctl, and re-chained with the operational one once Wifi/Thread
        // is up (`WifiTask::run`).
        let combined = wifi_net_handler(
            &self.stack.matter,
            &false,
            self.gen_diag,
            &(),
            &net_ctl,
            &mut *self.networks,
            &net_ctl,
            &self.handler,
            self.crypto.weak_rand()?,
        );
        // The Network Commissioning handler keeps its connection manager dormant
        // while not commissioned, and the commissioning net-ctl defers connects.
        let im = self
            .stack
            .im(&self.crypto, (&self.handler, combined), &self.kv);

        let mut btp_task = pin!(self.stack.run_btp(&self.crypto, peripheral));

        let mut im_task = pin!(self.stack.run_im(&im));

        select(&mut btp_task, &mut im_task).coalesce().await
    }
}

impl<'a, const B: usize, S, E, C, H, K, X, Z> WifiTask
    for MatterStackWirelessTask<'a, B, wireless::Wifi, S, E, C, H, K, X, Z>
where
    S: Networks + Embedding,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
    Z: NetCtl + WifiDiag + NetChangeNotif,
{
    async fn run<T, N, Q, D>(
        &mut self,
        net_stack: T,
        netif: N,
        net_ctl: Q,
        mut mdns: D,
    ) -> Result<(), Error>
    where
        T: NetStack,
        N: NetifDiag + NetChangeNotif,
        Q: NetCtl + WifiDiag + NetChangeNotif,
        D: Mdns,
    {
        info!("Wifi driver started");

        let net_ctl_s = NetCtlWithStatusImpl::new(
            &self.stack.network.net_state,
            WirelessNetCtl::Operational(&net_ctl),
        );

        // Non-concurrent commissioning deferred connect. In BLE-only commissioning
        // the commissioner's `ConnectNetwork` is deferred (Wifi can't run during
        // BLE) and must be replayed once the operational network is up but *before*
        // `CommissioningComplete`. The handler's connection manager only connects
        // *after* the device is commissioned, so this one-shot connect is
        // performed here - before the handler borrows the networks store. The
        // target network ID is the one the commissioner selected, remembered in
        // `NetCtlState`.
        let deferred_connect_id = self.stack.network.net_state.lock(|state| {
            let state = state.borrow();
            state.is_prov_ready().then(|| state.network_id.clone())
        });

        if let Some(network_id) = deferred_connect_id {
            info!("Non-concurrent commissioning: performing the deferred connect");

            let mut buf = [0u8; MAX_CREDS_SIZE];

            connect_once(&mut *self.networks, &net_ctl_s, &network_id, &mut buf).await?;
        }

        // The Network Commissioning handler drives the maintenance `WirelessMgr`
        // with the operational `net_ctl`.
        let combined = wifi_net_handler(
            &self.stack.matter,
            &false,
            self.gen_diag,
            &netif,
            &net_ctl_s,
            &mut *self.networks,
            &net_ctl_s,
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

        let mut oper_task =
            pin!(select4(&mut net_task, &mut mdns_task, &mut im_task, &mut user_task).coalesce());

        // Hand the radio back to BLE once a commissioning window that has to be advertised
        // there appears. The window still open from the commissioning this phase is finishing
        // is not one of them - non-concurrent commissioning completes over the operational
        // network, and only then does the window close - so wait for it to go away first, and
        // only then for the next one to open.
        let mut comm_window_task = pin!(async {
            self.stack.wait_next_comm_window().await;

            info!("Commissioning window opened; handing the radio back to BLE");

            Ok(())
        });

        select(&mut oper_task, &mut comm_window_task)
            .coalesce()
            .await
    }
}

impl<'a, const B: usize, S, E, C, H, K, X, Z> WifiCoexTask
    for MatterStackWirelessTask<'a, B, wireless::Wifi, S, E, C, H, K, X, Z>
where
    S: Networks + Embedding,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
    Z: NetCtl + WifiDiag + NetChangeNotif,
{
    async fn run<T, N, Q, D, G>(
        &mut self,
        net_stack: T,
        netif: N,
        net_ctl: Q,
        mut mdns: D,
        mut gatt: G,
    ) -> Result<(), Error>
    where
        T: NetStack,
        N: NetifDiag + NetChangeNotif,
        Q: NetCtl + WifiDiag + NetChangeNotif,
        D: Mdns,
        G: GattPeripheral,
    {
        info!("Wifi and BLE drivers started");

        let net_ctl_s = NetCtlWithStatusImpl::new(
            &self.stack.network.net_state,
            WirelessNetCtl::Operational(&net_ctl),
        );

        // The Network Commissioning handler drives the maintenance `WirelessMgr`
        // with the operational `net_ctl`; `run_net_coex` only runs the BTP coex
        // transport.
        let combined = wifi_net_handler(
            &self.stack.matter,
            &true,
            self.gen_diag,
            &netif,
            &net_ctl_s,
            &mut *self.networks,
            &net_ctl_s,
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
            stack.run_net_coex(&self.crypto, &net_stack, &netif, &mut mdns, &mut gatt)
        );

        let mut im_task = pin_alloc!(bump, self.stack.run_im_with_bump(&im));

        let mut user_task = pin_alloc!(bump, self.user_task.run(&net_stack, &netif));

        select3(&mut net_task, &mut im_task, &mut user_task)
            .coalesce()
            .await
    }
}
