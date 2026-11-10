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
use rs_matter_dm::clusters::net_comm::{NetCtl, NetworkType};
use rs_matter_dm::clusters::thread_diag::ThreadDiag;
use rs_matter_dm::endpoints::thread_net_handler;
use rs_matter_dm::networks::wireless::{
    self, connect_once, NetCtlWithStatusImpl, NoopWirelessNetCtl, MAX_CREDS_SIZE,
};
use rs_matter_dm::networks::NetChangeNotif;
use rs_matter_dm::root_endpoint;
use rs_matter_dm_core::persist::KvBlobStoreAccess;
use rs_matter_dm_core::{DataModel, Endpoint};
use rs_matter_transport::network::btp::Btp;
use rs_matter_transport::network::NoNetwork;
use rs_matter_utils::error::Error;
use rs_matter_utils::futures::{select, select3, select4, Coalesce};
use rs_matter_utils::sync::MaybeSend;

use crate::mdns::Mdns;
use crate::net::NetStack;
use crate::network::{Embedding, StackNetwork};
use crate::wireless::{
    GattPeripheral, GattTask, MatterStackWirelessTask, UntilBleCommWindow, WirelessNetCtl,
};
use crate::{alloc_init, pin_alloc, MatterStack, RunOptions, UserTask};

use super::{GattDriver, PreexistingWireless};

impl<const B: usize, S, E> MatterStack<'_, B, S, E>
where
    S: StackNetwork,
    E: Embedding,
{
    /// Run the Matter stack for a wireless network where the BLE and the Wifi stacks can co-exist.
    ///
    /// # Arguments
    /// - `thread` - a user-provided `ThreadCoex` implementation
    /// - `crypto` - a user-provided `Crypto` implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation
    /// - `options` - the optional settings: `()` for the defaults, a `UserTask`, or an `Options`
    pub async fn run_thread<W, C, H, K, O>(
        &self,
        mut thread: W,
        crypto: C,
        handler: H,
        kv: K,
        options: O,
    ) -> Result<(), Error>
    where
        W: ThreadCoexDriver,
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
        O: RunOptions,
    {
        let _lock = self.run_lock.lock().await;

        // Lent to the Network Commissioning handler of each phase
        let mut networks = self.networks.lock().await;

        info!("Matter Stack memory: {}b", core::mem::size_of_val(self));

        // Since this is the last code executed in the method, resetting the allocator should be safe
        // because all boxes returned by it should be dropped by then
        let _defer = scopeguard::guard((), |_| unsafe {
            self.bump.reset();
        });

        self.matter().reset_transport()?;

        let (gen_diag, user) = options.into_parts();

        let btp = alloc_init!(self.bump, Btp::init());

        let net_task = pin_alloc!(
            self.bump,
            self.thread_coex_task(
                &mut networks,
                &btp,
                &mut thread,
                crypto,
                handler,
                kv,
                &gen_diag,
                user
            )
        );

        net_task.await
    }

    /// Run the Matter stack for a wireless network where the BLE and the Thread stacks cannot co-exist.
    ///
    /// # Arguments
    /// - `thread` - a user-provided `Thread` + `Gatt` implementation
    /// - `crypto` - a user-provided `Crypto` implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation
    /// - `options` - the optional settings: `()` for the defaults, a `UserTask`, or an `Options`
    pub async fn run_thread_no_coex<W, C, H, K, O>(
        &self,
        thread: W,
        crypto: C,
        handler: H,
        kv: K,
        options: O,
    ) -> Result<(), Error>
    where
        W: ThreadDriver + GattDriver,
        K: KvBlobStoreAccess,
        C: Crypto,
        H: DataModel,
        O: RunOptions,
    {
        let _lock = self.run_lock.lock().await;

        // Lent to the Network Commissioning handler of each phase
        let mut networks = self.networks.lock().await;

        info!("Matter Stack memory: {}b", core::mem::size_of_val(self));

        // Since this is the last code executed in the method, resetting the allocator should be safe
        // because all boxes returned by it should be dropped by then
        let _defer = scopeguard::guard((), |_| unsafe {
            self.bump.reset();
        });

        self.matter().reset_transport()?;

        let (gen_diag, user) = options.into_parts();

        let btp = alloc_init!(self.bump, Btp::init());

        let net_task = pin_alloc!(
            self.bump,
            self.thread_no_coex_task(
                &mut networks,
                &btp,
                thread,
                crypto,
                handler,
                kv,
                &gen_diag,
                user
            )
        );

        net_task.await
    }

    /// Run the Matter stack over the Thread network only, without BLE.
    ///
    /// This is meant for a commissioned device whose driver does not support BLE.
    /// A commissioning window is advertised over the Thread network only.
    ///
    /// An uncommissioned device can only be commissioned if its Thread interface
    /// is connected by other means, as the stack has no network credentials yet.
    ///
    /// # Arguments
    /// - `thread` - a user-provided `ThreadDriver` implementation
    /// - `crypto` - a user-provided `Crypto` implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation
    /// - `options` - the optional settings: `()` for the defaults, a `UserTask`, or an `Options`
    pub async fn run_thread_oper<W, C, H, K, O>(
        &self,
        mut thread: W,
        crypto: C,
        handler: H,
        kv: K,
        options: O,
    ) -> Result<(), Error>
    where
        W: ThreadDriver,
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
        O: RunOptions,
    {
        let _lock = self.run_lock.lock().await;

        // Lent to the Network Commissioning handler
        let mut networks = self.networks.lock().await;

        info!("Matter Stack memory: {}b", core::mem::size_of_val(self));

        if !self.matter().has_fabrics() {
            warn!("Device is not commissioned; without BLE it is reachable only if Thread is connected by other means");
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
            self.thread_oper_task(
                &mut networks,
                &mut thread,
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
    fn thread_oper_task<'t, W, C, H, K, U>(
        &'t self,
        networks: &'t mut S::Store,
        thread: &'t mut W,
        crypto: C,
        handler: H,
        kv: K,
        gen_diag: &'t dyn GenDiag,
        user: U,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        W: ThreadDriver,
        C: Crypto + 't,
        H: DataModel + 't,
        K: KvBlobStoreAccess + 't,
        U: UserTask + 't,
    {
        // There is no BLE phase, so the phantom net-ctl type is an irrelevant placeholder.
        // The task is not wrapped in `UntilBleCommWindow`, so it never hands the radio over.
        thread.run(
            MatterStackWirelessTask::<'_, _, _, _, _, _, _, _, _, NoopWirelessNetCtl> {
                stack: self,
                gen_diag,
                networks,
                crypto,
                handler,
                kv,
                user_task: user,
                net_type: NetworkType::Thread,
                btp: None,
                _network: PhantomData::<fn() -> wireless::Thread>,
                _net_ctl: PhantomData,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn thread_coex_task<'t, W, C, H, K, U>(
        &'t self,
        networks: &'t mut S::Store,
        btp: &'t Btp,
        thread: &'t mut W,
        crypto: C,
        handler: H,
        kv: K,
        gen_diag: &'t dyn GenDiag,
        user: U,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        W: ThreadCoexDriver,
        C: Crypto + 't,
        H: DataModel + 't,
        K: KvBlobStoreAccess + 't,
        U: UserTask + 't,
    {
        // The coex task never builds a `WirelessNetCtl` chain via `Q`, so its
        // phantom net-ctl type is an irrelevant placeholder.
        // `&kv` is also lent to the driver so it can persist its own state.
        thread.run(
            MatterStackWirelessTask::<'_, _, _, _, _, _, _, _, _, NoopWirelessNetCtl> {
                stack: self,
                gen_diag,
                networks,
                crypto,
                handler,
                kv,
                user_task: user,
                net_type: NetworkType::Thread,
                btp: Some(btp),
                _network: PhantomData::<fn() -> wireless::Thread>,
                _net_ctl: PhantomData,
            },
        )
    }

    #[allow(clippy::manual_async_fn, clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn thread_no_coex_task<'t, W, C, H, K, U>(
        &'t self,
        networks: &'t mut S::Store,
        btp: &'t Btp,
        mut thread: W,
        crypto: C,
        handler: H,
        kv: K,
        gen_diag: &'t dyn GenDiag,
        mut user: U,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        W: ThreadDriver + GattDriver + 't,
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
                        &mut thread,
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
                            <W as ThreadDriver>::NetCtl<'_>,
                        > {
                            stack: self,
                            gen_diag,
                            networks: &mut *networks,
                            crypto: &crypto,
                            handler: &handler,
                            kv: &kv,
                            user_task: &mut user,
                            net_type: NetworkType::Thread,
                            btp: Some(btp),
                            _network: PhantomData::<fn() -> wireless::Thread>,
                            _net_ctl: PhantomData,
                        },
                    )
                    .await?;
                }

                ThreadDriver::run(
                    &mut thread,
                    UntilBleCommWindow {
                        stack: self,
                        task: MatterStackWirelessTask::<
                            '_,
                            _,
                            _,
                            _,
                            _,
                            _,
                            _,
                            _,
                            _,
                            <W as ThreadDriver>::NetCtl<'_>,
                        > {
                            stack: self,
                            gen_diag,
                            networks: &mut *networks,
                            crypto: &crypto,
                            handler: &handler,
                            kv: &kv,
                            user_task: &mut user,
                            net_type: NetworkType::Thread,
                            btp: Some(btp),
                            _network: PhantomData::<fn() -> wireless::Thread>,
                            _net_ctl: PhantomData,
                        },
                    },
                )
                .await?;
            }
        }
    }

    /// Return a metadata for the root (Endpoint 0) of the Matter Node
    /// configured for BLE+Thread network.
    pub const fn thread_root_endpoint() -> Endpoint<'static> {
        const ENDPOINT: Endpoint<'static> = root_endpoint!(thread);

        ENDPOINT
    }
}

/// A trait representing a task that needs access to the operational wireless interface (Wifi or Thread)
/// (network stack, Netif and Wireless controller) to perform its work.
pub trait ThreadTask: MaybeSend {
    /// Run the task with the given network interface, UDP stack, wireless controller and mDNS
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
        C: NetCtl + ThreadDiag + NetChangeNotif,
        M: Mdns;
}

impl<T> ThreadTask for &mut T
where
    T: ThreadTask,
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
        C: NetCtl + ThreadDiag + NetChangeNotif,
        M: Mdns,
    {
        T::run(*self, net_stack, netif, net_ctl, mdns)
    }
}

/// A trait for running a task within a context where the wireless interface is initialized and operable
pub trait ThreadDriver: MaybeSend {
    /// The Thread network controller type this driver produces in its operational
    /// phase. Naming it here lets the commissioning and operational handler chains
    /// be built with the SAME `WirelessNetCtl<Self::NetCtl<'_>>` net-ctl type,
    /// yielding a single handler-chain monomorphization. The bound is Thread's own
    /// (`ThreadDiag`) — a Thread controller is never asked to be a Wifi one.
    type NetCtl<'a>: NetCtl + ThreadDiag + NetChangeNotif
    where
        Self: 'a;

    /// Setup the radio to operate in wireless (Wifi or Thread) mode
    /// and run the given task.
    fn run<T>(&mut self, task: T) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        T: ThreadTask;
}

impl<T> ThreadDriver for &mut T
where
    T: ThreadDriver,
{
    type NetCtl<'a>
        = T::NetCtl<'a>
    where
        Self: 'a;

    fn run<A>(&mut self, task: A) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        A: ThreadTask,
    {
        T::run(self, task)
    }
}

/// A trait representing a task that needs access to the operational wireless interface (Wifi or Thread)
/// as well as to the commissioning BTP GATT peripheral.
///
/// Typically, tasks performing the Matter concurrent commissioning workflow will implement this trait.
pub trait ThreadCoexTask: MaybeSend {
    /// Run the task with the given network stack, network interface, wireless controller and mDNS
    fn run<S, N, C, M, G>(
        &mut self,
        net_stack: S,
        netif: N,
        net_task: C,
        mdns: M,
        gatt: G,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        C: NetCtl + ThreadDiag + NetChangeNotif,
        M: Mdns,
        G: GattPeripheral;
}

impl<T> ThreadCoexTask for &mut T
where
    T: ThreadCoexTask,
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
        C: NetCtl + ThreadDiag + NetChangeNotif,
        M: Mdns,
        G: GattPeripheral,
    {
        T::run(*self, net_stack, netif, net_ctl, mdns, gatt)
    }
}

/// A trait for running a task within a context where both the wireless interface (Thread or Wifi)
/// is initialized and operable, as well as the BLE GATT peripheral is also operable.
///
/// Typically, tasks performing the Matter concurrent commissioning workflow will be run by
/// implementations of this trait.
pub trait ThreadCoexDriver: MaybeSend {
    /// Setup the radio to operate in wireless coexist mode (Wifi or Thread + BLE)
    /// and run the given task.
    fn run<T>(&mut self, task: T) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        T: ThreadCoexTask;
}

impl<T> ThreadCoexDriver for &mut T
where
    T: ThreadCoexDriver,
{
    fn run<A>(&mut self, task: A) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        A: ThreadCoexTask,
    {
        T::run(self, task)
    }
}

impl<S, N, C, M, P> ThreadDriver for PreexistingWireless<S, N, C, M, P>
where
    P: MaybeSend,
    S: NetStack,
    N: NetifDiag + NetChangeNotif,
    C: NetCtl + ThreadDiag + NetChangeNotif,
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
        T: ThreadTask,
    {
        task.run(&self.net_stack, &self.netif, &self.net_ctl, &mut self.mdns)
            .await
    }
}

impl<S, N, C, M, P> ThreadCoexDriver for PreexistingWireless<S, N, C, M, P>
where
    S: NetStack,
    N: NetifDiag + NetChangeNotif,
    C: NetCtl + ThreadDiag + NetChangeNotif,
    M: Mdns,
    P: GattPeripheral,
{
    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: ThreadCoexTask,
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

impl<'a, const B: usize, S, E, C, H, K, X, Q> GattTask
    for MatterStackWirelessTask<'a, B, wireless::Thread, S, E, C, H, K, X, Q>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: MaybeSend,
    Q: NetCtl + ThreadDiag + NetChangeNotif,
{
    async fn run<P>(&mut self, peripheral: P) -> Result<(), Error>
    where
        P: GattPeripheral,
    {
        let net_ctl = NetCtlWithStatusImpl::new(
            &self.stack.net_state,
            WirelessNetCtl::<Q>::Commissioning(NetworkType::Thread),
        );

        // No netif during the BLE phase; the operational network clusters
        // are chained on top of the user's handler with the commissioning
        // net-ctl, and re-chained with the operational one once Wifi/Thread
        // is up (`ThreadTask::run`).
        let combined = thread_net_handler(
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

        let mut btp_task = pin!(self
            .stack
            .run_btp(unwrap!(self.btp), &self.crypto, peripheral));

        let mut im_task = pin!(self.stack.run_im(&im));

        select(&mut btp_task, &mut im_task).coalesce().await
    }
}

impl<'a, const B: usize, S, E, C, H, K, X, Z> ThreadTask
    for MatterStackWirelessTask<'a, B, wireless::Thread, S, E, C, H, K, X, Z>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
    Z: NetCtl + ThreadDiag + NetChangeNotif,
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
        Q: NetCtl + ThreadDiag + NetChangeNotif,
        D: Mdns,
    {
        info!("Thread driver started");

        let net_ctl_s =
            NetCtlWithStatusImpl::new(&self.stack.net_state, WirelessNetCtl::Operational(&net_ctl));

        // Non-concurrent commissioning deferred connect.
        //
        // In non-concurrent (BLE-only) commissioning the commissioner's
        // `ConnectNetwork` command is received while the operational (Thread)
        // network cannot yet run, so the actual connect is deferred. Now that the
        // operational network is up, replay that connect *before* commissioning
        // completes - the commissioner re-establishes a CASE session over Thread
        // and only then sends `CommissioningComplete`. The handler's connection
        // manager only connects *after* the device is commissioned, so this
        // one-shot connect is performed here - before the handler borrows the
        // networks store.
        //
        // The target network is the exact one the commissioner selected: its ID
        // is remembered in `NetCtlState` by the commissioning-phase `connect`
        // wrapper. `is_prov_ready()` is true only in this pending non-concurrent
        // case (on a normal reboot of an already-commissioned device the state is
        // empty, so we skip the one-shot connect and let the handler's manager run).
        let deferred_connect_id = self.stack.net_state.lock(|state| {
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
        let combined = thread_net_handler(
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

        select4(&mut net_task, &mut mdns_task, &mut im_task, &mut user_task)
            .coalesce()
            .await
    }
}

impl<const B: usize, S, E, X> ThreadTask for UntilBleCommWindow<'_, B, S, E, X>
where
    S: StackNetwork,
    E: Embedding,
    X: ThreadTask,
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
        let stack = self.stack;

        let mut task = pin!(self.task.run(net_stack, netif, net_ctl, mdns));

        // Hand the radio back to BLE once a commissioning window that has to be advertised
        // there appears. The window still open from the commissioning this phase is finishing
        // is not one of them - non-concurrent commissioning completes over the operational
        // network, and only then does the window close - so wait for it to go away first, and
        // only then for the next one to open.
        let mut comm_window_task = pin!(async {
            stack.wait_next_comm_window().await;

            info!("Commissioning window opened; handing the radio back to BLE");

            Ok(())
        });

        select(&mut task, &mut comm_window_task).coalesce().await
    }
}

impl<'a, const B: usize, S, E, C, H, K, X, Z> ThreadCoexTask
    for MatterStackWirelessTask<'a, B, wireless::Thread, S, E, C, H, K, X, Z>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
    Z: NetCtl + ThreadDiag + NetChangeNotif,
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
        Q: NetCtl + ThreadDiag + NetChangeNotif,
        D: Mdns,
        G: GattPeripheral,
    {
        info!("Thread and BLE drivers started");

        let net_ctl_s =
            NetCtlWithStatusImpl::new(&self.stack.net_state, WirelessNetCtl::Operational(&net_ctl));

        // The Network Commissioning handler drives the maintenance `WirelessMgr`
        // with the operational `net_ctl`; `run_net_coex` only runs the BTP coex
        // transport.
        let combined = thread_net_handler(
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
}
