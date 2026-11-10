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

use rs_matter_crypto::Crypto;
use rs_matter_dm::clusters::eth_diag::EthDiag;
use rs_matter_dm::clusters::gen_diag::{GenDiag, NetifDiag};
use rs_matter_dm::endpoints::eth_net_handler;
use rs_matter_dm::networks::NetChangeNotif;
use rs_matter_dm::root_endpoint;
use rs_matter_dm_core::persist::KvBlobStoreAccess;
use rs_matter_dm_core::{DataModel, Endpoint};
use rs_matter_transport::network::NoNetwork;
use rs_matter_utils::error::Error;
use rs_matter_utils::futures::{select4, Coalesce};
use rs_matter_utils::sync::MaybeSend;

use crate::mdns::Mdns;
use crate::net::NetStack;
use crate::network::{Embedding, EthStackNetwork, StackNetwork};
use crate::{pin_alloc, MatterStack, RunOptions, UserTask};

/// A trait representing a task that needs access to the operational Ethernet interface
/// (Network stack, Netif and Ethernet diagnostics) to perform its work.
pub trait EthernetTask: MaybeSend {
    /// Run the task with the given network stack, network interface, Ethernet diagnostics and mDNS
    fn run<S, N, D, M>(
        &mut self,
        net_stack: S,
        netif: N,
        eth_diag: D,
        mdns: M,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        D: EthDiag,
        M: Mdns;
}

impl<T> EthernetTask for &mut T
where
    T: EthernetTask,
{
    fn run<S, N, D, M>(
        &mut self,
        net_stack: S,
        netif: N,
        eth_diag: D,
        mdns: M,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
        D: EthDiag,
        M: Mdns,
    {
        (*self).run(net_stack, netif, eth_diag, mdns)
    }
}

/// A trait for running a task within a context where the ethernet interface is initialized and operable
pub trait EthernetDriver: MaybeSend {
    /// Setup Ethernet and run the given task
    fn run<T>(&mut self, task: T) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        T: EthernetTask;
}

impl<T> EthernetDriver for &mut T
where
    T: EthernetDriver,
{
    fn run<A>(&mut self, task: A) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        A: EthernetTask,
    {
        (*self).run(task)
    }
}

/// A utility type for running an ethernet task with a pre-existing ethernet interface
/// rather than bringing up / tearing down the ethernet interface for the task.
pub struct PreexistingEthernet<S, N, D, M> {
    stack: S,
    netif: N,
    eth_diag: D,
    mdns: M,
}

impl<S, N, D, M> PreexistingEthernet<S, N, D, M> {
    /// Create a new `PreexistingEthernet` instance with the given UDP stack, network interface,
    /// Ethernet diagnostics and mDNS.
    pub const fn new(stack: S, netif: N, eth_diag: D, mdns: M) -> Self {
        Self {
            stack,
            netif,
            eth_diag,
            mdns,
        }
    }
}

impl<S, N, D, M> EthernetDriver for PreexistingEthernet<S, N, D, M>
where
    S: NetStack,
    N: NetifDiag + NetChangeNotif,
    D: EthDiag,
    M: Mdns,
{
    async fn run<T>(&mut self, mut task: T) -> Result<(), Error>
    where
        T: EthernetTask,
    {
        task.run(&self.stack, &self.netif, &self.eth_diag, &mut self.mdns)
            .await
    }
}

/// The Ethernet driver of a node without Ethernet, such as an `AnyDriver` for Wifi and
/// Thread only. It has no values, so it is never run.
pub enum NoEthernet {}

impl EthernetDriver for NoEthernet {
    async fn run<T>(&mut self, _task: T) -> Result<(), Error>
    where
        T: EthernetTask,
    {
        match *self {}
    }
}

/// The methods of the `MatterStack` for Ethernet.
impl<const B: usize, S, E> MatterStack<'_, B, S, E>
where
    S: EthStackNetwork,
    E: Embedding,
{
    /// Return a metadata for the root (Endpoint 0) of the Matter Node
    /// configured for Ethernet network.
    pub const fn eth_root_endpoint() -> Endpoint<'static> {
        const ENDPOINT: Endpoint<'static> = root_endpoint!(eth);

        ENDPOINT
    }

    /// Run the Matter stack for an Ethernet network.
    ///
    /// # Arguments
    /// - `ethernet` - a user-provided `Ethernet` implementation
    /// - `crypto` - a user-provided crypto implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation for loading the persisted state of the stack
    /// - `options` - the optional settings: `()` for the defaults, a `UserTask`, or an `Options`
    pub async fn run_eth<N, C, H, K, O>(
        &self,
        mut ethernet: N,
        crypto: C,
        handler: H,
        kv: K,
        options: O,
    ) -> Result<(), Error>
    where
        N: EthernetDriver,
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
        O: RunOptions,
    {
        let _lock = self.run_lock.lock().await;

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
            self.run_ethernet(&mut ethernet, crypto, handler, &kv, &gen_diag, user)
        );

        net_task.await
    }

    fn run_ethernet<'t, N, C, H, K, X>(
        &'t self,
        ethernet: &'t mut N,
        crypto: C,
        handler: H,
        kv: K,
        gen_diag: &'t dyn GenDiag,
        user: X,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        N: EthernetDriver + 't,
        C: Crypto + 't,
        H: DataModel + 't,
        K: KvBlobStoreAccess + 't,
        X: UserTask + 't,
    {
        EthernetDriver::run(
            ethernet,
            MatterStackEthernetTask {
                stack: self,
                gen_diag,
                crypto,
                handler,
                kv,
                user_task: user,
            },
        )
    }
}

struct MatterStackEthernetTask<'a, const B: usize, S, E, C, H, K, X>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
{
    stack: &'a MatterStack<'a, B, S, E>,
    gen_diag: &'a dyn GenDiag,
    crypto: C,
    handler: H,
    kv: K,
    user_task: X,
}

impl<const B: usize, S, E, C, H, K, X> EthernetTask
    for MatterStackEthernetTask<'_, B, S, E, C, H, K, X>
where
    S: StackNetwork,
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
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

        // The operational network clusters of the root endpoint need the
        // netif, which only exists here; chain them on top of the user's
        // handler, which owns everything else. `&self.handler` doubles as
        // the `Metadata` provider (`(M, H)` form for `InteractionModel::new`).
        let combined = eth_net_handler(
            &self.stack.matter,
            &false,
            self.gen_diag,
            &netif,
            &eth_diag,
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
