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
use rs_matter_dm::clusters::gen_diag::NetifDiag;
use rs_matter_dm::endpoints::eth_net_handler;
use rs_matter_dm::networks::NetChangeNotif;
use rs_matter_dm::root_endpoint;
use rs_matter_dm_core::persist::{KvBlobStore, KvBlobStoreAccess};
use rs_matter_dm_core::{DataModel, Endpoint};
use rs_matter_pairing::DiscoveryCapabilities;
use rs_matter_transport::network::NoNetwork;
use rs_matter_utils::error::Error;
use rs_matter_utils::futures::{select4, Coalesce};
use rs_matter_utils::init::{init, Init};
use rs_matter_utils::sync::MaybeSend;

use crate::mdns::Mdns;
use crate::net::NetStack;
use crate::network::{Embedding, Network};
use crate::private::Sealed;
use crate::{pin_alloc, DummyAttrNotifier, MatterStack, UserTask};

/// An implementation of the `Network` trait for Ethernet.
///
/// Note that "Ethernet" - in the context of this crate - means
/// not just the Ethernet transport, but also any other IP-based transport
/// (like Wifi or Thread), where the Matter stack would not be concerned
/// with the management of the network transport (as in re-connecting to the
/// network on lost signal, managing network credentials and so on).
///
/// The expectation is nevertheless that for production use-cases
/// the `Eth` network would really only be used for Ethernet.
pub struct Eth<E = ()> {
    embedding: E,
}

impl<E> Sealed for Eth<E> {}

impl<E> Network for Eth<E>
where
    E: Embedding,
{
    const INIT: Self = Self { embedding: E::INIT };

    type Embedding<'a>
        = E
    where
        E: 'a;

    fn init() -> impl Init<Self> {
        init!(Self {
            embedding <- E::init(),
        })
    }

    fn discovery_capabilities(&self) -> DiscoveryCapabilities {
        DiscoveryCapabilities::IP
    }

    fn embedding(&self) -> &Self::Embedding<'_> {
        &self.embedding
    }
}

// A type alias for a Matter stack running over Ethernet.
pub type EthMatterStack<'a, const B: usize, E = ()> = MatterStack<'a, B, Eth<E>>;

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

/// A specialization of the `MatterStack` for Ethernet.
impl<const B: usize, E> MatterStack<'_, B, Eth<E>>
where
    E: Embedding,
{
    /// Return a metadata for the root (Endpoint 0) of the Matter Node
    /// configured for Ethernet network.
    pub const fn root_endpoint() -> Endpoint<'static> {
        const ENDPOINT: Endpoint<'static> = root_endpoint!(eth);

        ENDPOINT
    }

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

        // Reset the events counter so we don't carry a stale watermark across a
        // factory reset (Matter Core spec R1.5.1, §7.14.1.1).
        self.im(crypto, handler, &kv).factory_reset().await
    }

    /// Run the startup sequence of the stack: re-hydrate the persisted state and
    /// open the basic commissioning window if the device is not commissioned yet.
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

    /// Run the Matter stack for a pre-existing Ethernet network.
    ///
    /// # Arguments
    /// - `net_stack` - a user-provided network stack implementation
    /// - `netif` - a user-provided `Netif` implementation for the Ethernet network
    /// - `eth_diag` - a user-provided `EthDiag` implementation (`&()` if it has nothing to report)
    /// - `mdns` - a user-provided mDNS implementation
    /// - `crypto` - a user-provided crypto implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation for loading the persisted state of the stack
    /// - `user` - a user-provided future that will be polled only when the netif interface is up
    #[allow(clippy::too_many_arguments)]
    pub fn run_preex<'t, U, N, D, M, C, H, K, X>(
        &'t self,
        net_stack: U,
        netif: N,
        eth_diag: D,
        mdns: M,
        crypto: C,
        handler: H,
        kv: K,
        user: X,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        U: NetStack + 't,
        N: NetifDiag + NetChangeNotif + 't,
        D: EthDiag + 't,
        M: Mdns + 't,
        C: Crypto + 't,
        H: DataModel + 't,
        K: KvBlobStoreAccess + 't,
        X: UserTask + 't,
    {
        self.run(
            PreexistingEthernet::new(net_stack, netif, eth_diag, mdns),
            crypto,
            handler,
            kv,
            user,
        )
    }

    /// Run the Matter stack for an Ethernet network.
    ///
    /// # Arguments
    /// - `ethernet` - a user-provided `Ethernet` implementation
    /// - `crypto` - a user-provided crypto implementation
    /// - `handler` - a user-provided DM handler implementation
    /// - `kv` - a user-provided `KvBlobStoreAccess` implementation for loading the persisted state of the stack
    /// - `user` - a user-provided future that will be polled only when the netif interface is up
    pub async fn run<N, C, H, K, X>(
        &self,
        mut ethernet: N,
        crypto: C,
        handler: H,
        kv: K,
        user: X,
    ) -> Result<(), Error>
    where
        N: EthernetDriver,
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
        X: UserTask,
    {
        let _lock = self.run_lock.lock().await;

        info!("Matter Stack memory: {}b", core::mem::size_of_val(self));

        // Since this is the last code executed in the method, resetting the allocator should be safe
        // because all boxes returned by it should be dropped by then
        let _defer = scopeguard::guard((), |_| unsafe {
            self.bump.reset();
        });

        self.matter().reset_transport()?;

        let net_task = pin_alloc!(
            self.bump,
            self.run_ethernet(&mut ethernet, crypto, handler, &kv, user)
        );

        net_task.await
    }

    fn run_ethernet<'t, N, C, H, K, X>(
        &'t self,
        ethernet: &'t mut N,
        crypto: C,
        handler: H,
        kv: K,
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
                crypto,
                handler,
                kv,
                user_task: user,
            },
        )
    }
}

struct MatterStackEthernetTask<'a, const B: usize, E, C, H, K, X>
where
    E: Embedding,
    C: Crypto,
    H: DataModel,
    K: KvBlobStoreAccess,
    X: UserTask,
{
    stack: &'a MatterStack<'a, B, Eth<E>>,
    crypto: C,
    handler: H,
    kv: K,
    user_task: X,
}

impl<const B: usize, E, C, H, K, X> EthernetTask for MatterStackEthernetTask<'_, B, E, C, H, K, X>
where
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
            &(),
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
