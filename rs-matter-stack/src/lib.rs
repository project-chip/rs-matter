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

//! The assembly of a node: it organizes the `rs-matter` boilerplate, so that
//! the code on top only provides the data model, the storage and a network driver.
//!
//! A driver brings up a network for as long as it runs a task of the stack, and hands it
//! the objects of that network. See `EthernetDriver`, `WifiDriver`, `ThreadDriver`
//! and `GattDriver`, and the `Preexisting*` types for a network which is already up.
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(async_fn_in_trait)]
#![allow(unknown_lints)]
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::uninlined_format_args)]
#![warn(clippy::large_futures)]
#![warn(clippy::large_stack_frames)]
#![warn(clippy::large_types_passed_by_value)]

use core::cell::Cell;
use core::future::Future;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use core::pin::pin;

use cfg_if::cfg_if;

use rs_matter_crypto::{Crypto, Rng};
use rs_matter_dm::clusters::basic_info::BasicInfoConfig;
use rs_matter_dm::clusters::dev_att::DeviceAttestation;
use rs_matter_dm::clusters::gen_diag::NetifDiag;
use rs_matter_dm::clusters::sw_diag::SwDiag;
use rs_matter_dm::endpoints::RootHandler;
use rs_matter_dm::networks::NetChangeNotif;
use rs_matter_dm_core::persist::{KvBlobStore, KvBlobStoreAccess};
use rs_matter_dm_core::{AttrChangeNotifier, AttrId, ClusterId, DataModel, EndptId};
use rs_matter_im::{InteractionModel, InteractionModelState};
use rs_matter_node::{BasicCommData, Matter, MATTER_PORT};
use rs_matter_pairing::qr::QrTextType;
use rs_matter_respond::{DefaultResponder, ExchangeHandler, Responder};
use rs_matter_sc::pase::MAX_COMM_WINDOW_TIMEOUT_SECS;
use rs_matter_transport::exchange::MatterBuffers;
use rs_matter_transport::network::{
    Address, ChainedNetwork, NetworkMulticast, NetworkReceive, NetworkSend, NoNetwork,
};
use rs_matter_utils::error::Error;
use rs_matter_utils::futures::{select, select_slice, Coalesce};
use rs_matter_utils::init::{init, Init};
use rs_matter_utils::storage::Vec;
use rs_matter_utils::sync::blocking::Mutex;
use rs_matter_utils::sync::{IfMutex, MaybeSend};
use rs_matter_utils::timers::{Duration, Timer};

use crate::bump::Bump;
use crate::mdns::{Mdns, MAX_NETIF_IPV6_ADDRS};
use crate::net::{NetSocket, NetStack};
use crate::network::Network;

#[cfg(feature = "alloc")]
extern crate alloc;

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

pub mod ble;
pub mod bump;
pub mod eth;
pub mod mdns;
pub mod net;
pub mod network;
pub mod wireless;

mod private {
    /// A marker super-trait for sealed traits
    pub trait Sealed {}

    impl Sealed for () {}
}

cfg_if! {
    if #[cfg(feature = "max-subscriptions-32")] {
        /// Max number of subscriptions
        const MAX_SUBSCRIPTIONS: usize = 32;
    } else if #[cfg(feature = "max-subscriptions-16")] {
        /// Max number of subscriptions
        const MAX_SUBSCRIPTIONS: usize = 16;
    } else if #[cfg(feature = "max-subscriptions-8")] {
        /// Max number of subscriptions
        const MAX_SUBSCRIPTIONS: usize = 8;
    } else if #[cfg(feature = "max-subscriptions-7")] {
        /// Max number of subscriptions
        const MAX_SUBSCRIPTIONS: usize = 7;
    } else if #[cfg(feature = "max-subscriptions-6")] {
        /// Max number of subscriptions
        const MAX_SUBSCRIPTIONS: usize = 6;
    } else if #[cfg(feature = "max-subscriptions-5")] {
        /// Max number of subscriptions
        const MAX_SUBSCRIPTIONS: usize = 5;
    } else if #[cfg(feature = "max-subscriptions-4")] {
        /// Max number of subscriptions
        const MAX_SUBSCRIPTIONS: usize = 4;
    } else if #[cfg(feature = "max-subscriptions-3")] {
        /// Max number of subscriptions
        const MAX_SUBSCRIPTIONS: usize = 3;
    } else if #[cfg(feature = "max-subscriptions-2")] {
        /// Max number of subscriptions
        const MAX_SUBSCRIPTIONS: usize = 2;
    } else if #[cfg(feature = "max-subscriptions-1")] {
        /// Max number of subscriptions
        const MAX_SUBSCRIPTIONS: usize = 1;
    } else {
        /// Max number of subscriptions
        const MAX_SUBSCRIPTIONS: usize = 3;
    }
}

cfg_if! {
    if #[cfg(feature = "events-ringbuf-size-2048")] {
        /// Events ringbuf size
        const EVENTS_RINGBUF_SIZE: usize = 2048;
    } else if #[cfg(feature = "events-ringbuf-size-1024")] {
        /// Events ringbuf size
        const EVENTS_RINGBUF_SIZE: usize = 1024;
    } else if #[cfg(feature = "events-ringbuf-size-512")] {
        /// Events ringbuf size
        const EVENTS_RINGBUF_SIZE: usize = 512;
    } else if #[cfg(feature = "events-ringbuf-size-256")] {
        /// Events ringbuf size
        const EVENTS_RINGBUF_SIZE: usize = 256;
    } else if #[cfg(feature = "events-ringbuf-size-128")] {
        /// Events ringbuf size
        const EVENTS_RINGBUF_SIZE: usize = 128;
    } else if #[cfg(feature = "events-ringbuf-size-64")] {
        /// Events ringbuf size
        const EVENTS_RINGBUF_SIZE: usize = 64;
    } else if #[cfg(feature = "events-ringbuf-size-0")] {
        /// Events ringbuf size
        const EVENTS_RINGBUF_SIZE: usize = 0;
    } else {
        /// Events ringbuf size
        const EVENTS_RINGBUF_SIZE: usize = 256;
    }
}

cfg_if! {
    if #[cfg(feature = "max-im-buffers-64")] {
        /// Max number of IM buffers
        const MAX_IM_BUFFERS: usize = 64;
    } else if #[cfg(feature = "max-im-buffers-32")] {
        /// Max number of IM buffers
        const MAX_IM_BUFFERS: usize = 32;
    } else if #[cfg(feature = "max-im-buffers-16")] {
        /// Max number of IM buffers
        const MAX_IM_BUFFERS: usize = 16;
    } else if #[cfg(feature = "max-im-buffers-10")] {
        /// Max number of IM buffers
        const MAX_IM_BUFFERS: usize = 10;
    } else if #[cfg(feature = "max-im-buffers-9")] {
        /// Max number of IM buffers
        const MAX_IM_BUFFERS: usize = 9;
    } else if #[cfg(feature = "max-im-buffers-8")] {
        /// Max number of IM buffers
        const MAX_IM_BUFFERS: usize = 8;
    } else if #[cfg(feature = "max-im-buffers-7")] {
        /// Max number of IM buffers
        const MAX_IM_BUFFERS: usize = 7;
    } else if #[cfg(feature = "max-im-buffers-6")] {
        /// Max number of IM buffers
        const MAX_IM_BUFFERS: usize = 6;
    } else if #[cfg(feature = "max-im-buffers-5")] {
        /// Max number of IM buffers
        const MAX_IM_BUFFERS: usize = 5;
    } else if #[cfg(feature = "max-im-buffers-4")] {
        /// Max number of IM buffers
        const MAX_IM_BUFFERS: usize = 4;
    } else {
        /// Max number of IM buffers
        const MAX_IM_BUFFERS: usize = 10;
    }
}

cfg_if! {
    if #[cfg(feature = "max-responders-32")] {
        /// Max number of concurrent responders
        const MAX_RESPONDERS: usize = 32;
    } else if #[cfg(feature = "max-responders-16")] {
        /// Max number of concurrent responders
        const MAX_RESPONDERS: usize = 16;
    } else if #[cfg(feature = "max-responders-8")] {
        /// Max number of concurrent responders
        const MAX_RESPONDERS: usize = 8;
    } else if #[cfg(feature = "max-responders-7")] {
        /// Max number of concurrent responders
        const MAX_RESPONDERS: usize = 7;
    } else if #[cfg(feature = "max-responders-6")] {
        /// Max number of concurrent responders
        const MAX_RESPONDERS: usize = 6;
    } else if #[cfg(feature = "max-responders-5")] {
        /// Max number of concurrent responders
        const MAX_RESPONDERS: usize = 5;
    } else if #[cfg(feature = "max-responders-4")] {
        /// Max number of concurrent responders
        const MAX_RESPONDERS: usize = 4;
    } else if #[cfg(feature = "max-responders-3")] {
        /// Max number of concurrent responders
        const MAX_RESPONDERS: usize = 3;
    } else if #[cfg(feature = "max-responders-2")] {
        /// Max number of concurrent responders
        const MAX_RESPONDERS: usize = 2;
    } else if #[cfg(feature = "max-responders-1")] {
        /// Max number of concurrent responders
        const MAX_RESPONDERS: usize = 1;
    } else {
        /// Max number of concurrent responders
        const MAX_RESPONDERS: usize = 4;
    }
}

const MAX_BUSY_RESPONDERS: usize = 2;

pub type MatterStackInteractionModel<'a, C, H, K> = InteractionModel<
    'a,
    C,
    MatterBuffers<MAX_IM_BUFFERS>,
    H,
    K,
    // The accessory role: inbound `ReportData` is disowned.
    (),
    MAX_SUBSCRIPTIONS,
    EVENTS_RINGBUF_SIZE,
>;

/// The `InteractionModelState` specialization owned by `MatterStack`: the
/// subscriptions table and the events queue.
pub type MatterStackInteractionModelState =
    InteractionModelState<MAX_SUBSCRIPTIONS, EVENTS_RINGBUF_SIZE>;

/// The `MatterStack` struct is the main entry point for the Matter stack.
///
/// It wraps the actual `rs-matter` Matter instance and provides a simplified API for running the stack.
pub struct MatterStack<'a, const B: usize, N>
where
    N: Network,
{
    matter: Matter<'a>,
    buffers: MatterBuffers<MAX_IM_BUFFERS>,
    /// The interaction-model state: subscriptions table and events queue.
    state: MatterStackInteractionModelState,
    bump: Bump<B>,
    run_lock: IfMutex<()>,
    /// Whether the Interaction Model state (events watermark, persisted
    /// subscriptions) and the cluster handlers (the networks store among them)
    /// have already been re-hydrated from the KV store.
    ///
    /// `InteractionModel::startup` cannot be driven from `MatterStack::startup`,
    /// because it has to run on the very Interaction Model instance that is then
    /// run: a resumed subscription borrows that instance's IM buffers, and
    /// constructing an `InteractionModel` clears the subscriptions table. So the
    /// stack hydrates from `run_im` instead.
    ///
    /// The stack however builds one Interaction Model *per phase* (BLE
    /// commissioning, then operational), and only the first one may hydrate:
    /// re-loading the networks store on the phase switch would drop the
    /// credentials that non-concurrent commissioning has in memory but - with the
    /// failsafe still armed - not yet persisted.
    im_hydrated: Mutex<Cell<bool>>,
    #[allow(unused)]
    network: N,
}

impl<'a, const B: usize, N> MatterStack<'a, B, N>
where
    N: Network,
{
    /// Return the user-owned system handler for the root endpoint (Endpoint 0).
    ///
    /// The returned chain services every root endpoint system cluster except the
    /// operational network ones (Network Commissioning, the network-type diagnostics
    /// cluster, General Diagnostics and General Commissioning), which the stack
    /// chains on top of the user handler by itself, per network type and - with
    /// non-concurrent commissioning - per commissioning phase.
    ///
    /// Chain the returned handler (wrapped in `Async`) with the application
    /// clusters, and with any additional root endpoint clusters, and pass the
    /// result as the `handler` argument of the `run*` methods.
    ///
    /// # Arguments
    /// - `matter` - the `Matter` instance the clusters serve (see `matter()`)
    /// - `sw_diag` - the `SwDiag` implementation (pass `&()` for the no-op default)
    /// - `rand` - a random number generator
    pub fn root_handler<'r>(
        matter: &'r Matter<'r>,
        sw_diag: &'r dyn SwDiag,
        rand: impl Rng,
    ) -> RootHandler<'r> {
        rs_matter_dm::endpoints::root_handler(matter, sw_diag, rand)
    }

    /// Create a new `MatterStack` instance.
    #[allow(clippy::large_stack_frames)]
    #[inline(always)]
    pub const fn new(
        dev_det: &'a BasicInfoConfig,
        dev_comm: BasicCommData,
        dev_att: &'a dyn DeviceAttestation,
    ) -> Self {
        Self {
            matter: Matter::new(dev_det, dev_comm, dev_att, MATTER_PORT),
            buffers: MatterBuffers::new(),
            state: MatterStackInteractionModelState::new(),
            bump: Bump::new(),
            run_lock: IfMutex::new(()),
            im_hydrated: Mutex::new(Cell::new(false)),
            network: N::INIT,
        }
    }

    #[allow(clippy::large_stack_frames)]
    pub fn init(
        dev_det: &'a BasicInfoConfig,
        dev_comm: BasicCommData,
        dev_att: &'a dyn DeviceAttestation,
    ) -> impl Init<Self> {
        init!(Self {
            matter <- Matter::init(
                dev_det,
                dev_comm,
                dev_att,
                MATTER_PORT,
            ),
            buffers <- MatterBuffers::init(),
            state <- MatterStackInteractionModelState::init(),
            bump <- Bump::init(),
            run_lock <- IfMutex::init(()),
            im_hydrated: Mutex::new(Cell::new(false)),
            network <- N::init(),
        })
    }

    /// A utility method to replace the initial Device Attestation Data Fetcher with another one.
    ///
    /// Reasoning and use-cases explained in the documentation of `replace_mdns`.
    pub fn replace_dev_att(&mut self, dev_att: &'a dyn DeviceAttestation) {
        self.matter.replace_dev_att(dev_att);
    }

    /// Get a reference to the `Matter` instance.
    pub const fn matter(&self) -> &Matter<'a> {
        &self.matter
    }

    /// Get a reference to the `Network` instance.
    /// Useful when the user instantiates `MatterStack` with a custom network type.
    pub const fn network(&self) -> &N {
        &self.network
    }

    /// Create a new shared `KvBlobStore` instance, which is used to read and write blobs from the storage.
    ///
    /// The user needs to provide a `KvBlobStore` implementation, which is used to actually read and write the blobs from the storage.
    ///
    /// # Arguments
    /// - `store` - the raw [`KvBlobStore`] implementation to wrap
    pub fn kv<'s, S: KvBlobStore + MaybeSend + 's>(
        &'s self,
        store: S,
    ) -> impl KvBlobStoreAccess + 's {
        self.matter().kv(store)
    }

    /// Open the basic communication window, which allows commissioning tools to discover and commission the device.
    ///
    /// # Arguments
    /// - `crypto` - a user-provided crypto implementation, necessary for the secure sessions establishment that happens in the basic communication window
    /// - `notify` - a user-provided `AttrChangeNotifier`; typically, `Data Model::change_notify`; used to notify the Matter instance about changes in the state of the clusters' attributes, so that it can notify commissioning tools about them
    pub fn open_basic_comm_window<C>(
        &self,
        crypto: C,
        notify: &dyn AttrChangeNotifier,
    ) -> Result<(), Error>
    where
        C: Crypto,
    {
        self.matter()
            .open_basic_comm_window(MAX_COMM_WINDOW_TIMEOUT_SECS, crypto, notify)?;

        self.matter()
            .print_standard_qr_text(self.network.discovery_capabilities())?;

        self.matter()
            .print_standard_qr_code(QrTextType::Unicode, self.network.discovery_capabilities())
    }

    /// This method is a specialization of `run_transport_net` over the UDP transport (both IPv4 and IPv6).
    /// It calls `run_transport_net`.
    ///
    /// #Arguments
    /// - `crypto` - a user-provided crypto implementation, necessary for the secure sessions establishment that happens in the operational network
    /// - `net_stack` - a user-provided network stack
    /// - `net_interface` - the index of the network interface for joining multicast groups
    /// - `until` - the method will return once this future becomes ready
    /// - `comm` - a tuple of additional and optional `NetworkReceive` and `NetworkSend` transport implementations
    ///   (useful when a second transport needs to run in parallel with the operational Matter transport,
    ///   i.e. when using concurrent commissisoning)
    async fn run_oper_net<C, U, X, R, S>(
        &self,
        crypto: &C,
        net_stack: &U,
        net_interface: u32,
        until: X,
        mut comm: Option<(R, S)>,
    ) -> Result<(), Error>
    where
        C: Crypto,
        U: NetStack,
        X: Future<Output = Result<(), Error>> + MaybeSend,
        R: NetworkReceive,
        S: NetworkSend,
    {
        let mut socket = net_stack
            .bind(
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    MATTER_PORT,
                    0,
                    net_interface,
                )),
                // rs-matter does not really use IPv4 multicast for Groups, so we can just use `Ipv4Addr::UNSPECIFIED` here.
                Ipv4Addr::UNSPECIFIED,
                net_interface,
            )
            .await?;

        let (send, recv, multicast) = socket.split();

        let mut until_task = pin!(until);

        if let Some((comm_recv, comm_send)) = comm.as_mut() {
            info!("Running operational and commissioning networks");

            let mut netw_task = pin!(self.run_transport_net(
                crypto,
                ChainedNetwork::new(Address::is_udp, send, comm_send),
                ChainedNetwork::new(Address::is_udp, recv, comm_recv),
                ChainedNetwork::new(Address::is_udp, multicast, NoNetwork),
            ));

            select(&mut netw_task, &mut until_task).coalesce().await
        } else {
            info!("Running operational network");

            let mut netw_task = pin!(self.run_transport_net(crypto, send, recv, multicast));

            select(&mut netw_task, &mut until_task).coalesce().await
        }
    }

    /// This method runs the mDNS service.
    ///
    /// The netif instance is necessary, so that the loop can monitor the network and bring up/down
    /// the mDNS service when the netif goes up/down or changes its IP addresses.
    ///
    /// This is necessary because mDNS needs to know the current IP addresses and
    /// also needs to stop when the netif goes down.
    ///
    /// # Arguments
    /// - `crypto` - a user-provided crypto implementation
    /// - `net_stack` - a user-provided network stack
    /// - `netif` - a user-provided `Netif` implementation
    /// - `mdns` - a user-provided mDNS implementation
    async fn run_oper_netif_mdns<C, U, I, M>(
        &self,
        crypto: &C,
        net_stack: &U,
        netif: &I,
        mdns: &mut M,
    ) -> Result<(), Error>
    where
        C: Crypto,
        U: NetStack,
        I: NetifDiag + NetChangeNotif,
        M: Mdns,
    {
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        struct NetifState {
            ipv6: Vec<Ipv6Addr, MAX_NETIF_IPV6_ADDRS>,
            ipv4: Ipv4Addr,
            mac: [u8; 8],
            operational: bool,
            netif_index: u32,
        }

        impl NetifState {
            pub const fn new() -> Self {
                Self {
                    ipv6: Vec::new(),
                    ipv4: Ipv4Addr::UNSPECIFIED,
                    mac: [0; 8],
                    operational: false,
                    netif_index: 0,
                }
            }
        }

        fn load_netif_state<I>(net_diag: &I, state: &mut NetifState) -> Result<(), Error>
        where
            I: NetifDiag,
        {
            state.operational = false;
            state.ipv6.clear();
            state.ipv4 = Ipv4Addr::UNSPECIFIED;
            state.mac = [0; 8];

            net_diag.netifs(&mut |ni| {
                if ni.operational && !ni.ipv6_addrs.is_empty() {
                    state.operational = true;
                    state.ipv6.clear();
                    for addr in ni.ipv6_addrs {
                        if addr.is_unspecified() || state.ipv6.contains(addr) {
                            continue;
                        }

                        if state.ipv6.push(*addr).is_err() {
                            warn!(
                                "Netif {} has more than {} IPv6 addresses; {} will not be advertised",
                                ni.name, MAX_NETIF_IPV6_ADDRS, addr
                            );
                            break;
                        }
                    }
                    state.ipv4 = ni
                        .ipv4_addrs
                        .first()
                        .copied()
                        .unwrap_or(Ipv4Addr::UNSPECIFIED);
                    state.mac = *ni.hw_addr;
                    state.netif_index = ni.netif_index;
                }

                Ok(())
            })
        }

        async fn wait_changed<I>(
            net_diag: &I,
            cur_state: &NetifState,
            new_state: &mut NetifState,
        ) -> Result<(), Error>
        where
            I: NetifDiag + NetChangeNotif,
        {
            loop {
                load_netif_state(net_diag, new_state)?;

                if &*new_state != cur_state {
                    info!(
                        "Netif change detected.\n    Old: {:?}\n    New: {:?}",
                        cur_state, new_state
                    );
                    break Ok(());
                }

                trace!("No change");
                net_diag.wait_changed().await;
            }
        }

        let mut new_state = NetifState::new();
        load_netif_state(netif, &mut new_state)?;

        loop {
            let cur_state = new_state.clone();

            let mut netif_changed_task = pin!(wait_changed(netif, &cur_state, &mut new_state));

            let mut mdns_task = pin!(async {
                if cur_state.operational {
                    info!("Netif up: {:?}", cur_state);

                    info!("Running mDNS");

                    loop {
                        let _result = mdns
                            .run(
                                self.matter(),
                                crypto,
                                net_stack,
                                &cur_state.mac,
                                cur_state.ipv4,
                                &cur_state.ipv6,
                                cur_state.netif_index,
                            )
                            .await;

                        warn!("mDNS failed with {:?}, retrying in 5s...", _result);
                        Timer::after(Duration::from_secs(5)).await;
                    }
                } else {
                    info!("Netif down");
                    core::future::pending::<()>().await;
                }

                Ok(())
            });

            select(&mut netif_changed_task, &mut mdns_task)
                .coalesce()
                .await?;
        }
    }

    #[inline(always)]
    fn im<C, H, K>(&self, crypto: C, handler: H, kv: K) -> MatterStackInteractionModel<'_, C, H, K>
    where
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
    {
        MatterStackInteractionModel::new(
            self.matter(),
            crypto,
            &self.buffers,
            handler,
            kv,
            &self.state,
        )
    }

    async fn run_im<C, H, K>(
        &self,
        im: &MatterStackInteractionModel<'_, C, H, K>,
    ) -> Result<(), Error>
    where
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
    {
        // TODO
        // Reset the Matter transport buffers and all sessions first
        // self.matter().reset_transport()?;

        self.startup_im(im).await?;

        let mut responder = pin!(self.run_responder(im));
        let mut im_job = pin!(im.run());

        select(&mut responder, &mut im_job).coalesce().await
    }

    async fn run_im_with_bump<C, H, K>(
        &self,
        im: &MatterStackInteractionModel<'_, C, H, K>,
    ) -> Result<(), Error>
    where
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
    {
        // TODO
        // Reset the Matter transport buffers and all sessions first
        // self.matter().reset_transport()?;

        self.startup_im(im).await?;

        let mut responder = pin_alloc!(self.bump, self.run_responder_with_bump(im));
        let mut im_job = pin!(im.run());

        select(&mut responder, &mut im_job).coalesce().await
    }

    /// Re-hydrate the Interaction Model state (events watermark, persisted
    /// subscriptions) and deliver the `Startup` lifecycle op to the cluster
    /// handlers, which load the networks store among others - but only for the
    /// first Interaction Model instance that this stack runs (see `im_hydrated`).
    ///
    /// `BasicInformation::StartUp` is emitted by `InteractionModel::run` itself,
    /// once per process lifetime.
    async fn startup_im<C, H, K>(
        &self,
        im: &MatterStackInteractionModel<'_, C, H, K>,
    ) -> Result<(), Error>
    where
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
    {
        if self.im_hydrated.lock(|hydrated| hydrated.replace(true)) {
            return Ok(());
        }

        im.startup().await
    }

    async fn run_responder<C, H, K>(
        &self,
        im: &MatterStackInteractionModel<'_, C, H, K>,
    ) -> Result<(), Error>
    where
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
    {
        let responder = DefaultResponder::new(im);

        // Run the responder with up to MAX_RESPONDERS handlers (i.e. MAX_RESPONDERS exchanges can be handled simultenously)
        // Clients trying to open more exchanges than the ones currently running will get "I'm busy, please try again later"
        pin!(responder.run::<MAX_RESPONDERS, MAX_BUSY_RESPONDERS>()).await?;

        Ok(())
    }

    async fn run_responder_with_bump<C, H, K>(
        &self,
        im: &MatterStackInteractionModel<'_, C, H, K>,
    ) -> Result<(), Error>
    where
        C: Crypto,
        H: DataModel,
        K: KvBlobStoreAccess,
    {
        let responder = DefaultResponder::new(im);

        let mut actual = pin_alloc!(
            self.bump,
            self.run_one_responder_with_bump::<MAX_RESPONDERS, _>(responder.responder())
        );
        let mut busy = pin_alloc!(
            self.bump,
            self.run_one_responder_with_bump::<MAX_BUSY_RESPONDERS, _>(responder.busy_responder())
        );

        select(&mut actual, &mut busy).coalesce().await
    }

    /// Run a responder with Q handlers using the provided bump allocator.
    async fn run_one_responder_with_bump<const Q: usize, T>(
        &self,
        responder: &Responder<'_, T>,
    ) -> Result<(), Error>
    where
        T: ExchangeHandler,
    {
        info!("{}: Creating {} handlers", responder.name(), Q);

        let mut handlers = Vec::<_, Q>::new();
        debug!(
            "{}: Handlers size: {}B",
            responder.name(),
            core::mem::size_of_val(&handlers)
        );

        for handler_id in 0..Q {
            unwrap!(handlers
                .push(pin_alloc!(self.bump, responder.handle(handler_id)))
                .map_err(|_| ())); // Cannot fail because the vector has size N
        }

        let handlers = pin!(handlers);
        let handlers = unsafe { handlers.map_unchecked_mut(|handlers| handlers.as_mut_slice()) };

        select_slice(handlers).await.0
    }

    fn run_transport_net<'t, C, S, R, M>(
        &'t self,
        crypto: &'t C,
        send: S,
        recv: R,
        multicast: M,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend + 't
    where
        C: Crypto + 't,
        S: NetworkSend + 't,
        R: NetworkReceive + 't,
        M: NetworkMulticast + 't,
    {
        self.matter().run(crypto, send, recv, multicast)
    }
}

/// A trait representing a user task that needs access to the operational network interface
/// (Netif and net stack) to perform its work.
///
/// Note that the task would be started only when `rs-matter`
/// brings up the operational interface (eth, wifi or thread)
/// and if the interface goes down, the user task would be stopped.
/// Upon re-connection, the task would be started again.
pub trait UserTask: MaybeSend {
    /// Run the task with the given network stack and network interface
    fn run<S, N>(
        &mut self,
        net_stack: S,
        netif: N,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif;
}

impl<T> UserTask for &mut T
where
    T: UserTask,
{
    fn run<S, N>(
        &mut self,
        net_stack: S,
        netif: N,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
    {
        (*self).run(net_stack, netif)
    }
}

impl UserTask for () {
    fn run<S, N>(
        &mut self,
        _net_stack: S,
        _netif: N,
    ) -> impl Future<Output = Result<(), Error>> + MaybeSend
    where
        S: NetStack,
        N: NetifDiag + NetChangeNotif,
    {
        core::future::pending::<Result<(), Error>>()
    }
}

// The data model is not created yet, so we don't have to notify anything
pub(crate) struct DummyAttrNotifier;

impl AttrChangeNotifier for DummyAttrNotifier {
    fn notify_attr_changed(&self, _endpoint_id: EndptId, _cluster_id: ClusterId, _attr_id: AttrId) {
    }

    fn notify_cluster_changed(&self, _endpoint_id: EndptId, _cluster_id: ClusterId) {}

    fn notify_endpoint_changed(&self, _endpoint_id: EndptId) {}

    fn notify_all_changed(&self) {}
}
