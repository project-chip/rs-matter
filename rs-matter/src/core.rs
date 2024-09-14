/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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

use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use crate::acl::AclMgr;
use crate::data_model::{
    cluster_basic_information::BasicInfoConfig,
    sdm::{dev_att::DevAttDataFetcher, failsafe::FailSafe},
};
use crate::error::*;
use crate::fabric::FabricMgr;
use crate::mdns::MdnsService;
use crate::pairing::{print_pairing_code_and_qr, DiscoveryCapabilities};
use crate::secure_channel::{pake::PaseMgr, spake2p::VerifierData};
use crate::transport::core::{PacketBufferExternalAccess, TransportMgr};
use crate::transport::network::{NetworkReceive, NetworkSend};
use crate::utils::cell::RefCell;
use crate::utils::epoch::Epoch;
use crate::utils::init::{init, Init};
use crate::utils::rand::Rand;
use crate::utils::storage::pooled::BufferAccess;
use crate::utils::sync::Notification;

/* The Matter Port */
pub const MATTER_PORT: u16 = 5540;

/// Device Commissioning Data
#[derive(Debug, Clone)]
pub struct CommissioningData {
    /// The data like password or verifier that is required to authenticate
    pub verifier: VerifierData,
    /// The 12-bit discriminator used to differentiate between multiple devices
    pub discriminator: u16,
}

/// The primary Matter Object
pub struct Matter<'a> {
    pub(crate) fabric_mgr: RefCell<FabricMgr>,
    pub acl_mgr: RefCell<AclMgr>, // Public for tests
    pub(crate) pase_mgr: RefCell<PaseMgr>,
    pub(crate) failsafe: RefCell<FailSafe>,
    pub transport_mgr: TransportMgr<'a>, // Public for tests
    persist_notification: Notification<NoopRawMutex>,
    epoch: Epoch,
    rand: Rand,
    dev_det: &'a BasicInfoConfig<'a>,
    dev_att: &'a dyn DevAttDataFetcher,
    port: u16,
}

impl<'a> Matter<'a> {
    /// Create a new Matter object when support for the Rust Standard Library is enabled.
    ///
    /// # Parameters
    /// * dev_det: An object of type [BasicInfoConfig].
    /// * dev_att: An object that implements the trait [DevAttDataFetcher]. Any Matter device
    ///   requires a set of device attestation certificates and keys. It is the responsibility of
    ///   this object to return the device attestation details when queried upon.
    /// * mdns: An object of type [MdnsService]. This object is responsible for handling mDNS
    ///   responses and queries related to the operation of the Matter stack.
    /// * port: The port number on which the Matter stack will listen for incoming connections.
    #[cfg(feature = "std")]
    #[inline(always)]
    pub const fn new_default(
        dev_det: &'a BasicInfoConfig<'a>,
        dev_att: &'a dyn DevAttDataFetcher,
        mdns: MdnsService<'a>,
        port: u16,
    ) -> Self {
        use crate::utils::epoch::sys_epoch;
        use crate::utils::rand::sys_rand;

        Self::new(dev_det, dev_att, mdns, sys_epoch, sys_rand, port)
    }

    /// Create a new Matter object
    ///
    /// # Parameters
    /// * dev_det: An object of type [BasicInfoConfig].
    /// * dev_att: An object that implements the trait [DevAttDataFetcher]. Any Matter device
    ///   requires a set of device attestation certificates and keys. It is the responsibility of
    ///   this object to return the device attestation details when queried upon.
    /// * mdns: An object of type [MdnsService]. This object is responsible for handling mDNS
    ///   responses and queries related to the operation of the Matter stack.
    /// * epoch: A function of type [Epoch]. This function is responsible for providing the current
    ///   "unix" time in milliseconds
    /// * rand: A function of type [Rand]. This function is responsible for generating random data.
    /// * port: The port number on which the Matter stack will listen for incoming connections.
    #[inline(always)]
    pub const fn new(
        dev_det: &'a BasicInfoConfig<'a>,
        dev_att: &'a dyn DevAttDataFetcher,
        mdns: MdnsService<'a>,
        epoch: Epoch,
        rand: Rand,
        port: u16,
    ) -> Self {
        Self {
            fabric_mgr: RefCell::new(FabricMgr::new()),
            acl_mgr: RefCell::new(AclMgr::new()),
            pase_mgr: RefCell::new(PaseMgr::new(epoch, rand)),
            failsafe: RefCell::new(FailSafe::new()),
            transport_mgr: TransportMgr::new(mdns, dev_det, port, epoch, rand),
            persist_notification: Notification::new(),
            epoch,
            rand,
            dev_det,
            dev_att,
            port,
        }
    }

    /// Create an in-place initializer for a Matter object
    /// when support for the Rust Standard Library is enabled.
    ///
    /// # Parameters
    /// * dev_det: An object of type [BasicInfoConfig].
    /// * dev_att: An object that implements the trait [DevAttDataFetcher]. Any Matter device
    ///   requires a set of device attestation certificates and keys. It is the responsibility of
    ///   this object to return the device attestation details when queried upon.
    /// * mdns: An object of type [MdnsService]. This object is responsible for handling mDNS
    ///   responses and queries related to the operation of the Matter stack.
    /// * port: The port number on which the Matter stack will listen for incoming connections.
    #[cfg(feature = "std")]
    pub fn init_default(
        dev_det: &'a BasicInfoConfig<'a>,
        dev_att: &'a dyn DevAttDataFetcher,
        mdns: MdnsService<'a>,
        port: u16,
    ) -> impl Init<Self> {
        use crate::utils::epoch::sys_epoch;
        use crate::utils::rand::sys_rand;

        Self::init(dev_det, dev_att, mdns, sys_epoch, sys_rand, port)
    }

    /// Create an in-place initializer for a Matter object
    ///
    /// # Parameters
    /// * dev_det: An object of type [BasicInfoConfig].
    /// * dev_att: An object that implements the trait [DevAttDataFetcher]. Any Matter device
    ///   requires a set of device attestation certificates and keys. It is the responsibility of
    ///   this object to return the device attestation details when queried upon.
    /// * mdns: An object of type [MdnsService]. This object is responsible for handling mDNS
    ///   responses and queries related to the operation of the Matter stack.
    /// * epoch: A function of type [Epoch]. This function is responsible for providing the current
    ///   "unix" time in milliseconds
    /// * rand: A function of type [Rand]. This function is responsible for generating random data.
    /// * port: The port number on which the Matter stack will listen for incoming connections.
    pub fn init(
        dev_det: &'a BasicInfoConfig<'a>,
        dev_att: &'a dyn DevAttDataFetcher,
        mdns: MdnsService<'a>,
        epoch: Epoch,
        rand: Rand,
        port: u16,
    ) -> impl Init<Self> {
        init!(
            Self {
                fabric_mgr <- RefCell::init(FabricMgr::init()),
                acl_mgr <- RefCell::init(AclMgr::init()),
                pase_mgr <- RefCell::init(PaseMgr::init(epoch, rand)),
                failsafe: RefCell::new(FailSafe::new()),
                transport_mgr <- TransportMgr::init(mdns, dev_det, port, epoch, rand),
                persist_notification: Notification::new(),
                epoch,
                rand,
                dev_det,
                dev_att,
                port,
            }
        )
    }

    pub fn initialize_transport_buffers(&self) -> Result<(), Error> {
        self.transport_mgr.initialize_buffers()
    }

    pub fn dev_det(&self) -> &BasicInfoConfig<'_> {
        self.dev_det
    }

    pub fn dev_att(&self) -> &dyn DevAttDataFetcher {
        self.dev_att
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn rand(&self) -> Rand {
        self.rand
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn transport_rx_buffer(&self) -> impl BufferAccess<[u8]> + '_ {
        self.transport_mgr.rx_buffer()
    }

    pub fn transport_tx_buffer(&self) -> impl BufferAccess<[u8]> + '_ {
        self.transport_mgr.tx_buffer()
    }

    /// A utility method to replace the initial mDNS implementation with another one.
    ///
    /// Useful in particular with `MdnsService::Provided`, where the user would still like
    /// to create the `Matter` instance in a const-context, as in e.g.:
    /// `const MATTER: Matter<'static> = Matter::new(...);`
    ///
    /// The above const-creation is incompatible with `MdnsService::Provided` which carries a
    /// `&dyn Mdns` pointer, which cannot be initialized from within a const context with anything
    /// else than a `const`. (At least not yet - there is an unstable nightly Rust feature for that).
    ///
    /// The solution is to const-construct the `Matter` object with `MdnsService::Disabled`, and
    /// after that - while/if we still have exclusive, mutable access to the `Matter` object -
    /// replace the `MdnsService::Disabled` initial impl with another, like `MdnsService::Provided`.
    pub fn replace_mdns(&mut self, mdns: MdnsService<'a>) {
        self.transport_mgr.replace_mdns(mdns);
    }

    /// A utility method to replace the initial Device Attestation Data Fetcher with another one.
    ///
    /// Reasoning and use-cases explained in the documentation of `replace_mdns`.
    pub fn replace_dev_att(&mut self, dev_att: &'a dyn DevAttDataFetcher) {
        self.dev_att = dev_att;
    }

    pub fn load_fabrics(&self, data: &[u8]) -> Result<(), Error> {
        self.fabric_mgr
            .borrow_mut()
            .load(data, &self.transport_mgr.mdns)
    }

    pub fn load_acls(&self, data: &[u8]) -> Result<(), Error> {
        self.acl_mgr.borrow_mut().load(data)
    }

    pub fn store_fabrics<'b>(&self, buf: &'b mut [u8]) -> Result<Option<&'b [u8]>, Error> {
        self.fabric_mgr.borrow_mut().store(buf)
    }

    pub fn store_acls<'b>(&self, buf: &'b mut [u8]) -> Result<Option<&'b [u8]>, Error> {
        self.acl_mgr.borrow_mut().store(buf)
    }

    pub fn is_changed(&self) -> bool {
        self.acl_mgr.borrow().is_changed() || self.fabric_mgr.borrow().is_changed()
    }

    /// Return `true` if there is at least one commissioned fabric
    //
    // TODO:
    // The implementation of this method needs to change in future,
    // because the current implementation does not really track whether
    // `CommissioningComplete` had been actually received for the fabric.
    //
    // The fabric is created once we receive `AddNoc`, but that's just
    // not enough. The fabric should NOT be considered commissioned until
    // after we receive `CommissioningComplete` on behalf of a Case session
    // for the fabric in question.
    pub fn is_commissioned(&self) -> bool {
        self.fabric_mgr.borrow().used_count() > 0
    }

    fn start_comissioning(
        &self,
        dev_comm: CommissioningData,
        discovery_capabilities: DiscoveryCapabilities,
        buf: &mut [u8],
    ) -> Result<bool, Error> {
        if !self.pase_mgr.borrow().is_pase_session_enabled() && self.fabric_mgr.borrow().is_empty()
        {
            print_pairing_code_and_qr(self.dev_det, &dev_comm, discovery_capabilities, buf)?;

            self.pase_mgr.borrow_mut().enable_pase_session(
                dev_comm.verifier,
                dev_comm.discriminator,
                &self.transport_mgr.mdns,
            )?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Resets the transport layer by clearing all sessions, exchanges, the RX buffer and the TX buffer
    /// NOTE: User should be careful _not_ to call this method while the transport layer and/or the built-in mDNS is running.
    pub fn reset_transport(&self) -> Result<(), Error> {
        self.transport_mgr.reset()
    }

    pub async fn run<S, R>(
        &self,
        send: S,
        recv: R,
        dev_comm: Option<(CommissioningData, DiscoveryCapabilities)>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
    {
        if let Some((dev_comm, discovery_caps)) = dev_comm {
            let buf_access = PacketBufferExternalAccess(&self.transport_mgr.rx);
            let mut buf = buf_access.get().await.ok_or(ErrorCode::NoSpace)?;

            self.start_comissioning(dev_comm, discovery_caps, &mut buf)?;
        }

        self.transport_mgr.run(send, recv).await
    }

    #[cfg(not(all(
        feature = "std",
        any(target_os = "macos", all(feature = "zeroconf", target_os = "linux"))
    )))]
    pub async fn run_builtin_mdns<S, R>(
        &self,
        send: S,
        recv: R,
        host: &crate::mdns::Host<'_>,
        interface: Option<u32>,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
    {
        self.transport_mgr
            .run_builtin_mdns(send, recv, host, interface)
            .await
    }

    /// Notify that the ACLs or Fabrics _might_ have changed
    /// This method is supposed to be called after processing SC and IM messages that might affect the ACLs or Fabrics.
    ///
    /// The default IM and SC handlers (`DataModel` and `SecureChannel`) do call this method after processing the messages.
    ///
    /// TODO: Fix the method name as it is not clear enough. Potentially revamp the whole persistence notification logic
    pub fn notify_changed(&self) {
        if self.is_changed() {
            self.persist_notification.notify();
        }
    }

    /// A hook for user persistence code to wait for potential changes in ACLs and/or Fabrics.
    /// Once this future resolves, user code is supposed to inspect ACLs and Fabrics for changes, and
    /// if there are changes, persist them.
    ///
    /// TODO: Fix the method name as it is not clear enough. Potentially revamp the whole persistence notification logic
    pub async fn wait_changed(&self) {
        self.persist_notification.wait().await
    }
}
