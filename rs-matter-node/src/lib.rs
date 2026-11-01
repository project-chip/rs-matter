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

//! The Matter node: the [`Matter`] object, which puts the transport (of
//! `rs-matter-transport`), the Secure Channel state (of `rs-matter-sc`) and the
//! state of the node (of `rs-matter-node-core`) together, and the `Accessor`.
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(async_fn_in_trait)]
#![allow(unknown_lints)]
#![allow(clippy::uninlined_format_args)]
#![recursion_limit = "1024"]
// `cargo llvm-cov` sets `coverage_nightly` when it runs on a nightly toolchain;
// the test modules are then excluded from the coverage report
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

#[cfg(feature = "alloc")]
extern crate alloc;

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

use core::cell::UnsafeCell;
use core::num::NonZeroU8;

use rand_core::Rng;

use crate::attest::DeviceAttestation;
use crate::basic_info::{
    BasicInfoConfig, BasicInfoSettings, BASIC_INFO_CLUSTER_ID, CONFIGURATION_VERSION_ATTR_ID,
};
use crate::crypto::Crypto;
use crate::dm::ROOT_ENDPOINT_ID;
use crate::dm::{AttrChangeNotifier, EndptId, GroupMembership};
use crate::error::{Error, ErrorCode};
use crate::fabric::Fabrics;
use crate::failsafe::{FailSafe, DEFAULT_FAILSAFE_EXPIRY_SECS};
use crate::handover::{CommissioningHandover, HandoverRegulatory};
use crate::icd::IcdAdvertisement;
use crate::networks::{load_networks, Networks};
use crate::pairing::qr::{
    no_optional_data, CommFlowType, NoOptionalData, Qr, QrPayload, QrTextType,
};
use crate::pairing::DiscoveryCapabilities;
use crate::persist::{
    KvBlobStore, KvBlobStoreAccess, MatterKvBlobStoreAccess, Persist, OPERATIONAL_HOURS_KEY,
    REBOOT_COUNT_KEY,
};
use crate::rtc::Rtc;
#[cfg(feature = "case-resumption")]
use crate::sc::case::ResumableSessions;
use crate::sc::pase::spake2p::SPAKE2P_VERIFIER_SALT_ZEROED;
use crate::sc::pase::{CommWindowState, Pase};
use crate::sc::{ScHost, ScState};
use crate::transport::network::MatterLocalService;
use crate::transport::network::{NetworkMulticast, NetworkReceive, NetworkSend};
use crate::transport::session::Sessions;
use crate::transport::{
    PacketBufferExternalAccess, Transport, TransportHost, TransportRunner, MAX_RX_BUF_SIZE,
    MAX_TX_BUF_SIZE,
};
use crate::utils::cell::RefCell;
use crate::utils::init::{init, Init, UnsafeCellInit};
use crate::utils::storage::pooled::Buffers;
use crate::utils::sync::blocking::Mutex;
use crate::utils::sync::Notification;
use crate::utils::timers::Instant;
#[cfg(feature = "case-resumption")]
use crate::utils::timers::{Duration, Timer};

// The dependencies, under the names the code uses for them
use rs_matter_cert::attest;
use rs_matter_crypto as crypto;
use rs_matter_dm_core as dm;
use rs_matter_dm_core::persist;
use rs_matter_node_core::{basic_info, fabric, failsafe, handover, icd, networks, rtc};
use rs_matter_pairing as pairing;
use rs_matter_sc as sc;
#[cfg(test)]
use rs_matter_tlv as tlv;
use rs_matter_utils as utils;
use rs_matter_utils::error;

pub use rs_matter_node_core::{BasicCommData, MATTER_PORT};
pub use transaction::Transaction;

pub use rs_matter_transport as transport;
#[cfg(feature = "groups")]
pub use rs_matter_transport::groupcast;
pub use rs_matter_transport::proto::im;

pub mod acl;
#[cfg(feature = "pics")]
pub mod pics;
mod transaction;

/// The reason for the latest boot of the node.
///
/// The values are the ones of the General Diagnostics cluster.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum BootReason {
    Unspecified = 0,
    PowerOnReboot = 1,
    BrownOutReset = 2,
    SoftwareWatchdogReset = 3,
    HardwareWatchdogReset = 4,
    SoftwareUpdateCompleted = 5,
    SoftwareReset = 6,
}

/// The primary Matter Object
// `repr(C)` pins the field order. The transport's fields are accessed one by
// one all over the hot paths, so it comes first: on targets like Thumb only the
// first 4 KiB of the object are reachable with a short immediate offset. Left
// to the compiler, the order shifts with small changes to any of the field
// types, and with it the code size.
#[repr(C)]
pub struct Matter<'a> {
    /// The transport state of the Matter Object
    pub(crate) transport: Transport,
    /// The device attestation data fetcher for this Matter device
    dev_att: &'a dyn DeviceAttestation,
    /// The internal state of the Matter Object, protected by a mutex for concurrent access from different threads and async tasks.
    state: LockedBySessions<NodeState>,
    /// The basic information configuration for this Matter device
    dev_det: &'a BasicInfoConfig<'a>,
    /// The scratch buffer used by the key-value persistence machinery for
    /// (de)serializing BLOBs. Behind a blocking mutex so [`Matter::kv`] can
    /// recombine it with the user's raw [`KvBlobStore`](crate::persist::KvBlobStore)
    /// into a full [`KvBlobStoreAccess`](crate::persist::KvBlobStoreAccess). Its
    /// size is set by the `kv-blob-store-*` Cargo features (see
    /// [`KV_BUF_SIZE`](crate::persist::KV_BUF_SIZE)).
    kv_buf: Mutex<RefCell<[u8; crate::persist::KV_BUF_SIZE]>>,
    /// The basic commissioning data for this Matter device
    dev_comm: BasicCommData,
    /// The port number on which the Matter stack will listen for incoming connections
    port: u16,
    /// The Groupcast testing-mode bridge - shared between the transport RX
    /// path, the Interaction Model's invoke processing and the Groupcast
    /// cluster handler. See `dm::clusters::groupcast::TestingBridge`.
    #[cfg(feature = "groups")]
    groupcast_testing: crate::groupcast::TestingBridge,
    /// Fires when the Trusted Time Source is set, changed or cleared.
    time_source_changed: Notification,
}

impl<'a> Matter<'a> {
    /// Create a new Matter object.
    ///
    /// # Parameters
    /// * dev_det: An object of type [BasicInfoConfig].
    /// * dev_comm: An object of type [BasicCommData]. This object contains the basic commissioning
    ///   data required for the device.
    /// * dev_att: An object that implements the trait [DevAttDataFetcher]. Any Matter device
    ///   requires a set of device attestation certificates and keys. It is the responsibility of
    ///   this object to return the device attestation details when queried upon.
    /// * port: The port number on which the Matter stack will listen for incoming connections.
    #[inline(always)]
    pub const fn new(
        dev_det: &'a BasicInfoConfig<'a>,
        dev_comm: BasicCommData,
        dev_att: &'a dyn DeviceAttestation,
        port: u16,
    ) -> Self {
        Self {
            state: LockedBySessions::new(NodeState::new()),
            transport: Transport::new(dev_det.sai),
            dev_det,
            dev_comm,
            dev_att,
            port,
            #[cfg(feature = "groups")]
            groupcast_testing: crate::groupcast::TestingBridge::new(),
            kv_buf: Mutex::new(RefCell::new([0; crate::persist::KV_BUF_SIZE])),
            time_source_changed: Notification::new(),
        }
    }

    /// Create an in-place initializer for a Matter object.
    ///
    /// # Parameters
    /// * dev_det: An object of type [BasicInfoConfig].
    /// * dev_comm: An object of type [BasicCommData]. This object contains the basic commissioning
    ///   data required for the device.
    /// * dev_att: An object that implements the trait [DevAttDataFetcher]. Any Matter device
    ///   requires a set of device attestation certificates and keys. It is the responsibility of
    ///   this object to return the device attestation details when queried upon.
    /// * port: The port number on which the Matter stack will listen for incoming connections.
    pub fn init(
        dev_det: &'a BasicInfoConfig<'a>,
        dev_comm: BasicCommData,
        dev_att: &'a dyn DeviceAttestation,
        port: u16,
    ) -> impl Init<Self> {
        // Two variants because the `init!` macro does not accept `#[cfg]`
        // on fields
        #[cfg(feature = "groups")]
        {
            init!(
                Self {
                    state <- LockedBySessions::init(NodeState::init()),
                    transport <- Transport::init(dev_det.sai),
                    dev_det,
                    dev_comm,
                    dev_att,
                    port,
                    groupcast_testing <- crate::groupcast::TestingBridge::init(),
                    kv_buf <- Mutex::init(RefCell::init(crate::utils::init::zeroed())),
                    time_source_changed <- Notification::init(),
                }
            )
        }

        #[cfg(not(feature = "groups"))]
        {
            init!(
                Self {
                    state <- LockedBySessions::init(NodeState::init()),
                    transport <- Transport::init(dev_det.sai),
                    dev_det,
                    dev_comm,
                    dev_att,
                    port,
                    kv_buf <- Mutex::init(RefCell::init(crate::utils::init::zeroed())),
                    time_source_changed <- Notification::init(),
                }
            )
        }
    }

    pub fn dev_det(&self) -> &BasicInfoConfig<'_> {
        self.dev_det
    }

    pub fn dev_att(&self) -> &dyn DeviceAttestation {
        self.dev_att
    }

    pub fn dev_comm(&self) -> &BasicCommData {
        &self.dev_comm
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Persist the reboot count established by [`Matter::startup`], so the
    /// next boot counts from it.
    ///
    /// Separate from `startup` on purpose. The counter needs one write per
    /// boot - there is exactly one increment per boot, so unlike the event
    /// counter there is nothing to batch - and putting that write in the boot
    /// path means a device stuck in a boot loop rewrites flash on every
    /// iteration. Calling this once the boot looks healthy (the transport is
    /// up, or some device-specific milestone) leaves a boot loop writing
    /// nothing at all.
    ///
    /// The cost of deferring is that a crash before this call leaves that boot
    /// uncounted, which the spec's "best-effort" wording allows.
    ///
    /// Idempotent: a call that would rewrite the value already on record does
    /// nothing, so it is safe to call repeatedly (per milestone, or on a
    /// timer).
    ///
    /// A device that never calls this reports a plausible count for the current
    /// boot but never advances across reboots.
    pub fn persist_reboot_count<K: KvBlobStoreAccess>(&self, kv: K) -> Result<(), Error> {
        let reboot_count = self.with_state(|state| *state.reboot_count);

        let mut persist = Persist::new(kv);

        // Nothing to do if this boot's count is already on record, so
        // calling this more than once per boot costs no writes.
        if persist.load_tlv::<u16>(REBOOT_COUNT_KEY)? != Some(reboot_count) {
            persist.store_tlv(REBOOT_COUNT_KEY, reboot_count)?;
        }

        persist.run()
    }

    /// The node's reboot count, as reported by
    /// `GeneralDiagnostics::RebootCount`.
    ///
    /// Bumped once per [`Matter::startup`] and persisted, so it survives
    /// reboots and resets only on a factory reset.
    pub fn reboot_count(&self) -> u16 {
        self.with_state(|state| *state.reboot_count)
    }

    /// Persist the node's operational hours, so that
    /// [`Matter::total_operational_hours`] carries them across reboots.
    ///
    /// Call periodically, e.g. hourly. A call with no new hour to record writes
    /// nothing, and the hours since the last call are lost on a reboot, which
    /// the spec's "best-effort" wording allows.
    ///
    /// A device that never calls this reports the hours of the current boot only.
    pub fn persist_operational_hours<K: KvBlobStoreAccess>(&self, kv: K) -> Result<(), Error> {
        let hours = self.total_operational_hours();

        let mut persist = Persist::new(kv);

        if persist.load_tlv::<u32>(OPERATIONAL_HOURS_KEY)? != Some(hours) {
            persist.store_tlv(OPERATIONAL_HOURS_KEY, hours)?;
        }

        persist.run()
    }

    /// The node's operational hours, as reported by
    /// `GeneralDiagnostics::TotalOperationalHours`: those on record at
    /// [`Matter::startup`] plus those of the current boot.
    ///
    /// Reset only by [`Matter::factory_reset`].
    pub fn total_operational_hours(&self) -> u32 {
        let recorded = self.with_state(|state| *state.operational_hours);
        let current = Instant::now().as_secs() / (60 * 60);

        recorded.saturating_add(current.min(u32::MAX as u64) as u32)
    }

    /// The reason for the node's latest boot, as reported by
    /// `GeneralDiagnostics::BootReason`.
    ///
    /// `Unspecified` unless the platform sets it with [`Matter::set_boot_reason`].
    pub fn boot_reason(&self) -> BootReason {
        self.with_state(|state| *state.boot_reason)
    }

    /// Set the reason for the node's latest boot. Call once at startup.
    pub fn set_boot_reason(&self, reason: BootReason) {
        self.with_state(|state| *state.boot_reason = reason);
    }

    /// Wait until the Trusted Time Source is set, changed or cleared.
    ///
    /// Single waiter: the [`TimeSyncClient`](crate::dm::clusters::time_sync::client::TimeSyncClient).
    pub async fn wait_trusted_time_source_changed(&self) {
        self.time_source_changed.wait().await
    }

    pub fn notify_trusted_time_source_changed(&self) {
        self.time_source_changed.notify();
    }

    /// What the device advertises as an ICD - its `SAT`, and for a
    /// Long-Idle-Time-capable one the `ICD` TXT key and the `SII` cap while
    /// operating as a SIT - or `None` when it is not one.
    pub fn icd_advertisement(&self) -> Option<IcdAdvertisement> {
        self.with_state(|state| *state.icd_adv)
    }

    /// Set the ICD advertisement and, if it changed, signal the mDNS layer to
    /// re-publish.
    ///
    /// Also snapshots the advertisement's fast polling interval onto the
    /// transport, which the send paths read while holding the very lock the
    /// advertisement itself lives under.
    pub fn set_icd_advertisement(&self, adv: Option<IcdAdvertisement>) {
        let changed = self.with_state(|state| {
            let changed = *state.icd_adv != adv;
            *state.icd_adv = adv;
            changed
        });

        self.transport
            .set_icd_fast_poll_interval(adv.map_or(0, |adv| adv.fast_poll_ms));

        if changed {
            self.transport.notify_mdns_changed();
        }
    }

    /// Return true if the ICD device is considered "busy" right now, i.e. it cannot
    /// switch to idle mode even if there is no traffic. The device is considered busy if:
    /// - the commissioning fail-safe is armed
    /// - and/or there are any open exchanges on any session (an interaction in flight)
    pub fn is_icd_busy(&self) -> bool {
        self.with_state(|state| {
            state.failsafe.is_armed()
                || state.sessions.iter().any(|session| session.has_exchanges())
        })
    }

    /// Combine a user-provided raw [`KvBlobStore`] with the scratch buffer owned
    /// by this `Matter` object to obtain a full [`KvBlobStoreAccess`].
    ///
    /// # Arguments
    /// - `store` - the raw [`KvBlobStore`] implementation to wrap
    pub fn kv<'s, S: KvBlobStore + 's>(&'s self, store: S) -> MatterKvBlobStoreAccess<'s, S> {
        MatterKvBlobStoreAccess::new(store, &self.kv_buf)
    }

    /// Get a reference to the transport state of this Matter object.
    ///
    /// All transport-related state and operations (mDNS change/resolve
    /// rendezvous, session/group notifications, RX/TX buffers, exchange
    /// initiation/acceptance) live on [`Transport`].
    #[inline(always)]
    pub const fn transport(&self) -> &Transport {
        &self.transport
    }

    pub fn transport_rx_buffer(&self) -> PacketBufferExternalAccess<'_, MAX_RX_BUF_SIZE> {
        self.transport().rx_buffer()
    }

    pub fn transport_tx_buffer(&self) -> PacketBufferExternalAccess<'_, MAX_TX_BUF_SIZE> {
        self.transport().tx_buffer()
    }

    /// A utility method to replace the initial Device Attestation with another one.
    pub fn replace_dev_att(&mut self, dev_att: &'a dyn DeviceAttestation) {
        self.dev_att = dev_att;
    }

    /// Log the standard QR code text.
    ///
    /// The printed QR code text corresponds to the standard commissioning flow (i.e. `CommFlowType::Standard`)
    /// and contains no optional data.
    ///
    /// This method is useful primarily during development, when the Matter device is
    /// attached to a console. It is expected that the developer will call this method prior to running the Matter transport.
    ///
    /// # Arguments
    /// - `disc_caps`: The discovery capabilities to be used in the QR code payload
    pub fn print_standard_qr_text(&self, disc_caps: DiscoveryCapabilities) -> Result<(), Error> {
        let rx_buf = self.transport().rx_buffer();

        let mut buf = rx_buf.get_immediate().ok_or(ErrorCode::NoMemory)?;
        let buf = &mut *buf;

        let payload = self.standard_qr_payload(disc_caps)?;

        let (text, _) = payload.as_str(buf)?;

        // Do not remove this logging line or change its formatting.
        // C++ E2E tests rely on this log line to grep the QR code
        info!("SetupQRCode: [{}]", text);

        Ok(())
    }

    /// Log the NDEF message an NFC tag should carry for this device.
    ///
    /// # Arguments
    /// - `disc_caps`: The discovery capabilities to be used in the QR code payload
    pub fn print_standard_nfc_ndef(&self, disc_caps: DiscoveryCapabilities) -> Result<(), Error> {
        let rx_buf = self.transport().rx_buffer();

        let mut buf = rx_buf.get_immediate().ok_or(ErrorCode::NoMemory)?;
        let buf = &mut *buf;

        let payload = self.standard_qr_payload(disc_caps)?;

        let (ndef, remaining) = payload.as_ndef(buf)?;

        // Hex, because bytes are what get written to the tag, and as one
        // contiguous string so it can be compared against a tag reader's dump.
        // (`fmt::Bytes` pretty-prints across lines, which is unusable here.)
        // The buffer `as_ndef` hands back is where it goes - two characters per
        // byte.
        const HEX: &[u8; 16] = b"0123456789ABCDEF";

        let hex_len = ndef.len() * 2;
        if remaining.len() < hex_len {
            Err(ErrorCode::BufferTooSmall)?;
        }

        for (index, byte) in ndef.iter().enumerate() {
            remaining[index * 2] = HEX[(byte >> 4) as usize];
            remaining[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
        }

        // Cannot fail: every byte written above is an ASCII hex digit.
        let hex = unwrap!(
            core::str::from_utf8(&remaining[..hex_len]).map_err(|_| ErrorCode::InvalidData)
        );

        info!("SetupNFCTagNDEF: [{}]", hex);

        Ok(())
    }

    /// Log the standard QR code.
    ///
    /// The printed QR code corresponds to the standard commissioning flow (i.e. `CommFlowType::Standard`)
    /// and contains no optional data.
    ///
    /// This method is useful primarily during development, when the Matter device is
    /// attached to a console. It is expected that the developer will call this method prior to running the Matter transport.
    ///
    /// # Arguments
    /// - `text_type`: The type of text representation to use when printing the QR code
    /// - `disc_caps`: The discovery capabilities to be used in the QR code payload
    pub fn print_standard_qr_code(
        &self,
        text_type: QrTextType,
        disc_caps: DiscoveryCapabilities,
    ) -> Result<(), Error> {
        // Also print the pairing code for convenience
        info!(
            "PairingCode: [{}]",
            self.dev_comm.compute_pretty_pairing_code()
        );

        let rx_buf = self.transport().rx_buffer();

        let mut buf = rx_buf.get_immediate().ok_or(ErrorCode::NoMemory)?;
        let buf = &mut *buf;

        let payload = self.standard_qr_payload(disc_caps)?;

        let (text, buf) = payload.as_str(buf)?;

        let (tmp_buf, out_buf) = buf.split_at_mut(buf.len() / 2);

        let qr = Qr::compute(text, tmp_buf, out_buf)?;

        const BORDER_SIZE: u8 = 4;

        for y in qr.lines_range(text_type, BORDER_SIZE) {
            info!(
                "{}",
                qr.line_as_str(text_type, BORDER_SIZE, false, false, y, tmp_buf)?
                    .0
            );
        }

        Ok(())
    }

    /// Return the standard QR code payload
    ///
    /// The returned QR code payload corresponds to the standard commissioning flow (i.e. `CommFlowType::Standard`)
    /// and contains no optional data.
    ///
    /// # Arguments
    /// - `disc_caps`: The discovery capabilities to be used in the QR code payload
    fn standard_qr_payload(
        &self,
        disc_caps: DiscoveryCapabilities,
    ) -> Result<QrPayload<'_, NoOptionalData>, Error> {
        let payload = QrPayload::new(
            disc_caps,
            CommFlowType::Standard,
            self.dev_comm.clone(),
            self.dev_det.vid,
            self.dev_det.pid,
            self.dev_det.serial_no,
            no_optional_data as _,
        );

        Ok(payload)
    }

    /// Return `true` if there is at least one fabric.
    ///
    /// Note that this is emphatically *not* "the device is commissioned": a fabric is created
    /// as soon as `AddNOC` is received, which is well before the commissioner has established a
    /// CASE session over the operational network and sent `CommissioningComplete`. Code that
    /// needs to know whether commissioning is still in progress should use
    /// [`Matter::is_comm_window_open`] instead, as the commissioning window stays open for exactly
    /// that long.
    pub fn has_fabrics(&self) -> bool {
        self.with_state(|state| state.fabrics.iter().next().is_some())
    }

    /// Return the state of the commissioning window - whether one is open, and if so who
    /// opened it. See [`CommWindowState`] for what the answer is good for.
    pub fn comm_window_state(&self) -> CommWindowState {
        self.with_state(|state| state.pase.comm_window_state())
    }

    /// Open a basic commissioning window
    ///
    /// The method will return an error if the commissioning window cannot be opened
    /// (due to another window already being opened, for example).
    ///
    /// # Arguments
    /// - `timeout_secs`: The timeout in seconds for the basic commissioning window
    ///
    /// **Note:** This is the low-level building block that mutates PASE
    /// state and routes a `notify_cluster_changed(...)` to subscribers
    /// via `notify`, but does **not** bump the per-cluster `Dataver` of
    /// `AdministratorCommissioning` — a subsequent dataver-filtered
    /// read could therefore cache-hit and miss the change. Application
    /// code that holds a `InteractionModel` should prefer
    /// [`crate::im::InteractionModel::open_basic_comm_window`], which delegates
    /// here and additionally bumps dataver via its
    /// [`AttrChangeNotifier`] impl.
    pub fn open_basic_comm_window<C: Crypto>(
        &self,
        timeout_secs: u16,
        crypto: C,
        notify: &dyn AttrChangeNotifier,
    ) -> Result<(), Error> {
        let notify_mdns = || self.transport().notify_comm_window_changed();
        let notify_change = |endpt_id, clust_id| notify.notify_cluster_changed(endpt_id, clust_id);

        self.with_state(|state| {
            let mut rand = crypto.rand()?;

            let mdns_id = rand.next_u64();

            let mut salt = SPAKE2P_VERIFIER_SALT_ZEROED;
            rand.fill_bytes(salt.access_mut());

            state.pase.open_basic_comm_window(
                mdns_id,
                salt.access(),
                self.dev_comm.password.reference(),
                self.dev_comm.discriminator,
                timeout_secs,
                None,
                notify_mdns,
                notify_change,
            )
        })
    }

    /// Close the commissioning window (basic or other)
    ///
    /// The method will return Ok(false) if there is no active PASE commissioning window to close.
    ///
    /// **Note:** As with [`Matter::open_basic_comm_window`], this does
    /// not bump the per-cluster `Dataver` of
    /// `AdministratorCommissioning`. Prefer
    /// [`crate::im::InteractionModel::close_comm_window`] when a `InteractionModel`
    /// is available.
    pub fn close_comm_window(&self, notify: &dyn AttrChangeNotifier) -> Result<bool, Error> {
        let notify_mdns = || self.transport().notify_comm_window_changed();
        let notify_change = |endpt_id, clust_id| notify.notify_cluster_changed(endpt_id, clust_id);

        self.with_state(|state| state.pase.close_comm_window(notify_mdns, notify_change))
    }

    /// Bump `BasicInformation::ConfigurationVersion` by one, persist
    /// the new value via `kv`, and route an attribute-change
    /// notification to subscribers via `notify`.
    ///
    /// Per Matter Core Spec, the device MUST bump
    /// this attribute on any change to its exposed fixed-quality
    /// surface (a firmware update that adds or removes functionality,
    /// internal reconfiguration that changes any `F`-quality attribute,
    /// bridged-node add/remove on a bridge). `rs-matter` cannot detect
    /// such events on its own — the application drives the bump.
    ///
    /// **Note:** Like the other low-level mutators on `Matter`, this
    /// does **not** bump the per-cluster `Dataver` of
    /// `BasicInformation`. A subsequent dataver-filtered read could
    /// therefore cache-hit and miss the change. Application code that
    /// holds a `InteractionModel` should prefer
    /// [`crate::im::InteractionModel::bump_configuration_version`], which
    /// delegates here and additionally bumps dataver via its
    /// [`AttrChangeNotifier`] impl.
    ///
    /// Returns the new `ConfigurationVersion` value.
    pub fn bump_configuration_version<S: KvBlobStoreAccess>(
        &self,
        kv: S,
        notify: &dyn AttrChangeNotifier,
    ) -> Result<u32, Error> {
        let mut persist = Persist::new(kv);

        let new_version = self.with_state(|state| {
            let new_version = state.basic_info_settings.bump_configuration_version();

            state.basic_info_settings.store_persist(&mut persist)?;

            notify.notify_attr_changed(
                ROOT_ENDPOINT_ID,
                BASIC_INFO_CLUSTER_ID,
                CONFIGURATION_VERSION_ATTR_ID,
            );

            Ok::<_, Error>(new_version)
        })?;

        persist.run()?;

        Ok(new_version)
    }

    /// Create a new transport runner instance
    pub fn transport_runner<C: Crypto>(&self, crypto: C) -> TransportRunner<'_, C> {
        TransportRunner::new(self, crypto)
    }

    /// Run the Matter transport layer.
    ///
    /// # Arguments
    /// - `crypto`: The crypto backend
    /// - `send`: The network send interface
    /// - `recv`: The network receive interface
    /// - `multicast`: The multicast network interface (for receiving groupcast messages)
    ///   When running on top of non-IP networks like BLE pass a no-op implementation like `NoNetwork` here and the multicast functionality will be disabled.
    pub async fn run<C, S, R, M>(
        &self,
        crypto: C,
        send: S,
        recv: R,
        multicast: M,
    ) -> Result<(), Error>
    where
        C: Crypto,
        S: NetworkSend,
        R: NetworkReceive,
        M: NetworkMulticast,
    {
        let mut transport_runner = self.transport_runner(crypto);

        transport_runner.run(send, recv, multicast).await
    }

    /// Access the Matter state by invoking a closure with mutable references to the state.
    pub fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut MatterState) -> R,
    {
        self.transport.with_sessions(|sessions| {
            let (sessions, state) = self.state.access(sessions);

            f(&mut MatterState {
                fabrics: &mut state.fabrics,
                sessions,
                #[cfg(feature = "case-resumption")]
                resumption: &mut state.resumption,
                pase: &mut state.pase,
                failsafe: &mut state.failsafe,
                basic_info_settings: &mut state.basic_info_settings,
                rtc: &mut state.rtc,
                icd_adv: &mut state.icd_adv,
                reboot_count: &mut state.reboot_count,
                operational_hours: &mut state.operational_hours,
                boot_reason: &mut state.boot_reason,
            })
        })
    }

    /// Return the Groupcast testing-mode bridge.
    #[cfg(feature = "groups")]
    pub fn groupcast_testing(&self) -> &crate::groupcast::TestingBridge {
        &self.groupcast_testing
    }

    /// Access the Real-Time-clock by invoking a closure with a mutable reference to it.
    #[deprecated(
        note = "Access the RTC through with_state instead. This method will be removed in a future release."
    )]
    pub fn with_rtc<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Rtc) -> R,
    {
        self.with_state(|state| f(state.rtc))
    }

    /// Reset the transport layer by clearing all sessions, exchanges, the RX buffer and the TX buffer
    /// NOTE: User should be careful _not_ to call this method while the transport layer and/or the built-in mDNS is running.
    pub fn reset_transport(&self) -> Result<(), Error> {
        self.with_state(|state| {
            state.sessions.reset();

            self.transport().reset()
        })
    }

    /// Suspend the commissioning in flight on this node: hand its outcome to
    /// `f` as a [`CommissioningHandover`] and roll this node back.
    ///
    /// Requires an armed fail-safe with a processed `AddNOC`. The envelope
    /// borrows the node state and lives only for the duration of `f`, which
    /// runs with the state locked and so must not call back into `Matter`.
    /// Serializing and transporting the envelope is up to `f`.
    ///
    /// If `f` succeeds, the node is rolled back as on fail-safe expiry: the
    /// pending fabric and `networks` are restored from `kv` (the latter from
    /// under `networks_key`), PASE sessions are dropped, the fail-safe is
    /// disarmed. If `f` fails, nothing changes.
    ///
    /// Returns what `f` returned.
    pub fn suspend_commissioning<N, K, F, R>(
        &self,
        mut networks: N,
        networks_key: u16,
        kv: K,
        f: F,
    ) -> Result<R, Error>
    where
        N: Networks,
        K: KvBlobStoreAccess,
        F: FnOnce(&CommissioningHandover<'_>) -> Result<R, Error>,
    {
        let notify_mdns = || self.transport().notify_comm_window_changed();

        self.with_state(|state| {
            let (fab_idx, remaining_secs) = state
                .failsafe
                .pending_add_noc()
                .ok_or(ErrorCode::FailSafeRequired)?;

            let fabric = state.fabrics.fabric(fab_idx)?;

            let regulatory = state
                .basic_info_settings
                .location
                .as_ref()
                .zip(state.basic_info_settings.location_type)
                .map(|(country_code, location_type)| HandoverRegulatory {
                    country_code: country_code.as_str(),
                    location_type,
                });

            let result = CommissioningHandover::with_pending(
                fabric,
                &mut networks,
                regulatory,
                remaining_secs,
                state.failsafe.breadcrumb(),
                f,
            )?;

            info!("Commissioning of fabric {} suspended", fab_idx);

            // The identity now lives in the envelope: stand down
            state.failsafe.expire(
                state.fabrics,
                || {
                    state.sessions.remove_pase(None);
                },
                &kv,
                notify_mdns,
                |_, _| {},
            )?;

            load_networks(&mut networks, networks_key, &kv)?;

            Ok(result)
        })
    }

    /// Resume a commissioning whose phase 1 ran elsewhere, from its
    /// [`CommissioningHandover`] envelope.
    ///
    /// Leaves the node as `AddNOC` over PASE would: the fabric is operational
    /// and advertised, the staged networks are handed to the connectivity
    /// manager, and the fail-safe is armed for the fabric for the exporter's
    /// remaining time, floored to [`DEFAULT_FAILSAFE_EXPIRY_SECS`].
    /// `CommissioningComplete` over CASE then commits; expiry rolls back to
    /// `kv`. Only the regulatory config is persisted right away.
    ///
    /// `networks` must be the store of the Network Commissioning handler
    /// persisting under `networks_key` (typically a `&mut` to it), so that the
    /// handler commits or rolls back the staged networks.
    ///
    /// Call at startup, before serving traffic: no attribute-change
    /// notifications are emitted. Fails with `Busy` if the fail-safe is armed
    /// and `InvalidData` if the envelope does not validate, leaving the node
    /// untouched.
    ///
    /// Returns the local index of the resumed fabric.
    pub fn resume_commissioning<C, N, K>(
        &self,
        crypto: C,
        mut networks: N,
        networks_key: u16,
        kv: K,
        handover: &CommissioningHandover<'_>,
    ) -> Result<NonZeroU8, Error>
    where
        C: Crypto,
        N: Networks,
        K: KvBlobStoreAccess,
    {
        handover.validate()?;

        let icac = handover.icac.map(|icac| icac.0);

        let (fab_idx, regulatory) = self.with_state(|state| {
            if state.failsafe.is_armed() {
                error!("Cannot resume a commissioning while the fail-safe is armed");
                Err(ErrorCode::Busy)?;
            }

            let time = state.rtc.utc_time();

            kv.access(|_, buf| {
                FailSafe::check_new_noc(
                    &crypto,
                    time,
                    state.fabrics,
                    handover.root_ca.0,
                    icac,
                    handover.noc.0,
                    handover.secret_key.reference(),
                    buf,
                )
            })?;

            let fabric = state.fabrics.add_with_acl(
                &crypto,
                handover.secret_key.reference(),
                handover.root_ca.0,
                handover.noc.0,
                icac.unwrap_or(&[]),
                Some(handover.ipk.reference()),
                handover.admin_vendor_id,
                handover.acl.iter()?,
            )?;

            let fab_idx = fabric.fab_idx();

            // From here on, failures are undone like a fail-safe expiry
            state.failsafe.arm_resumed(
                fab_idx,
                handover
                    .fail_safe_remaining_secs
                    .max(DEFAULT_FAILSAFE_EXPIRY_SECS),
                handover.breadcrumb,
            )?;

            let result = (|| {
                if !handover.label.is_empty() {
                    state.fabrics.update_label(fab_idx, handover.label)?;
                }

                handover::stage_networks(handover, &mut networks)?;

                if let Some(regulatory) = &handover.regulatory {
                    state
                        .basic_info_settings
                        .set_location(regulatory.country_code);
                    state.basic_info_settings.location_type = Some(regulatory.location_type);
                }

                Ok::<_, Error>(())
            })();

            if let Err(err) = result {
                let _ = state.failsafe.expire(
                    state.fabrics,
                    || {
                        state.sessions.remove_pase(None);
                    },
                    &kv,
                    || {},
                    |_, _| {},
                );

                let _ = load_networks(&mut networks, networks_key, &kv);

                return Err(err);
            }

            info!(
                "Commissioning resumed as fabric {}; awaiting CommissioningComplete over CASE",
                fab_idx
            );

            Ok((fab_idx, handover.regulatory.is_some()))
        })?;

        self.transport().notify_timeouts_changed();

        if regulatory {
            let mut persist = Persist::new(&kv);

            self.with_state(|state| state.basic_info_settings.store_persist(&mut persist))?;

            persist.run()?;
        }

        self.transport().notify_mdns_changed();

        Ok(fab_idx)
    }

    /// Factory-reset the `Matter` persistable state by removing all fabrics and
    /// resetting the basic info settings, the RTC state, the operational hours
    /// and (if compiled in) the CASE resumption cache and the group data message
    /// counter - both in-memory and in the provided KV store.
    ///
    /// The counterpart of [`Matter::startup`]. Call when the node is
    /// factory-reset, alongside
    /// [`InteractionModel::factory_reset`](crate::im::InteractionModel::factory_reset).
    ///
    /// Everything is removed even if removing some of it fails, the first failure
    /// being returned.
    ///
    /// Arguments:
    /// - `kv`: The key-value store access (obtained via [`Matter::kv`]) to remove the fabrics
    ///   and basic info settings from. Provides both the store and the scratch buffer.
    pub fn factory_reset<K: KvBlobStoreAccess>(&self, kv: K) -> Result<(), Error> {
        let result = self.with_state(|state| {
            // The KV ops are sync, so do them all inside a single `access` closure.
            kv.access(|mut store, buf| {
                let result = state
                    .fabrics
                    .reset_persist(&mut store, buf)
                    .and(state.basic_info_settings.reset_persist(&mut store, buf))
                    .and(state.rtc.reset_persist(&mut store, buf));
                #[cfg(feature = "case-resumption")]
                let result = result.and(state.resumption.reset_persist(&mut store, buf));
                #[cfg(feature = "groups")]
                let result = result.and(state.sessions.reset_persist(&mut store, buf));

                *state.operational_hours = 0;

                result.and(store.remove(OPERATIONAL_HOURS_KEY, buf))
            })
        });

        self.transport().notify_mdns_changed();

        result
    }

    /// Re-hydrate the `Matter` persistable state - the fabrics, the basic info
    /// settings, the RTC state and (if compiled in) the CASE resumption cache
    /// and the group data message counter - from the provided KV store.
    ///
    /// Call once at startup, before the transport starts serving traffic. The
    /// Data-Model counterpart is
    /// [`InteractionModel::startup`](crate::im::InteractionModel::startup).
    ///
    /// Arguments:
    /// - `kv`: The key-value store access (obtained via [`Matter::kv`]) to load the fabrics
    ///   and basic info settings from. Provides both the store and the scratch buffer.
    pub fn startup<K: KvBlobStoreAccess>(&self, kv: K) -> Result<(), Error> {
        self.with_state(|state| {
            kv.access(|store, buf| state.fabrics.load_persist(store, buf))?;
            state.basic_info_settings.load_persist(&kv)?;
            state.rtc.load_persist(&kv)?;
            #[cfg(feature = "case-resumption")]
            state.resumption.load_persist(&kv)?;
            #[cfg(feature = "groups")]
            state.sessions.load_persist(&kv)?;

            let mut persist = Persist::new(&kv);

            // `RebootCount` for *this* boot: the persisted value plus one.
            //
            // Only loaded here - the matching write is
            // [`Matter::persist_reboot_count`], which the device calls once
            // it considers the boot healthy. Writing it here instead would
            // put one flash write in the boot path, so a device stuck in a
            // boot loop would churn its write-endurance budget while
            // already broken.
            //
            // Reaching `startup` *is* a boot, so no platform support is
            // needed to detect one, and the spec asks only for a
            // "best-effort" count - it deliberately does not distinguish a
            // crash from a power cut. A wake from sleep does not re-enter
            // startup, which is the one case the spec excludes.
            *state.reboot_count = persist
                .load_tlv::<u16>(REBOOT_COUNT_KEY)?
                .unwrap_or(0)
                .saturating_add(1);

            // `TotalOperationalHours` on record; the current boot's hours
            // count on top of it.
            *state.operational_hours = persist.load_tlv(OPERATIONAL_HOURS_KEY)?.unwrap_or(0);

            persist.run()
        })?;

        self.transport().notify_mdns_changed();

        Ok(())
    }

    /// Background task that flushes the CASE session resumption cache
    /// to persistent storage whenever it is mutated.
    ///
    /// The task waits for a mutation event fired by the CASE handshake
    /// paths (both full handshake and resumption), sleeps for
    /// `min_interval` so a burst of handshakes coalesces into one
    /// write, and then serialises the current cache to `kv` under
    /// [`crate::persist::CASE_RESUMPTION_KEY`].
    ///
    /// `min_interval` therefore doubles as (a) a burst-coalescing
    /// debounce and (b) a hard lower bound on the time between two
    /// consecutive persists — a mutation‑storm cannot drive more than
    /// one write per `min_interval` regardless of arrival rate. Pick
    /// something appropriate for the underlying medium:
    ///
    /// - POSIX / dev builds: anything from a few hundred ms upwards is
    ///   fine; `Duration::from_millis(500)` matches the pre‑existing
    ///   hard‑coded behaviour.
    /// - MCU firmwares writing to internal flash: prefer tens of
    ///   seconds (e.g. `Duration::from_secs(30)`) so a
    ///   commissioner-driven wave of CASE handshakes doesn't churn the
    ///   flash write endurance budget. The cache is a soft cache — a
    ///   power cut that loses the most recent entry only forces a
    ///   full CASE handshake the next time the peer connects, which
    ///   is the same fallback any resumption failure produces.
    ///
    /// Intended to be spawned alongside [`Matter::run`], for example
    /// via `crate::utils::futures::select` or a dedicated executor task. It
    /// never returns on the happy path — a `Result` is only produced
    /// if the KV backend errors.
    ///
    /// # Arguments
    /// - `kv`: The key-value store access (obtained via [`Matter::kv`])
    ///   used to persist the cache. Provides both the store and the
    ///   scratch buffer.
    /// - `min_interval`: Minimum time between two consecutive persists
    ///   (see above).
    #[cfg(feature = "case-resumption")]
    pub async fn run_persist_resumption<K: KvBlobStoreAccess>(
        &self,
        kv: K,
        min_interval: Duration,
    ) -> Result<(), Error> {
        loop {
            self.transport().wait_resumption_dirty().await;
            Timer::after(min_interval).await;

            self.with_state(|state| state.resumption.store_persist(&kv))?;

            debug!("CASE session resumption cache persisted");
        }
    }

    /// Invoke the given closure for each currently published Matter mDNS service.
    pub fn mdns_services<F>(&self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(MatterLocalService) -> Result<(), Error>,
    {
        self.with_state(|state| {
            if let Some(comm_window) = state.pase.comm_window() {
                f(comm_window.mdns_service())?;
            }

            for fabric in state.fabrics.iter() {
                if let Some(service) = MatterLocalService::for_fabric(fabric) {
                    f(service)?;
                }
            }

            Ok(())
        })
    }
}

impl GroupMembership for Matter<'_> {
    fn is_member(
        &self,
        fab_idx: NonZeroU8,
        group_id: u16,
        endpoint_id: EndptId,
    ) -> Result<bool, Error> {
        #[cfg(feature = "groups")]
        {
            self.with_state(|state| {
                let fabric = state.fabrics.fabric(fab_idx)?;

                Ok(fabric
                    .groups()
                    .get(group_id)
                    .map(|g| g.endpoints.contains(&endpoint_id))
                    .unwrap_or(false))
            })
        }

        // Without multicast group support the group table is empty
        #[cfg(not(feature = "groups"))]
        {
            let _ = (fab_idx, group_id, endpoint_id);
            Ok(false)
        }
    }
}

impl ScHost for Matter<'_> {
    fn with_sc_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut ScState) -> R,
    {
        self.with_state(|state| {
            f(&mut ScState {
                sessions: &mut *state.sessions,
                fabrics: &mut *state.fabrics,
                #[cfg(feature = "case-resumption")]
                resumption: &mut *state.resumption,
                pase: &mut *state.pase,
                failsafe: &mut *state.failsafe,
                rtc: &mut *state.rtc,
            })
        })
    }
}

impl TransportHost for Matter<'_> {
    fn transport(&self) -> &Transport {
        &self.transport
    }

    fn with_fabrics(&self, f: &mut dyn FnMut(&mut Sessions, &Fabrics)) {
        self.transport.with_sessions(|sessions| {
            let (sessions, state) = self.state.access(sessions);

            f(sessions, &state.fabrics)
        })
    }

    fn mdns_services(
        &self,
        f: &mut dyn FnMut(MatterLocalService) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Matter::mdns_services(self, f)
    }

    fn dev_det(&self) -> &BasicInfoConfig<'_> {
        self.dev_det
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn icd_advertisement(&self) -> Option<IcdAdvertisement> {
        Matter::icd_advertisement(self)
    }

    #[cfg(feature = "groups")]
    fn groupcast_testing(&self) -> &crate::groupcast::TestingBridge {
        &self.groupcast_testing
    }
}

// Only the name, so that the types holding a `&Matter` (e.g. the system
// cluster handlers) can derive `Debug`
impl core::fmt::Debug for Matter<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Matter").finish_non_exhaustive()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Matter<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Matter {{ .. }}")
    }
}

/// The state of the Matter Object, as seen by [`Matter::with_state`]: the sessions of the
/// transport and the state of the node, locked together.
///
/// Public for unit tests.
pub struct MatterState<'a> {
    /// All fabrics
    pub fabrics: &'a mut Fabrics,
    /// All sessions
    pub sessions: &'a mut Sessions,
    /// CASE session resumption cache
    ///
    /// Public for unit tests
    #[cfg(feature = "case-resumption")]
    pub resumption: &'a mut ResumableSessions,
    /// The PASE session state
    pub pase: &'a mut Pase,
    /// The Failsafe state
    pub failsafe: &'a mut FailSafe,
    /// The mutable basic information settings
    pub basic_info_settings: &'a mut BasicInfoSettings,
    /// Real Time Clock state and Last-Known-Good UTC Time tracking (Matter Core spec).
    pub rtc: &'a mut Rtc,
    /// What the device advertises as an ICD. The ICD Management handler keeps
    /// this in sync with its operating mode.
    icd_adv: &'a mut Option<IcdAdvertisement>,
    /// The node's reboot counter, bumped and persisted by `Matter::startup`.
    reboot_count: &'a mut u16,
    /// The operational hours on record at `Matter::startup`.
    operational_hours: &'a mut u32,
    /// The reason for the latest boot, as set by the platform.
    boot_reason: &'a mut BootReason,
}

/// A value protected by the lock of the sessions of a transport, rather than by a lock of
/// its own. A second lock and a second borrow flag at each `Matter::with_state` would cost
/// about 2 KB of code.
struct LockedBySessions<T> {
    value: UnsafeCell<T>,
}

// SAFETY: `access` is the only way to the value, and it needs the sessions locked.
unsafe impl<T: Send> Sync for LockedBySessions<T> {}

impl<T> LockedBySessions<T> {
    #[inline(always)]
    const fn new(value: T) -> Self {
        Self {
            value: UnsafeCell::new(value),
        }
    }

    fn init<I: Init<T>>(value: I) -> impl Init<Self> {
        init!(Self {
            value <- UnsafeCell::init(value),
        })
    }

    /// Return the value, given the sessions of the transport of the same `Matter` object.
    ///
    /// The `&mut Sessions` proves that the lock of the sessions is held, and the result
    /// borrows it, so there cannot be another reference to the value at the same time.
    /// The sessions of another transport would not prove this, so this type stays private.
    #[inline(always)]
    fn access<'a>(&'a self, sessions: &'a mut Sessions) -> (&'a mut Sessions, &'a mut T) {
        // SAFETY: see above
        (sessions, unsafe { &mut *self.value.get() })
    }
}

/// The state of the node: the state of the Matter Object without the sessions.
struct NodeState {
    fabrics: Fabrics,
    #[cfg(feature = "case-resumption")]
    resumption: ResumableSessions,
    pase: Pase,
    failsafe: FailSafe,
    basic_info_settings: BasicInfoSettings,
    rtc: Rtc,
    icd_adv: Option<IcdAdvertisement>,
    reboot_count: u16,
    operational_hours: u32,
    boot_reason: BootReason,
}

impl NodeState {
    /// Create a new instance of NodeState
    #[inline(always)]
    const fn new() -> Self {
        Self {
            fabrics: Fabrics::new(),
            #[cfg(feature = "case-resumption")]
            resumption: ResumableSessions::new(),
            pase: Pase::new(),
            failsafe: FailSafe::new(),
            basic_info_settings: BasicInfoSettings::new(),
            rtc: Rtc::new(),
            icd_adv: None,
            reboot_count: 0,
            operational_hours: 0,
            boot_reason: BootReason::Unspecified,
        }
    }

    /// Return an in-place initializer for NodeState
    // NOTE: `init!` (pinned-init) rejects `#[cfg]` on its fields, so the
    // `case-resumption` field forces two full variants of this initializer.
    #[cfg(feature = "case-resumption")]
    fn init() -> impl Init<Self> {
        init!(Self {
            fabrics <- Fabrics::init(),
            resumption <- ResumableSessions::init(),
            pase <- Pase::init(),
            failsafe <- FailSafe::init(),
            basic_info_settings <- BasicInfoSettings::init(),
            rtc <- Rtc::init(),
            icd_adv: None,
            reboot_count: 0,
            operational_hours: 0,
            boot_reason: BootReason::Unspecified,
        })
    }

    /// Return an in-place initializer for NodeState
    #[cfg(not(feature = "case-resumption"))]
    fn init() -> impl Init<Self> {
        init!(Self {
            fabrics <- Fabrics::init(),
            pase <- Pase::init(),
            failsafe <- FailSafe::init(),
            basic_info_settings <- BasicInfoSettings::init(),
            rtc <- Rtc::init(),
            icd_adv: None,
            reboot_count: 0,
            operational_hours: 0,
            boot_reason: BootReason::Unspecified,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test {
    use crate::persist::{KvBlobStoreAccess, OPERATIONAL_HOURS_KEY};
    use crate::persist::{MemKv, MemKvBlobStore};
    use crate::tlv::{TLVTag, ToTLV};
    use crate::utils::storage::WriteBuf;
    use crate::BootReason;
    use crate::Matter;

    pub fn test_matter() -> Matter<'static> {
        Matter::new(
            &rs_matter_node_core::test_device::TEST_DEV_DET,
            rs_matter_node_core::test_device::TEST_DEV_COMM,
            &rs_matter_node_core::test_device::TEST_DEV_ATT,
            0,
        )
    }

    #[test]
    fn with_fabrics_hands_out_the_sessions_and_the_fabrics() {
        use crate::transport::TransportHost;

        let matter = test_matter();

        let mut empty = false;

        TransportHost::with_fabrics(&matter, &mut |sessions, fabrics| {
            assert_eq!(sessions.iter().count(), 0);

            empty = fabrics.iter().next().is_none();
        });

        assert!(empty);
    }

    /// The sessions and the state of the node are under one lock, so a nested access
    /// is caught by the borrow flag of the sessions.
    #[test]
    #[should_panic(expected = "already borrowed")]
    fn nested_state_access_panics() {
        let matter = test_matter();

        matter.with_state(|_| matter.with_state(|_| ()));
    }

    #[test]
    fn operational_hours_and_boot_reason() {
        let store = MemKvBlobStore::default();
        let kv = MemKv::new(store.clone());

        // The hours a previous boot recorded.
        kv.access(|store, buf| {
            let mut wb = WriteBuf::new(buf);
            41_u32.to_tlv(&TLVTag::Anonymous, &mut wb)?;

            let len = wb.get_tail();
            let (data, buf) = buf.split_at_mut(len);

            store.store(OPERATIONAL_HOURS_KEY, data, buf)
        })
        .unwrap();

        let matter = test_matter();
        matter.startup(&kv).unwrap();

        assert_eq!(matter.total_operational_hours(), 41);

        matter.persist_operational_hours(&kv).unwrap();
        assert!(store.contains_key(OPERATIONAL_HOURS_KEY));

        assert_eq!(matter.boot_reason(), BootReason::Unspecified);
        matter.set_boot_reason(BootReason::BrownOutReset);
        assert_eq!(matter.boot_reason(), BootReason::BrownOutReset);

        matter.factory_reset(&kv).unwrap();

        assert_eq!(matter.total_operational_hours(), 0);
        assert!(!store.contains_key(OPERATIONAL_HOURS_KEY));
    }

    /// An in-memory [`KvBlobStore`](crate::persist::KvBlobStore) for the
    /// counter persistence tests below.
    #[cfg(all(feature = "groups", feature = "std"))]
    struct GroupCtrKv(std::collections::HashMap<u16, std::vec::Vec<u8>>);

    #[cfg(all(feature = "groups", feature = "std"))]
    impl crate::persist::KvBlobStore for &mut GroupCtrKv {
        fn load<'a>(
            &mut self,
            key: u16,
            buf: &'a mut [u8],
        ) -> Result<Option<&'a [u8]>, crate::error::Error> {
            Ok(self.0.get(&key).map(|v| {
                buf[..v.len()].copy_from_slice(v);
                &buf[..v.len()]
            }))
        }

        fn store(
            &mut self,
            key: u16,
            data: &[u8],
            _buf: &mut [u8],
        ) -> Result<(), crate::error::Error> {
            self.0.insert(key, data.to_vec());
            Ok(())
        }

        fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), crate::error::Error> {
            self.0.remove(&key);
            Ok(())
        }
    }

    /// The reboot-survival contract of [`Matter::startup`]: it reads
    /// the boundary the previous run stored (same key, same encoding) and
    /// resumes the counter *at* it - past everything that run could have sent.
    ///
    /// Startup itself writes nothing; the first reservation is what extends
    /// the boundary and demands it be stored before its value is sent.
    #[cfg(all(feature = "groups", feature = "std"))]
    #[test]
    fn test_group_data_ctr_resumes_from_storage() {
        use crate::crypto::test_only_crypto;
        use crate::persist::GROUP_DATA_COUNTER_KEY;
        use crate::transport::session::GROUP_DATA_CTR_EPOCH;

        /// The previous run's stored boundary.
        const STORED: u32 = 5000;

        let mut kv = GroupCtrKv(std::collections::HashMap::new());
        kv.0.insert(GROUP_DATA_COUNTER_KEY, STORED.to_le_bytes().to_vec());

        let matter = test_matter();
        matter.startup(matter.kv(&mut kv)).unwrap();

        // Startup itself does not write - a node that never sends a group
        // message leaves the key exactly as the previous run left it.
        let stored = kv.0.get(&GROUP_DATA_COUNTER_KEY).unwrap();
        assert_eq!(
            u32::from_le_bytes(stored.as_slice().try_into().unwrap()),
            STORED
        );

        // The first value handed out is the stored boundary itself - past
        // everything the previous run could have used - and it comes with the
        // next boundary, which `initiate_group` stores before sending.
        let (first, boundary) = matter
            .with_state(|state| {
                state
                    .sessions
                    .reserve_global_group_data_ctr(test_only_crypto())
            })
            .unwrap();

        assert_eq!(first, STORED);
        assert_eq!(boundary, Some(STORED + GROUP_DATA_CTR_EPOCH));
    }

    /// A factory reset drops the stored boundary along with the fabrics and
    /// group keys it covered, and the next use seeds a fresh counter that is
    /// again persisted before anything can be sent.
    #[cfg(all(feature = "groups", feature = "std"))]
    #[test]
    fn test_group_data_ctr_factory_reset() {
        use crate::crypto::test_only_crypto;
        use crate::persist::GROUP_DATA_COUNTER_KEY;
        use crate::transport::session::GROUP_DATA_CTR_EPOCH;

        let mut kv = GroupCtrKv(std::collections::HashMap::new());
        kv.0.insert(GROUP_DATA_COUNTER_KEY, 5000u32.to_le_bytes().to_vec());

        let matter = test_matter();
        matter.startup(matter.kv(&mut kv)).unwrap();

        matter.factory_reset(matter.kv(&mut kv)).unwrap();

        assert!(!kv.0.contains_key(&GROUP_DATA_COUNTER_KEY));

        // The counter is back to "first boot": the next reservation seeds it
        // at random and hands back a boundary that must be stored first.
        let (value, boundary) = matter
            .with_state(|state| {
                state
                    .sessions
                    .reserve_global_group_data_ctr(test_only_crypto())
            })
            .unwrap();

        assert_ne!(value, 0);
        assert_eq!(boundary, Some(value + GROUP_DATA_CTR_EPOCH));
    }
}
