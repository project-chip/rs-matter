/*
 *
 *    Copyright (c) 2025-2026 Project CHIP Authors
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

//! This module contains the implementation of the Ethernet Network Diagnostics cluster and its handler.
//!
//! The optional attributes and features to advertise are picked endpoint-side with [`Options`],
//! e.g. `clusters!(eth, eth_diag(phy_rate, carrier_detect); …)`. Their values come from an
//! [`EthDiag`] implementation.

use bitflags::bitflags;

use crate::dm::{Attribute, Cluster, Command, Dataver, InvokeContext, Quality, ReadContext};
use crate::error::Error;
use crate::tlv::Nullable;
use crate::utils::sync::MaybeSendSync;

pub use crate::dm::clusters::decl::ethernet_network_diagnostics::*;

bitflags! {
    /// The optional attributes and features of the cluster to advertise.
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct Options: u8 {
        /// `PHYRate`
        const PHY_RATE = 0x01;
        /// `FullDuplex`
        const FULL_DUPLEX = 0x02;
        /// `CarrierDetect`
        const CARRIER_DETECT = 0x04;
        /// `TimeSinceReset`
        const TIME_SINCE_RESET = 0x08;
        /// The `PKTCNT` feature: `PacketRxCount`, `PacketTxCount` and the `ResetCounts` command
        const PACKET_COUNTS = 0x10;
        /// The `ERRCNT` feature: `TxErrCount`, `CollisionCount`, `OverrunCount`
        /// and the `ResetCounts` command
        const ERROR_COUNTS = 0x20;
    }
}

/// The data source of the Ethernet Network Diagnostics cluster.
///
/// Only the methods of the attributes advertised via [`Options`] are called.
pub trait EthDiag: MaybeSendSync {
    /// The PHY rate, or `None` if the interface is not configured or operational
    fn phy_rate(&self) -> Result<Option<PHYRateEnum>, Error> {
        Ok(None)
    }

    /// Whether the interface is in full-duplex mode, or `None` if it is not configured or operational
    fn full_duplex(&self) -> Result<Option<bool>, Error> {
        Ok(None)
    }

    /// The Carrier Detect signal, or `None` if the interface is not configured or operational
    fn carrier_detect(&self) -> Result<Option<bool>, Error> {
        Ok(None)
    }

    /// Minutes since the interface was last reset
    fn time_since_reset(&self) -> Result<u64, Error> {
        Ok(0)
    }

    fn packet_rx_count(&self) -> Result<u64, Error> {
        Ok(0)
    }

    fn packet_tx_count(&self) -> Result<u64, Error> {
        Ok(0)
    }

    fn tx_err_count(&self) -> Result<u64, Error> {
        Ok(0)
    }

    fn collision_count(&self) -> Result<u64, Error> {
        Ok(0)
    }

    fn overrun_count(&self) -> Result<u64, Error> {
        Ok(0)
    }

    /// Reset the packet and error counts to 0
    fn reset_counts(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl<T> EthDiag for &T
where
    T: EthDiag,
{
    fn phy_rate(&self) -> Result<Option<PHYRateEnum>, Error> {
        (*self).phy_rate()
    }

    fn full_duplex(&self) -> Result<Option<bool>, Error> {
        (*self).full_duplex()
    }

    fn carrier_detect(&self) -> Result<Option<bool>, Error> {
        (*self).carrier_detect()
    }

    fn time_since_reset(&self) -> Result<u64, Error> {
        (*self).time_since_reset()
    }

    fn packet_rx_count(&self) -> Result<u64, Error> {
        (*self).packet_rx_count()
    }

    fn packet_tx_count(&self) -> Result<u64, Error> {
        (*self).packet_tx_count()
    }

    fn tx_err_count(&self) -> Result<u64, Error> {
        (*self).tx_err_count()
    }

    fn collision_count(&self) -> Result<u64, Error> {
        (*self).collision_count()
    }

    fn overrun_count(&self) -> Result<u64, Error> {
        (*self).overrun_count()
    }

    fn reset_counts(&self) -> Result<(), Error> {
        (*self).reset_counts()
    }
}

impl EthDiag for () {}

/// Compute the `Cluster<'static>` metadata advertising the options encoded in `OPTS`
/// (the [`Options::bits`] value).
pub const fn cluster<const OPTS: u8>() -> Cluster<'static> {
    let opts = Options::from_bits_truncate(OPTS);

    let mut features = 0u32;

    if opts.contains(Options::PACKET_COUNTS) {
        features |= Feature::PACKET_COUNTS.bits();
    }

    if opts.contains(Options::ERROR_COUNTS) {
        features |= Feature::ERROR_COUNTS.bits();
    }

    Cluster {
        feature_map: features,
        with_attrs: eth_diag_attrs::<OPTS>,
        with_cmds: eth_diag_cmds::<OPTS>,
        ..FULL_CLUSTER
    }
}

const fn eth_diag_attrs<const OPTS: u8>(attr: &Attribute, _: u16, _: u32) -> bool {
    use AttributeId as A;

    if !attr.quality.contains(Quality::OPTIONAL) {
        return true;
    }

    let id = attr.id;

    let opt = if id == A::PHYRate as u32 {
        Options::PHY_RATE
    } else if id == A::FullDuplex as u32 {
        Options::FULL_DUPLEX
    } else if id == A::CarrierDetect as u32 {
        Options::CARRIER_DETECT
    } else if id == A::TimeSinceReset as u32 {
        Options::TIME_SINCE_RESET
    } else if id == A::PacketRxCount as u32 || id == A::PacketTxCount as u32 {
        Options::PACKET_COUNTS
    } else if id == A::TxErrCount as u32
        || id == A::CollisionCount as u32
        || id == A::OverrunCount as u32
    {
        Options::ERROR_COUNTS
    } else {
        return false;
    };

    Options::from_bits_truncate(OPTS).contains(opt)
}

const fn eth_diag_cmds<const OPTS: u8>(cmd: &Command, _: u16, _: u32) -> bool {
    cmd.id == CommandId::ResetCounts as u32
        && Options::from_bits_truncate(OPTS)
            .intersects(Options::PACKET_COUNTS.union(Options::ERROR_COUNTS))
}

/// The system implementation of a handler for the Ethernet Network Diagnostics Matter cluster.
///
/// [`Self::CLUSTER`](ClusterHandler::CLUSTER) is the empty-options shape; what is actually
/// advertised and dispatched follows the cluster metadata of the endpoint (see [`cluster`]).
#[derive(Clone)]
pub struct EthDiagHandler<'a> {
    dataver: Dataver,
    diag: &'a dyn EthDiag,
}

impl<'a> EthDiagHandler<'a> {
    /// Create a new instance of `EthDiagHandler` with the given `Dataver` and data source.
    /// Pass `&()` when the data source has nothing to report.
    pub const fn new(dataver: Dataver, diag: &'a dyn EthDiag) -> Self {
        Self { dataver, diag }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for EthDiagHandler<'_> {
    const CLUSTER: Cluster<'static> = cluster::<0>();

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn phy_rate(&self, _ctx: impl ReadContext) -> Result<Nullable<PHYRateEnum>, Error> {
        Ok(Nullable::new(self.diag.phy_rate()?))
    }

    fn full_duplex(&self, _ctx: impl ReadContext) -> Result<Nullable<bool>, Error> {
        Ok(Nullable::new(self.diag.full_duplex()?))
    }

    fn carrier_detect(&self, _ctx: impl ReadContext) -> Result<Nullable<bool>, Error> {
        Ok(Nullable::new(self.diag.carrier_detect()?))
    }

    fn time_since_reset(&self, _ctx: impl ReadContext) -> Result<u64, Error> {
        self.diag.time_since_reset()
    }

    fn packet_rx_count(&self, _ctx: impl ReadContext) -> Result<u64, Error> {
        self.diag.packet_rx_count()
    }

    fn packet_tx_count(&self, _ctx: impl ReadContext) -> Result<u64, Error> {
        self.diag.packet_tx_count()
    }

    fn tx_err_count(&self, _ctx: impl ReadContext) -> Result<u64, Error> {
        self.diag.tx_err_count()
    }

    fn collision_count(&self, _ctx: impl ReadContext) -> Result<u64, Error> {
        self.diag.collision_count()
    }

    fn overrun_count(&self, _ctx: impl ReadContext) -> Result<u64, Error> {
        self.diag.overrun_count()
    }

    fn handle_reset_counts(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        self.diag.reset_counts()
    }
}
