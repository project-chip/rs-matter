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

//! This module contains the implementation of the Wifi Network Diagnostics cluster and its handler.
//!
//! The optional attributes and features to advertise are picked endpoint-side with [`Options`],
//! e.g. `clusters!(wifi, wifi_diag(packet_counts); …)`.

use core::fmt::Debug;

use bitflags::bitflags;

use crate::dm::{Attribute, Cluster, Command, Dataver, InvokeContext, Quality, ReadContext};
use crate::error::Error;
use crate::tlv::{Nullable, NullableBuilder, Octets, OctetsBuilder, TLVBuilderParent};
use crate::utils::sync::DynBase;

pub use crate::dm::clusters::decl::wi_fi_network_diagnostics::*;

/// A trait required by `WifiDiag` and `ThreadDiag` that provides information whether the
/// device is connected to a wireless network
pub trait WirelessDiag: DynBase {
    /// Returns true if the device is connected to a wireless network
    fn connected(&self) -> Result<bool, Error> {
        Ok(false)
    }
}

impl<T> WirelessDiag for &T
where
    T: WirelessDiag,
{
    fn connected(&self) -> Result<bool, Error> {
        (*self).connected()
    }
}

impl WirelessDiag for () {}

/// A [`WirelessDiag`] that always reports the node as connected.
///
/// For links whose liveness is implied by the node answering at all - notably
/// the wired interface behind `EthNetCtl`, which cannot carry the read of an
/// attribute while being down.
pub struct AlwaysConnected;

impl DynBase for AlwaysConnected {}

impl WirelessDiag for AlwaysConnected {
    fn connected(&self) -> Result<bool, Error> {
        Ok(true)
    }
}

/// A trait for the Wifi Diagnostics cluster.
///
/// The names of the methods in this trait are matching 1:1 the mandatory attributes of the
/// Wifi Diagnostics cluster.
pub trait WifiDiag: WirelessDiag {
    #[allow(clippy::type_complexity)]
    fn bssid(&self, f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>) -> Result<(), Error> {
        f(None)
    }

    fn security_type(&self) -> Result<Nullable<SecurityTypeEnum>, Error> {
        Ok(Nullable::none())
    }

    fn wi_fi_version(&self) -> Result<Nullable<WiFiVersionEnum>, Error> {
        Ok(Nullable::none())
    }

    fn channel_number(&self) -> Result<Nullable<u16>, Error> {
        Ok(Nullable::none())
    }

    fn rssi(&self) -> Result<Nullable<i8>, Error> {
        Ok(Nullable::none())
    }

    fn beacon_lost_count(&self) -> Result<Nullable<u32>, Error> {
        Ok(Nullable::none())
    }

    fn beacon_rx_count(&self) -> Result<Nullable<u32>, Error> {
        Ok(Nullable::none())
    }

    fn packet_multicast_rx_count(&self) -> Result<Nullable<u32>, Error> {
        Ok(Nullable::none())
    }

    fn packet_multicast_tx_count(&self) -> Result<Nullable<u32>, Error> {
        Ok(Nullable::none())
    }

    fn packet_unicast_rx_count(&self) -> Result<Nullable<u32>, Error> {
        Ok(Nullable::none())
    }

    fn packet_unicast_tx_count(&self) -> Result<Nullable<u32>, Error> {
        Ok(Nullable::none())
    }

    fn current_max_rate(&self) -> Result<Nullable<u64>, Error> {
        Ok(Nullable::none())
    }

    fn overrun_count(&self) -> Result<Nullable<u64>, Error> {
        Ok(Nullable::none())
    }

    /// Reset the beacon and packet counts to 0
    fn reset_counts(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl<T> WifiDiag for &T
where
    T: WifiDiag,
{
    fn bssid(&self, f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>) -> Result<(), Error> {
        (*self).bssid(f)
    }

    fn security_type(&self) -> Result<Nullable<SecurityTypeEnum>, Error> {
        (*self).security_type()
    }

    fn wi_fi_version(&self) -> Result<Nullable<WiFiVersionEnum>, Error> {
        (*self).wi_fi_version()
    }

    fn channel_number(&self) -> Result<Nullable<u16>, Error> {
        (*self).channel_number()
    }

    fn rssi(&self) -> Result<Nullable<i8>, Error> {
        (*self).rssi()
    }

    fn beacon_lost_count(&self) -> Result<Nullable<u32>, Error> {
        (*self).beacon_lost_count()
    }

    fn beacon_rx_count(&self) -> Result<Nullable<u32>, Error> {
        (*self).beacon_rx_count()
    }

    fn packet_multicast_rx_count(&self) -> Result<Nullable<u32>, Error> {
        (*self).packet_multicast_rx_count()
    }

    fn packet_multicast_tx_count(&self) -> Result<Nullable<u32>, Error> {
        (*self).packet_multicast_tx_count()
    }

    fn packet_unicast_rx_count(&self) -> Result<Nullable<u32>, Error> {
        (*self).packet_unicast_rx_count()
    }

    fn packet_unicast_tx_count(&self) -> Result<Nullable<u32>, Error> {
        (*self).packet_unicast_tx_count()
    }

    fn current_max_rate(&self) -> Result<Nullable<u64>, Error> {
        (*self).current_max_rate()
    }

    fn overrun_count(&self) -> Result<Nullable<u64>, Error> {
        (*self).overrun_count()
    }

    fn reset_counts(&self) -> Result<(), Error> {
        (*self).reset_counts()
    }
}

impl WifiDiag for () {}

bitflags! {
    /// The optional attributes and features of the cluster to advertise.
    #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct Options: u8 {
        /// The `ERRCNT` feature: `BeaconLostCount`, `OverrunCount` and the `ResetCounts` command
        const ERROR_COUNTS = 0x01;
        /// The `PKTCNT` feature: `BeaconRxCount` and the `Packet*Count` attributes
        const PACKET_COUNTS = 0x02;
        /// `CurrentMaxRate`
        const CURRENT_MAX_RATE = 0x04;
    }
}

/// Compute the `Cluster<'static>` metadata advertising the options encoded in `OPTS`
/// (the [`Options::bits`] value).
pub const fn cluster<const OPTS: u8>() -> Cluster<'static> {
    let opts = Options::from_bits_truncate(OPTS);

    let mut features = 0u32;

    if opts.contains(Options::ERROR_COUNTS) {
        features |= Feature::ERROR_COUNTS.bits();
    }

    if opts.contains(Options::PACKET_COUNTS) {
        features |= Feature::PACKET_COUNTS.bits();
    }

    Cluster {
        feature_map: features,
        with_attrs: wifi_diag_attrs::<OPTS>,
        with_cmds: wifi_diag_cmds::<OPTS>,
        ..FULL_CLUSTER
    }
}

const fn wifi_diag_attrs<const OPTS: u8>(attr: &Attribute, _: u16, _: u32) -> bool {
    use AttributeId as A;

    if !attr.quality.contains(Quality::OPTIONAL) {
        return true;
    }

    let id = attr.id;

    let opt = if id == A::BeaconLostCount as u32 || id == A::OverrunCount as u32 {
        Options::ERROR_COUNTS
    } else if id == A::BeaconRxCount as u32
        || id == A::PacketMulticastRxCount as u32
        || id == A::PacketMulticastTxCount as u32
        || id == A::PacketUnicastRxCount as u32
        || id == A::PacketUnicastTxCount as u32
    {
        Options::PACKET_COUNTS
    } else if id == A::CurrentMaxRate as u32 {
        Options::CURRENT_MAX_RATE
    } else {
        return false;
    };

    Options::from_bits_truncate(OPTS).contains(opt)
}

const fn wifi_diag_cmds<const OPTS: u8>(cmd: &Command, _: u16, _: u32) -> bool {
    // `ERRCNT` only - unlike Ethernet's `PKTCNT | ERRCNT` - although it resets the packet counts too
    cmd.id == CommandId::ResetCounts as u32
        && Options::from_bits_truncate(OPTS).contains(Options::ERROR_COUNTS)
}

/// A cluster implementing the Matter Wifi Diagnostics Cluster.
#[derive(Clone)]
pub struct WifiDiagHandler<'a> {
    dataver: Dataver,
    diag: &'a dyn WifiDiag,
}

impl<'a> WifiDiagHandler<'a> {
    /// Create a new instance.
    pub const fn new(dataver: Dataver, diag: &'a dyn WifiDiag) -> Self {
        Self { dataver, diag }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for WifiDiagHandler<'_> {
    const CLUSTER: Cluster<'static> = cluster::<0>();

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn bssid<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        let mut builder = Some(builder);
        let mut parent = None;

        self.diag.bssid(&mut |bssid| {
            let builder = unwrap!(builder.take());

            parent = Some(if let Some(bssid) = bssid {
                builder.non_null()?.set(Octets::new(bssid))?
            } else {
                builder.null()?
            });

            Ok(())
        })?;

        Ok(unwrap!(parent.take()))
    }

    fn security_type(&self, _ctx: impl ReadContext) -> Result<Nullable<SecurityTypeEnum>, Error> {
        self.diag.security_type()
    }

    fn wi_fi_version(&self, _ctx: impl ReadContext) -> Result<Nullable<WiFiVersionEnum>, Error> {
        self.diag.wi_fi_version()
    }

    fn channel_number(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        self.diag.channel_number()
    }

    fn rssi(&self, _ctx: impl ReadContext) -> Result<Nullable<i8>, Error> {
        self.diag.rssi()
    }

    fn beacon_lost_count(&self, _ctx: impl ReadContext) -> Result<Nullable<u32>, Error> {
        self.diag.beacon_lost_count()
    }

    fn beacon_rx_count(&self, _ctx: impl ReadContext) -> Result<Nullable<u32>, Error> {
        self.diag.beacon_rx_count()
    }

    fn packet_multicast_rx_count(&self, _ctx: impl ReadContext) -> Result<Nullable<u32>, Error> {
        self.diag.packet_multicast_rx_count()
    }

    fn packet_multicast_tx_count(&self, _ctx: impl ReadContext) -> Result<Nullable<u32>, Error> {
        self.diag.packet_multicast_tx_count()
    }

    fn packet_unicast_rx_count(&self, _ctx: impl ReadContext) -> Result<Nullable<u32>, Error> {
        self.diag.packet_unicast_rx_count()
    }

    fn packet_unicast_tx_count(&self, _ctx: impl ReadContext) -> Result<Nullable<u32>, Error> {
        self.diag.packet_unicast_tx_count()
    }

    fn current_max_rate(&self, _ctx: impl ReadContext) -> Result<Nullable<u64>, Error> {
        self.diag.current_max_rate()
    }

    fn overrun_count(&self, _ctx: impl ReadContext) -> Result<Nullable<u64>, Error> {
        self.diag.overrun_count()
    }

    fn handle_reset_counts(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        self.diag.reset_counts()
    }
}

impl Debug for WifiDiagHandler<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WifiDiagHandler")
            .field("dataver", &self.dataver)
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for WifiDiagHandler<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "WifiDiagHandler {{ dataver: {} }}", self.dataver.get());
    }
}
