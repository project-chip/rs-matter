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

//! This module contains the implementation of the Thread Network Diagnostics cluster and its handler.

use core::fmt::Debug;

use rs_matter_macros::{FromTLV, ToTLV};

use crate::dm::{ArrayAttributeRead, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::{
    Nullable, NullableBuilder, Octets, OctetsBuilder, TLVBuilderParent, ToTLVArrayBuilder,
    ToTLVBuilder, Utf8StrBuilder,
};
use crate::with;

pub use crate::dm::clusters::decl::thread_network_diagnostics::*;

use super::wifi_diag::WirelessDiag;

/// Thread Neighbor Table as returned by the `ThreadDiag` trait
#[derive(Debug, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NeighborTable {
    pub ext_address: u64,
    pub age: u32,
    pub rloc16: u16,
    pub link_frame_counter: u32,
    pub mle_frame_counter: u32,
    pub lqi: u8,
    pub average_rssi: Option<i8>,
    pub last_rssi: Option<i8>,
    pub frame_error_rate: u8,
    pub message_error_rate: u8,
    pub rx_on_when_idle: bool,
    pub full_thread_device: bool,
    pub full_network_data: bool,
    pub is_child: bool,
}

/// A snapshot of the IEEE 802.15.4 MAC counters — the cluster's `MACCounts`
/// (`MACCNT`) feature set, attributes `TxTotalCount` .. `RxErrOtherCount` —
/// as returned by [`ThreadDiag::mac_counters`].
///
/// The two `*MaxRetryExpiryCount` values are `Option`s because not every
/// Thread backend tracks them; `None` surfaces as an unsupported attribute.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MacCounters {
    pub tx_total_count: u32,
    pub tx_unicast_count: u32,
    pub tx_broadcast_count: u32,
    pub tx_ack_requested_count: u32,
    pub tx_acked_count: u32,
    pub tx_no_ack_requested_count: u32,
    pub tx_data_count: u32,
    pub tx_data_poll_count: u32,
    pub tx_beacon_count: u32,
    pub tx_beacon_request_count: u32,
    pub tx_other_count: u32,
    pub tx_retry_count: u32,
    pub tx_direct_max_retry_expiry_count: Option<u32>,
    pub tx_indirect_max_retry_expiry_count: Option<u32>,
    pub tx_err_cca_count: u32,
    pub tx_err_abort_count: u32,
    pub tx_err_busy_channel_count: u32,
    pub rx_total_count: u32,
    pub rx_unicast_count: u32,
    pub rx_broadcast_count: u32,
    pub rx_data_count: u32,
    pub rx_data_poll_count: u32,
    pub rx_beacon_count: u32,
    pub rx_beacon_request_count: u32,
    pub rx_other_count: u32,
    pub rx_address_filtered_count: u32,
    pub rx_dest_addr_filtered_count: u32,
    pub rx_duplicated_count: u32,
    pub rx_err_no_frame_count: u32,
    pub rx_err_unknown_neighbor_count: u32,
    pub rx_err_invalid_src_addr_count: u32,
    pub rx_err_sec_count: u32,
    pub rx_err_fcs_count: u32,
    pub rx_err_other_count: u32,
}

impl NeighborTable {
    /// Reads the `NeighborTable` into the provided `NeighborTableStructBuilder`.
    fn read_into<P: TLVBuilderParent>(
        &self,
        builder: NeighborTableStructBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .ext_address(self.ext_address)?
            .age(self.age)?
            .rloc_16(self.rloc16)?
            .link_frame_counter(self.link_frame_counter)?
            .mle_frame_counter(self.mle_frame_counter)?
            .lqi(self.lqi)?
            .average_rssi(Nullable::new(self.average_rssi))?
            .last_rssi(Nullable::new(self.last_rssi))?
            .frame_error_rate(self.frame_error_rate)?
            .message_error_rate(self.message_error_rate)?
            .rx_on_when_idle(self.rx_on_when_idle)?
            .full_thread_device(self.full_thread_device)?
            .full_network_data(self.full_network_data)?
            .is_child(self.is_child)?
            .end()
    }
}

/// Thread Route Table as returned by the `ThreadDiag` trait
#[derive(Debug, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteTable {
    pub ext_address: u64,
    pub rloc16: u16,
    pub router_id: u8,
    pub next_hop: u8,
    pub path_cost: u8,
    pub lqi_in: u8,
    pub lqi_out: u8,
    pub age: u8,
    pub allocated: bool,
    pub link_established: bool,
}

impl RouteTable {
    /// Reads the `RouteTable` into the provided `RouteTableStructBuilder`.
    fn read_into<P: TLVBuilderParent>(
        &self,
        builder: RouteTableStructBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .ext_address(self.ext_address)?
            .rloc_16(self.rloc16)?
            .router_id(self.router_id)?
            .next_hop(self.next_hop)?
            .path_cost(self.path_cost)?
            .lqi_in(self.lqi_in)?
            .lqi_out(self.lqi_out)?
            .age(self.age)?
            .allocated(self.allocated)?
            .link_established(self.link_established)?
            .end()
    }
}

/// Thread Routing Role as returned by the `ThreadDiag` trait
#[derive(Debug, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SecurityPolicy {
    pub rotation_time: u16,
    pub flags: u16,
}

/// Thread Operational Dataset Components as returned by the `ThreadDiag` trait
#[derive(Debug, Clone, Eq, PartialEq, Hash, FromTLV, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OperationalDatasetComponents {
    pub active_timestamp_present: bool,
    pub pending_timestamp_present: bool,
    pub master_key_present: bool,
    pub network_name_present: bool,
    pub extended_pan_id_present: bool,
    pub mesh_local_prefix_present: bool,
    pub delay_present: bool,
    pub pan_id_present: bool,
    pub channel_present: bool,
    pub pskc_present: bool,
    pub security_policy_present: bool,
    pub channel_mask_present: bool,
}

impl OperationalDatasetComponents {
    /// Reads the `OperationalDatasetComponents` into the provided `OperationalDatasetComponentsBuilder`.
    fn read_into<P: TLVBuilderParent>(
        &self,
        builder: OperationalDatasetComponentsBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .active_timestamp_present(self.active_timestamp_present)?
            .pending_timestamp_present(self.pending_timestamp_present)?
            .master_key_present(self.master_key_present)?
            .network_name_present(self.network_name_present)?
            .extended_pan_id_present(self.extended_pan_id_present)?
            .mesh_local_prefix_present(self.mesh_local_prefix_present)?
            .delay_present(self.delay_present)?
            .pan_id_present(self.pan_id_present)?
            .channel_present(self.channel_present)?
            .pskc_present(self.pskc_present)?
            .security_policy_present(self.security_policy_present)?
            .channel_mask_present(self.channel_mask_present)?
            .end()
    }
}

/// The minimal set of data required to implement the Thread Network Diagnostics Cluster
///
/// The names of the methods in this trait are matching 1:1 the mandatory attributes of the
/// Thread Network Diagnostics Cluster.
pub trait ThreadDiag: WirelessDiag {
    fn channel(&self) -> Result<Option<u16>, Error> {
        Ok(None)
    }

    fn routing_role(&self) -> Result<Option<RoutingRoleEnum>, Error> {
        Ok(None)
    }

    fn network_name(
        &self,
        f: &mut dyn FnMut(Option<&str>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        f(None)
    }

    fn pan_id(&self) -> Result<Option<u16>, Error> {
        Ok(None)
    }

    fn extended_pan_id(&self) -> Result<Option<u64>, Error> {
        Ok(None)
    }

    #[allow(clippy::type_complexity)]
    fn mesh_local_prefix(
        &self,
        f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        f(None)
    }

    fn neighbor_table(
        &self,
        _f: &mut dyn FnMut(&NeighborTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn route_table(
        &self,
        _f: &mut dyn FnMut(&RouteTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn partition_id(&self) -> Result<Option<u32>, Error> {
        Ok(None)
    }

    fn weighting(&self) -> Result<Option<u16>, Error> {
        Ok(None)
    }

    fn data_version(&self) -> Result<Option<u16>, Error> {
        Ok(None)
    }

    fn stable_data_version(&self) -> Result<Option<u16>, Error> {
        Ok(None)
    }

    fn leader_router_id(&self) -> Result<Option<u8>, Error> {
        Ok(None)
    }

    fn ext_address(&self) -> Result<Option<u64>, Error> {
        Ok(None)
    }

    fn rloc_16(&self) -> Result<Option<u16>, Error> {
        Ok(None)
    }

    fn security_policy(&self) -> Result<Option<SecurityPolicy>, Error> {
        Ok(None)
    }

    #[allow(clippy::type_complexity)]
    fn channel_page0_mask(
        &self,
        f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        f(None)
    }

    #[allow(clippy::type_complexity)]
    fn operational_dataset_components(
        &self,
        f: &mut dyn FnMut(Option<&OperationalDatasetComponents>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        f(None)
    }

    #[allow(clippy::type_complexity)]
    fn active_network_faults_list(
        &self,
        _f: &mut dyn FnMut(NetworkFaultEnum) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Lend a snapshot of the IEEE 802.15.4 MAC counters (the cluster's
    /// `MACCounts` feature set) to the provided closure, or call it with
    /// `None` if the backend does not track them - in which case the
    /// corresponding attributes read as unsupported.
    ///
    /// Lent by reference (as the other composite payloads of this trait)
    /// rather than returned by value: the snapshot is a ~144-byte struct.
    #[allow(clippy::type_complexity)]
    fn mac_counters(
        &self,
        f: &mut dyn FnMut(Option<&MacCounters>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        f(None)
    }
}

impl<T> ThreadDiag for &T
where
    T: ThreadDiag,
{
    fn mac_counters(
        &self,
        f: &mut dyn FnMut(Option<&MacCounters>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).mac_counters(f)
    }

    fn channel(&self) -> Result<Option<u16>, Error> {
        (*self).channel()
    }

    fn routing_role(&self) -> Result<Option<RoutingRoleEnum>, Error> {
        (*self).routing_role()
    }

    fn network_name(
        &self,
        f: &mut dyn FnMut(Option<&str>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).network_name(f)
    }

    fn pan_id(&self) -> Result<Option<u16>, Error> {
        (*self).pan_id()
    }

    fn extended_pan_id(&self) -> Result<Option<u64>, Error> {
        (*self).extended_pan_id()
    }

    fn mesh_local_prefix(
        &self,
        f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).mesh_local_prefix(f)
    }

    fn neighbor_table(
        &self,
        f: &mut dyn FnMut(&NeighborTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).neighbor_table(f)
    }

    fn route_table(
        &self,
        f: &mut dyn FnMut(&RouteTable) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).route_table(f)
    }

    fn partition_id(&self) -> Result<Option<u32>, Error> {
        (*self).partition_id()
    }

    fn weighting(&self) -> Result<Option<u16>, Error> {
        (*self).weighting()
    }

    fn data_version(&self) -> Result<Option<u16>, Error> {
        (*self).data_version()
    }

    fn stable_data_version(&self) -> Result<Option<u16>, Error> {
        (*self).stable_data_version()
    }

    fn leader_router_id(&self) -> Result<Option<u8>, Error> {
        (*self).leader_router_id()
    }

    fn ext_address(&self) -> Result<Option<u64>, Error> {
        (*self).ext_address()
    }

    fn rloc_16(&self) -> Result<Option<u16>, Error> {
        (*self).rloc_16()
    }

    fn security_policy(&self) -> Result<Option<SecurityPolicy>, Error> {
        (*self).security_policy()
    }

    fn channel_page0_mask(
        &self,
        f: &mut dyn FnMut(Option<&[u8]>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).channel_page0_mask(f)
    }

    fn operational_dataset_components(
        &self,
        f: &mut dyn FnMut(Option<&OperationalDatasetComponents>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).operational_dataset_components(f)
    }

    fn active_network_faults_list(
        &self,
        f: &mut dyn FnMut(NetworkFaultEnum) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).active_network_faults_list(f)
    }
}

impl ThreadDiag for () {}

/// A cluster implementing the Matter Thread Diagnostics Cluster.
#[derive(Clone)]
pub struct ThreadDiagHandler<'a> {
    dataver: Dataver,
    diag: &'a dyn ThreadDiag,
}

impl<'a> ThreadDiagHandler<'a> {
    /// Create a new instance.
    pub const fn new(dataver: Dataver, diag: &'a dyn ThreadDiag) -> Self {
        Self { dataver, diag }
    }

    /// Read one MAC counter off the wrapped [`ThreadDiag`]'s (lent) snapshot;
    /// `AttributeNotFound` when the backend does not track the counters (or
    /// this particular one).
    fn counter(&self, pick: impl FnOnce(&MacCounters) -> Option<u32>) -> Result<u32, Error> {
        let mut pick = Some(pick);
        let mut value = None;

        self.diag.mac_counters(&mut |counters| {
            if let (Some(counters), Some(pick)) = (counters, pick.take()) {
                value = pick(counters);
            }

            Ok(())
        })?;

        value.ok_or_else(|| ErrorCode::AttributeNotFound.into())
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for ThreadDiagHandler<'_> {
    const CLUSTER: crate::dm::Cluster<'static> =
        FULL_CLUSTER.with_attrs(with!(required)).with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn channel(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        Ok(Nullable::new(self.diag.channel()?))
    }

    fn routing_role(&self, _ctx: impl ReadContext) -> Result<Nullable<RoutingRoleEnum>, Error> {
        Ok(Nullable::new(self.diag.routing_role()?))
    }

    fn network_name<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, Utf8StrBuilder<P>>,
    ) -> Result<P, Error> {
        let mut builder = Some(builder);
        let mut parent = None;

        self.diag.network_name(&mut |name| {
            if let Some(name) = name {
                parent = Some(unwrap!(builder.take()).non_null()?.set(name)?);
            } else {
                parent = Some(unwrap!(builder.take()).null()?);
            }

            Ok(())
        })?;

        Ok(unwrap!(parent))
    }

    fn pan_id(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        Ok(Nullable::new(self.diag.pan_id()?))
    }

    fn extended_pan_id(&self, _ctx: impl ReadContext) -> Result<Nullable<u64>, Error> {
        Ok(Nullable::new(self.diag.extended_pan_id()?))
    }

    fn mesh_local_prefix<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        let mut builder = Some(builder);
        let mut parent = None;

        self.diag.mesh_local_prefix(&mut |prefix| {
            if let Some(prefix) = prefix {
                parent = Some(
                    unwrap!(builder.take())
                        .non_null()?
                        .set(Octets::new(prefix))?,
                );
            } else {
                parent = Some(unwrap!(builder.take()).null()?);
            }

            Ok(())
        })?;

        Ok(unwrap!(parent))
    }

    fn neighbor_table<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            NeighborTableStructArrayBuilder<P>,
            NeighborTableStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(builder) => {
                let mut builder = Some(builder);

                self.diag.neighbor_table(&mut |item| {
                    builder = Some(item.read_into(unwrap!(builder.take()).push()?)?);

                    Ok(())
                })?;

                unwrap!(builder).end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let mut builder = Some(builder);
                let mut parent = None;
                let mut current = 0;

                self.diag.neighbor_table(&mut |item| {
                    if index == current {
                        parent = Some(item.read_into(unwrap!(builder.take()))?);
                    }

                    current += 1;

                    Ok(())
                })?;

                if let Some(parent) = parent {
                    Ok(parent)
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeRead::ReadNone(builder) => builder.end(),
        }
    }

    fn route_table<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<RouteTableStructArrayBuilder<P>, RouteTableStructBuilder<P>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(builder) => {
                let mut builder = Some(builder);

                self.diag.route_table(&mut |item| {
                    builder = Some(item.read_into(unwrap!(builder.take()).push()?)?);

                    Ok(())
                })?;

                unwrap!(builder).end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let mut builder = Some(builder);
                let mut parent = None;
                let mut current = 0;

                self.diag.route_table(&mut |item| {
                    if index == current {
                        parent = Some(item.read_into(unwrap!(builder.take()))?);
                    }

                    current += 1;

                    Ok(())
                })?;

                if let Some(parent) = parent {
                    Ok(parent)
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeRead::ReadNone(builder) => builder.end(),
        }
    }

    fn partition_id(&self, _ctx: impl ReadContext) -> Result<Nullable<u32>, Error> {
        Ok(Nullable::new(self.diag.partition_id()?))
    }

    fn weighting(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        Ok(Nullable::new(self.diag.weighting()?))
    }

    fn data_version(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        Ok(Nullable::new(self.diag.data_version()?))
    }

    fn stable_data_version(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        Ok(Nullable::new(self.diag.stable_data_version()?))
    }

    fn leader_router_id(&self, _ctx: impl ReadContext) -> Result<Nullable<u8>, Error> {
        Ok(Nullable::new(self.diag.leader_router_id()?))
    }

    fn security_policy<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, SecurityPolicyBuilder<P>>,
    ) -> Result<P, Error> {
        let security_policy = self.diag.security_policy()?;
        if let Some(security_policy) = security_policy {
            builder
                .non_null()?
                .rotation_time(security_policy.rotation_time)?
                .flags(security_policy.flags)?
                .end()
        } else {
            builder.null()
        }
    }

    fn channel_page_0_mask<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        let mut builder = Some(builder);
        let mut parent = None;

        self.diag.channel_page0_mask(&mut |mask| {
            if let Some(mask) = mask {
                parent = Some(unwrap!(builder.take()).non_null()?.set(Octets::new(mask))?);
            } else {
                parent = Some(unwrap!(builder.take()).null()?);
            }

            Ok(())
        })?;

        Ok(unwrap!(parent.take()))
    }

    fn operational_dataset_components<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: NullableBuilder<P, OperationalDatasetComponentsBuilder<P>>,
    ) -> Result<P, Error> {
        let mut builder = Some(builder);
        let mut parent = None;

        self.diag.operational_dataset_components(&mut |dsc| {
            if let Some(dsc) = dsc {
                parent = Some(dsc.read_into(unwrap!(builder.take()).non_null()?)?);
            } else {
                parent = Some(unwrap!(builder.take()).null()?);
            }

            Ok(())
        })?;

        Ok(unwrap!(parent))
    }

    fn active_network_faults_list<P: TLVBuilderParent>(
        &self,
        _ctx: impl ReadContext,
        builder: ArrayAttributeRead<
            ToTLVArrayBuilder<P, NetworkFaultEnum>,
            ToTLVBuilder<P, NetworkFaultEnum>,
        >,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(builder) => {
                let mut builder = Some(builder);

                self.diag.active_network_faults_list(&mut |fault| {
                    builder = Some(unwrap!(builder.take()).push(&fault)?);

                    Ok(())
                })?;

                unwrap!(builder.take()).end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let mut builder = Some(builder);
                let mut parent = None;
                let mut current = 0;

                self.diag.active_network_faults_list(&mut |fault| {
                    if index == current {
                        parent = Some(unwrap!(builder.take()).set(&fault)?);
                    }

                    current += 1;

                    Ok(())
                })?;

                if let Some(parent) = parent {
                    Ok(parent)
                } else {
                    Err(ErrorCode::InvalidAction.into())
                }
            }
            ArrayAttributeRead::ReadNone(builder) => builder.end(),
        }
    }
    fn ext_address(&self, _ctx: impl ReadContext) -> Result<Nullable<u64>, Error> {
        Ok(Nullable::new(self.diag.ext_address()?))
    }

    fn rloc_16(&self, _ctx: impl ReadContext) -> Result<Nullable<u16>, Error> {
        Ok(Nullable::new(self.diag.rloc_16()?))
    }

    // The MAC counter attributes (`MACCounts` feature set), all served off
    // one `ThreadDiag::mac_counters` snapshot.

    fn tx_total_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_total_count))
    }

    fn tx_unicast_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_unicast_count))
    }

    fn tx_broadcast_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_broadcast_count))
    }

    fn tx_ack_requested_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_ack_requested_count))
    }

    fn tx_acked_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_acked_count))
    }

    fn tx_no_ack_requested_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_no_ack_requested_count))
    }

    fn tx_data_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_data_count))
    }

    fn tx_data_poll_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_data_poll_count))
    }

    fn tx_beacon_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_beacon_count))
    }

    fn tx_beacon_request_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_beacon_request_count))
    }

    fn tx_other_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_other_count))
    }

    fn tx_retry_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_retry_count))
    }

    fn tx_err_cca_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_err_cca_count))
    }

    fn tx_err_abort_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_err_abort_count))
    }

    fn tx_err_busy_channel_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.tx_err_busy_channel_count))
    }

    fn rx_total_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_total_count))
    }

    fn rx_unicast_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_unicast_count))
    }

    fn rx_broadcast_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_broadcast_count))
    }

    fn rx_data_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_data_count))
    }

    fn rx_data_poll_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_data_poll_count))
    }

    fn rx_beacon_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_beacon_count))
    }

    fn rx_beacon_request_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_beacon_request_count))
    }

    fn rx_other_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_other_count))
    }

    fn rx_address_filtered_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_address_filtered_count))
    }

    fn rx_dest_addr_filtered_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_dest_addr_filtered_count))
    }

    fn rx_duplicated_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_duplicated_count))
    }

    fn rx_err_no_frame_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_err_no_frame_count))
    }

    fn rx_err_unknown_neighbor_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_err_unknown_neighbor_count))
    }

    fn rx_err_invalid_src_addr_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_err_invalid_src_addr_count))
    }

    fn rx_err_sec_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_err_sec_count))
    }

    fn rx_err_fcs_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_err_fcs_count))
    }

    fn rx_err_other_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| Some(counters.rx_err_other_count))
    }

    fn tx_direct_max_retry_expiry_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| counters.tx_direct_max_retry_expiry_count)
    }

    fn tx_indirect_max_retry_expiry_count(&self, _ctx: impl ReadContext) -> Result<u32, Error> {
        self.counter(|counters| counters.tx_indirect_max_retry_expiry_count)
    }

    fn handle_reset_counts(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        Err(ErrorCode::CommandNotFound.into())
    }
}

impl Debug for ThreadDiagHandler<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreadDiagHandler")
            .field("dataver", &self.dataver)
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for ThreadDiagHandler<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "ThreadDiagHandler {{ dataver: {} }}", self.dataver.get());
    }
}
