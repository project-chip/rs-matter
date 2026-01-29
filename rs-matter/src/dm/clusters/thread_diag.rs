/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
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
}

impl<T> ThreadDiag for &T
where
    T: ThreadDiag,
{
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
pub struct ThreadDiagHandler<'a> {
    dataver: Dataver,
    diag: &'a dyn ThreadDiag,
}

impl<'a> ThreadDiagHandler<'a> {
    /// Create a new instance.
    pub const fn new(dataver: Dataver, diag: &'a dyn ThreadDiag) -> Self {
        Self { dataver, diag }
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
}

impl ClusterSyncHandler for ThreadDiagHandler<'_> {
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

    fn handle_reset_counts(&self, _ctx: impl InvokeContext) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }
}
