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

//! This module contains the implementation of the General Diagnostics cluster and its handler.

use core::net::{Ipv4Addr, Ipv6Addr};

use crate::dm::objects::{ArrayAttributeRead, Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::{Nullable, Octets, TLVBuilder, TLVBuilderParent};
use crate::with;

pub use crate::dm::clusters::decl::general_diagnostics::*;

/// A structure describing the network interface info as returned by the `GenDiag` trait.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetifInfo<'a> {
    /// The name of the network interface.
    pub name: &'a str,
    /// Whether the network interface is operational from the POV of Matter.
    /// I.e. the node is advertising itself operationally on this interface.
    pub operational: bool,
    /// Whether any Ipv4 off-premise services used by the node are reachable on this interface.
    /// `None` if the node does not use such services or it is unclear if these are reachable.
    pub offprem_svc_reachable_ipv4: Option<bool>,
    /// Whether any Ipv6 off-premise services used by the node are reachable on this interface.
    /// `None` if the node does not use such services or it is unclear if these are reachable.
    pub offprem_svc_reachable_ipv6: Option<bool>,
    /// 0-padded hardware address of the network interface.
    /// (i.e. either 6 bytes for Eth and Wifi (prefixed with two zero bytes) or 8 bytes for Thread)
    pub hw_addr: &'a [u8; 8],
    /// The IPv4 addresses assigned to the network interface.
    pub ipv4_addrs: &'a [Ipv4Addr],
    /// The IPv6 addresses assigned to the network interface.
    pub ipv6_addrs: &'a [Ipv6Addr],
    /// The type of the network interface.
    pub netif_type: InterfaceTypeEnum,
    /// The index of the network interface.
    /// Might not be available on all platforms.
    pub netif_index: u32,
}

impl NetifInfo<'_> {
    /// Read the network interface info into the given `NetworkInterfaceBuilder`.
    fn read_into<P: TLVBuilderParent>(
        &self,
        builder: NetworkInterfaceBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .name(self.name)?
            .is_operational(self.operational)?
            .off_premise_services_reachable_i_pv_4(Nullable::new(self.offprem_svc_reachable_ipv4))?
            .off_premise_services_reachable_i_pv_6(Nullable::new(self.offprem_svc_reachable_ipv6))?
            .hardware_address(Octets::new(self.hw_addr))?
            .i_pv_4_addresses()?
            .with(|mut builder| {
                for addr in self.ipv4_addrs {
                    builder = builder.push(Octets::new(&addr.octets()))?;
                }

                builder.end()
            })?
            .i_pv_6_addresses()?
            .with(|mut builder| {
                for addr in self.ipv6_addrs {
                    builder = builder.push(Octets::new(&addr.octets()))?;
                }

                builder.end()
            })?
            .r#type(self.netif_type)?
            .end()
    }
}

/// A trait to which the system implementation of the General Diagnostics Matter cluster
/// delegates for information.
pub trait GenDiag {
    /// Get the reboot count of the node.
    fn reboot_count(&self) -> Result<u16, Error>;

    /// Get the uptime of the node in seconds.
    fn uptime_secs(&self) -> Result<u64, Error>;

    /// Whether the test event triggers are enabled.
    /// Check the Matter Core spec for more info.
    fn test_event_triggers_enabled(&self) -> Result<bool, Error>;

    /// Trigger a test event.
    /// Check the Matter Core spec for more info.
    fn test_event_trigger(&self, key: &[u8], trigger: u64) -> Result<(), Error>;
}

impl<T> GenDiag for &T
where
    T: GenDiag,
{
    fn reboot_count(&self) -> Result<u16, Error> {
        (**self).reboot_count()
    }

    fn uptime_secs(&self) -> Result<u64, Error> {
        (**self).uptime_secs()
    }

    fn test_event_triggers_enabled(&self) -> Result<bool, Error> {
        (**self).test_event_triggers_enabled()
    }

    fn test_event_trigger(&self, key: &[u8], trigger: u64) -> Result<(), Error> {
        (**self).test_event_trigger(key, trigger)
    }
}

/// A dummy implementation of the `GenDiag` trait.
impl GenDiag for () {
    fn reboot_count(&self) -> Result<u16, Error> {
        Ok(0)
    }

    fn uptime_secs(&self) -> Result<u64, Error> {
        Ok(u32::MAX as _)
    }

    fn test_event_triggers_enabled(&self) -> Result<bool, Error> {
        Ok(false)
    }

    fn test_event_trigger(&self, _key: &[u8], _trigger: u64) -> Result<(), Error> {
        Err(ErrorCode::ConstraintError.into())
    }
}

pub trait NetifDiag {
    /// Iterate over the network interfaces and call the given function for each of them.
    /// Call the function with `None` at the end.
    fn netifs(&self, f: &mut dyn FnMut(&NetifInfo) -> Result<(), Error>) -> Result<(), Error>;
}

impl<T> NetifDiag for &T
where
    T: NetifDiag,
{
    fn netifs(&self, f: &mut dyn FnMut(&NetifInfo) -> Result<(), Error>) -> Result<(), Error> {
        (*self).netifs(f)
    }
}

/// A dummy implementation of the `NetifDiag` trait.
impl NetifDiag for () {
    fn netifs(&self, _f: &mut dyn FnMut(&NetifInfo) -> Result<(), Error>) -> Result<(), Error> {
        Ok(())
    }
}

/// The system implementation of a handler for the General Diagnostics Matter cluster.
#[derive(Clone)]
pub struct GenDiagHandler<'a> {
    dataver: Dataver,
    diag: &'a dyn GenDiag,
    netif_diag: &'a dyn NetifDiag,
}

impl<'a> GenDiagHandler<'a> {
    /// Create a new instance of `GenDiagHandler` with the given `Dataver`.
    pub const fn new(
        dataver: Dataver,
        diag: &'a dyn GenDiag,
        netif_diag: &'a dyn NetifDiag,
    ) -> Self {
        Self {
            dataver,
            diag,
            netif_diag,
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for GenDiagHandler<'_> {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_attrs(with!(required))
        .with_cmds(with!(CommandId::TestEventTrigger));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn network_interfaces<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<NetworkInterfaceArrayBuilder<P>, NetworkInterfaceBuilder<P>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(builder) => {
                let mut builder = Some(builder);
                self.netif_diag.netifs(&mut |netif| {
                    builder = Some(netif.read_into(unwrap!(builder.take()).push()?)?);

                    Ok(())
                })?;

                builder.take().unwrap().end()
            }
            ArrayAttributeRead::ReadOne(index, builder) => {
                let mut builder = Some(builder);
                let mut parent_builder = None;
                let mut current = 0;

                self.netif_diag.netifs(&mut |netif| {
                    if current == index as usize {
                        parent_builder = Some(netif.read_into(unwrap!(builder.take()))?);
                    }

                    current += 1;

                    Ok(())
                })?;

                parent_builder.take().ok_or_else(|| {
                    ErrorCode::InvalidAction.into() // TODO
                })
            }
        }
    }

    fn reboot_count(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        self.diag.reboot_count()
    }

    fn test_event_triggers_enabled(&self, _ctx: &ReadContext<'_>) -> Result<bool, Error> {
        self.diag.test_event_triggers_enabled()
    }

    fn handle_test_event_trigger(
        &self,
        _ctx: &InvokeContext<'_>,
        request: TestEventTriggerRequest<'_>,
    ) -> Result<(), Error> {
        let key = request.enable_key()?.0;
        let trigger = request.event_trigger()?;

        self.diag.test_event_trigger(key, trigger)
    }

    fn handle_time_snapshot<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _response: TimeSnapshotResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::CommandNotFound.into())
    }
}
