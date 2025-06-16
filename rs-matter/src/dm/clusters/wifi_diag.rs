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

//! This module contains the implementation of the Wifi Network Diagnostics cluster and its handler.

use crate::dm::objects::{Cluster, Dataver, InvokeContext, ReadContext};
use crate::error::{Error, ErrorCode};
use crate::tlv::{Nullable, NullableBuilder, Octets, OctetsBuilder, TLVBuilderParent};
use crate::with;

pub use crate::dm::clusters::decl::wi_fi_network_diagnostics::*;

/// A trait required by `WifiDiag` and `ThreadDiag` that provides information whether the
/// devicde is connected to a wireless network
pub trait WirelessDiag {
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
}

impl WifiDiag for () {}

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
    const CLUSTER: Cluster<'static> = FULL_CLUSTER
        .with_revision(1)
        .with_attrs(with!(required))
        .with_cmds(with!());

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn bssid<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
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

    fn security_type(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<SecurityTypeEnum>, Error> {
        self.diag.security_type()
    }

    fn wi_fi_version(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<WiFiVersionEnum>, Error> {
        self.diag.wi_fi_version()
    }

    fn channel_number(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<u16>, Error> {
        self.diag.channel_number()
    }

    fn rssi(&self, _ctx: &ReadContext<'_>) -> Result<Nullable<i8>, Error> {
        self.diag.rssi()
    }

    fn handle_reset_counts(&self, _ctx: &InvokeContext<'_>) -> Result<(), Error> {
        Err(ErrorCode::InvalidAction.into())
    }
}
