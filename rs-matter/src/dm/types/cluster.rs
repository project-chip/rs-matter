/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

use core::fmt::{self, Debug};

use crate::acl::{AccessReq, Accessor};
use crate::dm::*;
use crate::error::{Error, ErrorCode};
use crate::im::GenericPath;
use crate::im::IMStatusCode;
use crate::tlv::{TLVTag, TLVWrite};

/// A type alias for the attribute matching function
pub type WithAttrs = fn(&Attribute, u16, u32) -> bool;
/// A type alias for the command matching function
pub type WithCmds = fn(&Command, u16, u32) -> bool;
/// A type alias for the event matching function
pub type WithEvents = fn(&Event, u16, u32) -> bool;

/// A struct modeling the cluster meta-data
/// (i.e. what is the cluster ID, revision, features, attributes and their access, commands and their access)
/// in the Matter data model.
#[derive(Debug, Clone)]
pub struct Cluster<'a> {
    /// The ID of the cluster
    pub id: ClusterId,
    /// The revision of the cluster
    pub revision: u16,
    /// The feature map of the cluster
    pub feature_map: u32,
    /// The attributes of the cluster.
    ///
    /// These could be all attributes as specified in the Matter spec,
    /// even if the concrete instantiation of the cluster supports only a subset of these.
    /// See` with_attrs` for more details.
    pub attributes: &'a [Attribute],
    /// The commands of the cluster.
    ///
    /// These could be all commands as specified in the Matter spec,
    /// even if the concrete instantiation of the cluster supports only a subset of these.
    /// See` with_cmds` for more details.
    pub commands: &'a [Command],
    /// The events of the cluster.
    ///
    /// These could be all events as specified in the Matter spec,
    /// even if the concrete instantiation of the cluster supports only a subset of these.
    /// See` with_events` for more details.
    pub events: &'a [Event],
    /// A function that takes an attribute and returns a boolean indicating if the attribute
    /// is supported by the cluster.
    pub with_attrs: WithAttrs,
    /// A function that takes a command and returns a boolean indicating if the command
    /// is supported by the cluster.
    pub with_cmds: WithCmds,
    /// A function that takes an event and returns a boolean indicating if the event
    /// is supported by the cluster.
    pub with_events: WithEvents,
}

impl<'a> Cluster<'a> {
    /// Create a new cluster
    ///
    /// # Arguments
    /// - `id`: The ID of the cluster
    /// - `revision`: The revision of the cluster
    /// - `feature_map`: The feature map of the cluster
    /// - `attributes`: The attributes of the cluster
    /// - `commands`: The commands of the cluster
    /// - `with_attrs`: A function that takes an attribute and returns a boolean indicating if the attribute should be included
    /// - `with_cmds`: A function that takes a command and returns a boolean indicating if the command should be included
    /// - `with_events`: A function that takes an event and returns a boolean indicating if the event should be included
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        id: ClusterId,
        revision: u16,
        feature_map: u32,
        attributes: &'a [Attribute],
        commands: &'a [Command],
        events: &'a [Event],
        with_attrs: WithAttrs,
        with_cmds: WithCmds,
        with_events: WithEvents,
    ) -> Self {
        Self {
            id,
            revision,
            feature_map,
            attributes,
            commands,
            events,
            with_attrs,
            with_cmds,
            with_events,
        }
    }

    /// Return a new cluster with a modified revision
    pub const fn with_revision(self, revision: u16) -> Self {
        Self { revision, ..self }
    }

    /// Return a new cluster with a modified feature map
    pub const fn with_features(self, feature_map: u32) -> Self {
        Self {
            feature_map,
            ..self
        }
    }

    /// Return a new cluster with a modified attributes' matcher
    pub const fn with_attrs(self, with_attrs: WithAttrs) -> Self {
        Self { with_attrs, ..self }
    }

    /// Return a new cluster with a modified commands' matcher
    pub const fn with_cmds(self, with_cmds: WithCmds) -> Self {
        Self { with_cmds, ..self }
    }

    /// Return a new cluster with a modified events' matcher
    pub const fn with_events(self, with_events: WithEvents) -> Self {
        Self {
            with_events,
            ..self
        }
    }

    /// Check if the accessor has the required permissions to access the attribute
    /// designated by the provided path.
    ///
    /// if `write` is true, the operation is a write operation, otherwise it is a read operation.
    /// `device_types` lists the device types declared by the endpoint hosting `path`,
    /// so ACL entries with a `Target` of kind `DeviceType` can be evaluated correctly.
    pub(crate) fn check_attr_access(
        &self,
        accessor: &Accessor,
        timed: bool,
        path: GenericPath,
        device_types: &[DeviceType],
        write: bool,
        attr_id: AttrId,
    ) -> Result<(), IMStatusCode> {
        let mut access_req = AccessReq::new_with_device_types(
            accessor,
            path,
            if write { Access::WRITE } else { Access::READ },
            device_types,
        );

        let target_perms = self
            .attributes
            .iter()
            .find(|attr| attr.id == attr_id)
            .map(|attr| attr.access)
            .unwrap_or(Access::empty());

        if write && !timed && target_perms.contains(Access::TIMED_ONLY) {
            Err(IMStatusCode::NeedsTimedInteraction)?;
        }

        if !target_perms.contains(access_req.operation()) {
            Err(if matches!(access_req.operation(), Access::WRITE) {
                IMStatusCode::UnsupportedWrite
            } else {
                IMStatusCode::UnsupportedRead
            })?;
        }

        access_req.set_target_perms(target_perms);
        if access_req.allow() {
            Ok(())
        } else {
            Err(IMStatusCode::UnsupportedAccess)
        }
    }

    /// Check if the accessor has the required permissions to access the command
    /// designated by the provided path.
    /// `device_types` lists the device types declared by the endpoint hosting `path`.
    pub(crate) fn check_cmd_access(
        &self,
        accessor: &Accessor,
        timed: bool,
        path: GenericPath,
        device_types: &[DeviceType],
        cmd_id: CmdId,
    ) -> Result<(), IMStatusCode> {
        let mut access_req =
            AccessReq::new_with_device_types(accessor, path, Access::WRITE, device_types);

        let target_perms = self
            .commands
            .iter()
            .find(|cmd| cmd.id == cmd_id)
            .map(|cmd| cmd.access)
            .unwrap_or(Access::empty());

        if !timed && target_perms.contains(Access::TIMED_ONLY) {
            Err(IMStatusCode::NeedsTimedInteraction)?;
        }

        // Per Matter Core spec section 8.9.4 (Invoke Interaction): "Else if
        // the command in the path is fabric-scoped and there is no accessing
        // fabric, a CommandStatusIB SHALL be generated with the
        // UNSUPPORTED_ACCESS Status Code." This is the catch for fabric-scoped
        // admin commands invoked over a PASE session that hasn't yet promoted
        // its fabric index via AddNOC.
        if target_perms.contains(Access::FAB_SCOPED) && accessor.fab_idx == 0 {
            Err(IMStatusCode::UnsupportedAccess)?;
        }

        access_req.set_target_perms(target_perms);
        if access_req.allow() {
            Ok(())
        } else {
            Err(IMStatusCode::UnsupportedAccess)
        }
    }

    /// Check if the accessor has the required permissions to access the event
    /// designated by the provided path.
    /// `device_types` lists the device types declared by the endpoint hosting `path`.
    pub(crate) fn check_event_access(
        &self,
        accessor: &Accessor,
        path: GenericPath,
        device_types: &[DeviceType],
        event_id: EventId,
    ) -> Result<(), IMStatusCode> {
        let mut access_req =
            AccessReq::new_with_device_types(accessor, path, Access::READ, device_types);

        let target_perms = self
            .events
            .iter()
            .find(|event| event.id == event_id)
            .map(|event| event.access)
            .unwrap_or(Access::empty());

        access_req.set_target_perms(target_perms);
        if access_req.allow() {
            Ok(())
        } else {
            Err(IMStatusCode::UnsupportedAccess)
        }
    }

    /// Return a reference to the attribute with the given ID, if it exists.
    pub fn attribute(&self, id: AttrId) -> Option<&Attribute> {
        self.attributes().find(|attr| attr.id == id)
    }

    /// Return a reference to the command with the given ID, if it exists.
    pub fn command(&self, id: CmdId) -> Option<&Command> {
        self.commands().find(|cmd| cmd.id == id)
    }

    /// Return a reference to the event with the given ID, if it exists.
    pub fn event(&self, id: EventId) -> Option<&Event> {
        self.events().find(|event| event.id == id)
    }

    /// Return an iterator over the attributes of the cluster which are
    /// configured to be included based on the provided configuration.
    pub(crate) fn attributes(&self) -> impl Iterator<Item = &Attribute> + '_ {
        self.attributes
            .iter()
            .filter(|attr| (self.with_attrs)(attr, self.revision, self.feature_map))
    }

    /// Return an iterator over the commands of the cluster which are
    /// configured to be included based on the provided configuration.
    pub(crate) fn commands(&self) -> impl Iterator<Item = &Command> + '_ {
        self.commands
            .iter()
            .filter(|cmd| (self.with_cmds)(cmd, self.revision, self.feature_map))
    }

    /// Return an iterator over the events of the cluster which are
    /// configured to be included based on the provided configuration.
    pub(crate) fn events(&self) -> impl Iterator<Item = &Event> + '_ {
        self.events
            .iter()
            .filter(|event| (self.with_events)(event, self.revision, self.feature_map))
    }

    /// Performs an IM attribute read for the given attribute ID.
    ///
    /// The provided attribute ID must be a global attribute, or else
    /// an error will be returned.
    pub fn read<W: Reply>(&self, attr: &AttrDetails, mut writer: W) -> Result<(), Error> {
        match attr.attr_id.try_into()? {
            GlobalElements::GeneratedCmdList => {
                self.encode_generated_command_ids(
                    Self::fetch_index(attr),
                    &W::TAG,
                    writer.writer(),
                )?;
                writer.complete()
            }
            GlobalElements::AcceptedCmdList => {
                self.encode_accepted_command_ids(
                    Self::fetch_index(attr),
                    &W::TAG,
                    writer.writer(),
                )?;
                writer.complete()
            }
            GlobalElements::EventList => {
                self.encode_event_ids(Self::fetch_index(attr), &W::TAG, &mut writer.writer())?;
                writer.complete()
            }
            GlobalElements::AttributeList => {
                self.encode_attribute_ids(Self::fetch_index(attr), &W::TAG, &mut writer.writer())?;
                writer.complete()
            }
            GlobalElements::FeatureMap => {
                debug!(
                    "Endpt(0x??)::Cluster(0x{:04x})::Attr::FeatureMap(0xfffc)::Read -> Ok({:08x})",
                    self.id, self.feature_map
                );
                writer.set(self.feature_map)
            }
            GlobalElements::ClusterRevision => {
                debug!(
                    "Endpt(0x??)::Cluster(0x{:04x})::Attr::ClusterRevision(0xfffd)::Read -> Ok({})",
                    self.id, self.revision
                );
                writer.set(self.revision)
            }
            other => {
                error!("Attribute {:?} not supported", other);
                Err(ErrorCode::AttributeNotFound.into())
            }
        }
    }

    fn encode_attribute_ids<W: TLVWrite>(
        &self,
        index: Option<Option<usize>>,
        tag: &TLVTag,
        mut tw: W,
    ) -> Result<(), Error> {
        debug!(
            "Endpt(0x??)::Cluster(0x{:04x})::Attr::AttributeIDs(0xfffb)::Read{{{:?}}} -> Ok([",
            self.id, index
        );

        if let Some(Some(index)) = index {
            let attr = self
                .attributes()
                .nth(index)
                .ok_or(ErrorCode::ConstraintError)?;

            tw.u32(tag, attr.id)?;
            debug!("    Attr: 0x{:02x},", attr.id);
        } else {
            tw.start_array(tag)?;

            if index.is_none() {
                for attr in self.attributes() {
                    tw.u32(&TLVTag::Anonymous, attr.id)?;
                    debug!("    Attr: 0x{:02x},", attr.id);
                }
            }

            tw.end_container()?;
        }

        debug!("])");

        Ok(())
    }

    fn encode_accepted_command_ids<W: TLVWrite>(
        &self,
        index: Option<Option<usize>>,
        tag: &TLVTag,
        mut tw: W,
    ) -> Result<(), Error> {
        debug!(
            "Endpt(0x??)::Cluster(0x{:04x})::Attr::AcceptedCmdIDs(0xfff9)::Read{{{:?}}} -> Ok([",
            self.id, index
        );

        if let Some(Some(index)) = index {
            let cmd = self
                .commands()
                .nth(index)
                .ok_or(ErrorCode::ConstraintError)?;

            tw.u32(tag, cmd.id)?;
            debug!("    Cmd: 0x{:02x}, ", cmd.id);
        } else {
            tw.start_array(tag)?;

            if index.is_none() {
                for cmd in self.commands() {
                    tw.u32(&TLVTag::Anonymous, cmd.id)?;
                    debug!("    Cmd: 0x{:02x}, ", cmd.id);
                }
            }

            tw.end_container()?;
        }

        debug!("])");

        Ok(())
    }

    fn encode_generated_command_ids<W: TLVWrite>(
        &self,
        index: Option<Option<usize>>,
        tag: &TLVTag,
        mut tw: W,
    ) -> Result<(), Error> {
        // Matter C++ SDK unit tests do require the generated command IDs to be in ascending order and not to have repetitions.
        // Therefore, we are generating the array incrementally, using a variation of the selection sort algorithm

        debug!(
            "Endpt(0x??)::Cluster(0x{:04x})::Attr::GeneratedCmdIDs(0xfff8)::Read{{{:?}}} -> Ok(",
            self.id, index
        );

        if !matches!(index, Some(Some(_))) {
            tw.start_array(tag)?;
        }

        let mut count = 0;
        let mut max_inserted_cmd = None;

        while let Some(next_cmd) = self
            .commands()
            .filter_map(|cmd| cmd.resp_id)
            .filter(|cmd| {
                max_inserted_cmd
                    .map(|max_inserted| *cmd > max_inserted)
                    .unwrap_or(true)
            })
            .min()
        {
            if index == Some(Some(count)) {
                tw.u32(tag, next_cmd)?;
                debug!("    Cmd: 0x{:02x}, ", next_cmd);
            } else if index.is_none() {
                tw.u32(&TLVTag::Anonymous, next_cmd)?;
                debug!("    Cmd: 0x{:02x}, ", next_cmd);
            }

            max_inserted_cmd = Some(next_cmd);
            count += 1;
        }

        if let Some(Some(index)) = index {
            if index >= count {
                Err(ErrorCode::ConstraintError)?;
            }
        }

        if !matches!(index, Some(Some(_))) {
            tw.end_container()?;
        }

        debug!("])");

        Ok(())
    }

    fn encode_event_ids<W: TLVWrite>(
        &self,
        index: Option<Option<usize>>,
        tag: &TLVTag,
        mut tw: W,
    ) -> Result<(), Error> {
        debug!(
            "Endpt(0x??)::Cluster(0x{:04x})::Attr::EventIDs(0xfffa)::Read{{{:?}}} -> Ok([",
            self.id, index
        );

        if let Some(Some(index)) = index {
            let event = self.events().nth(index).ok_or(ErrorCode::ConstraintError)?;

            tw.u32(tag, event.id)?;
            debug!("    Event: 0x{:02x}, ", event.id);
        } else {
            tw.start_array(tag)?;

            if index.is_none() {
                for event in self.events() {
                    tw.u32(&TLVTag::Anonymous, event.id)?;
                    debug!("    Event: 0x{:02x}, ", event.id);
                }
            }

            tw.end_container()?;
        }

        debug!("])");

        Ok(())
    }

    fn fetch_index(attr: &AttrDetails) -> Option<Option<usize>> {
        attr.list_index
            .clone()
            .map(|li| li.into_option().map(|index| index as usize))
    }
}

impl core::fmt::Display for Cluster<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id: {}, ", self.id)?;

        write!(f, "attrs [")?;
        for (index, attr) in self.attributes().enumerate() {
            if index > 0 {
                write!(f, ", {}", attr)?;
            } else {
                write!(f, "{}", attr)?;
            }
        }

        write!(f, "], cmds [")?;
        for (index, cmd) in self.commands().enumerate() {
            if index > 0 {
                write!(f, ", {}", cmd)?;
            } else {
                write!(f, "{}", cmd)?;
            }
        }

        write!(f, "]")
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Cluster<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "id: {}, ", self.id);

        defmt::write!(f, "attrs [");
        for (index, attr) in self.attributes().enumerate() {
            if index > 0 {
                defmt::write!(f, ", ");
            }
            defmt::write!(f, "{}", attr);
        }

        defmt::write!(f, "], cmds [");
        for (index, cmd) in self.commands().enumerate() {
            if index > 0 {
                defmt::write!(f, ", ");
            }
            defmt::write!(f, "{}", cmd);
        }

        defmt::write!(f, "]")
    }
}

/// A macro to generate the clusters' meta-data for an endpoint.
///
/// Net-type tokens (pick exactly one):
/// - `sys;` - all system model clusters except the concrete Network Diagnostics
///   cluster. Usually you want `eth;` / `wifi;` / `thread;` instead.
/// - `eth;` / `wifi;` / `thread;` - same as `sys;` plus the matching Network
///   Diagnostics cluster.
///
/// Optional cluster-shape modifiers — supply zero or more, in the order
/// shown, after the net-type token:
/// - `sw_diag(heap | watermarks | thread, …)` - shape the Software Diagnostics
///   cluster's advertised attribute/command surface. Tokens map to
///   [`crate::dm::clusters::sw_diag::Options`]: `heap` → `HEAP`,
///   `watermarks` → `WATERMARKS` (claims the Matter `WATERMARKS` feature and
///   implies `HEAP`), `thread` → `THREAD` (advertises `ThreadMetrics`; unrelated
///   to the Thread network protocol).
/// - `time_sync(time_zone | ntp_client | ntp_server | time_sync_client, …)` -
///   shape the Time Synchronization cluster. Tokens map 1:1 to
///   [`crate::dm::clusters::time_sync::Options`] and to the matching Matter
///   features (`TIME_ZONE`, `NTP_CLIENT`, `NTP_SERVER`, `TIME_SYNC_CLIENT`).
///
/// Omitting a modifier advertises the corresponding cluster's empty-options
/// shape (required globals + always-on attributes, no features, no commands).
///
/// Trailing positional arguments are additional `Cluster<'static>` literals
/// merged into the slice — e.g. `clusters!(eth, sw_diag(heap); my_cluster)`.
///
/// The Groups cluster is intentionally *not* included in any of these presets:
/// Root Node (Matter Device Library §2.1.5) does not list Groups, and Groups
/// (Matter Application Cluster Specification §1.3) is scoped to per-endpoint
/// group membership which has no defined behavior on the Root Node. Wire
/// `GroupsHandler::CLUSTER` onto the application endpoint(s) where it actually
/// has meaning instead.
#[allow(unused_macros)]
#[macro_export]
macro_rules! clusters {
    (sys
        $(, sw_diag($($sw_opt:ident),* $(,)?))?
        $(, time_sync($($ts_opt:ident),* $(,)?))?
        ; $($cluster:expr $(,)?)*
    ) => {
        $crate::clusters!(
            <$crate::dm::clusters::desc::DescHandler as $crate::dm::clusters::desc::ClusterHandler>::CLUSTER,
            <$crate::dm::clusters::acl::AclHandler as $crate::dm::clusters::acl::ClusterHandler>::CLUSTER,
            <$crate::dm::clusters::basic_info::BasicInfoHandler as $crate::dm::clusters::basic_info::ClusterHandler>::CLUSTER,
            <$crate::dm::clusters::gen_comm::GenCommHandler as $crate::dm::clusters::gen_comm::ClusterHandler>::CLUSTER,
            <$crate::dm::clusters::gen_diag::GenDiagHandler as $crate::dm::clusters::gen_diag::ClusterHandler>::CLUSTER,
            $crate::dm::clusters::sw_diag::cluster(
                $crate::__sw_diag_options!( $($($sw_opt),*)? )
            ),
            $crate::dm::clusters::time_sync::cluster::<{
                $crate::__time_sync_options!( $($($ts_opt),*)? ).bits()
            }>(),
            <$crate::dm::clusters::adm_comm::AdminCommHandler as $crate::dm::clusters::adm_comm::ClusterHandler>::CLUSTER,
            <$crate::dm::clusters::noc::NocHandler as $crate::dm::clusters::noc::ClusterHandler>::CLUSTER,
            <$crate::dm::clusters::grp_key_mgmt::GrpKeyMgmtHandler as $crate::dm::clusters::grp_key_mgmt::ClusterHandler>::CLUSTER,
            $($cluster,)*
        )
    };
    (eth
        $(, sw_diag($($sw_opt:ident),* $(,)?))?
        $(, time_sync($($ts_opt:ident),* $(,)?))?
        ; $($cluster:expr $(,)?)*
    ) => {
        $crate::clusters!(
            sys
            $(, sw_diag($($sw_opt),*))?
            $(, time_sync($($ts_opt),*))?
            ;
            $crate::dm::clusters::net_comm::NetworkType::Ethernet.cluster(),
            <$crate::dm::clusters::eth_diag::EthDiagHandler as $crate::dm::clusters::eth_diag::ClusterHandler>::CLUSTER,
            $($cluster,)*
        )
    };
    (thread
        $(, sw_diag($($sw_opt:ident),* $(,)?))?
        $(, time_sync($($ts_opt:ident),* $(,)?))?
        ; $($cluster:expr $(,)?)*
    ) => {
        $crate::clusters!(
            sys
            $(, sw_diag($($sw_opt),*))?
            $(, time_sync($($ts_opt),*))?
            ;
            $crate::dm::clusters::net_comm::NetworkType::Thread.cluster(),
            <$crate::dm::clusters::thread_diag::ThreadDiagHandler as $crate::dm::clusters::thread_diag::ClusterHandler>::CLUSTER,
            $($cluster,)*
        )
    };
    (wifi
        $(, sw_diag($($sw_opt:ident),* $(,)?))?
        $(, time_sync($($ts_opt:ident),* $(,)?))?
        ; $($cluster:expr $(,)?)*
    ) => {
        $crate::clusters!(
            sys
            $(, sw_diag($($sw_opt),*))?
            $(, time_sync($($ts_opt),*))?
            ;
            $crate::dm::clusters::net_comm::NetworkType::Wifi.cluster(),
            <$crate::dm::clusters::wifi_diag::WifiDiagHandler as $crate::dm::clusters::wifi_diag::ClusterHandler>::CLUSTER,
            $($cluster,)*
        )
    };
    ($($cluster:expr $(,)?)*) => {
        &[
            $($cluster,)*
        ]
    }
}

/// Internal helper: turn a comma-separated list of `sw_diag(...)` lowercase
/// tokens into the corresponding [`crate::dm::clusters::sw_diag::Options`]
/// bitset value. `heap` → `HEAP`, `watermarks` → `WATERMARKS`, `thread`
/// → `THREAD`.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __sw_diag_options {
    () => { $crate::dm::clusters::sw_diag::Options::empty() };
    ($($opt:ident),+ $(,)?) => {
        $crate::dm::clusters::sw_diag::Options::empty()
            $(.union($crate::__sw_diag_option_bit!($opt)))+
    };
}

/// Internal helper: map one lowercase `sw_diag(...)` token to the matching
/// [`crate::dm::clusters::sw_diag::Options`] constant.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __sw_diag_option_bit {
    (heap) => {
        $crate::dm::clusters::sw_diag::Options::HEAP
    };
    (watermarks) => {
        $crate::dm::clusters::sw_diag::Options::WATERMARKS
    };
    (thread) => {
        $crate::dm::clusters::sw_diag::Options::THREAD
    };
}

/// Internal helper: turn a comma-separated list of `time_sync(...)` lowercase
/// tokens into the corresponding [`crate::dm::clusters::time_sync::Options`]
/// bitset value. Tokens map 1:1 to the matching Matter features.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __time_sync_options {
    () => { $crate::dm::clusters::time_sync::Options::empty() };
    ($($opt:ident),+ $(,)?) => {
        $crate::dm::clusters::time_sync::Options::empty()
            $(.union($crate::__time_sync_option_bit!($opt)))+
    };
}

/// Internal helper: map one lowercase `time_sync(...)` token to the matching
/// [`crate::dm::clusters::time_sync::Options`] constant.
#[allow(unused_macros)]
#[doc(hidden)]
#[macro_export]
macro_rules! __time_sync_option_bit {
    (time_zone) => {
        $crate::dm::clusters::time_sync::Options::TIME_ZONE
    };
    (ntp_client) => {
        $crate::dm::clusters::time_sync::Options::NTP_CLIENT
    };
    (ntp_server) => {
        $crate::dm::clusters::time_sync::Options::NTP_SERVER
    };
    (time_sync_client) => {
        $crate::dm::clusters::time_sync::Options::TIME_SYNC_CLIENT
    };
}

/// A macro that generates a "with" fn for matching attributes and commands
///
/// Usage:
/// - `with!()` - returns false for all attributes and commands
/// - `with!(all)` - returns true for all attributes and commands
/// - `with!(attr_or_cmd1, attr_or_cmd2, ...)` - returns true for the specified attributes or commands
/// - `with!(required[; (attr1, attr2, ...)])` - returns true for all mandatory attributes and the specified attributes
/// - `with!(system[; (attr1, attr2, ...)])` - returns true for all system attributes and the specified attributes
#[allow(unused_macros)]
#[macro_export]
macro_rules! with {
    () => {
        |_, _, _| false
    };
    (all) => {
        |_, _, _| true
    };
    (required) => {
        |attr, _, _| !attr.quality.contains($crate::dm::Quality::OPTIONAL)
    };
    (required; $($id:path $(|)?)*) => {
        #[allow(clippy::collapsible_match)]
        |attr, _, _| {
            if !attr.quality.contains($crate::dm::Quality::OPTIONAL) {
                true
            } else if let Ok(l) = attr.id.try_into() {
                #[allow(unreachable_patterns)]
                match l {
                    $($id => true,)*
                    _ => false,
                }
            } else {
                false
            }
        }
    };
    (system) => {
        |attr, _, _| attr.is_system()
    };
    (system; $($id:path $(|)?)*) => {
        #[allow(clippy::collapsible_match)]
        |attr, _, _| {
            if attr.is_system() {
                true
            } else if let Ok(l) = attr.id.try_into() {
                #[allow(unreachable_patterns)]
                match l {
                    $($id => true,)*
                    _ => false,
                }
            } else {
                false
            }
        }
    };
    ($id0:path $(| $id:path $(|)?)*) => {
        #[allow(clippy::collapsible_match)]
        |leaf, _, _| {
            if let Ok(l) = leaf.id.try_into() {
                #[allow(unreachable_patterns)]
                match l {
                    $id0 => true,
                    $($id => true,)*
                    _ => false,
                }
            } else {
                false
            }
        }
    };
}

/// A macro that generates an "except" fn for matching attributes and commands
///
/// Usage:
/// - `except!()` - returns true for all attributes and commands
/// - `except!(all)` - returns false for all attributes and commands
/// - `except!(attr_or_cmd1, attr_or_cmd2, ...)` - returns true for all but the specified attributes or commands
#[allow(unused_macros)]
#[macro_export]
macro_rules! except {
    () => {
        |_, _, _| true
    };
    (all) => {
        |_, _, _| false
    };
    ($id0:path $(| $id:path $(|)?)*) => {
        #[allow(clippy::collapsible_match)]
        |leaf, _, _| {
            if let Ok(l) = leaf.id.try_into() {
                #[allow(unreachable_patterns)]
                match l {
                    $id0 => false,
                    $($id => false,)*
                    _ => true,
                }
            } else {
                false
            }
        }
    };
}
