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

use crate::acl::Accessor;
use crate::dm::{AsyncHandler, GlobalElements, HandlerContext, Node};
use crate::error::{Error, ErrorCode};
use crate::im::{
    AttrDataTag, AttrPath, AttrResp, AttrRespTag, AttrStatus, CmdDataTag, CmdPath, CmdResp,
    CmdRespTag, CmdStatus, EventData, EventFilter, EventPath, EventResp, IMStatusCode,
};
use crate::tlv::{TLVArray, TLVElement, TLVTag, TLVWrite, TagType, ToTLV};
use crate::transport::exchange::Exchange;

use super::{
    AttrDetails, CmdDetails, InvokeContextInstance, ReadContextInstance, WriteContextInstance,
};

// A type for writing the outcome of an attribute-read or command-invoke operation.
pub trait Reply {
    /// The tag to use if writing the data "manually" by using the `writer` method.
    const TAG: TagType;

    /// Set the TLV value of the reply and complete.
    fn set<T: ToTLV>(self, value: T) -> Result<(), Error>;

    /// Return the tag to use if writing the TLV reply data in smaller chunks by using the `writer` method
    /// (as opposed to just calling `set`).
    /// A convenience method to avoid using the `Self::TAG` directly.
    fn tag(&self) -> &'static TagType {
        &Self::TAG
    }

    /// Remove everything written via the `writer` method since the last call to `reset`.
    fn reset(&mut self);

    /// Return a TLV writer to write the TLV reply data manually.
    fn writer(&mut self) -> impl TLVWrite + Send + '_;

    /// Complete the manual TLV write of the reply.
    fn complete(self) -> Result<(), Error>;
}

/// A trait for encoding the attribute value for an attribute read operation.
pub trait ReadReply {
    /// Return the reply data writer for an attribute, if the given `dataver` is still the latest
    /// cluster dataver.
    fn with_dataver(self, dataver: u32) -> Result<Option<impl Reply>, Error>;
}

/// A trait for encoding the result from a command invoke operation.
pub trait InvokeReply {
    /// Return the reply data writer for a command with the provided Command ID.
    fn with_command(self, cmd: u32) -> Result<impl Reply, Error>;
}

pub struct HandlerInvoker<'a, 'b, C> {
    exchange: &'b mut Exchange<'a>,
    context: C,
}

impl<'a, 'b, C> HandlerInvoker<'a, 'b, C>
where
    C: HandlerContext,
{
    pub const fn new(exchange: &'b mut Exchange<'a>, context: C) -> Self {
        Self { exchange, context }
    }

    pub fn exchange(&mut self) -> &mut Exchange<'a> {
        self.exchange
    }

    pub async fn process_read<T: TLVWrite + Send>(
        &mut self,
        item: &Result<AttrDetails, AttrStatus>,
        mut tw: T,
    ) -> Result<(), Error> {
        let tail = tw.get_tail();

        let result = self.do_process_read(item, &mut tw).await;

        if result.is_err() {
            // If there was an error, rewind to the tail so we don't write any data.
            tw.rewind_to(tail);
        }

        result
    }

    async fn do_process_read<T: TLVWrite + Send>(
        &mut self,
        item: &Result<AttrDetails, AttrStatus>,
        mut tw: T,
    ) -> Result<(), Error> {
        let result = match item {
            Ok(attr) => {
                let pos = tw.get_tail();

                let result = self.read(attr, &mut tw).await;

                match result {
                    Ok(()) => Ok(None),
                    Err(e) if e.code() != ErrorCode::NoSpace => {
                        error!("Error reading attribute: {}", e);

                        tw.rewind_to(pos);

                        Ok(attr.status(e.into()))
                    }
                    Err(e) => Err(e),
                }
            }
            Err(status) => {
                error!("Error processing attribute read: {:?}", status);
                Ok(Some(status.clone()))
            }
        };

        match result {
            Ok(Some(status)) => AttrResp::Status(status).to_tlv(&TagType::Anonymous, tw),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub async fn read<T: TLVWrite + Send>(
        &mut self,
        attr: &AttrDetails,
        tw: T,
    ) -> Result<(), Error> {
        self.context
            .handler()
            .read(
                ReadContextInstance::new(self.exchange, &self.context, attr),
                ReadReplyInstance::new(attr, tw),
            )
            .await
    }

    pub async fn process_write<T: TLVWrite>(
        &mut self,
        item: &Result<(AttrDetails, TLVElement<'_>), AttrStatus>,
        mut tw: T,
    ) -> Result<(), Error> {
        let tail = tw.get_tail();

        let result = self.do_process_write(item, &mut tw).await;

        if result.is_err() {
            // If there was an error, rewind to the tail so we don't write any data.
            tw.rewind_to(tail);
        }

        result
    }

    async fn do_process_write<T: TLVWrite>(
        &mut self,
        item: &Result<(AttrDetails, TLVElement<'_>), AttrStatus>,
        mut tw: T,
    ) -> Result<(), Error> {
        let result = match item {
            Ok((attr, data)) => {
                let pos = tw.get_tail();

                let result = self.write(attr, data).await;

                match result {
                    Ok(()) => {
                        // A write that was accepted by the cluster handler
                        // counts as an attribute change for subscription
                        // reporting purposes. Notify generically here so that
                        // cluster handlers do not each need to call
                        // `notify_attr_changed` from every attribute setter.
                        self.context.notify_attr_changed(
                            attr.endpoint_id,
                            attr.cluster_id,
                            attr.attr_id,
                        );
                        Ok(attr.status(IMStatusCode::Success))
                    }
                    Err(err) if err.code() != ErrorCode::NoSpace => {
                        error!("Error writing attribute: {}", err);

                        tw.rewind_to(pos);

                        Ok(attr.status(err.into()))
                    }
                    Err(err) => Err(err),
                }
            }
            Err(status) => {
                error!("Error processing attribute write: {:?}", status);
                Ok(Some(status.clone()))
            }
        };

        match result {
            Ok(Some(status)) => status.to_tlv(&TagType::Anonymous, tw),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub async fn write(&mut self, attr: &AttrDetails, data: &TLVElement<'_>) -> Result<(), Error> {
        self.context
            .handler()
            .write(WriteContextInstance::new(
                self.exchange,
                &self.context,
                attr,
                data,
            ))
            .await
    }

    pub async fn process_invoke<T: TLVWrite + Send>(
        &mut self,
        item: &Result<(CmdDetails, TLVElement<'_>), CmdStatus>,
        mut tw: T,
    ) -> Result<(), Error> {
        let tail = tw.get_tail();

        let result = self.do_process_invoke(item, &mut tw).await;

        if result.is_err() {
            // If there was an error, rewind to the tail so we don't write any data.
            tw.rewind_to(tail);
        }

        result
    }

    async fn do_process_invoke<T: TLVWrite + Send>(
        &mut self,
        item: &Result<(CmdDetails, TLVElement<'_>), CmdStatus>,
        mut tw: T,
    ) -> Result<(), Error> {
        let result = match item {
            Ok((cmd, data)) => {
                let pos = tw.get_tail();

                let result = self.invoke(cmd, data, &mut tw).await;

                match result {
                    Ok(()) => {
                        if pos == tw.get_tail() {
                            Ok(cmd.status(IMStatusCode::Success))
                        } else {
                            Ok(None)
                        }
                    }
                    Err(err) if err.code() != ErrorCode::NoSpace => {
                        error!("Error invoking command: {}", err);

                        tw.rewind_to(pos);

                        Ok(cmd.status(err.into()))
                    }
                    Err(err) => Err(err),
                }
            }
            Err(status) => {
                error!("Error processing command: {:?}", status);
                Ok(Some(status.clone()))
            }
        };

        match result {
            Ok(Some(status)) => CmdResp::Status(status).to_tlv(&TagType::Anonymous, tw),
            Ok(None) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub async fn invoke<T: TLVWrite + Send>(
        &mut self,
        cmd: &CmdDetails,
        data: &TLVElement<'_>,
        tw: T,
    ) -> Result<(), Error> {
        self.context
            .handler()
            .invoke(
                InvokeContextInstance::new(self.exchange, &self.context, cmd, data),
                InvokeReplyInstance::new(cmd, tw),
            )
            .await
    }
}

pub struct EventReader {
    max_seen_event_number: u64,
    next_max_seen_event_number: u64,
    /// Whether the originating Read/Subscribe request had `fabricFiltered=true`.
    /// When set, fabric-sensitive events (those whose payload carries a
    /// `FabricIndex` context-tag 254) are dropped if their fabric index does
    /// not match the accessor's. See Matter Core spec section 8.5.2.
    fabric_filtered: bool,
}

impl EventReader {
    pub const fn new(
        max_seen_event_number: u64,
        next_max_seen_event_number: u64,
        fabric_filtered: bool,
    ) -> Self {
        Self {
            max_seen_event_number,
            next_max_seen_event_number,
            fabric_filtered,
        }
    }

    pub fn process_read<T: TLVWrite>(
        &mut self,
        event: EventData<'_>,
        paths: &TLVArray<'_, EventPath>,
        event_filters: &Option<TLVArray<'_, EventFilter>>,
        node: &Node<'_>,
        accessor: &Accessor<'_>,
        mut tw: T,
    ) -> Result<bool, Error> {
        let event_number = event.event_number;
        if !(event_number > self.max_seen_event_number
            && event_number <= self.next_max_seen_event_number)
        {
            // This event is outside the range of interest, skip
            return Ok(false);
        }

        let tail = tw.get_tail();

        let result = self.do_process_read(event, paths, event_filters, node, accessor, &mut tw);

        if result.is_err() {
            // If there was an error, rewind to the tail so we don't write any data
            // and leave `max_seen_event_number` untouched so this event will be
            // retried on the next chunk.
            tw.rewind_to(tail);
        } else {
            // The event was considered (whether or not it actually matched the
            // path/filter/access checks). Advance the local watermark so that
            // chunked reads do not re-consider the same event again on
            // continuation, and so that the iteration converges.
            self.max_seen_event_number = event_number;
        }

        result
    }

    fn do_process_read<T: TLVWrite>(
        &mut self,
        event: EventData<'_>,
        paths: &TLVArray<'_, EventPath>,
        event_filters: &Option<TLVArray<'_, EventFilter>>,
        node: &Node<'_>,
        accessor: &Accessor<'_>,
        mut tw: T,
    ) -> Result<bool, Error> {
        if self.fabric_filtered && !Self::matches_fabric(&event, accessor) {
            return Ok(false);
        }

        if Self::matches_paths(&event, paths, node, accessor)?
            && Self::matches_filters(&event, event_filters)?
            && Self::matches_access(&event, node, accessor)?
        {
            EventResp::Data(event).to_tlv(&TagType::Anonymous, &mut tw)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Per Matter Core spec section 8.5.2 (Fabric-Sensitive Reporting):
    /// When `fabricFiltered=true`, fabric-sensitive events (those whose payload
    /// carries a `FabricIndex` field at context tag 254) SHALL only be reported
    /// to the requesting fabric.
    ///
    /// Events without a `FabricIndex` field are not fabric-sensitive and pass
    /// through unfiltered. Events with a `FabricIndex` field that matches the
    /// accessor's fabric are reported as well.
    fn matches_fabric(event: &EventData<'_>, accessor: &Accessor<'_>) -> bool {
        // Inspect the event payload struct for context tag 254 (FabricIndex).
        let Ok(payload) = event.data.structure() else {
            // Not a struct payload — treat as non-fabric-sensitive.
            return true;
        };

        let Ok(elem) = payload.find_ctx(GlobalElements::FabricIndex as u8) else {
            // No `FabricIndex` field — non-fabric-sensitive, allow.
            return true;
        };

        match elem.non_empty().and_then(|e| e.u8().ok()) {
            Some(fab_idx) => fab_idx == accessor.fab_idx,
            // Field present but unreadable / null — be conservative and allow.
            None => true,
        }
    }

    fn matches_paths(
        event: &EventData<'_>,
        paths: &TLVArray<'_, EventPath>,
        node: &Node<'_>,
        accessor: &Accessor<'_>,
    ) -> Result<bool, Error> {
        for path in paths {
            let path = path?;

            if Self::matches_path(event, path, node, accessor) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn matches_path(
        event: &EventData<'_>,
        path: EventPath,
        node: &Node<'_>,
        accessor: &Accessor<'_>,
    ) -> bool {
        if node.validate_event_path(&path, accessor).is_err() {
            return false;
        }

        let epath = &event.path;

        epath
            .node
            .is_none_or(|node| path.node.is_none_or(|expected_node| expected_node == node))
            && epath.endpoint.is_none_or(|endpoint| {
                path.endpoint
                    .is_none_or(|expected_endpoint| expected_endpoint == endpoint)
            })
            && epath.cluster.is_none_or(|cluster| {
                path.cluster
                    .is_none_or(|expected_cluster| expected_cluster == cluster)
            })
            && epath.event.is_none_or(|event| {
                path.event
                    .is_none_or(|expected_event| expected_event == event)
            })
    }

    fn matches_filters(
        event: &EventData<'_>,
        event_filters: &Option<TLVArray<'_, EventFilter>>,
    ) -> Result<bool, Error> {
        if let Some(filters) = &event_filters {
            // Check if the event passes the filters. If it doesn't pass any of them, skip it.
            // We assume the 99% case is that there is a single filter, on event-no, so just brute force filtering
            for filter in filters {
                if let Some(event_min) = filter?.event_min {
                    if event.event_number < event_min {
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }

    fn matches_access(
        event: &EventData<'_>,
        node: &Node<'_>,
        accessor: &Accessor<'_>,
    ) -> Result<bool, Error> {
        Ok(node.validate_event_path(&event.path, accessor).is_ok())
    }
}

/// A concrete implementation of the `ReadReply` trait for encoding attribute data.
pub struct ReadReplyInstance<T> {
    dataver_filter: Option<u32>,
    path: AttrPath,
    tw: T,
}

impl<T> ReadReplyInstance<T>
where
    T: TLVWrite,
{
    pub fn new(attr: &AttrDetails, tw: T) -> Self {
        Self {
            dataver_filter: attr.dataver,
            path: attr.reply_path(),
            tw,
        }
    }
}

impl<T> ReadReply for ReadReplyInstance<T>
where
    T: TLVWrite + Send,
{
    fn with_dataver(self, dataver: u32) -> Result<Option<impl Reply>, Error> {
        if self
            .dataver_filter
            .map(|dataver_filter| dataver_filter != dataver)
            .unwrap_or(true)
        {
            let mut writer = AttrReadReplyInstance::new(self.tw);
            let mut tw = writer.writer();

            tw.start_struct(&TLVTag::Anonymous)?;
            tw.start_struct(&TLVTag::Context(AttrRespTag::Data as _))?;
            tw.u32(&TLVTag::Context(AttrDataTag::DataVer as _), dataver)?;
            self.path
                .to_tlv(&TagType::Context(AttrDataTag::Path as _), tw)?;

            Ok(Some(writer))
        } else {
            Ok(None)
        }
    }
}

/// A concrete implementation of the `Reply` trait for writing a reply to an attribute read operation.
pub(crate) struct AttrReadReplyInstance<T>
where
    T: TLVWrite,
{
    anchor: T::Position,
    tw: T,
}

impl<T> AttrReadReplyInstance<T>
where
    T: TLVWrite,
{
    pub(crate) const TAG: TLVTag = TLVTag::Context(AttrDataTag::Data as _);

    fn new(tw: T) -> Self {
        Self {
            anchor: tw.get_tail(),
            tw,
        }
    }
}

impl<T> Reply for AttrReadReplyInstance<T>
where
    T: TLVWrite + Send,
{
    const TAG: TagType = Self::TAG;

    fn set<P: ToTLV>(mut self, value: P) -> Result<(), Error> {
        value.to_tlv(&Self::TAG, &mut self.tw)?;
        self.complete()
    }

    fn complete(mut self) -> Result<(), Error> {
        self.tw.end_container()?;
        self.tw.end_container()?;

        Ok(())
    }

    fn writer(&mut self) -> impl TLVWrite + Send + '_ {
        &mut self.tw
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}

/// A concrete implementation of the `InvokeReply` trait for encoding command data.
pub struct InvokeReplyInstance<T> {
    path: CmdPath,
    command_ref: Option<u16>,
    tw: T,
}

impl<T> InvokeReplyInstance<T>
where
    T: TLVWrite,
{
    pub const fn new(cmd: &CmdDetails, tw: T) -> Self {
        Self {
            path: cmd.reply_path(),
            command_ref: cmd.command_ref,
            tw,
        }
    }
}

impl<T> InvokeReply for InvokeReplyInstance<T>
where
    T: TLVWrite + Send,
{
    fn with_command(mut self, cmd: u32) -> Result<impl Reply, Error> {
        let mut writer = CmdInvokeReplyInstance::new(self.tw, self.command_ref);
        let mut tw = writer.writer();

        tw.start_struct(&TLVTag::Anonymous)?;
        tw.start_struct(&TLVTag::Context(CmdRespTag::Cmd as _))?;

        self.path.cmd = Some(cmd as _);
        self.path
            .to_tlv(&TagType::Context(CmdDataTag::Path as _), tw)?;

        Ok(writer)
    }
}

/// A concrete implementation of the `Reply` trait for writing the reply of a command invocation.
struct CmdInvokeReplyInstance<T>
where
    T: TLVWrite,
{
    anchor: T::Position,
    command_ref: Option<u16>,
    tw: T,
}

impl<T> CmdInvokeReplyInstance<T>
where
    T: TLVWrite,
{
    const TAG: TagType = TagType::Context(CmdDataTag::Data as _);

    fn new(tw: T, command_ref: Option<u16>) -> Self {
        Self {
            anchor: tw.get_tail(),
            command_ref,
            tw,
        }
    }
}

impl<T> Reply for CmdInvokeReplyInstance<T>
where
    T: TLVWrite + Send,
{
    const TAG: TagType = Self::TAG;

    fn set<P: ToTLV>(mut self, value: P) -> Result<(), Error> {
        value.to_tlv(&Self::TAG, &mut self.tw)?;
        self.complete()
    }

    fn complete(mut self) -> Result<(), Error> {
        if let Some(command_ref) = self.command_ref {
            self.tw
                .u16(&TLVTag::Context(CmdDataTag::CommandRef as _), command_ref)?;
        }

        self.tw.end_container()?;
        self.tw.end_container()?;

        Ok(())
    }

    fn writer(&mut self) -> impl TLVWrite + Send + '_ {
        &mut self.tw
    }

    fn reset(&mut self) {
        self.tw.rewind_to(self.anchor);
    }
}
