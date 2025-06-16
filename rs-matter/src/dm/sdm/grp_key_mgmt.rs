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

//! This module contains the implementation of the Group Key Management cluster and its handler.
//! Note that the implementation is currently stubbed out, as `rs-matter` does not support Groups yet.

use crate::dm::objects::{
    ArrayAttributeRead, ArrayAttributeWrite, Cluster, Dataver, InvokeContext, ReadContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVBuilderParent;
use crate::with;

pub use crate::dm::clusters::group_key_management::*;

/// The system implementation of a handler for the Group Key Management Matter cluster.
/// This is a stub implementation, as `rs-matter` does not support Groups yet.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GrpKeyMgmtHandler {
    dataver: Dataver,
}

impl GrpKeyMgmtHandler {
    /// Creates a new instance of the `GrpKeyMgmtHandler` with the given `Dataver`.
    pub const fn new(dataver: Dataver) -> Self {
        Self { dataver }
    }

    /// Adapt the handler instance to the generic `rs-matter` `Handler` trait
    pub const fn adapt(self) -> HandlerAdaptor<Self> {
        HandlerAdaptor(self)
    }
}

impl ClusterHandler for GrpKeyMgmtHandler {
    const CLUSTER: Cluster<'static> = FULL_CLUSTER.with_attrs(with!(required));

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    fn group_key_map<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<GroupKeyMapStructArrayBuilder<P>, GroupKeyMapStructBuilder<P>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(builder) => builder.end(),
            ArrayAttributeRead::ReadOne(_, _) => Err(ErrorCode::InvalidAction.into()), // TODO
        }
    }

    fn group_table<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<
            GroupInfoMapStructArrayBuilder<P>,
            GroupInfoMapStructBuilder<P>,
        >,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(builder) => builder.end(),
            ArrayAttributeRead::ReadOne(_, _) => Err(ErrorCode::InvalidAction.into()), // TODO
        }
    }

    fn max_groups_per_fabric(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        Ok(1)
    }

    fn max_group_keys_per_fabric(&self, _ctx: &ReadContext<'_>) -> Result<u16, Error> {
        Ok(1)
    }

    fn set_group_key_map(
        &self,
        _ctx: &crate::dm::objects::WriteContext<'_>,
        _value: ArrayAttributeWrite<
            crate::tlv::TLVArray<'_, GroupKeyMapStruct<'_>>,
            GroupKeyMapStruct<'_>,
        >,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn handle_key_set_write(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: KeySetWriteRequest<'_>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn handle_key_set_read<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: KeySetReadRequest<'_>,
        _response: KeySetReadResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::NotFound.into())
    }

    fn handle_key_set_remove(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: KeySetRemoveRequest<'_>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn handle_key_set_read_all_indices<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        response: KeySetReadAllIndicesResponseBuilder<P>,
    ) -> Result<P, Error> {
        response.group_key_set_i_ds()?.end()?.end()
    }
}
