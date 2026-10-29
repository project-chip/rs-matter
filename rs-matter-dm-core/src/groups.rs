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

use core::num::NonZeroU8;

use crate::error::Error;
use crate::utils::sync::MaybeSendSync;

use super::EndptId;

/// Tells which endpoints are members of which groups.
///
/// The node implements it with its group table. The cluster handlers that
/// need to know about group membership (e.g. Scenes) are given one when they
/// are created.
pub trait GroupMembership: MaybeSendSync {
    /// Whether the endpoint `endpoint_id` is a member of the group `group_id`
    /// on the fabric `fab_idx`.
    fn is_member(
        &self,
        fab_idx: NonZeroU8,
        group_id: u16,
        endpoint_id: EndptId,
    ) -> Result<bool, Error>;
}

impl<T> GroupMembership for &T
where
    T: GroupMembership,
{
    fn is_member(
        &self,
        fab_idx: NonZeroU8,
        group_id: u16,
        endpoint_id: EndptId,
    ) -> Result<bool, Error> {
        (**self).is_member(fab_idx, group_id, endpoint_id)
    }
}
