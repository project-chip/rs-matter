/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
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
#![allow(clippy::bad_bit_mask)]

use core::fmt::{self, Debug};

use strum::FromRepr;

use crate::attribute_enum;
use crate::error::{Error, ErrorCode};
use crate::im::{AttrPath, AttrStatus, GenericPath, IMStatusCode};
use crate::tlv::{AsNullable, FromTLV, Nullable, TLVBuilder, TLVBuilderParent, TLVElement, TLVTag};
use crate::utils::maybe::Maybe;

use super::{Access, AttrId, Cluster, ClusterId, EndptId, Node, Quality};

/// A type modeling the attribute meta-data in the Matter data model.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Attribute {
    /// The attribute ID
    pub id: AttrId,
    /// The access control for the attribute
    pub access: Access,
    /// The quality of the attribute
    pub quality: Quality,
}

impl Attribute {
    /// Create a new attribute with the given ID, access control and quality.
    pub const fn new(id: AttrId, access: Access, quality: Quality) -> Self {
        Self {
            id,
            access,
            quality,
        }
    }

    /// Return `true` if the attribute is a system one (i.e. a global attribute).
    pub const fn is_system(&self) -> bool {
        Self::is_system_attr(self.id)
    }

    /// Return `true` if the attribute ID is a system one (i.e. a global attribute).
    pub const fn is_system_attr(attr_id: AttrId) -> bool {
        attr_id >= (GlobalElements::GeneratedCmdList as AttrId) && attr_id <= u16::MAX as AttrId
    }
}

impl core::fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// An enum for the attribute IDs of all Matter Global attributes
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromRepr)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u32)]
pub enum GlobalElements {
    FabricIndex = 0xFE,
    GeneratedCmdList = 0xFFF8,
    AcceptedCmdList = 0xFFF9,
    EventList = 0xFFFA,
    AttributeList = 0xFFFB,
    FeatureMap = 0xFFFC,
    ClusterRevision = 0xFFFD,
}

attribute_enum!(GlobalElements);

/// The global attribute for the Generated Command List.
pub const GENERATED_COMMAND_LIST: Attribute = Attribute::new(
    GlobalElements::GeneratedCmdList as _,
    Access::RV,
    Quality::A,
);

/// The global attribute for the Accepted Command List.
pub const ACCEPTED_COMMAND_LIST: Attribute =
    Attribute::new(GlobalElements::AcceptedCmdList as _, Access::RV, Quality::A);

/// The global attribute for the Event List.
pub const EVENT_LIST: Attribute =
    Attribute::new(GlobalElements::EventList as _, Access::RV, Quality::A);

/// The global attribute for the Attribute List.
pub const ATTRIBUTE_LIST: Attribute =
    Attribute::new(GlobalElements::AttributeList as _, Access::RV, Quality::A);

/// The global attribute for the Feature Map.
pub const FEATURE_MAP: Attribute =
    Attribute::new(GlobalElements::FeatureMap as _, Access::RV, Quality::NONE);

/// The global attribute for the Cluster Revision.
pub const CLUSTER_REVISION: Attribute = Attribute::new(
    GlobalElements::ClusterRevision as _,
    Access::RV,
    Quality::NONE,
);

/// A macro to generate the attributes for a cluster.
#[allow(unused_macros)]
#[macro_export]
macro_rules! attributes {
    () => {
        &[
            $crate::dm::GENERATED_COMMAND_LIST,
            $crate::dm::ACCEPTED_COMMAND_LIST,
            $crate::dm::EVENT_LIST,
            $crate::dm::ATTRIBUTE_LIST,
            $crate::dm::FEATURE_MAP,
            $crate::dm::CLUSTER_REVISION,
        ]
    };
    ($attr0:expr $(, $attr:expr)* $(,)?) => {
        &[
            $attr0,
            $($attr,)*
            $crate::dm::GENERATED_COMMAND_LIST,
            $crate::dm::ACCEPTED_COMMAND_LIST,
            $crate::dm::EVENT_LIST,
            $crate::dm::ATTRIBUTE_LIST,
            $crate::dm::FEATURE_MAP,
            $crate::dm::CLUSTER_REVISION,
        ]
    }
}

/// A macro to generate a `TryFrom` implementation for an attribute enum.
#[allow(unused_macros)]
#[macro_export]
macro_rules! attribute_enum {
    ($en:ty) => {
        impl core::convert::TryFrom<$crate::dm::AttrId> for $en {
            type Error = $crate::error::Error;

            fn try_from(id: $crate::dm::AttrId) -> Result<Self, Self::Error> {
                <$en>::from_repr(id)
                    .ok_or_else(|| $crate::error::ErrorCode::AttributeNotFound.into())
            }
        }
    };
}

/// An enum for modeling reads from attributes whose type is an array.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ArrayAttributeRead<T, E> {
    /// Read the whole array
    ReadAll(T),
    /// Read one element of the array
    ReadOne(u16, E),
    /// Read an empty array
    ReadNone(T),
}

impl<T, E> ArrayAttributeRead<T, E> {
    /// Create a new `ArrayAttributeRead` from an index.
    pub fn new<P>(
        index: Option<Maybe<u16, AsNullable>>,
        parent: P,
        tag: &TLVTag,
    ) -> Result<Self, Error>
    where
        P: TLVBuilderParent,
        T: TLVBuilder<P>,
        E: TLVBuilder<P>,
    {
        match index.map(Nullable::into_option) {
            Some(Some(index)) => Ok(Self::ReadOne(index, E::new(parent, tag)?)),
            Some(None) => Ok(Self::ReadNone(T::new(parent, tag)?)),
            None => Ok(Self::ReadAll(T::new(parent, tag)?)),
        }
    }
}

/// An enum for modeling writes to attributes whose type is an array.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ArrayAttributeWrite<T, E> {
    /// Replace the whole array
    Replace(T),
    /// Add a new element to the array
    Add(E),
    /// Replace/update an element of the array
    Update(u16, E),
    /// Remove an element of the array
    Remove(u16),
}

impl<T, E> ArrayAttributeWrite<T, E> {
    /// Create a new `ArrayAttributeWrite` from a TLV element
    /// and an index.
    pub fn new<'a>(
        index: Option<Maybe<u16, AsNullable>>,
        data: &TLVElement<'a>,
    ) -> Result<Self, Error>
    where
        T: FromTLV<'a>,
        E: FromTLV<'a>,
    {
        match index.map(Nullable::into_option) {
            Some(Some(_index)) => {
                // Index is present and non-null => this is an item update or removal
                // Note that this is not supported by the Matter Core spec yet (section 10.6.4.3.1 "Lists" in V1.4.2), so we return an error instead

                // if data.null().is_ok() {
                //     // Data is null - item removal
                //     Ok(Self::Remove(index))
                // } else {
                //     Ok(Self::Update(index, FromTLV::from_tlv(data)?))
                // }

                Err(ErrorCode::InvalidAction.into())
            }
            Some(None) => {
                // Index is present but null => item addition
                Ok(Self::Add(FromTLV::from_tlv(data)?))
            }
            None => {
                // Index is not present => array replace
                Ok(Self::Replace(FromTLV::from_tlv(data)?))
            }
        }
    }
}

/// The `AttrDetails` type captures all necessary information to perform an Attribute Read or Write operation
///
/// This type is built by the Data Model during the expansion of the attributes in the `Read` and `Write` IM actions
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttrDetails<'a> {
    /// The node meta-data
    pub node: &'a Node<'a>,
    /// The concrete (expanded) endpoint ID
    pub endpoint_id: EndptId,
    /// The concrete (expanded) cluster ID
    pub cluster_id: ClusterId,
    /// The concrete (expanded) attribute ID
    pub attr_id: AttrId,
    /// List index, if any
    pub list_index: Option<Nullable<u16>>,
    /// Valid only when the operation is attrubute read of
    /// an individual array item
    /// When `true`, the path written to the output will contain
    /// `null` as a list index. This is necessary when we are returning
    /// an array attribute in a chunked manner
    pub list_chunked: bool,
    /// The fabric index associated with this request
    pub fab_idx: u8,
    /// Whether fabric filtering is active for this request
    pub fab_filter: bool,
    /// Attribute expected data version (when writing)
    pub dataver: Option<u32>,
    /// Whether the original attribute was a wildcard one
    pub wildcard: bool,
}

impl AttrDetails<'_> {
    /// Return `true` if the attribute is a system one (i.e. a global attribute).
    pub const fn is_system(&self) -> bool {
        Attribute::is_system_attr(self.attr_id)
    }

    /// Return the path with which this attribute read/write request
    /// should be replied.
    pub fn reply_path(&self) -> AttrPath {
        AttrPath {
            node: None,
            endpoint: Some(self.endpoint_id),
            cluster: Some(self.cluster_id),
            attr: Some(self.attr_id),
            list_index: if self.list_chunked {
                match self.list_index.as_ref().map(|li| li.as_opt_ref()) {
                    // Convert specific indexed item to item with index null (= append)
                    Some(Some(_)) => Some(Nullable::none()),
                    // Convert the `rs-matter`-specific request for an empty array to Matter spec compliant result
                    Some(None) | None => None,
                }
            } else {
                self.list_index.clone()
            },
            tag_compression: None,
        }
    }

    pub fn cluster(&self) -> Result<&Cluster<'_>, Error> {
        self.node
            .endpoint(self.endpoint_id)
            .and_then(|endpoint| endpoint.cluster(self.cluster_id))
            .ok_or_else(|| {
                error!("Cluster not found");
                ErrorCode::ClusterNotFound.into()
            })
    }

    pub const fn status(&self, status: IMStatusCode) -> Option<AttrStatus> {
        if self.should_report(status) {
            Some(AttrStatus::new(
                &GenericPath {
                    endpoint: Some(self.endpoint_id),
                    cluster: Some(self.cluster_id),
                    leaf: Some(self.attr_id as _),
                },
                status,
                None,
            ))
        } else {
            None
        }
    }

    /// Check the data version of the attribute (attribute write operations only).
    ///
    /// if the attribute data version is set and is different
    /// from the provided one then return an error.
    pub fn check_dataver(&self, dataver: u32) -> Result<(), Error> {
        if let Some(req_dataver) = self.dataver {
            if req_dataver != dataver {
                Err(ErrorCode::DataVersionMismatch)?;
            }
        }

        Ok(())
    }

    const fn should_report(&self, status: IMStatusCode) -> bool {
        !self.wildcard
            || !matches!(
                status,
                IMStatusCode::UnsupportedEndpoint
                    | IMStatusCode::UnsupportedCluster
                    | IMStatusCode::UnsupportedAttribute
                    | IMStatusCode::UnsupportedCommand
                    | IMStatusCode::UnsupportedAccess
                    | IMStatusCode::UnsupportedRead
                    | IMStatusCode::UnsupportedWrite
                    | IMStatusCode::DataVersionMismatch
            )
    }
}

#[cfg(test)]
#[allow(clippy::bool_assert_comparison)]
mod tests {
    use super::Access;
    use crate::dm::Privilege;

    #[test]
    fn test_read() {
        let c = Access::READ;
        // Read without NEED_VIEW, implies No Read is possible
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), false);

        let c = Access::WRITE | Access::NEED_VIEW;
        // Read without Read, implies No Read is possible
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), false);

        let c = Access::RV;
        // Read with View or Admin privilege
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::ADMIN), true);

        let c = Access::READ | Access::NEED_ADMIN;
        // Read without Admin privilege
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), false);
        assert_eq!(c.is_ok(Access::READ, Privilege::OPERATE), false);
        assert_eq!(c.is_ok(Access::READ, Privilege::MANAGE), false);
        assert_eq!(c.is_ok(Access::READ, Privilege::ADMIN), true);

        let c = Access::READ | Access::NEED_OPERATE;
        // Read without Operate privilege
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), false);
        assert_eq!(c.is_ok(Access::READ, Privilege::OPERATE), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::MANAGE), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::ADMIN), true);
    }

    #[test]
    fn test_write() {
        let c = Access::WRITE;
        // Write NEED_*, implies No Write is possible
        assert_eq!(c.is_ok(Access::WRITE, Privilege::VIEW), false);

        let c = Access::READ | Access::NEED_MANAGE;
        // Write without Write, implies No Write is possible
        assert_eq!(c.is_ok(Access::WRITE, Privilege::MANAGE), false);

        let c = Access::RWVA;
        // Write with View and Admin privilege
        assert_eq!(c.is_ok(Access::WRITE, Privilege::VIEW), false);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::ADMIN), true);

        let c = Access::RWVA;
        // WRITE without Admin privilege
        assert_eq!(c.is_ok(Access::WRITE, Privilege::VIEW), false);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::OPERATE), false);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::MANAGE), false);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::ADMIN), true);
        // Read with View Privilege
        assert_eq!(c.is_ok(Access::READ, Privilege::VIEW), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::OPERATE), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::MANAGE), true);
        assert_eq!(c.is_ok(Access::READ, Privilege::ADMIN), true);

        let c = Access::WRITE | Access::NEED_OPERATE;
        // WRITE without Operate privilege
        assert_eq!(c.is_ok(Access::WRITE, Privilege::VIEW), false);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::OPERATE), true);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::MANAGE), true);
        assert_eq!(c.is_ok(Access::WRITE, Privilege::ADMIN), true);
    }
}
