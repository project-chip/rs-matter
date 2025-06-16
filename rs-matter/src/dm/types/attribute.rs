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
    pub fn is_system(&self) -> bool {
        Self::is_system_attr(self.id)
    }

    /// Return `true` if the attribute ID is a system one (i.e. a global attribute).
    pub fn is_system_attr(attr_id: AttrId) -> bool {
        attr_id >= (GlobalElements::GeneratedCmdList as AttrId)
    }
}

impl core::fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

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

pub const GENERATED_COMMAND_LIST: Attribute = Attribute::new(
    GlobalElements::GeneratedCmdList as _,
    Access::RV,
    Quality::NONE,
);

pub const ACCEPTED_COMMAND_LIST: Attribute = Attribute::new(
    GlobalElements::AcceptedCmdList as _,
    Access::RV,
    Quality::NONE,
);

pub const EVENT_LIST: Attribute =
    Attribute::new(GlobalElements::EventList as _, Access::RV, Quality::NONE);

pub const ATTRIBUTE_LIST: Attribute = Attribute::new(
    GlobalElements::AttributeList as _,
    Access::RV,
    Quality::NONE,
);

pub const FEATURE_MAP: Attribute =
    Attribute::new(GlobalElements::FeatureMap as _, Access::RV, Quality::NONE);

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
        if let Some(Some(index)) = index.clone().map(Into::into) {
            // Valid index - read one element
            Ok(Self::ReadOne(index, TLVBuilder::new(parent, tag)?))
        } else {
            // Read the whole array
            Ok(Self::ReadAll(TLVBuilder::new(parent, tag)?))
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
        if let Some(Some(index)) = index.clone().map(Into::into) {
            // If the index is valid, this is an item update or removal
            if data.null().is_ok() {
                // Data is null - item removal
                Ok(Self::Remove(index))
            } else {
                Ok(Self::Update(index, FromTLV::from_tlv(data)?))
            }
        } else if data.array().is_ok() {
            // The data is an array, so the whole array needs to be replaced
            Ok(Self::Replace(FromTLV::from_tlv(data)?))
        } else {
            // The data is not an array and there is no index, so this must be an Add operation
            Ok(Self::Add(FromTLV::from_tlv(data)?))
        }
    }
}

// TODO: What if we instead of creating this, we just pass the AttrData/AttrPath to the read/write
// methods?
/// The Attribute Details structure records the details about the attribute under consideration.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttrDetails<'a> {
    pub node: &'a Node<'a>,
    /// The actual endpoint ID
    pub endpoint_id: EndptId,
    /// The actual cluster ID
    pub cluster_id: ClusterId,
    /// The actual attribute ID
    pub attr_id: AttrId,
    /// List Index, if any
    pub list_index: Option<Nullable<u16>>,
    /// The current Fabric Index
    pub fab_idx: u8,
    /// Fabric Filtering Activated
    pub fab_filter: bool,
    pub dataver: Option<u32>,
    pub wildcard: bool,
}

impl AttrDetails<'_> {
    pub fn is_system(&self) -> bool {
        Attribute::is_system_attr(self.attr_id)
    }

    pub fn path(&self) -> AttrPath {
        AttrPath {
            endpoint: Some(self.endpoint_id),
            cluster: Some(self.cluster_id),
            attr: Some(self.attr_id),
            list_index: self.list_index.clone(),
            ..Default::default()
        }
    }

    pub fn cluster(&self) -> Result<&Cluster, Error> {
        self.node
            .endpoint(self.endpoint_id)
            .and_then(|endpoint| endpoint.cluster(self.cluster_id))
            .ok_or_else(|| {
                error!("Cluster not found");
                ErrorCode::ClusterNotFound.into()
            })
    }

    pub fn status(&self, status: IMStatusCode) -> Result<Option<AttrStatus>, Error> {
        if self.should_report(status) {
            Ok(Some(AttrStatus::new(
                &GenericPath {
                    endpoint: Some(self.endpoint_id),
                    cluster: Some(self.cluster_id),
                    leaf: Some(self.attr_id as _),
                },
                status,
                0,
            )))
        } else {
            Ok(None)
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

    fn should_report(&self, status: IMStatusCode) -> bool {
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
