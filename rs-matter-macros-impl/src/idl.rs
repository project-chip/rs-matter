/*
 * Copyright (c) 2024 Project CHIP Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::quote;

use rs_matter_data_model::Cluster;

mod bitmap;
mod cluster;
mod enumeration;
mod field;
mod handler;
mod id;
mod struct_in;
mod struct_out;

/// Some context data for IDL generation
///
/// Data that is necessary to be able to code generate various bits.
/// In particular, matter_rs types (e.g. TLV or traits) are needed,
/// hence the crate name is provided
pub struct IdlGenerateContext {
    rs_matter_crate: Ident,
}

impl IdlGenerateContext {
    pub fn new(rs_matter_crate: impl AsRef<str>) -> Self {
        Self {
            rs_matter_crate: Ident::new(rs_matter_crate.as_ref(), Span::call_site()),
        }
    }
}

/// Return a token stream containing Rust types corresponding to all definitions
/// in the provided IDL cluster:
///
pub fn cluster(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    cluster_internal(cluster, true, context)
}

fn cluster_internal(
    cluster: &Cluster,
    with_async: bool,
    context: &IdlGenerateContext,
) -> TokenStream {
    //let cluster_module_name = Ident::new(&cluster.id.to_case(Case::Snake), Span::call_site());

    let bitmaps = bitmap::bitmaps(cluster, context);
    let enums = enumeration::enums(cluster, context);
    let struct_tags = struct_in::struct_tags(cluster);
    let structs = struct_in::structs(cluster, context);
    let struct_builders = struct_out::struct_builders(cluster, context);

    let attribute_id = cluster::attribute_id(cluster, context);
    let command_id = cluster::command_id(cluster, context);
    let command_response_id = cluster::command_response_id(cluster, context);
    let cluster_meta = cluster::cluster(cluster, context);

    let handler = handler::handler(false, false, cluster, context);
    let handler_inherent_impl = handler::handler(false, true, cluster, context);
    let handler_adaptor = handler::handler_adaptor(false, cluster, context);

    let cluster_code = Literal::u32_unsuffixed(cluster.code as u32);

    let quote = quote!(
        pub const ID: u32 = #cluster_code;

        #bitmaps

        #enums

        #struct_tags

        #structs

        #struct_builders

        #attribute_id

        #command_id

        #command_response_id

        #cluster_meta

        #handler

        #handler_inherent_impl

        #handler_adaptor
    );

    if with_async {
        let async_handler = handler::handler(true, false, cluster, context);
        let async_handler_inherent_impl = handler::handler(true, true, cluster, context);
        let async_handler_adaptor = handler::handler_adaptor(true, cluster, context);

        quote!(
            #quote

            #async_handler

            #async_handler_inherent_impl

            #async_handler_adaptor
        )
    } else {
        quote
    }
}

#[cfg(test)]
mod tests {
    use assert_tokenstreams_eq::assert_tokenstreams_eq;

    use rs_matter_data_model::idl::Idl;
    use rs_matter_data_model::{Cluster, CSA_STANDARD_CLUSTERS_IDL};

    use crate::idl::IdlGenerateContext;

    use super::cluster_internal;

    pub(crate) fn parse_idl(input: &str) -> Idl {
        Idl::parse(input.into()).expect("valid input")
    }

    pub(crate) fn get_cluster_named<'a>(idl: &'a Idl, name: &str) -> Option<&'a Cluster> {
        idl.clusters.iter().find(|&cluster| cluster.id == name)
    }

    #[test]
    fn test_unit_testing_cluster() {
        let idl = parse_idl(&CSA_STANDARD_CLUSTERS_IDL);

        let cluster = get_cluster_named(&idl, "UnitTesting").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!(
        //     "====\n{}\n====",
        //     &cluster_internal(cluster, false, &context)
        // );

        assert_tokenstreams_eq!(
            &cluster_internal(cluster, false, &context),
            &TOKEN_STREAM_OUTPUT
        );
    }

    const TOKEN_STREAM_OUTPUT: &str = r#"
pub const ID: u32 = 4294048773;
#[cfg(not(feature = "defmt"))]
bitflags::bitflags! { # [repr (transparent)] # [derive (Default , Debug , Copy , Clone , Eq , PartialEq , Hash)] pub struct Bitmap16MaskMap : u16 { const MASK_VAL_1 = 1 ; const MASK_VAL_2 = 2 ; const MASK_VAL_3 = 4 ; const MASK_VAL_4 = 16384 ; } }
#[cfg(feature = "defmt")]
defmt::bitflags! { # [repr (transparent)] # [derive (Default)] pub struct Bitmap16MaskMap : u16 { const MASK_VAL_1 = 1 ; const MASK_VAL_2 = 2 ; const MASK_VAL_3 = 4 ; const MASK_VAL_4 = 16384 ; } }
rs_matter_crate::bitflags_tlv!(Bitmap16MaskMap, u16);
#[cfg(not(feature = "defmt"))]
bitflags::bitflags! { # [repr (transparent)] # [derive (Default , Debug , Copy , Clone , Eq , PartialEq , Hash)] pub struct Bitmap32MaskMap : u32 { const MASK_VAL_1 = 1 ; const MASK_VAL_2 = 2 ; const MASK_VAL_3 = 4 ; const MASK_VAL_4 = 1073741824 ; } }
#[cfg(feature = "defmt")]
defmt::bitflags! { # [repr (transparent)] # [derive (Default)] pub struct Bitmap32MaskMap : u32 { const MASK_VAL_1 = 1 ; const MASK_VAL_2 = 2 ; const MASK_VAL_3 = 4 ; const MASK_VAL_4 = 1073741824 ; } }
rs_matter_crate::bitflags_tlv!(Bitmap32MaskMap, u32);
#[cfg(not(feature = "defmt"))]
bitflags::bitflags! { # [repr (transparent)] # [derive (Default , Debug , Copy , Clone , Eq , PartialEq , Hash)] pub struct Bitmap64MaskMap : u64 { const MASK_VAL_1 = 1 ; const MASK_VAL_2 = 2 ; const MASK_VAL_3 = 4 ; const MASK_VAL_4 = 4611686018427387904 ; } }
#[cfg(feature = "defmt")]
defmt::bitflags! { # [repr (transparent)] # [derive (Default)] pub struct Bitmap64MaskMap : u64 { const MASK_VAL_1 = 1 ; const MASK_VAL_2 = 2 ; const MASK_VAL_3 = 4 ; const MASK_VAL_4 = 4611686018427387904 ; } }
rs_matter_crate::bitflags_tlv!(Bitmap64MaskMap, u64);
#[cfg(not(feature = "defmt"))]
bitflags::bitflags! { # [repr (transparent)] # [derive (Default , Debug , Copy , Clone , Eq , PartialEq , Hash)] pub struct Bitmap8MaskMap : u8 { const MASK_VAL_1 = 1 ; const MASK_VAL_2 = 2 ; const MASK_VAL_3 = 4 ; const MASK_VAL_4 = 64 ; } }
#[cfg(feature = "defmt")]
defmt::bitflags! { # [repr (transparent)] # [derive (Default)] pub struct Bitmap8MaskMap : u8 { const MASK_VAL_1 = 1 ; const MASK_VAL_2 = 2 ; const MASK_VAL_3 = 4 ; const MASK_VAL_4 = 64 ; } }
rs_matter_crate::bitflags_tlv!(Bitmap8MaskMap, u8);
#[cfg(not(feature = "defmt"))]
bitflags::bitflags! { # [repr (transparent)] # [derive (Default , Debug , Copy , Clone , Eq , PartialEq , Hash)] pub struct SimpleBitmap : u8 { const VALUE_A = 1 ; const VALUE_B = 2 ; const VALUE_C = 4 ; } }
#[cfg(feature = "defmt")]
defmt::bitflags! { # [repr (transparent)] # [derive (Default)] pub struct SimpleBitmap : u8 { const VALUE_A = 1 ; const VALUE_B = 2 ; const VALUE_C = 4 ; } }
rs_matter_crate::bitflags_tlv!(SimpleBitmap, u8);
#[derive(
    Debug,
    PartialEq,
    Eq,
    Copy,
    Clone,
    Hash,
    rs_matter_crate :: tlv :: FromTLV,
    rs_matter_crate :: tlv :: ToTLV,
)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum SimpleEnum {
    #[enumval(0)]
    Unspecified = 0,
    #[enumval(1)]
    ValueA = 1,
    #[enumval(2)]
    ValueB = 2,
    #[enumval(3)]
    ValueC = 3,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum SimpleStructTag {
    A = 0,
    B = 1,
    C = 2,
    D = 3,
    E = 4,
    F = 5,
    G = 6,
    H = 7,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestFabricScopedTag {
    FabricSensitiveInt8U = 1,
    OptionalFabricSensitiveInt8U = 2,
    NullableFabricSensitiveInt8U = 3,
    NullableOptionalFabricSensitiveInt8U = 4,
    FabricSensitiveCharString = 5,
    FabricSensitiveStruct = 6,
    FabricSensitiveInt8UList = 7,
    FabricIndex = 254,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum NullablesAndOptionalsStructTag {
    NullableInt = 0,
    OptionalInt = 1,
    NullableOptionalInt = 2,
    NullableString = 3,
    OptionalString = 4,
    NullableOptionalString = 5,
    NullableStruct = 6,
    OptionalStruct = 7,
    NullableOptionalStruct = 8,
    NullableList = 9,
    OptionalList = 10,
    NullableOptionalList = 11,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum NestedStructTag {
    A = 0,
    B = 1,
    C = 2,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum NestedStructListTag {
    A = 0,
    B = 1,
    C = 2,
    D = 3,
    E = 4,
    F = 5,
    G = 6,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum DoubleNestedStructListTag {
    A = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestListStructOctetTag {
    Member1 = 0,
    Member2 = 1,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestSpecificResponseTag {
    ReturnValue = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestAddArgumentsResponseTag {
    ReturnValue = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestSimpleArgumentResponseTag {
    ReturnValue = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestStructArrayArgumentResponseTag {
    Arg1 = 0,
    Arg2 = 1,
    Arg3 = 2,
    Arg4 = 3,
    Arg5 = 4,
    Arg6 = 5,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestAddArgumentsRequestTag {
    Arg1 = 0,
    Arg2 = 1,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestListInt8UReverseResponseTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestSimpleArgumentRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestEnumsResponseTag {
    Arg1 = 0,
    Arg2 = 1,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestStructArrayArgumentRequestRequestTag {
    Arg1 = 0,
    Arg2 = 1,
    Arg3 = 2,
    Arg4 = 3,
    Arg5 = 4,
    Arg6 = 5,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestNullableOptionalResponseTag {
    WasPresent = 0,
    WasNull = 1,
    Value = 2,
    OriginalValue = 3,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestStructArgumentRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestComplexNullableOptionalResponseTag {
    NullableIntWasNull = 0,
    NullableIntValue = 1,
    OptionalIntWasPresent = 2,
    OptionalIntValue = 3,
    NullableOptionalIntWasPresent = 4,
    NullableOptionalIntWasNull = 5,
    NullableOptionalIntValue = 6,
    NullableStringWasNull = 7,
    NullableStringValue = 8,
    OptionalStringWasPresent = 9,
    OptionalStringValue = 10,
    NullableOptionalStringWasPresent = 11,
    NullableOptionalStringWasNull = 12,
    NullableOptionalStringValue = 13,
    NullableStructWasNull = 14,
    NullableStructValue = 15,
    OptionalStructWasPresent = 16,
    OptionalStructValue = 17,
    NullableOptionalStructWasPresent = 18,
    NullableOptionalStructWasNull = 19,
    NullableOptionalStructValue = 20,
    NullableListWasNull = 21,
    NullableListValue = 22,
    OptionalListWasPresent = 23,
    OptionalListValue = 24,
    NullableOptionalListWasPresent = 25,
    NullableOptionalListWasNull = 26,
    NullableOptionalListValue = 27,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestNestedStructArgumentRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum BooleanResponseTag {
    Value = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestListStructArgumentRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum SimpleStructResponseTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestListInt8UArgumentRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestEmitTestEventResponseTag {
    Value = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestNestedStructListArgumentRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestEmitTestFabricScopedEventResponseTag {
    Value = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestListNestedStructListArgumentRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestBatchHelperResponseTag {
    Buffer = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestListInt8UReverseRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestEnumsRequestRequestTag {
    Arg1 = 0,
    Arg2 = 1,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestNullableOptionalRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestComplexNullableOptionalRequestRequestTag {
    NullableInt = 0,
    OptionalInt = 1,
    NullableOptionalInt = 2,
    NullableString = 3,
    OptionalString = 4,
    NullableOptionalString = 5,
    NullableStruct = 6,
    OptionalStruct = 7,
    NullableOptionalStruct = 8,
    NullableList = 9,
    OptionalList = 10,
    NullableOptionalList = 11,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum SimpleStructEchoRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestSimpleOptionalArgumentRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestEmitTestEventRequestRequestTag {
    Arg1 = 0,
    Arg2 = 1,
    Arg3 = 2,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestEmitTestFabricScopedEventRequestRequestTag {
    Arg1 = 0,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestBatchHelperRequestRequestTag {
    SleepBeforeResponseTimeMs = 0,
    SizeOfResponseBuffer = 1,
    FillCharacter = 2,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TestSecondBatchHelperRequestRequestTag {
    SleepBeforeResponseTimeMs = 0,
    SizeOfResponseBuffer = 1,
    FillCharacter = 2,
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SimpleStruct<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> SimpleStruct<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn a(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn b(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
    pub fn c(&self) -> Result<SimpleEnum, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
    }
    pub fn d(&self) -> Result<rs_matter_crate::tlv::OctetStr<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(3)?)
    }
    pub fn e(&self) -> Result<rs_matter_crate::tlv::Utf8Str<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(4)?)
    }
    pub fn f(&self) -> Result<SimpleBitmap, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(5)?)
    }
    pub fn g(&self) -> Result<f32, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(6)?)
    }
    pub fn h(&self) -> Result<f64, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(7)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for SimpleStruct<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for SimpleStruct<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestFabricScoped<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestFabricScoped<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn fabric_sensitive_int_8_u(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
    pub fn optional_fabric_sensitive_int_8_u(
        &self,
    ) -> Result<Option<u8>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(2)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_fabric_sensitive_int_8_u(
        &self,
    ) -> Result<rs_matter_crate::tlv::Nullable<u8>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(3)?)
    }
    pub fn nullable_optional_fabric_sensitive_int_8_u(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::Nullable<u8>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(4)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn fabric_sensitive_char_string(
        &self,
    ) -> Result<rs_matter_crate::tlv::Utf8Str<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(5)?)
    }
    pub fn fabric_sensitive_struct(
        &self,
    ) -> Result<SimpleStruct<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(6)?)
    }
    pub fn fabric_sensitive_int_8_u_list(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, u8>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(7)?)
    }
    pub fn fabric_index(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(254)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestFabricScoped<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestFabricScoped<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NullablesAndOptionalsStruct<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> NullablesAndOptionalsStruct<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn nullable_int(
        &self,
    ) -> Result<rs_matter_crate::tlv::Nullable<u16>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn optional_int(&self) -> Result<Option<u16>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(1)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_int(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::Nullable<u16>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(2)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_string(
        &self,
    ) -> Result<
        rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(3)?)
    }
    pub fn optional_string(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::Utf8Str<'_>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(4)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_string(
        &self,
    ) -> Result<
        Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>>,
        rs_matter_crate::error::Error,
    > {
        let element = self.0.structure()?.find_ctx(5)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_struct(
        &self,
    ) -> Result<rs_matter_crate::tlv::Nullable<SimpleStruct<'_>>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(6)?)
    }
    pub fn optional_struct(
        &self,
    ) -> Result<Option<SimpleStruct<'_>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(7)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_struct(
        &self,
    ) -> Result<
        Option<rs_matter_crate::tlv::Nullable<SimpleStruct<'_>>>,
        rs_matter_crate::error::Error,
    > {
        let element = self.0.structure()?.find_ctx(8)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_list(
        &self,
    ) -> Result<
        rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::TLVArray<'_, SimpleEnum>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(9)?)
    }
    pub fn optional_list(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::TLVArray<'_, SimpleEnum>>, rs_matter_crate::error::Error>
    {
        let element = self.0.structure()?.find_ctx(10)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_list(
        &self,
    ) -> Result<
        Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::TLVArray<'_, SimpleEnum>>>,
        rs_matter_crate::error::Error,
    > {
        let element = self.0.structure()?.find_ctx(11)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for NullablesAndOptionalsStruct<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for NullablesAndOptionalsStruct<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NestedStruct<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> NestedStruct<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn a(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn b(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
    pub fn c(&self) -> Result<SimpleStruct<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for NestedStruct<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for NestedStruct<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NestedStructList<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> NestedStructList<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn a(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn b(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
    pub fn c(&self) -> Result<SimpleStruct<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
    }
    pub fn d(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, SimpleStruct<'_>>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(3)?)
    }
    pub fn e(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, u32>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(4)?)
    }
    pub fn f(
        &self,
    ) -> Result<
        rs_matter_crate::tlv::TLVArray<'_, rs_matter_crate::tlv::OctetStr<'_>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(5)?)
    }
    pub fn g(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, u8>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(6)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for NestedStructList<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for NestedStructList<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DoubleNestedStructList<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> DoubleNestedStructList<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn a(
        &self,
    ) -> Result<
        rs_matter_crate::tlv::TLVArray<'_, NestedStructList<'_>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for DoubleNestedStructList<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for DoubleNestedStructList<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestListStructOctet<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestListStructOctet<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn member_1(&self) -> Result<u64, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn member_2(
        &self,
    ) -> Result<rs_matter_crate::tlv::OctetStr<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestListStructOctet<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestListStructOctet<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestSpecificResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestSpecificResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn return_value(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestSpecificResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestSpecificResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestAddArgumentsResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestAddArgumentsResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn return_value(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestAddArgumentsResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestAddArgumentsResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestSimpleArgumentResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestSimpleArgumentResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn return_value(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestSimpleArgumentResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestSimpleArgumentResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestStructArrayArgumentResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestStructArrayArgumentResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(
        &self,
    ) -> Result<
        rs_matter_crate::tlv::TLVArray<'_, NestedStructList<'_>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn arg_2(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, SimpleStruct<'_>>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
    pub fn arg_3(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, SimpleEnum>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
    }
    pub fn arg_4(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, bool>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(3)?)
    }
    pub fn arg_5(&self) -> Result<SimpleEnum, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(4)?)
    }
    pub fn arg_6(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(5)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestStructArrayArgumentResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestStructArrayArgumentResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestAddArgumentsRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestAddArgumentsRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn arg_2(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestAddArgumentsRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestAddArgumentsRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestListInt8UReverseResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestListInt8UReverseResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, u8>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestListInt8UReverseResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestListInt8UReverseResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestSimpleArgumentRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestSimpleArgumentRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestSimpleArgumentRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestSimpleArgumentRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestEnumsResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestEnumsResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<u16, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn arg_2(&self) -> Result<SimpleEnum, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestEnumsResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestEnumsResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestStructArrayArgumentRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestStructArrayArgumentRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(
        &self,
    ) -> Result<
        rs_matter_crate::tlv::TLVArray<'_, NestedStructList<'_>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn arg_2(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, SimpleStruct<'_>>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
    pub fn arg_3(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, SimpleEnum>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
    }
    pub fn arg_4(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, bool>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(3)?)
    }
    pub fn arg_5(&self) -> Result<SimpleEnum, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(4)?)
    }
    pub fn arg_6(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(5)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestStructArrayArgumentRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestStructArrayArgumentRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestNullableOptionalResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestNullableOptionalResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn was_present(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn was_null(&self) -> Result<Option<bool>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(1)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn value(&self) -> Result<Option<u8>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(2)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn original_value(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::Nullable<u8>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(3)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestNullableOptionalResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestNullableOptionalResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestStructArgumentRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestStructArgumentRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<SimpleStruct<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestStructArgumentRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestStructArgumentRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestComplexNullableOptionalResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestComplexNullableOptionalResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn nullable_int_was_null(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn nullable_int_value(&self) -> Result<Option<u16>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(1)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn optional_int_was_present(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
    }
    pub fn optional_int_value(&self) -> Result<Option<u16>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(3)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_int_was_present(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(4)?)
    }
    pub fn nullable_optional_int_was_null(
        &self,
    ) -> Result<Option<bool>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(5)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_int_value(
        &self,
    ) -> Result<Option<u16>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(6)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_string_was_null(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(7)?)
    }
    pub fn nullable_string_value(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::Utf8Str<'_>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(8)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn optional_string_was_present(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(9)?)
    }
    pub fn optional_string_value(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::Utf8Str<'_>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(10)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_string_was_present(
        &self,
    ) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(11)?)
    }
    pub fn nullable_optional_string_was_null(
        &self,
    ) -> Result<Option<bool>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(12)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_string_value(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::Utf8Str<'_>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(13)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_struct_was_null(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(14)?)
    }
    pub fn nullable_struct_value(
        &self,
    ) -> Result<Option<SimpleStruct<'_>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(15)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn optional_struct_was_present(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(16)?)
    }
    pub fn optional_struct_value(
        &self,
    ) -> Result<Option<SimpleStruct<'_>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(17)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_struct_was_present(
        &self,
    ) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(18)?)
    }
    pub fn nullable_optional_struct_was_null(
        &self,
    ) -> Result<Option<bool>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(19)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_struct_value(
        &self,
    ) -> Result<Option<SimpleStruct<'_>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(20)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_list_was_null(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(21)?)
    }
    pub fn nullable_list_value(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::TLVArray<'_, SimpleEnum>>, rs_matter_crate::error::Error>
    {
        let element = self.0.structure()?.find_ctx(22)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn optional_list_was_present(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(23)?)
    }
    pub fn optional_list_value(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::TLVArray<'_, SimpleEnum>>, rs_matter_crate::error::Error>
    {
        let element = self.0.structure()?.find_ctx(24)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_list_was_present(
        &self,
    ) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(25)?)
    }
    pub fn nullable_optional_list_was_null(
        &self,
    ) -> Result<Option<bool>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(26)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_list_value(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::TLVArray<'_, SimpleEnum>>, rs_matter_crate::error::Error>
    {
        let element = self.0.structure()?.find_ctx(27)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestComplexNullableOptionalResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestComplexNullableOptionalResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestNestedStructArgumentRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestNestedStructArgumentRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<NestedStruct<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestNestedStructArgumentRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestNestedStructArgumentRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BooleanResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> BooleanResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn value(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for BooleanResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for BooleanResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestListStructArgumentRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestListStructArgumentRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, SimpleStruct<'_>>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestListStructArgumentRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestListStructArgumentRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SimpleStructResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> SimpleStructResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<SimpleStruct<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for SimpleStructResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for SimpleStructResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestListInt8UArgumentRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestListInt8UArgumentRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, u8>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestListInt8UArgumentRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestListInt8UArgumentRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestEmitTestEventResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestEmitTestEventResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn value(&self) -> Result<u64, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestEmitTestEventResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestEmitTestEventResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestNestedStructListArgumentRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestNestedStructListArgumentRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<NestedStructList<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestNestedStructListArgumentRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestNestedStructListArgumentRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestEmitTestFabricScopedEventResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestEmitTestFabricScopedEventResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn value(&self) -> Result<u64, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestEmitTestFabricScopedEventResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestEmitTestFabricScopedEventResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestListNestedStructListArgumentRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestListNestedStructListArgumentRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(
        &self,
    ) -> Result<
        rs_matter_crate::tlv::TLVArray<'_, NestedStructList<'_>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestListNestedStructListArgumentRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestListNestedStructListArgumentRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestBatchHelperResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestBatchHelperResponse<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn buffer(
        &self,
    ) -> Result<rs_matter_crate::tlv::OctetStr<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestBatchHelperResponse<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestBatchHelperResponse<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestListInt8UReverseRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestListInt8UReverseRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(
        &self,
    ) -> Result<rs_matter_crate::tlv::TLVArray<'_, u8>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestListInt8UReverseRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestListInt8UReverseRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestEnumsRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestEnumsRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<u16, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn arg_2(&self) -> Result<SimpleEnum, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestEnumsRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestEnumsRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestNullableOptionalRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestNullableOptionalRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::Nullable<u8>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(0)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestNullableOptionalRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestNullableOptionalRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestComplexNullableOptionalRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestComplexNullableOptionalRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn nullable_int(
        &self,
    ) -> Result<rs_matter_crate::tlv::Nullable<u16>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn optional_int(&self) -> Result<Option<u16>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(1)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_int(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::Nullable<u16>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(2)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_string(
        &self,
    ) -> Result<
        rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(3)?)
    }
    pub fn optional_string(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::Utf8Str<'_>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(4)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_string(
        &self,
    ) -> Result<
        Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>>,
        rs_matter_crate::error::Error,
    > {
        let element = self.0.structure()?.find_ctx(5)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_struct(
        &self,
    ) -> Result<rs_matter_crate::tlv::Nullable<SimpleStruct<'_>>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(6)?)
    }
    pub fn optional_struct(
        &self,
    ) -> Result<Option<SimpleStruct<'_>>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(7)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_struct(
        &self,
    ) -> Result<
        Option<rs_matter_crate::tlv::Nullable<SimpleStruct<'_>>>,
        rs_matter_crate::error::Error,
    > {
        let element = self.0.structure()?.find_ctx(8)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_list(
        &self,
    ) -> Result<
        rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::TLVArray<'_, SimpleEnum>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(9)?)
    }
    pub fn optional_list(
        &self,
    ) -> Result<Option<rs_matter_crate::tlv::TLVArray<'_, SimpleEnum>>, rs_matter_crate::error::Error>
    {
        let element = self.0.structure()?.find_ctx(10)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
    pub fn nullable_optional_list(
        &self,
    ) -> Result<
        Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::TLVArray<'_, SimpleEnum>>>,
        rs_matter_crate::error::Error,
    > {
        let element = self.0.structure()?.find_ctx(11)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestComplexNullableOptionalRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestComplexNullableOptionalRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SimpleStructEchoRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> SimpleStructEchoRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<SimpleStruct<'_>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for SimpleStructEchoRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for SimpleStructEchoRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestSimpleOptionalArgumentRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestSimpleOptionalArgumentRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<Option<bool>, rs_matter_crate::error::Error> {
        let element = self.0.structure()?.find_ctx(0)?;
        if element.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
        }
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestSimpleOptionalArgumentRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestSimpleOptionalArgumentRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestEmitTestEventRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestEmitTestEventRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn arg_2(&self) -> Result<SimpleEnum, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
    pub fn arg_3(&self) -> Result<bool, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestEmitTestEventRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestEmitTestEventRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestEmitTestFabricScopedEventRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestEmitTestFabricScopedEventRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn arg_1(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestEmitTestFabricScopedEventRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestEmitTestFabricScopedEventRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestBatchHelperRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestBatchHelperRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn sleep_before_response_time_ms(&self) -> Result<u16, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn size_of_response_buffer(&self) -> Result<u16, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
    pub fn fill_character(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestBatchHelperRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestBatchHelperRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TestSecondBatchHelperRequestRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
impl<'a> TestSecondBatchHelperRequestRequest<'a> {
    #[doc = "Create a new instance"]
    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
        Self(element)
    }
    #[doc = "Return the underlying TLV element"]
    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
        &self.0
    }
    pub fn sleep_before_response_time_ms(&self) -> Result<u16, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
    }
    pub fn size_of_response_buffer(&self) -> Result<u16, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
    }
    pub fn fill_character(&self) -> Result<u8, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
    }
}
impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestSecondBatchHelperRequestRequest<'a> {
    fn from_tlv(
        element: &rs_matter_crate::tlv::TLVElement<'a>,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Ok(Self::new(element.clone()))
    }
}
impl rs_matter_crate::tlv::ToTLV for TestSecondBatchHelperRequestRequest<'_> {
    fn to_tlv<W: rs_matter_crate::tlv::TLVWrite>(
        &self,
        tag: &rs_matter_crate::tlv::TLVTag,
        tw: W,
    ) -> Result<(), rs_matter_crate::error::Error> {
        self.0.to_tlv(tag, tw)
    }
    fn tlv_iter(
        &self,
        tag: rs_matter_crate::tlv::TLVTag,
    ) -> impl Iterator<Item = Result<rs_matter_crate::tlv::TLV, rs_matter_crate::error::Error>>
    {
        self.0.tlv_iter(tag)
    }
}
pub struct SimpleStructBuilder<P, const F: usize = 0usize>(P);
impl<P> SimpleStructBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> SimpleStructBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn a(
        mut self,
        value: u8,
    ) -> Result<SimpleStructBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(SimpleStructBuilder(self.0))
    }
}
impl<P> SimpleStructBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn b(
        mut self,
        value: bool,
    ) -> Result<SimpleStructBuilder<P, 2usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(SimpleStructBuilder(self.0))
    }
}
impl<P> SimpleStructBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn c(
        mut self,
        value: SimpleEnum,
    ) -> Result<SimpleStructBuilder<P, 3usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(2),
            self.0.writer(),
        )?;
        Ok(SimpleStructBuilder(self.0))
    }
}
impl<P> SimpleStructBuilder<P, 3>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn d(
        mut self,
        value: rs_matter_crate::tlv::OctetStr<'_>,
    ) -> Result<SimpleStructBuilder<P, 4usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(3),
            self.0.writer(),
        )?;
        Ok(SimpleStructBuilder(self.0))
    }
}
impl<P> SimpleStructBuilder<P, 4>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn e(
        mut self,
        value: rs_matter_crate::tlv::Utf8Str<'_>,
    ) -> Result<SimpleStructBuilder<P, 5usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(4),
            self.0.writer(),
        )?;
        Ok(SimpleStructBuilder(self.0))
    }
}
impl<P> SimpleStructBuilder<P, 5>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn f(
        mut self,
        value: SimpleBitmap,
    ) -> Result<SimpleStructBuilder<P, 6usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(5),
            self.0.writer(),
        )?;
        Ok(SimpleStructBuilder(self.0))
    }
}
impl<P> SimpleStructBuilder<P, 6>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn g(
        mut self,
        value: f32,
    ) -> Result<SimpleStructBuilder<P, 7usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(6),
            self.0.writer(),
        )?;
        Ok(SimpleStructBuilder(self.0))
    }
}
impl<P> SimpleStructBuilder<P, 7>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn h(
        mut self,
        value: f64,
    ) -> Result<SimpleStructBuilder<P, 8usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(7),
            self.0.writer(),
        )?;
        Ok(SimpleStructBuilder(self.0))
    }
}
impl<P> SimpleStructBuilder<P, 8usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for SimpleStructBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for SimpleStructBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct SimpleStructArrayBuilder<P>(P);
impl<P> SimpleStructArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<SimpleStructBuilder<SimpleStructArrayBuilder<P>>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::TLVBuilder::new(
            SimpleStructArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for SimpleStructArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for SimpleStructArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestFabricScopedBuilder<P, const F: usize = 1usize>(P);
impl<P> TestFabricScopedBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestFabricScopedBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn fabric_sensitive_int_8_u(
        mut self,
        value: u8,
    ) -> Result<TestFabricScopedBuilder<P, 2usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(TestFabricScopedBuilder(self.0))
    }
}
impl<P> TestFabricScopedBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_fabric_sensitive_int_8_u(
        mut self,
        value: Option<u8>,
    ) -> Result<TestFabricScopedBuilder<P, 3usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(2),
            self.0.writer(),
        )?;
        Ok(TestFabricScopedBuilder(self.0))
    }
}
impl<P> TestFabricScopedBuilder<P, 3>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_fabric_sensitive_int_8_u(
        mut self,
        value: rs_matter_crate::tlv::Nullable<u8>,
    ) -> Result<TestFabricScopedBuilder<P, 4usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(3),
            self.0.writer(),
        )?;
        Ok(TestFabricScopedBuilder(self.0))
    }
}
impl<P> TestFabricScopedBuilder<P, 4>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_fabric_sensitive_int_8_u(
        mut self,
        value: Option<rs_matter_crate::tlv::Nullable<u8>>,
    ) -> Result<TestFabricScopedBuilder<P, 5usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(4),
            self.0.writer(),
        )?;
        Ok(TestFabricScopedBuilder(self.0))
    }
}
impl<P> TestFabricScopedBuilder<P, 5>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn fabric_sensitive_char_string(
        mut self,
        value: rs_matter_crate::tlv::Utf8Str<'_>,
    ) -> Result<TestFabricScopedBuilder<P, 6usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(5),
            self.0.writer(),
        )?;
        Ok(TestFabricScopedBuilder(self.0))
    }
}
impl<P> TestFabricScopedBuilder<P, 6>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn fabric_sensitive_struct(
        self,
    ) -> Result<
        SimpleStructBuilder<TestFabricScopedBuilder<P, 7usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestFabricScopedBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(6),
        )
    }
}
impl<P> TestFabricScopedBuilder<P, 7>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn fabric_sensitive_int_8_u_list(
        self,
    ) -> Result<
        rs_matter_crate::tlv::ToTLVArrayBuilder<TestFabricScopedBuilder<P, 254usize>, u8>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestFabricScopedBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(7),
        )
    }
}
impl<P> TestFabricScopedBuilder<P, 254>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn fabric_index(
        mut self,
        value: u8,
    ) -> Result<TestFabricScopedBuilder<P, 255usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(254),
            self.0.writer(),
        )?;
        Ok(TestFabricScopedBuilder(self.0))
    }
}
impl<P> TestFabricScopedBuilder<P, 255usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for TestFabricScopedBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestFabricScopedBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestFabricScopedArrayBuilder<P>(P);
impl<P> TestFabricScopedArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestFabricScopedBuilder<TestFabricScopedArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestFabricScopedArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestFabricScopedArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestFabricScopedArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct NullablesAndOptionalsStructBuilder<P, const F: usize = 0usize>(P);
impl<P> NullablesAndOptionalsStructBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_int(
        mut self,
        value: rs_matter_crate::tlv::Nullable<u16>,
    ) -> Result<NullablesAndOptionalsStructBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(NullablesAndOptionalsStructBuilder(self.0))
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_int(
        mut self,
        value: Option<u16>,
    ) -> Result<NullablesAndOptionalsStructBuilder<P, 2usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(NullablesAndOptionalsStructBuilder(self.0))
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_int(
        mut self,
        value: Option<rs_matter_crate::tlv::Nullable<u16>>,
    ) -> Result<NullablesAndOptionalsStructBuilder<P, 3usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(2),
            self.0.writer(),
        )?;
        Ok(NullablesAndOptionalsStructBuilder(self.0))
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 3>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_string(
        mut self,
        value: rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>,
    ) -> Result<NullablesAndOptionalsStructBuilder<P, 4usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(3),
            self.0.writer(),
        )?;
        Ok(NullablesAndOptionalsStructBuilder(self.0))
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 4>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_string(
        mut self,
        value: Option<rs_matter_crate::tlv::Utf8Str<'_>>,
    ) -> Result<NullablesAndOptionalsStructBuilder<P, 5usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(4),
            self.0.writer(),
        )?;
        Ok(NullablesAndOptionalsStructBuilder(self.0))
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 5>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_string(
        mut self,
        value: Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>>,
    ) -> Result<NullablesAndOptionalsStructBuilder<P, 6usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(5),
            self.0.writer(),
        )?;
        Ok(NullablesAndOptionalsStructBuilder(self.0))
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 6>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_struct(
        self,
    ) -> Result<
        rs_matter_crate::tlv::NullableBuilder<
            NullablesAndOptionalsStructBuilder<P, 7usize>,
            SimpleStructBuilder<NullablesAndOptionalsStructBuilder<P, 7usize>>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NullablesAndOptionalsStructBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(6),
        )
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 7>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_struct(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            NullablesAndOptionalsStructBuilder<P, 8usize>,
            SimpleStructBuilder<NullablesAndOptionalsStructBuilder<P, 8usize>>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NullablesAndOptionalsStructBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(7),
        )
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 8>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_struct(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            NullablesAndOptionalsStructBuilder<P, 9usize>,
            rs_matter_crate::tlv::NullableBuilder<
                NullablesAndOptionalsStructBuilder<P, 9usize>,
                SimpleStructBuilder<NullablesAndOptionalsStructBuilder<P, 9usize>>,
            >,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NullablesAndOptionalsStructBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(8),
        )
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 9>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_list(
        self,
    ) -> Result<
        rs_matter_crate::tlv::NullableBuilder<
            NullablesAndOptionalsStructBuilder<P, 10usize>,
            rs_matter_crate::tlv::ToTLVArrayBuilder<
                NullablesAndOptionalsStructBuilder<P, 10usize>,
                SimpleEnum,
            >,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NullablesAndOptionalsStructBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(9),
        )
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 10>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_list(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            NullablesAndOptionalsStructBuilder<P, 11usize>,
            rs_matter_crate::tlv::ToTLVArrayBuilder<
                NullablesAndOptionalsStructBuilder<P, 11usize>,
                SimpleEnum,
            >,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NullablesAndOptionalsStructBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(10),
        )
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 11>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_list(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            NullablesAndOptionalsStructBuilder<P, 12usize>,
            rs_matter_crate::tlv::NullableBuilder<
                NullablesAndOptionalsStructBuilder<P, 12usize>,
                rs_matter_crate::tlv::ToTLVArrayBuilder<
                    NullablesAndOptionalsStructBuilder<P, 12usize>,
                    SimpleEnum,
                >,
            >,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NullablesAndOptionalsStructBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(11),
        )
    }
}
impl<P> NullablesAndOptionalsStructBuilder<P, 12usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for NullablesAndOptionalsStructBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for NullablesAndOptionalsStructBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct NullablesAndOptionalsStructArrayBuilder<P>(P);
impl<P> NullablesAndOptionalsStructArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        NullablesAndOptionalsStructBuilder<NullablesAndOptionalsStructArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NullablesAndOptionalsStructArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for NullablesAndOptionalsStructArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for NullablesAndOptionalsStructArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct NestedStructBuilder<P, const F: usize = 0usize>(P);
impl<P> NestedStructBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> NestedStructBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn a(
        mut self,
        value: u8,
    ) -> Result<NestedStructBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(NestedStructBuilder(self.0))
    }
}
impl<P> NestedStructBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn b(
        mut self,
        value: bool,
    ) -> Result<NestedStructBuilder<P, 2usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(NestedStructBuilder(self.0))
    }
}
impl<P> NestedStructBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn c(
        self,
    ) -> Result<SimpleStructBuilder<NestedStructBuilder<P, 3usize>>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::TLVBuilder::new(
            NestedStructBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(2),
        )
    }
}
impl<P> NestedStructBuilder<P, 3usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for NestedStructBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for NestedStructBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct NestedStructArrayBuilder<P>(P);
impl<P> NestedStructArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<NestedStructBuilder<NestedStructArrayBuilder<P>>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::TLVBuilder::new(
            NestedStructArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for NestedStructArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for NestedStructArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct NestedStructListBuilder<P, const F: usize = 0usize>(P);
impl<P> NestedStructListBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> NestedStructListBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn a(
        mut self,
        value: u8,
    ) -> Result<NestedStructListBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(NestedStructListBuilder(self.0))
    }
}
impl<P> NestedStructListBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn b(
        mut self,
        value: bool,
    ) -> Result<NestedStructListBuilder<P, 2usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(NestedStructListBuilder(self.0))
    }
}
impl<P> NestedStructListBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn c(
        self,
    ) -> Result<
        SimpleStructBuilder<NestedStructListBuilder<P, 3usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NestedStructListBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(2),
        )
    }
}
impl<P> NestedStructListBuilder<P, 3>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn d(
        self,
    ) -> Result<
        SimpleStructArrayBuilder<NestedStructListBuilder<P, 4usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NestedStructListBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(3),
        )
    }
}
impl<P> NestedStructListBuilder<P, 4>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn e(
        self,
    ) -> Result<
        rs_matter_crate::tlv::ToTLVArrayBuilder<NestedStructListBuilder<P, 5usize>, u32>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NestedStructListBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(4),
        )
    }
}
impl<P> NestedStructListBuilder<P, 5>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn f(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OctetsArrayBuilder<NestedStructListBuilder<P, 6usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NestedStructListBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(5),
        )
    }
}
impl<P> NestedStructListBuilder<P, 6>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn g(
        self,
    ) -> Result<
        rs_matter_crate::tlv::ToTLVArrayBuilder<NestedStructListBuilder<P, 7usize>, u8>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NestedStructListBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(6),
        )
    }
}
impl<P> NestedStructListBuilder<P, 7usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for NestedStructListBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for NestedStructListBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct NestedStructListArrayBuilder<P>(P);
impl<P> NestedStructListArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        NestedStructListBuilder<NestedStructListArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            NestedStructListArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for NestedStructListArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for NestedStructListArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct DoubleNestedStructListBuilder<P, const F: usize = 0usize>(P);
impl<P> DoubleNestedStructListBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> DoubleNestedStructListBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn a(
        self,
    ) -> Result<
        NestedStructListArrayBuilder<DoubleNestedStructListBuilder<P, 1usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            DoubleNestedStructListBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> DoubleNestedStructListBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for DoubleNestedStructListBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for DoubleNestedStructListBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct DoubleNestedStructListArrayBuilder<P>(P);
impl<P> DoubleNestedStructListArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        DoubleNestedStructListBuilder<DoubleNestedStructListArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            DoubleNestedStructListArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for DoubleNestedStructListArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for DoubleNestedStructListArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListStructOctetBuilder<P, const F: usize = 0usize>(P);
impl<P> TestListStructOctetBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestListStructOctetBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn member_1(
        mut self,
        value: u64,
    ) -> Result<TestListStructOctetBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestListStructOctetBuilder(self.0))
    }
}
impl<P> TestListStructOctetBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn member_2(
        mut self,
        value: rs_matter_crate::tlv::OctetStr<'_>,
    ) -> Result<TestListStructOctetBuilder<P, 2usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(TestListStructOctetBuilder(self.0))
    }
}
impl<P> TestListStructOctetBuilder<P, 2usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for TestListStructOctetBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestListStructOctetBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListStructOctetArrayBuilder<P>(P);
impl<P> TestListStructOctetArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestListStructOctetBuilder<TestListStructOctetArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestListStructOctetArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestListStructOctetArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestListStructOctetArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestSpecificResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> TestSpecificResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestSpecificResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn return_value(
        mut self,
        value: u8,
    ) -> Result<TestSpecificResponseBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestSpecificResponseBuilder(self.0))
    }
}
impl<P> TestSpecificResponseBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for TestSpecificResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestSpecificResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestSpecificResponseArrayBuilder<P>(P);
impl<P> TestSpecificResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestSpecificResponseBuilder<TestSpecificResponseArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestSpecificResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestSpecificResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestSpecificResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestAddArgumentsResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> TestAddArgumentsResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestAddArgumentsResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn return_value(
        mut self,
        value: u8,
    ) -> Result<TestAddArgumentsResponseBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestAddArgumentsResponseBuilder(self.0))
    }
}
impl<P> TestAddArgumentsResponseBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestAddArgumentsResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestAddArgumentsResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestAddArgumentsResponseArrayBuilder<P>(P);
impl<P> TestAddArgumentsResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestAddArgumentsResponseBuilder<TestAddArgumentsResponseArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestAddArgumentsResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestAddArgumentsResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestAddArgumentsResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestSimpleArgumentResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> TestSimpleArgumentResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestSimpleArgumentResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn return_value(
        mut self,
        value: bool,
    ) -> Result<TestSimpleArgumentResponseBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestSimpleArgumentResponseBuilder(self.0))
    }
}
impl<P> TestSimpleArgumentResponseBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestSimpleArgumentResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestSimpleArgumentResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestSimpleArgumentResponseArrayBuilder<P>(P);
impl<P> TestSimpleArgumentResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestSimpleArgumentResponseBuilder<TestSimpleArgumentResponseArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestSimpleArgumentResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestSimpleArgumentResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestSimpleArgumentResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestStructArrayArgumentResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> TestStructArrayArgumentResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestStructArrayArgumentResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        NestedStructListArrayBuilder<TestStructArrayArgumentResponseBuilder<P, 1usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArrayArgumentResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> TestStructArrayArgumentResponseBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_2(
        self,
    ) -> Result<
        SimpleStructArrayBuilder<TestStructArrayArgumentResponseBuilder<P, 2usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArrayArgumentResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(1),
        )
    }
}
impl<P> TestStructArrayArgumentResponseBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_3(
        self,
    ) -> Result<
        rs_matter_crate::tlv::ToTLVArrayBuilder<
            TestStructArrayArgumentResponseBuilder<P, 3usize>,
            SimpleEnum,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArrayArgumentResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(2),
        )
    }
}
impl<P> TestStructArrayArgumentResponseBuilder<P, 3>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_4(
        self,
    ) -> Result<
        rs_matter_crate::tlv::ToTLVArrayBuilder<
            TestStructArrayArgumentResponseBuilder<P, 4usize>,
            bool,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArrayArgumentResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(3),
        )
    }
}
impl<P> TestStructArrayArgumentResponseBuilder<P, 4>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_5(
        mut self,
        value: SimpleEnum,
    ) -> Result<TestStructArrayArgumentResponseBuilder<P, 5usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(4),
            self.0.writer(),
        )?;
        Ok(TestStructArrayArgumentResponseBuilder(self.0))
    }
}
impl<P> TestStructArrayArgumentResponseBuilder<P, 5>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_6(
        mut self,
        value: bool,
    ) -> Result<TestStructArrayArgumentResponseBuilder<P, 6usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(5),
            self.0.writer(),
        )?;
        Ok(TestStructArrayArgumentResponseBuilder(self.0))
    }
}
impl<P> TestStructArrayArgumentResponseBuilder<P, 6usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestStructArrayArgumentResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestStructArrayArgumentResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestStructArrayArgumentResponseArrayBuilder<P>(P);
impl<P> TestStructArrayArgumentResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestStructArrayArgumentResponseBuilder<TestStructArrayArgumentResponseArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArrayArgumentResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestStructArrayArgumentResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestStructArrayArgumentResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestAddArgumentsRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestAddArgumentsRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestAddArgumentsRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        mut self,
        value: u8,
    ) -> Result<TestAddArgumentsRequestBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestAddArgumentsRequestBuilder(self.0))
    }
}
impl<P> TestAddArgumentsRequestBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_2(
        mut self,
        value: u8,
    ) -> Result<TestAddArgumentsRequestBuilder<P, 2usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(TestAddArgumentsRequestBuilder(self.0))
    }
}
impl<P> TestAddArgumentsRequestBuilder<P, 2usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestAddArgumentsRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestAddArgumentsRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestAddArgumentsRequestArrayBuilder<P>(P);
impl<P> TestAddArgumentsRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestAddArgumentsRequestBuilder<TestAddArgumentsRequestArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestAddArgumentsRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestAddArgumentsRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestAddArgumentsRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListInt8UReverseResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> TestListInt8UReverseResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestListInt8UReverseResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        rs_matter_crate::tlv::ToTLVArrayBuilder<TestListInt8UReverseResponseBuilder<P, 1usize>, u8>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestListInt8UReverseResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> TestListInt8UReverseResponseBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestListInt8UReverseResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestListInt8UReverseResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListInt8UReverseResponseArrayBuilder<P>(P);
impl<P> TestListInt8UReverseResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestListInt8UReverseResponseBuilder<TestListInt8UReverseResponseArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestListInt8UReverseResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestListInt8UReverseResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestListInt8UReverseResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestSimpleArgumentRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestSimpleArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestSimpleArgumentRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        mut self,
        value: bool,
    ) -> Result<TestSimpleArgumentRequestRequestBuilder<P, 1usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestSimpleArgumentRequestRequestBuilder(self.0))
    }
}
impl<P> TestSimpleArgumentRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestSimpleArgumentRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestSimpleArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestSimpleArgumentRequestRequestArrayBuilder<P>(P);
impl<P> TestSimpleArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestSimpleArgumentRequestRequestBuilder<TestSimpleArgumentRequestRequestArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestSimpleArgumentRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestSimpleArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestSimpleArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEnumsResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> TestEnumsResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestEnumsResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        mut self,
        value: u16,
    ) -> Result<TestEnumsResponseBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestEnumsResponseBuilder(self.0))
    }
}
impl<P> TestEnumsResponseBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_2(
        mut self,
        value: SimpleEnum,
    ) -> Result<TestEnumsResponseBuilder<P, 2usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(TestEnumsResponseBuilder(self.0))
    }
}
impl<P> TestEnumsResponseBuilder<P, 2usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for TestEnumsResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestEnumsResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEnumsResponseArrayBuilder<P>(P);
impl<P> TestEnumsResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestEnumsResponseBuilder<TestEnumsResponseArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestEnumsResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestEnumsResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestEnumsResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestStructArrayArgumentRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestStructArrayArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestStructArrayArgumentRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        NestedStructListArrayBuilder<TestStructArrayArgumentRequestRequestBuilder<P, 1usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArrayArgumentRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> TestStructArrayArgumentRequestRequestBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_2(
        self,
    ) -> Result<
        SimpleStructArrayBuilder<TestStructArrayArgumentRequestRequestBuilder<P, 2usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArrayArgumentRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(1),
        )
    }
}
impl<P> TestStructArrayArgumentRequestRequestBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_3(
        self,
    ) -> Result<
        rs_matter_crate::tlv::ToTLVArrayBuilder<
            TestStructArrayArgumentRequestRequestBuilder<P, 3usize>,
            SimpleEnum,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArrayArgumentRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(2),
        )
    }
}
impl<P> TestStructArrayArgumentRequestRequestBuilder<P, 3>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_4(
        self,
    ) -> Result<
        rs_matter_crate::tlv::ToTLVArrayBuilder<
            TestStructArrayArgumentRequestRequestBuilder<P, 4usize>,
            bool,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArrayArgumentRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(3),
        )
    }
}
impl<P> TestStructArrayArgumentRequestRequestBuilder<P, 4>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_5(
        mut self,
        value: SimpleEnum,
    ) -> Result<
        TestStructArrayArgumentRequestRequestBuilder<P, 5usize>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(4),
            self.0.writer(),
        )?;
        Ok(TestStructArrayArgumentRequestRequestBuilder(self.0))
    }
}
impl<P> TestStructArrayArgumentRequestRequestBuilder<P, 5>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_6(
        mut self,
        value: bool,
    ) -> Result<
        TestStructArrayArgumentRequestRequestBuilder<P, 6usize>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(5),
            self.0.writer(),
        )?;
        Ok(TestStructArrayArgumentRequestRequestBuilder(self.0))
    }
}
impl<P> TestStructArrayArgumentRequestRequestBuilder<P, 6usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestStructArrayArgumentRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestStructArrayArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestStructArrayArgumentRequestRequestArrayBuilder<P>(P);
impl<P> TestStructArrayArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestStructArrayArgumentRequestRequestBuilder<
            TestStructArrayArgumentRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArrayArgumentRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestStructArrayArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestStructArrayArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestNullableOptionalResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> TestNullableOptionalResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestNullableOptionalResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn was_present(
        mut self,
        value: bool,
    ) -> Result<TestNullableOptionalResponseBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestNullableOptionalResponseBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn was_null(
        mut self,
        value: Option<bool>,
    ) -> Result<TestNullableOptionalResponseBuilder<P, 2usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(TestNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestNullableOptionalResponseBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn value(
        mut self,
        value: Option<u8>,
    ) -> Result<TestNullableOptionalResponseBuilder<P, 3usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(2),
            self.0.writer(),
        )?;
        Ok(TestNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestNullableOptionalResponseBuilder<P, 3>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn original_value(
        mut self,
        value: Option<rs_matter_crate::tlv::Nullable<u8>>,
    ) -> Result<TestNullableOptionalResponseBuilder<P, 4usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(3),
            self.0.writer(),
        )?;
        Ok(TestNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestNullableOptionalResponseBuilder<P, 4usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestNullableOptionalResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestNullableOptionalResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestNullableOptionalResponseArrayBuilder<P>(P);
impl<P> TestNullableOptionalResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestNullableOptionalResponseBuilder<TestNullableOptionalResponseArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestNullableOptionalResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestNullableOptionalResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestNullableOptionalResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestStructArgumentRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestStructArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestStructArgumentRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        SimpleStructBuilder<TestStructArgumentRequestRequestBuilder<P, 1usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArgumentRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> TestStructArgumentRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestStructArgumentRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestStructArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestStructArgumentRequestRequestArrayBuilder<P>(P);
impl<P> TestStructArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestStructArgumentRequestRequestBuilder<TestStructArgumentRequestRequestArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestStructArgumentRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestStructArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestStructArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestComplexNullableOptionalResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> TestComplexNullableOptionalResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_int_was_null(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 1usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_int_value(
        mut self,
        value: Option<u16>,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 2usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_int_was_present(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 3usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(2),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 3>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_int_value(
        mut self,
        value: Option<u16>,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 4usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(3),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 4>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_int_was_present(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 5usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(4),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 5>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_int_was_null(
        mut self,
        value: Option<bool>,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 6usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(5),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 6>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_int_value(
        mut self,
        value: Option<u16>,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 7usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(6),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 7>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_string_was_null(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 8usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(7),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 8>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_string_value(
        mut self,
        value: Option<rs_matter_crate::tlv::Utf8Str<'_>>,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 9usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(8),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 9>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_string_was_present(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 10usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(9),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 10>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_string_value(
        mut self,
        value: Option<rs_matter_crate::tlv::Utf8Str<'_>>,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 11usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(10),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 11>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_string_was_present(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 12usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(11),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 12>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_string_was_null(
        mut self,
        value: Option<bool>,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 13usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(12),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 13>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_string_value(
        mut self,
        value: Option<rs_matter_crate::tlv::Utf8Str<'_>>,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 14usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(13),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 14>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_struct_was_null(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 15usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(14),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 15>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_struct_value(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            TestComplexNullableOptionalResponseBuilder<P, 16usize>,
            SimpleStructBuilder<TestComplexNullableOptionalResponseBuilder<P, 16usize>>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(15),
        )
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 16>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_struct_was_present(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 17usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(16),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 17>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_struct_value(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            TestComplexNullableOptionalResponseBuilder<P, 18usize>,
            SimpleStructBuilder<TestComplexNullableOptionalResponseBuilder<P, 18usize>>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(17),
        )
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 18>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_struct_was_present(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 19usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(18),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 19>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_struct_was_null(
        mut self,
        value: Option<bool>,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 20usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(19),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 20>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_struct_value(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            TestComplexNullableOptionalResponseBuilder<P, 21usize>,
            SimpleStructBuilder<TestComplexNullableOptionalResponseBuilder<P, 21usize>>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(20),
        )
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 21>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_list_was_null(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 22usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(21),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 22>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_list_value(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            TestComplexNullableOptionalResponseBuilder<P, 23usize>,
            rs_matter_crate::tlv::ToTLVArrayBuilder<
                TestComplexNullableOptionalResponseBuilder<P, 23usize>,
                SimpleEnum,
            >,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(22),
        )
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 23>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_list_was_present(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 24usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(23),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 24>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_list_value(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            TestComplexNullableOptionalResponseBuilder<P, 25usize>,
            rs_matter_crate::tlv::ToTLVArrayBuilder<
                TestComplexNullableOptionalResponseBuilder<P, 25usize>,
                SimpleEnum,
            >,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(24),
        )
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 25>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_list_was_present(
        mut self,
        value: bool,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 26usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(25),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 26>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_list_was_null(
        mut self,
        value: Option<bool>,
    ) -> Result<TestComplexNullableOptionalResponseBuilder<P, 27usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(26),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalResponseBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 27>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_list_value(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            TestComplexNullableOptionalResponseBuilder<P, 28usize>,
            rs_matter_crate::tlv::ToTLVArrayBuilder<
                TestComplexNullableOptionalResponseBuilder<P, 28usize>,
                SimpleEnum,
            >,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(27),
        )
    }
}
impl<P> TestComplexNullableOptionalResponseBuilder<P, 28usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestComplexNullableOptionalResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestComplexNullableOptionalResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestComplexNullableOptionalResponseArrayBuilder<P>(P);
impl<P> TestComplexNullableOptionalResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestComplexNullableOptionalResponseBuilder<
            TestComplexNullableOptionalResponseArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestComplexNullableOptionalResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestComplexNullableOptionalResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestNestedStructArgumentRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestNestedStructArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestNestedStructArgumentRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        NestedStructBuilder<TestNestedStructArgumentRequestRequestBuilder<P, 1usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestNestedStructArgumentRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> TestNestedStructArgumentRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestNestedStructArgumentRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestNestedStructArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestNestedStructArgumentRequestRequestArrayBuilder<P>(P);
impl<P> TestNestedStructArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestNestedStructArgumentRequestRequestBuilder<
            TestNestedStructArgumentRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestNestedStructArgumentRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestNestedStructArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P>
    for TestNestedStructArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct BooleanResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> BooleanResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> BooleanResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn value(
        mut self,
        value: bool,
    ) -> Result<BooleanResponseBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(BooleanResponseBuilder(self.0))
    }
}
impl<P> BooleanResponseBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for BooleanResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for BooleanResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct BooleanResponseArrayBuilder<P>(P);
impl<P> BooleanResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<BooleanResponseBuilder<BooleanResponseArrayBuilder<P>>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::TLVBuilder::new(
            BooleanResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for BooleanResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for BooleanResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListStructArgumentRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestListStructArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestListStructArgumentRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        SimpleStructArrayBuilder<TestListStructArgumentRequestRequestBuilder<P, 1usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestListStructArgumentRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> TestListStructArgumentRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestListStructArgumentRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestListStructArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListStructArgumentRequestRequestArrayBuilder<P>(P);
impl<P> TestListStructArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestListStructArgumentRequestRequestBuilder<
            TestListStructArgumentRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestListStructArgumentRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestListStructArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestListStructArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct SimpleStructResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> SimpleStructResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> SimpleStructResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        SimpleStructBuilder<SimpleStructResponseBuilder<P, 1usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            SimpleStructResponseBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> SimpleStructResponseBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent for SimpleStructResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for SimpleStructResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct SimpleStructResponseArrayBuilder<P>(P);
impl<P> SimpleStructResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        SimpleStructResponseBuilder<SimpleStructResponseArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            SimpleStructResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for SimpleStructResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for SimpleStructResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListInt8UArgumentRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestListInt8UArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestListInt8UArgumentRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        rs_matter_crate::tlv::ToTLVArrayBuilder<
            TestListInt8UArgumentRequestRequestBuilder<P, 1usize>,
            u8,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestListInt8UArgumentRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> TestListInt8UArgumentRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestListInt8UArgumentRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestListInt8UArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListInt8UArgumentRequestRequestArrayBuilder<P>(P);
impl<P> TestListInt8UArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestListInt8UArgumentRequestRequestBuilder<
            TestListInt8UArgumentRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestListInt8UArgumentRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestListInt8UArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestListInt8UArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEmitTestEventResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> TestEmitTestEventResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestEmitTestEventResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn value(
        mut self,
        value: u64,
    ) -> Result<TestEmitTestEventResponseBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestEmitTestEventResponseBuilder(self.0))
    }
}
impl<P> TestEmitTestEventResponseBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestEmitTestEventResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestEmitTestEventResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEmitTestEventResponseArrayBuilder<P>(P);
impl<P> TestEmitTestEventResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestEmitTestEventResponseBuilder<TestEmitTestEventResponseArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestEmitTestEventResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestEmitTestEventResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestEmitTestEventResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestNestedStructListArgumentRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestNestedStructListArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestNestedStructListArgumentRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        NestedStructListBuilder<TestNestedStructListArgumentRequestRequestBuilder<P, 1usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestNestedStructListArgumentRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> TestNestedStructListArgumentRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestNestedStructListArgumentRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestNestedStructListArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestNestedStructListArgumentRequestRequestArrayBuilder<P>(P);
impl<P> TestNestedStructListArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestNestedStructListArgumentRequestRequestBuilder<
            TestNestedStructListArgumentRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestNestedStructListArgumentRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestNestedStructListArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P>
    for TestNestedStructListArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEmitTestFabricScopedEventResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> TestEmitTestFabricScopedEventResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestEmitTestFabricScopedEventResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn value(
        mut self,
        value: u64,
    ) -> Result<
        TestEmitTestFabricScopedEventResponseBuilder<P, 1usize>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestEmitTestFabricScopedEventResponseBuilder(self.0))
    }
}
impl<P> TestEmitTestFabricScopedEventResponseBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestEmitTestFabricScopedEventResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestEmitTestFabricScopedEventResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEmitTestFabricScopedEventResponseArrayBuilder<P>(P);
impl<P> TestEmitTestFabricScopedEventResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestEmitTestFabricScopedEventResponseBuilder<
            TestEmitTestFabricScopedEventResponseArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestEmitTestFabricScopedEventResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestEmitTestFabricScopedEventResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestEmitTestFabricScopedEventResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListNestedStructListArgumentRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestListNestedStructListArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestListNestedStructListArgumentRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        NestedStructListArrayBuilder<
            TestListNestedStructListArgumentRequestRequestBuilder<P, 1usize>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestListNestedStructListArgumentRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> TestListNestedStructListArgumentRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestListNestedStructListArgumentRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P>
    for TestListNestedStructListArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListNestedStructListArgumentRequestRequestArrayBuilder<P>(P);
impl<P> TestListNestedStructListArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestListNestedStructListArgumentRequestRequestBuilder<
            TestListNestedStructListArgumentRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestListNestedStructListArgumentRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestListNestedStructListArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P>
    for TestListNestedStructListArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestBatchHelperResponseBuilder<P, const F: usize = 0usize>(P);
impl<P> TestBatchHelperResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestBatchHelperResponseBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn buffer(
        mut self,
        value: rs_matter_crate::tlv::OctetStr<'_>,
    ) -> Result<TestBatchHelperResponseBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestBatchHelperResponseBuilder(self.0))
    }
}
impl<P> TestBatchHelperResponseBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestBatchHelperResponseBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestBatchHelperResponseBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestBatchHelperResponseArrayBuilder<P>(P);
impl<P> TestBatchHelperResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestBatchHelperResponseBuilder<TestBatchHelperResponseArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestBatchHelperResponseArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestBatchHelperResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestBatchHelperResponseArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListInt8UReverseRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestListInt8UReverseRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestListInt8UReverseRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        rs_matter_crate::tlv::ToTLVArrayBuilder<
            TestListInt8UReverseRequestRequestBuilder<P, 1usize>,
            u8,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestListInt8UReverseRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> TestListInt8UReverseRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestListInt8UReverseRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestListInt8UReverseRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestListInt8UReverseRequestRequestArrayBuilder<P>(P);
impl<P> TestListInt8UReverseRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestListInt8UReverseRequestRequestBuilder<
            TestListInt8UReverseRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestListInt8UReverseRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestListInt8UReverseRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestListInt8UReverseRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEnumsRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestEnumsRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestEnumsRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        mut self,
        value: u16,
    ) -> Result<TestEnumsRequestRequestBuilder<P, 1usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestEnumsRequestRequestBuilder(self.0))
    }
}
impl<P> TestEnumsRequestRequestBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_2(
        mut self,
        value: SimpleEnum,
    ) -> Result<TestEnumsRequestRequestBuilder<P, 2usize>, rs_matter_crate::error::Error> {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(TestEnumsRequestRequestBuilder(self.0))
    }
}
impl<P> TestEnumsRequestRequestBuilder<P, 2usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestEnumsRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestEnumsRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEnumsRequestRequestArrayBuilder<P>(P);
impl<P> TestEnumsRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestEnumsRequestRequestBuilder<TestEnumsRequestRequestArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestEnumsRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestEnumsRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestEnumsRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestNullableOptionalRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestNullableOptionalRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestNullableOptionalRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        mut self,
        value: Option<rs_matter_crate::tlv::Nullable<u8>>,
    ) -> Result<TestNullableOptionalRequestRequestBuilder<P, 1usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestNullableOptionalRequestRequestBuilder(self.0))
    }
}
impl<P> TestNullableOptionalRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestNullableOptionalRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestNullableOptionalRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestNullableOptionalRequestRequestArrayBuilder<P>(P);
impl<P> TestNullableOptionalRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestNullableOptionalRequestRequestBuilder<
            TestNullableOptionalRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestNullableOptionalRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestNullableOptionalRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestNullableOptionalRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestComplexNullableOptionalRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_int(
        mut self,
        value: rs_matter_crate::tlv::Nullable<u16>,
    ) -> Result<
        TestComplexNullableOptionalRequestRequestBuilder<P, 1usize>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalRequestRequestBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_int(
        mut self,
        value: Option<u16>,
    ) -> Result<
        TestComplexNullableOptionalRequestRequestBuilder<P, 2usize>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalRequestRequestBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_int(
        mut self,
        value: Option<rs_matter_crate::tlv::Nullable<u16>>,
    ) -> Result<
        TestComplexNullableOptionalRequestRequestBuilder<P, 3usize>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(2),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalRequestRequestBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 3>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_string(
        mut self,
        value: rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>,
    ) -> Result<
        TestComplexNullableOptionalRequestRequestBuilder<P, 4usize>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(3),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalRequestRequestBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 4>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_string(
        mut self,
        value: Option<rs_matter_crate::tlv::Utf8Str<'_>>,
    ) -> Result<
        TestComplexNullableOptionalRequestRequestBuilder<P, 5usize>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(4),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalRequestRequestBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 5>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_string(
        mut self,
        value: Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>>,
    ) -> Result<
        TestComplexNullableOptionalRequestRequestBuilder<P, 6usize>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(5),
            self.0.writer(),
        )?;
        Ok(TestComplexNullableOptionalRequestRequestBuilder(self.0))
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 6>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_struct(
        self,
    ) -> Result<
        rs_matter_crate::tlv::NullableBuilder<
            TestComplexNullableOptionalRequestRequestBuilder<P, 7usize>,
            SimpleStructBuilder<TestComplexNullableOptionalRequestRequestBuilder<P, 7usize>>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(6),
        )
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 7>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_struct(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            TestComplexNullableOptionalRequestRequestBuilder<P, 8usize>,
            SimpleStructBuilder<TestComplexNullableOptionalRequestRequestBuilder<P, 8usize>>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(7),
        )
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 8>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_struct(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            TestComplexNullableOptionalRequestRequestBuilder<P, 9usize>,
            rs_matter_crate::tlv::NullableBuilder<
                TestComplexNullableOptionalRequestRequestBuilder<P, 9usize>,
                SimpleStructBuilder<TestComplexNullableOptionalRequestRequestBuilder<P, 9usize>>,
            >,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(8),
        )
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 9>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_list(
        self,
    ) -> Result<
        rs_matter_crate::tlv::NullableBuilder<
            TestComplexNullableOptionalRequestRequestBuilder<P, 10usize>,
            rs_matter_crate::tlv::ToTLVArrayBuilder<
                TestComplexNullableOptionalRequestRequestBuilder<P, 10usize>,
                SimpleEnum,
            >,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(9),
        )
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 10>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn optional_list(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            TestComplexNullableOptionalRequestRequestBuilder<P, 11usize>,
            rs_matter_crate::tlv::ToTLVArrayBuilder<
                TestComplexNullableOptionalRequestRequestBuilder<P, 11usize>,
                SimpleEnum,
            >,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(10),
        )
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 11>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn nullable_optional_list(
        self,
    ) -> Result<
        rs_matter_crate::tlv::OptionalBuilder<
            TestComplexNullableOptionalRequestRequestBuilder<P, 12usize>,
            rs_matter_crate::tlv::NullableBuilder<
                TestComplexNullableOptionalRequestRequestBuilder<P, 12usize>,
                rs_matter_crate::tlv::ToTLVArrayBuilder<
                    TestComplexNullableOptionalRequestRequestBuilder<P, 12usize>,
                    SimpleEnum,
                >,
            >,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(11),
        )
    }
}
impl<P> TestComplexNullableOptionalRequestRequestBuilder<P, 12usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestComplexNullableOptionalRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestComplexNullableOptionalRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestComplexNullableOptionalRequestRequestArrayBuilder<P>(P);
impl<P> TestComplexNullableOptionalRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestComplexNullableOptionalRequestRequestBuilder<
            TestComplexNullableOptionalRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestComplexNullableOptionalRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestComplexNullableOptionalRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P>
    for TestComplexNullableOptionalRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct SimpleStructEchoRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> SimpleStructEchoRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> SimpleStructEchoRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        self,
    ) -> Result<
        SimpleStructBuilder<SimpleStructEchoRequestRequestBuilder<P, 1usize>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            SimpleStructEchoRequestRequestBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Context(0),
        )
    }
}
impl<P> SimpleStructEchoRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for SimpleStructEchoRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for SimpleStructEchoRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct SimpleStructEchoRequestRequestArrayBuilder<P>(P);
impl<P> SimpleStructEchoRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        SimpleStructEchoRequestRequestBuilder<SimpleStructEchoRequestRequestArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            SimpleStructEchoRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for SimpleStructEchoRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for SimpleStructEchoRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestSimpleOptionalArgumentRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestSimpleOptionalArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestSimpleOptionalArgumentRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        mut self,
        value: Option<bool>,
    ) -> Result<
        TestSimpleOptionalArgumentRequestRequestBuilder<P, 1usize>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestSimpleOptionalArgumentRequestRequestBuilder(self.0))
    }
}
impl<P> TestSimpleOptionalArgumentRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestSimpleOptionalArgumentRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestSimpleOptionalArgumentRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestSimpleOptionalArgumentRequestRequestArrayBuilder<P>(P);
impl<P> TestSimpleOptionalArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestSimpleOptionalArgumentRequestRequestBuilder<
            TestSimpleOptionalArgumentRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestSimpleOptionalArgumentRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestSimpleOptionalArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P>
    for TestSimpleOptionalArgumentRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEmitTestEventRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestEmitTestEventRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestEmitTestEventRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        mut self,
        value: u8,
    ) -> Result<TestEmitTestEventRequestRequestBuilder<P, 1usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestEmitTestEventRequestRequestBuilder(self.0))
    }
}
impl<P> TestEmitTestEventRequestRequestBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_2(
        mut self,
        value: SimpleEnum,
    ) -> Result<TestEmitTestEventRequestRequestBuilder<P, 2usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(TestEmitTestEventRequestRequestBuilder(self.0))
    }
}
impl<P> TestEmitTestEventRequestRequestBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_3(
        mut self,
        value: bool,
    ) -> Result<TestEmitTestEventRequestRequestBuilder<P, 3usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(2),
            self.0.writer(),
        )?;
        Ok(TestEmitTestEventRequestRequestBuilder(self.0))
    }
}
impl<P> TestEmitTestEventRequestRequestBuilder<P, 3usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestEmitTestEventRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestEmitTestEventRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEmitTestEventRequestRequestArrayBuilder<P>(P);
impl<P> TestEmitTestEventRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestEmitTestEventRequestRequestBuilder<TestEmitTestEventRequestRequestArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestEmitTestEventRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestEmitTestEventRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestEmitTestEventRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEmitTestFabricScopedEventRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestEmitTestFabricScopedEventRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestEmitTestFabricScopedEventRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn arg_1(
        mut self,
        value: u8,
    ) -> Result<
        TestEmitTestFabricScopedEventRequestRequestBuilder<P, 1usize>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestEmitTestFabricScopedEventRequestRequestBuilder(self.0))
    }
}
impl<P> TestEmitTestFabricScopedEventRequestRequestBuilder<P, 1usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestEmitTestFabricScopedEventRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P>
    for TestEmitTestFabricScopedEventRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestEmitTestFabricScopedEventRequestRequestArrayBuilder<P>(P);
impl<P> TestEmitTestFabricScopedEventRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestEmitTestFabricScopedEventRequestRequestBuilder<
            TestEmitTestFabricScopedEventRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestEmitTestFabricScopedEventRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestEmitTestFabricScopedEventRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P>
    for TestEmitTestFabricScopedEventRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestBatchHelperRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestBatchHelperRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestBatchHelperRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn sleep_before_response_time_ms(
        mut self,
        value: u16,
    ) -> Result<TestBatchHelperRequestRequestBuilder<P, 1usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestBatchHelperRequestRequestBuilder(self.0))
    }
}
impl<P> TestBatchHelperRequestRequestBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn size_of_response_buffer(
        mut self,
        value: u16,
    ) -> Result<TestBatchHelperRequestRequestBuilder<P, 2usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(TestBatchHelperRequestRequestBuilder(self.0))
    }
}
impl<P> TestBatchHelperRequestRequestBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn fill_character(
        mut self,
        value: u8,
    ) -> Result<TestBatchHelperRequestRequestBuilder<P, 3usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(2),
            self.0.writer(),
        )?;
        Ok(TestBatchHelperRequestRequestBuilder(self.0))
    }
}
impl<P> TestBatchHelperRequestRequestBuilder<P, 3usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestBatchHelperRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestBatchHelperRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestBatchHelperRequestRequestArrayBuilder<P>(P);
impl<P> TestBatchHelperRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestBatchHelperRequestRequestBuilder<TestBatchHelperRequestRequestArrayBuilder<P>>,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestBatchHelperRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent for TestBatchHelperRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestBatchHelperRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestSecondBatchHelperRequestRequestBuilder<P, const F: usize = 0usize>(P);
impl<P> TestSecondBatchHelperRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_struct(tag)?;
        Ok(Self(parent))
    }
}
impl<P> TestSecondBatchHelperRequestRequestBuilder<P, 0>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn sleep_before_response_time_ms(
        mut self,
        value: u16,
    ) -> Result<TestSecondBatchHelperRequestRequestBuilder<P, 1usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(0),
            self.0.writer(),
        )?;
        Ok(TestSecondBatchHelperRequestRequestBuilder(self.0))
    }
}
impl<P> TestSecondBatchHelperRequestRequestBuilder<P, 1>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn size_of_response_buffer(
        mut self,
        value: u16,
    ) -> Result<TestSecondBatchHelperRequestRequestBuilder<P, 2usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(1),
            self.0.writer(),
        )?;
        Ok(TestSecondBatchHelperRequestRequestBuilder(self.0))
    }
}
impl<P> TestSecondBatchHelperRequestRequestBuilder<P, 2>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    pub fn fill_character(
        mut self,
        value: u8,
    ) -> Result<TestSecondBatchHelperRequestRequestBuilder<P, 3usize>, rs_matter_crate::error::Error>
    {
        rs_matter_crate::tlv::ToTLV::to_tlv(
            &value,
            &rs_matter_crate::tlv::TLVTag::Context(2),
            self.0.writer(),
        )?;
        Ok(TestSecondBatchHelperRequestRequestBuilder(self.0))
    }
}
impl<P> TestSecondBatchHelperRequestRequestBuilder<P, 3usize>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Finish the struct and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P, const F: usize> rs_matter_crate::tlv::TLVBuilderParent
    for TestSecondBatchHelperRequestRequestBuilder<P, F>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestSecondBatchHelperRequestRequestBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
pub struct TestSecondBatchHelperRequestRequestArrayBuilder<P>(P);
impl<P> TestSecondBatchHelperRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    #[doc = "Create a new instance"]
    pub fn new(
        mut parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        parent.writer().start_array(tag)?;
        Ok(Self(parent))
    }
    #[doc = "Push a new element into the array"]
    pub fn push(
        self,
    ) -> Result<
        TestSecondBatchHelperRequestRequestBuilder<
            TestSecondBatchHelperRequestRequestArrayBuilder<P>,
        >,
        rs_matter_crate::error::Error,
    > {
        rs_matter_crate::tlv::TLVBuilder::new(
            TestSecondBatchHelperRequestRequestArrayBuilder(self.0),
            &rs_matter_crate::tlv::TLVTag::Anonymous,
        )
    }
    #[doc = "Finish the array and return the parent"]
    pub fn end(mut self) -> Result<P, rs_matter_crate::error::Error> {
        use rs_matter_crate::tlv::TLVWrite;
        self.0.writer().end_container()?;
        Ok(self.0)
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilderParent
    for TestSecondBatchHelperRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    type Write = P::Write;
    fn writer(&mut self) -> &mut P::Write {
        self.0.writer()
    }
}
impl<P> rs_matter_crate::tlv::TLVBuilder<P> for TestSecondBatchHelperRequestRequestArrayBuilder<P>
where
    P: rs_matter_crate::tlv::TLVBuilderParent,
{
    fn new(
        parent: P,
        tag: &rs_matter_crate::tlv::TLVTag,
    ) -> Result<Self, rs_matter_crate::error::Error> {
        Self::new(parent, tag)
    }
    fn unchecked_into_parent(self) -> P {
        self.0
    }
}
#[derive(strum :: FromRepr)]
#[repr(u32)]
pub enum AttributeId {
    Boolean = 0,
    Bitmap8 = 1,
    Bitmap16 = 2,
    Bitmap32 = 3,
    Bitmap64 = 4,
    Int8u = 5,
    Int16u = 6,
    Int24u = 7,
    Int32u = 8,
    Int40u = 9,
    Int48u = 10,
    Int56u = 11,
    Int64u = 12,
    Int8s = 13,
    Int16s = 14,
    Int24s = 15,
    Int32s = 16,
    Int40s = 17,
    Int48s = 18,
    Int56s = 19,
    Int64s = 20,
    Enum8 = 21,
    Enum16 = 22,
    FloatSingle = 23,
    FloatDouble = 24,
    OctetString = 25,
    ListInt8u = 26,
    ListOctetString = 27,
    ListStructOctetString = 28,
    LongOctetString = 29,
    CharString = 30,
    LongCharString = 31,
    EpochUs = 32,
    EpochS = 33,
    VendorId = 34,
    ListNullablesAndOptionalsStruct = 35,
    EnumAttr = 36,
    StructAttr = 37,
    RangeRestrictedInt8u = 38,
    RangeRestrictedInt8s = 39,
    RangeRestrictedInt16u = 40,
    RangeRestrictedInt16s = 41,
    ListLongOctetString = 42,
    ListFabricScoped = 43,
    TimedWriteBoolean = 48,
    GeneralErrorBoolean = 49,
    ClusterErrorBoolean = 50,
    Unsupported = 255,
    NullableBoolean = 16384,
    NullableBitmap8 = 16385,
    NullableBitmap16 = 16386,
    NullableBitmap32 = 16387,
    NullableBitmap64 = 16388,
    NullableInt8u = 16389,
    NullableInt16u = 16390,
    NullableInt24u = 16391,
    NullableInt32u = 16392,
    NullableInt40u = 16393,
    NullableInt48u = 16394,
    NullableInt56u = 16395,
    NullableInt64u = 16396,
    NullableInt8s = 16397,
    NullableInt16s = 16398,
    NullableInt24s = 16399,
    NullableInt32s = 16400,
    NullableInt40s = 16401,
    NullableInt48s = 16402,
    NullableInt56s = 16403,
    NullableInt64s = 16404,
    NullableEnum8 = 16405,
    NullableEnum16 = 16406,
    NullableFloatSingle = 16407,
    NullableFloatDouble = 16408,
    NullableOctetString = 16409,
    NullableCharString = 16414,
    NullableEnumAttr = 16420,
    NullableStruct = 16421,
    NullableRangeRestrictedInt8u = 16422,
    NullableRangeRestrictedInt8s = 16423,
    NullableRangeRestrictedInt16u = 16424,
    NullableRangeRestrictedInt16s = 16425,
    WriteOnlyInt8u = 16426,
    GeneratedCommandList = 65528,
    AcceptedCommandList = 65529,
    EventList = 65530,
    AttributeList = 65531,
    FeatureMap = 65532,
    ClusterRevision = 65533,
}
impl AttributeId {
    pub const fn all() -> &'static [u32] {
        static ALL: &[u32] = &[
            AttributeId::Boolean as _,
            AttributeId::Bitmap8 as _,
            AttributeId::Bitmap16 as _,
            AttributeId::Bitmap32 as _,
            AttributeId::Bitmap64 as _,
            AttributeId::Int8u as _,
            AttributeId::Int16u as _,
            AttributeId::Int24u as _,
            AttributeId::Int32u as _,
            AttributeId::Int40u as _,
            AttributeId::Int48u as _,
            AttributeId::Int56u as _,
            AttributeId::Int64u as _,
            AttributeId::Int8s as _,
            AttributeId::Int16s as _,
            AttributeId::Int24s as _,
            AttributeId::Int32s as _,
            AttributeId::Int40s as _,
            AttributeId::Int48s as _,
            AttributeId::Int56s as _,
            AttributeId::Int64s as _,
            AttributeId::Enum8 as _,
            AttributeId::Enum16 as _,
            AttributeId::FloatSingle as _,
            AttributeId::FloatDouble as _,
            AttributeId::OctetString as _,
            AttributeId::ListInt8u as _,
            AttributeId::ListOctetString as _,
            AttributeId::ListStructOctetString as _,
            AttributeId::LongOctetString as _,
            AttributeId::CharString as _,
            AttributeId::LongCharString as _,
            AttributeId::EpochUs as _,
            AttributeId::EpochS as _,
            AttributeId::VendorId as _,
            AttributeId::ListNullablesAndOptionalsStruct as _,
            AttributeId::EnumAttr as _,
            AttributeId::StructAttr as _,
            AttributeId::RangeRestrictedInt8u as _,
            AttributeId::RangeRestrictedInt8s as _,
            AttributeId::RangeRestrictedInt16u as _,
            AttributeId::RangeRestrictedInt16s as _,
            AttributeId::ListLongOctetString as _,
            AttributeId::ListFabricScoped as _,
            AttributeId::TimedWriteBoolean as _,
            AttributeId::GeneralErrorBoolean as _,
            AttributeId::ClusterErrorBoolean as _,
            AttributeId::Unsupported as _,
            AttributeId::NullableBoolean as _,
            AttributeId::NullableBitmap8 as _,
            AttributeId::NullableBitmap16 as _,
            AttributeId::NullableBitmap32 as _,
            AttributeId::NullableBitmap64 as _,
            AttributeId::NullableInt8u as _,
            AttributeId::NullableInt16u as _,
            AttributeId::NullableInt24u as _,
            AttributeId::NullableInt32u as _,
            AttributeId::NullableInt40u as _,
            AttributeId::NullableInt48u as _,
            AttributeId::NullableInt56u as _,
            AttributeId::NullableInt64u as _,
            AttributeId::NullableInt8s as _,
            AttributeId::NullableInt16s as _,
            AttributeId::NullableInt24s as _,
            AttributeId::NullableInt32s as _,
            AttributeId::NullableInt40s as _,
            AttributeId::NullableInt48s as _,
            AttributeId::NullableInt56s as _,
            AttributeId::NullableInt64s as _,
            AttributeId::NullableEnum8 as _,
            AttributeId::NullableEnum16 as _,
            AttributeId::NullableFloatSingle as _,
            AttributeId::NullableFloatDouble as _,
            AttributeId::NullableOctetString as _,
            AttributeId::NullableCharString as _,
            AttributeId::NullableEnumAttr as _,
            AttributeId::NullableStruct as _,
            AttributeId::NullableRangeRestrictedInt8u as _,
            AttributeId::NullableRangeRestrictedInt8s as _,
            AttributeId::NullableRangeRestrictedInt16u as _,
            AttributeId::NullableRangeRestrictedInt16s as _,
            AttributeId::WriteOnlyInt8u as _,
            AttributeId::GeneratedCommandList as _,
            AttributeId::AcceptedCommandList as _,
            AttributeId::EventList as _,
            AttributeId::AttributeList as _,
            AttributeId::FeatureMap as _,
            AttributeId::ClusterRevision as _,
        ];
        ALL
    }
    pub const fn mandatory() -> &'static [u32] {
        static MANDATORY: &[u32] = &[
            AttributeId::Boolean as _,
            AttributeId::Bitmap8 as _,
            AttributeId::Bitmap16 as _,
            AttributeId::Bitmap32 as _,
            AttributeId::Bitmap64 as _,
            AttributeId::Int8u as _,
            AttributeId::Int16u as _,
            AttributeId::Int24u as _,
            AttributeId::Int32u as _,
            AttributeId::Int40u as _,
            AttributeId::Int48u as _,
            AttributeId::Int56u as _,
            AttributeId::Int64u as _,
            AttributeId::Int8s as _,
            AttributeId::Int16s as _,
            AttributeId::Int24s as _,
            AttributeId::Int32s as _,
            AttributeId::Int40s as _,
            AttributeId::Int48s as _,
            AttributeId::Int56s as _,
            AttributeId::Int64s as _,
            AttributeId::Enum8 as _,
            AttributeId::Enum16 as _,
            AttributeId::FloatSingle as _,
            AttributeId::FloatDouble as _,
            AttributeId::OctetString as _,
            AttributeId::ListInt8u as _,
            AttributeId::ListOctetString as _,
            AttributeId::ListStructOctetString as _,
            AttributeId::LongOctetString as _,
            AttributeId::CharString as _,
            AttributeId::LongCharString as _,
            AttributeId::EpochUs as _,
            AttributeId::EpochS as _,
            AttributeId::VendorId as _,
            AttributeId::ListNullablesAndOptionalsStruct as _,
            AttributeId::EnumAttr as _,
            AttributeId::StructAttr as _,
            AttributeId::RangeRestrictedInt8u as _,
            AttributeId::RangeRestrictedInt8s as _,
            AttributeId::RangeRestrictedInt16u as _,
            AttributeId::RangeRestrictedInt16s as _,
            AttributeId::ListLongOctetString as _,
            AttributeId::ListFabricScoped as _,
            AttributeId::TimedWriteBoolean as _,
            AttributeId::GeneralErrorBoolean as _,
            AttributeId::ClusterErrorBoolean as _,
            AttributeId::NullableBoolean as _,
            AttributeId::NullableBitmap8 as _,
            AttributeId::NullableBitmap16 as _,
            AttributeId::NullableBitmap32 as _,
            AttributeId::NullableBitmap64 as _,
            AttributeId::NullableInt8u as _,
            AttributeId::NullableInt16u as _,
            AttributeId::NullableInt24u as _,
            AttributeId::NullableInt32u as _,
            AttributeId::NullableInt40u as _,
            AttributeId::NullableInt48u as _,
            AttributeId::NullableInt56u as _,
            AttributeId::NullableInt64u as _,
            AttributeId::NullableInt8s as _,
            AttributeId::NullableInt16s as _,
            AttributeId::NullableInt24s as _,
            AttributeId::NullableInt32s as _,
            AttributeId::NullableInt40s as _,
            AttributeId::NullableInt48s as _,
            AttributeId::NullableInt56s as _,
            AttributeId::NullableInt64s as _,
            AttributeId::NullableEnum8 as _,
            AttributeId::NullableEnum16 as _,
            AttributeId::NullableFloatSingle as _,
            AttributeId::NullableFloatDouble as _,
            AttributeId::NullableOctetString as _,
            AttributeId::NullableCharString as _,
            AttributeId::NullableEnumAttr as _,
            AttributeId::NullableStruct as _,
            AttributeId::NullableRangeRestrictedInt8u as _,
            AttributeId::NullableRangeRestrictedInt8s as _,
            AttributeId::NullableRangeRestrictedInt16u as _,
            AttributeId::NullableRangeRestrictedInt16s as _,
            AttributeId::GeneratedCommandList as _,
            AttributeId::AcceptedCommandList as _,
            AttributeId::EventList as _,
            AttributeId::AttributeList as _,
            AttributeId::FeatureMap as _,
            AttributeId::ClusterRevision as _,
        ];
        MANDATORY
    }
    pub const fn global() -> &'static [u32] {
        static GLOBAL: &[u32] = &[
            AttributeId::GeneratedCommandList as _,
            AttributeId::AcceptedCommandList as _,
            AttributeId::EventList as _,
            AttributeId::AttributeList as _,
            AttributeId::FeatureMap as _,
            AttributeId::ClusterRevision as _,
        ];
        GLOBAL
    }
}
impl core::convert::TryFrom<rs_matter_crate::data_model::objects::AttrId> for AttributeId {
    type Error = rs_matter_crate::error::Error;
    fn try_from(id: rs_matter_crate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
        AttributeId::from_repr(id)
            .ok_or_else(|| rs_matter_crate::error::ErrorCode::AttributeNotFound.into())
    }
}
#[derive(strum :: FromRepr)]
#[repr(u32)]
pub enum CommandId {
    Test = 0,
    TestNotHandled = 1,
    TestSpecific = 2,
    TestUnknownCommand = 3,
    TestAddArguments = 4,
    TestSimpleArgumentRequest = 5,
    TestStructArrayArgumentRequest = 6,
    TestStructArgumentRequest = 7,
    TestNestedStructArgumentRequest = 8,
    TestListStructArgumentRequest = 9,
    TestListInt8UArgumentRequest = 10,
    TestNestedStructListArgumentRequest = 11,
    TestListNestedStructListArgumentRequest = 12,
    TestListInt8UReverseRequest = 13,
    TestEnumsRequest = 14,
    TestNullableOptionalRequest = 15,
    TestComplexNullableOptionalRequest = 16,
    SimpleStructEchoRequest = 17,
    TimedInvokeRequest = 18,
    TestSimpleOptionalArgumentRequest = 19,
    TestEmitTestEventRequest = 20,
    TestEmitTestFabricScopedEventRequest = 21,
    TestBatchHelperRequest = 22,
    TestSecondBatchHelperRequest = 23,
}
impl CommandId {
    pub const fn all() -> &'static [u32] {
        static ALL: &[u32] = &[
            CommandId::Test as _,
            CommandId::TestNotHandled as _,
            CommandId::TestSpecific as _,
            CommandId::TestUnknownCommand as _,
            CommandId::TestAddArguments as _,
            CommandId::TestSimpleArgumentRequest as _,
            CommandId::TestStructArrayArgumentRequest as _,
            CommandId::TestStructArgumentRequest as _,
            CommandId::TestNestedStructArgumentRequest as _,
            CommandId::TestListStructArgumentRequest as _,
            CommandId::TestListInt8UArgumentRequest as _,
            CommandId::TestNestedStructListArgumentRequest as _,
            CommandId::TestListNestedStructListArgumentRequest as _,
            CommandId::TestListInt8UReverseRequest as _,
            CommandId::TestEnumsRequest as _,
            CommandId::TestNullableOptionalRequest as _,
            CommandId::TestComplexNullableOptionalRequest as _,
            CommandId::SimpleStructEchoRequest as _,
            CommandId::TimedInvokeRequest as _,
            CommandId::TestSimpleOptionalArgumentRequest as _,
            CommandId::TestEmitTestEventRequest as _,
            CommandId::TestEmitTestFabricScopedEventRequest as _,
            CommandId::TestBatchHelperRequest as _,
            CommandId::TestSecondBatchHelperRequest as _,
        ];
        ALL
    }
}
impl core::convert::TryFrom<rs_matter_crate::data_model::objects::CmdId> for CommandId {
    type Error = rs_matter_crate::error::Error;
    fn try_from(id: rs_matter_crate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
        CommandId::from_repr(id)
            .ok_or_else(|| rs_matter_crate::error::ErrorCode::CommandNotFound.into())
    }
}
#[derive(strum :: FromRepr)]
#[repr(u32)]
pub enum CommandResponseId {
    TestSpecificResponse = 0,
    TestAddArgumentsResponse = 1,
    TestSimpleArgumentResponse = 2,
    TestStructArrayArgumentResponse = 3,
    TestListInt8UReverseResponse = 4,
    TestEnumsResponse = 5,
    TestNullableOptionalResponse = 6,
    TestComplexNullableOptionalResponse = 7,
    BooleanResponse = 8,
    SimpleStructResponse = 9,
    TestEmitTestEventResponse = 10,
    TestEmitTestFabricScopedEventResponse = 11,
    TestBatchHelperResponse = 12,
}
impl CommandResponseId {
    pub const fn all() -> &'static [u32] {
        static ALL: &[u32] = &[
            CommandResponseId::TestSpecificResponse as _,
            CommandResponseId::TestAddArgumentsResponse as _,
            CommandResponseId::TestSimpleArgumentResponse as _,
            CommandResponseId::TestStructArrayArgumentResponse as _,
            CommandResponseId::TestListInt8UReverseResponse as _,
            CommandResponseId::TestEnumsResponse as _,
            CommandResponseId::TestNullableOptionalResponse as _,
            CommandResponseId::TestComplexNullableOptionalResponse as _,
            CommandResponseId::BooleanResponse as _,
            CommandResponseId::SimpleStructResponse as _,
            CommandResponseId::TestEmitTestEventResponse as _,
            CommandResponseId::TestEmitTestFabricScopedEventResponse as _,
            CommandResponseId::TestBatchHelperResponse as _,
        ];
        ALL
    }
}
impl core::convert::TryFrom<rs_matter_crate::data_model::objects::CmdId> for CommandResponseId {
    type Error = rs_matter_crate::error::Error;
    fn try_from(id: rs_matter_crate::data_model::objects::CmdId) -> Result<Self, Self::Error> {
        CommandResponseId::from_repr(id)
            .ok_or_else(|| rs_matter_crate::error::ErrorCode::CommandNotFound.into())
    }
}
const CLUSTER_REVISION: u16 = 1;
pub const CLUSTER: rs_matter_crate::data_model::objects::Cluster<'static> =
    ClusterConf::Default.cluster();
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
pub enum ClusterConf<'a> {
    #[default]
    Default,
    Mandatory {
        revision: u16,
        feature_map: u32,
    },
    All {
        revision: u16,
        feature_map: u32,
    },
    Custom {
        revision: u16,
        feature_map: u32,
        supported_attributes: &'a [u32],
        accepted_commands: &'a [u32],
        generated_commands: &'a [u32],
    },
}
impl<'a> ClusterConf<'a> {
    pub const fn cluster(&self) -> rs_matter_crate::data_model::objects::Cluster<'a> {
        static ATTRIBUTES_ACCESS: &[rs_matter_crate::data_model::objects::Attribute] = &[
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Boolean as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Bitmap8 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Bitmap16 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Bitmap32 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Bitmap64 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int8u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int16u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int24u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int32u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int40u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int48u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int56u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int64u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int8s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int16s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int24s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int32s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int40s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int48s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int56s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Int64s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Enum8 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Enum16 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::FloatSingle as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::FloatDouble as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::OctetString as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::ListInt8u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::ListOctetString as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::ListStructOctetString as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::LongOctetString as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::CharString as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::LongCharString as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::EpochUs as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::EpochS as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::VendorId as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::ListNullablesAndOptionalsStruct as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::EnumAttr as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::StructAttr as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::RangeRestrictedInt8u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::RangeRestrictedInt8s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::RangeRestrictedInt16u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::RangeRestrictedInt16s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::ListLongOctetString as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::ListFabricScoped as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::TimedWriteBoolean as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    )
                    .union(rs_matter_crate::data_model::objects::Access::TIMED_ONLY),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::GeneralErrorBoolean as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::ClusterErrorBoolean as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::Unsupported as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableBoolean as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableBitmap8 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableBitmap16 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableBitmap32 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableBitmap64 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt8u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt16u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt24u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt32u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt40u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt48u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt56u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt64u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt8s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt16s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt24s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt32s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt40s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt48s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt56s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableInt64s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableEnum8 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableEnum16 as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableFloatSingle as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableFloatDouble as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableOctetString as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableCharString as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableEnumAttr as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableStruct as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableRangeRestrictedInt8u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableRangeRestrictedInt8s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableRangeRestrictedInt16u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::NullableRangeRestrictedInt16s as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::WriteOnlyInt8u as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::WRITE)
                    .union(
                        rs_matter_crate::data_model::objects::Access::NEED_OPERATE
                            .union(
                                rs_matter_crate::data_model::objects::Access::NEED_MANAGE.union(
                                    rs_matter_crate::data_model::objects::Access::NEED_ADMIN,
                                ),
                            )
                            .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                    ),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::GeneratedCommandList as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::AcceptedCommandList as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::EventList as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::AttributeList as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::FeatureMap as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
            rs_matter_crate::data_model::objects::Attribute::new(
                AttributeId::ClusterRevision as _,
                rs_matter_crate::data_model::objects::Access::READ
                    .union(rs_matter_crate::data_model::objects::Access::NEED_VIEW),
                rs_matter_crate::data_model::objects::Quality::SN,
            ),
        ];
        rs_matter_crate::data_model::objects::Cluster {
            id: ID as _,
            attributes_access: ATTRIBUTES_ACCESS,
            revision: match self {
                ClusterConf::Default => CLUSTER_REVISION,
                ClusterConf::Mandatory { revision, .. } => *revision,
                ClusterConf::All { revision, .. } => *revision,
                ClusterConf::Custom { revision, .. } => *revision,
            },
            feature_map: match self {
                ClusterConf::Default => 0,
                ClusterConf::Mandatory { feature_map, .. } => *feature_map,
                ClusterConf::All { feature_map, .. } => *feature_map,
                ClusterConf::Custom { feature_map, .. } => *feature_map,
            },
            supported_attributes: match self {
                ClusterConf::Custom {
                    supported_attributes,
                    ..
                } => supported_attributes,
                _ => AttributeId::all(),
            },
            accepted_commands: match self {
                ClusterConf::Custom {
                    accepted_commands, ..
                } => accepted_commands,
                _ => CommandId::all(),
            },
            generated_commands: match self {
                ClusterConf::Custom {
                    generated_commands, ..
                } => generated_commands,
                _ => CommandResponseId::all(),
            },
        }
    }
}
pub trait UnitTestingHandler {
    fn dataver(&self) -> u32;
    fn dataver_changed(&self);
    fn boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<bool, rs_matter_crate::error::Error>;
    fn bitmap_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<Bitmap8MaskMap, rs_matter_crate::error::Error>;
    fn bitmap_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<Bitmap16MaskMap, rs_matter_crate::error::Error>;
    fn bitmap_32(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<Bitmap32MaskMap, rs_matter_crate::error::Error>;
    fn bitmap_64(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<Bitmap64MaskMap, rs_matter_crate::error::Error>;
    fn int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u8, rs_matter_crate::error::Error>;
    fn int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u16, rs_matter_crate::error::Error>;
    fn int_24_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u32, rs_matter_crate::error::Error>;
    fn int_32_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u32, rs_matter_crate::error::Error>;
    fn int_40_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u64, rs_matter_crate::error::Error>;
    fn int_48_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u64, rs_matter_crate::error::Error>;
    fn int_56_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u64, rs_matter_crate::error::Error>;
    fn int_64_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u64, rs_matter_crate::error::Error>;
    fn int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i8, rs_matter_crate::error::Error>;
    fn int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i16, rs_matter_crate::error::Error>;
    fn int_24_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i32, rs_matter_crate::error::Error>;
    fn int_32_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i32, rs_matter_crate::error::Error>;
    fn int_40_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i64, rs_matter_crate::error::Error>;
    fn int_48_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i64, rs_matter_crate::error::Error>;
    fn int_56_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i64, rs_matter_crate::error::Error>;
    fn int_64_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i64, rs_matter_crate::error::Error>;
    fn enum_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u8, rs_matter_crate::error::Error>;
    fn enum_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u16, rs_matter_crate::error::Error>;
    fn float_single(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<f32, rs_matter_crate::error::Error>;
    fn float_double(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<f64, rs_matter_crate::error::Error>;
    fn octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::OctetsBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn list_int_8_u<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            rs_matter_crate::tlv::ToTLVArrayBuilder<P, u8>,
            rs_matter_crate::tlv::ToTLVBuilder<P, u8>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn list_octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            rs_matter_crate::tlv::OctetsArrayBuilder<P>,
            rs_matter_crate::tlv::OctetsBuilder<P>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn list_struct_octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            TestListStructOctetArrayBuilder<P>,
            TestListStructOctetBuilder<P>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn long_octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::OctetsBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn char_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::Utf8StrBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn long_char_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::Utf8StrBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn epoch_us(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u64, rs_matter_crate::error::Error>;
    fn epoch_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u32, rs_matter_crate::error::Error>;
    fn vendor_id(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u16, rs_matter_crate::error::Error>;
    fn list_nullables_and_optionals_struct<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            NullablesAndOptionalsStructArrayBuilder<P>,
            NullablesAndOptionalsStructBuilder<P>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn enum_attr(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<SimpleEnum, rs_matter_crate::error::Error>;
    fn struct_attr<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: SimpleStructBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn range_restricted_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u8, rs_matter_crate::error::Error>;
    fn range_restricted_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i8, rs_matter_crate::error::Error>;
    fn range_restricted_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u16, rs_matter_crate::error::Error>;
    fn range_restricted_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i16, rs_matter_crate::error::Error>;
    fn list_long_octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            rs_matter_crate::tlv::OctetsArrayBuilder<P>,
            rs_matter_crate::tlv::OctetsBuilder<P>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn list_fabric_scoped<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            TestFabricScopedArrayBuilder<P>,
            TestFabricScopedBuilder<P>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn timed_write_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<bool, rs_matter_crate::error::Error>;
    fn general_error_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<bool, rs_matter_crate::error::Error>;
    fn cluster_error_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<bool, rs_matter_crate::error::Error>;
    fn unsupported(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<bool, rs_matter_crate::error::Error> {
        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
    }
    fn nullable_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<bool>, rs_matter_crate::error::Error>;
    fn nullable_bitmap_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<Bitmap8MaskMap>, rs_matter_crate::error::Error>;
    fn nullable_bitmap_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<Bitmap16MaskMap>, rs_matter_crate::error::Error>;
    fn nullable_bitmap_32(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<Bitmap32MaskMap>, rs_matter_crate::error::Error>;
    fn nullable_bitmap_64(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<Bitmap64MaskMap>, rs_matter_crate::error::Error>;
    fn nullable_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u8>, rs_matter_crate::error::Error>;
    fn nullable_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u16>, rs_matter_crate::error::Error>;
    fn nullable_int_24_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u32>, rs_matter_crate::error::Error>;
    fn nullable_int_32_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u32>, rs_matter_crate::error::Error>;
    fn nullable_int_40_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u64>, rs_matter_crate::error::Error>;
    fn nullable_int_48_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u64>, rs_matter_crate::error::Error>;
    fn nullable_int_56_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u64>, rs_matter_crate::error::Error>;
    fn nullable_int_64_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u64>, rs_matter_crate::error::Error>;
    fn nullable_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i8>, rs_matter_crate::error::Error>;
    fn nullable_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i16>, rs_matter_crate::error::Error>;
    fn nullable_int_24_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i32>, rs_matter_crate::error::Error>;
    fn nullable_int_32_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i32>, rs_matter_crate::error::Error>;
    fn nullable_int_40_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i64>, rs_matter_crate::error::Error>;
    fn nullable_int_48_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i64>, rs_matter_crate::error::Error>;
    fn nullable_int_56_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i64>, rs_matter_crate::error::Error>;
    fn nullable_int_64_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i64>, rs_matter_crate::error::Error>;
    fn nullable_enum_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u8>, rs_matter_crate::error::Error>;
    fn nullable_enum_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u16>, rs_matter_crate::error::Error>;
    fn nullable_float_single(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<f32>, rs_matter_crate::error::Error>;
    fn nullable_float_double(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<f64>, rs_matter_crate::error::Error>;
    fn nullable_octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::NullableBuilder<P, rs_matter_crate::tlv::OctetsBuilder<P>>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn nullable_char_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::NullableBuilder<P, rs_matter_crate::tlv::Utf8StrBuilder<P>>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn nullable_enum_attr(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<SimpleEnum>, rs_matter_crate::error::Error>;
    fn nullable_struct<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::NullableBuilder<P, SimpleStructBuilder<P>>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn nullable_range_restricted_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u8>, rs_matter_crate::error::Error>;
    fn nullable_range_restricted_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i8>, rs_matter_crate::error::Error>;
    fn nullable_range_restricted_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u16>, rs_matter_crate::error::Error>;
    fn nullable_range_restricted_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i16>, rs_matter_crate::error::Error>;
    fn write_only_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u8, rs_matter_crate::error::Error> {
        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
    }
    fn set_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: bool,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_bitmap_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: Bitmap8MaskMap,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_bitmap_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: Bitmap16MaskMap,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_bitmap_32(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: Bitmap32MaskMap,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_bitmap_64(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: Bitmap64MaskMap,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u8,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u16,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_24_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u32,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_32_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u32,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_40_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u64,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_48_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u64,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_56_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u64,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_64_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u64,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i8,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i16,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_24_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i32,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_32_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i32,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_40_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i64,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_48_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i64,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_56_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i64,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_int_64_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i64,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_enum_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u8,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_enum_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u16,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_float_single(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: f32,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_float_double(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: f64,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::OctetStr<'_>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_list_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, u8>,
            u8,
        >,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_list_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, rs_matter_crate::tlv::OctetStr<'_>>,
            rs_matter_crate::tlv::OctetStr<'_>,
        >,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_list_struct_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, TestListStructOctet<'_>>,
            TestListStructOctet<'_>,
        >,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_long_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::OctetStr<'_>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_char_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Utf8Str<'_>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_long_char_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Utf8Str<'_>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_epoch_us(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u64,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_epoch_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u32,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_vendor_id(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u16,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_list_nullables_and_optionals_struct(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, NullablesAndOptionalsStruct<'_>>,
            NullablesAndOptionalsStruct<'_>,
        >,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_enum_attr(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: SimpleEnum,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_struct_attr(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: SimpleStruct<'_>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_range_restricted_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u8,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_range_restricted_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i8,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_range_restricted_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u16,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_range_restricted_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i16,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_list_long_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, rs_matter_crate::tlv::OctetStr<'_>>,
            rs_matter_crate::tlv::OctetStr<'_>,
        >,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_list_fabric_scoped(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, TestFabricScoped<'_>>,
            TestFabricScoped<'_>,
        >,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_timed_write_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: bool,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_general_error_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: bool,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_cluster_error_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: bool,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_unsupported(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: bool,
    ) -> Result<(), rs_matter_crate::error::Error> {
        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
    }
    fn set_nullable_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<bool>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_bitmap_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<Bitmap8MaskMap>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_bitmap_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<Bitmap16MaskMap>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_bitmap_32(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<Bitmap32MaskMap>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_bitmap_64(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<Bitmap64MaskMap>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u8>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u16>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_24_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u32>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_32_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u32>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_40_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u64>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_48_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u64>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_56_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u64>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_64_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u64>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i8>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i16>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_24_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i32>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_32_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i32>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_40_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i64>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_48_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i64>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_56_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i64>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_int_64_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i64>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_enum_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u8>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_enum_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u16>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_float_single(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<f32>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_float_double(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<f64>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::OctetStr<'_>>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_char_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_enum_attr(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<SimpleEnum>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_struct(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<SimpleStruct<'_>>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_range_restricted_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u8>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_range_restricted_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i8>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_range_restricted_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u16>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_nullable_range_restricted_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i16>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn set_write_only_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u8,
    ) -> Result<(), rs_matter_crate::error::Error> {
        Err(rs_matter_crate::error::ErrorCode::InvalidAction.into())
    }
    fn handle_test(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn handle_test_not_handled(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn handle_test_specific<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        response: TestSpecificResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_unknown_command(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn handle_test_add_arguments<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestAddArgumentsRequest<'_>,
        response: TestAddArgumentsResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_simple_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestSimpleArgumentRequestRequest<'_>,
        response: TestSimpleArgumentResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_struct_array_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestStructArrayArgumentRequestRequest<'_>,
        response: TestStructArrayArgumentResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_struct_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_nested_struct_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestNestedStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_list_struct_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestListStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_list_int_8_u_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestListInt8UArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_nested_struct_list_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestNestedStructListArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_list_nested_struct_list_argument_request<
        P: rs_matter_crate::tlv::TLVBuilderParent,
    >(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestListNestedStructListArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_list_int_8_u_reverse_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestListInt8UReverseRequestRequest<'_>,
        response: TestListInt8UReverseResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_enums_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestEnumsRequestRequest<'_>,
        response: TestEnumsResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_nullable_optional_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestNullableOptionalRequestRequest<'_>,
        response: TestNullableOptionalResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_complex_nullable_optional_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestComplexNullableOptionalRequestRequest<'_>,
        response: TestComplexNullableOptionalResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_simple_struct_echo_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: SimpleStructEchoRequestRequest<'_>,
        response: SimpleStructResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_timed_invoke_request(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn handle_test_simple_optional_argument_request(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestSimpleOptionalArgumentRequestRequest<'_>,
    ) -> Result<(), rs_matter_crate::error::Error>;
    fn handle_test_emit_test_event_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestEmitTestEventRequestRequest<'_>,
        response: TestEmitTestEventResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_emit_test_fabric_scoped_event_request<
        P: rs_matter_crate::tlv::TLVBuilderParent,
    >(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestEmitTestFabricScopedEventRequestRequest<'_>,
        response: TestEmitTestFabricScopedEventResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_batch_helper_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestBatchHelperRequestRequest<'_>,
        response: TestBatchHelperResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
    fn handle_test_second_batch_helper_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestSecondBatchHelperRequestRequest<'_>,
        response: TestBatchHelperResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error>;
}
impl<T> UnitTestingHandler for &T
where
    T: UnitTestingHandler,
{
    fn dataver(&self) -> u32 {
        T::dataver(self)
    }
    fn dataver_changed(&self) {
        T::dataver_changed(self)
    }
    fn boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<bool, rs_matter_crate::error::Error> {
        T::boolean(self, ctx)
    }
    fn bitmap_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<Bitmap8MaskMap, rs_matter_crate::error::Error> {
        T::bitmap_8(self, ctx)
    }
    fn bitmap_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<Bitmap16MaskMap, rs_matter_crate::error::Error> {
        T::bitmap_16(self, ctx)
    }
    fn bitmap_32(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<Bitmap32MaskMap, rs_matter_crate::error::Error> {
        T::bitmap_32(self, ctx)
    }
    fn bitmap_64(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<Bitmap64MaskMap, rs_matter_crate::error::Error> {
        T::bitmap_64(self, ctx)
    }
    fn int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u8, rs_matter_crate::error::Error> {
        T::int_8_u(self, ctx)
    }
    fn int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u16, rs_matter_crate::error::Error> {
        T::int_16_u(self, ctx)
    }
    fn int_24_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u32, rs_matter_crate::error::Error> {
        T::int_24_u(self, ctx)
    }
    fn int_32_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u32, rs_matter_crate::error::Error> {
        T::int_32_u(self, ctx)
    }
    fn int_40_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u64, rs_matter_crate::error::Error> {
        T::int_40_u(self, ctx)
    }
    fn int_48_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u64, rs_matter_crate::error::Error> {
        T::int_48_u(self, ctx)
    }
    fn int_56_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u64, rs_matter_crate::error::Error> {
        T::int_56_u(self, ctx)
    }
    fn int_64_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u64, rs_matter_crate::error::Error> {
        T::int_64_u(self, ctx)
    }
    fn int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i8, rs_matter_crate::error::Error> {
        T::int_8_s(self, ctx)
    }
    fn int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i16, rs_matter_crate::error::Error> {
        T::int_16_s(self, ctx)
    }
    fn int_24_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i32, rs_matter_crate::error::Error> {
        T::int_24_s(self, ctx)
    }
    fn int_32_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i32, rs_matter_crate::error::Error> {
        T::int_32_s(self, ctx)
    }
    fn int_40_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i64, rs_matter_crate::error::Error> {
        T::int_40_s(self, ctx)
    }
    fn int_48_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i64, rs_matter_crate::error::Error> {
        T::int_48_s(self, ctx)
    }
    fn int_56_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i64, rs_matter_crate::error::Error> {
        T::int_56_s(self, ctx)
    }
    fn int_64_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i64, rs_matter_crate::error::Error> {
        T::int_64_s(self, ctx)
    }
    fn enum_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u8, rs_matter_crate::error::Error> {
        T::enum_8(self, ctx)
    }
    fn enum_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u16, rs_matter_crate::error::Error> {
        T::enum_16(self, ctx)
    }
    fn float_single(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<f32, rs_matter_crate::error::Error> {
        T::float_single(self, ctx)
    }
    fn float_double(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<f64, rs_matter_crate::error::Error> {
        T::float_double(self, ctx)
    }
    fn octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::OctetsBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::octet_string(self, ctx, builder)
    }
    fn list_int_8_u<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            rs_matter_crate::tlv::ToTLVArrayBuilder<P, u8>,
            rs_matter_crate::tlv::ToTLVBuilder<P, u8>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::list_int_8_u(self, ctx, builder)
    }
    fn list_octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            rs_matter_crate::tlv::OctetsArrayBuilder<P>,
            rs_matter_crate::tlv::OctetsBuilder<P>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::list_octet_string(self, ctx, builder)
    }
    fn list_struct_octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            TestListStructOctetArrayBuilder<P>,
            TestListStructOctetBuilder<P>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::list_struct_octet_string(self, ctx, builder)
    }
    fn long_octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::OctetsBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::long_octet_string(self, ctx, builder)
    }
    fn char_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::Utf8StrBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::char_string(self, ctx, builder)
    }
    fn long_char_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::Utf8StrBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::long_char_string(self, ctx, builder)
    }
    fn epoch_us(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u64, rs_matter_crate::error::Error> {
        T::epoch_us(self, ctx)
    }
    fn epoch_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u32, rs_matter_crate::error::Error> {
        T::epoch_s(self, ctx)
    }
    fn vendor_id(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u16, rs_matter_crate::error::Error> {
        T::vendor_id(self, ctx)
    }
    fn list_nullables_and_optionals_struct<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            NullablesAndOptionalsStructArrayBuilder<P>,
            NullablesAndOptionalsStructBuilder<P>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::list_nullables_and_optionals_struct(self, ctx, builder)
    }
    fn enum_attr(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<SimpleEnum, rs_matter_crate::error::Error> {
        T::enum_attr(self, ctx)
    }
    fn struct_attr<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: SimpleStructBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::struct_attr(self, ctx, builder)
    }
    fn range_restricted_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u8, rs_matter_crate::error::Error> {
        T::range_restricted_int_8_u(self, ctx)
    }
    fn range_restricted_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i8, rs_matter_crate::error::Error> {
        T::range_restricted_int_8_s(self, ctx)
    }
    fn range_restricted_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u16, rs_matter_crate::error::Error> {
        T::range_restricted_int_16_u(self, ctx)
    }
    fn range_restricted_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<i16, rs_matter_crate::error::Error> {
        T::range_restricted_int_16_s(self, ctx)
    }
    fn list_long_octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            rs_matter_crate::tlv::OctetsArrayBuilder<P>,
            rs_matter_crate::tlv::OctetsBuilder<P>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::list_long_octet_string(self, ctx, builder)
    }
    fn list_fabric_scoped<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::data_model::objects::ArrayAttributeRead<
            TestFabricScopedArrayBuilder<P>,
            TestFabricScopedBuilder<P>,
        >,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::list_fabric_scoped(self, ctx, builder)
    }
    fn timed_write_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<bool, rs_matter_crate::error::Error> {
        T::timed_write_boolean(self, ctx)
    }
    fn general_error_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<bool, rs_matter_crate::error::Error> {
        T::general_error_boolean(self, ctx)
    }
    fn cluster_error_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<bool, rs_matter_crate::error::Error> {
        T::cluster_error_boolean(self, ctx)
    }
    fn unsupported(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<bool, rs_matter_crate::error::Error> {
        T::unsupported(self, ctx)
    }
    fn nullable_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<bool>, rs_matter_crate::error::Error> {
        T::nullable_boolean(self, ctx)
    }
    fn nullable_bitmap_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<Bitmap8MaskMap>, rs_matter_crate::error::Error> {
        T::nullable_bitmap_8(self, ctx)
    }
    fn nullable_bitmap_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<Bitmap16MaskMap>, rs_matter_crate::error::Error>
    {
        T::nullable_bitmap_16(self, ctx)
    }
    fn nullable_bitmap_32(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<Bitmap32MaskMap>, rs_matter_crate::error::Error>
    {
        T::nullable_bitmap_32(self, ctx)
    }
    fn nullable_bitmap_64(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<Bitmap64MaskMap>, rs_matter_crate::error::Error>
    {
        T::nullable_bitmap_64(self, ctx)
    }
    fn nullable_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u8>, rs_matter_crate::error::Error> {
        T::nullable_int_8_u(self, ctx)
    }
    fn nullable_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u16>, rs_matter_crate::error::Error> {
        T::nullable_int_16_u(self, ctx)
    }
    fn nullable_int_24_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u32>, rs_matter_crate::error::Error> {
        T::nullable_int_24_u(self, ctx)
    }
    fn nullable_int_32_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u32>, rs_matter_crate::error::Error> {
        T::nullable_int_32_u(self, ctx)
    }
    fn nullable_int_40_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u64>, rs_matter_crate::error::Error> {
        T::nullable_int_40_u(self, ctx)
    }
    fn nullable_int_48_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u64>, rs_matter_crate::error::Error> {
        T::nullable_int_48_u(self, ctx)
    }
    fn nullable_int_56_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u64>, rs_matter_crate::error::Error> {
        T::nullable_int_56_u(self, ctx)
    }
    fn nullable_int_64_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u64>, rs_matter_crate::error::Error> {
        T::nullable_int_64_u(self, ctx)
    }
    fn nullable_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i8>, rs_matter_crate::error::Error> {
        T::nullable_int_8_s(self, ctx)
    }
    fn nullable_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i16>, rs_matter_crate::error::Error> {
        T::nullable_int_16_s(self, ctx)
    }
    fn nullable_int_24_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i32>, rs_matter_crate::error::Error> {
        T::nullable_int_24_s(self, ctx)
    }
    fn nullable_int_32_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i32>, rs_matter_crate::error::Error> {
        T::nullable_int_32_s(self, ctx)
    }
    fn nullable_int_40_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i64>, rs_matter_crate::error::Error> {
        T::nullable_int_40_s(self, ctx)
    }
    fn nullable_int_48_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i64>, rs_matter_crate::error::Error> {
        T::nullable_int_48_s(self, ctx)
    }
    fn nullable_int_56_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i64>, rs_matter_crate::error::Error> {
        T::nullable_int_56_s(self, ctx)
    }
    fn nullable_int_64_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i64>, rs_matter_crate::error::Error> {
        T::nullable_int_64_s(self, ctx)
    }
    fn nullable_enum_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u8>, rs_matter_crate::error::Error> {
        T::nullable_enum_8(self, ctx)
    }
    fn nullable_enum_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u16>, rs_matter_crate::error::Error> {
        T::nullable_enum_16(self, ctx)
    }
    fn nullable_float_single(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<f32>, rs_matter_crate::error::Error> {
        T::nullable_float_single(self, ctx)
    }
    fn nullable_float_double(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<f64>, rs_matter_crate::error::Error> {
        T::nullable_float_double(self, ctx)
    }
    fn nullable_octet_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::NullableBuilder<P, rs_matter_crate::tlv::OctetsBuilder<P>>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::nullable_octet_string(self, ctx, builder)
    }
    fn nullable_char_string<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::NullableBuilder<P, rs_matter_crate::tlv::Utf8StrBuilder<P>>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::nullable_char_string(self, ctx, builder)
    }
    fn nullable_enum_attr(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<SimpleEnum>, rs_matter_crate::error::Error> {
        T::nullable_enum_attr(self, ctx)
    }
    fn nullable_struct<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
        builder: rs_matter_crate::tlv::NullableBuilder<P, SimpleStructBuilder<P>>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::nullable_struct(self, ctx, builder)
    }
    fn nullable_range_restricted_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u8>, rs_matter_crate::error::Error> {
        T::nullable_range_restricted_int_8_u(self, ctx)
    }
    fn nullable_range_restricted_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i8>, rs_matter_crate::error::Error> {
        T::nullable_range_restricted_int_8_s(self, ctx)
    }
    fn nullable_range_restricted_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<u16>, rs_matter_crate::error::Error> {
        T::nullable_range_restricted_int_16_u(self, ctx)
    }
    fn nullable_range_restricted_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<rs_matter_crate::tlv::Nullable<i16>, rs_matter_crate::error::Error> {
        T::nullable_range_restricted_int_16_s(self, ctx)
    }
    fn write_only_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::ReadContext<'_>,
    ) -> Result<u8, rs_matter_crate::error::Error> {
        T::write_only_int_8_u(self, ctx)
    }
    fn set_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: bool,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_boolean(self, ctx, value)
    }
    fn set_bitmap_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: Bitmap8MaskMap,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_bitmap_8(self, ctx, value)
    }
    fn set_bitmap_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: Bitmap16MaskMap,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_bitmap_16(self, ctx, value)
    }
    fn set_bitmap_32(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: Bitmap32MaskMap,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_bitmap_32(self, ctx, value)
    }
    fn set_bitmap_64(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: Bitmap64MaskMap,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_bitmap_64(self, ctx, value)
    }
    fn set_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u8,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_8_u(self, ctx, value)
    }
    fn set_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u16,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_16_u(self, ctx, value)
    }
    fn set_int_24_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u32,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_24_u(self, ctx, value)
    }
    fn set_int_32_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u32,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_32_u(self, ctx, value)
    }
    fn set_int_40_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u64,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_40_u(self, ctx, value)
    }
    fn set_int_48_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u64,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_48_u(self, ctx, value)
    }
    fn set_int_56_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u64,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_56_u(self, ctx, value)
    }
    fn set_int_64_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u64,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_64_u(self, ctx, value)
    }
    fn set_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i8,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_8_s(self, ctx, value)
    }
    fn set_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i16,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_16_s(self, ctx, value)
    }
    fn set_int_24_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i32,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_24_s(self, ctx, value)
    }
    fn set_int_32_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i32,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_32_s(self, ctx, value)
    }
    fn set_int_40_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i64,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_40_s(self, ctx, value)
    }
    fn set_int_48_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i64,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_48_s(self, ctx, value)
    }
    fn set_int_56_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i64,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_56_s(self, ctx, value)
    }
    fn set_int_64_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i64,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_int_64_s(self, ctx, value)
    }
    fn set_enum_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u8,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_enum_8(self, ctx, value)
    }
    fn set_enum_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u16,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_enum_16(self, ctx, value)
    }
    fn set_float_single(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: f32,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_float_single(self, ctx, value)
    }
    fn set_float_double(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: f64,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_float_double(self, ctx, value)
    }
    fn set_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::OctetStr<'_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_octet_string(self, ctx, value)
    }
    fn set_list_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, u8>,
            u8,
        >,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_list_int_8_u(self, ctx, value)
    }
    fn set_list_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, rs_matter_crate::tlv::OctetStr<'_>>,
            rs_matter_crate::tlv::OctetStr<'_>,
        >,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_list_octet_string(self, ctx, value)
    }
    fn set_list_struct_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, TestListStructOctet<'_>>,
            TestListStructOctet<'_>,
        >,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_list_struct_octet_string(self, ctx, value)
    }
    fn set_long_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::OctetStr<'_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_long_octet_string(self, ctx, value)
    }
    fn set_char_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Utf8Str<'_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_char_string(self, ctx, value)
    }
    fn set_long_char_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Utf8Str<'_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_long_char_string(self, ctx, value)
    }
    fn set_epoch_us(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u64,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_epoch_us(self, ctx, value)
    }
    fn set_epoch_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u32,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_epoch_s(self, ctx, value)
    }
    fn set_vendor_id(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u16,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_vendor_id(self, ctx, value)
    }
    fn set_list_nullables_and_optionals_struct(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, NullablesAndOptionalsStruct<'_>>,
            NullablesAndOptionalsStruct<'_>,
        >,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_list_nullables_and_optionals_struct(self, ctx, value)
    }
    fn set_enum_attr(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: SimpleEnum,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_enum_attr(self, ctx, value)
    }
    fn set_struct_attr(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: SimpleStruct<'_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_struct_attr(self, ctx, value)
    }
    fn set_range_restricted_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u8,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_range_restricted_int_8_u(self, ctx, value)
    }
    fn set_range_restricted_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i8,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_range_restricted_int_8_s(self, ctx, value)
    }
    fn set_range_restricted_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u16,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_range_restricted_int_16_u(self, ctx, value)
    }
    fn set_range_restricted_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: i16,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_range_restricted_int_16_s(self, ctx, value)
    }
    fn set_list_long_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, rs_matter_crate::tlv::OctetStr<'_>>,
            rs_matter_crate::tlv::OctetStr<'_>,
        >,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_list_long_octet_string(self, ctx, value)
    }
    fn set_list_fabric_scoped(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::data_model::objects::ArrayAttributeWrite<
            rs_matter_crate::tlv::TLVArray<'_, TestFabricScoped<'_>>,
            TestFabricScoped<'_>,
        >,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_list_fabric_scoped(self, ctx, value)
    }
    fn set_timed_write_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: bool,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_timed_write_boolean(self, ctx, value)
    }
    fn set_general_error_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: bool,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_general_error_boolean(self, ctx, value)
    }
    fn set_cluster_error_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: bool,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_cluster_error_boolean(self, ctx, value)
    }
    fn set_unsupported(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: bool,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_unsupported(self, ctx, value)
    }
    fn set_nullable_boolean(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<bool>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_boolean(self, ctx, value)
    }
    fn set_nullable_bitmap_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<Bitmap8MaskMap>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_bitmap_8(self, ctx, value)
    }
    fn set_nullable_bitmap_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<Bitmap16MaskMap>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_bitmap_16(self, ctx, value)
    }
    fn set_nullable_bitmap_32(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<Bitmap32MaskMap>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_bitmap_32(self, ctx, value)
    }
    fn set_nullable_bitmap_64(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<Bitmap64MaskMap>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_bitmap_64(self, ctx, value)
    }
    fn set_nullable_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u8>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_8_u(self, ctx, value)
    }
    fn set_nullable_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u16>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_16_u(self, ctx, value)
    }
    fn set_nullable_int_24_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u32>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_24_u(self, ctx, value)
    }
    fn set_nullable_int_32_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u32>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_32_u(self, ctx, value)
    }
    fn set_nullable_int_40_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u64>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_40_u(self, ctx, value)
    }
    fn set_nullable_int_48_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u64>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_48_u(self, ctx, value)
    }
    fn set_nullable_int_56_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u64>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_56_u(self, ctx, value)
    }
    fn set_nullable_int_64_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u64>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_64_u(self, ctx, value)
    }
    fn set_nullable_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i8>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_8_s(self, ctx, value)
    }
    fn set_nullable_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i16>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_16_s(self, ctx, value)
    }
    fn set_nullable_int_24_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i32>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_24_s(self, ctx, value)
    }
    fn set_nullable_int_32_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i32>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_32_s(self, ctx, value)
    }
    fn set_nullable_int_40_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i64>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_40_s(self, ctx, value)
    }
    fn set_nullable_int_48_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i64>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_48_s(self, ctx, value)
    }
    fn set_nullable_int_56_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i64>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_56_s(self, ctx, value)
    }
    fn set_nullable_int_64_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i64>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_int_64_s(self, ctx, value)
    }
    fn set_nullable_enum_8(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u8>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_enum_8(self, ctx, value)
    }
    fn set_nullable_enum_16(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u16>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_enum_16(self, ctx, value)
    }
    fn set_nullable_float_single(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<f32>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_float_single(self, ctx, value)
    }
    fn set_nullable_float_double(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<f64>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_float_double(self, ctx, value)
    }
    fn set_nullable_octet_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::OctetStr<'_>>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_octet_string(self, ctx, value)
    }
    fn set_nullable_char_string(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_char_string(self, ctx, value)
    }
    fn set_nullable_enum_attr(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<SimpleEnum>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_enum_attr(self, ctx, value)
    }
    fn set_nullable_struct(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<SimpleStruct<'_>>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_struct(self, ctx, value)
    }
    fn set_nullable_range_restricted_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u8>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_range_restricted_int_8_u(self, ctx, value)
    }
    fn set_nullable_range_restricted_int_8_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i8>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_range_restricted_int_8_s(self, ctx, value)
    }
    fn set_nullable_range_restricted_int_16_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<u16>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_range_restricted_int_16_u(self, ctx, value)
    }
    fn set_nullable_range_restricted_int_16_s(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: rs_matter_crate::tlv::Nullable<i16>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_nullable_range_restricted_int_16_s(self, ctx, value)
    }
    fn set_write_only_int_8_u(
        &self,
        ctx: &rs_matter_crate::data_model::objects::WriteContext<'_>,
        value: u8,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::set_write_only_int_8_u(self, ctx, value)
    }
    fn handle_test(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::handle_test(self, ctx)
    }
    fn handle_test_not_handled(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::handle_test_not_handled(self, ctx)
    }
    fn handle_test_specific<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        response: TestSpecificResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_specific(self, ctx, response)
    }
    fn handle_test_unknown_command(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::handle_test_unknown_command(self, ctx)
    }
    fn handle_test_add_arguments<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestAddArgumentsRequest<'_>,
        response: TestAddArgumentsResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_add_arguments(self, ctx, request, response)
    }
    fn handle_test_simple_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestSimpleArgumentRequestRequest<'_>,
        response: TestSimpleArgumentResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_simple_argument_request(self, ctx, request, response)
    }
    fn handle_test_struct_array_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestStructArrayArgumentRequestRequest<'_>,
        response: TestStructArrayArgumentResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_struct_array_argument_request(self, ctx, request, response)
    }
    fn handle_test_struct_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_struct_argument_request(self, ctx, request, response)
    }
    fn handle_test_nested_struct_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestNestedStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_nested_struct_argument_request(self, ctx, request, response)
    }
    fn handle_test_list_struct_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestListStructArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_list_struct_argument_request(self, ctx, request, response)
    }
    fn handle_test_list_int_8_u_argument_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestListInt8UArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_list_int_8_u_argument_request(self, ctx, request, response)
    }
    fn handle_test_nested_struct_list_argument_request<
        P: rs_matter_crate::tlv::TLVBuilderParent,
    >(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestNestedStructListArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_nested_struct_list_argument_request(self, ctx, request, response)
    }
    fn handle_test_list_nested_struct_list_argument_request<
        P: rs_matter_crate::tlv::TLVBuilderParent,
    >(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestListNestedStructListArgumentRequestRequest<'_>,
        response: BooleanResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_list_nested_struct_list_argument_request(self, ctx, request, response)
    }
    fn handle_test_list_int_8_u_reverse_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestListInt8UReverseRequestRequest<'_>,
        response: TestListInt8UReverseResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_list_int_8_u_reverse_request(self, ctx, request, response)
    }
    fn handle_test_enums_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestEnumsRequestRequest<'_>,
        response: TestEnumsResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_enums_request(self, ctx, request, response)
    }
    fn handle_test_nullable_optional_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestNullableOptionalRequestRequest<'_>,
        response: TestNullableOptionalResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_nullable_optional_request(self, ctx, request, response)
    }
    fn handle_test_complex_nullable_optional_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestComplexNullableOptionalRequestRequest<'_>,
        response: TestComplexNullableOptionalResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_complex_nullable_optional_request(self, ctx, request, response)
    }
    fn handle_simple_struct_echo_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: SimpleStructEchoRequestRequest<'_>,
        response: SimpleStructResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_simple_struct_echo_request(self, ctx, request, response)
    }
    fn handle_timed_invoke_request(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::handle_timed_invoke_request(self, ctx)
    }
    fn handle_test_simple_optional_argument_request(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestSimpleOptionalArgumentRequestRequest<'_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        T::handle_test_simple_optional_argument_request(self, ctx, request)
    }
    fn handle_test_emit_test_event_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestEmitTestEventRequestRequest<'_>,
        response: TestEmitTestEventResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_emit_test_event_request(self, ctx, request, response)
    }
    fn handle_test_emit_test_fabric_scoped_event_request<
        P: rs_matter_crate::tlv::TLVBuilderParent,
    >(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestEmitTestFabricScopedEventRequestRequest<'_>,
        response: TestEmitTestFabricScopedEventResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_emit_test_fabric_scoped_event_request(self, ctx, request, response)
    }
    fn handle_test_batch_helper_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestBatchHelperRequestRequest<'_>,
        response: TestBatchHelperResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_batch_helper_request(self, ctx, request, response)
    }
    fn handle_test_second_batch_helper_request<P: rs_matter_crate::tlv::TLVBuilderParent>(
        &self,
        ctx: &rs_matter_crate::data_model::objects::InvokeContext<'_>,
        request: TestSecondBatchHelperRequestRequest<'_>,
        response: TestBatchHelperResponseBuilder<P>,
    ) -> Result<P, rs_matter_crate::error::Error> {
        T::handle_test_second_batch_helper_request(self, ctx, request, response)
    }
}
pub struct UnitTestingAdaptor<T>(pub T);
impl<T> rs_matter_crate::data_model::objects::Handler for UnitTestingAdaptor<T>
where
    T: UnitTestingHandler,
{
    #[allow(unreachable_code)]
    fn read(
        &self,
        exchange: &rs_matter_crate::transport::exchange::Exchange<'_>,
        attr: &rs_matter_crate::data_model::objects::AttrDetails<'_>,
        encoder: rs_matter_crate::data_model::objects::AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        if let Some(mut writer) = encoder.with_dataver(self.0.dataver())? {
            if attr.is_system() {
                attr.cluster()?.read(attr.attr_id, writer)
            } else {
                match AttributeId::try_from(attr.attr_id)? {
                    AttributeId::Boolean => writer.set(self.0.boolean(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Bitmap8 => writer.set(self.0.bitmap_8(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Bitmap16 => writer.set(self.0.bitmap_16(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Bitmap32 => writer.set(self.0.bitmap_32(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Bitmap64 => writer.set(self.0.bitmap_64(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int8u => writer.set(self.0.int_8_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int16u => writer.set(self.0.int_16_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int24u => writer.set(self.0.int_24_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int32u => writer.set(self.0.int_32_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int40u => writer.set(self.0.int_40_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int48u => writer.set(self.0.int_48_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int56u => writer.set(self.0.int_56_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int64u => writer.set(self.0.int_64_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int8s => writer.set(self.0.int_8_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int16s => writer.set(self.0.int_16_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int24s => writer.set(self.0.int_24_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int32s => writer.set(self.0.int_32_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int40s => writer.set(self.0.int_40_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int48s => writer.set(self.0.int_48_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int56s => writer.set(self.0.int_56_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Int64s => writer.set(self.0.int_64_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Enum8 => writer.set(self.0.enum_8(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Enum16 => writer.set(self.0.enum_16(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::FloatSingle => writer.set(self.0.float_single(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::FloatDouble => writer.set(self.0.float_double(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::OctetString => {
                        self.0.octet_string(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::tlv::TLVBuilder::new(
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::ListInt8u => {
                        self.0.list_int_8_u(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::data_model::objects::ArrayAttributeRead::new(
                                attr.list_index.clone(),
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::ListOctetString => {
                        self.0.list_octet_string(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::data_model::objects::ArrayAttributeRead::new(
                                attr.list_index.clone(),
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::ListStructOctetString => {
                        self.0.list_struct_octet_string(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::data_model::objects::ArrayAttributeRead::new(
                                attr.list_index.clone(),
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::LongOctetString => {
                        self.0.long_octet_string(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::tlv::TLVBuilder::new(
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::CharString => {
                        self.0.char_string(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::tlv::TLVBuilder::new(
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::LongCharString => {
                        self.0.long_char_string(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::tlv::TLVBuilder::new(
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::EpochUs => writer.set(self.0.epoch_us(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::EpochS => writer.set(self.0.epoch_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::VendorId => writer.set(self.0.vendor_id(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::ListNullablesAndOptionalsStruct => {
                        self.0.list_nullables_and_optionals_struct(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::data_model::objects::ArrayAttributeRead::new(
                                attr.list_index.clone(),
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::EnumAttr => writer.set(self.0.enum_attr(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::StructAttr => {
                        self.0.struct_attr(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::tlv::TLVBuilder::new(
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::RangeRestrictedInt8u => {
                        writer.set(self.0.range_restricted_int_8_u(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                        )?)
                    }
                    AttributeId::RangeRestrictedInt8s => {
                        writer.set(self.0.range_restricted_int_8_s(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                        )?)
                    }
                    AttributeId::RangeRestrictedInt16u => {
                        writer.set(self.0.range_restricted_int_16_u(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                        )?)
                    }
                    AttributeId::RangeRestrictedInt16s => {
                        writer.set(self.0.range_restricted_int_16_s(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                        )?)
                    }
                    AttributeId::ListLongOctetString => {
                        self.0.list_long_octet_string(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::data_model::objects::ArrayAttributeRead::new(
                                attr.list_index.clone(),
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::ListFabricScoped => {
                        self.0.list_fabric_scoped(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::data_model::objects::ArrayAttributeRead::new(
                                attr.list_index.clone(),
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::TimedWriteBoolean => writer.set(self.0.timed_write_boolean(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::GeneralErrorBoolean => writer.set(self.0.general_error_boolean(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::ClusterErrorBoolean => writer.set(self.0.cluster_error_boolean(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::Unsupported => writer.set(self.0.unsupported(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableBoolean => writer.set(self.0.nullable_boolean(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableBitmap8 => writer.set(self.0.nullable_bitmap_8(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableBitmap16 => writer.set(self.0.nullable_bitmap_16(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableBitmap32 => writer.set(self.0.nullable_bitmap_32(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableBitmap64 => writer.set(self.0.nullable_bitmap_64(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt8u => writer.set(self.0.nullable_int_8_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt16u => writer.set(self.0.nullable_int_16_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt24u => writer.set(self.0.nullable_int_24_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt32u => writer.set(self.0.nullable_int_32_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt40u => writer.set(self.0.nullable_int_40_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt48u => writer.set(self.0.nullable_int_48_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt56u => writer.set(self.0.nullable_int_56_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt64u => writer.set(self.0.nullable_int_64_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt8s => writer.set(self.0.nullable_int_8_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt16s => writer.set(self.0.nullable_int_16_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt24s => writer.set(self.0.nullable_int_24_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt32s => writer.set(self.0.nullable_int_32_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt40s => writer.set(self.0.nullable_int_40_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt48s => writer.set(self.0.nullable_int_48_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt56s => writer.set(self.0.nullable_int_56_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableInt64s => writer.set(self.0.nullable_int_64_s(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableEnum8 => writer.set(self.0.nullable_enum_8(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableEnum16 => writer.set(self.0.nullable_enum_16(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableFloatSingle => writer.set(self.0.nullable_float_single(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableFloatDouble => writer.set(self.0.nullable_float_double(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableOctetString => {
                        self.0.nullable_octet_string(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::tlv::TLVBuilder::new(
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::NullableCharString => {
                        self.0.nullable_char_string(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::tlv::TLVBuilder::new(
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::NullableEnumAttr => writer.set(self.0.nullable_enum_attr(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    AttributeId::NullableStruct => {
                        self.0.nullable_struct(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                            rs_matter_crate::tlv::TLVBuilder::new(
                                rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                                &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                            )?,
                        )?;
                        writer.complete()
                    }
                    AttributeId::NullableRangeRestrictedInt8u => {
                        writer.set(self.0.nullable_range_restricted_int_8_u(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                        )?)
                    }
                    AttributeId::NullableRangeRestrictedInt8s => {
                        writer.set(self.0.nullable_range_restricted_int_8_s(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                        )?)
                    }
                    AttributeId::NullableRangeRestrictedInt16u => {
                        writer.set(self.0.nullable_range_restricted_int_16_u(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                        )?)
                    }
                    AttributeId::NullableRangeRestrictedInt16s => {
                        writer.set(self.0.nullable_range_restricted_int_16_s(
                            &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                        )?)
                    }
                    AttributeId::WriteOnlyInt8u => writer.set(self.0.write_only_int_8_u(
                        &rs_matter_crate::data_model::objects::ReadContext::new(exchange),
                    )?),
                    #[allow(unreachable_code)]
                    _ => Err(rs_matter_crate::error::ErrorCode::AttributeNotFound.into()),
                }
            }
        } else {
            Ok(())
        }
    }
    #[allow(unreachable_code)]
    fn write(
        &self,
        exchange: &rs_matter_crate::transport::exchange::Exchange<'_>,
        attr: &rs_matter_crate::data_model::objects::AttrDetails<'_>,
        data: rs_matter_crate::data_model::objects::AttrData<'_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        let data = data.with_dataver(self.0.dataver())?;
        if attr.is_system() {
            return Err(rs_matter_crate::error::ErrorCode::InvalidAction.into());
        }
        match AttributeId::try_from(attr.attr_id)? {
            AttributeId::Boolean => self.0.set_boolean(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Bitmap8 => self.0.set_bitmap_8(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Bitmap16 => self.0.set_bitmap_16(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Bitmap32 => self.0.set_bitmap_32(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Bitmap64 => self.0.set_bitmap_64(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int8u => self.0.set_int_8_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int16u => self.0.set_int_16_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int24u => self.0.set_int_24_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int32u => self.0.set_int_32_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int40u => self.0.set_int_40_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int48u => self.0.set_int_48_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int56u => self.0.set_int_56_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int64u => self.0.set_int_64_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int8s => self.0.set_int_8_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int16s => self.0.set_int_16_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int24s => self.0.set_int_24_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int32s => self.0.set_int_32_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int40s => self.0.set_int_40_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int48s => self.0.set_int_48_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int56s => self.0.set_int_56_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Int64s => self.0.set_int_64_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Enum8 => self.0.set_enum_8(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Enum16 => self.0.set_enum_16(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::FloatSingle => self.0.set_float_single(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::FloatDouble => self.0.set_float_double(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::OctetString => self.0.set_octet_string(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::ListInt8u => self.0.set_list_int_8_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::data_model::objects::ArrayAttributeWrite::new(
                    attr.list_index.clone(),
                    &data,
                )?,
            )?,
            AttributeId::ListOctetString => self.0.set_list_octet_string(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::data_model::objects::ArrayAttributeWrite::new(
                    attr.list_index.clone(),
                    &data,
                )?,
            )?,
            AttributeId::ListStructOctetString => self.0.set_list_struct_octet_string(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::data_model::objects::ArrayAttributeWrite::new(
                    attr.list_index.clone(),
                    &data,
                )?,
            )?,
            AttributeId::LongOctetString => self.0.set_long_octet_string(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::CharString => self.0.set_char_string(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::LongCharString => self.0.set_long_char_string(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::EpochUs => self.0.set_epoch_us(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::EpochS => self.0.set_epoch_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::VendorId => self.0.set_vendor_id(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::ListNullablesAndOptionalsStruct => {
                self.0.set_list_nullables_and_optionals_struct(
                    &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                    rs_matter_crate::data_model::objects::ArrayAttributeWrite::new(
                        attr.list_index.clone(),
                        &data,
                    )?,
                )?
            }
            AttributeId::EnumAttr => self.0.set_enum_attr(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::StructAttr => self.0.set_struct_attr(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::RangeRestrictedInt8u => self.0.set_range_restricted_int_8_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::RangeRestrictedInt8s => self.0.set_range_restricted_int_8_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::RangeRestrictedInt16u => self.0.set_range_restricted_int_16_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::RangeRestrictedInt16s => self.0.set_range_restricted_int_16_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::ListLongOctetString => self.0.set_list_long_octet_string(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::data_model::objects::ArrayAttributeWrite::new(
                    attr.list_index.clone(),
                    &data,
                )?,
            )?,
            AttributeId::ListFabricScoped => self.0.set_list_fabric_scoped(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::data_model::objects::ArrayAttributeWrite::new(
                    attr.list_index.clone(),
                    &data,
                )?,
            )?,
            AttributeId::TimedWriteBoolean => self.0.set_timed_write_boolean(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::GeneralErrorBoolean => self.0.set_general_error_boolean(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::ClusterErrorBoolean => self.0.set_cluster_error_boolean(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::Unsupported => self.0.set_unsupported(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableBoolean => self.0.set_nullable_boolean(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableBitmap8 => self.0.set_nullable_bitmap_8(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableBitmap16 => self.0.set_nullable_bitmap_16(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableBitmap32 => self.0.set_nullable_bitmap_32(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableBitmap64 => self.0.set_nullable_bitmap_64(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt8u => self.0.set_nullable_int_8_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt16u => self.0.set_nullable_int_16_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt24u => self.0.set_nullable_int_24_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt32u => self.0.set_nullable_int_32_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt40u => self.0.set_nullable_int_40_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt48u => self.0.set_nullable_int_48_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt56u => self.0.set_nullable_int_56_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt64u => self.0.set_nullable_int_64_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt8s => self.0.set_nullable_int_8_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt16s => self.0.set_nullable_int_16_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt24s => self.0.set_nullable_int_24_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt32s => self.0.set_nullable_int_32_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt40s => self.0.set_nullable_int_40_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt48s => self.0.set_nullable_int_48_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt56s => self.0.set_nullable_int_56_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableInt64s => self.0.set_nullable_int_64_s(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableEnum8 => self.0.set_nullable_enum_8(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableEnum16 => self.0.set_nullable_enum_16(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableFloatSingle => self.0.set_nullable_float_single(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableFloatDouble => self.0.set_nullable_float_double(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableOctetString => self.0.set_nullable_octet_string(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableCharString => self.0.set_nullable_char_string(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableEnumAttr => self.0.set_nullable_enum_attr(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableStruct => self.0.set_nullable_struct(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            AttributeId::NullableRangeRestrictedInt8u => {
                self.0.set_nullable_range_restricted_int_8_u(
                    &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                )?
            }
            AttributeId::NullableRangeRestrictedInt8s => {
                self.0.set_nullable_range_restricted_int_8_s(
                    &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                )?
            }
            AttributeId::NullableRangeRestrictedInt16u => {
                self.0.set_nullable_range_restricted_int_16_u(
                    &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                )?
            }
            AttributeId::NullableRangeRestrictedInt16s => {
                self.0.set_nullable_range_restricted_int_16_s(
                    &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                )?
            }
            AttributeId::WriteOnlyInt8u => self.0.set_write_only_int_8_u(
                &rs_matter_crate::data_model::objects::WriteContext::new(exchange),
                rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
            )?,
            _ => return Err(rs_matter_crate::error::ErrorCode::AttributeNotFound.into()),
        }
        self.0.dataver_changed();
        Ok(())
    }
    #[allow(unreachable_code)]
    fn invoke(
        &self,
        exchange: &rs_matter_crate::transport::exchange::Exchange<'_>,
        cmd: &rs_matter_crate::data_model::objects::CmdDetails<'_>,
        data: &rs_matter_crate::tlv::TLVElement<'_>,
        encoder: rs_matter_crate::data_model::objects::CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), rs_matter_crate::error::Error> {
        match CommandId::try_from(cmd.cmd_id)? {
            CommandId::Test => {
                self.0
                    .handle_test(&rs_matter_crate::data_model::objects::InvokeContext::new(
                        exchange,
                    ))?
            }
            CommandId::TestNotHandled => self.0.handle_test_not_handled(
                &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
            )?,
            CommandId::TestSpecific => {
                let mut writer = encoder.with_command(0u32)?;
                self.0.handle_test_specific(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestUnknownCommand => self.0.handle_test_unknown_command(
                &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
            )?,
            CommandId::TestAddArguments => {
                let mut writer = encoder.with_command(1u32)?;
                self.0.handle_test_add_arguments(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestSimpleArgumentRequest => {
                let mut writer = encoder.with_command(2u32)?;
                self.0.handle_test_simple_argument_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestStructArrayArgumentRequest => {
                let mut writer = encoder.with_command(3u32)?;
                self.0.handle_test_struct_array_argument_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestStructArgumentRequest => {
                let mut writer = encoder.with_command(8u32)?;
                self.0.handle_test_struct_argument_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestNestedStructArgumentRequest => {
                let mut writer = encoder.with_command(8u32)?;
                self.0.handle_test_nested_struct_argument_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestListStructArgumentRequest => {
                let mut writer = encoder.with_command(8u32)?;
                self.0.handle_test_list_struct_argument_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestListInt8UArgumentRequest => {
                let mut writer = encoder.with_command(8u32)?;
                self.0.handle_test_list_int_8_u_argument_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestNestedStructListArgumentRequest => {
                let mut writer = encoder.with_command(8u32)?;
                self.0.handle_test_nested_struct_list_argument_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestListNestedStructListArgumentRequest => {
                let mut writer = encoder.with_command(8u32)?;
                self.0
                    .handle_test_list_nested_struct_list_argument_request(
                        &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                        rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                        rs_matter_crate::tlv::TLVBuilder::new(
                            rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                            &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                        )?,
                    )?;
                writer.complete()?
            }
            CommandId::TestListInt8UReverseRequest => {
                let mut writer = encoder.with_command(4u32)?;
                self.0.handle_test_list_int_8_u_reverse_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestEnumsRequest => {
                let mut writer = encoder.with_command(5u32)?;
                self.0.handle_test_enums_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestNullableOptionalRequest => {
                let mut writer = encoder.with_command(6u32)?;
                self.0.handle_test_nullable_optional_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestComplexNullableOptionalRequest => {
                let mut writer = encoder.with_command(7u32)?;
                self.0.handle_test_complex_nullable_optional_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::SimpleStructEchoRequest => {
                let mut writer = encoder.with_command(9u32)?;
                self.0.handle_simple_struct_echo_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TimedInvokeRequest => self.0.handle_timed_invoke_request(
                &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
            )?,
            CommandId::TestSimpleOptionalArgumentRequest => {
                self.0.handle_test_simple_optional_argument_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                )?
            }
            CommandId::TestEmitTestEventRequest => {
                let mut writer = encoder.with_command(10u32)?;
                self.0.handle_test_emit_test_event_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestEmitTestFabricScopedEventRequest => {
                let mut writer = encoder.with_command(11u32)?;
                self.0.handle_test_emit_test_fabric_scoped_event_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestBatchHelperRequest => {
                let mut writer = encoder.with_command(12u32)?;
                self.0.handle_test_batch_helper_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            CommandId::TestSecondBatchHelperRequest => {
                let mut writer = encoder.with_command(12u32)?;
                self.0.handle_test_second_batch_helper_request(
                    &rs_matter_crate::data_model::objects::InvokeContext::new(exchange),
                    rs_matter_crate::tlv::FromTLV::from_tlv(&data)?,
                    rs_matter_crate::tlv::TLVBuilder::new(
                        rs_matter_crate::tlv::TLVWriteParent::new(writer.writer()),
                        &rs_matter_crate::data_model::objects::AttrDataWriter::TAG,
                    )?,
                )?;
                writer.complete()?
            }
            _ => return Err(rs_matter_crate::error::ErrorCode::CommandNotFound.into()),
        }
        self.0.dataver_changed();
        Ok(())
    }
}
impl<T> rs_matter_crate::data_model::objects::NonBlockingHandler for UnitTestingAdaptor<T> where
    T: UnitTestingHandler
{
}
"#;
}
