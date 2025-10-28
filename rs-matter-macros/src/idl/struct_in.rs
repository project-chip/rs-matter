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

//! A module for generating Rust types corresponding to structures in an IDL cluster.

use proc_macro2::{Ident, Literal, TokenStream};
use quote::quote;

use super::field::field_type;
use super::id::{ident, idl_field_name_to_rs_name, idl_field_name_to_rs_type_name};
use super::parser::{ApiMaturity, EntityContext, Struct, StructField};
use super::IdlGenerateContext;

/// Return a token stream containing simple enums with the tag IDs of
/// all structures in the given IDL entities.
pub fn struct_tags(structs: &Vec<Struct>, context: &IdlGenerateContext) -> TokenStream {
    let krate = context.rs_matter_crate.clone();

    let struct_tags = structs.iter().map(|s| struct_tag(s, &krate));

    quote!(
        #(#struct_tags)*
    )
}

/// Return a token stream containing the structure definitions
/// for all structures in the given IDL cluster.
pub fn structs(
    structs: &Vec<Struct>,
    entities: &EntityContext,
    context: &IdlGenerateContext,
) -> TokenStream {
    let structs = structs.iter().map(|s| structure(s, entities, context));

    quote!(
        #(#structs)*
    )
}

/// Create the token stream corresponding to a structure
/// tag definition.
///
/// Provide the raw `enum FooTag { }` declaration.
fn struct_tag(s: &Struct, krate: &Ident) -> TokenStream {
    let name = ident(&format!("{}Tag", s.id));

    let fields = s.fields.iter().map(struct_tag_field);

    quote!(
        #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
        #[cfg_attr(feature = "defmt", derive(#krate::reexport::defmt::Format))]
        #[repr(u8)]
        pub enum #name { #(#fields)* }
    )
}

/// Creates the token stream corresponding to a structure
/// definition.
///
/// Provide the raw `struct Foo<'a>(TLVElement<'a>); impl<'a> Foo<'a> { ... }` declaration.
fn structure(s: &Struct, entities: &EntityContext, context: &IdlGenerateContext) -> TokenStream {
    // NOTE: s.is_fabric_scoped not directly handled as the IDL
    //       will have fabric_idx with ID 254 automatically added.

    let krate = context.rs_matter_crate.clone();

    let name = ident(&s.id);
    let name_str = Literal::string(&s.id);

    let fields = s.fields.iter().map(|f| struct_field(f, entities, context));
    let fields_debug = s
        .fields
        .iter()
        .map(|f| struct_field_debug(f, false, &krate));
    let fields_format = s.fields.iter().map(|f| struct_field_debug(f, true, &krate));

    quote!(
        #[derive(PartialEq, Eq, Clone, Hash)]
        pub struct #name<'a>(#krate::tlv::TLVElement<'a>);

        impl<'a> #name<'a> {
            #[doc = "Create a new instance"]
            pub const fn new(element: #krate::tlv::TLVElement<'a>) -> Self {
                Self(element)
            }

            #[doc = "Return the underlying TLV element"]
            pub const fn tlv_element(&self) -> &#krate::tlv::TLVElement<'a> {
                &self.0
            }

            #(#fields)*
        }

        impl<'a> #krate::tlv::FromTLV<'a> for #name<'a> {
            fn from_tlv(element: &#krate::tlv::TLVElement<'a>) -> Result<Self, #krate::error::Error> {
                Ok(Self::new(element.clone()))
            }
        }

        impl #krate::tlv::ToTLV for #name<'_> {
            fn to_tlv<W: #krate::tlv::TLVWrite>(&self, tag: &#krate::tlv::TLVTag, tw: W) -> Result<(), #krate::error::Error> {
                self.0.to_tlv(tag, tw)
            }

            fn tlv_iter(&self, tag: #krate::tlv::TLVTag) -> impl Iterator<Item = Result<#krate::tlv::TLV, #krate::error::Error>> {
                self.0.tlv_iter(tag)
            }
        }

        impl core::fmt::Debug for #name<'_> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{} {{", #name_str)?;

                #(#fields_debug)*

                write!(f, "}}")
            }
        }

        #[cfg(feature = "defmt")]
        impl #krate::reexport::defmt::Format for #name<'_> {
            fn format(&self, f: #krate::reexport::defmt::Formatter<'_>) {
                #krate::reexport::defmt::write!(f, "{} {{", #name_str);

                #(#fields_format)*

                #krate::reexport::defmt::write!(f, "}}")
            }
        }
    )
}

/// Create the token stream corresponding to a field inside a structure
fn struct_field(
    f: &StructField,
    entities: &EntityContext,
    context: &IdlGenerateContext,
) -> TokenStream {
    // f.fabric_sensitive does not seem to have any specific meaning so we ignore it
    // fabric_sensitive seems to be specific to fabric_scoped structs

    let doc_comment = struct_field_comment(f);
    let krate = context.rs_matter_crate.clone();

    let code = Literal::u8_unsuffixed(f.field.code as u8);
    let field_type = field_type(
        &f.field.data_type,
        f.is_nullable,
        f.is_optional(),
        entities,
        &krate,
    );
    let name = ident(&idl_field_name_to_rs_name(&f.field.id));

    if f.is_optional() {
        quote!(
            #doc_comment
            pub fn #name(&self) -> Result<#field_type, #krate::error::Error> {
                let element = self.0.structure()?.find_ctx(#code)?;

                if element.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(#krate::tlv::FromTLV::from_tlv(&element)?))
                }
            }
        )
    } else {
        quote!(
            #doc_comment
            pub fn #name(&self) -> Result<#field_type, #krate::error::Error> {
                #krate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(#code)?)
            }
        )
    }
}

/// Create the token stream corresponding to a debug printout of a field inside a structure
fn struct_field_debug(f: &StructField, defmt: bool, krate: &Ident) -> TokenStream {
    let name = ident(&idl_field_name_to_rs_name(&f.field.id));
    let name_str = Literal::string(&idl_field_name_to_rs_name(&f.field.id));
    let write = if defmt {
        quote!(#krate::reexport::defmt::write!)
    } else {
        quote!(write!)
    };
    let write_suffix = if defmt { quote!() } else { quote!(?) };

    if f.is_optional() {
        quote!(
            match self.#name() {
                Ok(Some(value)) => #write(f, "{}: Some({:?}),", #name_str, value)#write_suffix,
                Ok(None) => #write(f, "{}: None,", #name_str)#write_suffix,
                Err(e) => #write(f, "{}: ??? {:?},", #name_str, e.code())#write_suffix,
            }
        )
    } else {
        quote!(
            match self.#name() {
                Ok(value) => #write(f, "{}: {:?},", #name_str, value)#write_suffix,
                Err(e) => #write(f, "{}: ??? {:?},", #name_str, e.code())#write_suffix,
            }
        )
    }
}

/// Create the token stream corresponding to the tag of a field inside a structure
fn struct_tag_field(f: &StructField) -> TokenStream {
    // f.fabric_sensitive does not seem to have any specific meaning so we ignore it
    // fabric_sensitive seems to be specific to fabric_scoped structs

    let doc_comment = struct_field_comment(f);

    let code = Literal::u8_unsuffixed(f.field.code as u8);
    let name = ident(&idl_field_name_to_rs_type_name(&f.field.id));

    quote!(
        #doc_comment
        #name = #code,
    )
}

/// Create the token stream corresponding to the comment of a field inside a structure
pub(crate) fn struct_field_comment(f: &StructField) -> TokenStream {
    match f.maturity {
        ApiMaturity::Provisional => quote!(#[doc="provisional"]),
        ApiMaturity::Internal => quote!(#[doc="internal"]),
        ApiMaturity::Deprecated => quote!(#[doc="deprecated"]),
        _ => quote!(),
    }
}

#[cfg(test)]
mod tests {
    use crate::idl::{
        parser::EntityContext,
        struct_in::{struct_tags, structs},
        tests::{get_cluster_named, parse_idl},
        IdlGenerateContext,
    };

    use assert_tokenstreams_eq::assert_tokenstreams_eq;
    use quote::quote;

    #[test]
    fn test_structs() {
        let idl = parse_idl(
            "
              struct GlobalStruct {
                boolean global = 1;
              }
              cluster TestForStructs = 1 {

                // a somewhat complex struct
                struct NetworkInfoStruct {
                  boolean connected = 1;
                  optional int8u test_optional = 2;
                  nullable int16u test_nullable = 3;
                  optional nullable int32u test_both = 4;
                }

                // Some varying requests
                request struct IdentifyRequest {
                  int16u identifyTime = 0;
                }

                request struct SomeRequest {
                  group_id group = 0;
                }

                // Some responses
                response struct TestResponse = 0 {
                  int8u capacity = 0;
                }

                response struct AnotherResponse = 1 {
                  enum8 status = 0;
                  group_id groupID = 12;
                }

                shared struct SharedStruct {
                  boolean shared = 1;
                }
              }
            ",
        );

        let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &structs(&EntityContext::new(Some(&cluster.entities), &idl.globals), &context));

        assert_tokenstreams_eq!(
            &structs(
                &cluster.entities.structs,
                &EntityContext::new(Some(&cluster.entities), &idl.globals),
                &context
            ),
            &quote!(
                #[derive(PartialEq, Eq, Clone, Hash)]
                pub struct NetworkInfoStruct<'a>(rs_matter_crate::tlv::TLVElement<'a>);
                impl<'a> NetworkInfoStruct<'a> {
                    #[doc = "Create a new instance"]
                    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
                        Self(element)
                    }
                    #[doc = "Return the underlying TLV element"]
                    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
                        &self.0
                    }
                    pub fn connected(&self) -> Result<bool, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
                    }
                    pub fn test_optional(&self) -> Result<Option<u8>, rs_matter_crate::error::Error> {
                        let element = self.0.structure()?.find_ctx(2)?;
                        if element.is_empty() {
                            Ok(None)
                        } else {
                            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
                        }
                    }
                    pub fn test_nullable(
                        &self,
                    ) -> Result<rs_matter_crate::tlv::Nullable<u16>, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(3)?)
                    }
                    pub fn test_both(
                        &self,
                    ) -> Result<Option<rs_matter_crate::tlv::Nullable<u32>>, rs_matter_crate::error::Error> {
                        let element = self.0.structure()?.find_ctx(4)?;
                        if element.is_empty() {
                            Ok(None)
                        } else {
                            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
                        }
                    }
                }
                impl<'a> rs_matter_crate::tlv::FromTLV<'a> for NetworkInfoStruct<'a> {
                    fn from_tlv(
                        element: &rs_matter_crate::tlv::TLVElement<'a>,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Ok(Self::new(element.clone()))
                    }
                }
                impl rs_matter_crate::tlv::ToTLV for NetworkInfoStruct<'_> {
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
                impl core::fmt::Debug for NetworkInfoStruct<'_> {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(f, "{} {{", "NetworkInfoStruct")?;
                        match self.connected() {
                            Ok(value) => write!(f, "{}: {:?},", "connected", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "connected", e.code())?,
                        }
                        match self.test_optional() {
                            Ok(Some(value)) => write!(f, "{}: Some({:?}),", "test_optional", value)?,
                            Ok(None) => write!(f, "{}: None,", "test_optional")?,
                            Err(e) => write!(f, "{}: ??? {:?},", "test_optional", e.code())?,
                        }
                        match self.test_nullable() {
                            Ok(value) => write!(f, "{}: {:?},", "test_nullable", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "test_nullable", e.code())?,
                        }
                        match self.test_both() {
                            Ok(Some(value)) => write!(f, "{}: Some({:?}),", "test_both", value)?,
                            Ok(None) => write!(f, "{}: None,", "test_both")?,
                            Err(e) => write!(f, "{}: ??? {:?},", "test_both", e.code())?,
                        }
                        write!(f, "}}")
                    }
                }
                #[cfg(feature = "defmt")]
                impl rs_matter_crate::reexport::defmt::Format for NetworkInfoStruct<'_> {
                    fn format(&self, f: rs_matter_crate::reexport::defmt::Formatter<'_>) {
                        rs_matter_crate::reexport::defmt::write!(f, "{} {{", "NetworkInfoStruct");
                        match self.connected() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "connected", value)
                            }
                            Err(e) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: ??? {:?},", "connected", e.code())
                            }
                        }
                        match self.test_optional() {
                            Ok(Some(value)) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: Some({:?}),",
                                "test_optional",
                                value
                            ),
                            Ok(None) => rs_matter_crate::reexport::defmt::write!(f, "{}: None,", "test_optional"),
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "test_optional",
                                e.code()
                            ),
                        }
                        match self.test_nullable() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "test_nullable", value)
                            }
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "test_nullable",
                                e.code()
                            ),
                        }
                        match self.test_both() {
                            Ok(Some(value)) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: Some({:?}),", "test_both", value)
                            }
                            Ok(None) => rs_matter_crate::reexport::defmt::write!(f, "{}: None,", "test_both"),
                            Err(e) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: ??? {:?},", "test_both", e.code())
                            }
                        }
                        rs_matter_crate::reexport::defmt::write!(f, "}}")
                    }
                }
                #[derive(PartialEq, Eq, Clone, Hash)]
                pub struct IdentifyRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
                impl<'a> IdentifyRequest<'a> {
                    #[doc = "Create a new instance"]
                    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
                        Self(element)
                    }
                    #[doc = "Return the underlying TLV element"]
                    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
                        &self.0
                    }
                    pub fn identify_time(&self) -> Result<u16, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
                    }
                }
                impl<'a> rs_matter_crate::tlv::FromTLV<'a> for IdentifyRequest<'a> {
                    fn from_tlv(
                        element: &rs_matter_crate::tlv::TLVElement<'a>,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Ok(Self::new(element.clone()))
                    }
                }
                impl rs_matter_crate::tlv::ToTLV for IdentifyRequest<'_> {
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
                impl core::fmt::Debug for IdentifyRequest<'_> {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(f, "{} {{", "IdentifyRequest")?;
                        match self.identify_time() {
                            Ok(value) => write!(f, "{}: {:?},", "identify_time", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "identify_time", e.code())?,
                        }
                        write!(f, "}}")
                    }
                }
                #[cfg(feature = "defmt")]
                impl rs_matter_crate::reexport::defmt::Format for IdentifyRequest<'_> {
                    fn format(&self, f: rs_matter_crate::reexport::defmt::Formatter<'_>) {
                        rs_matter_crate::reexport::defmt::write!(f, "{} {{", "IdentifyRequest");
                        match self.identify_time() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "identify_time", value)
                            }
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "identify_time",
                                e.code()
                            ),
                        }
                        rs_matter_crate::reexport::defmt::write!(f, "}}")
                    }
                }
                #[derive(PartialEq, Eq, Clone, Hash)]
                pub struct SomeRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
                impl<'a> SomeRequest<'a> {
                    #[doc = "Create a new instance"]
                    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
                        Self(element)
                    }
                    #[doc = "Return the underlying TLV element"]
                    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
                        &self.0
                    }
                    pub fn group(&self) -> Result<u16, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
                    }
                }
                impl<'a> rs_matter_crate::tlv::FromTLV<'a> for SomeRequest<'a> {
                    fn from_tlv(
                        element: &rs_matter_crate::tlv::TLVElement<'a>,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Ok(Self::new(element.clone()))
                    }
                }
                impl rs_matter_crate::tlv::ToTLV for SomeRequest<'_> {
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
                impl core::fmt::Debug for SomeRequest<'_> {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(f, "{} {{", "SomeRequest")?;
                        match self.group() {
                            Ok(value) => write!(f, "{}: {:?},", "group", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "group", e.code())?,
                        }
                        write!(f, "}}")
                    }
                }
                #[cfg(feature = "defmt")]
                impl rs_matter_crate::reexport::defmt::Format for SomeRequest<'_> {
                    fn format(&self, f: rs_matter_crate::reexport::defmt::Formatter<'_>) {
                        rs_matter_crate::reexport::defmt::write!(f, "{} {{", "SomeRequest");
                        match self.group() {
                            Ok(value) => rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "group", value),
                            Err(e) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: ??? {:?},", "group", e.code())
                            }
                        }
                        rs_matter_crate::reexport::defmt::write!(f, "}}")
                    }
                }
                #[derive(PartialEq, Eq, Clone, Hash)]
                pub struct TestResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
                impl<'a> TestResponse<'a> {
                    #[doc = "Create a new instance"]
                    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
                        Self(element)
                    }
                    #[doc = "Return the underlying TLV element"]
                    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
                        &self.0
                    }
                    pub fn capacity(&self) -> Result<u8, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
                    }
                }
                impl<'a> rs_matter_crate::tlv::FromTLV<'a> for TestResponse<'a> {
                    fn from_tlv(
                        element: &rs_matter_crate::tlv::TLVElement<'a>,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Ok(Self::new(element.clone()))
                    }
                }
                impl rs_matter_crate::tlv::ToTLV for TestResponse<'_> {
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
                impl core::fmt::Debug for TestResponse<'_> {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(f, "{} {{", "TestResponse")?;
                        match self.capacity() {
                            Ok(value) => write!(f, "{}: {:?},", "capacity", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "capacity", e.code())?,
                        }
                        write!(f, "}}")
                    }
                }
                #[cfg(feature = "defmt")]
                impl rs_matter_crate::reexport::defmt::Format for TestResponse<'_> {
                    fn format(&self, f: rs_matter_crate::reexport::defmt::Formatter<'_>) {
                        rs_matter_crate::reexport::defmt::write!(f, "{} {{", "TestResponse");
                        match self.capacity() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "capacity", value)
                            }
                            Err(e) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: ??? {:?},", "capacity", e.code())
                            }
                        }
                        rs_matter_crate::reexport::defmt::write!(f, "}}")
                    }
                }
                #[derive(PartialEq, Eq, Clone, Hash)]
                pub struct AnotherResponse<'a>(rs_matter_crate::tlv::TLVElement<'a>);
                impl<'a> AnotherResponse<'a> {
                    #[doc = "Create a new instance"]
                    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
                        Self(element)
                    }
                    #[doc = "Return the underlying TLV element"]
                    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
                        &self.0
                    }
                    pub fn status(&self) -> Result<u8, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
                    }
                    pub fn group_id(&self) -> Result<u16, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(12)?)
                    }
                }
                impl<'a> rs_matter_crate::tlv::FromTLV<'a> for AnotherResponse<'a> {
                    fn from_tlv(
                        element: &rs_matter_crate::tlv::TLVElement<'a>,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Ok(Self::new(element.clone()))
                    }
                }
                impl rs_matter_crate::tlv::ToTLV for AnotherResponse<'_> {
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
                impl core::fmt::Debug for AnotherResponse<'_> {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(f, "{} {{", "AnotherResponse")?;
                        match self.status() {
                            Ok(value) => write!(f, "{}: {:?},", "status", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "status", e.code())?,
                        }
                        match self.group_id() {
                            Ok(value) => write!(f, "{}: {:?},", "group_id", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "group_id", e.code())?,
                        }
                        write!(f, "}}")
                    }
                }
                #[cfg(feature = "defmt")]
                impl rs_matter_crate::reexport::defmt::Format for AnotherResponse<'_> {
                    fn format(&self, f: rs_matter_crate::reexport::defmt::Formatter<'_>) {
                        rs_matter_crate::reexport::defmt::write!(f, "{} {{", "AnotherResponse");
                        match self.status() {
                            Ok(value) => rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "status", value),
                            Err(e) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: ??? {:?},", "status", e.code())
                            }
                        }
                        match self.group_id() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "group_id", value)
                            }
                            Err(e) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: ??? {:?},", "group_id", e.code())
                            }
                        }
                        rs_matter_crate::reexport::defmt::write!(f, "}}")
                    }
                }
            )
        );

        // panic!("====\n{}\n====", struct_tags(&cluster.entities.structs, &context));

        assert_tokenstreams_eq!(
            &struct_tags(&cluster.entities.structs, &context),
            &quote!(
                #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                #[cfg_attr(feature = "defmt", derive(rs_matter_crate::reexport::defmt::Format))]
                #[repr(u8)]
                pub enum NetworkInfoStructTag {
                    Connected = 1,
                    TestOptional = 2,
                    TestNullable = 3,
                    TestBoth = 4,
                }
                #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                #[cfg_attr(feature = "defmt", derive(rs_matter_crate::reexport::defmt::Format))]
                #[repr(u8)]
                pub enum IdentifyRequestTag {
                    IdentifyTime = 0,
                }
                #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                #[cfg_attr(feature = "defmt", derive(rs_matter_crate::reexport::defmt::Format))]
                #[repr(u8)]
                pub enum SomeRequestTag {
                    Group = 0,
                }
                #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                #[cfg_attr(feature = "defmt", derive(rs_matter_crate::reexport::defmt::Format))]
                #[repr(u8)]
                pub enum TestResponseTag {
                    Capacity = 0,
                }
                #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                #[cfg_attr(feature = "defmt", derive(rs_matter_crate::reexport::defmt::Format))]
                #[repr(u8)]
                pub enum AnotherResponseTag {
                    Status = 0,
                    GroupId = 12,
                }
            )
        );
    }

    #[test]
    fn test_on_off_structs() {
        let idl = parse_idl(
            "
              cluster OnOff = 6 {
                revision 6;

                request struct OffWithEffectRequest {
                  EffectIdentifierEnum effectIdentifier = 0;
                  enum8 effectVariant = 1;
                }

                request struct OnWithTimedOffRequest {
                  OnOffControlBitmap onOffControl = 0;
                  int16u onTime = 1;
                  int16u offWaitTime = 2;
                }
              }
        ",
        );

        let cluster = get_cluster_named(&idl, "OnOff").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &structs(cluster, &context));

        assert_tokenstreams_eq!(
            &structs(
                &cluster.entities.structs,
                &EntityContext::new(Some(&cluster.entities), &idl.globals),
                &context
            ),
            &quote!(
                #[derive(PartialEq, Eq, Clone, Hash)]
                pub struct OffWithEffectRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
                impl<'a> OffWithEffectRequest<'a> {
                    #[doc = "Create a new instance"]
                    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
                        Self(element)
                    }
                    #[doc = "Return the underlying TLV element"]
                    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
                        &self.0
                    }
                    pub fn effect_identifier(&self) -> Result<EffectIdentifierEnum, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
                    }
                    pub fn effect_variant(&self) -> Result<u8, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
                    }
                }
                impl<'a> rs_matter_crate::tlv::FromTLV<'a> for OffWithEffectRequest<'a> {
                    fn from_tlv(
                        element: &rs_matter_crate::tlv::TLVElement<'a>,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Ok(Self::new(element.clone()))
                    }
                }
                impl rs_matter_crate::tlv::ToTLV for OffWithEffectRequest<'_> {
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
                impl core::fmt::Debug for OffWithEffectRequest<'_> {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(f, "{} {{", "OffWithEffectRequest")?;
                        match self.effect_identifier() {
                            Ok(value) => write!(f, "{}: {:?},", "effect_identifier", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "effect_identifier", e.code())?,
                        }
                        match self.effect_variant() {
                            Ok(value) => write!(f, "{}: {:?},", "effect_variant", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "effect_variant", e.code())?,
                        }
                        write!(f, "}}")
                    }
                }
                #[cfg(feature = "defmt")]
                impl rs_matter_crate::reexport::defmt::Format for OffWithEffectRequest<'_> {
                    fn format(&self, f: rs_matter_crate::reexport::defmt::Formatter<'_>) {
                        rs_matter_crate::reexport::defmt::write!(f, "{} {{", "OffWithEffectRequest");
                        match self.effect_identifier() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "effect_identifier", value)
                            }
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "effect_identifier",
                                e.code()
                            ),
                        }
                        match self.effect_variant() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "effect_variant", value)
                            }
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "effect_variant",
                                e.code()
                            ),
                        }
                        rs_matter_crate::reexport::defmt::write!(f, "}}")
                    }
                }
                #[derive(PartialEq, Eq, Clone, Hash)]
                pub struct OnWithTimedOffRequest<'a>(rs_matter_crate::tlv::TLVElement<'a>);
                impl<'a> OnWithTimedOffRequest<'a> {
                    #[doc = "Create a new instance"]
                    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
                        Self(element)
                    }
                    #[doc = "Return the underlying TLV element"]
                    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
                        &self.0
                    }
                    pub fn on_off_control(&self) -> Result<OnOffControlBitmap, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(0)?)
                    }
                    pub fn on_time(&self) -> Result<u16, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
                    }
                    pub fn off_wait_time(&self) -> Result<u16, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
                    }
                }
                impl<'a> rs_matter_crate::tlv::FromTLV<'a> for OnWithTimedOffRequest<'a> {
                    fn from_tlv(
                        element: &rs_matter_crate::tlv::TLVElement<'a>,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Ok(Self::new(element.clone()))
                    }
                }
                impl rs_matter_crate::tlv::ToTLV for OnWithTimedOffRequest<'_> {
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
                impl core::fmt::Debug for OnWithTimedOffRequest<'_> {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(f, "{} {{", "OnWithTimedOffRequest")?;
                        match self.on_off_control() {
                            Ok(value) => write!(f, "{}: {:?},", "on_off_control", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "on_off_control", e.code())?,
                        }
                        match self.on_time() {
                            Ok(value) => write!(f, "{}: {:?},", "on_time", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "on_time", e.code())?,
                        }
                        match self.off_wait_time() {
                            Ok(value) => write!(f, "{}: {:?},", "off_wait_time", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "off_wait_time", e.code())?,
                        }
                        write!(f, "}}")
                    }
                }
                #[cfg(feature = "defmt")]
                impl rs_matter_crate::reexport::defmt::Format for OnWithTimedOffRequest<'_> {
                    fn format(&self, f: rs_matter_crate::reexport::defmt::Formatter<'_>) {
                        rs_matter_crate::reexport::defmt::write!(f, "{} {{", "OnWithTimedOffRequest");
                        match self.on_off_control() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "on_off_control", value)
                            }
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "on_off_control",
                                e.code()
                            ),
                        }
                        match self.on_time() {
                            Ok(value) => rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "on_time", value),
                            Err(e) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: ??? {:?},", "on_time", e.code())
                            }
                        }
                        match self.off_wait_time() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "off_wait_time", value)
                            }
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "off_wait_time",
                                e.code()
                            ),
                        }
                        rs_matter_crate::reexport::defmt::write!(f, "}}")
                    }
                }
            )
        );

        // panic!("====\n{}\n====", &struct_tags(cluster, &context));

        assert_tokenstreams_eq!(
            &struct_tags(&cluster.entities.structs, &context),
            &quote!(
                #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                #[cfg_attr(feature = "defmt", derive(rs_matter_crate::reexport::defmt::Format))]
                #[repr(u8)]
                pub enum OffWithEffectRequestTag {
                    EffectIdentifier = 0,
                    EffectVariant = 1,
                }

                #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                #[cfg_attr(feature = "defmt", derive(rs_matter_crate::reexport::defmt::Format))]
                #[repr(u8)]
                pub enum OnWithTimedOffRequestTag {
                    OnOffControl = 0,
                    OnTime = 1,
                    OffWaitTime = 2,
                }
            )
        );
    }

    #[test]
    fn struct_fields_string() {
        let idl = parse_idl(
            "
              cluster TestForStructs = 1 {
                struct WithStringMember {
                  char_string<16> short_string = 1;
                  long_char_string<512> long_string = 2;
                  optional char_string<32> opt_str = 3;
                  optional nullable long_char_string<512> opt_nul_str = 4;
                }
              }
            ",
        );

        let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &structs(cluster, &context));

        assert_tokenstreams_eq!(
            &structs(
                &cluster.entities.structs,
                &EntityContext::new(Some(&cluster.entities), &idl.globals),
                &context
            ),
            &quote!(
                #[derive(PartialEq, Eq, Clone, Hash)]
                pub struct WithStringMember<'a>(rs_matter_crate::tlv::TLVElement<'a>);
                impl<'a> WithStringMember<'a> {
                    #[doc = "Create a new instance"]
                    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
                        Self(element)
                    }
                    #[doc = "Return the underlying TLV element"]
                    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
                        &self.0
                    }
                    pub fn short_string(
                        &self,
                    ) -> Result<rs_matter_crate::tlv::Utf8Str<'_>, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
                    }
                    pub fn long_string(
                        &self,
                    ) -> Result<rs_matter_crate::tlv::Utf8Str<'_>, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
                    }
                    pub fn opt_str(
                        &self,
                    ) -> Result<Option<rs_matter_crate::tlv::Utf8Str<'_>>, rs_matter_crate::error::Error> {
                        let element = self.0.structure()?.find_ctx(3)?;
                        if element.is_empty() {
                            Ok(None)
                        } else {
                            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
                        }
                    }
                    pub fn opt_nul_str(
                        &self,
                    ) -> Result<
                        Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::Utf8Str<'_>>>,
                        rs_matter_crate::error::Error,
                    > {
                        let element = self.0.structure()?.find_ctx(4)?;
                        if element.is_empty() {
                            Ok(None)
                        } else {
                            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
                        }
                    }
                }
                impl<'a> rs_matter_crate::tlv::FromTLV<'a> for WithStringMember<'a> {
                    fn from_tlv(
                        element: &rs_matter_crate::tlv::TLVElement<'a>,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Ok(Self::new(element.clone()))
                    }
                }
                impl rs_matter_crate::tlv::ToTLV for WithStringMember<'_> {
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
                impl core::fmt::Debug for WithStringMember<'_> {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(f, "{} {{", "WithStringMember")?;
                        match self.short_string() {
                            Ok(value) => write!(f, "{}: {:?},", "short_string", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "short_string", e.code())?,
                        }
                        match self.long_string() {
                            Ok(value) => write!(f, "{}: {:?},", "long_string", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "long_string", e.code())?,
                        }
                        match self.opt_str() {
                            Ok(Some(value)) => write!(f, "{}: Some({:?}),", "opt_str", value)?,
                            Ok(None) => write!(f, "{}: None,", "opt_str")?,
                            Err(e) => write!(f, "{}: ??? {:?},", "opt_str", e.code())?,
                        }
                        match self.opt_nul_str() {
                            Ok(Some(value)) => write!(f, "{}: Some({:?}),", "opt_nul_str", value)?,
                            Ok(None) => write!(f, "{}: None,", "opt_nul_str")?,
                            Err(e) => write!(f, "{}: ??? {:?},", "opt_nul_str", e.code())?,
                        }
                        write!(f, "}}")
                    }
                }
                #[cfg(feature = "defmt")]
                impl rs_matter_crate::reexport::defmt::Format for WithStringMember<'_> {
                    fn format(&self, f: rs_matter_crate::reexport::defmt::Formatter<'_>) {
                        rs_matter_crate::reexport::defmt::write!(f, "{} {{", "WithStringMember");
                        match self.short_string() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "short_string", value)
                            }
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "short_string",
                                e.code()
                            ),
                        }
                        match self.long_string() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "long_string", value)
                            }
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "long_string",
                                e.code()
                            ),
                        }
                        match self.opt_str() {
                            Ok(Some(value)) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: Some({:?}),", "opt_str", value)
                            }
                            Ok(None) => rs_matter_crate::reexport::defmt::write!(f, "{}: None,", "opt_str"),
                            Err(e) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: ??? {:?},", "opt_str", e.code())
                            }
                        }
                        match self.opt_nul_str() {
                            Ok(Some(value)) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: Some({:?}),", "opt_nul_str", value)
                            }
                            Ok(None) => rs_matter_crate::reexport::defmt::write!(f, "{}: None,", "opt_nul_str"),
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "opt_nul_str",
                                e.code()
                            ),
                        }
                        rs_matter_crate::reexport::defmt::write!(f, "}}")
                    }
                }
            )
        );

        // panic!("====\n{}\n====", &struct_tags(cluster, &context));

        assert_tokenstreams_eq!(
            &struct_tags(&cluster.entities.structs, &context),
            &quote!(
                #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                #[cfg_attr(feature = "defmt", derive(rs_matter_crate::reexport::defmt::Format))]
                #[repr(u8)]
                pub enum WithStringMemberTag {
                    ShortString = 1,
                    LongString = 2,
                    OptStr = 3,
                    OptNulStr = 4,
                }
            )
        );
    }

    #[test]
    fn struct_fields_octet_string() {
        let idl = parse_idl(
            "
              cluster TestForStructs = 1 {
                struct WithStringMember {
                  octet_string<16> short_string = 1;
                  long_octet_string<512> long_string = 2;
                  optional octet_string<32> opt_str = 3;
                  optional nullable long_octet_string<512> opt_nul_str = 4;
                }
              }
            ",
        );

        let cluster = get_cluster_named(&idl, "TestForStructs").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &structs(cluster, &context));

        assert_tokenstreams_eq!(
            &structs(
                &cluster.entities.structs,
                &EntityContext::new(Some(&cluster.entities), &idl.globals),
                &context
            ),
            &quote!(
                #[derive(PartialEq, Eq, Clone, Hash)]
                pub struct WithStringMember<'a>(rs_matter_crate::tlv::TLVElement<'a>);
                impl<'a> WithStringMember<'a> {
                    #[doc = "Create a new instance"]
                    pub const fn new(element: rs_matter_crate::tlv::TLVElement<'a>) -> Self {
                        Self(element)
                    }
                    #[doc = "Return the underlying TLV element"]
                    pub const fn tlv_element(&self) -> &rs_matter_crate::tlv::TLVElement<'a> {
                        &self.0
                    }
                    pub fn short_string(
                        &self,
                    ) -> Result<rs_matter_crate::tlv::OctetStr<'_>, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(1)?)
                    }
                    pub fn long_string(
                        &self,
                    ) -> Result<rs_matter_crate::tlv::OctetStr<'_>, rs_matter_crate::error::Error> {
                        rs_matter_crate::tlv::FromTLV::from_tlv(&self.0.structure()?.ctx(2)?)
                    }
                    pub fn opt_str(
                        &self,
                    ) -> Result<Option<rs_matter_crate::tlv::OctetStr<'_>>, rs_matter_crate::error::Error> {
                        let element = self.0.structure()?.find_ctx(3)?;
                        if element.is_empty() {
                            Ok(None)
                        } else {
                            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
                        }
                    }
                    pub fn opt_nul_str(
                        &self,
                    ) -> Result<
                        Option<rs_matter_crate::tlv::Nullable<rs_matter_crate::tlv::OctetStr<'_>>>,
                        rs_matter_crate::error::Error,
                    > {
                        let element = self.0.structure()?.find_ctx(4)?;
                        if element.is_empty() {
                            Ok(None)
                        } else {
                            Ok(Some(rs_matter_crate::tlv::FromTLV::from_tlv(&element)?))
                        }
                    }
                }
                impl<'a> rs_matter_crate::tlv::FromTLV<'a> for WithStringMember<'a> {
                    fn from_tlv(
                        element: &rs_matter_crate::tlv::TLVElement<'a>,
                    ) -> Result<Self, rs_matter_crate::error::Error> {
                        Ok(Self::new(element.clone()))
                    }
                }
                impl rs_matter_crate::tlv::ToTLV for WithStringMember<'_> {
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
                impl core::fmt::Debug for WithStringMember<'_> {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(f, "{} {{", "WithStringMember")?;
                        match self.short_string() {
                            Ok(value) => write!(f, "{}: {:?},", "short_string", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "short_string", e.code())?,
                        }
                        match self.long_string() {
                            Ok(value) => write!(f, "{}: {:?},", "long_string", value)?,
                            Err(e) => write!(f, "{}: ??? {:?},", "long_string", e.code())?,
                        }
                        match self.opt_str() {
                            Ok(Some(value)) => write!(f, "{}: Some({:?}),", "opt_str", value)?,
                            Ok(None) => write!(f, "{}: None,", "opt_str")?,
                            Err(e) => write!(f, "{}: ??? {:?},", "opt_str", e.code())?,
                        }
                        match self.opt_nul_str() {
                            Ok(Some(value)) => write!(f, "{}: Some({:?}),", "opt_nul_str", value)?,
                            Ok(None) => write!(f, "{}: None,", "opt_nul_str")?,
                            Err(e) => write!(f, "{}: ??? {:?},", "opt_nul_str", e.code())?,
                        }
                        write!(f, "}}")
                    }
                }
                #[cfg(feature = "defmt")]
                impl rs_matter_crate::reexport::defmt::Format for WithStringMember<'_> {
                    fn format(&self, f: rs_matter_crate::reexport::defmt::Formatter<'_>) {
                        rs_matter_crate::reexport::defmt::write!(f, "{} {{", "WithStringMember");
                        match self.short_string() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "short_string", value)
                            }
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "short_string",
                                e.code()
                            ),
                        }
                        match self.long_string() {
                            Ok(value) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: {:?},", "long_string", value)
                            }
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "long_string",
                                e.code()
                            ),
                        }
                        match self.opt_str() {
                            Ok(Some(value)) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: Some({:?}),", "opt_str", value)
                            }
                            Ok(None) => rs_matter_crate::reexport::defmt::write!(f, "{}: None,", "opt_str"),
                            Err(e) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: ??? {:?},", "opt_str", e.code())
                            }
                        }
                        match self.opt_nul_str() {
                            Ok(Some(value)) => {
                                rs_matter_crate::reexport::defmt::write!(f, "{}: Some({:?}),", "opt_nul_str", value)
                            }
                            Ok(None) => rs_matter_crate::reexport::defmt::write!(f, "{}: None,", "opt_nul_str"),
                            Err(e) => rs_matter_crate::reexport::defmt::write!(
                                f,
                                "{}: ??? {:?},",
                                "opt_nul_str",
                                e.code()
                            ),
                        }
                        rs_matter_crate::reexport::defmt::write!(f, "}}")
                    }
                }
            )
        );

        // panic!("====\n{}\n====", &struct_tags(cluster, &context));

        assert_tokenstreams_eq!(
            &struct_tags(&cluster.entities.structs, &context),
            &quote!(
                #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
                #[cfg_attr(feature = "defmt", derive(rs_matter_crate::reexport::defmt::Format))]
                #[repr(u8)]
                pub enum WithStringMemberTag {
                    ShortString = 1,
                    LongString = 2,
                    OptStr = 3,
                    OptNulStr = 4,
                }
            )
        );
    }
}
