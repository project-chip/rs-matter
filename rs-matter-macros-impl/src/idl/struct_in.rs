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

use rs_matter_data_model::{Cluster, Struct, StructField};

use super::field::field_type;
use super::id::{idl_field_name_to_rs_name, idl_field_name_to_rs_type_name};
use super::IdlGenerateContext;

pub fn struct_tags(cluster: &Cluster) -> TokenStream {
    let struct_tags = cluster.structs.iter().map(struct_tag);

    quote!(
        #(#struct_tags)*
    )
}

pub fn structs(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let structs = cluster.structs.iter().map(|s| structure(s, context));

    quote!(
        #(#structs)*
    )
}

/// Creates the token stream corresponding to a structure
/// tag definition.
///
/// Provides the raw `enum FooTag { }` declaration.
pub fn struct_tag(s: &Struct) -> TokenStream {
    let name = Ident::new(&format!("{}Tag", s.id), Span::call_site());

    let fields = s.fields.iter().map(struct_tag_field_definition);

    quote!(
        #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        #[repr(u8)]
        pub enum #name { #(#fields)* }
    )
}

/// Creates the token stream corresponding to a structure
/// definition.
///
/// Provides the raw `struct Foo<'a>(TLVElement<'a>); impl<'a> Foo<'a> { ... }` declaration.
fn structure(s: &Struct, context: &IdlGenerateContext) -> TokenStream {
    // NOTE: s.is_fabric_scoped not directly handled as the IDL
    //       will have fabric_idx with ID 254 automatically added.

    let name = Ident::new(&s.id, Span::call_site());

    let fields = s.fields.iter().map(|f| struct_field_definition(f, context));
    let krate = context.rs_matter_crate.clone();

    quote!(
        #[derive(Debug, PartialEq, Eq, Clone, Hash)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct #name<'a>(#krate::tlv::TLVElement<'a>);

        impl<'a> #name<'a> {
            #[doc="Create a new instance of #name"]
            pub const fn new(element: #krate::tlv::TLVElement<'a>) -> Self {
                Self(element)
            }

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
    )
}

fn struct_field_definition(f: &StructField, context: &IdlGenerateContext) -> TokenStream {
    // f.fabric_sensitive does not seem to have any specific meaning so we ignore it
    // fabric_sensitive seems to be specific to fabric_scoped structs

    let doc_comment = struct_field_comment(f);
    let krate = context.rs_matter_crate.clone();

    let code = Literal::u8_unsuffixed(f.field.code as u8);
    let field_type = field_type(&f.field.data_type, f.is_nullable, f.is_optional, &krate);
    let name = Ident::new(&idl_field_name_to_rs_name(&f.field.id), Span::call_site());

    if f.is_optional {
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

fn struct_tag_field_definition(f: &StructField) -> TokenStream {
    // f.fabric_sensitive does not seem to have any specific meaning so we ignore it
    // fabric_sensitive seems to be specific to fabric_scoped structs

    let doc_comment = struct_field_comment(f);

    let code = Literal::u8_unsuffixed(f.field.code as u8);
    let name = Ident::new(
        &idl_field_name_to_rs_type_name(&f.field.id),
        Span::call_site(),
    );

    quote!(
        #doc_comment
        #name = #code,
    )
}

pub(crate) fn struct_field_comment(f: &StructField) -> TokenStream {
    match f.maturity {
        rs_matter_data_model::ApiMaturity::Provisional => quote!(#[doc="provisional"]),
        rs_matter_data_model::ApiMaturity::Internal => quote!(#[doc="internal"]),
        rs_matter_data_model::ApiMaturity::Deprecated => quote!(#[doc="deprecated"]),
        _ => quote!(),
    }
}
