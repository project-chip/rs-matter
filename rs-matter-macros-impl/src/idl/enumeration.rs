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

//! A module for generating Rust types corresponding to enum definitions in an IDL cluster.

use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::quote;

use rs_matter_data_model::{Cluster, Enum};

use super::id::idl_id_to_enum_variant_name;
use super::IdlGenerateContext;

/// Create the token stream corresponding to all enum definitions in the provided IDL cluster.
pub fn enums(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let enums = cluster.enums.iter().map(|c| enumeration(c, context));

    quote!(
        #(#enums)*
    )
}

/// Create the token stream corresponding to an enum definition.
///
/// Essentially `enum Foo { kValue.... = ...}`
fn enumeration(e: &Enum, context: &IdlGenerateContext) -> TokenStream {
    let base_type = match e.base_type.as_ref() {
        "enum8" => quote!(u8),
        "enum16" => quote!(u16),
        other => panic!("Unknown enumeration base type {}", other),
    };
    let name = Ident::new(&e.id, Span::call_site());

    let items = e.entries.iter().map(|c| {
        let constant_name = Ident::new(&idl_id_to_enum_variant_name(&c.id), Span::call_site());
        let constant_value = Literal::i64_unsuffixed(c.code as i64);
        quote!(
            #[enumval(#constant_value)]
            #constant_name = #constant_value
        )
    });
    let krate = context.rs_matter_crate.clone();

    quote!(
        #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash, #krate::tlv::FromTLV, #krate::tlv::ToTLV)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        #[repr(#base_type)]
        pub enum #name {
            #(#items),*
        }
    )
}
