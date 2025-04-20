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

use rs_matter_data_model::{Bitmap, Cluster};

use crate::idl::id::idl_id_to_constant_name;

use super::IdlGenerateContext;

pub fn bitmaps(cluster: &Cluster, context: &IdlGenerateContext) -> TokenStream {
    let bitmaps = cluster.bitmaps.iter().map(|c| bitmap(c, context));

    quote!(
        #(#bitmaps)*
    )
}

/// Creates the token stream corresponding to a bitmap definition.
fn bitmap(b: &Bitmap, context: &IdlGenerateContext) -> TokenStream {
    let base_type = match b.base_type.as_ref() {
        "bitmap8" => quote!(u8),
        "bitmap16" => quote!(u16),
        "bitmap32" => quote!(u32),
        "bitmap64" => quote!(u64),
        other => panic!("Unknown bitmap base type {}", other),
    };
    let name = Ident::new(&b.id, Span::call_site());

    let items = b
        .entries
        .iter()
        .map(|c| {
            let constant_name = Ident::new(&idl_id_to_constant_name(&c.id), Span::call_site());
            let constant_value = Literal::i64_unsuffixed(c.code as i64);
            quote!(
              const #constant_name = #constant_value;
            )
        })
        .collect::<Vec<_>>();

    let krate = context.rs_matter_crate.clone();

    quote!(
        #[cfg(not(feature = "defmt"))]
        bitflags::bitflags! {
            #[repr(transparent)]
            #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
            pub struct #name: #base_type {
                #(#items)*
            }
        }

        #[cfg(feature = "defmt")]
        defmt::bitflags! {
            #[repr(transparent)]
            #[derive(Default)]
            pub struct #name: #base_type {
                #(#items)*
            }
        }

        #krate::bitflags_tlv!(#name, #base_type);
    )
}
