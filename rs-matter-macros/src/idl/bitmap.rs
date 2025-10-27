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

//! A module for generating Rust types corresponding to bitmap definitions in an IDL cluster.

use proc_macro2::{Literal, TokenStream};

use quote::quote;

use super::id::{ident, idl_id_to_constant_name};
use super::parser::{Bitmap, EntityContext};
use super::IdlGenerateContext;

/// Create the token stream corresponding to all bitmap definitions in the provided IDL cluster.
pub fn bitmaps(entities: &EntityContext, context: &IdlGenerateContext) -> TokenStream {
    let bitmaps = entities.bitmaps().map(|c| bitmap(c, context));

    quote!(
        #(#bitmaps)*
    )
}

/// Create the token stream corresponding to a bitmap definition.
fn bitmap(b: &Bitmap, context: &IdlGenerateContext) -> TokenStream {
    let base_type = match b.base_type.as_ref() {
        "bitmap8" => quote!(u8),
        "bitmap16" => quote!(u16),
        "bitmap32" => quote!(u32),
        "bitmap64" => quote!(u64),
        other => panic!("Unknown bitmap base type {other}"),
    };
    let name = ident(&b.id);

    let items = b
        .entries
        .iter()
        .map(|c| {
            let constant_name = ident(&idl_id_to_constant_name(&c.id));
            let constant_value = Literal::i64_unsuffixed(c.code as i64);
            quote!(
              const #constant_name = #constant_value;
            )
        })
        .collect::<Vec<_>>();

    let krate = context.rs_matter_crate.clone();

    // The Matter C++ integration tests do expect our bitflags to preserve any set bits
    // even if these bits are not named / documented
    //
    // Hence the `const _INTERNAL_ALL_BITS = !0;` at the end of the bitflags definition, as per
    // https://docs.rs/bitflags/latest/bitflags/#externally-defined-flags
    //
    // Note also that the `defmt` version of `bitflags!` does not support the `const _ =` syntax,
    // and therefore we use the `_INTERNAL_ALL_BITS` named constant instead.

    quote!(
        #[cfg(not(feature = "defmt"))]
        #krate::reexport::bitflags::bitflags! {
            #[repr(transparent)]
            #[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
            pub struct #name: #base_type {
                #(#items)*

                const _INTERNAL_ALL_BITS = !0;
            }
        }

        #[cfg(feature = "defmt")]
        #krate::reexport::defmt::bitflags! {
            #[repr(transparent)]
            #[derive(Default)]
            pub struct #name: #base_type {
                #(#items)*

                const _INTERNAL_ALL_BITS = !0;
            }
        }

        #krate::bitflags_tlv!(#name, #base_type);
    )
}

#[cfg(test)]
mod test {
    use assert_tokenstreams_eq::assert_tokenstreams_eq;

    use quote::quote;

    use super::bitmaps;
    use crate::idl::parser::EntityContext;
    use crate::idl::tests::{get_cluster_named, parse_idl};
    use crate::idl::IdlGenerateContext;

    #[test]
    fn test_bitmaps() {
        let idl = parse_idl(
            "
              bitmap GlobalBitmap : bitmap8 {
                kGlobal = 0x1;
              }
              cluster OnOff = 6 {
                revision 6;

                bitmap Feature : bitmap32 {
                  kLighting = 0x1;
                  kDeadFrontBehavior = 0x2;
                  kOffOnly = 0x4;
                }

                bitmap OnOffControlBitmap : bitmap8 {
                  kAcceptOnlyWhenOn = 0x1;
                }

                shared bitmap SharedBitmap : bitmap8 {
                  kShared = 0x1;
                }
              }
        ",
        );
        let cluster = get_cluster_named(&idl, "OnOff").expect("Cluster exists");
        let context = IdlGenerateContext::new("rs_matter_crate");

        // panic!("====\n{}\n====", &bitmaps(cluster, &context));

        assert_tokenstreams_eq!(
            &bitmaps(
                &EntityContext::new(Some(&cluster.entities), &idl.globals),
                &context
            ),
            &quote!(
                #[cfg(not(feature = "defmt"))]
                rs_matter_crate::reexport::bitflags::bitflags! { # [repr (transparent)] # [derive (Default , Debug , Copy , Clone , Eq , PartialEq , Hash)] pub struct Feature : u32 { const LIGHTING = 1 ; const DEAD_FRONT_BEHAVIOR = 2 ; const OFF_ONLY = 4 ; const _INTERNAL_ALL_BITS = !0 ; } }
                #[cfg(feature = "defmt")]
                rs_matter_crate::reexport::defmt::bitflags! { # [repr (transparent)] # [derive (Default)] pub struct Feature : u32 { const LIGHTING = 1 ; const DEAD_FRONT_BEHAVIOR = 2 ; const OFF_ONLY = 4 ; const _INTERNAL_ALL_BITS = !0 ; } }
                rs_matter_crate::bitflags_tlv!(Feature, u32);
                #[cfg(not(feature = "defmt"))]
                rs_matter_crate::reexport::bitflags::bitflags! { # [repr (transparent)] # [derive (Default , Debug , Copy , Clone , Eq , PartialEq , Hash)] pub struct OnOffControlBitmap : u8 { const ACCEPT_ONLY_WHEN_ON = 1 ; const _INTERNAL_ALL_BITS = !0 ; } }
                #[cfg(feature = "defmt")]
                rs_matter_crate::reexport::defmt::bitflags! { # [repr (transparent)] # [derive (Default)] pub struct OnOffControlBitmap : u8 { const ACCEPT_ONLY_WHEN_ON = 1 ; const _INTERNAL_ALL_BITS = !0 ; } }
                rs_matter_crate::bitflags_tlv!(OnOffControlBitmap, u8);
                #[cfg(not(feature = "defmt"))]
                rs_matter_crate::reexport::bitflags::bitflags! { # [repr (transparent)] # [derive (Default , Debug , Copy , Clone , Eq , PartialEq , Hash)] pub struct GlobalBitmap : u8 { const GLOBAL = 1 ; const _INTERNAL_ALL_BITS = ! 0 ; } }
                #[cfg(feature = "defmt")]
                rs_matter_crate::reexport::defmt::bitflags! { # [repr (transparent)] # [derive (Default)] pub struct GlobalBitmap : u8 { const GLOBAL = 1 ; const _INTERNAL_ALL_BITS = ! 0 ; } }
                rs_matter_crate::bitflags_tlv!(GlobalBitmap, u8);
                #[cfg(not(feature = "defmt"))]
                rs_matter_crate::reexport::bitflags::bitflags! { # [repr (transparent)] # [derive (Default , Debug , Copy , Clone , Eq , PartialEq , Hash)] pub struct SharedBitmap : u8 { const SHARED = 1 ; const _INTERNAL_ALL_BITS = ! 0 ; } }
                #[cfg(feature = "defmt")]
                rs_matter_crate::reexport::defmt::bitflags! { # [repr (transparent)] # [derive (Default)] pub struct SharedBitmap : u8 { const SHARED = 1 ; const _INTERNAL_ALL_BITS = ! 0 ; } }
                rs_matter_crate::bitflags_tlv!(SharedBitmap, u8);
            )
        );
    }
}
