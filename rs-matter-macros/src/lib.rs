/*
 *
 *    Copyright (c) 2022-2026 Project CHIP Authors
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

use proc_macro::TokenStream;

use syn::{parse_macro_input, DeriveInput};

mod tlv;

/// Generate code that derives `FromTLV` for the provided Rust type.
#[proc_macro_derive(FromTLV, attributes(tlvargs, tagval, enumval))]
pub fn derive_fromtlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    crate::tlv::derive_fromtlv(ast, get_crate_name()).into()
}

/// Generate code that derives `ToTLV` for the provided Rust type.
#[proc_macro_derive(ToTLV, attributes(tlvargs, tagval, enumval))]
pub fn derive_totlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    crate::tlv::derive_totlv(ast, get_crate_name()).into()
}

fn get_crate_name() -> String {
    let found_crate = proc_macro_crate::crate_name("rs-matter").unwrap_or_else(|err| {
        eprintln!("Warning: defaulting to `crate` {err}");
        proc_macro_crate::FoundCrate::Itself
    });

    match found_crate {
        proc_macro_crate::FoundCrate::Itself => String::from("crate"),
        proc_macro_crate::FoundCrate::Name(name) => name,
    }
}
