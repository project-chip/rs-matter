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
    crate::tlv::derive_fromtlv(ast, tlv_crate_path()).into()
}

/// Generate code that derives `ToTLV` for the provided Rust type.
#[proc_macro_derive(ToTLV, attributes(tlvargs, tagval, enumval))]
pub fn derive_totlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    crate::tlv::derive_totlv(ast, tlv_crate_path()).into()
}

/// Return the path to the `rs-matter-tlv` crate, as seen from the crate being compiled
///
/// That is `crate` in `rs-matter-tlv` itself, `::rs_matter_tlv` in the crates that
/// depend on it (possibly renamed), and `::rs_matter::tlv` in the crates that only
/// depend on the `rs-matter` facade.
fn tlv_crate_path() -> String {
    use proc_macro_crate::{crate_name, FoundCrate};

    match crate_name("rs-matter-tlv") {
        Ok(FoundCrate::Itself) => "crate".into(),
        Ok(FoundCrate::Name(name)) => format!("::{name}"),
        Err(_) => match crate_name("rs-matter") {
            Ok(FoundCrate::Name(name)) => format!("::{name}::tlv"),
            _ => {
                eprintln!("Warning: neither `rs-matter-tlv` nor `rs-matter` found; defaulting to `crate::tlv`");
                "crate::tlv".into()
            }
        },
    }
}
