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

use std::collections::HashSet;

use proc_macro::TokenStream;
use proc_macro2::{Group, Ident, Punct};
use quote::quote;
use rs_matter_data_model::CSA_STANDARD_CLUSTERS_IDL;
use rs_matter_macros_impl::idl::server_side_cluster_generate;
use syn::{parse::Parse, parse_macro_input, DeriveInput};

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

#[proc_macro_derive(ToTLV, attributes(tlvargs, tagval))]
pub fn derive_totlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    rs_matter_macros_impl::tlv::derive_totlv(ast, get_crate_name()).into()
}

#[proc_macro_derive(FromTLV, attributes(tlvargs, tagval))]
pub fn derive_fromtlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    rs_matter_macros_impl::tlv::derive_fromtlv(ast, get_crate_name()).into()
}

#[derive(Debug)]
struct MatterIdlImportArgs {
    // What clusters to import. Non-empty list if
    // a clusters argument was given
    clusters: Option<HashSet<String>>,
}

impl Parse for MatterIdlImportArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let clusters = if !input.is_empty() {
            // Argument is "clusters = [....]"
            //
            // Token stream looks like:
            //
            // TokenStream [
            //     Ident {
            //         ident: "clusters",
            //         span: #0 bytes(224041..224049),
            //     },
            //     Punct {
            //         ch: '=',
            //         spacing: Alone,
            //         span: #0 bytes(224050..224051),
            //     },
            //     Group {
            //         delimiter: Bracket,
            //         stream: TokenStream [
            //             Literal {
            //                 kind: Str,
            //                 symbol: "OnOff",
            //                 suffix: None,
            //                 span: #0 bytes(224053..224060),
            //             },
            //         ],
            //         span: #0 bytes(224052..224061),
            //     },
            //  ]

            assert_eq!(input.parse::<Ident>()?.to_string(), "clusters");
            assert_eq!(input.parse::<Punct>()?.as_char(), '=');

            Some(
                input
                    .parse::<Group>()?
                    .stream()
                    .into_iter()
                    .map(|item| match item {
                        proc_macro2::TokenTree::Literal(l) => {
                            let repr = l.to_string();
                            // Representation  includes quotes. Remove them
                            // TODO: this does NOT support `r"..."` or similar, however
                            //       those should generally not be needed
                            repr[1..(repr.len() - 1)].to_owned()
                        }
                        _ => panic!("Expected a token"),
                    })
                    .collect::<HashSet<_>>(),
            )
        } else {
            None
        };

        if let Some(ref values) = clusters {
            if values.is_empty() {
                panic!("Input clusters MUST be non-empty. If you want no filtering, omit this argument.");
            }
        }

        Ok(MatterIdlImportArgs { clusters })
    }
}

/// Imports a matter IDL and generates code for it
///
/// Files are assumed to be located inside `RS_MATTER_IDL_DIR` from the environment.
/// Generally this means that `.cargo/config.toml` should include something like
/// `RS_MATTER_IDL_DIR = { value="idl", relative=true }`
///
/// `idl_import!("file.matter")` imports the entire file.
///
/// `idl_import!("file.matter", clusters=["A", "B", "C"])` restricts the
/// import to the given clusters
#[proc_macro]
pub fn idl_import(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as MatterIdlImportArgs);

    let idl = rs_matter_data_model::idl::Idl::parse(CSA_STANDARD_CLUSTERS_IDL.into()).unwrap();

    let streams = idl
        .clusters
        .iter()
        .filter(|c| match input.clusters {
            Some(ref v) => v.contains(&c.id),
            None => true,
        })
        .map(server_side_cluster_generate);

    quote!(
        // IDL-generated code:
        #(#streams)*
    )
    .into()
}
