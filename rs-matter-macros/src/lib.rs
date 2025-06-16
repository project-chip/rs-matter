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
use proc_macro2::{Ident, Punct};

use quote::quote;

use crate::idl::{cluster, IdlGenerateContext, CSA_STANDARD_CLUSTERS_IDL};

use syn::{parse::Parse, parse_macro_input, DeriveInput, Token};

mod idl;
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

/// Generate code for one or more Matter cluster definitions as specified in the Matter IDL/ZAP file.
///
/// The IDL file used is rs_matter_data_model::CSA_STANDARD_CLUSTERS_IDL, so
/// at this time only "standard" clusters can be imported.
///
/// `import!(OnOff)` imports the OnOff cluster
#[proc_macro]
pub fn import(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as MatterImportArgs);

    let time = std::time::SystemTime::now();

    let idl = crate::idl::Idl::parse(CSA_STANDARD_CLUSTERS_IDL.into()).unwrap();

    let elapsed = time
        .elapsed()
        .unwrap_or(core::time::Duration::from_millis(0));

    if input.print_timings {
        eprintln!("Elapsed time to parse IDL: {}ms", elapsed.as_millis());
    }

    if let Some(cap_parse) = input.cap_parse {
        if elapsed > cap_parse {
            panic!(
                "Parsing the IDL took too long, exceeding the cap of {}ms.",
                cap_parse.as_millis()
            );
        }
    }

    let time = std::time::SystemTime::now();

    let context = IdlGenerateContext::new(input.rs_matter_crate);

    for cluster in input.clusters.iter() {
        if !idl.clusters.iter().any(|c| &c.id == cluster) {
            panic!("Cluster {cluster} not found in the IDL");
        }
    }

    let clusters = idl
        .clusters
        .iter()
        .filter(|c| input.clusters.is_empty() || input.clusters.contains(&c.id))
        .map(|c| cluster(c, &context));

    let result = quote!(
        // IDL-generated code:
        #(#clusters)*
    )
    .into();

    let elapsed = time
        .elapsed()
        .unwrap_or(core::time::Duration::from_millis(0));

    if input.print_timings {
        eprintln!("Elapsed time to generate code: {}ms", elapsed.as_millis());
    }

    if let Some(cap_codegen) = input.cap_codegen {
        if elapsed > cap_codegen {
            panic!(
                "Code generation took too long, exceeding the cap of {}ms.",
                cap_codegen.as_millis()
            );
        }
    }

    result
}

#[derive(Debug)]
struct MatterImportArgs {
    /// Crate name to refer to for `rs-matter`
    rs_matter_crate: String,

    /// What clusters to import. If the set is empty, all clusters will be imported
    clusters: HashSet<String>,

    /// Whether to print timings for the macro execution
    print_timings: bool,

    /// Optional time limit for parsing
    cap_parse: Option<core::time::Duration>,

    /// Optional time limit for code generation
    cap_codegen: Option<core::time::Duration>,
}

impl Parse for MatterImportArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut clusters = HashSet::new();

        let mut print_timings = false;
        let mut cap_parse = None;
        let mut cap_codegen = None;

        let mut parse_timings = false;

        // Argument is "[Cluster1[[,] Cluster2[,] ...][; [print_timings][[,] cap_parse=XXX][[,] cap_codegen=YYY]]"
        while !input.is_empty() {
            if input.peek(Token![,]) {
                input.parse::<Punct>()?;
            } else if input.peek(Token![;]) {
                input.parse::<Punct>()?;
                parse_timings = true;
                break;
            } else {
                let cluster: Ident = input.parse()?;

                clusters.insert(cluster.to_string());
            }
        }

        if parse_timings {
            while !input.is_empty() {
                if input.peek(Token![,]) {
                    input.parse::<Punct>()?;
                } else {
                    let param: Ident = input.parse()?;

                    match param.to_string().as_str() {
                        "print_timings" => {
                            print_timings = true;
                        }
                        "cap_parse" => {
                            input.parse::<Token![=]>()?;

                            let value = input.parse::<syn::LitInt>()?;
                            cap_parse = Some(core::time::Duration::from_millis(
                                str::parse::<u64>(value.base10_digits()).unwrap(),
                            ));
                        }
                        "cap_codegen" => {
                            input.parse::<Token![=]>()?;

                            let value = input.parse::<syn::LitInt>()?;
                            cap_codegen = Some(core::time::Duration::from_millis(
                                str::parse::<u64>(value.base10_digits()).unwrap(),
                            ));
                        }
                        _ => {
                            return Err(syn::Error::new(
                                param.span(),
                                "Unknown parameter, expected 'print_timings', 'cap_parse', or 'cap_codegen'",
                            ));
                        }
                    }
                }
            }
        }

        Ok(MatterImportArgs {
            rs_matter_crate: get_crate_name(),
            clusters,
            print_timings,
            cap_parse,
            cap_codegen,
        })
    }
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
