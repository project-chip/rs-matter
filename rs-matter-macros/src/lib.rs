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
use rs_matter_data_model::CSA_STANDARD_CLUSTERS_IDL;
use rs_matter_macros_impl::idl::{cluster, IdlGenerateContext};
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

#[proc_macro_derive(ToTLV, attributes(tlvargs, tagval, enumval))]
pub fn derive_totlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    rs_matter_macros_impl::tlv::derive_totlv(ast, get_crate_name()).into()
}

#[proc_macro_derive(FromTLV, attributes(tlvargs, tagval, enumval))]
pub fn derive_fromtlv(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    rs_matter_macros_impl::tlv::derive_fromtlv(ast, get_crate_name()).into()
}

#[derive(Debug)]
struct MatterImportArgs {
    // Crate name to refer to for `rs-matter`
    rs_matter_crate: String,

    // What clusters to import. If the set is empty, all clusters will be imported
    clusters: HashSet<String>,
}

impl Parse for MatterImportArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut clusters = HashSet::new();

        // Argument is "[Cluster1[, Cluster2, ...]]"
        while !input.is_empty() {
            let cluster: Ident = input.parse()?;

            clusters.insert(cluster.to_string());

            if !input.is_empty() {
                let punct = input.parse::<Punct>()?;
                if punct.as_char() != ',' {
                    return Err(syn::Error::new(
                        punct.span(),
                        "Expected a comma between cluster names",
                    ));
                }
            }
        }

        Ok(MatterImportArgs {
            rs_matter_crate: get_crate_name(),
            clusters,
        })
    }
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

    let idl = rs_matter_data_model::idl::Idl::parse(CSA_STANDARD_CLUSTERS_IDL.into()).unwrap();
    let context = IdlGenerateContext::new(input.rs_matter_crate);

    let clusters = idl
        .clusters
        .iter()
        .filter(|c| input.clusters.is_empty() || input.clusters.contains(&c.id))
        .map(|c| cluster(c, &context));

    quote!(
        // IDL-generated code:
        #(#clusters)*
    )
    .into()
}
