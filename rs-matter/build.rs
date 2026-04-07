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
use std::path::PathBuf;

use quote::quote;
use rs_matter_macros_impl::{
    cluster, globals, Idl, IdlGenerateContext, CSA_STANDARD_CLUSTERS_IDL_V1_4_2_0,
};

/// Clusters to generate code for.
/// This list matches the previous `import!()` invocation in `src/dm/clusters.rs`.
const CLUSTERS: &[&str] = &[
    "AdministratorCommissioning",
    "AccessControl",
    "BasicInformation",
    "BridgedDeviceBasicInformation",
    "ContentLauncher",
    "Descriptor",
    "EthernetNetworkDiagnostics",
    "GeneralDiagnostics",
    "GeneralCommissioning",
    "GroupKeyManagement",
    "Groups",
    "KeypadInput",
    "LevelControl",
    "MediaPlayback",
    "NetworkCommissioning",
    "OnOff",
    "OperationalCredentials",
    "WakeOnLan",
    "ThreadNetworkDiagnostics",
    "UnitTesting",
    "WiFiNetworkDiagnostics",
];

fn main() {
    // Tell cargo to rerun if the IDL files change
    println!(
        "cargo:rerun-if-changed={}",
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../rs-matter-macros-impl/src/idl/parser")
            .display()
    );

    let idl_file = CSA_STANDARD_CLUSTERS_IDL_V1_4_2_0;

    let idl = match Idl::parse(idl_file.into()) {
        Ok(result) => result,
        Err(e) => {
            let span_bytes = &idl_file.as_bytes()[e.error_location.offset()..];
            panic!(
                "Parser failed with {:?}, at\n===\n{}\n===\n",
                e,
                core::str::from_utf8(&span_bytes[..span_bytes.len().min(256)]).unwrap()
            );
        }
    };

    // When building inside rs-matter itself, the crate name is "crate"
    let context = IdlGenerateContext::new("crate");

    let cluster_filter: HashSet<&str> = CLUSTERS.iter().copied().collect();

    for name in &cluster_filter {
        if !idl.clusters.iter().any(|c| c.id == *name) {
            panic!("Cluster {name} not found in the IDL");
        }
    }

    let clusters = idl
        .clusters
        .iter()
        .filter(|c| cluster_filter.contains(c.id.as_str()))
        .map(|c| cluster(c, &idl.globals, &context));
    let globals_code = globals(&idl.globals, &context);

    let result = quote!(
        // IDL-generated code (via build.rs):
        #globals_code

        #(#clusters)*
    );

    // Format with prettyplease for readable output
    let file = syn::parse2(result).expect("Generated code is not valid Rust");
    let formatted = prettyplease::unparse(&file);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out_dir.join("clusters_generated.rs"), formatted).unwrap();
}
