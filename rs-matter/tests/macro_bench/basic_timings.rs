//! This test is used to benchmark the time it takes to parse and codegen the `import!` macro.

 // TODO: No longer necessary with #342
rs_matter::import!(
    // AdministratorCommissioning, Removed due to use of globals
    AccessControl,
    BasicInformation,
    Descriptor,
    EthernetNetworkDiagnostics,
    GeneralDiagnostics,
    GeneralCommissioning,
    GroupKeyManagement,
    NetworkCommissioning,
    OnOff,
    // OperationalCredentials, Removed due to use of globals
    ThreadNetworkDiagnostics,
    WiFiNetworkDiagnostics;
    print_timings,
    cap_parse = 300,
    cap_codegen = 400
);

// `trybench` wants this
fn main() {
}
