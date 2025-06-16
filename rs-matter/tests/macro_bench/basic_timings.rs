//! This test is used to benchmark the time it takes to parse and codegen the `import!` macro.

rs_matter::import!(
    AdministratorCommissioning,
    AccessControl,
    BasicInformation,
    Descriptor,
    EthernetNetworkDiagnostics,
    GeneralDiagnostics,
    GeneralCommissioning,
    GroupKeyManagement,
    NetworkCommissioning,
    OnOff,
    OperationalCredentials,
    ThreadNetworkDiagnostics,
    WiFiNetworkDiagnostics;
    print_timings,
    cap_parse = 180,
    cap_codegen = 400
);

// `trybench` wants this
fn main() {
}
