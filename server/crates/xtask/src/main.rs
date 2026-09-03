//! Repository tasks. `cargo run -p xtask -- gen-names` regenerates
//! `matter-names/src/generated.rs` from the CSA `.matter` IDL.

use std::process::ExitCode;

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("gen-names") => match gen_names() {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("gen-names: {e}");
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!("unknown task {other:?}; available: gen-names");
            ExitCode::FAILURE
        }
    }
}

fn gen_names() -> Result<String, String> {
    let idl_path = matter_names::codegen::idl_path();
    let idl = std::fs::read_to_string(&idl_path)
        .map_err(|e| format!("cannot read {}: {e}", idl_path.display()))?;
    let out = matter_names::codegen::generate(&idl)?;
    let dest = matter_names::codegen::generated_path();
    std::fs::write(&dest, &out).map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
    Ok(format!("wrote {} ({} bytes)", dest.display(), out.len()))
}
