use divan::black_box;
use miette::GraphicalReportHandler;
use rs_matter_data_model::{idl::Idl, CSA_STANDARD_CLUSTERS_IDL};

fn main() {
    // Run registered benchmarks.
    divan::main();
}

// Benchmark parsing sample-clusters.matter
#[divan::bench]
fn parse_client_clusters() {
    if let Err(e) = Idl::parse(black_box(CSA_STANDARD_CLUSTERS_IDL.into())) {
        let mut buf = String::new();
        GraphicalReportHandler::new()
            .render_report(&mut buf, &e)
            .unwrap();
        eprintln!("\n{buf}");
    }
}
