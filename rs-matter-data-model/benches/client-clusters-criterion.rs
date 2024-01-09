use criterion::{black_box, criterion_group, criterion_main, Criterion};
use miette::GraphicalReportHandler;
use rs_matter_data_model::idl::Idl;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("load example client clusters", |b| {
        b.iter(|| {
            if let Err(e) = Idl::parse(black_box(
                include_str!("../../idl/controller-clusters.matter").into(),
            )) {
                let mut buf = String::new();
                GraphicalReportHandler::new()
                    .render_report(&mut buf, &e)
                    .unwrap();
                eprintln!("\n{}", buf);
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
