use criterion::{black_box, criterion_group, criterion_main, Criterion};
use matter_idl_parser::Idl;
use miette::GraphicalReportHandler;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("load example client clusters", |b| {
        b.iter(|| {
            if let Err(e) = Idl::parse(black_box(include_str!("../sample-clusters.matter").into()))
            {
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
