use std::fs;

use clap::Parser;
use rs_matter_data_model::idl::Idl;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::prelude::*;

// Simple program parsing a IDL file
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IDL file to open
    name: String,

    /// How many time to parse this file
    #[arg(short, long, value_name = "CNT")]
    repeat_count: Option<u32>,

    #[arg(short, long)]
    log_level: Option<LevelFilter>,
}

fn main() -> miette::Result<()> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(
            stdout_log.with_filter(
                args.log_level
                    .unwrap_or(args.log_level.unwrap_or(LevelFilter::ERROR)),
            ),
        )
        .init();

    let contents = fs::read_to_string(args.name).expect("Valid input file");

    for _ in 0..args.repeat_count.unwrap_or(1) {
        Idl::parse((&*contents).into())?;
    }
    Ok(())
}
