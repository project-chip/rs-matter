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

//! `xtask` - A utility for managing development tasks in the `rs-matter` project.

use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use env_logger::fmt::style;
use log::{Level, LevelFilter};

use crate::itest::ITests;

mod itest;
mod tlv;

/// The main command-line interface for `xtask`.
#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "`rs-matter` development tasks")]
struct Cli {
    /// Task verbosity
    #[arg(short = 'v', long, default_value = "normal")]
    verbosity: Verbosity,

    #[command(subcommand)]
    command: Command,
}

/// Available commands for `xtask`.
#[derive(Subcommand)]
enum Command {
    /// Run Chip integration tests (calls `itest-setup` and `itest-exe` commands as necessary)
    Itest {
        #[command(flatten)]
        setup_args: ItestSetupArgs,
        #[command(flatten)]
        build_args: BuildArgs,
        /// Test names to run (if empty, runs all default tests)
        tests: Vec<String>,
        /// Timeout for each test in seconds
        #[arg(long, default_value = "120")]
        timeout: u32,
        /// Skip settting up of the Chip environment (assume it's already set up)
        #[arg(long)]
        skip_setup: bool,
        /// Skip building the tested executable (assume it's already built)
        #[arg(long)]
        skip_build: bool,
    },
    /// Setup Chip environment for integration testing
    ItestSetup(ItestSetupArgs),
    /// Build the to-be-tested executable (`chip-tool-tests`)
    ItestExe(BuildArgs),
    /// Print Chip integration test tooling information
    ItestTools,
    /// Print Chip integration test packages information
    ItestPackages,
    /// Decode TLV octets
    Tlv {
        /// The TLV octets are decimal
        #[arg(short = 'd', long)]
        dec: bool,
        /// Decode a Matter-encoded certificate
        #[arg(long)]
        cert: bool,
        /// Decode a Matter-encoded certificate and encode as ASN1
        #[arg(long)]
        as_asn1: bool,
        /// A comma-separated list of TLV octets to decode (e.g., "0x01,0x02,0x03" or "1,2,3")
        tlv: String,
    },
}

impl Command {
    fn run(&self, print_cmd_output: bool) -> anyhow::Result<()> {
        match self {
            Command::ItestTools => ITests::new(workspace_dir(), print_cmd_output).print_tooling(),
            Command::ItestPackages => {
                ITests::new(workspace_dir(), print_cmd_output).print_packages()
            }
            Command::ItestSetup(args) => ITests::new(workspace_dir(), print_cmd_output)
                .setup(Some(&args.gitref), args.force_setup),
            Command::ItestExe(args) => ITests::new(workspace_dir(), print_cmd_output).build(
                &args.profile,
                &args.features,
                args.force_rebuild,
            ),
            Command::Itest {
                setup_args,
                build_args,
                tests,
                timeout,
                skip_setup,
                skip_build,
            } => {
                if !skip_setup {
                    Command::ItestExe(build_args.clone()).run(print_cmd_output)?;
                }

                if !*skip_build {
                    Command::ItestSetup(setup_args.clone()).run(print_cmd_output)?;
                }

                ITests::new(workspace_dir(), print_cmd_output).run(
                    tests,
                    *timeout,
                    &build_args.profile,
                )
            }
            Command::Tlv {
                dec,
                cert,
                as_asn1,
                tlv,
            } => tlv::decode(tlv, *dec, *cert, *as_asn1),
        }
    }
}

/// Verbosity
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Verbosity {
    /// Silent - print only errors
    #[clap(alias = "s")]
    Silent,
    /// Reduced - print only the main tasks
    #[clap(alias = "r")]
    Reduced,
    /// Normal
    #[default]
    #[clap(alias = "n")]
    Normal,
    /// Verbose - print executed commands
    #[clap(alias = "v")]
    Verbose,
    /// Chatty - print the full output of executed commands
    #[clap(alias = "c")]
    Chatty,
}

impl Verbosity {
    fn log_level(&self) -> LevelFilter {
        match self {
            Self::Silent => LevelFilter::Off,
            Self::Reduced => LevelFilter::Warn,
            Self::Normal => LevelFilter::Info,
            Self::Verbose => LevelFilter::Debug,
            Self::Chatty => LevelFilter::Trace,
        }
    }
}

/// Arguments for the `itest-setup` command
#[derive(Parser, Debug, Clone)]
struct ItestSetupArgs {
    /// Chip repository reference (branch/tag/commit)
    #[arg(long, default_value = "master")]
    gitref: String,
    /// Force setup even if cached
    #[arg(long)]
    force_setup: bool,
}

/// Arguments for the `build` command
#[derive(Parser, Debug, Clone)]
struct BuildArgs {
    /// Build profile (debug or release)
    #[arg(long, default_value = "debug")]
    profile: String,
    /// Additional cargo features
    #[arg(long)]
    features: Vec<String>,
    /// Force clean rebuild
    #[arg(long)]
    force_rebuild: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let print_cmd_output = matches!(cli.verbosity, Verbosity::Chatty);

    env_logger::builder()
        .format(|buf, record| {
            let style = match record.level() {
                Level::Trace => style::AnsiColor::Cyan.on_default(),
                Level::Debug => style::AnsiColor::Blue.on_default(),
                Level::Info => style::AnsiColor::Green.on_default(),
                Level::Warn => style::AnsiColor::Green
                    .on_default()
                    .effects(style::Effects::BOLD),
                Level::Error => style::AnsiColor::Red
                    .on_default()
                    .effects(style::Effects::BOLD),
            };

            let prefix = match record.level() {
                Level::Trace => "      >",
                Level::Debug => "    >",
                Level::Info => "  >",
                Level::Warn => ">",
                Level::Error => "!",
            };

            writeln!(buf, "{prefix} {style}{}{style:#}", record.args())
        })
        .filter_level(cli.verbosity.log_level())
        .init();

    cli.command.run(print_cmd_output)
}

fn workspace_dir() -> PathBuf {
    std::env::current_dir().unwrap()
}
