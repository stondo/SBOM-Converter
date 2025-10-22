//! Main binary entry point for the sbom-converter.

use clap::{Parser, ValueEnum};
use sbom_converter::errors::ConverterError;
use sbom_converter::{Config, ConversionDirection};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,

    #[arg(short, long, value_enum)]
    direction: CliDirection,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long)]
    validate: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum CliDirection {
    #[value(name = "cdx-to-spdx")]
    CdxToSpdx,
    #[value(name = "spdx-to-cdx")]
    SpdxToCdx,
}

fn setup_logging(verbose: bool) {
    let filter_level = if verbose {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Warn
    };

    env_logger::Builder::new()
        .filter(None, filter_level)
        .format_timestamp(None)
        .format_target(false)
        .init();
}

fn run_app() -> Result<(), ConverterError> {
    let cli = Cli::parse();

    setup_logging(cli.verbose);

    let direction = match cli.direction {
        CliDirection::CdxToSpdx => ConversionDirection::CdxToSpdx,
        CliDirection::SpdxToCdx => ConversionDirection::SpdxToCdx,
    };

    let config = Config {
        input_file: cli.input,
        output_file: cli.output,
        direction,
        validate: cli.validate,
    };

    sbom_converter::run(config)
}

fn main() -> ExitCode {
    match run_app() {
        Ok(_) => {
            log::info!("Conversion completed successfully.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            log::error!("A fatal error occurred:");
            log::error!("{}", e);
            let mut source = std::error::Error::source(&e);
            while let Some(s) = source {
                log::error!("  Caused by: {}", s);
                source = std::error::Error::source(s);
            }
            ExitCode::FAILURE
        }
    }
}
