//! Main binary entry point for the sbom-converter.

use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use sbom_converter::errors::ConverterError;
use sbom_converter::formats::Format;
use sbom_converter::validation::{validate_cdx, validate_spdx};
use sbom_converter::{Config, ConversionDirection};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    // Legacy mode: if no subcommand is provided, treat as convert
    #[arg(short, long, value_name = "FILE", global = true)]
    input: Option<PathBuf>,

    #[arg(short, long, value_name = "FILE", global = true)]
    output: Option<PathBuf>,

    #[arg(short, long, value_enum, global = true)]
    direction: Option<CliDirection>,

    #[arg(
        long,
        value_enum,
        help = "Input file format (autodetect if not specified)",
        global = true
    )]
    input_format: Option<CliFormat>,

    #[arg(
        long,
        value_enum,
        help = "Output file format (autodetect if not specified)",
        global = true
    )]
    output_format: Option<CliFormat>,

    #[arg(short, long, global = true)]
    verbose: bool,

    #[arg(long, global = true)]
    validate: bool,

    #[arg(
        long,
        help = "Split vulnerabilities into separate VEX file (SPDX→CDX only)",
        global = true
    )]
    split_vex: bool,

    #[arg(
        long,
        help = "Only convert packages/libraries, skip individual files (SPDX→CDX only)",
        global = true
    )]
    packages_only: bool,

    #[arg(
        long,
        help = "Skip JSON-LD structural validation (SPDX JSON-LD only)",
        global = true
    )]
    skip_jsonld_validation: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Convert between SBOM formats
    Convert {
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        #[arg(short, long, value_enum)]
        direction: CliDirection,

        #[arg(
            long,
            value_enum,
            help = "Input file format (autodetect if not specified)"
        )]
        input_format: Option<CliFormat>,

        #[arg(
            long,
            value_enum,
            help = "Output file format (autodetect if not specified)"
        )]
        output_format: Option<CliFormat>,
    },

    /// Validate an SBOM file
    Validate {
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        #[arg(long, value_enum, help = "SBOM format (autodetect if not specified)")]
        format: Option<CliFormat>,

        #[arg(long, help = "Exit with non-zero code if errors are found")]
        fail_on_errors: bool,

        #[arg(long, help = "Disable colored output")]
        no_color: bool,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum CliFormat {
    #[value(name = "json")]
    Json,
    #[value(name = "xml")]
    Xml,
    #[value(name = "cdx")]
    Cdx,
    #[value(name = "spdx")]
    Spdx,
    #[value(name = "autodetect")]
    Autodetect,
}

#[derive(Debug, Clone, ValueEnum)]
enum CliDirection {
    #[value(name = "cdx-to-spdx")]
    CdxToSpdx,
    #[value(name = "spdx-to-cdx")]
    SpdxToCdx,
    #[value(name = "cdx-to-cdx")]
    CdxToCdx,
    #[value(name = "spdx-to-spdx")]
    SpdxToSpdx,
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

fn run_validate(
    input: PathBuf,
    format: Option<CliFormat>,
    fail_on_errors: bool,
    no_color: bool,
) -> Result<(), ConverterError> {
    // Read the file
    let content = fs::read_to_string(&input)
        .map_err(|e| ConverterError::Io(e, format!("Failed to read file: {}", input.display())))?;

    // Parse as JSON
    let value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| ConverterError::ParseError(format!("Invalid JSON: {}", e)))?;

    // Determine format
    let detected_format = if let Some(fmt) = format {
        match fmt {
            CliFormat::Cdx => "cdx",
            CliFormat::Spdx => "spdx",
            CliFormat::Json | CliFormat::Xml | CliFormat::Autodetect => {
                // Auto-detect from content
                if value.get("bomFormat").is_some() {
                    "cdx"
                } else if value.get("spdxVersion").is_some() {
                    "spdx"
                } else {
                    return Err(ConverterError::InvalidInput(
                        "Could not detect SBOM format. Use --format to specify.".to_string(),
                    ));
                }
            }
        }
    } else {
        // Auto-detect from content
        if value.get("bomFormat").is_some() {
            "cdx"
        } else if value.get("spdxVersion").is_some() {
            "spdx"
        } else {
            return Err(ConverterError::InvalidInput(
                "Could not detect SBOM format. File must have 'bomFormat' (CycloneDX) or 'spdxVersion' (SPDX) field.".to_string()
            ));
        }
    };

    // Run validation
    let mut report = if detected_format == "cdx" {
        validate_cdx(&value)
    } else {
        validate_spdx(&value)
    };

    report.file_path = Some(input.display().to_string());

    // Print report
    if no_color {
        report.print_plain();
    } else {
        report.print_colored();
    }

    // Exit with error code if requested and errors found
    if fail_on_errors && report.has_errors() {
        return Err(ConverterError::Validation(format!(
            "Validation failed with {} errors",
            report.error_count()
        )));
    }

    Ok(())
}

fn run_convert(
    input: PathBuf,
    output: PathBuf,
    direction: CliDirection,
    input_format: Option<CliFormat>,
    output_format: Option<CliFormat>,
    verbose: bool,
    validate: bool,
    split_vex: bool,
    packages_only: bool,
    skip_jsonld_validation: bool,
) -> Result<(), ConverterError> {
    let direction = match direction {
        CliDirection::CdxToSpdx => ConversionDirection::CdxToSpdx,
        CliDirection::SpdxToCdx => ConversionDirection::SpdxToCdx,
        CliDirection::CdxToCdx => ConversionDirection::CdxToSpdx, // Dummy for format conversion
        CliDirection::SpdxToSpdx => ConversionDirection::SpdxToCdx, // Dummy for format conversion
    };

    // Convert CLI format options to internal Format type
    let input_format = input_format.map(|f| match f {
        CliFormat::Json => Format::Json,
        CliFormat::Xml => Format::Xml,
        CliFormat::Cdx | CliFormat::Spdx | CliFormat::Autodetect => {
            // Autodetect from file extension
            Format::from_extension(&input).unwrap_or(Format::Json)
        }
    });

    let output_format = output_format.map(|f| match f {
        CliFormat::Json => Format::Json,
        CliFormat::Xml => Format::Xml,
        CliFormat::Cdx | CliFormat::Spdx | CliFormat::Autodetect => {
            // Autodetect from file extension
            Format::from_extension(&output).unwrap_or(Format::Json)
        }
    });

    let config = Config {
        input_file: input,
        output_file: output,
        direction,
        input_format,
        output_format,
        validate,
        split_vex,
        packages_only,
        skip_jsonld_validation,
    };

    sbom_converter::run(config)
}

fn run_app() -> Result<(), ConverterError> {
    let cli = Cli::parse();

    setup_logging(cli.verbose);

    match cli.command {
        Some(Command::Convert {
            input,
            output,
            direction,
            input_format,
            output_format,
        }) => run_convert(
            input,
            output,
            direction,
            input_format,
            output_format,
            cli.verbose,
            cli.validate,
            cli.split_vex,
            cli.packages_only,
            cli.skip_jsonld_validation,
        ),
        Some(Command::Validate {
            input,
            format,
            fail_on_errors,
            no_color,
        }) => run_validate(input, format, fail_on_errors, no_color),
        None => {
            // Legacy mode: no subcommand, use old flags
            if let (Some(input), Some(output), Some(direction)) =
                (cli.input, cli.output, cli.direction)
            {
                run_convert(
                    input,
                    output,
                    direction,
                    cli.input_format,
                    cli.output_format,
                    cli.verbose,
                    cli.validate,
                    cli.split_vex,
                    cli.packages_only,
                    cli.skip_jsonld_validation,
                )
            } else {
                eprintln!("{}", "Error: Missing required arguments".red().bold());
                eprintln!("\n{}", "Use one of:".bold());
                eprintln!(
                    "  {} convert --input <FILE> --output <FILE> --direction <DIRECTION>",
                    "sbom-converter".cyan()
                );
                eprintln!("  {} validate --input <FILE>", "sbom-converter".cyan());
                eprintln!("\nRun {} for more information", "--help".green());
                std::process::exit(1);
            }
        }
    }
}

fn main() -> ExitCode {
    match run_app() {
        Ok(()) => {
            log::info!("{}", "Conversion completed successfully.".green());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}", "[ERROR] A fatal error occurred:".red().bold());
            eprintln!("{}", format!("[ERROR] {}", e).red());
            ExitCode::FAILURE
        }
    }
}
