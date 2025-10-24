//! Main binary entry point for the sbom-converter.

use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use sbom_converter::errors::ConverterError;
use sbom_converter::formats::Format;
use sbom_converter::validation::{validate_cdx, validate_spdx, ValidationIssue};
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

        #[arg(long, value_enum, help = "Output format for validation report", default_value = "text")]
        report_format: OutputFormat,

        #[arg(long, help = "Validate against JSON schema")]
        schema: bool,

        #[arg(long, help = "Show detected format and version")]
        show_version: bool,
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
enum OutputFormat {
    #[value(name = "text")]
    Text,
    #[value(name = "json")]
    Json,
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

/// Validate an SBOM file (JSON or XML format)
/// 
/// # Validation Approach
/// 
/// This tool uses format-aware validation:
/// 
/// ## JSON Files
/// - **Structural validation**: Parse JSON and validate against internal models
/// - **Schema validation** (with `--schema`): Validate against JSON Schema (e.g., bom-1.6.schema.json)
/// - Full validation matches CycloneDX CLI behavior
/// 
/// ## XML Files  
/// - **Structural validation**: Parse XML and validate against internal models
/// - **XSD schema validation** (with `--schema`): Validate using libxml2 against XSD schemas (e.g., bom-1.6.xsd)
/// - Matches CycloneDX CLI validation approach using XSD
/// 
/// ## Implementation
/// - **XML validation** uses libxml2 bindings for native XSD schema validation
/// - Validates namespace URI matches expected CycloneDX namespace
/// - Provides detailed error messages for schema violations
/// - Requires libxml2-devel and clang-devel system packages for building
/// 
/// ## Reference
/// - CycloneDX CLI validates JSON with JSON Schema and XML with XSD schemas
/// - See: https://github.com/CycloneDX/cyclonedx-dotnet-library/blob/main/src/CycloneDX.Core/Xml/Validator.cs
fn run_validate(
    input: PathBuf,
    format: Option<CliFormat>,
    fail_on_errors: bool,
    no_color: bool,
    output_format: OutputFormat,
    schema: bool,
    show_version: bool,
) -> Result<(), ConverterError> {
    use sbom_converter::version_detection::{detect_format, format_description};
    use sbom_converter::formats::Format;

    // Detect input format (XML or JSON)
    let input_format = Format::from_extension(&input).unwrap_or(Format::Json);
    
    // Read the file content
    let content = fs::read_to_string(&input)
        .map_err(|e| ConverterError::Io(e, format!("Failed to read file: {}", input.display())))?;

    // Parse to JSON for validation (works for both formats)
    // For XML: we parse and validate the XML structure, then extract metadata
    // For JSON: we parse the JSON directly
    let value: serde_json::Value = match input_format {
        Format::Xml => {
            // For XML files: validate XML structure by parsing it
            if !matches!(output_format, OutputFormat::Json) && !no_color {
                println!("{}", "ℹ Validating XML structure...".cyan());
            }
            
            let xml_reader = std::io::BufReader::new(content.as_bytes());
            
            // Parse XML to CdxDocument - this validates XML well-formedness and structure
            let cdx_doc = sbom_converter::formats::cdx::xml::parse(xml_reader)
                .map_err(|e| ConverterError::ParseError(format!("Invalid XML: {}", e)))?;
            
            // Convert to JSON representation for metadata extraction
            sbom_converter::formats::cdx::converter::document_to_json(&cdx_doc)
        }
        Format::Json => {
            // For JSON files: parse directly
            serde_json::from_str(&content)
                .map_err(|e| ConverterError::ParseError(format!("Invalid JSON: {}", e)))?
        }
    };

    // Detect format and version from the JSON representation
    let detected = detect_format(&value);

    if show_version {
        if matches!(output_format, OutputFormat::Json) {
            let version_info = serde_json::json!({
                "format": detected.name(),
                "version": detected.version(),
                "has_schema": detected.has_schema(),
                "schema_file": detected.schema_file(),
            });
            println!("{}", serde_json::to_string_pretty(&version_info).unwrap());
            return Ok(());
        } else {
            println!("\n{}", "Format Detection:".bold());
            println!("  Format: {}", format_description(&detected).cyan());
            if let Some(schema_file) = detected.schema_file() {
                println!("  Schema: {}", schema_file.green());
            } else {
                println!("  Schema: {}", "Not available".yellow());
            }
            println!();
        }
    }

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

    // Run structural validation
    let mut report = if detected_format == "cdx" {
        validate_cdx(&value)
    } else {
        validate_spdx(&value)
    };

    report.file_path = Some(input.display().to_string());

    // Run schema validation if requested
    // Note: JSON files are validated against JSON Schema (.schema.json files)
    //       XML files should be validated against XSD schemas (.xsd files)
    //       Currently, XML XSD validation is not implemented due to Rust ecosystem limitations
    //       XML files receive structural validation only (parsing + model validation)
    if schema {
        match input_format {
            Format::Json => {
                // JSON schema validation
                if let Some(schema_file) = detected.schema_file() {
                    let schema_path = std::path::PathBuf::from("schemas").join(schema_file);
                    if schema_path.exists() {
                        match validate_against_schema(&value, &schema_path) {
                            Ok(()) => {
                                if !matches!(output_format, OutputFormat::Json) {
                                    println!("{}", "✓ JSON Schema validation passed".green().bold());
                                }
                            }
                            Err(e) => {
                                report.add_issue(
                                    ValidationIssue::error(format!("Schema validation failed: {}", e))
                                        .with_suggestion("Check the file against the official JSON schema"),
                                );
                            }
                        }
                    } else {
                        report.add_issue(
                            ValidationIssue::warning(format!(
                                "Schema file not found: {}",
                                schema_path.display()
                            ))
                            .with_suggestion("Schema validation skipped"),
                        );
                    }
                } else {
                    report.add_issue(
                        ValidationIssue::warning("No JSON schema available for this format/version")
                            .with_suggestion("Structural validation only"),
                    );
                }
            }
            Format::Xml => {
                // XML XSD validation
                use sbom_converter::xml_validator;
                
                // Extract schema version from detected format
                let schema_version = detected.version().unwrap_or("1.6");
                
                match xml_validator::validate_xml_string(&content, schema_version, "schemas") {
                    Ok(validation_result) => {
                        if validation_result.valid {
                            if !matches!(output_format, OutputFormat::Json) {
                                println!("{}", "✓ XSD schema validation passed".green().bold());
                            }
                        } else {
                            for msg in validation_result.messages {
                                report.add_issue(
                                    ValidationIssue::error(format!("XSD validation: {}", msg))
                                );
                            }
                        }
                    }
                    Err(e) => {
                        report.add_issue(
                            ValidationIssue::error(format!("XSD validation error: {}", e))
                                .with_suggestion("Check that schema files are available in schemas/ directory")
                        );
                    }
                }
            }
        }
    }

    // Output report
    match output_format {
        OutputFormat::Json => {
            let json = report
                .to_json()
                .map_err(|e| ConverterError::SerializationError(format!("Failed to serialize report: {}", e)))?;
            println!("{}", json);
        }
        OutputFormat::Text => {
            if no_color {
                report.print_plain();
            } else {
                report.print_colored();
            }
        }
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

/// Validate JSON against a schema file
fn validate_against_schema(
    value: &serde_json::Value,
    schema_path: &std::path::Path,
) -> Result<(), String> {
    let schema_content = fs::read_to_string(schema_path)
        .map_err(|e| format!("Failed to read schema: {}", e))?;

    let schema: serde_json::Value =
        serde_json::from_str(&schema_content).map_err(|e| format!("Invalid schema JSON: {}", e))?;

    let compiled = jsonschema::validator_for(&schema)
        .map_err(|e| format!("Failed to compile schema: {}", e))?;

    if compiled.is_valid(value) {
        Ok(())
    } else {
        let errors: Vec<String> = compiled
            .iter_errors(value)
            .map(|e| format!("{} at {}", e, e.instance_path))
            .collect();
        Err(errors.join("; "))
    }
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
            report_format,
            schema,
            show_version,
        }) => run_validate(input, format, fail_on_errors, no_color, report_format, schema, show_version),
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
