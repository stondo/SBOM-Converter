//! Main library for the SBOM converter.
//!
//! This crate contains the core logic for the bi-directional, streaming
//! conversion between CycloneDX and SPDX formats.

// Make modules public within the crate but not necessarily public API
pub mod converter_cdx_to_spdx;
pub mod converter_spdx_to_cdx;
pub mod errors;
pub mod formats;
pub mod models_cdx;
pub mod models_spdx;
pub mod progress;
pub mod schema;
pub mod validation;
pub mod version_detection;

use clap::ValueEnum;
use errors::ConverterError;
use log::info;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::time::Instant;

/// Defines the conversion direction.
#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum ConversionDirection {
    /// Convert from CycloneDX 1.6 to SPDX 3.0.1
    CdxToSpdx,
    /// Convert from SPDX 3.0.1 to CycloneDX 1.6
    SpdxToCdx,
}

/// Top-level configuration for a conversion run.
#[derive(Debug)]
pub struct Config {
    pub input_file: PathBuf,
    pub output_file: PathBuf,
    pub direction: ConversionDirection,
    pub input_format: Option<formats::Format>,
    pub output_format: Option<formats::Format>,
    pub validate: bool,
    pub split_vex: bool,
    pub packages_only: bool,
    pub skip_jsonld_validation: bool,
}

/// The main entry point for the conversion logic.
///
/// This function opens the files, handles validation, and dispatches to
/// the correct converter based on the chosen direction and formats.
pub fn run(config: Config) -> Result<(), ConverterError> {
    let start_time = Instant::now();
    info!("Starting conversion: {:?}", config.direction);
    info!("  Input: {}", config.input_file.display());
    info!("  Output: {}", config.output_file.display());

    // Determine input and output formats
    let input_format = config.input_format.unwrap_or_else(|| {
        formats::Format::from_extension(&config.input_file).unwrap_or(formats::Format::Json)
    });

    let output_format = config.output_format.unwrap_or_else(|| {
        formats::Format::from_extension(&config.output_file).unwrap_or(formats::Format::Json)
    });

    info!("  Input format: {:?}", input_format);
    info!("  Output format: {:?}", output_format);

    // Check for unsupported format combinations
    if input_format == formats::Format::Xml && config.direction == ConversionDirection::SpdxToCdx {
        return Err(ConverterError::UnsupportedFormat(
            "SPDX XML input is not supported (SPDX 3.0+ uses JSON-LD, not XML)".to_string(),
        ));
    }

    if output_format == formats::Format::Xml && config.direction == ConversionDirection::CdxToSpdx {
        return Err(ConverterError::UnsupportedFormat(
            "SPDX XML output is not supported (SPDX 3.0+ uses JSON-LD, not XML)".to_string(),
        ));
    }

    // --- 1. Validation (Optional) ---
    if config.validate {
        let schema_start = Instant::now();
        info!("Running pre-validation...");
        let schema_str = match config.direction {
            ConversionDirection::CdxToSpdx => {
                // We are reading CDX, so validate against CDX schema
                include_str!("../schemas/cdx_1.6.schema.json")
            }
            ConversionDirection::SpdxToCdx => {
                // We are reading SPDX, so validate against SPDX 3.0.1 schema
                // Note: SPDX 3.0.1 schema is strict and may reject files that
                // convert successfully. Use --validate flag judiciously.
                include_str!("../schemas/spdx_3.0.1.schema.json")
            }
        };

        schema::validate_json_schema(
            schema_str,
            &config.input_file,
            config.skip_jsonld_validation,
        )?;
        info!(
            "Validation passed successfully. (Took {:.2?})",
            schema_start.elapsed()
        );
    } else {
        info!("Skipping pre-validation.");
    }

    // --- 2. Handle Format Conversion ---
    // If XML input, convert to JSON first (to temp file)
    // If XML output needed, we'll convert from JSON at the end
    let working_input_path: PathBuf;
    let temp_input_file: Option<PathBuf>;

    if input_format == formats::Format::Xml && config.direction == ConversionDirection::CdxToSpdx {
        info!("Converting XML input to JSON for processing...");
        let temp_dir = std::env::temp_dir();
        let temp_json = temp_dir.join(format!(
            "sbom-converter-xml-input-{}.json",
            uuid::Uuid::new_v4()
        ));

        // Parse XML
        let xml_file = File::open(&config.input_file)
            .map_err(|e| ConverterError::Io(e, "Failed to open XML input".to_string()))?;
        let xml_reader = BufReader::new(xml_file);
        let cdx_doc = formats::cdx::xml::parse(xml_reader)?;

        // Convert to JSON-compatible format
        let json_value = formats::cdx::converter::document_to_json(&cdx_doc);

        // Write to temp JSON
        let json_file = File::create(&temp_json)
            .map_err(|e| ConverterError::Io(e, "Failed to create temp JSON".to_string()))?;
        serde_json::to_writer_pretty(json_file, &json_value).map_err(|e| {
            ConverterError::SerializationError(format!("Failed to write temp JSON: {}", e))
        })?;

        working_input_path = temp_json.clone();
        temp_input_file = Some(temp_json);
    } else {
        working_input_path = config.input_file.clone();
        temp_input_file = None;
    }

    let working_output_path: PathBuf;
    let temp_output_file: Option<PathBuf>;

    if output_format == formats::Format::Xml {
        info!("Will convert output to XML after processing...");
        let temp_dir = std::env::temp_dir();
        let temp_json = temp_dir.join(format!(
            "sbom-converter-xml-output-{}.json",
            uuid::Uuid::new_v4()
        ));
        working_output_path = temp_json.clone();
        temp_output_file = Some(temp_json);
    } else {
        working_output_path = config.output_file.clone();
        temp_output_file = None;
    }

    // --- 3. File Handling ---
    let input_file = File::open(&working_input_path)
        .map_err(|e| ConverterError::Io(e, "Failed to open input file".to_string()))?;
    let input_reader = BufReader::new(input_file);

    let output_file = File::create(&working_output_path)
        .map_err(|e| ConverterError::Io(e, "Failed to create output file".to_string()))?;
    let mut output_writer = BufWriter::new(output_file);

    // --- 4. Dispatch to Converter ---
    info!("Starting streaming conversion process...");
    let conversion_start = Instant::now();

    // Create progress tracker (reports every 1000 elements)
    let progress = progress::ProgressTracker::new(1000);

    match config.direction {
        ConversionDirection::CdxToSpdx => {
            // Use Strategy 1: "Temp File" Method
            // Create a temp file for relationships
            let temp_dir = std::env::temp_dir();
            let temp_file_path =
                temp_dir.join(format!("sbom-converter-temp-{}.json", uuid::Uuid::new_v4()));

            converter_cdx_to_spdx::convert_cdx_to_spdx(
                input_reader,
                &mut output_writer,
                &temp_file_path,
                progress.clone(),
            )?;

            // Clean up temp file
            if temp_file_path.exists() {
                let _ = std::fs::remove_file(&temp_file_path);
            }
        }
        ConversionDirection::SpdxToCdx => {
            // Use Strategy 2: "Multi-Pass Index" Method
            // Note: We use working_input_path (which might be temp JSON from XML)
            converter_spdx_to_cdx::convert_spdx_to_cdx(
                input_reader,
                output_writer,
                &working_input_path,
                progress.clone(),
                config.packages_only,
                config.split_vex,
            )?;
        }
    }

    progress.finish();

    info!(
        "Streaming conversion finished. (Took {:.2?})",
        conversion_start.elapsed()
    );

    // --- 5. Handle XML Output (Convert from temp JSON) ---
    if let Some(temp_output) = temp_output_file {
        info!("Converting JSON output to XML...");

        // Read the standard CDX JSON output
        let json_content = std::fs::read_to_string(&temp_output)
            .map_err(|e| ConverterError::Io(e, "Failed to read temp JSON output".to_string()))?;

        let json_value: serde_json::Value = serde_json::from_str(&json_content)
            .map_err(|e| ConverterError::ParseError(format!("Failed to parse temp JSON: {}", e)))?;

        // Convert standard CDX JSON to CdxDocument for XML serialization
        let cdx_doc = formats::cdx::converter::json_to_document(&json_value).map_err(|e| {
            ConverterError::ParseError(format!("Failed to convert JSON to document: {}", e))
        })?;

        // Write as XML to final output
        let xml_file = File::create(&config.output_file)
            .map_err(|e| ConverterError::Io(e, "Failed to create XML output file".to_string()))?;
        formats::cdx::xml::write(xml_file, &cdx_doc)?;

        // Clean up temp file
        if temp_output.exists() {
            let _ = std::fs::remove_file(&temp_output);
        }
    }

    // --- 6. Clean up XML input temp file ---
    if let Some(temp_input) = temp_input_file {
        if temp_input.exists() {
            let _ = std::fs::remove_file(&temp_input);
        }
    }

    info!(
        "Streaming conversion finished. (Took {:.2?})",
        conversion_start.elapsed()
    );
    info!("Total execution time: {:.2?}", start_time.elapsed());
    Ok(())
}
