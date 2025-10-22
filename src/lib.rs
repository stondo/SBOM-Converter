//! Main library for the SBOM converter.
//!
//! This crate contains the core logic for the bi-directional, streaming
//! conversion between CycloneDX and SPDX formats.

// Make modules public within the crate but not necessarily public API
pub mod converter_cdx_to_spdx;
pub mod converter_spdx_to_cdx;
pub mod errors;
pub mod models_cdx;
pub mod models_spdx;
pub mod schema;

use clap::ValueEnum;
use errors::ConverterError;
use log::{info, warn};
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
    pub validate: bool,
}

/// The main entry point for the conversion logic.
///
/// This function opens the files, handles validation, and dispatches to
/// the correct streaming converter based on the chosen direction.
pub fn run(config: Config) -> Result<(), ConverterError> {
    let start_time = Instant::now();
    info!("Starting conversion: {:?}", config.direction);
    info!("  Input: {}", config.input_file.display());
    info!("  Output: {}", config.output_file.display());

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
                // We are reading SPDX, but we don't have its schema bundled.
                // In a real app, we'd bundle spdx_3.0.schema.json as well.
                // For now, we'll just log a warning.
                warn!("SPDX validation is not yet implemented.");
                // As a placeholder, let's pretend we did.
                // In a real app, you'd load the SPDX schema.
                "" // Empty string will skip validation
            }
        };

        if !schema_str.is_empty() {
            schema::validate_json_schema(schema_str, &config.input_file)?;
            info!(
                "Validation passed successfully. (Took {:.2?})",
                schema_start.elapsed()
            );
        }
    } else {
        info!("Skipping pre-validation.");
    }

    // --- 2. File Handling ---
    let input_file = File::open(&config.input_file)
        .map_err(|e| ConverterError::Io(e, format!("Failed to open input file")))?;
    let input_reader = BufReader::new(input_file);

    let output_file = File::create(&config.output_file)
        .map_err(|e| ConverterError::Io(e, format!("Failed to create output file")))?;
    let mut output_writer = BufWriter::new(output_file);

    // --- 3. Dispatch to Converter ---
    info!("Starting streaming conversion process...");
    let conversion_start = Instant::now();

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
            )?;

            // Clean up temp file
            if temp_file_path.exists() {
                let _ = std::fs::remove_file(&temp_file_path);
            }
        }
        ConversionDirection::SpdxToCdx => {
            // Use Strategy 2: "Multi-Pass Index" Method
            // We need the input file path for the second pass
            converter_spdx_to_cdx::convert_spdx_to_cdx(
                input_reader,
                output_writer,
                &config.input_file,
            )?;
        }
    }

    info!(
        "Streaming conversion finished. (Took {:.2?})",
        conversion_start.elapsed()
    );
    info!("Total execution time: {:.2?}", start_time.elapsed());
    Ok(())
}
