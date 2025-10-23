//! Handles the optional JSON schema validation.
//!
//! This uses the `jsonschema` crate as specified in `Cargo.toml`.
//! 
//! Note: Schema validation only works for simple JSON format.
//! JSON-LD format (used by Yocto/OpenEmbedded) is detected and 
//! validation is skipped with a warning, as the schema doesn't
//! support the JSON-LD serialization.

use crate::errors::ConverterError;
use jsonschema;
use log::{info, warn};
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// Validates a given JSON file against a schema string.
/// 
/// For SPDX files, if JSON-LD format is detected (presence of @context),
/// validation is skipped as the schema only supports simple JSON format.
/// The file will still be processed successfully for conversion.
pub fn validate_json_schema(schema_str: &str, json_file_path: &Path) -> Result<(), ConverterError> {
    info!("Loading schema...");
    let schema_json: Value = serde_json::from_str(schema_str).map_err(ConverterError::Serde)?;
    let compiled_schema = jsonschema::validator_for(&schema_json)
        .map_err(|e| ConverterError::Validation(e.to_string()))?;

    info!("Loading and parsing input file for validation...");
    let file = File::open(json_file_path)
        .map_err(|e| ConverterError::Io(e, "Failed to open input for validation".to_string()))?;
    let reader = BufReader::new(file);
    let instance: Value = serde_json::from_reader(reader).map_err(ConverterError::Serde)?;

    // Check if this is JSON-LD format (has @context)
    if instance.get("@context").is_some() {
        warn!("Detected JSON-LD format (@context present). Schema validation is only supported for simple JSON format.");
        warn!("Skipping validation. The file will still be processed for conversion.");
        return Ok(());
    }

    info!("Validating instance against schema...");

    if compiled_schema.is_valid(&instance) {
        info!("Validation successful!");
        Ok(())
    } else {
        Err(ConverterError::Validation(
            "Input file failed schema validation. The file does not conform to the expected schema.".to_string()
        ))
    }
}
