//! Handles the optional JSON schema validation.
//!
//! This uses the `jsonschema` crate as specified in `Cargo.toml`.
//! 
//! ## Validation Behavior
//! 
//! ### Simple JSON Format (SPDX 3.0.1 simple JSON, CycloneDX 1.6)
//! - Validated against the bundled JSON Schema
//! - Full structural and semantic validation
//! 
//! ### JSON-LD Format (SPDX 3.0.1 RDF serialization, Yocto/OpenEmbedded)
//! - Validation is skipped (JSON Schema does not apply to RDF serialization)
//! - The conversion process validates structure implicitly
//! - For semantic RDF validation, use dedicated RDF/SHACL tools

use crate::errors::ConverterError;
use jsonschema;
use log::info;
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// Validates a given JSON file against a schema string.
/// 
/// For SPDX files in JSON-LD format (detected by @context field),
/// validation is skipped since JSON Schema does not apply to RDF serialization.
/// The conversion process will still validate the structure implicitly.
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
        info!("Detected JSON-LD format. Skipping schema validation (not applicable to RDF serialization).");
        info!("Note: The conversion process will validate structure implicitly. For semantic validation, use RDF/SHACL tools.");
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
