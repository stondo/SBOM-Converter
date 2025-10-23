//! Handles the optional JSON schema validation.
//!
//! This uses the `jsonschema` crate as specified in `Cargo.toml`.
//! 
//! ## Validation Behavior
//! 
//! ### Simple JSON Format
//! - Validated against the bundled SPDX 3.0.1 or CycloneDX 1.6 JSON Schema
//! - Full structural and semantic validation
//! 
//! ### JSON-LD Format (Yocto/OpenEmbedded)
//! - Structural validation only (checks @context, @graph, element structure)
//! - Does not perform RDF semantic validation
//! - For full semantic validation, use RDF/SHACL tools
//! - Conversion will still work correctly even with validation skipped

use crate::errors::ConverterError;
use jsonschema;
use log::{info, warn};
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// Validates a given JSON file against a schema string.
/// 
/// For SPDX files in JSON-LD format (detected by @context field):
/// - If `skip_jsonld_validation` is false: performs structural validation
/// - If `skip_jsonld_validation` is true: skips validation entirely
/// 
/// JSON-LD structural validation checks @context, @graph, and element structure,
/// but does not perform full RDF semantic validation.
pub fn validate_json_schema(
    schema_str: &str,
    json_file_path: &Path,
    skip_jsonld_validation: bool,
) -> Result<(), ConverterError> {
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
        if skip_jsonld_validation {
            info!("Detected JSON-LD format. Skipping structural validation (--skip-jsonld-validation flag set).");
            info!("Note: The conversion process will validate structure implicitly.");
            return Ok(());
        } else {
            info!("Detected JSON-LD format. Performing structural validation...");
            return validate_jsonld_structure(&instance);
        }
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

/// Performs basic structural validation for JSON-LD formatted SPDX files.
/// 
/// This validates the JSON-LD structure but not the full RDF semantics.
/// For complete semantic validation, use RDF/SHACL tools.
fn validate_jsonld_structure(instance: &Value) -> Result<(), ConverterError> {
    // Check @context exists and is valid
    let context = instance.get("@context")
        .ok_or_else(|| ConverterError::Validation("JSON-LD missing @context".to_string()))?;
    
    if !context.is_string() && !context.is_array() && !context.is_object() {
        return Err(ConverterError::Validation(
            "JSON-LD @context must be a string, array, or object".to_string()
        ));
    }
    
    // Check @graph exists and is an array
    let graph = instance.get("@graph")
        .ok_or_else(|| ConverterError::Validation("JSON-LD missing @graph".to_string()))?;
    
    let graph_array = graph.as_array()
        .ok_or_else(|| ConverterError::Validation("JSON-LD @graph must be an array".to_string()))?;
    
    if graph_array.is_empty() {
        warn!("JSON-LD @graph is empty - no elements to convert");
    }
    
    // Validate each element in @graph has required JSON-LD properties
    let mut element_count = 0;
    let mut elements_with_type = 0;
    let mut elements_with_id = 0;
    
    for (idx, element) in graph_array.iter().enumerate() {
        element_count += 1;
        
        if !element.is_object() {
            return Err(ConverterError::Validation(
                format!("JSON-LD @graph element {} is not an object", idx)
            ));
        }
        
        // Check for @type (not strictly required but common in SPDX)
        if element.get("@type").is_some() {
            elements_with_type += 1;
        }
        
        // Check for @id (identifies the entity)
        if element.get("@id").is_some() {
            elements_with_id += 1;
        }
    }
    
    info!("JSON-LD structural validation passed:");
    info!("  - {} elements in @graph", element_count);
    info!("  - {} elements with @type", elements_with_type);
    info!("  - {} elements with @id", elements_with_id);
    
    // Note: Not all JSON-LD elements require @type or @id (they can be blank nodes or inline values)
    // Only warn if there's a very low proportion
    if element_count > 10 && elements_with_id == 0 {
        warn!("No elements have @id - file may not be a proper SPDX JSON-LD document");
    }
    
    Ok(())
}
