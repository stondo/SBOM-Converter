//! CycloneDX JSON format handler

use crate::errors::ConverterError;
use crate::formats::cdx::CdxDocument;
use std::io::{Read, Write};

/// Parse CycloneDX from JSON
pub fn parse<R: Read>(reader: R) -> Result<CdxDocument, ConverterError> {
    serde_json::from_reader(reader)
        .map_err(|e| ConverterError::ParseError(format!("Failed to parse CycloneDX JSON: {}", e)))
}

/// Write CycloneDX as JSON
pub fn write<W: Write>(writer: W, bom: &CdxDocument) -> Result<(), ConverterError> {
    serde_json::to_writer_pretty(writer, bom).map_err(|e| {
        ConverterError::SerializationError(format!("Failed to write CycloneDX JSON: {}", e))
    })
}
