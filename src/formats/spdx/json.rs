//! SPDX JSON format handler

use crate::errors::ConverterError;
use crate::models_spdx::SpdxDocument;
use std::io::{Read, Write};

/// Parse SPDX from JSON
pub fn parse<R: Read>(reader: R) -> Result<SpdxDocument, ConverterError> {
    serde_json::from_reader(reader).map_err(|e| {
        ConverterError::ParseError(format!("Failed to parse SPDX JSON: {}", e))
    })
}

/// Write SPDX as JSON
pub fn write<W: Write>(writer: W, doc: &SpdxDocument) -> Result<(), ConverterError> {
    serde_json::to_writer_pretty(writer, doc).map_err(|e| {
        ConverterError::SerializationError(format!("Failed to write SPDX JSON: {}", e))
    })
}

