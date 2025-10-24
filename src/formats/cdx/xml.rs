//! CycloneDX XML format handler

use crate::errors::ConverterError;
use crate::formats::cdx::CdxDocument;
use quick_xml::de::from_reader;
use quick_xml::se::to_string;
use std::io::{BufRead, Write};

/// Parse CycloneDX from XML
pub fn parse<R: BufRead>(reader: R) -> Result<CdxDocument, ConverterError> {
    from_reader(reader).map_err(|e| {
        ConverterError::ParseError(format!("Failed to parse CycloneDX XML: {}", e))
    })
}

/// Write CycloneDX as XML
pub fn write<W: Write>(mut writer: W, bom: &CdxDocument) -> Result<(), ConverterError> {
    // Add XML declaration
    writer
        .write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        .map_err(|e| {
            ConverterError::Io(e, "Failed to write XML declaration".to_string())
        })?;

    // Serialize to XML string
    let xml_content = to_string(bom).map_err(|e| {
        ConverterError::SerializationError(format!("Failed to serialize CycloneDX to XML: {}", e))
    })?;

    // Write XML content
    writer.write_all(xml_content.as_bytes()).map_err(|e| {
        ConverterError::Io(e, "Failed to write XML content".to_string())
    })?;

    Ok(())
}

