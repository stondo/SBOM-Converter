//! SPDX XML format handler
//!
//! Note: SPDX 3.0+ doesn't have an official XML format yet.
//! This is a placeholder for potential future support or custom implementation.

use crate::errors::ConverterError;
use crate::models_spdx::SpdxDocument;
use std::io::{Read, Write};

/// Parse SPDX from XML
pub fn parse<R: Read>(_reader: R) -> Result<SpdxDocument, ConverterError> {
    Err(ConverterError::UnsupportedFormat(
        "SPDX 3.0.1 XML format is not officially supported by the SPDX specification".to_string(),
    ))
}

/// Write SPDX as XML
pub fn write<W: Write>(_writer: W, _doc: &SpdxDocument) -> Result<(), ConverterError> {
    Err(ConverterError::UnsupportedFormat(
        "SPDX 3.0.1 XML format is not officially supported by the SPDX specification".to_string(),
    ))
}

// Note: SPDX 2.3 had XML support (RDF/XML), but SPDX 3.0+ uses JSON-LD as the primary format.
// If we want to support SPDX 2.3 XML in the future, we'll need to add it as a separate module.
