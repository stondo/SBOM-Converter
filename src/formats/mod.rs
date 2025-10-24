//! Format detection and definition module.
//!
//! This module provides types and utilities for detecting and handling
//! different SBOM file formats (JSON, XML, etc.).

pub mod cdx;
pub mod spdx;

use crate::errors::ConverterError;
use std::path::Path;

/// Supported SBOM formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// JSON format
    Json,
    /// XML format
    Xml,
}

impl Format {
    /// Detect format from file extension
    pub fn from_extension(path: &Path) -> Result<Self, ConverterError> {
        let extension = path
            .extension()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                ConverterError::InvalidInput(format!(
                    "Could not determine file extension for: {}",
                    path.display()
                ))
            })?;

        match extension.to_lowercase().as_str() {
            "json" => Ok(Format::Json),
            "xml" => Ok(Format::Xml),
            ext => Err(ConverterError::InvalidInput(format!(
                "Unsupported file format: .{}. Supported formats: .json, .xml",
                ext
            ))),
        }
    }

    /// Detect format from file content
    pub fn from_content(content: &[u8]) -> Result<Self, ConverterError> {
        // Skip whitespace
        let trimmed = content
            .iter()
            .skip_while(|&&b| b.is_ascii_whitespace())
            .copied()
            .collect::<Vec<u8>>();

        if trimmed.is_empty() {
            return Err(ConverterError::InvalidInput(
                "Empty file content".to_string(),
            ));
        }

        match trimmed[0] {
            b'{' | b'[' => Ok(Format::Json),
            b'<' => Ok(Format::Xml),
            _ => Err(ConverterError::InvalidInput(
                "Could not detect format from content. Expected JSON (starts with '{' or '[') or XML (starts with '<')".to_string()
            )),
        }
    }

    /// Get the typical file extension for this format
    pub fn extension(&self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Xml => "xml",
        }
    }

    /// Get the MIME type for this format
    pub fn mime_type(&self) -> &'static str {
        match self {
            Format::Json => "application/json",
            Format::Xml => "application/xml",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_from_extension() {
        assert_eq!(
            Format::from_extension(&PathBuf::from("test.json")).unwrap(),
            Format::Json
        );
        assert_eq!(
            Format::from_extension(&PathBuf::from("test.xml")).unwrap(),
            Format::Xml
        );
        assert_eq!(
            Format::from_extension(&PathBuf::from("TEST.JSON")).unwrap(),
            Format::Json
        );
        assert!(Format::from_extension(&PathBuf::from("test.txt")).is_err());
        assert!(Format::from_extension(&PathBuf::from("test")).is_err());
    }

    #[test]
    fn test_from_content() {
        assert_eq!(
            Format::from_content(b"{\"test\": true}").unwrap(),
            Format::Json
        );
        assert_eq!(Format::from_content(b"[1, 2, 3]").unwrap(), Format::Json);
        assert_eq!(
            Format::from_content(b"<?xml version=\"1.0\"?>").unwrap(),
            Format::Xml
        );
        assert_eq!(Format::from_content(b"<root></root>").unwrap(), Format::Xml);
        assert_eq!(
            Format::from_content(b"  \n  {\"test\": true}").unwrap(),
            Format::Json
        );
        assert!(Format::from_content(b"").is_err());
        assert!(Format::from_content(b"invalid").is_err());
    }

    #[test]
    fn test_extension_method() {
        assert_eq!(Format::Json.extension(), "json");
        assert_eq!(Format::Xml.extension(), "xml");
    }

    #[test]
    fn test_mime_type() {
        assert_eq!(Format::Json.mime_type(), "application/json");
        assert_eq!(Format::Xml.mime_type(), "application/xml");
    }
}
