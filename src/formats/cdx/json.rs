//! CycloneDX JSON format handler

use crate::errors::ConverterError;
use crate::models_cdx::Cdx;
use std::io::{Read, Write};

/// Parse CycloneDX from JSON
pub fn parse<R: Read>(reader: R) -> Result<Cdx, ConverterError> {
    serde_json::from_reader(reader).map_err(|e| {
        ConverterError::ParseError(format!("Failed to parse CycloneDX JSON: {}", e))
    })
}

/// Write CycloneDX as JSON
pub fn write<W: Write>(writer: W, bom: &Cdx) -> Result<(), ConverterError> {
    serde_json::to_writer_pretty(writer, bom).map_err(|e| {
        ConverterError::SerializationError(format!("Failed to write CycloneDX JSON: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_minimal_cdx() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1
        }"#;

        let cursor = Cursor::new(json.as_bytes());
        let result = parse(cursor);
        assert!(result.is_ok());
        let bom = result.unwrap();
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.6");
    }

    #[test]
    fn test_write_cdx() {
        let bom = Cdx {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            version: 1,
            ..Default::default()
        };

        let mut output = Vec::new();
        let result = write(&mut output, &bom);
        assert!(result.is_ok());

        let json_str = String::from_utf8(output).unwrap();
        assert!(json_str.contains("CycloneDX"));
        assert!(json_str.contains("1.6"));
    }
}
