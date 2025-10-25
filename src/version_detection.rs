//! Version detection for SBOM files
//!
//! Automatically detects the format and version of SBOM files.

use serde_json::Value;

/// SBOM format type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDx(String),  // version string
    Spdx(String),       // version string
    Unknown,
}

impl SbomFormat {
    /// Get a human-readable name
    pub fn name(&self) -> &str {
        match self {
            SbomFormat::CycloneDx(_) => "CycloneDX",
            SbomFormat::Spdx(_) => "SPDX",
            SbomFormat::Unknown => "Unknown",
        }
    }

    /// Get the version string
    pub fn version(&self) -> Option<&str> {
        match self {
            SbomFormat::CycloneDx(v) | SbomFormat::Spdx(v) => Some(v.as_str()),
            SbomFormat::Unknown => None,
        }
    }

    /// Check if the format is supported for schema validation
    pub fn has_schema(&self) -> bool {
        match self {
            SbomFormat::CycloneDx(v) => {
                v.starts_with("1.3") || v.starts_with("1.4") || 
                v.starts_with("1.5") || v.starts_with("1.6") || v.starts_with("1.7")
            }
            SbomFormat::Spdx(v) => v.starts_with("3.0") || v.starts_with("2."),
            SbomFormat::Unknown => false,
        }
    }

    /// Get the schema file name for this format
    pub fn schema_file(&self) -> Option<&str> {
        match self {
            SbomFormat::CycloneDx(v) if v.starts_with("1.7") => Some("cdx_1.7.schema.json"),
            SbomFormat::CycloneDx(v) if v.starts_with("1.6") => Some("cdx_1.6.schema.json"),
            SbomFormat::CycloneDx(v) if v.starts_with("1.5") => Some("cdx_1.5.schema.json"),
            SbomFormat::CycloneDx(v) if v.starts_with("1.4") => Some("cdx_1.4.schema.json"),
            SbomFormat::CycloneDx(v) if v.starts_with("1.3") => Some("cdx_1.3.schema.json"),
            SbomFormat::Spdx(v) if v.starts_with("3.0") => Some("spdx_3.0.1.schema.json"),
            SbomFormat::Spdx(v) if v.starts_with("2.3") => Some("spdx_2.3.schema.json"),
            SbomFormat::Spdx(v) if v.starts_with("2.2") => Some("spdx_2.2.schema.json"),
            _ => None,
        }
    }
}

/// Detect the SBOM format and version from JSON content
pub fn detect_format(value: &Value) -> SbomFormat {
    // Check for CycloneDX
    if let Some(bom_format) = value.get("bomFormat").and_then(|v| v.as_str()) {
        if bom_format == "CycloneDX" {
            if let Some(spec_version) = value.get("specVersion").and_then(|v| v.as_str()) {
                return SbomFormat::CycloneDx(spec_version.to_string());
            }
            return SbomFormat::CycloneDx("unknown".to_string());
        }
    }

    // Check for SPDX
    if let Some(spdx_version) = value.get("spdxVersion").and_then(|v| v.as_str()) {
        // Strip "SPDX-" prefix if present
        let version = spdx_version.strip_prefix("SPDX-").unwrap_or(spdx_version);
        return SbomFormat::Spdx(version.to_string());
    }

    // Check for SPDX 3.0 (different structure)
    if let Some(_spdx_id) = value.get("spdxId") {
        // SPDX 3.0 uses spdxId instead of SPDXID
        if value.get("creationInfo").is_some() {
            return SbomFormat::Spdx("3.0".to_string());
        }
    }

    // Check for SPDX 2.x
    if value.get("SPDXID").is_some() {
        // Try to get version from other fields
        if let Some(creation_info) = value.get("creationInfo") {
            if let Some(created) = creation_info.get("created") {
                let _ = created; // Just checking existence
                return SbomFormat::Spdx("2.3".to_string());
            }
        }
        return SbomFormat::Spdx("2.x".to_string());
    }

    SbomFormat::Unknown
}

/// Get a description of the detected format
pub fn format_description(format: &SbomFormat) -> String {
    match format {
        SbomFormat::CycloneDx(v) => format!("CycloneDX {}", v),
        SbomFormat::Spdx(v) => format!("SPDX {}", v),
        SbomFormat::Unknown => "Unknown format".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_detect_cyclonedx() {
        let cdx = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1
        });

        let format = detect_format(&cdx);
        assert_eq!(format, SbomFormat::CycloneDx("1.6".to_string()));
        assert_eq!(format.name(), "CycloneDX");
        assert_eq!(format.version(), Some("1.6"));
        assert!(format.has_schema());
        assert_eq!(format.schema_file(), Some("cdx_1.6.schema.json"));
    }

    #[test]
    fn test_detect_spdx_3() {
        let spdx = json!({
            "spdxVersion": "SPDX-3.0",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z"
            }
        });

        let format = detect_format(&spdx);
        assert_eq!(format, SbomFormat::Spdx("3.0".to_string()));
        assert_eq!(format.name(), "SPDX");
        assert_eq!(format.version(), Some("3.0"));
    }

    #[test]
    fn test_detect_spdx_2() {
        let spdx = json!({
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT"
        });

        let format = detect_format(&spdx);
        assert_eq!(format, SbomFormat::Spdx("2.3".to_string()));
    }

    #[test]
    fn test_detect_unknown() {
        let unknown = json!({
            "someField": "someValue"
        });

        let format = detect_format(&unknown);
        assert_eq!(format, SbomFormat::Unknown);
        assert_eq!(format.name(), "Unknown");
        assert_eq!(format.version(), None);
        assert!(!format.has_schema());
        assert_eq!(format.schema_file(), None);
    }

    #[test]
    fn test_format_description() {
        assert_eq!(
            format_description(&SbomFormat::CycloneDx("1.6".to_string())),
            "CycloneDX 1.6"
        );
        assert_eq!(
            format_description(&SbomFormat::Spdx("3.0".to_string())),
            "SPDX 3.0"
        );
        assert_eq!(
            format_description(&SbomFormat::Unknown),
            "Unknown format"
        );
    }
}
