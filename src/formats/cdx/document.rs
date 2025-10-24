//! Full document structures for non-streaming operations (XML, validation, etc.)
//!
//! These structures represent complete BOMs loaded in memory, used for:
//! - XML parsing/serialization
//! - Validation
//! - Analysis operations
//!
//! For streaming JSON operations, see models_cdx.rs

use serde::{Deserialize, Serialize};

/// Complete CycloneDX BOM document for XML/full parsing
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename = "bom")]
#[serde(rename_all = "camelCase")]
pub struct CdxDocument {
    /// XML namespace (for XML serialization)
    #[serde(rename = "@xmlns", skip_serializing_if = "Option::is_none")]
    pub xmlns: Option<String>,

    /// BOM format (should be "CycloneDX")
    #[serde(rename = "@bomFormat", skip_serializing_if = "Option::is_none")]
    pub bom_format: Option<String>,

    /// Spec version (e.g., "1.6")
    #[serde(rename = "@specVersion", skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,

    /// BOM version
    #[serde(rename = "@version")]
    pub version: u32,

    /// Serial number (URN)
    #[serde(rename = "@serialNumber", skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,

    /// Metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<CdxMetadata>,

    /// Components
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<CdxComponents>,

    /// Dependencies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<CdxDependencies>,

    /// Vulnerabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<CdxVulnerabilities>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<CdxTools>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<Box<CdxComponent>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxTools {
    #[serde(rename = "tool", default)]
    pub tools: Vec<CdxTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxTool {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxComponents {
    #[serde(rename = "component", default)]
    pub components: Vec<CdxComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CdxComponent {
    #[serde(rename = "@type")]
    pub component_type: String,

    #[serde(rename = "@bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,

    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<CdxHashes>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub licenses: Option<CdxLicenses>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxHashes {
    #[serde(rename = "hash", default)]
    pub hashes: Vec<CdxHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxHash {
    #[serde(rename = "@alg")]
    pub alg: String,

    #[serde(rename = "$text")]
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxLicenses {
    #[serde(rename = "license", default)]
    pub licenses: Vec<CdxLicense>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxLicense {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxDependencies {
    #[serde(rename = "dependency", default)]
    pub dependencies: Vec<CdxDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CdxDependency {
    #[serde(rename = "@ref")]
    pub dependency_ref: String,

    #[serde(rename = "dependency", default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<CdxDependsOn>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxDependsOn {
    #[serde(rename = "@ref")]
    pub dependency_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxVulnerabilities {
    #[serde(rename = "vulnerability", default)]
    pub vulnerabilities: Vec<CdxVulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CdxVulnerability {
    #[serde(rename = "@bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cdx_document() {
        let doc = CdxDocument::default();
        assert_eq!(doc.version, 0);
        assert!(doc.components.is_none());
    }

    #[test]
    fn test_cdx_document_with_version() {
        let doc = CdxDocument {
            version: 1,
            spec_version: Some("1.6".to_string()),
            ..Default::default()
        };
        assert_eq!(doc.version, 1);
        assert_eq!(doc.spec_version, Some("1.6".to_string()));
    }
}
