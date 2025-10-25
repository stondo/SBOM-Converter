//! Contains *minimal* data structures for streaming SPDX 3.0.1 JSON.
//!
//! We also define the *output* structs for serialization.

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io::{BufWriter, Write};

// --- Minimal Deserialization Structs (for Pass 1 & 2) ---

/// Minimal struct for Pass 1 (Indexing) - Simple JSON format
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SpdxRelationshipMinimal {
    pub spdx_element_id: String,
    pub relationship_type: String, // e.g., "DEPENDS_ON", "AFFECTS"
    pub related_spdx_element: String,
}

/// Minimal struct for JSON-LD Relationship format
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JsonLdRelationship {
    #[serde(rename = "type")]
    pub relationship_type_name: String, // "Relationship" or "LifecycleScopedRelationship"
    #[serde(rename = "spdxId")]
    pub spdx_id: Option<String>, // JSON-LD @id equivalent
    pub from: String,              // source element ID
    pub relationship_type: String, // e.g., "hasDeclaredLicense", "contains", "dependsOn"
    pub to: Vec<String>,           // target element IDs (can be multiple)
}

/// Minimal struct for Pass 2 (Conversion) - Simple JSON format
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SpdxElementMinimal {
    pub spdx_id: String,
    #[serde(rename = "type")]
    pub element_type: String, // "SpdxPackage", "SpdxFile", "SpdxVulnerability"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>, // Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_concluded: Option<String>, // SPDX expression
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_identifier: Option<Vec<SpdxExternalIdentifier>>, // For CPE
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_using: Option<Vec<SpdxHash>>, // For hashes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_primary_purpose: Option<String>, // For scope
    // We use IgnoredAny to quickly skip over fields we don't need
    #[serde(flatten)]
    pub extra: HashMap<String, IgnoredAny>,
}

impl SpdxElementMinimal {
    /// Extract CPE from external identifiers
    pub fn extract_cpe(&self) -> Option<String> {
        self.external_identifier
            .as_ref()?
            .iter()
            .find(|id| id.external_identifier_type.as_deref() == Some("cpe23"))
            .and_then(|id| id.identifier.clone())
    }

    /// Extract PURL from external identifiers
    pub fn extract_purl(&self) -> Option<String> {
        self.external_identifier
            .as_ref()?
            .iter()
            .find(|id| id.external_identifier_type.as_deref() == Some("purl"))
            .and_then(|id| id.identifier.clone())
    }

    /// Convert SPDX hashes to CycloneDX format
    pub fn extract_hashes(&self) -> Option<Vec<crate::models_cdx::CdxHash>> {
        let verified = self.verified_using.as_ref()?;
        let hashes: Vec<_> = verified
            .iter()
            .filter_map(|h| {
                let alg = h.algorithm.as_ref()?.to_uppercase();
                let content = h.hash_value.clone()?;
                Some(crate::models_cdx::CdxHash {
                    alg: match alg.as_str() {
                        "SHA256" => "SHA-256".to_string(),
                        "SHA1" => "SHA-1".to_string(),
                        other => other.to_string(),
                    },
                    content,
                })
            })
            .collect();
        if hashes.is_empty() {
            None
        } else {
            Some(hashes)
        }
    }

    /// Map SPDX purpose to CycloneDX scope
    pub fn map_scope(&self) -> Option<String> {
        match self.software_primary_purpose.as_deref()? {
            "install" => Some("required".to_string()),
            "source" | "build" => Some("excluded".to_string()),
            _ => None,
        }
    }
}

/// Minimal struct for JSON-LD Element format (enhanced for full data extraction)
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JsonLdElement {
    #[serde(rename = "type")]
    pub element_type: String, // "software_Package", "software_File", "security_Vulnerability"
    #[serde(rename = "spdxId")]
    pub spdx_id: String, // Full URI in JSON-LD
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_package_version: Option<String>, // JSON-LD uses different field name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_primary_purpose: Option<String>, // "install", "source", etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_identifier: Option<Vec<SpdxExternalIdentifier>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_using: Option<Vec<SpdxHash>>,
    // We use IgnoredAny to quickly skip over fields we don't need
    #[serde(flatten)]
    pub extra: HashMap<String, IgnoredAny>,
}

/// External identifier (CPE, PURL, etc.)
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SpdxExternalIdentifier {
    #[serde(rename = "type")]
    pub id_type: String,
    pub external_identifier_type: Option<String>, // "cpe23", "purl", etc.
    pub identifier: Option<String>,
}

/// Hash information from SPDX
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SpdxHash {
    #[serde(rename = "type")]
    pub hash_type: String,
    pub algorithm: Option<String>, // "sha256", "sha1", etc.
    pub hash_value: Option<String>,
}

/// Vulnerability data from JSON-LD
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JsonLdVulnerability {
    #[serde(rename = "type")]
    pub vuln_type: String,
    #[serde(rename = "spdxId")]
    pub spdx_id: String,
    pub external_identifier: Option<Vec<SpdxExternalIdentifier>>,
}

impl JsonLdVulnerability {
    /// Extract CVE ID from spdxId URL or external identifiers
    pub fn extract_cve_id(&self) -> Option<String> {
        // Try external_identifier first
        if let Some(cve) = self.external_identifier.as_ref().and_then(|ids| {
            ids.iter()
                .find(|id| id.external_identifier_type.as_deref() == Some("cve"))
                .and_then(|id| id.identifier.clone())
        }) {
            return Some(cve);
        }

        // Fall back to extracting from spdxId URL (e.g., .../vulnerability/CVE-2025-11081)
        if let Some(cve_part) = self.spdx_id.split("/vulnerability/").nth(1) {
            return Some(cve_part.to_string());
        }

        None
    }
}

/// VEX assessment relationship from JSON-LD
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JsonLdVexRelationship {
    #[serde(rename = "type")]
    pub relationship_type: String, // "security_VexNotAffectedVulnAssessmentRelationship", etc.
    #[serde(rename = "spdxId")]
    pub spdx_id: String,
    pub from: String, // vulnerability ID
    #[serde(rename = "relationshipType")]
    pub relationship_type_enum: String, // "doesNotAffect", "fixedIn"
    pub to: Vec<String>, // affected component IDs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_impact_statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_vex_version: Option<String>,
}

impl JsonLdVexRelationship {
    /// Map SPDX VEX state to CycloneDX analysis state
    pub fn map_state(&self) -> String {
        match self.relationship_type.as_str() {
            "security_VexNotAffectedVulnAssessmentRelationship" => "not_affected",
            "security_VexFixedVulnAssessmentRelationship" => "resolved",
            _ => "in_triage",
        }
        .to_string()
    }
}

impl JsonLdElement {
    /// Convert JSON-LD element to simple format for processing
    pub fn to_simple(&self) -> SpdxElementMinimal {
        SpdxElementMinimal {
            spdx_id: self.spdx_id.clone(),
            element_type: self.element_type.clone(),
            name: self.name.clone(),
            version_info: self.software_package_version.clone(),
            summary: self.summary.clone().or_else(|| self.description.clone()),
            purl: None,              // Would need to extract from externalIdentifier
            license_concluded: None, // Would need to extract from relationships
            external_identifier: self.external_identifier.clone(),
            verified_using: self.verified_using.clone(),
            software_primary_purpose: self.software_primary_purpose.clone(),
            extra: HashMap::new(),
        }
    }

    /// Extract CPE from external identifiers
    pub fn extract_cpe(&self) -> Option<String> {
        self.external_identifier
            .as_ref()?
            .iter()
            .find(|id| id.external_identifier_type.as_deref() == Some("cpe23"))
            .and_then(|id| id.identifier.clone())
    }

    /// Extract PURL from external identifiers
    pub fn extract_purl(&self) -> Option<String> {
        self.external_identifier
            .as_ref()?
            .iter()
            .find(|id| id.external_identifier_type.as_deref() == Some("purl"))
            .and_then(|id| id.identifier.clone())
    }

    /// Convert SPDX hashes to CycloneDX format
    pub fn extract_hashes(&self) -> Option<Vec<crate::models_cdx::CdxHash>> {
        let verified = self.verified_using.as_ref()?;
        let hashes: Vec<_> = verified
            .iter()
            .filter_map(|h| {
                let alg = h.algorithm.as_ref()?.to_uppercase();
                let content = h.hash_value.clone()?;
                Some(crate::models_cdx::CdxHash {
                    alg: match alg.as_str() {
                        "SHA256" => "SHA-256".to_string(),
                        "SHA1" => "SHA-1".to_string(),
                        other => other.to_string(),
                    },
                    content,
                })
            })
            .collect();
        if hashes.is_empty() {
            None
        } else {
            Some(hashes)
        }
    }

    /// Map SPDX purpose to CycloneDX scope
    pub fn map_scope(&self) -> Option<String> {
        match self.software_primary_purpose.as_deref()? {
            "install" => Some("required".to_string()),
            "source" | "build" => Some("excluded".to_string()),
            _ => None,
        }
    }
}

// --- Full Serialization Structs (for writing) ---

/// Top-level SPDX Document (minimal)
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SpdxDocument {
    pub spdx_version: String,
    pub data_license: String,
    pub spdx_id: String,
    pub name: String,
    pub document_namespace: String,
    pub creation_info: SpdxCreationInfo,
}

impl SpdxDocument {
    pub fn from_cdx_bom(_bom: &crate::models_cdx::CdxBom) -> Self {
        use uuid::Uuid;
        Self {
            spdx_version: "SPDX-3.0".to_string(),
            data_license: "CC0-1.0".to_string(),
            spdx_id: "SPDXRef-DOCUMENT".to_string(),
            name: "Converted SBOM".to_string(),
            document_namespace: format!("urn:uuid:{}", Uuid::new_v4()),
            creation_info: SpdxCreationInfo {
                created: chrono::Utc::now().to_rfc3339(),
                creators: vec!["Tool: sbom-converter".to_string()],
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SpdxCreationInfo {
    pub created: String, // ISO 8601
    pub creators: Vec<String>,
}

/// Represents an SPDX Package (element)
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SpdxPackage {
    #[serde(rename = "spdxId")]
    pub spdx_id: String,
    #[serde(rename = "type")]
    pub element_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>, // Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_concluded: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_identifier: Option<Vec<SpdxExternalIdentifier>>, // For CPE
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_using: Option<Vec<SpdxHash>>, // For hashes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_primary_purpose: Option<String>, // For scope mapping
}

impl SpdxPackage {
    pub fn from_cdx_component(comp: &crate::models_cdx::CdxComponent) -> Self {
        // Convert CPE to SPDX externalIdentifier
        let external_identifier = comp.cpe.as_ref().map(|cpe| {
            vec![SpdxExternalIdentifier {
                id_type: "ExternalIdentifier".to_string(),
                external_identifier_type: Some("cpe23Type".to_string()),
                identifier: Some(cpe.clone()),
            }]
        });

        // Convert CycloneDX hashes to SPDX verified_using
        let verified_using = comp.hashes.as_ref().map(|hashes| {
            hashes
                .iter()
                .map(|h| SpdxHash {
                    hash_type: "Hash".to_string(),
                    algorithm: Some(h.alg.to_lowercase()),
                    hash_value: Some(h.content.clone()),
                })
                .collect()
        });

        // Map CycloneDX scope to SPDX software_primaryPurpose
        let software_primary_purpose = comp.scope.as_ref().map(|scope| {
            match scope.as_str() {
                "required" => "install",
                "optional" => "optional",
                _ => "other",
            }
            .to_string()
        });

        Self {
            spdx_id: format!("SPDXRef-{}", comp.bom_ref),
            element_type: if comp.component_type == "file" {
                "SpdxFile".to_string()
            } else {
                "SpdxPackage".to_string()
            },
            name: comp.name.clone(),
            version_info: comp.version.clone(),
            summary: comp.description.clone(),
            purl: comp.purl.clone(),
            license_concluded: comp
                .licenses
                .as_ref()
                .and_then(|lics| lics.first())
                .and_then(|l| l.expression.clone()),
            external_identifier,
            verified_using,
            software_primary_purpose,
        }
    }
}

/// Represents an SPDX Element (generic)
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SpdxElement {
    #[serde(rename = "spdxId")]
    pub spdx_id: String,
    #[serde(rename = "type")]
    pub element_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_concluded: Option<String>,
}

/// Relationship type enum
#[derive(Serialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelationshipType {
    DependsOn,
    Affects,
}

/// Represents an SPDX Relationship
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SpdxRelationship {
    #[serde(rename = "spdxElementId")]
    pub spdx_element_id: String,
    pub relationship_type: RelationshipType,
    #[serde(rename = "relatedSpdxElement")]
    pub related_spdx_element: String,
}

// --- Streaming Visitor Logic (for SPDX -> CDX) ---

/// Custom visitor for Pass 1 (Indexing Pass)
pub struct SpdxPass1Visitor<'a> {
    pub index: &'a mut crate::converter_spdx_to_cdx::SpdxRelationshipIndex,
    pub progress: crate::progress::ProgressTracker,
}

impl<'de, 'a> Visitor<'de> for SpdxPass1Visitor<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a top-level SPDX JSON object (simple or JSON-LD format)")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut found_relationships = false;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "relationships" => {
                    // Simple JSON format: Found relationships array
                    found_relationships = true;
                    map.next_value_seed(SpdxRelationshipStreamVisitor {
                        index: self.index,
                        progress: self.progress.clone(),
                    })?;
                }
                "@graph" => {
                    // JSON-LD format: Process @graph array for relationships
                    found_relationships = true;
                    map.next_value_seed(JsonLdGraphStreamVisitor {
                        index: self.index,
                        progress: self.progress.clone(),
                    })?;
                }
                _ => {
                    // Skip all other keys
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if !found_relationships {
            eprintln!(
                "Warning: No relationships found in SPDX file (looked for 'relationships' or '@graph')"
            );
        }
        Ok(())
    }
}

/// Visitor for the 'relationships' array in Pass 1
struct SpdxRelationshipStreamVisitor<'a> {
    index: &'a mut crate::converter_spdx_to_cdx::SpdxRelationshipIndex,
    progress: crate::progress::ProgressTracker,
}

impl<'de, 'a> de::DeserializeSeed<'de> for SpdxRelationshipStreamVisitor<'a> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a> Visitor<'de> for SpdxRelationshipStreamVisitor<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of SPDX relationships")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while let Some(rel) = seq.next_element::<SpdxRelationshipMinimal>()? {
            // Add this relationship to our in-memory index
            self.index
                .entry(rel.spdx_element_id.clone())
                .or_default()
                .push(rel);
            self.progress.increment_relationship();
        }
        Ok(())
    }
}

/// Visitor for the '@graph' array in JSON-LD format (used in both passes)
struct JsonLdGraphStreamVisitor<'a> {
    index: &'a mut crate::converter_spdx_to_cdx::SpdxRelationshipIndex,
    progress: crate::progress::ProgressTracker,
}

impl<'de, 'a> de::DeserializeSeed<'de> for JsonLdGraphStreamVisitor<'a> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a> Visitor<'de> for JsonLdGraphStreamVisitor<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of JSON-LD objects in @graph")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        // In Pass 1, we only care about relationships
        // We need to deserialize as a generic Value to check the type
        while let Some(value) = seq.next_element::<serde_json::Value>()? {
            if let Some(type_name) = value.get("type").and_then(|t| t.as_str())
                && (type_name == "Relationship" || type_name == "LifecycleScopedRelationship")
            {
                // Parse as JSON-LD relationship
                let rel: JsonLdRelationship =
                    serde_json::from_value(value).map_err(de::Error::custom)?;

                // Convert to simple format and add to index
                for target in &rel.to {
                    let simple_rel = SpdxRelationshipMinimal {
                        spdx_element_id: rel.from.clone(),
                        relationship_type: rel.relationship_type.clone(),
                        related_spdx_element: target.clone(),
                    };
                    self.index
                        .entry(simple_rel.spdx_element_id.clone())
                        .or_default()
                        .push(simple_rel);
                    self.progress.increment_relationship();
                }
            }
        }
        Ok(())
    }
}

/// Custom visitor for Pass 2 (Conversion Pass)
pub struct SpdxPass2Visitor<'a, W: std::io::Write> {
    pub writer: &'a mut BufWriter<W>,
    pub index: &'a crate::converter_spdx_to_cdx::SpdxRelationshipIndex,
    pub first_component: bool,
    pub first_vulnerability: bool,
    pub progress: crate::progress::ProgressTracker,
    pub packages_only: bool,
}

impl<'de, 'a, W: std::io::Write> Visitor<'de> for SpdxPass2Visitor<'a, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a top-level SPDX JSON object (simple or JSON-LD format)")
    }

    fn visit_map<M>(mut self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut found_elements = false;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "elements" => {
                    // Simple JSON format: Found elements array
                    found_elements = true;
                    map.next_value_seed(SpdxElementStreamVisitor { state: &mut self })?;
                }
                "@graph" => {
                    // JSON-LD format: Process @graph array for elements
                    found_elements = true;
                    map.next_value_seed(JsonLdGraphPass2Visitor { state: &mut self })?;
                }
                _ => {
                    // Skip all other keys
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if !found_elements {
            eprintln!(
                "Warning: No elements found in SPDX file (looked for 'elements' or '@graph')"
            );
        }
        Ok(())
    }
}

/// Visitor for the 'elements' array in Pass 2
pub struct SpdxElementStreamVisitor<'a, 'b, W: std::io::Write> {
    state: &'b mut SpdxPass2Visitor<'a, W>,
}

impl<'de, 'a, 'b, W: std::io::Write> de::DeserializeSeed<'de>
    for SpdxElementStreamVisitor<'a, 'b, W>
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a, 'b, W: std::io::Write> Visitor<'de> for SpdxElementStreamVisitor<'a, 'b, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of SPDX elements")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while let Some(element) = seq.next_element::<SpdxElementMinimal>()? {
            // This is where we call the conversion logic
            crate::converter_spdx_to_cdx::handle_spdx_element(
                element,
                self.state.writer,
                self.state.index,
                &mut self.state.first_component,
                &mut self.state.first_vulnerability,
            )
            .map_err(de::Error::custom)?;
            self.state.progress.increment_element();
        }
        Ok(())
    }
}

/// Visitor for the '@graph' array in Pass 2 (Conversion)
pub struct JsonLdGraphPass2Visitor<'a, 'b, W: std::io::Write> {
    state: &'b mut SpdxPass2Visitor<'a, W>,
}

impl<'de, 'a, 'b, W: std::io::Write> de::DeserializeSeed<'de>
    for JsonLdGraphPass2Visitor<'a, 'b, W>
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a, 'b, W: std::io::Write> Visitor<'de> for JsonLdGraphPass2Visitor<'a, 'b, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of JSON-LD objects in @graph")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        // In Pass 2, we only care about elements (packages, files, vulnerabilities)
        while let Some(value) = seq.next_element::<serde_json::Value>()? {
            if let Some(type_name) = value.get("type").and_then(|t| t.as_str()) {
                // Skip files if packages_only is enabled
                if type_name == "software_File" && self.state.packages_only {
                    self.state.progress.increment_element();
                    continue;
                }

                if type_name == "software_Package" || type_name == "software_File" {
                    // Parse as JSON-LD element with full data
                    let element: JsonLdElement =
                        serde_json::from_value(value).map_err(de::Error::custom)?;

                    // Call enhanced handler with full element data
                    crate::converter_spdx_to_cdx::handle_jsonld_element(
                        element,
                        self.state.writer,
                        self.state.index,
                        &mut self.state.first_component,
                    )
                    .map_err(de::Error::custom)?;
                    self.state.progress.increment_element();
                } else if type_name == "security_Vulnerability" {
                    // Skip for now - will handle in Pass 3
                    self.state.progress.increment_element();
                }
            }
        }
        Ok(())
    }
}

/// Custom visitor for Pass 3 (Vulnerability Extraction Pass)
pub struct SpdxPass3VulnVisitor<'a, W: std::io::Write> {
    pub writer: &'a mut BufWriter<W>,
    pub serial_number: String,
    pub first_vuln: bool,
}

impl<'de, 'a, W: std::io::Write> Visitor<'de> for SpdxPass3VulnVisitor<'a, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a top-level SPDX JSON object for vulnerability extraction")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "@graph" {
                // This is JSON-LD format - process the graph
                let state = JsonLdVulnState {
                    writer: self.writer,
                    serial_number: &self.serial_number,
                    first_vuln: self.first_vuln,
                };
                map.next_value_seed(JsonLdGraphPass3Visitor { state })?;
            } else {
                // Skip other fields
                map.next_value::<serde_json::Value>()?;
            }
        }
        Ok(())
    }
}

/// Helper struct to hold state during Pass 3 graph processing
struct JsonLdVulnState<'a, 'b, W: std::io::Write> {
    writer: &'a mut BufWriter<W>,
    serial_number: &'b str,
    first_vuln: bool,
}

/// Visitor for @graph array in Pass 3 - extracts vulnerabilities and VEX relationships
struct JsonLdGraphPass3Visitor<'a, 'b, W: std::io::Write> {
    state: JsonLdVulnState<'a, 'b, W>,
}

impl<'de, 'a, 'b, W: std::io::Write> DeserializeSeed<'de> for JsonLdGraphPass3Visitor<'a, 'b, W> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a, 'b, W: std::io::Write> Visitor<'de> for JsonLdGraphPass3Visitor<'a, 'b, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("@graph array for vulnerability extraction")
    }

    fn visit_seq<A>(mut self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        // First pass: collect vulnerabilities
        let mut vulnerabilities: Vec<JsonLdVulnerability> = Vec::new();
        let mut vex_relationships: Vec<JsonLdVexRelationship> = Vec::new();

        // We need to collect all data first, then write
        // This requires deserializing the entire graph for this pass
        while let Some(element) = seq.next_element::<serde_json::Value>()? {
            if let Some(type_name) = element.get("type").and_then(|t| t.as_str()) {
                if type_name == "security_Vulnerability" {
                    if let Ok(vuln) = serde_json::from_value::<JsonLdVulnerability>(element) {
                        vulnerabilities.push(vuln);
                    }
                } else if type_name.starts_with("security_Vex")
                    && let Ok(vex) = serde_json::from_value::<JsonLdVexRelationship>(element)
                {
                    vex_relationships.push(vex);
                }
            }
        }

        // Now write vulnerabilities with their VEX assessments
        for vuln in vulnerabilities {
            if let Some(cve_id) = vuln.extract_cve_id() {
                // Find VEX relationships for this vulnerability
                let affects: Vec<String> = vex_relationships
                    .iter()
                    .filter(|vex| vex.from == vuln.spdx_id)
                    .flat_map(|vex| vex.to.iter())
                    .map(|spdx_id| {
                        let bom_ref = crate::converter_spdx_to_cdx::extract_bom_ref(spdx_id);
                        format!("{}#{}", self.state.serial_number, bom_ref)
                    })
                    .collect();

                // Determine VEX state
                let state = vex_relationships
                    .iter()
                    .find(|vex| vex.from == vuln.spdx_id)
                    .map(|vex| vex.map_state())
                    .unwrap_or_else(|| "not_affected".to_string());

                // Write vulnerability (even if no affects, for now)
                if !self.state.first_vuln {
                    self.state
                        .writer
                        .write_all(b",\n")
                        .map_err(de::Error::custom)?;
                }
                self.state.first_vuln = false;

                let cdx_vuln = crate::models_cdx::CdxVulnerability {
                    id: cve_id.clone(),
                    source: Some(crate::models_cdx::CdxVulnSource {
                        name: "NVD".to_string(),
                        url: Some(format!("https://nvd.nist.gov/vuln/detail/{}", cve_id)),
                    }),
                    description: None,
                    analysis: Some(crate::models_cdx::CdxAnalysis {
                        state,
                        detail: None,
                        first_issued: None,
                        last_updated: None,
                    }),
                    affects: Some(
                        affects
                            .into_iter()
                            .map(|ref_str| crate::models_cdx::CdxAffects { bom_ref: ref_str })
                            .collect(),
                    ),
                    extra: HashMap::new(),
                };

                self.state
                    .writer
                    .write_all(b"    ")
                    .map_err(de::Error::custom)?;
                serde_json::to_writer(&mut *self.state.writer, &cdx_vuln)
                    .map_err(de::Error::custom)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models_cdx::{CdxComponent, CdxHash};

    #[test]
    fn test_extract_cpe() {
        let mut pkg = SpdxElementMinimal {
            spdx_id: "SPDXRef-Package".to_string(),
            element_type: "SpdxPackage".to_string(),
            name: Some("test-package".to_string()),
            version_info: Some("1.0.0".to_string()),
            summary: None,
            purl: None,
            license_concluded: None,
            external_identifier: Some(vec![SpdxExternalIdentifier {
                id_type: "ExternalIdentifier".to_string(),
                external_identifier_type: Some("cpe23".to_string()),
                identifier: Some("cpe:2.3:a:vendor:product:1.0.0".to_string()),
            }]),
            verified_using: None,
            software_primary_purpose: None,
            extra: HashMap::new(),
        };

        assert_eq!(
            pkg.extract_cpe(),
            Some("cpe:2.3:a:vendor:product:1.0.0".to_string())
        );

        // Test with no external identifiers
        pkg.external_identifier = None;
        assert_eq!(pkg.extract_cpe(), None);

        // Test with wrong identifier type
        pkg.external_identifier = Some(vec![SpdxExternalIdentifier {
            id_type: "ExternalIdentifier".to_string(),
            external_identifier_type: Some("purl".to_string()),
            identifier: Some("pkg:maven/group/artifact".to_string()),
        }]);
        assert_eq!(pkg.extract_cpe(), None);
    }

    #[test]
    fn test_extract_purl() {
        let pkg = SpdxElementMinimal {
            spdx_id: "SPDXRef-Package".to_string(),
            element_type: "SpdxPackage".to_string(),
            name: Some("test-package".to_string()),
            version_info: Some("1.0.0".to_string()),
            summary: None,
            purl: None,
            license_concluded: None,
            external_identifier: Some(vec![SpdxExternalIdentifier {
                id_type: "ExternalIdentifier".to_string(),
                external_identifier_type: Some("purl".to_string()),
                identifier: Some("pkg:maven/com.example/my-library@1.0.0".to_string()),
            }]),
            verified_using: None,
            software_primary_purpose: None,
            extra: HashMap::new(),
        };

        assert_eq!(
            pkg.extract_purl(),
            Some("pkg:maven/com.example/my-library@1.0.0".to_string())
        );
    }

    #[test]
    fn test_extract_hashes() {
        let pkg = SpdxElementMinimal {
            spdx_id: "SPDXRef-Package".to_string(),
            element_type: "SpdxPackage".to_string(),
            name: Some("test-package".to_string()),
            version_info: Some("1.0.0".to_string()),
            summary: None,
            purl: None,
            license_concluded: None,
            external_identifier: None,
            verified_using: Some(vec![
                SpdxHash {
                    hash_type: "Hash".to_string(),
                    algorithm: Some("SHA256".to_string()),
                    hash_value: Some("abc123".to_string()),
                },
                SpdxHash {
                    hash_type: "Hash".to_string(),
                    algorithm: Some("SHA1".to_string()),
                    hash_value: Some("def456".to_string()),
                },
            ]),
            software_primary_purpose: None,
            extra: HashMap::new(),
        };

        let hashes = pkg.extract_hashes().unwrap();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0].alg, "SHA-256");
        assert_eq!(hashes[0].content, "abc123");
        assert_eq!(hashes[1].alg, "SHA-1");
        assert_eq!(hashes[1].content, "def456");
    }

    #[test]
    fn test_hash_normalization() {
        // Test lowercase input is normalized to uppercase with dashes
        let pkg = SpdxElementMinimal {
            spdx_id: "SPDXRef-Package".to_string(),
            element_type: "SpdxPackage".to_string(),
            name: Some("test-package".to_string()),
            version_info: Some("1.0.0".to_string()),
            summary: None,
            purl: None,
            license_concluded: None,
            external_identifier: None,
            verified_using: Some(vec![SpdxHash {
                hash_type: "Hash".to_string(),
                algorithm: Some("sha256".to_string()),
                hash_value: Some("abc123".to_string()),
            }]),
            software_primary_purpose: None,
            extra: HashMap::new(),
        };

        let hashes = pkg.extract_hashes().unwrap();
        assert_eq!(hashes[0].alg, "SHA-256");
    }

    #[test]
    fn test_map_scope() {
        let mut pkg = SpdxElementMinimal {
            spdx_id: "SPDXRef-Package".to_string(),
            element_type: "SpdxPackage".to_string(),
            name: Some("test-package".to_string()),
            version_info: Some("1.0.0".to_string()),
            summary: None,
            purl: None,
            license_concluded: None,
            external_identifier: None,
            verified_using: None,
            software_primary_purpose: Some("install".to_string()),
            extra: HashMap::new(),
        };

        assert_eq!(pkg.map_scope(), Some("required".to_string()));

        pkg.software_primary_purpose = Some("source".to_string());
        assert_eq!(pkg.map_scope(), Some("excluded".to_string()));

        pkg.software_primary_purpose = Some("build".to_string());
        assert_eq!(pkg.map_scope(), Some("excluded".to_string()));

        pkg.software_primary_purpose = Some("other".to_string());
        assert_eq!(pkg.map_scope(), None);

        pkg.software_primary_purpose = None;
        assert_eq!(pkg.map_scope(), None);
    }

    #[test]
    fn test_from_cdx_component_with_metadata() {
        let cdx_comp = CdxComponent {
            component_type: "library".to_string(),
            bom_ref: "pkg-123".to_string(),
            name: "my-library".to_string(),
            version: Some("2.0.0".to_string()),
            purl: Some("pkg:npm/my-library@2.0.0".to_string()),
            cpe: Some("cpe:2.3:a:vendor:my-library:2.0.0".to_string()),
            description: Some("A test library".to_string()),
            hashes: Some(vec![CdxHash {
                alg: "SHA-256".to_string(),
                content: "abcdef123456".to_string(),
            }]),
            scope: Some("required".to_string()),
            licenses: None,
            extra: HashMap::new(),
        };

        let spdx_pkg = SpdxPackage::from_cdx_component(&cdx_comp);

        assert_eq!(spdx_pkg.spdx_id, "SPDXRef-pkg-123");
        assert_eq!(spdx_pkg.name, "my-library");
        assert_eq!(spdx_pkg.version_info, Some("2.0.0".to_string()));
        assert_eq!(spdx_pkg.summary, Some("A test library".to_string()));
        assert_eq!(spdx_pkg.purl, Some("pkg:npm/my-library@2.0.0".to_string()));

        // Verify CPE mapping
        let ext_ids = spdx_pkg.external_identifier.unwrap();
        assert_eq!(ext_ids.len(), 1);
        assert_eq!(
            ext_ids[0].external_identifier_type,
            Some("cpe23Type".to_string())
        );
        assert_eq!(
            ext_ids[0].identifier,
            Some("cpe:2.3:a:vendor:my-library:2.0.0".to_string())
        );

        // Verify hash mapping (SHA-256 -> sha-256)
        let hashes = spdx_pkg.verified_using.unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].algorithm, Some("sha-256".to_string()));
        assert_eq!(hashes[0].hash_value, Some("abcdef123456".to_string()));

        // Verify scope mapping (required -> install)
        assert_eq!(
            spdx_pkg.software_primary_purpose,
            Some("install".to_string())
        );
    }

    #[test]
    fn test_from_cdx_component_without_metadata() {
        let cdx_comp = CdxComponent {
            component_type: "library".to_string(),
            bom_ref: "minimal-pkg".to_string(),
            name: "minimal-library".to_string(),
            version: None,
            purl: None,
            cpe: None,
            description: None,
            hashes: None,
            scope: None,
            licenses: None,
            extra: HashMap::new(),
        };

        let spdx_pkg = SpdxPackage::from_cdx_component(&cdx_comp);

        assert_eq!(spdx_pkg.spdx_id, "SPDXRef-minimal-pkg");
        assert_eq!(spdx_pkg.name, "minimal-library");
        assert!(spdx_pkg.version_info.is_none());
        assert!(spdx_pkg.summary.is_none());
        assert!(spdx_pkg.purl.is_none());
        assert!(spdx_pkg.external_identifier.is_none());
        assert!(spdx_pkg.verified_using.is_none());
        assert!(spdx_pkg.software_primary_purpose.is_none());
    }

    #[test]
    fn test_scope_mapping_bidirectional() {
        // Test required <-> install
        let mut cdx_comp = CdxComponent {
            component_type: "library".to_string(),
            bom_ref: "test".to_string(),
            name: "test".to_string(),
            version: None,
            purl: None,
            cpe: None,
            description: None,
            hashes: None,
            scope: Some("required".to_string()),
            licenses: None,
            extra: HashMap::new(),
        };

        let spdx_pkg = SpdxPackage::from_cdx_component(&cdx_comp);
        assert_eq!(
            spdx_pkg.software_primary_purpose,
            Some("install".to_string())
        );

        // Test optional <-> optional
        cdx_comp.scope = Some("optional".to_string());
        let spdx_pkg = SpdxPackage::from_cdx_component(&cdx_comp);
        assert_eq!(
            spdx_pkg.software_primary_purpose,
            Some("optional".to_string())
        );

        // Test excluded -> other
        cdx_comp.scope = Some("excluded".to_string());
        let spdx_pkg = SpdxPackage::from_cdx_component(&cdx_comp);
        assert_eq!(spdx_pkg.software_primary_purpose, Some("other".to_string()));
    }
}
