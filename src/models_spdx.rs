//! Contains *minimal* data structures for streaming SPDX 3.0.1 JSON.
//!
//! We also define the *output* structs for serialization.

use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io::BufWriter;

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
    pub from: String, // source element ID
    pub relationship_type: String, // e.g., "hasDeclaredLicense", "contains", "dependsOn"
    pub to: Vec<String>, // target element IDs (can be multiple)
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
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_concluded: Option<String>, // SPDX expression
    // We use IgnoredAny to quickly skip over fields we don't need
    #[serde(flatten)]
    pub extra: HashMap<String, IgnoredAny>,
}

/// Minimal struct for JSON-LD Element format
#[derive(Deserialize, Debug)]
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
    // We use IgnoredAny to quickly skip over fields we don't need
    #[serde(flatten)]
    pub extra: HashMap<String, IgnoredAny>,
}

impl JsonLdElement {
    /// Convert JSON-LD element to simple format for processing
    pub fn to_simple(&self) -> SpdxElementMinimal {
        SpdxElementMinimal {
            spdx_id: self.spdx_id.clone(),
            element_type: self.element_type.clone(),
            name: self.name.clone(),
            version_info: self.software_package_version.clone(),
            purl: None, // Would need to extract from externalIdentifier
            license_concluded: None, // Would need to extract from relationships
            extra: HashMap::new(),
        }
    }
}

// --- Full Serialization Structs (for writing) ---

/// Top-level SPDX Document (minimal)
#[derive(Serialize, Debug)]
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

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SpdxCreationInfo {
    pub created: String, // ISO 8601
    pub creators: Vec<String>,
}

/// Represents an SPDX Package (element)
#[derive(Serialize, Debug)]
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
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_concluded: Option<String>,
}

impl SpdxPackage {
    pub fn from_cdx_component(comp: &crate::models_cdx::CdxComponent) -> Self {
        Self {
            spdx_id: format!("SPDXRef-{}", comp.bom_ref),
            element_type: if comp.component_type == "file" {
                "SpdxFile".to_string()
            } else {
                "SpdxPackage".to_string()
            },
            name: comp.name.clone(),
            version_info: comp.version.clone(),
            purl: comp.purl.clone(),
            license_concluded: comp
                .licenses
                .as_ref()
                .and_then(|lics| lics.first())
                .and_then(|l| l.expression.clone()),
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
            eprintln!("Warning: No relationships found in SPDX file (looked for 'relationships' or '@graph')");
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
            if let Some(type_name) = value.get("type").and_then(|t| t.as_str()) {
                if type_name == "Relationship" || type_name == "LifecycleScopedRelationship" {
                    // Parse as JSON-LD relationship
                    let rel: JsonLdRelationship = serde_json::from_value(value)
                        .map_err(de::Error::custom)?;
                    
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
            eprintln!("Warning: No elements found in SPDX file (looked for 'elements' or '@graph')");
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
                if type_name == "software_Package" || type_name == "software_File" || type_name == "security_Vulnerability" {
                    // Parse as JSON-LD element
                    let element: JsonLdElement = serde_json::from_value(value)
                        .map_err(de::Error::custom)?;
                    
                    // Convert to simple format and process
                    let simple_element = element.to_simple();
                    crate::converter_spdx_to_cdx::handle_spdx_element(
                        simple_element,
                        self.state.writer,
                        self.state.index,
                        &mut self.state.first_component,
                        &mut self.state.first_vulnerability,
                    )
                    .map_err(de::Error::custom)?;
                    self.state.progress.increment_element();
                }
            }
        }
        Ok(())
    }
}

