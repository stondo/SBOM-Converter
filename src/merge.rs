//! SBOM merge functionality
//!
//! Merges multiple SBOM files into a single consolidated SBOM.
//! Supports both CycloneDX and SPDX formats.

use crate::errors::ConverterError;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;

/// Deduplication strategy for merging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupStrategy {
    /// Keep the first occurrence of a duplicate component
    First,
    /// Keep the latest (last) occurrence of a duplicate component
    Latest,
}

impl Default for DedupStrategy {
    fn default() -> Self {
        Self::First
    }
}

impl FromStr for DedupStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "first" => Ok(Self::First),
            "latest" | "last" => Ok(Self::Latest),
            _ => Err(format!("Invalid dedup strategy: {}", s)),
        }
    }
}

/// Merge multiple CycloneDX SBOM files
pub fn merge_cyclonedx_files(
    input_paths: &[impl AsRef<Path>],
    dedup_strategy: DedupStrategy,
) -> Result<Value, ConverterError> {
    let mut merged_components: HashMap<String, Value> = HashMap::new();
    let mut merged_dependencies: HashMap<String, HashSet<String>> = HashMap::new();
    let mut merged_vulnerabilities: Vec<Value> = Vec::new();

    let mut metadata: Option<Value> = None;
    let mut serial_number: Option<String> = None;
    let mut spec_version: String = "1.6".to_string();

    // Read and merge each input file
    for (idx, input_path) in input_paths.iter().enumerate() {
        let content = fs::read_to_string(input_path.as_ref()).map_err(|e| {
            ConverterError::Io(
                e,
                format!("Failed to read file: {}", input_path.as_ref().display()),
            )
        })?;

        let bom: Value = serde_json::from_str(&content).map_err(|e| {
            ConverterError::ParseError(format!(
                "Invalid JSON in {}: {}",
                input_path.as_ref().display(),
                e
            ))
        })?;

        // Validate it's a CycloneDX BOM
        if bom.get("bomFormat").and_then(|v| v.as_str()) != Some("CycloneDX") {
            return Err(ConverterError::ParseError(format!(
                "File {} is not a CycloneDX SBOM",
                input_path.as_ref().display()
            )));
        }

        // Use metadata from first file
        if idx == 0 {
            metadata = bom.get("metadata").cloned();
            serial_number = bom
                .get("serialNumber")
                .and_then(|v| v.as_str())
                .map(String::from);
            if let Some(v) = bom.get("specVersion").and_then(|v| v.as_str()) {
                spec_version = v.to_string();
            }
        }

        // Merge components
        if let Some(components) = bom.get("components").and_then(|v| v.as_array()) {
            for component in components {
                let key = get_component_key(component);
                match dedup_strategy {
                    DedupStrategy::First => {
                        merged_components
                            .entry(key)
                            .or_insert_with(|| component.clone());
                    }
                    DedupStrategy::Latest => {
                        merged_components.insert(key, component.clone());
                    }
                }
            }
        }

        // Merge dependencies
        if let Some(dependencies) = bom.get("dependencies").and_then(|v| v.as_array()) {
            for dep in dependencies {
                if let Some(ref_id) = dep.get("ref").and_then(|v| v.as_str()) {
                    let depends_on = dep
                        .get("dependsOn")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect::<HashSet<_>>()
                        })
                        .unwrap_or_default();

                    merged_dependencies
                        .entry(ref_id.to_string())
                        .or_default()
                        .extend(depends_on);
                }
            }
        }

        // Merge vulnerabilities
        if let Some(vulnerabilities) = bom.get("vulnerabilities").and_then(|v| v.as_array()) {
            merged_vulnerabilities.extend(vulnerabilities.iter().cloned());
        }
    }

    // Build merged BOM
    let mut merged_bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
    });

    if let Some(sn) = serial_number {
        merged_bom["serialNumber"] = json!(sn);
    } else {
        merged_bom["serialNumber"] = json!(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
    }

    if let Some(meta) = metadata {
        merged_bom["metadata"] = meta;
    }

    // Convert components HashMap to array
    let components: Vec<Value> = merged_components.into_values().collect();
    merged_bom["components"] = json!(components);

    // Convert dependencies HashMap to array
    let dependencies: Vec<Value> = merged_dependencies
        .into_iter()
        .map(|(ref_id, depends_on)| {
            let depends_on_vec: Vec<String> = depends_on.into_iter().collect();
            json!({
                "ref": ref_id,
                "dependsOn": depends_on_vec
            })
        })
        .collect();
    merged_bom["dependencies"] = json!(dependencies);

    // Add vulnerabilities if any
    if !merged_vulnerabilities.is_empty() {
        merged_bom["vulnerabilities"] = json!(merged_vulnerabilities);
    }

    Ok(merged_bom)
}

/// Merge multiple SPDX SBOM files
pub fn merge_spdx_files(
    input_paths: &[impl AsRef<Path>],
    dedup_strategy: DedupStrategy,
) -> Result<Value, ConverterError> {
    let mut merged_elements: HashMap<String, Value> = HashMap::new();
    let mut merged_relationships: Vec<Value> = Vec::new();

    let mut creation_info: Option<Value> = None;
    let mut document_namespace: Option<String> = None;
    let mut spdx_version: String = "3.0.1".to_string();

    // Read and merge each input file
    for (idx, input_path) in input_paths.iter().enumerate() {
        let content = fs::read_to_string(input_path.as_ref()).map_err(|e| {
            ConverterError::Io(
                e,
                format!("Failed to read file: {}", input_path.as_ref().display()),
            )
        })?;

        let doc: Value = serde_json::from_str(&content).map_err(|e| {
            ConverterError::ParseError(format!(
                "Invalid JSON in {}: {}",
                input_path.as_ref().display(),
                e
            ))
        })?;

        // Check if it's SPDX (either simple JSON or JSON-LD)
        let is_spdx = doc.get("spdxVersion").is_some()
            || doc
                .get("@context")
                .and_then(|v| v.as_str())
                .map(|s| s.contains("spdx"))
                .unwrap_or(false);

        if !is_spdx {
            return Err(ConverterError::ParseError(format!(
                "File {} is not an SPDX SBOM",
                input_path.as_ref().display()
            )));
        }

        // Use metadata from first file
        if idx == 0 {
            creation_info = doc.get("creationInfo").cloned();
            document_namespace = doc
                .get("documentNamespace")
                .and_then(|v| v.as_str())
                .map(String::from);
            if let Some(v) = doc.get("spdxVersion").and_then(|v| v.as_str()) {
                spdx_version = v.to_string();
            }
        }

        // Merge elements (for simple SPDX JSON)
        if let Some(elements) = doc.get("elements").and_then(|v| v.as_array()) {
            for element in elements {
                let key = get_spdx_element_key(element);
                match dedup_strategy {
                    DedupStrategy::First => {
                        merged_elements
                            .entry(key)
                            .or_insert_with(|| element.clone());
                    }
                    DedupStrategy::Latest => {
                        merged_elements.insert(key, element.clone());
                    }
                }
            }
        }

        // Merge @graph (for SPDX JSON-LD)
        if let Some(graph) = doc.get("@graph").and_then(|v| v.as_array()) {
            for element in graph {
                // Skip CreationInfo from subsequent files
                if element.get("@type").and_then(|v| v.as_str()) == Some("CreationInfo") && idx > 0
                {
                    continue;
                }

                let key = get_spdx_element_key(element);
                match dedup_strategy {
                    DedupStrategy::First => {
                        merged_elements
                            .entry(key)
                            .or_insert_with(|| element.clone());
                    }
                    DedupStrategy::Latest => {
                        merged_elements.insert(key, element.clone());
                    }
                }
            }
        }

        // Merge relationships
        if let Some(relationships) = doc.get("relationships").and_then(|v| v.as_array()) {
            merged_relationships.extend(relationships.iter().cloned());
        }
    }

    // Build merged SPDX document (simple JSON format)
    let mut merged_doc = json!({
        "spdxVersion": spdx_version,
    });

    if let Some(ns) = document_namespace {
        merged_doc["documentNamespace"] = json!(ns);
    } else {
        merged_doc["documentNamespace"] = json!(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
    }

    if let Some(info) = creation_info {
        merged_doc["creationInfo"] = info;
    }

    // Convert elements HashMap to array
    let elements: Vec<Value> = merged_elements.into_values().collect();
    merged_doc["elements"] = json!(elements);

    // Add relationships if any
    if !merged_relationships.is_empty() {
        merged_doc["relationships"] = json!(merged_relationships);
    }

    Ok(merged_doc)
}

/// Generate a unique key for a CycloneDX component
fn get_component_key(component: &Value) -> String {
    // Try purl first (Package URL is the best unique identifier)
    if let Some(purl) = component.get("purl").and_then(|v| v.as_str()) {
        return purl.to_string();
    }

    // Fall back to bom-ref
    if let Some(bom_ref) = component.get("bom-ref").and_then(|v| v.as_str()) {
        return bom_ref.to_string();
    }

    // Fall back to name + version
    let name = component
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let version = component
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    format!("{}@{}", name, version)
}

/// Generate a unique key for an SPDX element
fn get_spdx_element_key(element: &Value) -> String {
    // Try @id first (for JSON-LD)
    if let Some(id) = element.get("@id").and_then(|v| v.as_str()) {
        return id.to_string();
    }

    // Try spdxId
    if let Some(spdx_id) = element.get("spdxId").and_then(|v| v.as_str()) {
        return spdx_id.to_string();
    }

    // Fall back to name + version
    let name = element
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let version = element
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    format!("{}@{}", name, version)
}

/// Convert merged CycloneDX JSON Value to CdxDocument for XML serialization  
pub fn value_to_cdx_document(
    value: &Value,
) -> Result<crate::formats::cdx::CdxDocument, ConverterError> {
    use crate::formats::cdx::document::{
        CdxComponent, CdxComponents, CdxDependencies, CdxDependency, CdxDocument,
        CdxVulnerabilities, CdxVulnerability,
    };

    // The JSON structure uses "type" but XML struct uses "@type"
    // We need to transform the JSON to match XML expectations
    let mut xml_value = value.clone();

    // Transform components: "type" -> "@type", add "@" prefix to attributes
    if let Some(components) = xml_value
        .get_mut("components")
        .and_then(|c| c.as_array_mut())
    {
        for component in components {
            if let Some(obj) = component.as_object_mut() {
                // Rename "type" to "@type"
                if let Some(type_val) = obj.remove("type") {
                    obj.insert("@type".to_string(), type_val);
                }
                // Rename "bom-ref" to "@bom-ref"
                if let Some(bom_ref) = obj.remove("bom-ref") {
                    obj.insert("@bom-ref".to_string(), bom_ref);
                }
            }
        }
    }

    // Transform dependencies structure for XML
    if let Some(deps) = xml_value
        .get_mut("dependencies")
        .and_then(|d| d.as_array_mut())
    {
        for dep in deps {
            if let Some(obj) = dep.as_object_mut() {
                // Rename "ref" to "@ref"
                if let Some(ref_val) = obj.remove("ref") {
                    obj.insert("@ref".to_string(), ref_val);
                }
                // Transform dependsOn array to proper structure
                if let Some(depends_on) = obj.get_mut("dependsOn")
                    && let Some(arr) = depends_on.as_array()
                {
                    let deps_vec: Vec<Value> = arr.iter().map(|d| json!({"@ref": d})).collect();
                    *depends_on = json!({"dependency": deps_vec});
                }
            }
        }
    }

    // Build CdxDocument manually
    let json_bom = xml_value.as_object().ok_or_else(|| {
        ConverterError::SerializationError("BOM is not a valid JSON object".to_string())
    })?;

    let mut doc = CdxDocument {
        xmlns: Some("http://cyclonedx.org/schema/bom/1.6".to_string()),
        bom_format: Some("CycloneDX".to_string()),
        spec_version: json_bom
            .get("specVersion")
            .and_then(|v| v.as_str())
            .map(String::from),
        version: json_bom
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32,
        serial_number: json_bom
            .get("serialNumber")
            .and_then(|v| v.as_str())
            .map(String::from),
        metadata: None,
        components: None,
        dependencies: None,
        vulnerabilities: None,
    };

    // Handle components
    if let Some(components_array) = json_bom.get("components").and_then(|c| c.as_array()) {
        let components: Result<Vec<CdxComponent>, _> = components_array
            .iter()
            .map(|c| serde_json::from_value(c.clone()))
            .collect();

        doc.components = Some(CdxComponents {
            components: components.map_err(|e| {
                ConverterError::SerializationError(format!("Failed to parse components: {}", e))
            })?,
        });
    }

    // Handle dependencies
    if let Some(deps_array) = json_bom.get("dependencies").and_then(|d| d.as_array()) {
        let dependencies: Result<Vec<CdxDependency>, _> = deps_array
            .iter()
            .map(|d| serde_json::from_value(d.clone()))
            .collect();

        doc.dependencies = Some(CdxDependencies {
            dependencies: dependencies.map_err(|e| {
                ConverterError::SerializationError(format!("Failed to parse dependencies: {}", e))
            })?,
        });
    }

    // Handle vulnerabilities
    if let Some(vulns_array) = json_bom.get("vulnerabilities").and_then(|v| v.as_array()) {
        let vulnerabilities: Result<Vec<CdxVulnerability>, _> = vulns_array
            .iter()
            .map(|v| serde_json::from_value(v.clone()))
            .collect();

        doc.vulnerabilities = Some(CdxVulnerabilities {
            vulnerabilities: vulnerabilities.map_err(|e| {
                ConverterError::SerializationError(format!(
                    "Failed to parse vulnerabilities: {}",
                    e
                ))
            })?,
        });
    }

    // Handle metadata
    if let Some(metadata_val) = json_bom.get("metadata") {
        doc.metadata = Some(serde_json::from_value(metadata_val.clone()).map_err(|e| {
            ConverterError::SerializationError(format!("Failed to parse metadata: {}", e))
        })?);
    }

    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_key_with_purl() {
        let component = json!({
            "name": "test-package",
            "version": "1.0.0",
            "purl": "pkg:npm/test-package@1.0.0",
            "bom-ref": "pkg-123"
        });

        assert_eq!(get_component_key(&component), "pkg:npm/test-package@1.0.0");
    }

    #[test]
    fn test_component_key_with_bom_ref() {
        let component = json!({
            "name": "test-package",
            "version": "1.0.0",
            "bom-ref": "pkg-123"
        });

        assert_eq!(get_component_key(&component), "pkg-123");
    }

    #[test]
    fn test_component_key_fallback() {
        let component = json!({
            "name": "test-package",
            "version": "1.0.0"
        });

        assert_eq!(get_component_key(&component), "test-package@1.0.0");
    }

    #[test]
    fn test_dedup_strategy_from_str() {
        use std::str::FromStr;
        assert_eq!(DedupStrategy::from_str("first"), Ok(DedupStrategy::First));
        assert_eq!(DedupStrategy::from_str("latest"), Ok(DedupStrategy::Latest));
        assert_eq!(DedupStrategy::from_str("last"), Ok(DedupStrategy::Latest));
        assert!(DedupStrategy::from_str("invalid").is_err());
    }
}
