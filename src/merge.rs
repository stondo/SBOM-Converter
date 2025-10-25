//! SBOM merge functionality
//!
//! Merges multiple SBOM files into a single consolidated SBOM.
//! Supports both CycloneDX and SPDX formats.

use crate::errors::ConverterError;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

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

impl DedupStrategy {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "first" => Some(Self::First),
            "latest" | "last" => Some(Self::Latest),
            _ => None,
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
                        .or_insert_with(HashSet::new)
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
        assert_eq!(DedupStrategy::from_str("first"), Some(DedupStrategy::First));
        assert_eq!(
            DedupStrategy::from_str("latest"),
            Some(DedupStrategy::Latest)
        );
        assert_eq!(DedupStrategy::from_str("last"), Some(DedupStrategy::Latest));
        assert_eq!(DedupStrategy::from_str("invalid"), None);
    }
}
