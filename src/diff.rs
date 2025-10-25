//! SBOM diff functionality
//!
//! Compares two SBOM files and generates a detailed report of differences.
//! Supports both CycloneDX and SPDX formats.

use crate::errors::ConverterError;
use crate::version_detection::{SbomFormat, detect_format};
use colored::Colorize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Represents the differences between two SBOMs
#[derive(Debug, Clone)]
pub struct DiffReport {
    pub format1: SbomFormat,
    pub format2: SbomFormat,
    pub added_components: Vec<ComponentInfo>,
    pub removed_components: Vec<ComponentInfo>,
    pub modified_components: Vec<ComponentDiff>,
    pub common_components: Vec<ComponentInfo>,
    pub added_dependencies: Vec<DependencyInfo>,
    pub removed_dependencies: Vec<DependencyInfo>,
    pub added_vulnerabilities: Vec<VulnerabilityInfo>,
    pub removed_vulnerabilities: Vec<VulnerabilityInfo>,
    pub metadata_changes: Vec<MetadataChange>,
}

/// Simplified component information
#[derive(Debug, Clone)]
pub struct ComponentInfo {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub component_type: Option<String>,
}

/// Component-level differences
#[derive(Debug, Clone)]
pub struct ComponentDiff {
    pub name: String,
    pub version: Option<String>,
    pub changes: Vec<String>,
}

/// Dependency relationship information
#[derive(Debug, Clone)]
pub struct DependencyInfo {
    pub from: String,
    pub to: String,
}

/// Vulnerability information
#[derive(Debug, Clone)]
pub struct VulnerabilityInfo {
    pub id: String,
    pub source: Option<String>,
    pub affected_component: Option<String>,
}

/// Metadata change information
#[derive(Debug, Clone)]
pub struct MetadataChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

impl DiffReport {
    /// Format the diff report as human-readable text
    pub fn format_text(&self, diff_only: bool) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "═══════════════════════════════════════════════════════════\n"
        ));
        output.push_str(&format!("                    SBOM DIFF REPORT\n"));
        output.push_str(&format!(
            "═══════════════════════════════════════════════════════════\n\n"
        ));

        output.push_str(&format!("Format 1: {}\n", self.format1.description()));
        output.push_str(&format!("Format 2: {}\n", self.format2.description()));
        output.push_str(&format!("\n"));

        // Summary
        output.push_str(&format!(
            "───────────────────────────────────────────────────────────\n"
        ));
        output.push_str(&format!("  SUMMARY\n"));
        output.push_str(&format!(
            "───────────────────────────────────────────────────────────\n"
        ));
        output.push_str(&format!(
            "  Components added:      {}\n",
            self.added_components.len()
        ));
        output.push_str(&format!(
            "  Components removed:    {}\n",
            self.removed_components.len()
        ));
        output.push_str(&format!(
            "  Components modified:   {}\n",
            self.modified_components.len()
        ));
        output.push_str(&format!(
            "  Components unchanged:  {}\n",
            self.common_components.len()
        ));
        output.push_str(&format!(
            "  Dependencies added:    {}\n",
            self.added_dependencies.len()
        ));
        output.push_str(&format!(
            "  Dependencies removed:  {}\n",
            self.removed_dependencies.len()
        ));
        output.push_str(&format!(
            "  Vulnerabilities added:   {}\n",
            self.added_vulnerabilities.len()
        ));
        output.push_str(&format!(
            "  Vulnerabilities removed: {}\n",
            self.removed_vulnerabilities.len()
        ));
        output.push_str(&format!("\n"));

        // Added components
        if !self.added_components.is_empty() {
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            output.push_str(&format!("  {} COMPONENTS ADDED\n", "✓".green()));
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            for comp in &self.added_components {
                output.push_str(&format!("  + {}\n", format_component(comp).green()));
            }
            output.push_str("\n");
        }

        // Removed components
        if !self.removed_components.is_empty() {
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            output.push_str(&format!("  {} COMPONENTS REMOVED\n", "✗".red()));
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            for comp in &self.removed_components {
                output.push_str(&format!("  - {}\n", format_component(comp).red()));
            }
            output.push_str("\n");
        }

        // Modified components
        if !self.modified_components.is_empty() {
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            output.push_str(&format!("  {} COMPONENTS MODIFIED\n", "~".yellow()));
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            for comp in &self.modified_components {
                let comp_name = if let Some(ver) = &comp.version {
                    format!("{} ({})", comp.name, ver)
                } else {
                    comp.name.clone()
                };
                output.push_str(&format!("  ~ {}\n", comp_name.yellow()));
                for change in &comp.changes {
                    output.push_str(&format!("      {}\n", change));
                }
            }
            output.push_str("\n");
        }

        // Common components (only if not diff_only)
        if !diff_only && !self.common_components.is_empty() {
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            output.push_str(&format!(
                "  COMPONENTS UNCHANGED ({})\n",
                self.common_components.len()
            ));
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            for comp in self.common_components.iter().take(10) {
                output.push_str(&format!("  = {}\n", format_component(comp)));
            }
            if self.common_components.len() > 10 {
                output.push_str(&format!(
                    "  ... and {} more\n",
                    self.common_components.len() - 10
                ));
            }
            output.push_str("\n");
        }

        // Dependencies
        if !self.added_dependencies.is_empty() {
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            output.push_str(&format!("  {} DEPENDENCIES ADDED\n", "✓".green()));
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            for dep in &self.added_dependencies {
                output.push_str(
                    &format!("  + {} → {}\n", dep.from, dep.to)
                        .green()
                        .to_string()
                        .as_str(),
                );
            }
            output.push_str("\n");
        }

        if !self.removed_dependencies.is_empty() {
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            output.push_str(&format!("  {} DEPENDENCIES REMOVED\n", "✗".red()));
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            for dep in &self.removed_dependencies {
                output.push_str(
                    &format!("  - {} → {}\n", dep.from, dep.to)
                        .red()
                        .to_string()
                        .as_str(),
                );
            }
            output.push_str("\n");
        }

        // Vulnerabilities
        if !self.added_vulnerabilities.is_empty() {
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            output.push_str(&format!("  {} VULNERABILITIES ADDED\n", "⚠".yellow()));
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            for vuln in &self.added_vulnerabilities {
                output.push_str(
                    &format!("  + {}\n", format_vulnerability(vuln))
                        .yellow()
                        .to_string()
                        .as_str(),
                );
            }
            output.push_str("\n");
        }

        if !self.removed_vulnerabilities.is_empty() {
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            output.push_str(&format!("  {} VULNERABILITIES REMOVED\n", "✓".green()));
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            for vuln in &self.removed_vulnerabilities {
                output.push_str(
                    &format!("  - {}\n", format_vulnerability(vuln))
                        .green()
                        .to_string()
                        .as_str(),
                );
            }
            output.push_str("\n");
        }

        // Metadata changes
        if !self.metadata_changes.is_empty() {
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            output.push_str(&format!("  METADATA CHANGES\n"));
            output.push_str(&format!(
                "───────────────────────────────────────────────────────────\n"
            ));
            for change in &self.metadata_changes {
                output.push_str(&format!(
                    "  {}: {} → {}\n",
                    change.field, change.old_value, change.new_value
                ));
            }
            output.push_str("\n");
        }

        output.push_str(&format!(
            "═══════════════════════════════════════════════════════════\n"
        ));

        output
    }

    /// Format the diff report as JSON
    pub fn format_json(&self) -> Result<String, ConverterError> {
        let json_report = json!({
            "format1": self.format1.description(),
            "format2": self.format2.description(),
            "summary": {
                "components_added": self.added_components.len(),
                "components_removed": self.removed_components.len(),
                "components_modified": self.modified_components.len(),
                "components_unchanged": self.common_components.len(),
                "dependencies_added": self.added_dependencies.len(),
                "dependencies_removed": self.removed_dependencies.len(),
                "vulnerabilities_added": self.added_vulnerabilities.len(),
                "vulnerabilities_removed": self.removed_vulnerabilities.len(),
            },
            "components": {
                "added": self.added_components.iter().map(component_to_json).collect::<Vec<_>>(),
                "removed": self.removed_components.iter().map(component_to_json).collect::<Vec<_>>(),
                "modified": self.modified_components.iter().map(|c| json!({
                    "name": c.name,
                    "version": c.version,
                    "changes": c.changes,
                })).collect::<Vec<_>>(),
                "common": self.common_components.iter().map(component_to_json).collect::<Vec<_>>(),
            },
            "dependencies": {
                "added": self.added_dependencies.iter().map(|d| json!({
                    "from": d.from,
                    "to": d.to,
                })).collect::<Vec<_>>(),
                "removed": self.removed_dependencies.iter().map(|d| json!({
                    "from": d.from,
                    "to": d.to,
                })).collect::<Vec<_>>(),
            },
            "vulnerabilities": {
                "added": self.added_vulnerabilities.iter().map(vuln_to_json).collect::<Vec<_>>(),
                "removed": self.removed_vulnerabilities.iter().map(vuln_to_json).collect::<Vec<_>>(),
            },
            "metadata_changes": self.metadata_changes.iter().map(|m| json!({
                "field": m.field,
                "old_value": m.old_value,
                "new_value": m.new_value,
            })).collect::<Vec<_>>(),
        });

        serde_json::to_string_pretty(&json_report).map_err(|e| {
            ConverterError::SerializationError(format!("Failed to format JSON: {}", e))
        })
    }
}

/// Compare two SBOM files and generate a diff report
pub fn diff_sboms(
    file1: impl AsRef<Path>,
    file2: impl AsRef<Path>,
) -> Result<DiffReport, ConverterError> {
    // Read both files
    let content1 = std::fs::read_to_string(file1.as_ref()).map_err(|e| {
        ConverterError::Io(
            e,
            format!("Failed to read file1: {}", file1.as_ref().display()),
        )
    })?;
    let content2 = std::fs::read_to_string(file2.as_ref()).map_err(|e| {
        ConverterError::Io(
            e,
            format!("Failed to read file2: {}", file2.as_ref().display()),
        )
    })?;

    let value1: Value = serde_json::from_str(&content1)
        .map_err(|e| ConverterError::ParseError(format!("Invalid JSON in file1: {}", e)))?;
    let value2: Value = serde_json::from_str(&content2)
        .map_err(|e| ConverterError::ParseError(format!("Invalid JSON in file2: {}", e)))?;

    // Detect formats
    let format1 = detect_format(&value1);
    let format2 = detect_format(&value2);

    // Compare based on format
    match (&format1, &format2) {
        (SbomFormat::CycloneDx(_), SbomFormat::CycloneDx(_)) => {
            diff_cyclonedx(&value1, &value2, format1, format2)
        }
        (SbomFormat::Spdx(_), SbomFormat::Spdx(_)) => diff_spdx(&value1, &value2, format1, format2),
        _ => Err(ConverterError::ParseError(format!(
            "Cannot compare different SBOM formats: {} vs {}",
            format1.description(),
            format2.description()
        ))),
    }
}

/// Compare two CycloneDX SBOMs
fn diff_cyclonedx(
    value1: &Value,
    value2: &Value,
    format1: SbomFormat,
    format2: SbomFormat,
) -> Result<DiffReport, ConverterError> {
    let mut report = DiffReport {
        format1,
        format2,
        added_components: Vec::new(),
        removed_components: Vec::new(),
        modified_components: Vec::new(),
        common_components: Vec::new(),
        added_dependencies: Vec::new(),
        removed_dependencies: Vec::new(),
        added_vulnerabilities: Vec::new(),
        removed_vulnerabilities: Vec::new(),
        metadata_changes: Vec::new(),
    };

    // Extract components
    let components1 = extract_cdx_components(value1);
    let components2 = extract_cdx_components(value2);

    // Build component maps
    let map1: HashMap<String, ComponentInfo> = components1
        .into_iter()
        .map(|c| (component_key(&c), c))
        .collect();
    let map2: HashMap<String, ComponentInfo> = components2
        .into_iter()
        .map(|c| (component_key(&c), c))
        .collect();

    let keys1: HashSet<_> = map1.keys().cloned().collect();
    let keys2: HashSet<_> = map2.keys().cloned().collect();

    // Added components
    for key in keys2.difference(&keys1) {
        if let Some(comp) = map2.get(key) {
            report.added_components.push(comp.clone());
        }
    }

    // Removed components
    for key in keys1.difference(&keys2) {
        if let Some(comp) = map1.get(key) {
            report.removed_components.push(comp.clone());
        }
    }

    // Common and modified components
    for key in keys1.intersection(&keys2) {
        if let (Some(comp1), Some(comp2)) = (map1.get(key), map2.get(key)) {
            let changes = compare_components(comp1, comp2);
            if changes.is_empty() {
                report.common_components.push(comp1.clone());
            } else {
                report.modified_components.push(ComponentDiff {
                    name: comp1.name.clone(),
                    version: comp1.version.clone(),
                    changes,
                });
            }
        }
    }

    // Extract and compare dependencies
    let deps1 = extract_cdx_dependencies(value1);
    let deps2 = extract_cdx_dependencies(value2);
    let (added_deps, removed_deps) = diff_dependencies(&deps1, &deps2);
    report.added_dependencies = added_deps;
    report.removed_dependencies = removed_deps;

    // Extract and compare vulnerabilities
    let vulns1 = extract_cdx_vulnerabilities(value1);
    let vulns2 = extract_cdx_vulnerabilities(value2);
    let (added_vulns, removed_vulns) = diff_vulnerabilities(&vulns1, &vulns2);
    report.added_vulnerabilities = added_vulns;
    report.removed_vulnerabilities = removed_vulns;

    // Compare metadata
    report.metadata_changes = compare_cdx_metadata(value1, value2);

    Ok(report)
}

/// Compare two SPDX SBOMs
fn diff_spdx(
    value1: &Value,
    value2: &Value,
    format1: SbomFormat,
    format2: SbomFormat,
) -> Result<DiffReport, ConverterError> {
    let mut report = DiffReport {
        format1,
        format2,
        added_components: Vec::new(),
        removed_components: Vec::new(),
        modified_components: Vec::new(),
        common_components: Vec::new(),
        added_dependencies: Vec::new(),
        removed_dependencies: Vec::new(),
        added_vulnerabilities: Vec::new(),
        removed_vulnerabilities: Vec::new(),
        metadata_changes: Vec::new(),
    };

    // Extract packages (components in SPDX)
    let components1 = extract_spdx_packages(value1);
    let components2 = extract_spdx_packages(value2);

    // Build component maps
    let map1: HashMap<String, ComponentInfo> = components1
        .into_iter()
        .map(|c| (component_key(&c), c))
        .collect();
    let map2: HashMap<String, ComponentInfo> = components2
        .into_iter()
        .map(|c| (component_key(&c), c))
        .collect();

    let keys1: HashSet<_> = map1.keys().cloned().collect();
    let keys2: HashSet<_> = map2.keys().cloned().collect();

    // Added components
    for key in keys2.difference(&keys1) {
        if let Some(comp) = map2.get(key) {
            report.added_components.push(comp.clone());
        }
    }

    // Removed components
    for key in keys1.difference(&keys2) {
        if let Some(comp) = map1.get(key) {
            report.removed_components.push(comp.clone());
        }
    }

    // Common and modified components
    for key in keys1.intersection(&keys2) {
        if let (Some(comp1), Some(comp2)) = (map1.get(key), map2.get(key)) {
            let changes = compare_components(comp1, comp2);
            if changes.is_empty() {
                report.common_components.push(comp1.clone());
            } else {
                report.modified_components.push(ComponentDiff {
                    name: comp1.name.clone(),
                    version: comp1.version.clone(),
                    changes,
                });
            }
        }
    }

    // Extract and compare relationships (dependencies in SPDX)
    let deps1 = extract_spdx_relationships(value1);
    let deps2 = extract_spdx_relationships(value2);
    let (added_deps, removed_deps) = diff_dependencies(&deps1, &deps2);
    report.added_dependencies = added_deps;
    report.removed_dependencies = removed_deps;

    // Compare metadata
    report.metadata_changes = compare_spdx_metadata(value1, value2);

    Ok(report)
}

// Helper functions for extracting data from CycloneDX

fn extract_cdx_components(value: &Value) -> Vec<ComponentInfo> {
    let mut components = Vec::new();

    if let Some(comps) = value.get("components").and_then(|c| c.as_array()) {
        for comp in comps {
            components.push(ComponentInfo {
                name: comp
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                version: comp
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                purl: comp
                    .get("purl")
                    .and_then(|p| p.as_str())
                    .map(|s| s.to_string()),
                component_type: comp
                    .get("type")
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string()),
            });
        }
    }

    components
}

fn extract_cdx_dependencies(value: &Value) -> Vec<DependencyInfo> {
    let mut dependencies = Vec::new();

    if let Some(deps) = value.get("dependencies").and_then(|d| d.as_array()) {
        for dep in deps {
            if let Some(ref_id) = dep.get("ref").and_then(|r| r.as_str()) {
                if let Some(depends_on) = dep.get("dependsOn").and_then(|d| d.as_array()) {
                    for target in depends_on {
                        if let Some(target_str) = target.as_str() {
                            dependencies.push(DependencyInfo {
                                from: ref_id.to_string(),
                                to: target_str.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    dependencies
}

fn extract_cdx_vulnerabilities(value: &Value) -> Vec<VulnerabilityInfo> {
    let mut vulnerabilities = Vec::new();

    if let Some(vulns) = value.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln in vulns {
            vulnerabilities.push(VulnerabilityInfo {
                id: vuln
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                source: vuln
                    .get("source")
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string()),
                affected_component: vuln
                    .get("affects")
                    .and_then(|a| a.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|a| a.get("ref"))
                    .and_then(|r| r.as_str())
                    .map(|s| s.to_string()),
            });
        }
    }

    vulnerabilities
}

fn compare_cdx_metadata(value1: &Value, value2: &Value) -> Vec<MetadataChange> {
    let mut changes = Vec::new();

    // Compare serial number
    if let (Some(sn1), Some(sn2)) = (
        value1.get("serialNumber").and_then(|s| s.as_str()),
        value2.get("serialNumber").and_then(|s| s.as_str()),
    ) {
        if sn1 != sn2 {
            changes.push(MetadataChange {
                field: "serialNumber".to_string(),
                old_value: sn1.to_string(),
                new_value: sn2.to_string(),
            });
        }
    }

    // Compare version
    if let (Some(v1), Some(v2)) = (
        value1.get("version").and_then(|v| v.as_u64()),
        value2.get("version").and_then(|v| v.as_u64()),
    ) {
        if v1 != v2 {
            changes.push(MetadataChange {
                field: "version".to_string(),
                old_value: v1.to_string(),
                new_value: v2.to_string(),
            });
        }
    }

    changes
}

// Helper functions for extracting data from SPDX

fn extract_spdx_packages(value: &Value) -> Vec<ComponentInfo> {
    let mut components = Vec::new();

    // SPDX 3.x structure
    if let Some(graph) = value.get("@graph").and_then(|g| g.as_array()) {
        for element in graph {
            if let Some(elem_type) = element.get("type").and_then(|t| t.as_str()) {
                if elem_type.contains("Package") {
                    components.push(ComponentInfo {
                        name: element
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        version: element
                            .get("packageVersion")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        purl: element
                            .get("externalIdentifier")
                            .and_then(|ei| ei.as_array())
                            .and_then(|arr| {
                                arr.iter().find(|e| {
                                    e.get("externalIdentifierType").and_then(|t| t.as_str())
                                        == Some("purl")
                                })
                            })
                            .and_then(|e| e.get("identifier"))
                            .and_then(|i| i.as_str())
                            .map(|s| s.to_string()),
                        component_type: Some("package".to_string()),
                    });
                }
            }
        }
    }

    components
}

fn extract_spdx_relationships(value: &Value) -> Vec<DependencyInfo> {
    let mut dependencies = Vec::new();

    if let Some(graph) = value.get("@graph").and_then(|g| g.as_array()) {
        for element in graph {
            if let Some(elem_type) = element.get("type").and_then(|t| t.as_str()) {
                if elem_type.contains("Relationship") {
                    if let (Some(from), Some(to), Some(rel_type)) = (
                        element.get("from").and_then(|f| f.as_str()),
                        element.get("to").and_then(|t| t.as_array()),
                        element.get("relationshipType").and_then(|r| r.as_str()),
                    ) {
                        if rel_type.contains("dependsOn") || rel_type.contains("DEPENDS_ON") {
                            for target in to {
                                if let Some(target_str) = target.as_str() {
                                    dependencies.push(DependencyInfo {
                                        from: from.to_string(),
                                        to: target_str.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    dependencies
}

fn compare_spdx_metadata(value1: &Value, value2: &Value) -> Vec<MetadataChange> {
    let mut changes = Vec::new();

    // Compare spdxId
    if let (Some(id1), Some(id2)) = (
        value1.get("spdxId").and_then(|s| s.as_str()),
        value2.get("spdxId").and_then(|s| s.as_str()),
    ) {
        if id1 != id2 {
            changes.push(MetadataChange {
                field: "spdxId".to_string(),
                old_value: id1.to_string(),
                new_value: id2.to_string(),
            });
        }
    }

    // Compare creationInfo
    if let (Some(ci1), Some(ci2)) = (value1.get("creationInfo"), value2.get("creationInfo")) {
        if ci1 != ci2 {
            changes.push(MetadataChange {
                field: "creationInfo".to_string(),
                old_value: serde_json::to_string(ci1).unwrap_or_default(),
                new_value: serde_json::to_string(ci2).unwrap_or_default(),
            });
        }
    }

    changes
}

// Helper functions

fn component_key(comp: &ComponentInfo) -> String {
    if let Some(purl) = &comp.purl {
        purl.clone()
    } else if let Some(version) = &comp.version {
        format!("{}@{}", comp.name, version)
    } else {
        comp.name.clone()
    }
}

fn compare_components(comp1: &ComponentInfo, comp2: &ComponentInfo) -> Vec<String> {
    let mut changes = Vec::new();

    if comp1.version != comp2.version {
        changes.push(format!(
            "version: {:?} → {:?}",
            comp1.version, comp2.version
        ));
    }

    if comp1.component_type != comp2.component_type {
        changes.push(format!(
            "type: {:?} → {:?}",
            comp1.component_type, comp2.component_type
        ));
    }

    changes
}

fn diff_dependencies(
    deps1: &[DependencyInfo],
    deps2: &[DependencyInfo],
) -> (Vec<DependencyInfo>, Vec<DependencyInfo>) {
    let set1: HashSet<_> = deps1.iter().map(|d| (&d.from, &d.to)).collect();
    let set2: HashSet<_> = deps2.iter().map(|d| (&d.from, &d.to)).collect();

    let added: Vec<_> = deps2
        .iter()
        .filter(|d| !set1.contains(&(&d.from, &d.to)))
        .cloned()
        .collect();

    let removed: Vec<_> = deps1
        .iter()
        .filter(|d| !set2.contains(&(&d.from, &d.to)))
        .cloned()
        .collect();

    (added, removed)
}

fn diff_vulnerabilities(
    vulns1: &[VulnerabilityInfo],
    vulns2: &[VulnerabilityInfo],
) -> (Vec<VulnerabilityInfo>, Vec<VulnerabilityInfo>) {
    let set1: HashSet<_> = vulns1.iter().map(|v| &v.id).collect();
    let set2: HashSet<_> = vulns2.iter().map(|v| &v.id).collect();

    let added: Vec<_> = vulns2
        .iter()
        .filter(|v| !set1.contains(&v.id))
        .cloned()
        .collect();

    let removed: Vec<_> = vulns1
        .iter()
        .filter(|v| !set2.contains(&v.id))
        .cloned()
        .collect();

    (added, removed)
}

fn format_component(comp: &ComponentInfo) -> String {
    let mut parts = vec![comp.name.clone()];
    if let Some(version) = &comp.version {
        parts.push(format!("({})", version));
    }
    if let Some(purl) = &comp.purl {
        parts.push(format!("[{}]", purl));
    }
    parts.join(" ")
}

fn format_vulnerability(vuln: &VulnerabilityInfo) -> String {
    let mut parts = vec![vuln.id.clone()];
    if let Some(source) = &vuln.source {
        parts.push(format!("({})", source));
    }
    if let Some(affected) = &vuln.affected_component {
        parts.push(format!("affects: {}", affected));
    }
    parts.join(" ")
}

fn component_to_json(comp: &ComponentInfo) -> Value {
    json!({
        "name": comp.name,
        "version": comp.version,
        "purl": comp.purl,
        "type": comp.component_type,
    })
}

fn vuln_to_json(vuln: &VulnerabilityInfo) -> Value {
    json!({
        "id": vuln.id,
        "source": vuln.source,
        "affected_component": vuln.affected_component,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_key_with_purl() {
        let comp = ComponentInfo {
            name: "test-lib".to_string(),
            version: Some("1.0.0".to_string()),
            purl: Some("pkg:npm/test-lib@1.0.0".to_string()),
            component_type: Some("library".to_string()),
        };
        assert_eq!(component_key(&comp), "pkg:npm/test-lib@1.0.0");
    }

    #[test]
    fn test_component_key_without_purl() {
        let comp = ComponentInfo {
            name: "test-lib".to_string(),
            version: Some("1.0.0".to_string()),
            purl: None,
            component_type: Some("library".to_string()),
        };
        assert_eq!(component_key(&comp), "test-lib@1.0.0");
    }

    #[test]
    fn test_component_key_name_only() {
        let comp = ComponentInfo {
            name: "test-lib".to_string(),
            version: None,
            purl: None,
            component_type: Some("library".to_string()),
        };
        assert_eq!(component_key(&comp), "test-lib");
    }
}
