//! Validation module for SBOM files
//!
//! Provides detailed validation with helpful error messages and suggestions.

use colored::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

/// Validation severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// A single validation issue with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

impl ValidationIssue {
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
            location: None,
            suggestion: None,
            line: None,
        }
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
            location: None,
            suggestion: None,
            line: None,
        }
    }

    pub fn info(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            message: message.into(),
            location: None,
            suggestion: None,
            line: None,
        }
    }

    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    pub fn with_line(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }

    /// Format the issue with colors for terminal output
    pub fn format_colored(&self) -> String {
        let mut output = String::new();

        // Severity indicator
        let (icon, color_fn): (&str, fn(&str) -> ColoredString) = match self.severity {
            Severity::Error => ("✗", |s: &str| s.red().bold()),
            Severity::Warning => ("⚠", |s: &str| s.yellow().bold()),
            Severity::Info => ("ℹ", |s: &str| s.cyan().bold()),
        };

        output.push_str(&format!("{} ", color_fn(icon)));

        // Location
        if let Some(ref location) = self.location {
            output.push_str(&format!("[{}] ", location.bright_blue()));
        }

        // Line number
        if let Some(line) = self.line {
            output.push_str(&format!("line {}: ", line.to_string().bright_black()));
        }

        // Message
        output.push_str(&self.message);
        output.push('\n');

        // Suggestion
        if let Some(ref suggestion) = self.suggestion {
            output.push_str(&format!(
                "  {} {}\n",
                "→".bright_green(),
                suggestion.green()
            ));
        }

        output
    }

    /// Format without colors for logs or non-terminal output
    pub fn format_plain(&self) -> String {
        let mut output = String::new();

        let severity_str = match self.severity {
            Severity::Error => "ERROR",
            Severity::Warning => "WARNING",
            Severity::Info => "INFO",
        };

        output.push_str(&format!("[{}] ", severity_str));

        if let Some(ref location) = self.location {
            output.push_str(&format!("[{}] ", location));
        }

        if let Some(line) = self.line {
            output.push_str(&format!("line {}: ", line));
        }

        output.push_str(&self.message);
        output.push('\n');

        if let Some(ref suggestion) = self.suggestion {
            output.push_str(&format!("  Suggestion: {}\n", suggestion));
        }

        output
    }
}

/// Validation result containing all issues found
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub issues: Vec<ValidationIssue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    pub summary: ValidationSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationSummary {
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub total: usize,
}

impl ValidationReport {
    pub fn new() -> Self {
        Self {
            issues: Vec::new(),
            file_path: None,
            summary: ValidationSummary {
                errors: 0,
                warnings: 0,
                infos: 0,
                total: 0,
            },
        }
    }

    pub fn with_file(mut self, path: impl AsRef<Path>) -> Self {
        self.file_path = Some(path.as_ref().display().to_string());
        self
    }

    pub fn add_issue(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
        self.update_summary();
    }

    fn update_summary(&mut self) {
        self.summary.errors = self.error_count();
        self.summary.warnings = self.warning_count();
        self.summary.infos = self.info_count();
        self.summary.total = self.issues.len();
    }

    pub fn has_errors(&self) -> bool {
        self.issues.iter().any(|i| i.severity == Severity::Error)
    }

    pub fn error_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Warning)
            .count()
    }

    pub fn info_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Info)
            .count()
    }

    /// Convert the report to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Print the report with colors
    pub fn print_colored(&self) {
        if let Some(ref path) = self.file_path {
            println!("\n{} {}\n", "Validating:".bold(), path.bright_blue());
        }

        for issue in &self.issues {
            print!("{}", issue.format_colored());
        }

        if self.issues.is_empty() {
            println!("{}", "✓ No issues found".green().bold());
        } else {
            println!();
            let errors = self.error_count();
            let warnings = self.warning_count();
            let info = self.info_count();

            let mut summary = Vec::new();
            if errors > 0 {
                summary.push(
                    format!(
                        "{} {}",
                        errors,
                        if errors == 1 { "error" } else { "errors" }
                    )
                    .red()
                    .bold()
                    .to_string(),
                );
            }
            if warnings > 0 {
                summary.push(
                    format!(
                        "{} {}",
                        warnings,
                        if warnings == 1 { "warning" } else { "warnings" }
                    )
                    .yellow()
                    .bold()
                    .to_string(),
                );
            }
            if info > 0 {
                summary.push(
                    format!("{} {}", info, if info == 1 { "info" } else { "infos" })
                        .cyan()
                        .bold()
                        .to_string(),
                );
            }

            println!("{} {}", "Summary:".bold(), summary.join(", "));
        }
    }

    /// Print without colors (for logs)
    pub fn print_plain(&self) {
        if let Some(ref path) = self.file_path {
            println!("\nValidating: {}\n", path);
        }

        for issue in &self.issues {
            print!("{}", issue.format_plain());
        }

        if self.issues.is_empty() {
            println!("No issues found");
        } else {
            println!();
            println!(
                "Summary: {} errors, {} warnings, {} infos",
                self.error_count(),
                self.warning_count(),
                self.info_count()
            );
        }
    }
}

/// Validate CycloneDX BOM structure
pub fn validate_cdx(value: &Value) -> ValidationReport {
    let mut report = ValidationReport::new();

    // Check required fields
    if !value.is_object() {
        report.add_issue(
            ValidationIssue::error("Root element must be an object")
                .with_suggestion("Ensure the file is valid JSON and starts with '{'"),
        );
        return report;
    }

    let obj = value.as_object().unwrap();

    // bomFormat
    if let Some(bom_format) = obj.get("bomFormat") {
        if let Some(format) = bom_format.as_str() {
            if format != "CycloneDX" {
                report.add_issue(
                    ValidationIssue::error(format!(
                        "Invalid bomFormat: '{}', expected 'CycloneDX'",
                        format
                    ))
                    .with_location("bomFormat")
                    .with_suggestion("Set bomFormat to 'CycloneDX'"),
                );
            }
        } else {
            report.add_issue(
                ValidationIssue::error("bomFormat must be a string").with_location("bomFormat"),
            );
        }
    } else {
        report.add_issue(
            ValidationIssue::error("Missing required field: bomFormat")
                .with_suggestion("Add \"bomFormat\": \"CycloneDX\""),
        );
    }

    // specVersion
    if let Some(spec_version) = obj.get("specVersion") {
        if let Some(version) = spec_version.as_str() {
            if !version.starts_with("1.") {
                report.add_issue(
                    ValidationIssue::warning(format!(
                        "Unexpected specVersion: '{}', this tool is optimized for 1.x",
                        version
                    ))
                    .with_location("specVersion"),
                );
            }
        } else {
            report.add_issue(
                ValidationIssue::error("specVersion must be a string").with_location("specVersion"),
            );
        }
    } else {
        report.add_issue(
            ValidationIssue::error("Missing required field: specVersion")
                .with_suggestion("Add \"specVersion\": \"1.6\""),
        );
    }

    // version
    if let Some(version) = obj.get("version") {
        if !version.is_number() {
            report.add_issue(
                ValidationIssue::error("version must be a number")
                    .with_location("version")
                    .with_suggestion("Use \"version\": 1"),
            );
        }
    } else {
        report.add_issue(
            ValidationIssue::error("Missing required field: version")
                .with_suggestion("Add \"version\": 1"),
        );
    }

    // Components validation
    if let Some(components) = obj.get("components") {
        if let Some(comps) = components.as_array() {
            for (idx, comp) in comps.iter().enumerate() {
                validate_cdx_component(comp, idx, &mut report);
            }

            if comps.is_empty() {
                report.add_issue(
                    ValidationIssue::warning("Components array is empty")
                        .with_location("components"),
                );
            }
        } else {
            report.add_issue(
                ValidationIssue::error("components must be an array").with_location("components"),
            );
        }
    } else {
        report.add_issue(
            ValidationIssue::info("No components field found")
                .with_suggestion("Add components array if this BOM describes software components"),
        );
    }

    report
}

fn validate_cdx_component(comp: &Value, idx: usize, report: &mut ValidationReport) {
    let location = format!("components[{}]", idx);

    if !comp.is_object() {
        report.add_issue(
            ValidationIssue::error("Component must be an object").with_location(&location),
        );
        return;
    }

    let obj = comp.as_object().unwrap();

    // Required: type
    if let Some(comp_type) = obj.get("type") {
        if let Some(type_str) = comp_type.as_str() {
            let valid_types = [
                "application",
                "framework",
                "library",
                "container",
                "platform",
                "operating-system",
                "device",
                "device-driver",
                "firmware",
                "file",
                "machine-learning-model",
                "data",
            ];
            if !valid_types.contains(&type_str) {
                report.add_issue(
                    ValidationIssue::warning(format!("Uncommon component type: '{}'", type_str))
                        .with_location(format!("{}.type", location))
                        .with_suggestion(format!("Valid types: {}", valid_types.join(", "))),
                );
            }
        }
    } else {
        report.add_issue(
            ValidationIssue::error("Component missing required field: type")
                .with_location(&location)
                .with_suggestion("Add \"type\": \"library\" (or other valid type)"),
        );
    }

    // Required: name
    if let Some(name) = obj.get("name") {
        if let Some(name_str) = name.as_str() {
            if name_str.trim().is_empty() {
                report.add_issue(
                    ValidationIssue::error("Component name cannot be empty")
                        .with_location(format!("{}.name", location)),
                );
            }
        } else {
            report.add_issue(
                ValidationIssue::error("Component name must be a string")
                    .with_location(format!("{}.name", location)),
            );
        }
    } else {
        report.add_issue(
            ValidationIssue::error("Component missing required field: name")
                .with_location(&location)
                .with_suggestion("Add \"name\": \"component-name\""),
        );
    }

    // Recommended: version
    if !obj.contains_key("version") {
        report.add_issue(
            ValidationIssue::warning("Component missing version")
                .with_location(&location)
                .with_suggestion("Add \"version\": \"1.0.0\" for better tracking"),
        );
    }

    // Recommended: purl
    if !obj.contains_key("purl") {
        report.add_issue(
            ValidationIssue::info("Component missing purl (Package URL)")
                .with_location(&location)
                .with_suggestion(
                    "Add \"purl\": \"pkg:npm/name@version\" for better identification",
                ),
        );
    }
}

/// Validate SPDX document structure
pub fn validate_spdx(value: &Value) -> ValidationReport {
    let mut report = ValidationReport::new();

    if !value.is_object() {
        report.add_issue(
            ValidationIssue::error("Root element must be an object")
                .with_suggestion("Ensure the file is valid JSON and starts with '{'"),
        );
        return report;
    }

    let obj = value.as_object().unwrap();

    // Check for SPDX version
    if let Some(spdx_version) = obj.get("spdxVersion") {
        if let Some(version) = spdx_version.as_str()
            && !version.starts_with("SPDX-")
        {
            report.add_issue(
                ValidationIssue::error(format!("Invalid spdxVersion format: '{}'", version))
                    .with_location("spdxVersion")
                    .with_suggestion("Use format like 'SPDX-3.0'"),
            );
        }
    } else {
        report.add_issue(
            ValidationIssue::error("Missing required field: spdxVersion")
                .with_suggestion("Add \"spdxVersion\": \"SPDX-3.0\""),
        );
    }

    // Check for creationInfo or dataLicense
    if !obj.contains_key("creationInfo") && !obj.contains_key("dataLicense") {
        report.add_issue(
            ValidationIssue::error("Missing SPDX metadata (creationInfo or dataLicense)")
                .with_suggestion("Add creationInfo section with creation details"),
        );
    }

    // Check for elements or packages
    if !obj.contains_key("elements") && !obj.contains_key("packages") {
        report.add_issue(
            ValidationIssue::warning("No elements or packages found in SPDX document")
                .with_suggestion("Add elements array to describe software components"),
        );
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validation_issue_creation() {
        let issue = ValidationIssue::error("Test error")
            .with_location("test.field")
            .with_suggestion("Fix it")
            .with_line(42);

        assert_eq!(issue.severity, Severity::Error);
        assert_eq!(issue.message, "Test error");
        assert_eq!(issue.location, Some("test.field".to_string()));
        assert_eq!(issue.suggestion, Some("Fix it".to_string()));
        assert_eq!(issue.line, Some(42));
    }

    #[test]
    fn test_validate_cdx_valid() {
        let valid_cdx = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test-lib",
                    "version": "1.0.0"
                }
            ]
        });

        let report = validate_cdx(&valid_cdx);
        assert_eq!(report.error_count(), 0);
    }

    #[test]
    fn test_validate_cdx_missing_fields() {
        let invalid_cdx = json!({
            "bomFormat": "CycloneDX"
        });

        let report = validate_cdx(&invalid_cdx);
        assert!(report.has_errors());
        assert!(report.error_count() >= 2); // Missing specVersion and version
    }

    #[test]
    fn test_validate_cdx_invalid_component() {
        let cdx = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library"
                    // Missing name
                }
            ]
        });

        let report = validate_cdx(&cdx);
        assert!(report.has_errors());
    }
}
