//! Integration tests for the sbom-converter.
//!
//! These tests create dummy JSON files on the fly and run the
//! full binary executable against them to ensure the streaming
//! logic works end-to-end.

use assert_cmd::prelude::*; // Add `assert_cmd` to your dev-dependencies
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::Write;
use std::process::Command;
use tempfile::tempdir; // Add `tempfile` to your dev-dependencies

// --- Helper Functions ---

/// Helper to get the binary command for testing.
fn get_cmd() -> Command {
    Command::cargo_bin("sbom-converter").unwrap()
}

/// A minimal, valid CycloneDX 1.6 JSON object
fn get_test_cdx() -> Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-cdx-to-spdx",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg-a",
                "type": "library",
                "name": "Package A",
                "version": "1.0.0",
                "licenses": [
                    { "expression": "MIT" }
                ]
            },
            {
                "bom-ref": "pkg-b",
                "type": "library",
                "name": "Package B",
                "version": "2.0.0"
            }
        ],
        "dependencies": [
            {
                "ref": "pkg-a",
                "dependsOn": ["pkg-b"]
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2025-1234",
                "source": { "name": "Test" },
                "affects": [
                    { "ref": "pkg-b" }
                ]
            }
        ]
    })
}

/// A minimal, valid SPDX 3.0.1 JSON object
fn get_test_spdx() -> Value {
    json!({
        "creationInfo": {
            "spdxVersion": "SPDX-3.0",
            "dataLicense": "CC0-1.0",
            "spdxId": "SPDXRef-DOCUMENT",
            "name": "Test SPDX",
            "documentNamespace": "urn:uuid:test-spdx-to-cdx",
            "created": "2025-01-01T00:00:00Z",
            "creators": ["Tool: test"]
        },
        "elements": [
            {
                "spdxId": "pkg-1",
                "type": "SpdxPackage",
                "name": "Package 1",
                "versionInfo": "1.1.0",
                "licenseConcluded": "Apache-2.0"
            },
            {
                "spdxId": "pkg-2",
                "type": "SpdxPackage",
                "name": "Package 2"
            },
            {
                "spdxId": "vuln-cve",
                "type": "SpdxVulnerability",
                "name": "CVE-2025-5678"
            }
        ],
        "relationships": [
            {
                "spdxElementId": "pkg-1",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "pkg-2"
            },
            {
                "spdxElementId": "pkg-1",
                "relationshipType": "AFFECTS",
                "relatedSpdxElement": "vuln-cve"
            }
        ]
    })
}

// --- Test Cases ---

#[test]
fn test_cdx_to_spdx_streaming() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("test.cdx.json");
    let output_path = dir.path().join("output.spdx.json");

    // 1. Create the input file
    let mut input_file = File::create(&input_path).unwrap();
    let cdx_data = get_test_cdx();
    writeln!(input_file, "{}", cdx_data.to_string()).unwrap();

    // 2. Run the converter
    let mut cmd = get_cmd();
    cmd.arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--direction")
        .arg("cdx-to-spdx");

    // 3. Assert it runs successfully
    cmd.assert()
        .success();
        // Note: log messages go to stderr, not stdout

    // 4. Validate the output file
    let output_content = fs::read_to_string(output_path).unwrap();
    let output_json: Value = serde_json::from_str(&output_content).unwrap();

    // Check that elements were created
    let elements = output_json["elements"].as_array().unwrap();
    assert_eq!(elements.len(), 3); // pkg-a, pkg-b, vuln
    
    // Find elements by spdxId (order may vary)
    let pkg_a = elements.iter().find(|e| e["spdxId"] == "SPDXRef-pkg-a").unwrap();
    let pkg_b = elements.iter().find(|e| e["spdxId"] == "SPDXRef-pkg-b").unwrap();
    let vuln = elements.iter().find(|e| e["type"] == "SpdxVulnerability").unwrap();
    
    assert_eq!(pkg_a["name"], "Package A");
    assert_eq!(pkg_a["licenseConcluded"], "MIT");
    assert_eq!(pkg_b["name"], "Package B");
    assert_eq!(vuln["type"], "SpdxVulnerability");

    // Check that relationships were created (from temp file)
    let relationships = output_json["relationships"].as_array().unwrap();
    assert_eq!(relationships.len(), 2); // 1 dependency, 1 affects
    
    // Find relationships by type (order may vary)
    let dep_rel = relationships.iter().find(|r| r["relationshipType"] == "DEPENDS_ON").unwrap();
    let affect_rel = relationships.iter().find(|r| r["relationshipType"] == "AFFECTS").unwrap();
    
    assert_eq!(dep_rel["spdxElementId"], "SPDXRef-pkg-a");
    assert_eq!(dep_rel["relatedSpdxElement"], "SPDXRef-pkg-b");
    // The vulnerability affects the package, not the other way around
    assert_eq!(affect_rel["spdxElementId"], "SPDXRef-Vulnerability-CVE-2025-1234");
    assert_eq!(affect_rel["relatedSpdxElement"], "SPDXRef-pkg-b");
}

#[test]
fn test_spdx_to_cdx_streaming() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("test.spdx.json");
    let output_path = dir.path().join("output.cdx.json");

    // 1. Create the input file
    let mut input_file = File::create(&input_path).unwrap();
    let spdx_data = get_test_spdx();
    writeln!(input_file, "{}", spdx_data.to_string()).unwrap();

    // 2. Run the converter
    let mut cmd = get_cmd();
    cmd.arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--direction")
        .arg("spdx-to-cdx");

    // 3. Assert it runs successfully
    cmd.assert()
        .success();
        // Note: log messages go to stderr, not stdout

    // 4. Validate the output file
    let output_content = fs::read_to_string(output_path).unwrap();
    let output_json: Value = serde_json::from_str(&output_content).unwrap();

    // Check that components were created
    let components = output_json["components"].as_array().unwrap();
    assert_eq!(components.len(), 2); // pkg-1, pkg-2 (vuln is skipped)
    assert_eq!(components[0]["bom-ref"], "pkg-1");
    assert_eq!(components[0]["name"], "Package 1");
    assert_eq!(components[0]["licenses"][0]["expression"], "Apache-2.0");

    // Check that dependencies were created (from index)
    let dependencies = output_json["dependencies"].as_array().unwrap();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0]["ref"], "pkg-1");
    assert_eq!(dependencies[0]["dependsOn"][0], "pkg-2");
}

#[test]
fn test_validation_flag_cdx() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("invalid.cdx.json");
    let output_path = dir.path().join("output.spdx.json");

    // Create an invalid file (missing required 'type' field)
    let invalid_cdx = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            { "name": "Invalid Component" } // Missing 'type'
        ]
    });
    let mut input_file = File::create(&input_path).unwrap();
    writeln!(input_file, "{}", invalid_cdx.to_string()).unwrap();

    let mut cmd = get_cmd();
    cmd.arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--direction")
        .arg("cdx-to-spdx")
        .arg("--validate") // Enable validation
        .arg("--verbose"); // To check log output

    // It should fail validation before trying to convert
    cmd.assert()
        .failure();
}

#[test]
fn test_file_not_found() {
    let mut cmd = get_cmd();
    cmd.arg("--input")
        .arg("nonexistent-file.json")
        .arg("--output")
        .arg("output.json")
        .arg("--direction")
        .arg("cdx-to-spdx");

    cmd.assert()
        .failure();
}
