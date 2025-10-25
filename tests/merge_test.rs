//! Integration tests for the merge command.
//!
//! Tests merging multiple SBOM files with different scenarios:
//! - CycloneDX merge with deduplication
//! - SPDX merge with deduplication
//! - Different deduplication strategies

use assert_cmd::prelude::*;
use serde_json::{Value, json};
use std::fs::{self, File};
use std::process::Command;
use tempfile::tempdir;

/// Helper to get the binary command for testing.
fn get_cmd() -> Command {
    Command::cargo_bin("sbom-converter").unwrap()
}

#[test]
fn test_merge_two_cyclonedx_boms() {
    let dir = tempdir().unwrap();
    let input1 = dir.path().join("bom1.json");
    let input2 = dir.path().join("bom2.json");
    let output = dir.path().join("merged.json");

    // Create first BOM
    let bom1 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-1",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg-a",
                "type": "library",
                "name": "package-a",
                "version": "1.0.0",
                "purl": "pkg:npm/package-a@1.0.0"
            },
            {
                "bom-ref": "pkg-b",
                "type": "library",
                "name": "package-b",
                "version": "2.0.0",
                "purl": "pkg:npm/package-b@2.0.0"
            }
        ],
        "dependencies": [
            {
                "ref": "pkg-a",
                "dependsOn": ["pkg-b"]
            }
        ]
    });

    // Create second BOM (with pkg-b duplicate and new pkg-c)
    let bom2 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-2",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg-b",
                "type": "library",
                "name": "package-b",
                "version": "2.0.0",
                "purl": "pkg:npm/package-b@2.0.0"
            },
            {
                "bom-ref": "pkg-c",
                "type": "library",
                "name": "package-c",
                "version": "3.0.0",
                "purl": "pkg:npm/package-c@3.0.0"
            }
        ],
        "dependencies": [
            {
                "ref": "pkg-b",
                "dependsOn": ["pkg-c"]
            }
        ]
    });

    // Write input files
    serde_json::to_writer_pretty(&File::create(&input1).unwrap(), &bom1).unwrap();
    serde_json::to_writer_pretty(&File::create(&input2).unwrap(), &bom2).unwrap();

    // Run merge command
    get_cmd()
        .arg("merge")
        .arg("--inputs")
        .arg(&input1)
        .arg(&input2)
        .arg("--output")
        .arg(&output)
        .assert()
        .success();

    // Verify output
    let merged_content = fs::read_to_string(&output).unwrap();
    let merged: Value = serde_json::from_str(&merged_content).unwrap();

    assert_eq!(merged["bomFormat"], "CycloneDX");
    assert_eq!(merged["specVersion"], "1.6");

    let components = merged["components"].as_array().unwrap();
    assert_eq!(components.len(), 3, "Should have 3 unique components");

    // Verify all components are present
    let names: Vec<&str> = components
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"package-a"));
    assert!(names.contains(&"package-b"));
    assert!(names.contains(&"package-c"));

    // Verify dependencies were merged
    let dependencies = merged["dependencies"].as_array().unwrap();
    assert_eq!(dependencies.len(), 2);
}

#[test]
fn test_merge_with_first_dedup_strategy() {
    let dir = tempdir().unwrap();
    let input1 = dir.path().join("bom1.json");
    let input2 = dir.path().join("bom2.json");
    let output = dir.path().join("merged.json");

    // Create BOMs where package-x appears in both with different descriptions
    let bom1 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-1",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg-x",
                "type": "library",
                "name": "package-x",
                "version": "1.0.0",
                "description": "First occurrence",
                "purl": "pkg:npm/package-x@1.0.0"
            }
        ]
    });

    let bom2 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-2",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg-x",
                "type": "library",
                "name": "package-x",
                "version": "1.0.0",
                "description": "Second occurrence",
                "purl": "pkg:npm/package-x@1.0.0"
            }
        ]
    });

    serde_json::to_writer_pretty(&File::create(&input1).unwrap(), &bom1).unwrap();
    serde_json::to_writer_pretty(&File::create(&input2).unwrap(), &bom2).unwrap();

    // Merge with "first" strategy (default)
    get_cmd()
        .arg("merge")
        .arg("--inputs")
        .arg(&input1)
        .arg(&input2)
        .arg("--output")
        .arg(&output)
        .arg("--dedup")
        .arg("first")
        .assert()
        .success();

    let merged_content = fs::read_to_string(&output).unwrap();
    let merged: Value = serde_json::from_str(&merged_content).unwrap();

    let components = merged["components"].as_array().unwrap();
    assert_eq!(components.len(), 1);
    assert_eq!(
        components[0]["description"], "First occurrence",
        "Should keep first occurrence with 'first' strategy"
    );
}

#[test]
fn test_merge_with_latest_dedup_strategy() {
    let dir = tempdir().unwrap();
    let input1 = dir.path().join("bom1.json");
    let input2 = dir.path().join("bom2.json");
    let output = dir.path().join("merged.json");

    let bom1 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-1",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg-x",
                "type": "library",
                "name": "package-x",
                "version": "1.0.0",
                "description": "First occurrence",
                "purl": "pkg:npm/package-x@1.0.0"
            }
        ]
    });

    let bom2 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-2",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg-x",
                "type": "library",
                "name": "package-x",
                "version": "1.0.0",
                "description": "Latest occurrence",
                "purl": "pkg:npm/package-x@1.0.0"
            }
        ]
    });

    serde_json::to_writer_pretty(&File::create(&input1).unwrap(), &bom1).unwrap();
    serde_json::to_writer_pretty(&File::create(&input2).unwrap(), &bom2).unwrap();

    // Merge with "latest" strategy
    get_cmd()
        .arg("merge")
        .arg("--inputs")
        .arg(&input1)
        .arg(&input2)
        .arg("--output")
        .arg(&output)
        .arg("--dedup")
        .arg("latest")
        .assert()
        .success();

    let merged_content = fs::read_to_string(&output).unwrap();
    let merged: Value = serde_json::from_str(&merged_content).unwrap();

    let components = merged["components"].as_array().unwrap();
    assert_eq!(components.len(), 1);
    assert_eq!(
        components[0]["description"], "Latest occurrence",
        "Should keep latest occurrence with 'latest' strategy"
    );
}

#[test]
fn test_merge_three_cyclonedx_boms() {
    let dir = tempdir().unwrap();
    let input1 = dir.path().join("bom1.json");
    let input2 = dir.path().join("bom2.json");
    let input3 = dir.path().join("bom3.json");
    let output = dir.path().join("merged.json");

    let bom1 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"name": "pkg-a", "version": "1.0.0", "type": "library"}]
    });

    let bom2 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"name": "pkg-b", "version": "2.0.0", "type": "library"}]
    });

    let bom3 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"name": "pkg-c", "version": "3.0.0", "type": "library"}]
    });

    serde_json::to_writer_pretty(&File::create(&input1).unwrap(), &bom1).unwrap();
    serde_json::to_writer_pretty(&File::create(&input2).unwrap(), &bom2).unwrap();
    serde_json::to_writer_pretty(&File::create(&input3).unwrap(), &bom3).unwrap();

    get_cmd()
        .arg("merge")
        .arg("--inputs")
        .arg(&input1)
        .arg(&input2)
        .arg(&input3)
        .arg("--output")
        .arg(&output)
        .assert()
        .success();

    let merged_content = fs::read_to_string(&output).unwrap();
    let merged: Value = serde_json::from_str(&merged_content).unwrap();

    let components = merged["components"].as_array().unwrap();
    assert_eq!(components.len(), 3, "Should merge all three BOMs");
}

#[test]
fn test_merge_preserves_metadata() {
    let dir = tempdir().unwrap();
    let input1 = dir.path().join("bom1.json");
    let input2 = dir.path().join("bom2.json");
    let output = dir.path().join("merged.json");

    let bom1 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2024-01-01T00:00:00Z",
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "test-tool",
                    "version": "1.0.0"
                }]
            }
        },
        "components": [{"name": "pkg-a", "version": "1.0.0", "type": "library"}]
    });

    let bom2 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"name": "pkg-b", "version": "2.0.0", "type": "library"}]
    });

    serde_json::to_writer_pretty(&File::create(&input1).unwrap(), &bom1).unwrap();
    serde_json::to_writer_pretty(&File::create(&input2).unwrap(), &bom2).unwrap();

    get_cmd()
        .arg("merge")
        .arg("--inputs")
        .arg(&input1)
        .arg(&input2)
        .arg("--output")
        .arg(&output)
        .assert()
        .success();

    let merged_content = fs::read_to_string(&output).unwrap();
    let merged: Value = serde_json::from_str(&merged_content).unwrap();

    // Verify metadata from first file is preserved
    assert!(merged.get("metadata").is_some());
    assert_eq!(
        merged["metadata"]["tools"]["components"][0]["name"],
        "test-tool"
    );
}

#[test]
fn test_merge_spdx_documents() {
    let dir = tempdir().unwrap();
    let input1 = dir.path().join("spdx1.json");
    let input2 = dir.path().join("spdx2.json");
    let output = dir.path().join("merged.json");

    let spdx1 = json!({
        "spdxVersion": "SPDX-3.0.1",
        "documentNamespace": "urn:uuid:test-1",
        "creationInfo": {
            "created": "2024-01-01T00:00:00Z"
        },
        "elements": [
            {
                "spdxId": "SPDXRef-Package-A",
                "name": "package-a",
                "version": "1.0.0"
            },
            {
                "spdxId": "SPDXRef-Package-B",
                "name": "package-b",
                "version": "2.0.0"
            }
        ]
    });

    let spdx2 = json!({
        "spdxVersion": "SPDX-3.0.1",
        "documentNamespace": "urn:uuid:test-2",
        "creationInfo": {
            "created": "2024-01-02T00:00:00Z"
        },
        "elements": [
            {
                "spdxId": "SPDXRef-Package-B",
                "name": "package-b",
                "version": "2.0.0"
            },
            {
                "spdxId": "SPDXRef-Package-C",
                "name": "package-c",
                "version": "3.0.0"
            }
        ]
    });

    serde_json::to_writer_pretty(&File::create(&input1).unwrap(), &spdx1).unwrap();
    serde_json::to_writer_pretty(&File::create(&input2).unwrap(), &spdx2).unwrap();

    get_cmd()
        .arg("merge")
        .arg("--inputs")
        .arg(&input1)
        .arg(&input2)
        .arg("--output")
        .arg(&output)
        .assert()
        .success();

    let merged_content = fs::read_to_string(&output).unwrap();
    let merged: Value = serde_json::from_str(&merged_content).unwrap();

    assert_eq!(merged["spdxVersion"], "SPDX-3.0.1");

    let elements = merged["elements"].as_array().unwrap();
    assert_eq!(elements.len(), 3, "Should have 3 unique elements");

    // Verify all packages are present
    let names: Vec<&str> = elements
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"package-a"));
    assert!(names.contains(&"package-b"));
    assert!(names.contains(&"package-c"));
}

#[test]
fn test_merge_requires_minimum_two_files() {
    let dir = tempdir().unwrap();
    let input1 = dir.path().join("bom1.json");
    let output = dir.path().join("merged.json");

    let bom1 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": []
    });

    serde_json::to_writer_pretty(&File::create(&input1).unwrap(), &bom1).unwrap();

    // Should fail with only one input file
    get_cmd()
        .arg("merge")
        .arg("--inputs")
        .arg(&input1)
        .arg("--output")
        .arg(&output)
        .assert()
        .failure();
}

#[test]
fn test_merge_mixed_formats_fails() {
    let dir = tempdir().unwrap();
    let cdx_file = dir.path().join("cyclonedx.json");
    let spdx_file = dir.path().join("spdx.json");
    let output = dir.path().join("merged.json");

    let cdx = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": []
    });

    let spdx = json!({
        "spdxVersion": "SPDX-3.0.1",
        "documentNamespace": "urn:uuid:test",
        "elements": []
    });

    serde_json::to_writer_pretty(&File::create(&cdx_file).unwrap(), &cdx).unwrap();
    serde_json::to_writer_pretty(&File::create(&spdx_file).unwrap(), &spdx).unwrap();

    // Should fail when mixing CycloneDX and SPDX
    get_cmd()
        .arg("merge")
        .arg("--inputs")
        .arg(&cdx_file)
        .arg(&spdx_file)
        .arg("--output")
        .arg(&output)
        .assert()
        .failure();
}

#[test]
fn test_merge_xml_output() {
    let dir = tempdir().unwrap();
    let input1 = dir.path().join("input1.json");
    let input2 = dir.path().join("input2.json");
    let output = dir.path().join("merged.xml");

    let bom1 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:bom1",
        "components": [
            {
                "type": "library",
                "name": "lodash",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21"
            }
        ]
    });

    let bom2 = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:bom2",
        "components": [
            {
                "type": "library",
                "name": "express",
                "version": "4.18.0",
                "purl": "pkg:npm/express@4.18.0"
            }
        ]
    });

    serde_json::to_writer_pretty(&File::create(&input1).unwrap(), &bom1).unwrap();
    serde_json::to_writer_pretty(&File::create(&input2).unwrap(), &bom2).unwrap();

    // Merge with XML output format
    get_cmd()
        .arg("merge")
        .arg("--inputs")
        .arg(&input1)
        .arg(&input2)
        .arg("--output")
        .arg(&output)
        .arg("--output-format")
        .arg("xml")
        .assert()
        .success();

    // Verify output file exists and contains XML
    let merged_content = std::fs::read_to_string(&output).unwrap();
    assert!(merged_content.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(merged_content.contains("<bom"));
    assert!(merged_content.contains("xmlns=\"http://cyclonedx.org/schema/bom/1.6\""));
    assert!(merged_content.contains("bomFormat=\"CycloneDX\""));
    assert!(merged_content.contains("<components>"));
    assert!(merged_content.contains("<component"));
    assert!(merged_content.contains("lodash"));
    assert!(merged_content.contains("express"));
    assert!(merged_content.contains("</bom>"));
}
