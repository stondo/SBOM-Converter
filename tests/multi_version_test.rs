//! Integration tests for multi-version CycloneDX support.
//!
//! Tests conversion to different CycloneDX versions (1.3-1.7)
//! and validates that the correct specVersion is written.

use assert_cmd::prelude::*;
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::Write;
use std::process::Command;
use tempfile::tempdir;

// --- Helper Functions ---

/// Helper to get the binary command for testing.
fn get_cmd() -> Command {
    Command::cargo_bin("sbom-converter").unwrap()
}

/// A minimal, valid SPDX 3.0.1 JSON-LD object for testing
fn get_test_spdx() -> Value {
    json!({
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {
                "@type": "software_Package",
                "@id": "urn:spdx:test-package-1",
                "spdxId": "SPDXRef-Package-test",
                "name": "test-package",
                "version": "1.0.0",
                "creationInfo": "_:creationinfo"
            },
            {
                "@type": "software_Package",
                "@id": "urn:spdx:test-package-2",
                "spdxId": "SPDXRef-Package-dep",
                "name": "dependency-package",
                "version": "2.0.0",
                "creationInfo": "_:creationinfo"
            },
            {
                "@type": "CreationInfo",
                "@id": "_:creationinfo",
                "created": "2024-01-01T00:00:00Z",
                "specVersion": "3.0.1"
            }
        ]
    })
}

// --- Tests ---

#[test]
fn test_output_version_1_3() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.spdx.json");
    let output_path = dir.path().join("output.cdx.json");

    // Write SPDX input file
    let mut input_file = File::create(&input_path).unwrap();
    serde_json::to_writer_pretty(&mut input_file, &get_test_spdx()).unwrap();
    input_file.flush().unwrap();

    // Run conversion with --output-version 1.3
    get_cmd()
        .arg("convert")
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--direction")
        .arg("spdx-to-cdx")
        .arg("--output-version")
        .arg("1.3")
        .assert()
        .success();

    // Read output and verify specVersion
    let output_str = fs::read_to_string(&output_path).unwrap();
    let output_json: Value = serde_json::from_str(&output_str).unwrap();

    assert_eq!(output_json["bomFormat"], "CycloneDX");
    assert_eq!(output_json["specVersion"], "1.3");
}

#[test]
fn test_output_version_1_4() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.spdx.json");
    let output_path = dir.path().join("output.cdx.json");

    let mut input_file = File::create(&input_path).unwrap();
    serde_json::to_writer_pretty(&mut input_file, &get_test_spdx()).unwrap();
    input_file.flush().unwrap();

    get_cmd()
        .arg("convert")
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--direction")
        .arg("spdx-to-cdx")
        .arg("--output-version")
        .arg("1.4")
        .assert()
        .success();

    let output_str = fs::read_to_string(&output_path).unwrap();
    let output_json: Value = serde_json::from_str(&output_str).unwrap();

    assert_eq!(output_json["specVersion"], "1.4");
}

#[test]
fn test_output_version_1_5() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.spdx.json");
    let output_path = dir.path().join("output.cdx.json");

    let mut input_file = File::create(&input_path).unwrap();
    serde_json::to_writer_pretty(&mut input_file, &get_test_spdx()).unwrap();
    input_file.flush().unwrap();

    get_cmd()
        .arg("convert")
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--direction")
        .arg("spdx-to-cdx")
        .arg("--output-version")
        .arg("1.5")
        .assert()
        .success();

    let output_str = fs::read_to_string(&output_path).unwrap();
    let output_json: Value = serde_json::from_str(&output_str).unwrap();

    assert_eq!(output_json["specVersion"], "1.5");
}

#[test]
fn test_output_version_1_6_default() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.spdx.json");
    let output_path = dir.path().join("output.cdx.json");

    let mut input_file = File::create(&input_path).unwrap();
    serde_json::to_writer_pretty(&mut input_file, &get_test_spdx()).unwrap();
    input_file.flush().unwrap();

    // Test without --output-version flag (should default to 1.6)
    get_cmd()
        .arg("convert")
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--direction")
        .arg("spdx-to-cdx")
        .assert()
        .success();

    let output_str = fs::read_to_string(&output_path).unwrap();
    let output_json: Value = serde_json::from_str(&output_str).unwrap();

    assert_eq!(output_json["specVersion"], "1.6");
}

#[test]
fn test_output_version_1_6_explicit() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.spdx.json");
    let output_path = dir.path().join("output.cdx.json");

    let mut input_file = File::create(&input_path).unwrap();
    serde_json::to_writer_pretty(&mut input_file, &get_test_spdx()).unwrap();
    input_file.flush().unwrap();

    get_cmd()
        .arg("convert")
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--direction")
        .arg("spdx-to-cdx")
        .arg("--output-version")
        .arg("1.6")
        .assert()
        .success();

    let output_str = fs::read_to_string(&output_path).unwrap();
    let output_json: Value = serde_json::from_str(&output_str).unwrap();

    assert_eq!(output_json["specVersion"], "1.6");
}

#[test]
fn test_output_version_1_7() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.spdx.json");
    let output_path = dir.path().join("output.cdx.json");

    let mut input_file = File::create(&input_path).unwrap();
    serde_json::to_writer_pretty(&mut input_file, &get_test_spdx()).unwrap();
    input_file.flush().unwrap();

    get_cmd()
        .arg("convert")
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--direction")
        .arg("spdx-to-cdx")
        .arg("--output-version")
        .arg("1.7")
        .assert()
        .success();

    let output_str = fs::read_to_string(&output_path).unwrap();
    let output_json: Value = serde_json::from_str(&output_str).unwrap();

    assert_eq!(output_json["specVersion"], "1.7");
}

#[test]
fn test_output_version_with_vex_split() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.spdx.json");
    let output_path = dir.path().join("output.cdx.json");
    let vex_path = dir.path().join("input.spdx.vex.json");

    // Create SPDX input with vulnerability data
    let spdx_with_vuln = json!({
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {
                "@type": "software_Package",
                "@id": "urn:spdx:test-package-1",
                "spdxId": "SPDXRef-Package-test",
                "name": "test-package",
                "version": "1.0.0",
                "creationInfo": "_:creationinfo"
            },
            {
                "@type": "security_Vulnerability",
                "@id": "urn:spdx:vuln-1",
                "externalIdentifier": [
                    {
                        "@type": "ExternalIdentifier",
                        "externalIdentifierType": "cve",
                        "identifier": "CVE-2024-1234"
                    }
                ],
                "creationInfo": "_:creationinfo"
            },
            {
                "@type": "security_VexAffectedVulnAssessmentRelationship",
                "@id": "_:vex-rel-1",
                "from": "urn:spdx:vuln-1",
                "to": ["urn:spdx:test-package-1"],
                "relationshipType": "affects",
                "assessedElement": "urn:spdx:test-package-1",
                "creationInfo": "_:creationinfo"
            },
            {
                "@type": "CreationInfo",
                "@id": "_:creationinfo",
                "created": "2024-01-01T00:00:00Z",
                "specVersion": "3.0.1"
            }
        ]
    });

    let mut input_file = File::create(&input_path).unwrap();
    serde_json::to_writer_pretty(&mut input_file, &spdx_with_vuln).unwrap();
    input_file.flush().unwrap();

    // Run conversion with --split-vex and --output-version 1.5
    get_cmd()
        .arg("convert")
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--direction")
        .arg("spdx-to-cdx")
        .arg("--split-vex")
        .arg("--output-version")
        .arg("1.5")
        .assert()
        .success();

    // Verify main BOM has correct version
    let output_str = fs::read_to_string(&output_path).unwrap();
    let output_json: Value = serde_json::from_str(&output_str).unwrap();
    assert_eq!(output_json["specVersion"], "1.5");

    // Verify VEX file also has correct version
    if vex_path.exists() {
        let vex_str = fs::read_to_string(&vex_path).unwrap();
        let vex_json: Value = serde_json::from_str(&vex_str).unwrap();
        assert_eq!(vex_json["specVersion"], "1.5");
    }
}

#[test]
fn test_version_ignored_for_cdx_to_spdx() {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.cdx.json");
    let output_path = dir.path().join("output.spdx.json");

    // Create CycloneDX input
    let cdx_input = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:test-cdx",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg-a",
                "type": "library",
                "name": "Package A",
                "version": "1.0.0"
            }
        ]
    });

    let mut input_file = File::create(&input_path).unwrap();
    serde_json::to_writer_pretty(&mut input_file, &cdx_input).unwrap();
    input_file.flush().unwrap();

    // Run conversion (--output-version should be ignored for SPDX output)
    get_cmd()
        .arg("convert")
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--direction")
        .arg("cdx-to-spdx")
        .arg("--output-version")
        .arg("1.7")
        .assert()
        .success();

    // Verify SPDX output is always 3.0.1 format (version flag ignored)
    let output_str = fs::read_to_string(&output_path).unwrap();
    let output_json: Value = serde_json::from_str(&output_str).unwrap();

    // CDX to SPDX produces simple JSON format (not JSON-LD)
    // Verify it has SPDX structure
    assert!(output_json.get("spdxVersion").is_some() || output_json.get("@context").is_some());
    assert!(output_json.get("elements").is_some() || output_json.get("@graph").is_some());

    // The key point: conversion succeeded and --output-version was ignored
}
