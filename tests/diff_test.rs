use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

/// Helper function to create a test CycloneDX SBOM
fn create_test_cdx_bom(serial_number: &str, components: Vec<(&str, &str, Option<&str>)>) -> Value {
    let comps: Vec<Value> = components
        .iter()
        .map(|(name, version, purl)| {
            let mut comp = serde_json::json!({
                "type": "library",
                "name": name,
                "version": version,
            });
            if let Some(p) = purl {
                comp["purl"] = serde_json::json!(p);
            }
            comp
        })
        .collect();

    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial_number,
        "version": 1,
        "components": comps
    })
}

/// Helper function to create a test SPDX SBOM
fn create_test_spdx_bom(spdx_id: &str, packages: Vec<(&str, &str)>) -> Value {
    let mut graph: Vec<Value> = vec![serde_json::json!({
        "@id": spdx_id,
        "type": "SpdxDocument",
        "spdxVersion": "SPDX-3.0.1",
        "creationInfo": {
            "created": "2024-01-01T00:00:00Z"
        }
    })];

    for (i, (name, version)) in packages.iter().enumerate() {
        graph.push(serde_json::json!({
            "@id": format!("pkg:{}", i),
            "type": "software_Package",
            "name": name,
            "packageVersion": version
        }));
    }

    serde_json::json!({
        "@context": "https://spdx.github.io/spdx-3-model/context.json",
        "@graph": graph,
        "spdxId": spdx_id
    })
}

#[test]
fn test_diff_identical_cyclonedx_boms() {
    let temp_dir = TempDir::new().unwrap();

    let bom = create_test_cdx_bom(
        "urn:uuid:test-1",
        vec![
            ("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21")),
            ("express", "4.18.0", Some("pkg:npm/express@4.18.0")),
        ],
    );

    let file1_path = temp_dir.path().join("bom1.json");
    let file2_path = temp_dir.path().join("bom2.json");

    fs::write(&file1_path, serde_json::to_string_pretty(&bom).unwrap()).unwrap();
    fs::write(&file2_path, serde_json::to_string_pretty(&bom).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("sbom-converter").unwrap();
    cmd.arg("diff")
        .arg("--file1")
        .arg(&file1_path)
        .arg("--file2")
        .arg(&file2_path);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("Components added:      0"));
    assert!(stdout.contains("Components removed:    0"));
    assert!(stdout.contains("Components modified:   0"));
    assert!(stdout.contains("Components unchanged:  2"));
}

#[test]
fn test_diff_added_components() {
    let temp_dir = TempDir::new().unwrap();

    let bom1 = create_test_cdx_bom(
        "urn:uuid:test-1",
        vec![("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21"))],
    );

    let bom2 = create_test_cdx_bom(
        "urn:uuid:test-2",
        vec![
            ("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21")),
            ("express", "4.18.0", Some("pkg:npm/express@4.18.0")),
            ("react", "18.2.0", Some("pkg:npm/react@18.2.0")),
        ],
    );

    let file1_path = temp_dir.path().join("bom1.json");
    let file2_path = temp_dir.path().join("bom2.json");

    fs::write(&file1_path, serde_json::to_string_pretty(&bom1).unwrap()).unwrap();
    fs::write(&file2_path, serde_json::to_string_pretty(&bom2).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("sbom-converter").unwrap();
    cmd.arg("diff")
        .arg("--file1")
        .arg(&file1_path)
        .arg("--file2")
        .arg(&file2_path);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("Components added:      2"));
    assert!(stdout.contains("Components removed:    0"));
    assert!(stdout.contains("express"));
    assert!(stdout.contains("react"));
}

#[test]
fn test_diff_removed_components() {
    let temp_dir = TempDir::new().unwrap();

    let bom1 = create_test_cdx_bom(
        "urn:uuid:test-1",
        vec![
            ("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21")),
            ("express", "4.18.0", Some("pkg:npm/express@4.18.0")),
            ("react", "18.2.0", Some("pkg:npm/react@18.2.0")),
        ],
    );

    let bom2 = create_test_cdx_bom(
        "urn:uuid:test-2",
        vec![("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21"))],
    );

    let file1_path = temp_dir.path().join("bom1.json");
    let file2_path = temp_dir.path().join("bom2.json");

    fs::write(&file1_path, serde_json::to_string_pretty(&bom1).unwrap()).unwrap();
    fs::write(&file2_path, serde_json::to_string_pretty(&bom2).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("sbom-converter").unwrap();
    cmd.arg("diff")
        .arg("--file1")
        .arg(&file1_path)
        .arg("--file2")
        .arg(&file2_path);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("Components added:      0"));
    assert!(stdout.contains("Components removed:    2"));
    assert!(stdout.contains("express"));
    assert!(stdout.contains("react"));
}

#[test]
fn test_diff_json_output() {
    let temp_dir = TempDir::new().unwrap();

    let bom1 = create_test_cdx_bom(
        "urn:uuid:test-1",
        vec![("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21"))],
    );

    let bom2 = create_test_cdx_bom(
        "urn:uuid:test-2",
        vec![
            ("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21")),
            ("express", "4.18.0", Some("pkg:npm/express@4.18.0")),
        ],
    );

    let file1_path = temp_dir.path().join("bom1.json");
    let file2_path = temp_dir.path().join("bom2.json");

    fs::write(&file1_path, serde_json::to_string_pretty(&bom1).unwrap()).unwrap();
    fs::write(&file2_path, serde_json::to_string_pretty(&bom2).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("sbom-converter").unwrap();
    cmd.arg("diff")
        .arg("--file1")
        .arg(&file1_path)
        .arg("--file2")
        .arg(&file2_path)
        .arg("--report-format")
        .arg("json");

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());

    // Parse JSON output
    let json_start = stdout.find('{').unwrap();
    let json_str = &stdout[json_start..];
    let json_output: Value = serde_json::from_str(json_str).unwrap();

    assert_eq!(json_output["summary"]["components_added"], 1);
    assert_eq!(json_output["summary"]["components_removed"], 0);
    assert_eq!(json_output["summary"]["components_unchanged"], 1);

    let added_components = json_output["components"]["added"].as_array().unwrap();
    assert_eq!(added_components.len(), 1);
    assert_eq!(added_components[0]["name"], "express");
}

#[test]
fn test_diff_output_to_file() {
    let temp_dir = TempDir::new().unwrap();

    let bom1 = create_test_cdx_bom(
        "urn:uuid:test-1",
        vec![("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21"))],
    );

    let bom2 = create_test_cdx_bom(
        "urn:uuid:test-2",
        vec![
            ("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21")),
            ("express", "4.18.0", Some("pkg:npm/express@4.18.0")),
        ],
    );

    let file1_path = temp_dir.path().join("bom1.json");
    let file2_path = temp_dir.path().join("bom2.json");
    let output_path = temp_dir.path().join("diff_report.txt");

    fs::write(&file1_path, serde_json::to_string_pretty(&bom1).unwrap()).unwrap();
    fs::write(&file2_path, serde_json::to_string_pretty(&bom2).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("sbom-converter").unwrap();
    cmd.arg("diff")
        .arg("--file1")
        .arg(&file1_path)
        .arg("--file2")
        .arg(&file2_path)
        .arg("--output")
        .arg(&output_path);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // Check that output file was created
    assert!(output_path.exists());

    // Read and verify output file content
    let report_content = fs::read_to_string(&output_path).unwrap();
    assert!(report_content.contains("SBOM DIFF REPORT"));
    assert!(report_content.contains("Components added:      1"));
    assert!(report_content.contains("express"));
}

#[test]
fn test_diff_with_diff_only_flag() {
    let temp_dir = TempDir::new().unwrap();

    let bom1 = create_test_cdx_bom(
        "urn:uuid:test-1",
        vec![
            ("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21")),
            ("express", "4.18.0", Some("pkg:npm/express@4.18.0")),
        ],
    );

    let bom2 = create_test_cdx_bom(
        "urn:uuid:test-2",
        vec![
            ("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21")),
            ("react", "18.2.0", Some("pkg:npm/react@18.2.0")),
        ],
    );

    let file1_path = temp_dir.path().join("bom1.json");
    let file2_path = temp_dir.path().join("bom2.json");

    fs::write(&file1_path, serde_json::to_string_pretty(&bom1).unwrap()).unwrap();
    fs::write(&file2_path, serde_json::to_string_pretty(&bom2).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("sbom-converter").unwrap();
    cmd.arg("diff")
        .arg("--file1")
        .arg(&file1_path)
        .arg("--file2")
        .arg(&file2_path)
        .arg("--diff-only");

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    // Should show added and removed components
    assert!(stdout.contains("react"));
    assert!(stdout.contains("express"));
    // Should NOT show full "COMPONENTS UNCHANGED" section
    assert!(!stdout.contains("COMPONENTS UNCHANGED"));
}

#[test]
fn test_diff_identical_spdx_boms() {
    let temp_dir = TempDir::new().unwrap();

    let bom = create_test_spdx_bom(
        "https://example.com/sbom1",
        vec![("lodash", "4.17.21"), ("express", "4.18.0")],
    );

    let file1_path = temp_dir.path().join("sbom1.json");
    let file2_path = temp_dir.path().join("sbom2.json");

    fs::write(&file1_path, serde_json::to_string_pretty(&bom).unwrap()).unwrap();
    fs::write(&file2_path, serde_json::to_string_pretty(&bom).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("sbom-converter").unwrap();
    cmd.arg("diff")
        .arg("--file1")
        .arg(&file1_path)
        .arg("--file2")
        .arg(&file2_path);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("Components added:      0"));
    assert!(stdout.contains("Components removed:    0"));
    assert!(stdout.contains("Components unchanged:  2"));
}

#[test]
fn test_diff_spdx_added_packages() {
    let temp_dir = TempDir::new().unwrap();

    let bom1 = create_test_spdx_bom("https://example.com/sbom1", vec![("lodash", "4.17.21")]);

    let bom2 = create_test_spdx_bom(
        "https://example.com/sbom2",
        vec![
            ("lodash", "4.17.21"),
            ("express", "4.18.0"),
            ("react", "18.2.0"),
        ],
    );

    let file1_path = temp_dir.path().join("sbom1.json");
    let file2_path = temp_dir.path().join("sbom2.json");

    fs::write(&file1_path, serde_json::to_string_pretty(&bom1).unwrap()).unwrap();
    fs::write(&file2_path, serde_json::to_string_pretty(&bom2).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("sbom-converter").unwrap();
    cmd.arg("diff")
        .arg("--file1")
        .arg(&file1_path)
        .arg("--file2")
        .arg(&file2_path);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("Components added:      2"));
    assert!(stdout.contains("express"));
    assert!(stdout.contains("react"));
}

#[test]
fn test_diff_mixed_formats_fails() {
    let temp_dir = TempDir::new().unwrap();

    let cdx_bom = create_test_cdx_bom(
        "urn:uuid:test-1",
        vec![("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21"))],
    );

    let spdx_bom = create_test_spdx_bom("https://example.com/sbom", vec![("lodash", "4.17.21")]);

    let file1_path = temp_dir.path().join("cdx.json");
    let file2_path = temp_dir.path().join("spdx.json");

    fs::write(&file1_path, serde_json::to_string_pretty(&cdx_bom).unwrap()).unwrap();
    fs::write(
        &file2_path,
        serde_json::to_string_pretty(&spdx_bom).unwrap(),
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("sbom-converter").unwrap();
    cmd.arg("diff")
        .arg("--file1")
        .arg(&file1_path)
        .arg("--file2")
        .arg(&file2_path);

    let output = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stderr.contains("Cannot compare different SBOM formats"));
}

#[test]
fn test_diff_with_dependencies() {
    let temp_dir = TempDir::new().unwrap();

    let mut bom1 = create_test_cdx_bom(
        "urn:uuid:test-1",
        vec![
            ("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21")),
            ("express", "4.18.0", Some("pkg:npm/express@4.18.0")),
        ],
    );

    bom1["dependencies"] = serde_json::json!([
        {
            "ref": "pkg:npm/express@4.18.0",
            "dependsOn": ["pkg:npm/lodash@4.17.21"]
        }
    ]);

    let mut bom2 = create_test_cdx_bom(
        "urn:uuid:test-2",
        vec![
            ("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21")),
            ("express", "4.18.0", Some("pkg:npm/express@4.18.0")),
            ("react", "18.2.0", Some("pkg:npm/react@18.2.0")),
        ],
    );

    bom2["dependencies"] = serde_json::json!([
        {
            "ref": "pkg:npm/express@4.18.0",
            "dependsOn": ["pkg:npm/lodash@4.17.21"]
        },
        {
            "ref": "pkg:npm/react@18.2.0",
            "dependsOn": ["pkg:npm/lodash@4.17.21"]
        }
    ]);

    let file1_path = temp_dir.path().join("bom1.json");
    let file2_path = temp_dir.path().join("bom2.json");

    fs::write(&file1_path, serde_json::to_string_pretty(&bom1).unwrap()).unwrap();
    fs::write(&file2_path, serde_json::to_string_pretty(&bom2).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("sbom-converter").unwrap();
    cmd.arg("diff")
        .arg("--file1")
        .arg(&file1_path)
        .arg("--file2")
        .arg(&file2_path);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("Dependencies added:    1"));
}

#[test]
fn test_diff_with_vulnerabilities() {
    let temp_dir = TempDir::new().unwrap();

    let mut bom1 = create_test_cdx_bom(
        "urn:uuid:test-1",
        vec![("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21"))],
    );

    bom1["vulnerabilities"] = serde_json::json!([
        {
            "id": "CVE-2021-23337",
            "source": {
                "name": "NVD"
            },
            "affects": [
                {
                    "ref": "pkg:npm/lodash@4.17.21"
                }
            ]
        }
    ]);

    let bom2 = create_test_cdx_bom(
        "urn:uuid:test-2",
        vec![("lodash", "4.17.21", Some("pkg:npm/lodash@4.17.21"))],
    );

    let file1_path = temp_dir.path().join("bom1.json");
    let file2_path = temp_dir.path().join("bom2.json");

    fs::write(&file1_path, serde_json::to_string_pretty(&bom1).unwrap()).unwrap();
    fs::write(&file2_path, serde_json::to_string_pretty(&bom2).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("sbom-converter").unwrap();
    cmd.arg("diff")
        .arg("--file1")
        .arg(&file1_path)
        .arg("--file2")
        .arg(&file2_path);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("Vulnerabilities removed: 1"));
    assert!(stdout.contains("CVE-2021-23337"));
}
