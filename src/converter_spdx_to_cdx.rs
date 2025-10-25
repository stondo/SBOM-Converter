//! Implements Strategy 2: The "Multi-Pass Index" Method.
//!
//! Pass 1: Stream `relationships` array, build an in-memory index.
//! Pass 2: Stream `elements` array, writing `components` and `vulnerabilities`
//!         one-by-one. Then, use the index to write `dependencies`.

use crate::cdx_version::CdxVersion;
use crate::errors::ConverterError;
use crate::models_cdx as cdx;
use crate::models_spdx as spdx;
use crate::progress::ProgressTracker;
use log::{info, warn};
use serde::Deserializer;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use uuid::Uuid;

/// The in-memory index. Key is the source SPDX ID.
pub type SpdxRelationshipIndex = HashMap<String, Vec<spdx::SpdxRelationshipMinimal>>;

/// Vulnerability data extracted from Pass 3
#[derive(Debug)]
pub struct VulnerabilityData {
    pub id: String,           // CVE ID
    pub source_id: String,    // SPDX ID for the vulnerability
    pub affects: Vec<String>, // SPDX IDs of affected components
    pub state: String,        // "fixed", "not_affected", etc.
}

/// Main function for SPDX -> CDX conversion.
pub fn convert_spdx_to_cdx<R: Read, W: Write>(
    input_reader: BufReader<R>,
    mut output_writer: BufWriter<W>,
    input_path: &Path,
    progress: ProgressTracker,
    packages_only: bool,
    split_vex: bool,
    output_version: CdxVersion,
) -> Result<(), ConverterError> {
    // --- PASS 1: Build Index ---
    info!("[PASS 1/2] Building relationship index...");
    info!("  Target CycloneDX version: {}", output_version.as_str());
    let start_pass_1 = std::time::Instant::now();

    // We must consume the input_reader to build the index.
    let index = pass_1_build_index(input_reader, progress.clone())?;

    info!(
        "[PASS 1/2] Index complete. Found relationships for {} elements. (Took {:.2?})",
        index.len(),
        start_pass_1.elapsed()
    );

    // --- PASS 2: Convert and Write Components & Dependencies ---
    info!("[PASS 2/3] Re-opening file for components pass...");
    let start_pass_2 = std::time::Instant::now();

    // "Rewind" by re-opening the input file.
    let input_file_pass_2 = File::open(input_path)
        .map_err(|e| ConverterError::Io(e, "Failed to re-open input for Pass 2".to_string()))?;
    let input_reader_pass_2 = BufReader::new(input_file_pass_2);

    // Pass 2 writes components and dependencies, returns serial_number for Pass 3
    let serial_number = pass_2_convert_and_write(
        input_reader_pass_2,
        &mut output_writer,
        &index,
        progress.clone(),
        packages_only,
        split_vex,
        output_version,
    )?;

    info!(
        "[PASS 2/3] Components pass complete. (Took {:.2?})",
        start_pass_2.elapsed()
    );

    // --- PASS 3: Extract and Write Vulnerabilities ---
    info!("[PASS 3/3] Re-opening file for vulnerabilities pass...");
    let start_pass_3 = std::time::Instant::now();

    let input_file_pass_3 = File::open(input_path)
        .map_err(|e| ConverterError::Io(e, "Failed to re-open input for Pass 3".to_string()))?;
    let input_reader_pass_3 = BufReader::new(input_file_pass_3);

    if split_vex {
        // Close main BOM file without vulnerabilities
        output_writer.write_all(b"\n}\n")?;
        output_writer.flush()?;

        // Create separate VEX file
        let vex_path = input_path.with_extension("").with_extension("vex.json");
        info!(
            "Writing vulnerabilities to separate VEX file: {:?}",
            vex_path
        );
        let vex_file = File::create(&vex_path).map_err(|e| {
            ConverterError::Io(e, format!("Failed to create VEX file: {:?}", vex_path))
        })?;
        let mut vex_writer = BufWriter::new(vex_file);

        pass_3_extract_vulnerabilities(
            input_reader_pass_3,
            &mut vex_writer,
            &serial_number,
            true,
            output_version,
        )?;
    } else {
        // Write vulnerabilities to main file
        pass_3_extract_vulnerabilities(
            input_reader_pass_3,
            &mut output_writer,
            &serial_number,
            false,
            output_version,
        )?;
    }

    info!(
        "[PASS 3/3] Vulnerabilities pass complete. (Took {:.2?})",
        start_pass_3.elapsed()
    );

    Ok(())
}

/// Pass 1: Streams the input file and builds the relationship index.
fn pass_1_build_index<R: Read>(
    input_reader: BufReader<R>,
    progress: ProgressTracker,
) -> Result<SpdxRelationshipIndex, ConverterError> {
    let mut index: SpdxRelationshipIndex = HashMap::new();
    let visitor = spdx::SpdxPass1Visitor {
        index: &mut index,
        progress: progress.clone(),
    };
    let mut deserializer = serde_json::Deserializer::from_reader(input_reader);

    // Drive the streaming visitor
    deserializer.deserialize_any(visitor)?;

    Ok(index)
}

/// Pass 2: Streams the input file again, converts, and writes components/dependencies.
/// Returns the serial number for use in Pass 3.
fn pass_2_convert_and_write<R: Read, W: Write>(
    input_reader: BufReader<R>,
    writer: &mut BufWriter<W>,
    index: &SpdxRelationshipIndex,
    progress: ProgressTracker,
    packages_only: bool,
    split_vex: bool,
    output_version: CdxVersion,
) -> Result<String, ConverterError> {
    // --- Write CDX Header ---
    let serial_number = format!("urn:uuid:{}", Uuid::new_v4());
    writer.write_all(b"{\n")?;
    writer.write_all(b"  \"bomFormat\": \"CycloneDX\",\n")?;
    writer
        .write_all(format!("  \"specVersion\": \"{}\",\n", output_version.as_str()).as_bytes())?;
    writer.write_all(format!("  \"serialNumber\": \"{}\",\n", serial_number).as_bytes())?;
    writer.write_all(b"  \"version\": 1,\n")?;

    // --- Write Metadata ---
    let metadata = cdx::CdxMetadata {
        timestamp: chrono::Utc::now().to_rfc3339(),
        tools: Some(cdx::CdxTools {
            components: vec![cdx::CdxToolComponent {
                component_type: "application".to_string(),
                name: "sbom-converter".to_string(),
                bom_ref: format!("sbom-converter-{}", env!("CARGO_PKG_VERSION")),
            }],
        }),
    };
    writer.write_all(b"  \"metadata\": ")?;
    serde_json::to_writer(&mut *writer, &metadata)?;
    writer.write_all(b",\n")?;

    // --- Stream Elements (writing Components & Vulns) ---
    writer.write_all(b"  \"components\": [\n")?;

    let first_component = true;
    let first_vulnerability = true;

    let visitor = spdx::SpdxPass2Visitor {
        writer,
        index,
        first_component,
        first_vulnerability,
        progress: progress.clone(),
        packages_only,
    };

    let mut deserializer = serde_json::Deserializer::from_reader(input_reader);
    deserializer.deserialize_any(visitor)?;

    // Close components array
    writer.write_all(b"\n  ],\n")?;

    // --- Write Dependencies (from Index) ---
    writer.write_all(b"  \"dependencies\": [\n")?;
    let mut first_dep = true;
    for (spdx_id, relationships) in index.iter() {
        let mut depends_on = Vec::new();
        for rel in relationships {
            // Support both simple JSON (DEPENDS_ON) and JSON-LD (dependsOn, contains) formats
            let rel_type = rel.relationship_type.as_str();
            if rel_type == "DEPENDS_ON" || rel_type == "dependsOn" || rel_type == "contains" {
                // Map SPDX ID to bom-ref using same extraction logic
                let bom_ref = extract_bom_ref(&rel.related_spdx_element);
                depends_on.push(bom_ref);
            }
        }

        if !depends_on.is_empty() {
            if !first_dep {
                writer.write_all(b",\n")?;
            }
            first_dep = false;

            // Map SPDX ID to bom-ref for the dependency ref
            let dep_ref = extract_bom_ref(spdx_id);

            let dep = cdx::CdxDependency {
                dep_ref,
                depends_on,
            };
            writer.write_all(b"    ")?;
            serde_json::to_writer(&mut *writer, &dep)?;
        }
    }

    // Close dependencies array
    if split_vex {
        // No comma - we'll close the JSON right after this
        writer.write_all(b"\n  ]")?;
    } else {
        // Keep comma - Pass 3 will add vulnerabilities
        writer.write_all(b"\n  ],")?;
    }

    // Don't finalize JSON yet - Pass 3 may add vulnerabilities and close
    writer.flush()?;
    Ok(serial_number) // Return serial_number for Pass 3
}

/// Pass 3: Extracts vulnerabilities and VEX assessments from JSON-LD @graph.
fn pass_3_extract_vulnerabilities<R: Read, W: Write>(
    input_reader: BufReader<R>,
    writer: &mut BufWriter<W>,
    serial_number: &str,
    separate_file: bool,
    output_version: CdxVersion,
) -> Result<(), ConverterError> {
    if separate_file {
        // Write complete VEX document structure
        writer.write_all(b"{\n")?;
        writer.write_all(b"  \"bomFormat\": \"CycloneDX\",\n")?;
        writer.write_all(
            format!("  \"specVersion\": \"{}\",\n", output_version.as_str()).as_bytes(),
        )?;
        writer.write_all(format!("  \"serialNumber\": \"{}\",\n", serial_number).as_bytes())?;
        writer.write_all(b"  \"version\": 1,\n")?;

        // Add metadata
        let metadata = cdx::CdxMetadata {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tools: Some(cdx::CdxTools {
                components: vec![cdx::CdxToolComponent {
                    component_type: "application".to_string(),
                    name: "sbom-converter".to_string(),
                    bom_ref: format!("sbom-converter-{}", env!("CARGO_PKG_VERSION")),
                }],
            }),
        };
        writer.write_all(b"  \"metadata\": ")?;
        serde_json::to_writer(&mut *writer, &metadata)?;
        writer.write_all(b",\n")?;
    }

    writer.write_all(b"  \"vulnerabilities\": [\n")?;

    let first_vuln = true;
    let visitor = spdx::SpdxPass3VulnVisitor {
        writer,
        serial_number: serial_number.to_string(),
        first_vuln,
    };

    let mut deserializer = serde_json::Deserializer::from_reader(input_reader);
    deserializer.deserialize_any(visitor)?;

    writer.write_all(b"\n  ]")?;

    // --- Finalize JSON ---
    writer.write_all(b"\n}\n")?;
    writer.flush()?;
    Ok(())
}

/// This function is called *for each element* in the SPDX 'elements' array
/// during Pass 2.
pub fn handle_spdx_element<W: Write>(
    element: spdx::SpdxElementMinimal,
    writer: &mut BufWriter<W>,
    _index: &SpdxRelationshipIndex,
    first_component: &mut bool,
    _first_vulnerability: &mut bool,
) -> Result<(), std::io::Error> {
    match element.element_type.as_str() {
        // Support both simple JSON and JSON-LD type names
        "SpdxPackage" | "software_Package" | "SpdxFile" | "software_File" => {
            // Map SPDX ID to bom-ref
            let bom_ref = extract_bom_ref(&element.spdx_id);

            // Extract CPE from externalIdentifier
            let cpe = element.external_identifier.as_ref().and_then(|ids| {
                ids.iter()
                    .find(|id| id.external_identifier_type.as_deref() == Some("cpe23Type"))
                    .and_then(|id| id.identifier.clone())
            });

            // Extract hashes from verified_using
            let hashes = element
                .verified_using
                .as_ref()
                .map(|verified| {
                    verified
                        .iter()
                        .filter_map(|h| {
                            h.algorithm.as_ref().and_then(|alg| {
                                h.hash_value.as_ref().map(|val| cdx::CdxHash {
                                    alg: match alg.to_lowercase().as_str() {
                                        "sha256" | "sha-256" => "SHA-256".to_string(),
                                        "sha1" | "sha-1" => "SHA-1".to_string(),
                                        _ => alg.to_uppercase(),
                                    },
                                    content: val.clone(),
                                })
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .filter(|v| !v.is_empty());

            // Map software_primaryPurpose to scope
            let scope =
                element
                    .software_primary_purpose
                    .as_ref()
                    .map(|purpose| match purpose.as_str() {
                        "install" => "required".to_string(),
                        "optional" => "optional".to_string(),
                        _ => "required".to_string(),
                    });

            let component = cdx::CdxComponent {
                bom_ref,
                component_type: if element.element_type == "SpdxPackage"
                    || element.element_type == "software_Package"
                {
                    "library".to_string()
                } else {
                    "file".to_string()
                },
                name: element.name.unwrap_or_else(|| "Unknown".to_string()),
                version: element.version_info,
                description: element.summary,
                cpe,
                purl: element.purl,
                scope,
                hashes,
                licenses: element.license_concluded.map(|expr| {
                    vec![cdx::CdxLicenseChoice {
                        expression: Some(expr),
                        license: None,
                    }]
                }),
                extra: HashMap::new(), // We didn't deserialize any
            };

            if !*first_component {
                writer.write_all(b",\n")?;
            }
            *first_component = false;

            // Serialize this one component straight to the output file
            writer.write_all(b"    ")?;
            serde_json::to_writer(&mut *writer, &component)?;
        }
        "SpdxVulnerability" | "security_Vulnerability" => {
            // For now, we'll just skip them
            warn!(
                "Skipping vulnerability conversion (not implemented in this pass): {:?}",
                element.name
            );
        }
        _ => {
            // Other element type
        }
    }

    Ok(())
}

/// Extract a usable bom-ref from an SPDX ID (handles both simple format and JSON-LD URIs)
pub fn extract_bom_ref(spdx_id: &str) -> String {
    if spdx_id.starts_with("http://") || spdx_id.starts_with("https://") {
        // JSON-LD URI format: use a hash of the full URI to ensure uniqueness
        // This prevents collisions from URIs ending in common segments like "recipe"
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        spdx_id.hash(&mut hasher);
        let hash = hasher.finish();

        // Also try to extract a meaningful name component
        let name_part = spdx_id
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty() && s.chars().any(|c| c.is_alphabetic()))
            .unwrap_or("element");

        format!("{}-{:x}", name_part, hash)
    } else {
        // Simple JSON format: remove SPDXRef- prefix
        spdx_id
            .strip_prefix("SPDXRef-")
            .unwrap_or(spdx_id)
            .to_string()
    }
}

/// Handle JSON-LD element with full data extraction
pub fn handle_jsonld_element<W: Write>(
    element: spdx::JsonLdElement,
    writer: &mut BufWriter<W>,
    _index: &SpdxRelationshipIndex,
    first_component: &mut bool,
) -> Result<(), std::io::Error> {
    // Map SPDX ID to bom-ref
    let bom_ref = extract_bom_ref(&element.spdx_id);

    let component = cdx::CdxComponent {
        bom_ref,
        component_type: if element.element_type == "software_Package" {
            "library".to_string()
        } else {
            "file".to_string()
        },
        name: element
            .name
            .clone()
            .unwrap_or_else(|| "Unknown".to_string()),
        version: element.software_package_version.clone(),
        description: element.description.clone().or(element.summary.clone()),
        cpe: element.extract_cpe(),
        purl: element.extract_purl(),
        scope: element.map_scope(),
        hashes: element.extract_hashes(),
        licenses: None, // TODO: Extract from license relationships
        extra: HashMap::new(),
    };

    if !*first_component {
        writer.write_all(b",\n")?;
    }
    *first_component = false;

    // Serialize this one component straight to the output file
    writer.write_all(b"    ")?;
    serde_json::to_writer(&mut *writer, &component)?;

    Ok(())
}
