//! Implements Strategy 2: The "Multi-Pass Index" Method.
//!
//! Pass 1: Stream `relationships` array, build an in-memory index.
//! Pass 2: Stream `elements` array, writing `components` and `vulnerabilities`
//!         one-by-one. Then, use the index to write `dependencies`.

use crate::errors::ConverterError;
use crate::models_cdx as cdx;
use crate::models_spdx as spdx;
use log::{info, warn};
use serde::Deserializer;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use uuid::Uuid;

/// The in-memory index. Key is the source SPDX ID.
pub type SpdxRelationshipIndex = HashMap<String, Vec<spdx::SpdxRelationshipMinimal>>;

/// Main function for SPDX -> CDX conversion.
pub fn convert_spdx_to_cdx<R: Read, W: Write>(
    input_reader: BufReader<R>,
    mut output_writer: BufWriter<W>,
    input_path: &Path,
) -> Result<(), ConverterError> {
    // --- PASS 1: Build Index ---
    info!("[PASS 1/2] Building relationship index...");
    let start_pass_1 = std::time::Instant::now();

    // We must consume the input_reader to build the index.
    let index = pass_1_build_index(input_reader)?;

    info!(
        "[PASS 1/2] Index complete. Found relationships for {} elements. (Took {:.2?})",
        index.len(),
        start_pass_1.elapsed()
    );

    // --- PASS 2: Convert and Write ---
    info!("[PASS 2/2] Re-opening file for conversion pass...");
    let start_pass_2 = std::time::Instant::now();

    // "Rewind" by re-opening the input file.
    let input_file_pass_2 = File::open(input_path)
        .map_err(|e| ConverterError::Io(e, "Failed to re-open input for Pass 2".to_string()))?;
    let input_reader_pass_2 = BufReader::new(input_file_pass_2);

    pass_2_convert_and_write(input_reader_pass_2, &mut output_writer, &index)?;

    info!(
        "[PASS 2/2] Conversion pass complete. (Took {:.2?})",
        start_pass_2.elapsed()
    );

    Ok(())
}

/// Pass 1: Streams the input file and builds the relationship index.
fn pass_1_build_index<R: Read>(
    input_reader: BufReader<R>,
) -> Result<SpdxRelationshipIndex, ConverterError> {
    let mut index: SpdxRelationshipIndex = HashMap::new();
    let visitor = spdx::SpdxPass1Visitor { index: &mut index };
    let mut deserializer = serde_json::Deserializer::from_reader(input_reader);

    // Drive the streaming visitor
    deserializer.deserialize_any(visitor)?;

    Ok(index)
}

/// Pass 2: Streams the input file again, converts, and writes the output.
fn pass_2_convert_and_write<R: Read, W: Write>(
    input_reader: BufReader<R>,
    writer: &mut BufWriter<W>,
    index: &SpdxRelationshipIndex,
) -> Result<(), ConverterError> {
    // --- Write CDX Header ---
    let serial_number = format!("urn:uuid:{}", Uuid::new_v4());
    writer.write_all(b"{\n")?;
    writer.write_all(b"  \"bomFormat\": \"CycloneDX\",\n")?;
    writer.write_all(b"  \"specVersion\": \"1.6\",\n")?;
    writer.write_all(format!("  \"serialNumber\": \"{}\",\n", serial_number).as_bytes())?;
    writer.write_all(b"  \"version\": 1,\n")?;

    // --- Stream Elements (writing Components & Vulns) ---
    writer.write_all(b"  \"components\": [\n")?;

    let first_component = true;
    let first_vulnerability = true;

    let visitor = spdx::SpdxPass2Visitor {
        writer,
        index,
        first_component,
        first_vulnerability,
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
            if rel.relationship_type == "DEPENDS_ON" {
                // Map SPDX ID to bom-ref (strip SPDXRef- prefix if present)
                let bom_ref = rel.related_spdx_element
                    .strip_prefix("SPDXRef-")
                    .unwrap_or(&rel.related_spdx_element)
                    .to_string();
                depends_on.push(bom_ref);
            }
        }

        if !depends_on.is_empty() {
            if !first_dep {
                writer.write_all(b",\n")?;
            }
            first_dep = false;

            // Map SPDX ID to bom-ref for the dependency ref
            let dep_ref = spdx_id
                .strip_prefix("SPDXRef-")
                .unwrap_or(spdx_id)
                .to_string();

            let dep = cdx::CdxDependency {
                dep_ref,
                depends_on,
            };
            writer.write_all(b"    ")?;
            serde_json::to_writer(&mut *writer, &dep)?;
        }
    }
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
        "SpdxPackage" | "SpdxFile" => {
            // Map SPDX ID to bom-ref
            let bom_ref = element.spdx_id
                .strip_prefix("SPDXRef-")
                .unwrap_or(&element.spdx_id)
                .to_string();

            let component = cdx::CdxComponent {
                bom_ref,
                component_type: if element.element_type == "SpdxPackage" {
                    "library".to_string()
                } else {
                    "file".to_string()
                },
                name: element.name.unwrap_or_else(|| "Unknown".to_string()),
                version: element.version_info,
                purl: element.purl,
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
        "SpdxVulnerability" => {
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
