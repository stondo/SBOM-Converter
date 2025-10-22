//! Implements the CycloneDX -> SPDX streaming conversion.
//!
//! This module contains the logic for the "Temp File" method using a
//! proper `serde::de::Visitor` to ensure true streaming with low memory.
//! We stream the input CDX file once, writing `SpdxElement` objects to the
//! main output writer and `SpdxRelationship` objects to a temporary file.
//! Finally, we append the contents of the temp file to the main output.

use crate::errors::ConverterError;
use crate::models_cdx::{CdxComponent, CdxDependency, CdxVulnerability};
use crate::models_spdx::{RelationshipType, SpdxElement, SpdxPackage, SpdxRelationship};
use crate::progress::ProgressTracker;

use log::{debug, info};
use serde::Deserializer;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;

/// Orchestrates the CDX -> SPDX conversion.
///
/// Reads from `reader`, writes elements to `writer`, and writes relationships
/// to a temporary file at `temp_path`.
pub fn convert_cdx_to_spdx<R: Read>(
    reader: R,
    writer: &mut BufWriter<File>,
    temp_path: &Path,
    progress: ProgressTracker,
) -> Result<(), ConverterError> {
    info!("Starting CDX -> SPDX conversion stream...");
    debug!("Using temp file: {}", temp_path.display());

    // 1. Open the temporary file for relationships
    let temp_file = File::create(temp_path)
        .map_err(|e| ConverterError::FileIO(format!("Failed to create temp file: {}", e)))?;
    let mut temp_writer = BufWriter::new(temp_file);

    // 2. Write SPDX header
    writer.write_all(b"{\n")?;
    writer.write_all(b"  \"spdxVersion\": \"SPDX-3.0\",\n")?;
    writer.write_all(b"  \"dataLicense\": \"CC0-1.0\",\n")?;
    writer.write_all(b"  \"spdxId\": \"SPDXRef-DOCUMENT\",\n")?;
    writer.write_all(b"  \"name\": \"Converted SBOM\",\n")?;
    writer.write_all(
        format!(
            "  \"documentNamespace\": \"urn:uuid:{}\",\n",
            uuid::Uuid::new_v4()
        )
        .as_bytes(),
    )?;
    writer.write_all(b"  \"creationInfo\": {\n")?;
    writer.write_all(
        format!(
            "    \"created\": \"{}\",\n",
            chrono::Utc::now().to_rfc3339()
        )
        .as_bytes(),
    )?;
    writer.write_all(b"    \"creators\": [\"Tool: sbom-converter\"]\n")?;
    writer.write_all(b"  },\n")?;

    // 3. Start elements array
    writer.write_all(b"  \"elements\": [\n")?;
    let mut first_element = true;

    // 4. Set up the streaming deserializer
    let mut deserializer = serde_json::Deserializer::from_reader(reader);

    // 5. Run the streaming visitor
    let visitor = CdxVisitor {
        writer,
        temp_writer: &mut temp_writer,
        first_element: &mut first_element,
        progress: progress.clone(),
    };
    deserializer
        .deserialize_any(visitor)
        .map_err(|e| ConverterError::JsonParse(e.to_string()))?;

    // 6. Close the "elements" array
    writer.write_all(b"\n  ],\n")?;

    // 7. Start the "relationships" array
    writer.write_all(b"  \"relationships\": [\n")?;

    // 8. Flush and append temp file contents
    temp_writer.flush()?;
    drop(temp_writer); // Close the temp file writer

    info!("Appending relationships from temp file...");
    let temp_file = File::open(temp_path).map_err(|e| {
        ConverterError::FileIO(format!("Failed to open temp file for reading: {}", e))
    })?;
    let temp_reader = BufReader::new(temp_file);

    let mut first_relationship = true;
    for line in temp_reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue; // Skip empty lines
        }

        if !first_relationship {
            writer.write_all(b",\n")?;
        }
        writer.write_all(b"    ")?;
        writer.write_all(line.trim().as_bytes())?;
        first_relationship = false;
    }

    // 9. Close the "relationships" array and the main JSON object
    writer.write_all(b"\n  ]\n")?;
    writer.write_all(b"}\n")?;

    writer.flush()?;
    info!("CDX -> SPDX conversion complete.");
    Ok(())
}

// =========================================================================
// Serde Visitor Implementation for streaming
// =========================================================================

/// A visitor for the top-level CycloneDX BOM object.
struct CdxVisitor<'a, W: Write> {
    writer: &'a mut BufWriter<W>,
    temp_writer: &'a mut BufWriter<File>,
    first_element: &'a mut bool,
    progress: ProgressTracker,
}

impl<'de, 'a, W: Write> serde::de::Visitor<'de> for CdxVisitor<'a, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a CycloneDX BOM JSON object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: serde::de::MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "components" => {
                    // Stream components array
                    let component_visitor = ComponentArrayVisitor {
                        writer: self.writer,
                        first_element: self.first_element,
                        progress: self.progress.clone(),
                    };
                    map.next_value_seed(component_visitor)?;
                }
                "dependencies" => {
                    // Stream dependencies array
                    let dep_visitor = DependencyArrayVisitor {
                        temp_writer: self.temp_writer,
                        progress: self.progress.clone(),
                    };
                    map.next_value_seed(dep_visitor)?;
                }
                "vulnerabilities" => {
                    // Stream vulnerabilities array
                    let vuln_visitor = VulnerabilityArrayVisitor {
                        writer: self.writer,
                        temp_writer: self.temp_writer,
                        first_element: self.first_element,
                        progress: self.progress.clone(),
                    };
                    map.next_value_seed(vuln_visitor)?;
                }
                _ => {
                    // Skip other keys
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }

        Ok(())
    }
}

/// Visitor for the components array
struct ComponentArrayVisitor<'a, W: Write> {
    writer: &'a mut BufWriter<W>,
    first_element: &'a mut bool,
    progress: ProgressTracker,
}

impl<'de, 'a, W: Write> serde::de::DeserializeSeed<'de> for ComponentArrayVisitor<'a, W> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a, W: Write> serde::de::Visitor<'de> for ComponentArrayVisitor<'a, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of components")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        use serde::de::Error;

        while let Some(component) = seq.next_element::<CdxComponent>()? {
            handle_cdx_component(component, self.writer, self.first_element)
                .map_err(Error::custom)?;
            self.progress.increment_element();
        }
        Ok(())
    }
}

/// Visitor for the dependencies array
struct DependencyArrayVisitor<'a> {
    temp_writer: &'a mut BufWriter<File>,
    progress: ProgressTracker,
}

impl<'de, 'a> serde::de::DeserializeSeed<'de> for DependencyArrayVisitor<'a> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a> serde::de::Visitor<'de> for DependencyArrayVisitor<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of dependencies")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        use serde::de::Error;

        while let Some(dep) = seq.next_element::<CdxDependency>()? {
            handle_cdx_dependency(dep, self.temp_writer).map_err(Error::custom)?;
            self.progress.increment_relationship();
        }
        Ok(())
    }
}

/// Visitor for the vulnerabilities array
struct VulnerabilityArrayVisitor<'a, W: Write> {
    writer: &'a mut BufWriter<W>,
    temp_writer: &'a mut BufWriter<File>,
    first_element: &'a mut bool,
    progress: ProgressTracker,
}

impl<'de, 'a, W: Write> serde::de::DeserializeSeed<'de> for VulnerabilityArrayVisitor<'a, W> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a, W: Write> serde::de::Visitor<'de> for VulnerabilityArrayVisitor<'a, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of vulnerabilities")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        use serde::de::Error;

        while let Some(vuln) = seq.next_element::<CdxVulnerability>()? {
            handle_cdx_vulnerability(vuln, self.writer, self.temp_writer, self.first_element)
                .map_err(Error::custom)?;
            self.progress.increment_element();
        }
        Ok(())
    }
}

// =========================================================================
// Handler functions
// =========================================================================

/// Handles a single CDX component, converting and writing it
pub fn handle_cdx_component<W: Write>(
    component: CdxComponent,
    writer: &mut BufWriter<W>,
    first_element: &mut bool,
) -> Result<(), std::io::Error> {
    let spdx_pkg = SpdxPackage::from_cdx_component(&component);

    if !*first_element {
        writer.write_all(b",\n")?;
    }
    *first_element = false;

    writer.write_all(b"    ")?;
    serde_json::to_writer(&mut *writer, &spdx_pkg)?;
    Ok(())
}

/// Handles a single CDX dependency, writing relationships to temp file
pub fn handle_cdx_dependency(
    dep: CdxDependency,
    temp_writer: &mut BufWriter<File>,
) -> Result<(), std::io::Error> {
    for target_ref in dep.depends_on {
        let rel = SpdxRelationship {
            spdx_element_id: format!("SPDXRef-{}", dep.dep_ref),
            relationship_type: RelationshipType::DependsOn,
            related_spdx_element: format!("SPDXRef-{}", target_ref),
        };

        serde_json::to_writer(&mut *temp_writer, &rel)?;
        temp_writer.write_all(b"\n")?;
    }
    Ok(())
}

/// Handles a single CDX vulnerability, converting and writing it
pub fn handle_cdx_vulnerability<W: Write>(
    vuln: CdxVulnerability,
    writer: &mut BufWriter<W>,
    temp_writer: &mut BufWriter<File>,
    first_element: &mut bool,
) -> Result<(), std::io::Error> {
    // 1. Write the Vulnerability as an SPDX Element
    let vuln_spdx_id = format!("SPDXRef-Vulnerability-{}", vuln.id);
    let element = SpdxElement {
        spdx_id: vuln_spdx_id.clone(),
        element_type: "SpdxVulnerability".to_string(),
        name: vuln.id.clone(),
        version_info: None,
        purl: None,
        license_concluded: None,
    };

    if !*first_element {
        writer.write_all(b",\n")?;
    }
    *first_element = false;

    writer.write_all(b"    ")?;
    serde_json::to_writer(&mut *writer, &element)?;

    // 2. Write the "AFFECTS" relationships to the temp file
    if let Some(affects) = vuln.affects {
        for affected_component in affects {
            let rel = SpdxRelationship {
                spdx_element_id: vuln_spdx_id.clone(),
                relationship_type: RelationshipType::Affects,
                related_spdx_element: format!("SPDXRef-{}", affected_component.bom_ref),
            };

            serde_json::to_writer(&mut *temp_writer, &rel)?;
            temp_writer.write_all(b"\n")?;
        }
    }

    Ok(())
}
