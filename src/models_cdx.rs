//! Contains *minimal* data structures for streaming CycloneDX 1.6 JSON.
//!
//! We only define the fields we actually need for the conversion,
//! allowing `serde` to efficiently skip all other fields.

use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::BufWriter;

// --- Minimal Structs for Streaming ---

/// Top-level BOM structure (minimal)
#[derive(Deserialize, Serialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct CdxBom {
    #[serde(default)]
    pub bom_format: String,
    #[serde(default)]
    pub spec_version: String,
    #[serde(default)]
    pub serial_number: String,
    #[serde(default)]
    pub version: u32,
}

/// A minimal representation of a CycloneDX Component.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CdxComponent {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub component_type: String, // "library", "file", etc.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub licenses: Option<Vec<CdxLicenseChoice>>,
    // We use IgnoredAny to quickly skip over fields we don't need during deserialization
    // Skip it during serialization
    #[serde(flatten, skip_serializing)]
    pub extra: HashMap<String, IgnoredAny>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CdxLicenseChoice {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<CdxLicense>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CdxLicense {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// A minimal representation of a CycloneDX Dependency.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CdxDependency {
    #[serde(rename = "ref")]
    pub dep_ref: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

/// A minimal representation of a CycloneDX Vulnerability.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CdxVulnerability {
    pub id: String, // e.g., CVE-2021-44228
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CdxVulnSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affects: Option<Vec<CdxAffects>>,
    #[serde(flatten)]
    pub extra: HashMap<String, IgnoredAny>,
}

#[derive(Deserialize, Debug)]
pub struct CdxVulnSource {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct CdxAffects {
    #[serde(rename = "ref")]
    pub bom_ref: String,
}

// --- Streaming Visitor Logic ---

/// A custom serde Visitor to stream-deserialize the top-level CDX document.
pub struct CdxStreamingVisitor<'a, W: std::io::Write> {
    // This visitor holds the state for our "Temp File" strategy.
    pub writer: &'a mut BufWriter<W>,
    pub temp_writer: &'a mut BufWriter<File>,
    pub first_element: bool,
}

impl<'de, 'a, W: std::io::Write> Visitor<'de> for CdxStreamingVisitor<'a, W> {
    type Value = (); // We don't return anything; we write to files

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a top-level CycloneDX JSON object")
    }

    fn visit_map<M>(mut self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "components" => {
                    // Found the 'components' array. Stream it.
                    map.next_value_seed(CdxComponentStreamVisitor { state: &mut self })?;
                }
                "vulnerabilities" => {
                    // Found the 'vulnerabilities' array. Stream it.
                    map.next_value_seed(CdxVulnerabilityStreamVisitor { state: &mut self })?;
                }
                "dependencies" => {
                    // Found the 'dependencies' array. Stream it.
                    map.next_value_seed(CdxDependencyStreamVisitor { state: &mut self })?;
                }
                _ => {
                    // Skip all other keys and their values
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

// --- Component Stream Visitor ---
pub struct CdxComponentStreamVisitor<'a, 'b, W: std::io::Write> {
    state: &'b mut CdxStreamingVisitor<'a, W>,
}

impl<'de, 'a, 'b, W: std::io::Write> de::DeserializeSeed<'de>
    for CdxComponentStreamVisitor<'a, 'b, W>
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a, 'b, W: std::io::Write> Visitor<'de> for CdxComponentStreamVisitor<'a, 'b, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of CDX components")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while let Some(component) = seq.next_element::<CdxComponent>()? {
            // This is where we call the conversion logic
            crate::converter_cdx_to_spdx::handle_cdx_component(
                component,
                self.state.writer,
                &mut self.state.first_element,
            )
            .map_err(de::Error::custom)?;
        }
        Ok(())
    }
}

// --- Vulnerability Stream Visitor ---
pub struct CdxVulnerabilityStreamVisitor<'a, 'b, W: std::io::Write> {
    state: &'b mut CdxStreamingVisitor<'a, W>,
}

impl<'de, 'a, 'b, W: std::io::Write> de::DeserializeSeed<'de>
    for CdxVulnerabilityStreamVisitor<'a, 'b, W>
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a, 'b, W: std::io::Write> Visitor<'de> for CdxVulnerabilityStreamVisitor<'a, 'b, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of CDX vulnerabilities")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while let Some(vuln) = seq.next_element::<CdxVulnerability>()? {
            // This is where we call the conversion logic
            crate::converter_cdx_to_spdx::handle_cdx_vulnerability(
                vuln,
                self.state.writer,
                self.state.temp_writer,
                &mut self.state.first_element,
            )
            .map_err(de::Error::custom)?;
        }
        Ok(())
    }
}

// --- Dependency Stream Visitor ---
pub struct CdxDependencyStreamVisitor<'a, 'b, W: std::io::Write> {
    state: &'b mut CdxStreamingVisitor<'a, W>,
}

impl<'de, 'a, 'b, W: std::io::Write> de::DeserializeSeed<'de>
    for CdxDependencyStreamVisitor<'a, 'b, W>
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, 'a, 'b, W: std::io::Write> Visitor<'de> for CdxDependencyStreamVisitor<'a, 'b, W> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of CDX dependencies")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while let Some(dep) = seq.next_element::<CdxDependency>()? {
            // This is where we call the conversion logic
            crate::converter_cdx_to_spdx::handle_cdx_dependency(dep, self.state.temp_writer)
                .map_err(de::Error::custom)?;
        }
        Ok(())
    }
}
