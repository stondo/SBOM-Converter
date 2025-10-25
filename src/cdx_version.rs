//! CycloneDX version types and utilities

use std::str::FromStr;

/// CycloneDX specification version
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CdxVersion {
    V1_3,
    V1_4,
    V1_5,
    V1_6,
    V1_7,
}

impl CdxVersion {
    /// Get the version string (e.g., "1.6")
    pub fn as_str(&self) -> &'static str {
        match self {
            CdxVersion::V1_3 => "1.3",
            CdxVersion::V1_4 => "1.4",
            CdxVersion::V1_5 => "1.5",
            CdxVersion::V1_6 => "1.6",
            CdxVersion::V1_7 => "1.7",
        }
    }
}

impl FromStr for CdxVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1.3" => Ok(CdxVersion::V1_3),
            "1.4" => Ok(CdxVersion::V1_4),
            "1.5" => Ok(CdxVersion::V1_5),
            "1.6" => Ok(CdxVersion::V1_6),
            "1.7" => Ok(CdxVersion::V1_7),
            _ => Err(format!("Invalid CycloneDX version: {}", s)),
        }
    }
}

impl Default for CdxVersion {
    fn default() -> Self {
        Self::V1_6 // Keep 1.6 as default for compatibility
    }
}
