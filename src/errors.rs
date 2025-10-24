//! Defines the custom error types for the application.
//!
//! This uses `thiserror` as specified in `Cargo.toml` for clean,
//! boilerplate-free error handling.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConverterError {
    #[error("I/O Error: {1} - {0}")]
    Io(#[source] std::io::Error, String),

    #[error("JSON Deserialization Error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("JSON Schema Validation Error: {0}")]
    Validation(String),

    #[error("Schema Loading Error for file: {0}")]
    SchemaLoad(PathBuf),

    #[error("Configuration Error: {0}")]
    Config(String),

    #[error("Internal Streaming Error: {0}")]
    Streaming(String),

    #[error("Temporary file operation failed: {0}")]
    TempFile(#[source] std::io::Error),

    #[error("File I/O operation failed: {0}")]
    FileIO(String),

    #[error("JSON Parsing Error: {0}")]
    JsonParse(String),

    #[error("Parse Error: {0}")]
    ParseError(String),

    #[error("Serialization Error: {0}")]
    SerializationError(String),

    #[error("Invalid Input: {0}")]
    InvalidInput(String),

    #[error("Unsupported Format: {0}")]
    UnsupportedFormat(String),
}

// Implement From<io::Error> for easier error handling
impl From<std::io::Error> for ConverterError {
    fn from(err: std::io::Error) -> Self {
        ConverterError::Io(err, "IO operation failed".to_string())
    }
}
