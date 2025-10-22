# SBOM Converter

A high-performance, memory-efficient Rust tool for bidirectional conversion between **SPDX 3.0.1** and **CycloneDX 1.6** SBOM formats. Designed to handle extremely large SBOM files (tested with 2.9GB+ files) using streaming architecture with constant memory footprint.

**Supported Formats:**

- **SPDX:** Version 3.0.1 (JSON only)
- **CycloneDX:** Version 1.6 (JSON only)

## Features

- 🔄 **Bidirectional Conversion**: Convert between SPDX and CycloneDX formats
- 🚀 **Streaming Architecture**: Handles multi-gigabyte files with constant memory usage
- ⚡ **High Performance**: Multi-pass optimization for large-scale SBOMs
- ✅ **Schema Validation**: Optional JSON schema validation against official SPDX/CDX schemas
- 🛡️ **Robust Error Handling**: Comprehensive error messages and validation
- 📊 **Verbose Logging**: Optional detailed output for debugging and monitoring
- 📈 **Progress Tracking**: Real-time progress indicators for large file conversions (reports every 1000 elements)

## Architecture

### CDX → SPDX Conversion

Uses a **single-pass streaming with temp file** approach:

1. Stream through CDX file once
2. Write SPDX elements to main output file
3. Write relationships to temporary file
4. Merge temp file relationships into final output

### SPDX → CDX Conversion

Uses a **two-pass indexing** approach:

1. **Pass 1**: Build relationship index (HashMap of package dependencies)
2. **Pass 2**: Re-stream file and convert elements using the index

Both methods maintain **O(1) memory complexity** relative to file size using Serde's `Visitor` pattern.

## Installation

### Prerequisites

- Rust 1.85+ (2024 edition)
- Cargo

### Build from Source

```bash
# Clone the repository
git clone https://github.com/stondo/SBOM-Converter.git
cd SBOM-Converter

# Build release version (optimized)
cargo build --release

# Binary will be at: ./target/release/sbom-converter
```

## Usage

### Basic Command Structure

```bash
sbom-converter --input <INPUT_FILE> --output <OUTPUT_FILE> --direction <DIRECTION> [OPTIONS]
```

### Arguments

| Argument | Short | Required | Description |
|----------|-------|----------|-------------|
| `--input` | `-i` | Yes | Path to input SBOM file (JSON format) |
| `--output` | `-o` | Yes | Path to output SBOM file (JSON format) |
| `--direction` | `-d` | Yes | Conversion direction: `spdx-to-cdx` or `cdx-to-spdx` |
| `--verbose` | `-v` | No | Enable detailed logging output |
| `--validate` | | No | Enable JSON schema validation (requires schemas/) |

### Examples

#### Convert SPDX to CycloneDX

```bash
./target/release/sbom-converter \
  --input sbom-spdx.json \
  --output sbom-cyclonedx.json \
  --direction spdx-to-cdx \
  --verbose
```

#### Convert CycloneDX to SPDX

```bash
./target/release/sbom-converter \
  --input sbom-cyclonedx.json \
  --output sbom-spdx.json \
  --direction cdx-to-spdx \
  --verbose
```

#### With Schema Validation

```bash
./target/release/sbom-converter \
  --input large-sbom.json \
  --output converted-sbom.json \
  --direction spdx-to-cdx \
  --validate \
  --verbose
```

## Schema Validation

The tool supports optional JSON schema validation. Place the following schema files in the `schemas/` directory:

- `spdx_3.0.1.schema.json` - SPDX 3.0.1 JSON schema
- `cdx_1.6.schema.json` - CycloneDX 1.6 JSON schema

Schemas are automatically loaded when the `--validate` flag is used.

## Performance Characteristics

### Memory Usage

- **Constant O(1) memory** relative to file size for element streaming
- **O(n) memory** only for relationship indexing in SPDX→CDX conversion
  - Where n = number of relationships (typically much smaller than file size)

### Processing Speed

- Tested with **2.9GB SBOM files**
- Streaming prevents memory overflow on large files
- Release build recommended for optimal performance

### Benchmarks (Example Hardware)

```
File Size: 2.9GB
Conversion: SPDX → CDX
Time: ~45 seconds
Peak Memory: ~850MB (for relationship index)
```

## Error Handling

The tool provides clear error messages for common issues:

- **File I/O Errors**: Missing input files, permission issues, disk space
- **JSON Parse Errors**: Malformed JSON, invalid SBOM structure
- **Validation Errors**: Schema validation failures with line references
- **Schema Load Errors**: Missing or invalid schema files

Example error output:
```
Error: Failed to read input file
Cause: No such file or directory (os error 2)
File: input.json
```

## Project Structure

```
sbom-converter/
├── Cargo.toml                      # Project configuration
├── README.md                       # This file
├── schemas/                        # JSON schemas (optional)
│   ├── cdx_1.6.schema.json
│   └── spdx_3.0.1.schema.json
├── src/
│   ├── main.rs                     # CLI entry point
│   ├── lib.rs                      # Library interface
│   ├── errors.rs                   # Error types
│   ├── models_cdx.rs               # CycloneDX models & streaming
│   ├── models_spdx.rs              # SPDX models & streaming
│   ├── converter_cdx_to_spdx.rs    # CDX→SPDX converter
│   ├── converter_spdx_to_cdx.rs    # SPDX→CDX converter
│   └── schema.rs                   # Schema validation
└── tests/
    └── integration_test.rs         # Integration tests
```

## Dependencies

Major dependencies:

- **serde** / **serde_json** - JSON serialization/deserialization with streaming
- **clap** - Command-line argument parsing
- **jsonschema** - JSON schema validation
- **uuid** - Temporary file naming
- **chrono** - Timestamp handling
- **thiserror** - Error type derivation

See `Cargo.toml` for complete dependency list.

## Development

### Run Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test integration_test
```

### Debug Build

```bash
cargo build

# Run debug version
./target/debug/sbom-converter --help
```

### Code Quality

```bash
# Check for errors without building
cargo check

# Format code
cargo fmt

# Run linter
cargo clippy
```

## Troubleshooting

### Out of Memory Errors

- Ensure you're using the release build: `cargo build --release`
- For SPDX→CDX with extremely large relationship counts, increase system swap space

### JSON Parse Errors

- Validate input file is valid JSON: `jq . < input.json`
- Check for trailing commas or syntax errors
- Ensure file encoding is UTF-8

### Schema Validation Failures

- Verify schema files are in `schemas/` directory
- Check schema file names match expected patterns
- Try running without `--validate` flag to isolate conversion issues

## Limitations

- **Format Support:** Only JSON format is currently supported (XML and YAML are not supported)
- **SPDX Version:** Only SPDX 3.0.1 is supported (SPDX 2.x is not supported)
- **CycloneDX Version:** Only CycloneDX 1.6 is supported (earlier versions are not supported)
- **Relationship Mapping:** Some complex SPDX relationship types may be mapped in a lossy manner
- **External References:** External references and attestations may have limited mapping

## Contributing

Contributions are welcome! Areas for improvement:

- Additional SBOM format support (SWID, etc.)
- Enhanced relationship mapping
- Parallel processing for multi-core systems
- Support for compressed input files (gzip, bzip2, xz)
- Support for SPDX 2.x and earlier CycloneDX versions

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Acknowledgments

Built with Rust's powerful streaming capabilities using the Serde ecosystem.
