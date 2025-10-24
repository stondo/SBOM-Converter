# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-24

### Added

- **Bidirectional Conversion**: Complete support for SPDX 3.0.1 ↔ CycloneDX 1.6 conversion
- **JSON-LD Support**: Full support for SPDX 3.0.1 JSON-LD/RDF format (OpenEmbedded, Yocto)
- **Streaming Architecture**: Memory-efficient streaming for multi-gigabyte files (tested up to 2.5GB)
- **Schema Validation**: Optional JSON schema validation with `--validate` flag
  - Full schema validation for CycloneDX 1.6 and SPDX 3.0.1 simple JSON
  - Structural validation for SPDX JSON-LD format
  - Optional skip flag for JSON-LD validation (`--skip-jsonld-validation`)
- **Packages-Only Mode**: Filter individual files, keep only packages (`--packages-only`)
- **VEX Support**: Split vulnerabilities into separate VEX file (`--split-vex`)
- **Enhanced Metadata Extraction**:
  - CPE identifiers
  - SHA-256 and SHA-1 hashes
  - Component descriptions
  - Package URLs (PURLs)
  - License information
  - Vulnerability data with VEX analysis
- **Progress Tracking**: Real-time progress indicators for large files (reports every 1000 elements)
- **Verbose Logging**: Optional detailed output with `--verbose` flag
- **Comprehensive Error Handling**: Clear error messages with context

### Features

- **Multi-Format Support**:
  - SPDX 3.0.1 (Simple JSON and JSON-LD/RDF formats)
  - CycloneDX 1.6 (JSON only)
- **Production-Scale Performance**:
  - Handles 2.5GB files with ~2 million elements
  - ~100K elements/sec throughput
  - Constant O(1) memory for streaming
  - O(n) memory for relationship indexing
- **Complete Data Preservation**:
  - 100% round-trip fidelity for package metadata
  - All security data preserved (CPEs, hashes, vulnerabilities)
  - Relationship integrity maintained
- **CLI Options**:
  - `--input` / `-i`: Input SBOM file path
  - `--output` / `-o`: Output SBOM file path
  - `--direction` / `-d`: Conversion direction (spdx-to-cdx or cdx-to-spdx)
  - `--packages-only`: Filter individual files (SPDX→CDX only)
  - `--split-vex`: Split vulnerabilities to separate VEX file (SPDX→CDX only)
  - `--verbose` / `-v`: Enable detailed logging
  - `--validate`: Enable schema validation
  - `--skip-jsonld-validation`: Skip JSON-LD structural validation

### Technical

- **Rust 2024 Edition** (requires 1.85+)
- **Streaming JSON parsing** with Serde
- **Multi-pass optimization** for large-scale SBOMs:
  - CDX→SPDX: Single-pass streaming with temp file
  - SPDX→CDX: Three-pass indexing for comprehensive data extraction
- **Robust error handling** with thiserror
- **Comprehensive test suite** with integration tests

### Performance

- **Real-world benchmarks**:
  - 2.5GB SPDX file → 457MB CycloneDX in 21.9 seconds
  - 2.5GB SPDX file → 387KB CycloneDX (packages-only) in 19.8 seconds
  - 5.4MB SPDX file → 881KB CycloneDX in ~46ms
- **Validated with**:
  - OpenEmbedded/Yocto SPDX 3.0.1 JSON-LD files
  - Real-world embedded Linux distribution SBOMs
  - Multi-gigabyte production SBOM files

### Documentation

- Comprehensive README with usage examples
- Field mapping table for bidirectional conversion
- Performance benchmarks and characteristics
- Troubleshooting guide
- Data preservation guarantees

## [Unreleased]

### Planned Features

- XML support for SPDX 3.0.1 and CycloneDX 1.6
- Parallel processing for multi-core systems
- Compressed input file support (gzip, bzip2, xz)
- SPDX 2.x support
- Earlier CycloneDX versions support

---

[1.0.0]: https://github.com/stondo/SBOM-Converter/releases/tag/v1.0.0
