# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-10-25

### Added

#### Diff Command
- **New `diff` command** for comparing two SBOM files and generating detailed difference reports
- Comprehensive diff reporting with added, removed, modified, and unchanged components
- Support for both text (colored) and JSON output formats
- `--diff-only` flag to show only differences, hiding unchanged components
- Component identification using purl, bom-ref/spdxId, or name+version
- Dependency and vulnerability change tracking
- Full support for both CycloneDX and SPDX 3.0.1 formats
- 11 comprehensive test cases covering all diff scenarios

#### XML Format Support
- **XML output support for merge command** (CycloneDX only)
- JSON to XML conversion using quick-xml library with serialize feature
- Proper XML attribute transformation (@type, @bom-ref, @ref)
- Full namespace and schema validation support
- Manual XML structure building for CdxDocument serialization
- Test coverage for XML merge functionality

#### Multi-Version CycloneDX Support
- Support for CycloneDX versions 1.3, 1.4, 1.5, 1.6 (default), and 1.7
- `--output-version` flag to specify desired CycloneDX version
- Version-specific schema validation
- Backward compatibility with older CycloneDX versions

#### Enhanced SPDX 3.0.1 Support
- Improved JSON-LD format detection with @graph array support
- Automatic detection of SpdxDocument type elements in @graph structures
- Better handling of both simple JSON and JSON-LD formats
- Enhanced version detection with fallback to 3.0.1

### Changed
- Enhanced `merge` command documentation to reflect XML support
- Updated README with comprehensive diff command documentation (~110 lines)
- Improved CLI parameter naming (report_format in diff to avoid conflicts)
- Enhanced error messages for format mismatches in diff operations

### Fixed
- CLI parameter conflict between diff command and global options
- SPDX 3.0.1 JSON-LD detection failure with @graph structures
- JSON to XML attribute transformation for CycloneDX serialization
- Unused import warnings in merge module

### Performance
- All 73 tests passing (35 lib unit tests + 38 integration tests)
- Zero compiler warnings after cleanup
- Maintained streaming architecture efficiency
- Pre-commit hook enforced formatting on all commits

### Documentation
- Added comprehensive diff command documentation with examples
- Updated merge documentation to reflect XML support
- Enhanced competitive positioning documentation
- Added format compatibility matrix
- Documented data preservation guarantees for packages-only mode

### Testing
- 11 new diff command tests covering:
  - Identical SBOM comparison
  - Added/removed components tracking
  - Modified component detection
  - JSON output format validation
  - File output functionality
  - Diff-only filtering
  - SPDX format support
  - Mixed format error handling
  - Dependency change tracking
  - Vulnerability comparison
- XML merge test validation
- Total test coverage: 73 tests (100% pass rate)

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

[1.1.0]: https://github.com/stondo/SBOM-Converter/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/stondo/SBOM-Converter/releases/tag/v1.0.0
