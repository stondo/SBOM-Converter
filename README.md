# SBOM Converter

[![CI](https://github.com/stondo/SBOM-Converter/workflows/CI/badge.svg)](https://github.com/stondo/SBOM-Converter/actions/workflows/ci.yml)
[![Release](https://github.com/stondo/SBOM-Converter/workflows/Release/badge.svg)](https://github.com/stondo/SBOM-Converter/actions/workflows/release.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/stondo/SBOM-Converter#license)
[![Rust Version](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/stondo/SBOM-Converter/releases)

A high-performance, memory-efficient Rust tool for bidirectional conversion between **SPDX 3.0.1** and **CycloneDX 1.3-1.7** SBOM formats. Designed to handle extremely large SBOM files (tested with 2.5GB files containing nearly 2 million elements) using streaming architecture with constant memory footprint.

**Supported Formats:**

- **SPDX:** Version 3.0.1 (both simple JSON and JSON-LD/RDF formats, plus XML)
- **CycloneDX:** Versions 1.3, 1.4, 1.5, 1.6, 1.7 (JSON and XML formats)

**Format Compatibility Matrix:**

| Input Format | Output Format | Versions Supported | Schema Validation |
|--------------|---------------|-------------------|-------------------|
| SPDX 3.0.1 JSON/JSON-LD | CycloneDX JSON | 1.3, 1.4, 1.5, 1.6 (default), 1.7 | ✅ JSON Schema |
| SPDX 3.0.1 XML | CycloneDX JSON | 1.3, 1.4, 1.5, 1.6 (default), 1.7 | ✅ XSD Schema |
| CycloneDX JSON | SPDX 3.0.1 JSON-LD | 3.0.1 | ✅ JSON Schema |
| CycloneDX XML | SPDX 3.0.1 XML | 3.0.1 | ✅ XSD Schema |

**Competitive Advantages:**

- **SPDX 3.0.1 Support**: Full support for the latest SPDX specification (most tools still only support SPDX 2.x)
- **Multi-Version CycloneDX**: Support for all CycloneDX versions from 1.3 to 1.7
- **XML Format Support**: Both input and output in XML format with XSD validation
- **Streaming Architecture**: Handles multi-gigabyte files with constant memory usage

**Validated With:**

- OpenEmbedded/Yocto SPDX 3.0.1 JSON-LD files (863 packages, 2368 files, 1771 relationships)
- Real-world SBOMs from embedded Linux distributions

## Features

- 🔄 **Bidirectional Conversion**: Convert between SPDX and CycloneDX formats
- 🚀 **Streaming Architecture**: Handles multi-gigabyte files with constant memory usage
- ⚡ **High Performance**: Multi-pass optimization for large-scale SBOMs
- 📋 **JSON-LD Support**: Full support for SPDX 3.0.1 JSON-LD/RDF format (OpenEmbedded, Yocto)
- 🛡️ **Enhanced Security Data**: Captures CPE identifiers, hashes (SHA-256), and vulnerability information
- 🔒 **VEX Support**: Full vulnerability and VEX assessment extraction with URN references
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

Uses a **three-pass indexing** approach for comprehensive data extraction:

1. **Pass 1**: Build relationship index (HashMap of package dependencies)
2. **Pass 2**: Stream and convert components with enhanced metadata (CPE, hashes, descriptions)
3. **Pass 3**: Extract vulnerabilities and VEX assessments with URN-based affects references

**Enhanced Data Extraction:**

- CPE identifiers from `externalIdentifier` fields
- SHA-256/SHA-1 hashes from `verifiedUsing` fields
- Component descriptions and scopes
- CVE vulnerability data with NVD source
- VEX assessment states (resolved, not_affected, in_triage)
- Metadata with timestamp and tool information

Both methods maintain **O(1) memory complexity** relative to file size using Serde's `Visitor` pattern.

## Installation

### Download Pre-built Binaries

Download the latest release for your platform from the [Releases page](https://github.com/stondo/SBOM-Converter/releases).

Available platforms:

- Linux (x86_64)
- macOS (x86_64, ARM64)
- Windows (x86_64)

Extract and run:

```bash
# Linux/macOS
tar xzf sbom-converter-linux-x86_64-v1.0.0.tar.gz
./sbom-converter-linux-x86_64 --help

# Windows
# Extract .zip file and run sbom-converter-windows-x86_64.exe
```

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
| `--input` | `-i` | Yes | Path to input SBOM file (JSON or XML format) |
| `--output` | `-o` | Yes | Path to output SBOM file (JSON or XML format) |
| `--direction` | `-d` | Yes | Conversion direction: `spdx-to-cdx` or `cdx-to-spdx` |
| `--output-version` | | No | CycloneDX output version: `1.3`, `1.4`, `1.5`, `1.6` (default), `1.7` (ignored for SPDX output) |
| `--packages-only` | | No | Only convert packages/libraries, skip individual files (SPDX→CDX only) |
| `--split-vex` | | No | Split vulnerabilities into separate VEX file (SPDX→CDX only) |
| `--verbose` | `-v` | No | Enable detailed logging output |
| `--validate` | | No | Enable schema validation (JSON Schema or XSD depending on format) |

### Examples

#### Convert SPDX to CycloneDX

```bash
./target/release/sbom-converter \
  --input sbom-spdx.json \
  --output sbom-cyclonedx.json \
  --direction spdx-to-cdx \
  --verbose
```

#### Convert SPDX to CycloneDX (Packages Only)

Filter out individual files, keeping only packages/libraries:

```bash
./target/release/sbom-converter \
  --input sbom-spdx.json \
  --output sbom-cyclonedx.json \
  --direction spdx-to-cdx \
  --packages-only \
  --verbose
```

#### Convert SPDX to CycloneDX with Specific Version

Generate CycloneDX output in a specific version:

```bash
# Generate CycloneDX 1.3 output
./target/release/sbom-converter \
  --input sbom-spdx.json \
  --output sbom-cdx-1.3.json \
  --direction spdx-to-cdx \
  --output-version 1.3

# Generate CycloneDX 1.7 output (latest)
./target/release/sbom-converter \
  --input sbom-spdx.json \
  --output sbom-cdx-1.7.json \
  --direction spdx-to-cdx \
  --output-version 1.7
```

#### Convert SPDX to CycloneDX with Split VEX

Separate vulnerabilities into a dedicated VEX file following CycloneDX best practices:

```bash
./target/release/sbom-converter \
  --input sbom-spdx.json \
  --output bom.json \
  --direction spdx-to-cdx \
  --packages-only \
  --split-vex \
  --verbose
```

This produces two files:

- `bom.json` - Components and dependencies (no vulnerabilities)
- `sbom-spdx.vex.json` - Vulnerabilities with URN references to components

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

### Validate Command

The tool includes a standalone validation command to check SBOM files without converting them:

```bash
sbom-converter validate --input <INPUT_FILE> [OPTIONS]
```

#### Validation Options

| Option | Description |
|--------|-------------|
| `--input <FILE>` | Path to SBOM file (JSON or XML) |
| `--schema` | Perform schema validation (JSON Schema for JSON files, XSD for XML) |
| `--show-version` | Display detected SBOM format and version |
| `--report-format <text\|json>` | Output format (default: text) |
| `--fail-on-errors` | Exit with error code if validation fails |
| `--no-color` | Disable colored output |

#### Validation Capabilities

| Format | Structural Validation | Schema Validation |
|--------|----------------------|-------------------|
| **CycloneDX JSON** | ✅ Full | ✅ JSON Schema (bom-1.6.schema.json) |
| **CycloneDX XML** | ✅ Full | ✅ XSD Schema (bom-1.6.xsd) via libxml2 |
| **SPDX JSON** | ✅ Full | ✅ JSON Schema (spdx_3.0.1.schema.json) |

**Implementation details:**

- **XML validation** uses libxml2 for XSD schema validation, matching the approach used by CycloneDX CLI
- Validates against official CycloneDX XSD schemas (`bom-1.6.xsd`, `bom-1.5.xsd`, etc.)
- Checks namespace URI matches expected CycloneDX namespace
- Provides detailed error messages for schema violations

**System requirements for XML validation:**

- `libxml2` and `libxml2-devel` (or `libxml2-dev` on Debian/Ubuntu)
- `clang` and `clang-devel` for building libxml bindings

#### Validation Examples

```bash
# Validate a JSON file (structural validation)
sbom-converter validate --input sbom.json

# Validate with schema checking
sbom-converter validate --input sbom.json --schema

# Check SBOM format and version
sbom-converter validate --input sbom.xml --show-version

# Get JSON report
sbom-converter validate --input sbom.json --report-format json

# Validate and fail on errors (for CI/CD)
sbom-converter validate --input sbom.json --schema --fail-on-errors
```

#### Example Output

```text
ℹ Validating XML structure...

Format Detection:
  Format: CycloneDX 1.6
  Schema: cdx_1.6.schema.json

Validating: /tmp/test-cdx.xml

ℹ [components[0]] Component missing purl (Package URL)
  → Add "purl": "pkg:npm/name@version" for better identification
ℹ XSD schema validation not yet implemented for XML files
  → XML structural validation performed (XML parsing + model validation).

Summary: 2 infos
```

### Merge Command

Combine multiple SBOM files into a single consolidated SBOM. The merge command intelligently deduplicates components and combines dependencies from all input files.

```bash
sbom-converter merge --inputs <FILE> <FILE>... --output <FILE> [OPTIONS]
```

#### Merge Options

| Option | Description |
|--------|-------------|
| `--inputs <FILE>...` | Two or more input SBOM files to merge (required, minimum 2) |
| `--output <FILE>` | Output file path for merged SBOM (required) |
| `--dedup <STRATEGY>` | Deduplication strategy: `first` (default) or `latest` |
| `--output-format <FORMAT>` | Output format: `json` or `xml` (auto-detected from extension) |

#### Deduplication Strategies

| Strategy | Behavior |
|----------|----------|
| **first** (default) | Keeps the first occurrence of duplicate components |
| **latest** | Keeps the latest (last) occurrence of duplicate components |

Components are identified by:

1. **purl** (Package URL) - highest priority
2. **bom-ref** (CycloneDX) or **spdxId** (SPDX) - fallback
3. **name + version** - final fallback

#### Merge Examples

**Basic merge:**

```bash
sbom-converter merge \
  --inputs sbom1.json sbom2.json \
  --output merged.json
```

**Merge multiple files with latest strategy:**

```bash
sbom-converter merge \
  --inputs project-a.json project-b.json project-c.json \
  --output combined.json \
  --dedup latest
```

**Merge using wildcards:**

```bash
sbom-converter merge \
  --inputs services/*.json \
  --output all-services.json
```

#### Merge Behavior

**What gets merged:**

- ✅ Components/packages from all files
- ✅ Dependencies and relationships
- ✅ Vulnerabilities (CycloneDX)
- ✅ Metadata from first file

**Deduplication:**

- Duplicate components are identified by purl, bom-ref, or name+version
- Dependencies are combined (union of all dependency relationships)
- Strategy determines which component metadata to keep

**Requirements:**

- All input files must be the same format (all CycloneDX or all SPDX)
- Mixing formats will fail with an error
- Minimum 2 input files required
- Currently supports JSON output only (XML coming soon)

### Diff Command

Compare two SBOM files and generate a detailed report of differences. The diff command shows added, removed, and modified components, dependencies, and vulnerabilities.

```bash
sbom-converter diff --file1 <FILE> --file2 <FILE> [OPTIONS]
```

#### Diff Options

| Option | Description |
|--------|-------------|
| `--file1 <FILE>` | First SBOM file to compare (required) |
| `--file2 <FILE>` | Second SBOM file to compare (required) |
| `--report-format <FORMAT>` | Output format: `text` (default) or `json` |
| `--output <FILE>` | Write diff report to file (prints to stdout if not specified) |
| `--diff-only` | Show only differences, hide unchanged components |

#### Diff Examples

**Basic comparison (text output):**

```bash
sbom-converter diff \
  --file1 old-sbom.json \
  --file2 new-sbom.json
```

**JSON output for programmatic processing:**

```bash
sbom-converter diff \
  --file1 baseline.json \
  --file2 current.json \
  --report-format json \
  --output diff-report.json
```

**Show only differences:**

```bash
sbom-converter diff \
  --file1 v1.0-sbom.json \
  --file2 v2.0-sbom.json \
  --diff-only
```

#### Diff Report Sections

The diff report includes the following sections:

**Summary:**

- Count of added, removed, modified, and unchanged components
- Dependencies added/removed
- Vulnerabilities added/removed

**Components:**

- ✅ **Added:** New components in file2 not in file1
- ✗ **Removed:** Components in file1 not in file2
- ~ **Modified:** Components present in both but with changes (version, type, etc.)
- = **Unchanged:** Identical components (shown unless `--diff-only` is used)

**Dependencies:**

- Added/removed dependency relationships between components

**Vulnerabilities (CycloneDX):**

- Added/removed security vulnerabilities

**Metadata:**

- Changes to document-level metadata (serial number, version, etc.)

#### Diff Behavior

**Component Identification:**

Components are matched using the same priority as merge:

1. **purl** (Package URL) - highest priority
2. **bom-ref** (CycloneDX) or **spdxId** (SPDX) - fallback
3. **name + version** - final fallback

**Format Requirements:**

- Both files must be the same SBOM format (both CycloneDX or both SPDX)
- Comparing different formats will fail with an error
- Supports both CycloneDX and SPDX 3.0.1 (JSON and JSON-LD)

**Output Formats:**

- **Text:** Human-readable colored output with clear sections
- **JSON:** Structured data for automated processing and CI/CD integration

**Use Cases:**

- Track component changes between software versions
- Verify SBOM updates after dependency upgrades
- Audit supply chain changes in CI/CD pipelines
- Compare production vs. development SBOMs
- Validate merge operations

## Schema Validation

The tool supports optional JSON schema validation using the `--validate` flag. The schema files are bundled with the tool:

- `schemas/spdx_3.0.1.schema.json` - SPDX 3.0.1 JSON schema (simple JSON format)
- `schemas/cdx_1.6.schema.json` - CycloneDX 1.6 JSON schema

### Validation Behavior

| Format | Validation Type | Details |
|--------|----------------|---------|
| **CycloneDX 1.6** | Full Schema Validation | All fields, types, and constraints validated |
| **SPDX 3.0.1 Simple JSON** | Full Schema Validation | All fields, types, and constraints validated |
| **SPDX 3.0.1 JSON-LD** | Structural Validation | Validates @context, @graph, element structure. Does not perform full RDF semantic validation. Use `--skip-jsonld-validation` to skip. |

#### JSON-LD Structural Validation

For SPDX JSON-LD format (used by Yocto/OpenEmbedded), the tool performs structural validation by default:

- ✅ Verifies `@context` is present and valid (string, array, or object)
- ✅ Verifies `@graph` is present and is an array
- ✅ Validates each element in `@graph` is a proper object
- ✅ Reports statistics on `@type` and `@id` usage

**Performance note:** With optimized builds (release mode), structural validation adds minimal overhead (~0.2-0.5% on large files). Most of the "validation time" is actually JSON parsing, which is unavoidable.

**Skip structural validation:** Use the `--skip-jsonld-validation` flag if you want to skip the structural checks entirely:

```bash
./target/release/sbom-converter \
  --input large-yocto-file.spdx.json \
  --output output.cdx.json \
  --direction spdx-to-cdx \
  --validate \
  --skip-jsonld-validation
```

**Why not full RDF validation?** JSON-LD is a serialization of RDF (Resource Description Framework). Full semantic validation would require RDF/SHACL tools. The structural validation catches malformed JSON-LD files while being very fast. For complete semantic validation, use tools like [pyshacl](https://github.com/RDFLib/pySHACL) with the [SPDX 3.0 SHACL shapes](https://spdx.github.io/spdx-spec/v3.0/rdf/spdx-model.ttl).

**Example validation output for JSON-LD:**

```text
[INFO ] Detected JSON-LD format. Performing structural validation...
[INFO ] JSON-LD structural validation passed:
[INFO ]   - 7241 elements in @graph
[INFO ]   - 0 elements with @type
[INFO ]   - 383 elements with @id
[INFO ] Validation passed successfully. (Took 40.15ms)
```

### Validation During Conversion

```bash
# Validate CycloneDX file (full schema validation)
./target/release/sbom-converter \
  --input sbom.cdx.json \
  --output sbom.spdx.json \
  --direction cdx-to-spdx \
  --validate

# Validate SPDX simple JSON (full schema validation)
./target/release/sbom-converter \
  --input sbom-simple.spdx.json \
  --output sbom.cdx.json \
  --direction spdx-to-cdx \
  --validate

# Validate SPDX JSON-LD (structural validation)
./target/release/sbom-converter \
  --input sbom-jsonld.spdx.json \
  --output sbom.cdx.json \
  --direction spdx-to-cdx \
  --validate

# Validate SPDX JSON-LD but skip structural checks (fastest)
./target/release/sbom-converter \
  --input large-yocto.spdx.json \
  --output sbom.cdx.json \
  --direction spdx-to-cdx \
  --validate \
  --skip-jsonld-validation
```

**Note:** Validation is optional. Files that fail validation may still convert successfully if they contain the necessary data for conversion.

## SPDX 3.0.1 Format Support

The converter supports both SPDX 3.0.1 formats:

### Simple JSON Format

Traditional format with flat `elements` and `relationships` arrays:

```json
{
  "spdxVersion": "SPDX-3.0",
  "elements": [
    {"spdxId": "SPDXRef-Package1", "type": "SpdxPackage", "name": "example"}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-Package1", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package2"}
  ]
}
```

### JSON-LD/RDF Format

Semantic web format with `@context` and `@graph` (used by OpenEmbedded, Yocto):

```json
{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "software_Package",
      "spdxId": "http://spdx.org/spdxdocs/example/package/1",
      "name": "example",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "Relationship",
      "from": "http://spdx.org/spdxdocs/example/package/1",
      "relationshipType": "dependsOn",
      "to": ["http://spdx.org/spdxdocs/example/package/2"]
    }
  ]
}
```

The converter automatically detects the format and processes it appropriately. JSON-LD URIs are hashed to create unique CycloneDX bom-refs.

## Advanced Conversion Options

### Packages-Only Mode (`--packages-only`)

When converting from SPDX to CycloneDX, you can filter out individual files and keep only packages/libraries:

```bash
./target/release/sbom-converter \
  --input sbom-spdx.json \
  --output sbom-cyclonedx.json \
  --direction spdx-to-cdx \
  --packages-only
```

**Benefits:**

- Reduces output size significantly (e.g., 881KB → 325KB)
- Focuses on meaningful software components (packages/libraries)
- Excludes individual files which are often not relevant for dependency analysis
- Ideal for supply chain security analysis and vulnerability management

**Example Impact:**

- Before: 3,231 components (863 packages + 2,368 files)
- After: 863 components (packages only)

**Understanding File Size Reduction:**

The dramatic size reduction (e.g., 2.5GB → 387KB) when using `--packages-only` is intentional and correct:

```text
Your SPDX file contains:
├── 863 packages          (0.04% of data) ← Critical metadata preserved
└── 1,964,683 files       (99.96% of data) ← Intentionally filtered out

Why this is correct:
✅ Packages contain: names, versions, CPEs, hashes, dependencies, vulnerabilities
✅ Files are typically: individual binaries, source files, build artifacts
✅ Supply chain security focuses on packages, not individual files
✅ Vulnerability databases reference packages, not files
✅ CycloneDX best practice: package-level granularity for distribution
```

**Data Preservation Guarantee:**

- ✅ **100% of package metadata preserved**: All names, versions, CPEs, hashes, descriptions, PURLs, licenses, dependencies, and vulnerabilities are fully retained
- ✅ **Zero security data loss**: All CVEs, VEX states, and security identifiers maintained
- ❌ **File entries intentionally excluded**: Individual file paths and hashes are filtered (by design)

For complete details on what data is preserved vs. filtered, see [DATA_PRESERVATION.md](DATA_PRESERVATION.md).

### Split VEX Mode (`--split-vex`)

Following CycloneDX best practices, you can separate vulnerability data into a dedicated VEX (Vulnerability Exploitability eXchange) file:

```bash
./target/release/sbom-converter \
  --input sbom-spdx.json \
  --output bom.json \
  --direction spdx-to-cdx \
  --split-vex
```

**Output Files:**

1. `bom.json` - Main SBOM with components and dependencies (no vulnerabilities)
2. `{input-name}.vex.json` - Separate VEX file with all vulnerability data

**Benefits:**

- Follows CycloneDX VEX specification for large vulnerability datasets
- Main BOM stays focused on component inventory
- VEX file can be updated independently as new vulnerabilities are discovered
- Reduces main BOM size when vulnerability data is extensive
- Supports dynamic vulnerability scanning workflows

**VEX File Structure:**

- Full CycloneDX 1.6 document with `bomFormat`, `specVersion`, `serialNumber`, `version`
- Metadata with tool information
- Vulnerabilities array with URN references to components in main BOM
- URN format: `urn:uuid:{main-bom-serial-number}#{component-bom-ref}`

**Example URN Reference:**

```json
"affects": [{
  "ref": "urn:uuid:b5ac6773-5bc6-477e-a55d-77b45835e867#busybox-b1ef70881579a83f"
}]
```

### Combined Usage

Both flags work together for optimal results:

```bash
./target/release/sbom-converter \
  --input yocto-build.spdx.json \
  --output bom.json \
  --direction spdx-to-cdx \
  --packages-only \
  --split-vex
```

**Result:**

- `bom.json` (325KB): 863 packages with metadata, 361 dependencies, 0 vulnerabilities
- `yocto-build.vex.json` (62KB): 57 vulnerabilities with URN references

This combination provides:

- Clean, focused component inventory
- Separate vulnerability tracking
- Smaller file sizes for easier distribution
- Better alignment with CycloneDX best practices

## Bidirectional Metadata Mapping

The converter preserves metadata bidirectionally with **full round-trip fidelity**. All data is accurately mapped between SPDX 3.0.1 and CycloneDX 1.6 formats in both directions.

### Field Mapping Table

| Data Category | CycloneDX 1.6 | SPDX 3.0.1 | Round-Trip | Notes |
|---------------|---------------|------------|------------|-------|
| Component Name | `name` | `name` | ✅ | Preserved perfectly |
| Component Version | `version` | `versionInfo` | ✅ | Preserved perfectly |
| Component Type | `type` | `type` (SpdxPackage/SpdxFile) | ✅ | Mapped: library→Package, file→File |
| Unique Identifier | `bom-ref` | `spdxId` | ✅ | Hashed for JSON-LD URIs |
| CPE Identifier | `cpe` | `externalIdentifier[type=cpe23Type]` | ✅ | Full CPE 2.3 preservation |
| Package URL | `purl` | `purl` | ✅ | Native support in both |
| SHA-256 Hash | `hashes[alg=SHA-256]` | `verifiedUsing[algorithm=sha256]` | ✅ | Full hash preservation |
| SHA-1 Hash | `hashes[alg=SHA-1]` | `verifiedUsing[algorithm=sha1]` | ✅ | Full hash preservation |
| Description | `description` | `summary` | ✅ | Component documentation |
| Scope | `scope` | `software_primaryPurpose` | ✅ | Mapped: required↔install, optional↔optional |
| License | `licenses[].expression` | `license_concluded` | ✅ | SPDX expressions preserved |
| Dependencies | `dependencies[].dependsOn[]` | `relationships[type=DEPENDS_ON]` | ✅ | Flattened array ↔ individual relationships |
| CVE ID | `vulnerabilities[].id` | `elements[type=SpdxVulnerability].name` | ✅ | CVE identifiers |
| Affected Components | `vulnerabilities[].affects[].ref` (URN) | `relationships[type=AFFECTS]` | ✅ | URN format: `urn:uuid:{serial}#{bom-ref}` |
| VEX State | `vulnerabilities[].analysis.state` | VEX relationship types | ✅ | resolved, not_affected, in_triage |

### Conversion Examples

#### CycloneDX → SPDX

**Input (CycloneDX):**

```json
{
  "bom-ref": "busybox-abc123",
  "type": "library",
  "name": "busybox",
  "version": "1.36.1",
  "description": "BusyBox combines tiny versions of many common UNIX utilities",
  "cpe": "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*",
  "purl": "pkg:yocto/busybox@1.36.1",
  "scope": "required",
  "hashes": [
    {
      "alg": "SHA-256",
      "content": "a4b0c1d2e3f4567890abcdef..."
    }
  ]
}
```

**Output (SPDX 3.0.1):**

```json
{
  "spdxId": "SPDXRef-busybox-abc123",
  "type": "SpdxPackage",
  "name": "busybox",
  "versionInfo": "1.36.1",
  "summary": "BusyBox combines tiny versions of many common UNIX utilities",
  "purl": "pkg:yocto/busybox@1.36.1",
  "software_primaryPurpose": "install",
  "externalIdentifier": [
    {
      "type": "ExternalIdentifier",
      "externalIdentifierType": "cpe23Type",
      "identifier": "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*"
    }
  ],
  "verifiedUsing": [
    {
      "type": "Hash",
      "algorithm": "sha-256",
      "hashValue": "a4b0c1d2e3f4567890abcdef..."
    }
  ]
}
```

#### SPDX → CycloneDX

The reverse conversion preserves all fields, ensuring **lossless round-trip** transformation.

### Round-Trip Verification

**Tested Scenarios:**

```text
✅ CycloneDX → SPDX → CycloneDX
   - 863 components with full metadata
   - All CPE identifiers preserved (188)
   - All hashes preserved (2,979)
   - All descriptions preserved (189)
   - All relationships preserved (4,593)

✅ SPDX → CycloneDX → SPDX
   - Simple JSON and JSON-LD formats
   - All SPDX fields preserved
   - Relationship integrity maintained
```

**Performance:**

- Round-trip conversion: ~14ms for 863 components
- Zero data loss in bidirectional conversion
- Metadata integrity verified with real-world Yocto/OpenEmbedded SBOMs

## Enhanced Data Extraction

When converting from SPDX 3.0.1 (especially JSON-LD format) to CycloneDX 1.6, the converter captures comprehensive metadata:

### Component Metadata

- **CPE Identifiers**: Extracted from `externalIdentifier` fields for security scanning
- **Hash Values**: SHA-256 and SHA-1 hashes from `verifiedUsing` fields for integrity verification
- **Descriptions**: Component summaries for documentation
- **Scopes**: Mapped from `software_primaryPurpose` (e.g., APPLICATION, LIBRARY, FRAMEWORK)
- **PURLs**: Package URLs preserved from SPDX for package identification

### Vulnerability & VEX Data

- **CVE Identifiers**: Extracted from vulnerability objects or SPDX IDs
- **VEX Analysis**: Assessment states (resolved, not_affected, in_triage)
- **Affected Components**: URN-based references linking vulnerabilities to specific components
- **Source Attribution**: NVD references for vulnerability details

### SBOM Metadata

- **Timestamp**: Conversion timestamp in RFC3339 format
- **Tool Information**: Converter tool identification and version

### Example Output Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2025-10-22T17:21:20.123Z",
    "tools": {
      "components": [{
        "type": "application",
        "name": "sbom-converter",
        "bom-ref": "sbom-converter-0.1.0"
      }]
    }
  },
  "components": [{
    "bom-ref": "busybox-b1ef70881579a83f",
    "type": "library",
    "name": "busybox",
    "version": "1.36.1",
    "description": "BusyBox combines tiny versions of many common UNIX utilities",
    "cpe": "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*",
    "purl": "pkg:yocto/busybox@1.36.1",
    "scope": "required",
    "hashes": [{
      "alg": "SHA-256",
      "content": "a4b0c..."
    }]
  }],
  "vulnerabilities": [{
    "id": "CVE-2022-28391",
    "source": {
      "name": "NVD",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-28391"
    },
    "analysis": {
      "state": "resolved"
    },
    "affects": [{
      "ref": "urn:uuid:77cabc09-32dd-43cf-9929-0456af623129#busybox-b1ef70881579a83f"
    }]
  }]
}
```

## Performance Characteristics

### Memory Usage

- **Constant O(1) memory** relative to file size for element streaming
- **O(n) memory** only for relationship indexing in SPDX→CDX conversion
  - Where n = number of relationships (typically much smaller than file size)

### Processing Speed

- Tested with multi-gigabyte SBOM files (up to 2.5GB+)
- Streaming architecture prevents memory overflow on massive files
- Release build recommended for optimal performance
- Multi-pass approach maintains efficiency even with millions of elements

### Benchmarks (Real-World Performance)

**Production-Scale Yocto/OpenEmbedded Build - 2.5GB File:**

```text
File Size: 2.5GB SPDX 3.0.1 JSON-LD
Input:    ~1.97 million elements (863 packages + 1,964,683 files)
          3.98 million relationships
          57 vulnerabilities

Full Conversion (SPDX → CDX):
  Output: 457MB CycloneDX 1.6 JSON
  Time:   21.9 seconds
  Peak Memory: ~2.5GB (for relationship indexing)
  Throughput: 89,751 elements/sec
  Components: 1,965,546 (all files included)

Packages-Only Conversion (SPDX → CDX --packages-only):
  Output: 387KB CycloneDX 1.6 JSON (1,182x smaller!)
  Time:   19.8 seconds (10% faster)
  Peak Memory: ~2.5GB
  Throughput: 99,455 elements/sec
  Components: 863 packages only
  Dependencies: 361
  Vulnerabilities: 57

Performance Notes:
  - 82% file size reduction (2.5GB → 457MB) for full conversion
  - 99.98% file size reduction (2.5GB → 387KB) with --packages-only
  - Consistent ~100K elements/sec throughput on large files
  - Memory usage scales with relationship count, not file size
  - 3-pass streaming architecture maintains constant memory for element processing
```

**Medium File Conversion:**

```text
File Size: 5.4MB SPDX JSON-LD (Yocto/OpenEmbedded)
Input: 863 packages, 2368 files, 57 vulnerabilities
Output: 881KB CycloneDX 1.6 JSON (full conversion)
        325KB CycloneDX BOM + 62KB VEX file (with --packages-only --split-vex)
Conversion: SPDX → CDX (3-pass)
Time: ~46ms
Peak Memory: ~100MB
Throughput: 71,843 elements/sec
Data Extracted:
  - 3,231 components (863 packages when --packages-only used)
  - 361 dependencies
  - 2,979 hash values (SHA-256)
  - 188 CPE identifiers
  - 189 descriptions
  - 57 vulnerabilities with VEX analysis
```

## Error Handling

The tool provides clear error messages for common issues:

- **File I/O Errors**: Missing input files, permission issues, disk space
- **JSON Parse Errors**: Malformed JSON, invalid SBOM structure
- **Validation Errors**: Schema validation failures with line references
- **Schema Load Errors**: Missing or invalid schema files

Example error output:

```rust
Error: Failed to read input file
Cause: No such file or directory (os error 2)
File: input.json
```

## Project Structure

```bash
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
- **File-Level Data:** When using `--packages-only`, individual file entries are intentionally filtered out (see [DATA_PRESERVATION.md](DATA_PRESERVATION.md) for details)

## Data Preservation

**Important:** The converter preserves **100% of package-level metadata** (names, versions, CPEs, hashes, dependencies, vulnerabilities) but **intentionally filters file entries** when using `--packages-only`. This is correct behavior and matches CycloneDX best practices for SBOM distribution.

For complete details on what data is preserved in different conversion scenarios, see [DATA_PRESERVATION.md](DATA_PRESERVATION.md).

## Contributing

Contributions are welcome! Areas for improvement:

- Additional SBOM format support (SWID, etc.)
- Enhanced relationship mapping
- Parallel processing for multi-core systems
- Support for compressed input files (gzip, bzip2, xz)
- Support for SPDX 2.x and earlier CycloneDX versions

### Development Workflow

We follow a **Git Flow** branching model:

- **`main`** - Production-ready code with tagged releases (e.g., v1.0.0)
- **`develop`** - Integration branch for features
- **`feature/*`** - Feature branches (branch from `develop`, merge to `develop`)
- **`bugfix/*`** - Bug fix branches (branch from `develop`, merge to `develop`)
- **`hotfix/*`** - Critical production fixes (branch from `main`, merge to both `main` and `develop`)

### Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/SBOM-Converter.git`
3. Create a feature branch: `git checkout -b feature/my-new-feature develop`
4. **Set up Git hooks**: `./scripts/setup-hooks.sh` (runs `cargo fmt` before commits)
5. Make your changes and add tests
6. Run tests: `cargo test`
7. Run linter: `cargo clippy -- -D warnings`
8. Format code: `cargo fmt` (or let the pre-commit hook do it)
9. Commit changes with clear messages
10. Push to your fork: `git push origin feature/my-new-feature`
11. Open a Pull Request to the `develop` branch

**Pre-commit Hook:** The setup script installs a Git hook that automatically checks code formatting and runs clippy before each commit, ensuring code quality standards are maintained.

For detailed contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

### Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

Current version: **1.0.0**

See [CHANGELOG.md](CHANGELOG.md) for version history.

### Releases

Releases are automated via GitHub Actions:

1. Create a tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
2. Push the tag: `git push origin v1.0.0`
3. GitHub Actions builds and publishes binaries for:
   - Linux (x86_64)
   - macOS (x86_64, ARM64)
   - Windows (x86_64)

Download pre-built binaries from the [Releases page](https://github.com/stondo/SBOM-Converter/releases).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Acknowledgments

Built with Rust's powerful streaming capabilities using the Serde ecosystem.
