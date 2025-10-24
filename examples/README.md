# Example SBOM Files

This directory is for small, sanitized example SBOM files that can be safely committed to the repository.

## Purpose

Use this directory for:

- Small example files for documentation
- Sample files for integration tests (if needed)
- Demonstration files for README examples
- Template files for users

## Guidelines

✅ **DO include:**

- Small files (< 100KB recommended)
- Sanitized/anonymized data
- Generic example data
- Files that demonstrate specific features

❌ **DO NOT include:**

- Real project SBOMs with sensitive information
- Large files (> 100KB)
- Files with proprietary information
- Test output files (use `test-data/` instead)

## Current Examples

Currently empty. Add example files here as needed for documentation or testing purposes.

## Note

Files matching patterns `*.spdx.json`, `*.cdx.json`, and `*.vex.json` in this directory are gitignored by default for safety. To commit an example file, you'll need to force-add it:

```bash
git add -f examples/sample-bom.cdx.json
```

This ensures accidental commits of sensitive files are prevented.
