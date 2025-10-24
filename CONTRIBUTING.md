# Contributing to SBOM Converter

Thank you for your interest in contributing to the SBOM Converter project! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Branching Strategy](#branching-strategy)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

This project adheres to a code of conduct that all contributors are expected to follow. Please be respectful and professional in all interactions.

## Getting Started

### Prerequisites

- Rust 1.85+ (2024 edition)
- Git
- A GitHub account

### Setting Up Your Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:

   ```bash
   git clone https://github.com/YOUR-USERNAME/SBOM-Converter.git
   cd SBOM-Converter
   ```

3. Add the upstream repository:

   ```bash
   git remote add upstream https://github.com/stondo/SBOM-Converter.git
   ```

4. Build the project:

   ```bash
   cargo build
   ```

5. Run tests to verify everything works:

   ```bash
   cargo test
   ```

## Development Workflow

### Syncing Your Fork

Before starting work, sync your fork with upstream:

```bash
git checkout develop
git fetch upstream
git merge upstream/develop
git push origin develop
```

### Making Changes

1. Create a feature branch from `develop`
2. Make your changes
3. Test your changes thoroughly
4. Commit with clear, descriptive messages
5. Push to your fork
6. Open a Pull Request

## Daily Development Workflow

### Starting a New Feature

```bash
# Always start from develop
git checkout develop
git pull upstream develop

# Create feature branch
git checkout -b feature/my-awesome-feature

# Make changes, commit frequently
git add .
git commit -m "feat(component): add new feature"

# Push to your fork
git push origin feature/my-awesome-feature
```

### Working on a Bug Fix

```bash
git checkout develop
git pull upstream develop
git checkout -b bugfix/fix-issue-description

# Fix the bug, add test
git add .
git commit -m "fix(validation): handle null values correctly"

git push origin bugfix/fix-issue-description
# Open PR to upstream develop
```

### Running Tests Locally

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run integration tests
cargo test --test integration_test
```

### Code Quality Checks

Run these before pushing:

```bash
# Check formatting
cargo fmt --check

# Apply formatting
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Run all checks together
cargo test && cargo clippy -- -D warnings && cargo fmt --check
```

### Checking CI Status

After pushing:

1. **View all workflow runs**: <https://github.com/stondo/SBOM-Converter/actions>
2. **View your branch**: Look for your branch name in the Actions tab
3. **Check specific workflows**:
   - CI workflow (tests, lint, build)
   - Ensure all jobs pass before requesting review

### Updating Your Branch

If your branch becomes outdated:

```bash
# Sync with upstream develop
git checkout develop
git pull upstream develop

# Update your feature branch
git checkout feature/my-feature
git merge develop

# Or use rebase for cleaner history
git rebase develop

# Force push if you rebased (use with caution)
git push origin feature/my-feature --force-with-lease
```

## Branching Strategy

We follow a **Git Flow** branching model with the following branches:

### Main Branches

- **`main`** - Production-ready code. Only accepts merges from `develop` or hotfix branches.
  - Tagged with version numbers (e.g., `v1.0.0`)
  - All commits must be stable and tested
  - Protected branch requiring PR reviews

- **`develop`** - Integration branch for features.
  - Reflects the latest delivered development changes
  - All feature branches merge here first
  - Must pass all CI checks before merging to `main`

### Supporting Branches

#### Feature Branches

- **Naming**: `feature/<feature-name>`
- **Branch from**: `develop`
- **Merge into**: `develop`
- **Purpose**: Develop new features or enhancements

Examples:

- `feature/parallel-processing`
- `feature/xml-support`
- `feature/compression-support`

**Workflow**:

```bash
# Create feature branch
git checkout develop
git pull upstream develop
git checkout -b feature/my-new-feature

# Work on your feature...
git add .
git commit -m "Add my new feature"

# Push to your fork
git push origin feature/my-new-feature

# Open PR to upstream develop branch
```

#### Bugfix Branches

- **Naming**: `bugfix/<issue-number>-<description>` or `bugfix/<description>`
- **Branch from**: `develop`
- **Merge into**: `develop`
- **Purpose**: Fix bugs in the development branch

Example: `bugfix/123-fix-validation-crash`

#### Hotfix Branches

- **Naming**: `hotfix/<version>`
- **Branch from**: `main`
- **Merge into**: `main` and `develop`
- **Purpose**: Quick fixes for production issues

Example: `hotfix/1.0.1`

**Workflow**:

```bash
# Create hotfix branch
git checkout main
git pull upstream main
git checkout -b hotfix/1.0.1

# Fix the issue
git add .
git commit -m "Fix critical bug in validation"

# Push and create PRs to both main and develop
git push origin hotfix/1.0.1
```

#### Release Branches

- **Naming**: `release/<version>`
- **Branch from**: `develop`
- **Merge into**: `main` and `develop`
- **Purpose**: Prepare a new production release

Example: `release/1.1.0`

**Workflow**:

```bash
# Create release branch
git checkout develop
git pull upstream develop
git checkout -b release/1.1.0

# Update version, changelog, docs
# Test thoroughly
# Merge to main via PR (creates tag)
# Merge back to develop
```

## Pull Request Process

### Before Submitting

1. **Update your branch** with the latest changes from `develop`:

   ```bash
   git fetch upstream
   git rebase upstream/develop
   ```

2. **Run all tests**:

   ```bash
   cargo test
   cargo test --test integration_test
   ```

3. **Check formatting**:

   ```bash
   cargo fmt --check
   ```

4. **Run linter**:

   ```bash
   cargo clippy -- -D warnings
   ```

5. **Update documentation** if needed

6. **Update CHANGELOG.md** following [Keep a Changelog](https://keepachangelog.com/) format

### Submitting a PR

1. Push your changes to your fork
2. Go to the [SBOM Converter repository](https://github.com/stondo/SBOM-Converter)
3. Click "New Pull Request"
4. Select your fork and branch
5. Target branch should be `develop` (unless it's a hotfix)
6. Fill out the PR template with:
   - Clear description of changes
   - Related issue numbers (if any)
   - Testing performed
   - Screenshots (if UI changes)
7. Submit the PR

### PR Review Process

- At least one maintainer review is required
- All CI checks must pass
- Changes may be requested
- Once approved, a maintainer will merge your PR

## Coding Standards

### Rust Style Guide

- Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/)
- Use `cargo fmt` for consistent formatting
- Use `cargo clippy` to catch common mistakes
- Write idiomatic Rust code

### Code Quality

- **Keep functions small and focused** - Each function should do one thing well
- **Write self-documenting code** - Use clear variable and function names
- **Add comments for complex logic** - Explain the "why", not the "what"
- **Avoid unwrap()** - Use proper error handling with `Result` and `?`
- **Handle all error cases** - Never silently ignore errors

### Documentation

- Add doc comments (`///`) for public APIs
- Include examples in doc comments when helpful
- Update README.md for user-facing changes
- Update CHANGELOG.md for all changes

## Testing

### Test Requirements

All contributions must include appropriate tests:

1. **Unit Tests** - Test individual functions and modules
2. **Integration Tests** - Test end-to-end workflows
3. **Documentation Tests** - Ensure doc examples work

### Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run integration tests
cargo test --test integration_test
```

### Test Coverage

- Aim for high test coverage (>80%)
- Test both success and error cases
- Test edge cases and boundary conditions
- Include tests for bug fixes

### Performance Testing

For performance-critical changes:

1. Benchmark before and after changes
2. Test with large files (multi-GB)
3. Monitor memory usage
4. Document performance impact in PR

## Documentation

### When to Update Documentation

Update documentation when you:

- Add new features
- Change CLI arguments or behavior
- Modify configuration options
- Fix bugs that affect documented behavior
- Add or change dependencies

### Documentation Files

- **README.md** - User-facing documentation
- **CONTRIBUTING.md** - This file
- **CHANGELOG.md** - Record of changes
- **Code comments** - Inline documentation
- **Doc comments** - API documentation

### Style Guidelines

- Use clear, concise language
- Include code examples
- Use proper Markdown formatting
- Keep line length reasonable (~80-100 chars)
- Use headings hierarchically

## Commit Message Guidelines

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, etc.)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks

### Examples

```
feat(validation): add JSON-LD structural validation

Implement structural validation for SPDX JSON-LD format including
@context and @graph validation with optional skip flag.

Closes #42
```

```
fix(converter): handle null values in SPDX relationships

Add null checks to prevent panics when processing malformed
SPDX files with null relationship fields.

Fixes #58
```

## Release Process

Releases are managed by maintainers:

1. Create release branch from `develop`
2. Update version in `Cargo.toml`
3. Update `CHANGELOG.md`
4. Create PR to `main`
5. After merge, tag release (e.g., `v1.0.0`)
6. GitHub Actions builds and publishes binaries
7. Merge release branch back to `develop`

## Questions?

If you have questions or need help:

- Open an issue for discussion
- Check existing issues and PRs
- Review the README.md

Thank you for contributing! 🎉
