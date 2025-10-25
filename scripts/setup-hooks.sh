#!/bin/sh
#
# Setup script for Git hooks
# Run this after cloning the repository to install pre-commit hooks
#

set -e

echo "Setting up Git hooks for sbom-converter..."

# Get the repository root directory
REPO_ROOT=$(git rev-parse --show-toplevel)

# Define hook content
cat > "$REPO_ROOT/.git/hooks/pre-commit" << 'EOF'
#!/bin/sh
#
# Pre-commit hook for Rust projects
# Runs cargo fmt and cargo clippy before allowing commit
#

set -e

echo "Running pre-commit checks..."

# Check if cargo fmt would make changes
echo "→ Checking code formatting with cargo fmt..."
if ! cargo fmt -- --check; then
    echo ""
    echo "❌ Code is not formatted correctly!"
    echo "   Run 'cargo fmt' to format your code before committing."
    exit 1
fi
echo "✓ Code formatting is correct"

# Run clippy for linting (only warn, don't fail)
echo "→ Running cargo clippy..."
if ! cargo clippy --all-targets --all-features -- -D warnings 2>&1 | grep -q "warning:"; then
    echo "✓ No clippy warnings"
else
    echo "⚠ Clippy found some warnings (not blocking commit)"
fi

echo ""
echo "✓ All pre-commit checks passed!"
exit 0
EOF

# Make the hook executable
chmod +x "$REPO_ROOT/.git/hooks/pre-commit"

echo "✓ Pre-commit hook installed successfully!"
echo ""
echo "The following checks will run before each commit:"
echo "  - cargo fmt --check (enforced)"
echo "  - cargo clippy (warnings only)"
echo ""
echo "To bypass the hook temporarily, use: git commit --no-verify"
