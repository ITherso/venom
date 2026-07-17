#!/bin/bash
# Generate VENOM project metrics

echo "=== VENOM Metrics Generation ==="
echo ""

# Source code lines
echo "📊 Source Code Metrics:"
SCANNER_LINES=$(find crates/venom-scanner/src -name "*.rs" -not -path "*/tests/*" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')
TEST_LINES=$(find crates/venom-scanner/tests -name "*.rs" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')
TOTAL_LINES=$((SCANNER_LINES + TEST_LINES))

echo "  Scanner Source: $SCANNER_LINES lines"
echo "  Test Code: $TEST_LINES lines"
echo "  Total: $TOTAL_LINES lines"
echo ""

# Module count
echo "📦 Module Metrics:"
SOURCE_FILES=$(find crates/venom-scanner/src -name "*.rs" -not -path "*/tests/*" | wc -l)
TEST_FILES=$(find crates/venom-scanner/tests -name "*.rs" | wc -l)

echo "  Source modules: $SOURCE_FILES"
echo "  Test files: $TEST_FILES"
echo ""

# Git metrics
echo "📈 Repository Metrics:"
COMMITS=$(git log --oneline | wc -l)
BRANCHES=$(git branch | wc -l)

echo "  Total commits: $COMMITS"
echo "  Branches: $BRANCHES"
echo ""

# Dependencies
echo "📚 Dependencies:"
DEPS=$(grep -A 50 "^\[dependencies\]" crates/venom-scanner/Cargo.toml | grep "^[a-z]" | wc -l)
echo "  Direct dependencies: $DEPS"
echo ""

# Output for README
echo "=== Values for README ==="
echo ""
echo "Lines of Code: ~$TOTAL_LINES Rust"
echo "Source: ~$SCANNER_LINES lines (scanner)"
echo "Tests: ~$TEST_LINES lines (test suite)"
echo "Modules: $SOURCE_FILES core modules"
echo "Git Commits: $COMMITS (pushed)"
echo ""

# Generate markdown table
echo "=== Markdown Table ==="
echo ""
echo "| Metric | Value |"
echo "|--------|-------|"
echo "| Total Lines | ~$TOTAL_LINES |"
echo "| Scanner Source | ~$SCANNER_LINES |"
echo "| Test Code | ~$TEST_LINES |"
echo "| Source Modules | $SOURCE_FILES |"
echo "| Test Files | $TEST_FILES |"
echo "| Git Commits | $COMMITS |"
echo "| Status | ALPHA |"
