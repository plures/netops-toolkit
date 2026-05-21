#!/usr/bin/env bash
# Run the full integration test suite for netops-toolkit.
# No external services, Docker, or special setup required.
# Prerequisites: Python 3.9+, pip install -e ".[dev,tui]"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

echo "═══════════════════════════════════════════════════════════"
echo " netops-toolkit Integration Test Suite"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Check dependencies
python -c "import netmiko, paramiko, textual" 2>/dev/null || {
    echo "❌ Missing dependencies. Run: pip install -e '.[dev,tui]'"
    exit 1
}

echo "✅ Dependencies OK"
echo ""

# Run integration tests (scan pipeline + TUI)
echo "── Scan Pipeline Tests (mock SSH servers) ──────────────────"
python -m pytest tests/test_integration_scan.py -v --no-cov --tb=short
echo ""

echo "── TUI Integration Tests ──────────────────────────────────"
python -m pytest tests/test_integration_tui.py -v --no-cov --tb=short
echo ""

echo "═══════════════════════════════════════════════════════════"
echo " ✅ All integration tests passed"
echo "═══════════════════════════════════════════════════════════"
