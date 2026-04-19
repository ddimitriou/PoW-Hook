#!/bin/bash
# ---------------------------------------------------------------------------
# Run the unit test suite inside a Docker container (Linux environment).
# Required because git hooks with Python shebangs only execute correctly on Linux.
# Usage: bash tests/run_tests_windows.sh
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRJ_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Convert project root to a Windows-style drive path (C:/...) for the Docker
# -v mount on Windows.  On Linux/macOS this is a no-op.
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    WIN_DIR="$(cygpath -w "$PRJ_ROOT" | sed 's|\\|/|g')"
else
    WIN_DIR="$PRJ_ROOT"
fi

echo "🐳 Running unit tests inside Docker (ubuntu:22.04)..."
MSYS_NO_PATHCONV=1 docker run --rm \
    -v "${WIN_DIR}://work" \
    -w //work \
    --network host \
    ubuntu:22.04 bash -c '
        set -e
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq && apt-get install -y -qq python3 python3-pip git openssh-client 2>/dev/null
        pip3 install -q cryptography pytest 2>/dev/null

        git config --global init.defaultBranch master
        git config --global user.email "ci@test.com"
        git config --global user.name  "CI"

        python3 -m pytest tests/test_hooks.py -v --tb=short 2>&1
    '
