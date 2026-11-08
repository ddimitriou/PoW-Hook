#!/bin/bash
# ---------------------------------------------------------------------------
# Run the unit test suite inside a Docker container (Linux environment).
# Required because git hooks with Python shebangs only execute correctly on Linux.
# Builds tests/Dockerfile.test once (cached) and mounts the project read-write.
# Usage: bash tests/run_tests_windows.sh [extra pytest args]
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRJ_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Convert project root to a Windows-style drive path (C:/...) for the Docker
# -v mount on Windows.  On Linux/macOS this is a no-op.
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    WIN_DIR="$(cygpath -m "$PRJ_ROOT")"
else
    WIN_DIR="$PRJ_ROOT"
fi

echo "🐳 Building test image (ubuntu:22.04 + python3 + cryptography + pytest)..."
docker build -q -f "$SCRIPT_DIR/Dockerfile.test" -t pow-hook-tests "$PRJ_ROOT" >/dev/null

echo "🐳 Running unit tests inside Docker..."
MSYS_NO_PATHCONV=1 docker run --rm \
    -v "${WIN_DIR}://work" \
    -w //work \
    pow-hook-tests \
    python3 -m pytest tests/test_hooks.py -v --tb=short -p no:cacheprovider "$@"
