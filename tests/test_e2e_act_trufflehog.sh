#!/bin/bash
# ---------------------------------------------------------------------------
# E2E test: Trufflehog local scan + act server-side bypass rejection
#
# Requires: act (in PATH), Docker running, Python 3 with cryptography,
#           trufflesecurity/trufflehog Docker image available
#
# Flow:
#   1. Generate a test Ed25519 SSH keypair
#   2. Set up a fresh repo in github key_source mode
#   3. Install hooks with POW_CHECKS_CMD pointing at trufflehog
#   4. Stage a file containing a fake GitHub PAT
#   5. Attempt a normal commit → trufflehog must BLOCK it        (CHECK 1)
#   6. Bypass with --no-verify, then run act push → must FAIL
#      because the bypass commit has no PoW trailers              (CHECK 2)
# ---------------------------------------------------------------------------
set -euo pipefail

# Use the project's virtual environment if available, otherwise fallback to system python
VENV_PYTHON="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.venv/bin/python"
if [ -f "$VENV_PYTHON" ]; then
    PYTHON="$VENV_PYTHON"
else
    PYTHON="${PYTHON:-python3}"
fi
ACT="${ACT:-act}"

echo "🔍 Checking prerequisites..."
command -v "$ACT" >/dev/null 2>&1 || { echo "❌ 'act' not found. Install from https://github.com/nektos/act"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "❌ Docker not found."; exit 1; }
$PYTHON -c "import cryptography" 2>/dev/null || { echo "❌ cryptography package not installed for $PYTHON"; exit 1; }
docker image inspect trufflesecurity/trufflehog:latest >/dev/null 2>&1 \
    || docker pull trufflesecurity/trufflehog:latest \
    || { echo "❌ Could not pull trufflesecurity/trufflehog:latest"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRJ_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="$(mktemp -d)"

cleanup() {
    set +euo pipefail
    cd "$SCRIPT_DIR" 2>/dev/null || true
    rm -rf "$TEST_DIR" 2>/dev/null || true
    echo "🧹 Cleaned up."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Generate test Ed25519 keypair
# ---------------------------------------------------------------------------
echo "🔑 Generating test Ed25519 SSH keypair..."
KEY_PATH="$TEST_DIR/test_id_ed25519"
ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -q -C "e2e-trufflehog"
echo "✅ Keypair at $KEY_PATH"

# ---------------------------------------------------------------------------
# 2. Set up fresh git repo with GitHub SSH mode
# ---------------------------------------------------------------------------
echo "📦 Initialising test repository..."
cd "$TEST_DIR"
cp -r "$PRJ_ROOT"/hooks_templates .
cp -r "$PRJ_ROOT"/admin_templates .
cp "$PRJ_ROOT"/setup_hooks.py .
cp "$PRJ_ROOT"/.env.example .

git init
git config user.name  "E2E Test"
git config user.email "e2e@example.com"

cat > .pow-config.json <<'EOF'
{"key_source": "github"}
EOF

# POW_CHECKS_CMD: trufflehog scans the working tree for secrets.
# --no-verification: pattern-match only (no network calls to verify tokens).
# --fail: exit non-zero when detections are found.
cat > .env <<'EOF'
POW_CHECKS_CMD=docker run --rm -v "$(git rev-parse --show-toplevel)":/pwd trufflesecurity/trufflehog:latest filesystem /pwd --no-verification --fail
EOF

# ---------------------------------------------------------------------------
# 3. Install hooks
# ---------------------------------------------------------------------------
echo "🔧 Installing PoW hooks..."
# Convert key path to Windows-native format if on Windows
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    KEY_PATH_WIN=$(cygpath -w "$KEY_PATH" | tr '\\' '/')
else
    KEY_PATH_WIN="$KEY_PATH"
fi
export POW_SSH_KEY_OVERRIDE="$KEY_PATH_WIN"
export PYTHONUTF8=1
echo "   POW_SSH_KEY_OVERRIDE=$POW_SSH_KEY_OVERRIDE"
$PYTHON setup_hooks.py

# Scaffold .github for the act workflow
mkdir -p .github/scripts .github/workflows
cp admin_templates/github/scripts/verify_pow.py .github/scripts/

cat > .github/workflows/pow-validator.yml << 'WORKFLOW'
name: Proof of Work Validator
on:
  push:
    branches: [main]
jobs:
  verify-pow:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Install deps and verify
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          pip install cryptography -q --break-system-packages
          python3 .github/scripts/verify_pow.py
WORKFLOW

# Commit baseline (no PoW check on this one — it's the admin setup commit)
git add .pow-config.json .github
git commit --no-verify -m "chore: add pow config"
INITIAL_COMMIT=$(git rev-parse HEAD)

# ---------------------------------------------------------------------------
# CHECK 1: Trufflehog blocks secret commit locally
# ---------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 1: Trufflehog blocks secret locally"
echo "═══════════════════════════════════════════════════"

# GitHub classic PAT format: ghp_ + exactly 36 alphanumeric chars.
# Trufflehog detects this by regex pattern (--no-verification skips
# the live API call, so any string matching the pattern is flagged).
echo "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" > malicious_secret.txt
git add malicious_secret.txt

set +e
git commit -m "feat: add credential"
COMMIT_CODE=$?
set -e

if [ "$COMMIT_CODE" -ne 0 ]; then
    echo "✅ CHECK 1 PASSED: Trufflehog blocked the secret commit."
else
    echo "❌ CHECK 1 FAILED: Secret commit was not blocked by trufflehog."
    exit 1
fi

# ---------------------------------------------------------------------------
# CHECK 2: Bypass commit → act push must FAIL (missing PoW trailers)
# ---------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 2: Bypass commit (--no-verify) → must FAIL"
echo "═══════════════════════════════════════════════════"

git commit --no-verify -m "chore: bypass hooks and inject secret"
BYPASS_COMMIT=$(git rev-parse HEAD)

cat > .secrets <<'EOF'
GITHUB_TOKEN=dummy_token
EOF

cat > "$TEST_DIR/pow_trufflehog_event.json" <<EOF
{
  "ref": "refs/heads/main",
  "before": "$INITIAL_COMMIT",
  "after":  "$BYPASS_COMMIT",
  "repository": {"full_name": "owner/repo"},
  "pusher": {"name": "test_user"}
}
EOF

set +e
"$ACT" push \
    --eventpath "$TEST_DIR/pow_trufflehog_event.json" \
    --secret-file .secrets \
    --network host \
    -P ubuntu-latest=ghcr.io/catthehacker/ubuntu:act-latest \
    2>&1
ACT_EXIT=$?
set -e

if [ "$ACT_EXIT" -ne 0 ]; then
    echo "✅ CHECK 2 PASSED: act correctly rejected the bypass commit."
else
    echo "❌ CHECK 2 FAILED: act accepted a commit that bypassed the hooks."
    exit 1
fi

echo ""
echo "🎉 All Trufflehog E2E checks passed!"
exit 0
