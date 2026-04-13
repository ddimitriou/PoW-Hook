#!/bin/bash
# ---------------------------------------------------------------------------
# CI E2E test: Trufflehog secret scan — no act required.
# Exercises the pre-commit hook directly and then calls verify_pow.py directly
# to confirm that bypass commits are rejected server-side.
# For full local simulation with act, use test_e2e_act_trufflehog.sh.
#
# Requires: Python 3 with cryptography, Docker (for the trufflehog scan),
#           ssh-keygen, curl
#
# Flow:
#   1. Generate a test Ed25519 SSH keypair
#   2. Set up a fresh repo with POW_CHECKS_CMD pointing at trufflehog
#   3. Install hooks
#   4. Stage a file containing a fake GitHub PAT
#   5. Attempt a normal commit → trufflehog must BLOCK it        (CHECK 1)
#   6. Bypass with --no-verify, run verify_pow.py directly →
#      must FAIL because the bypass commit has no PoW trailers   (CHECK 2)
# ---------------------------------------------------------------------------
set -euo pipefail

PYTHON="${PYTHON:-python3}"

echo "🔍 Checking prerequisites..."
command -v ssh-keygen >/dev/null 2>&1 || { echo "❌ ssh-keygen not found."; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "❌ Docker not found."; exit 1; }
$PYTHON -c "import cryptography" 2>/dev/null || { echo "❌ cryptography not installed for $PYTHON"; exit 1; }
docker image inspect trufflesecurity/trufflehog:latest >/dev/null 2>&1 \
    || docker pull trufflesecurity/trufflehog:latest \
    || { echo "❌ Could not pull trufflesecurity/trufflehog:latest"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -q -C "e2e-ci-trufflehog"
echo "✅ Keypair at $KEY_PATH"

# ---------------------------------------------------------------------------
# 2. Set up fresh git repo
# ---------------------------------------------------------------------------
echo "📦 Initialising test repository..."
cd "$TEST_DIR"
git init -b main
git config user.name  "E2E Test"
git config user.email "e2e@example.com"

cp -r "$SCRIPT_DIR"/hooks_templates .
cp -r "$SCRIPT_DIR"/admin_templates .
cp "$SCRIPT_DIR"/setup_hooks.py .
cp "$SCRIPT_DIR"/.env.example .

cat > .pow-config.json <<'EOF'
{"key_source": "github"}
EOF

# POW_CHECKS_CMD: trufflehog scans the working tree for secrets.
# --no-verification: pattern-match only (no live API calls).
# --fail: exit non-zero when detections are found.
cat > .env <<'EOF'
POW_CHECKS_CMD=docker run --rm -v "$(git rev-parse --show-toplevel)":/pwd trufflesecurity/trufflehog:latest filesystem /pwd --no-verification --fail
EOF

# Set up a bare remote so verify_pow.py's cleanup-push completes cleanly
git init --bare "$TEST_DIR/remote.git"
git remote add origin "$TEST_DIR/remote.git"

# ---------------------------------------------------------------------------
# 3. Install hooks
# ---------------------------------------------------------------------------
echo "🔧 Installing PoW hooks..."
export POW_SSH_KEY_OVERRIDE="$KEY_PATH"
export PYTHONUTF8=1
$PYTHON setup_hooks.py

# Baseline commit — admin setup, no PoW check needed
git add .pow-config.json
git commit --no-verify -m "chore: add pow config"
INITIAL_COMMIT=$(git rev-parse HEAD)
git push -u origin main --quiet

# ---------------------------------------------------------------------------
# CHECK 1: Trufflehog blocks secret commit locally
# ---------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 1: Trufflehog blocks secret commit locally"
echo "═══════════════════════════════════════════════════"

# GitHub classic PAT format: ghp_ + exactly 36 alphanumeric chars.
# Trufflehog detects this by regex with --no-verification.
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
# CHECK 2: Bypass commit → verify_pow.py must exit non-zero (missing trailers)
# ---------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 2: Bypass commit (--no-verify) — verify must FAIL"
echo "═══════════════════════════════════════════════════"

git commit --no-verify -m "chore: bypass hooks and inject secret"
BYPASS_COMMIT=$(git rev-parse HEAD)
git push origin main --quiet

cat > "$TEST_DIR/bypass_event.json" <<EOF
{
  "ref": "refs/heads/main",
  "before": "$INITIAL_COMMIT",
  "after":  "$BYPASS_COMMIT",
  "repository": {"full_name": "owner/repo"},
  "pusher": {"name": "test_user"}
}
EOF

set +e
GITHUB_TOKEN=dummy_token \
GITHUB_REPOSITORY=owner/repo \
GITHUB_EVENT_NAME=push \
GITHUB_EVENT_PATH="$TEST_DIR/bypass_event.json" \
GITHUB_REF=refs/heads/main \
$PYTHON admin_templates/github/scripts/verify_pow.py 2>&1
CHECK2_EXIT=$?
set -e

if [ "$CHECK2_EXIT" -ne 0 ]; then
    echo "✅ CHECK 2 PASSED: verify_pow.py correctly rejected the bypass commit."
else
    echo "❌ CHECK 2 FAILED: verify_pow.py accepted a commit that bypassed the hooks."
    exit 1
fi

echo ""
echo "🎉 All CI Trufflehog checks passed!"
exit 0
