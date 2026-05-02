#!/bin/bash
# ---------------------------------------------------------------------------
# CI E2E test: GitHub SSH key mode — no act required.
# Calls verify_pow.py directly instead of simulating a push event through act.
# For full local simulation with act, use test_e2e_github_ssh.sh.
#
# Requires: Python 3 with cryptography, ssh-keygen, curl
#
# Flow:
#   1. Generate a test Ed25519 SSH keypair
#   2. Set up a fresh repo in github key_source mode
#   3. Install hooks (POW_SSH_KEY_OVERRIDE pointing at the test key)
#   4. Start the mock GitHub API server (test_mock_github_api.py)
#   5. Make a validly-signed commit, run verify_pow.py → must PASS  (CHECK 1)
#   6. Make a bypass commit (--no-verify), run verify_pow.py → must FAIL (CHECK 2)
# ---------------------------------------------------------------------------
set -euo pipefail

# Use the project's virtual environment if available, otherwise fallback to system python
VENV_PYTHON="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.venv/bin/python"
if [ -f "$VENV_PYTHON" ]; then
    PYTHON="$VENV_PYTHON"
else
    PYTHON="${PYTHON:-python3}"
fi

echo "🔍 Checking prerequisites..."
command -v ssh-keygen >/dev/null 2>&1 || { echo "❌ ssh-keygen not found."; exit 1; }
$PYTHON -c "import cryptography" 2>/dev/null || { echo "❌ cryptography not installed for $PYTHON"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRJ_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="$(mktemp -d)"
MOCK_PORT=$($PYTHON -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
MOCK_PID=""

cleanup() {
    set +euo pipefail
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
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
ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -q -C "e2e-ci"
echo "✅ Keypair at $KEY_PATH"

# ---------------------------------------------------------------------------
# 2. Set up fresh git repo
# ---------------------------------------------------------------------------
echo "📦 Initialising test repository..."
cd "$TEST_DIR"
git init -b main
git config user.name  "E2E Test"
git config user.email "e2e@example.com"

cp -r "$PRJ_ROOT"/hooks_templates .
cp -r "$PRJ_ROOT"/admin_templates .
cp "$PRJ_ROOT"/setup_hooks.py .
cp "$PRJ_ROOT"/.env.example .

cat > .pow-config.json <<'EOF'
{"key_source": "github"}
EOF

cat > .env <<'EOF'
# Empty env — no attestation dispatch in CI test
EOF

# Set up a bare remote so verify_pow.py's cleanup-push (on rejection) completes cleanly
git init --bare "$TEST_DIR/remote.git"
git remote add origin "$TEST_DIR/remote.git"

# ---------------------------------------------------------------------------
# 3. Install hooks
# ---------------------------------------------------------------------------
echo "🔧 Installing PoW hooks..."
export POW_SSH_KEY_OVERRIDE="$KEY_PATH"
export PYTHONUTF8=1
$PYTHON setup_hooks.py

# Baseline commit (not signed — hooks not yet triggered)
git add .pow-config.json
git commit --no-verify -m "chore: add pow config"
INITIAL_COMMIT=$(git rev-parse HEAD)
git push -u origin main --quiet

# ---------------------------------------------------------------------------
# 4. Start mock GitHub API server
# ---------------------------------------------------------------------------
echo "🌐 Starting mock GitHub API server on port $MOCK_PORT..."
$PYTHON "$SCRIPT_DIR/test_mock_github_api.py" $MOCK_PORT "$TEST_DIR/test_id_ed25519.pub" &
MOCK_PID=$!

for i in $(seq 1 20); do
    if curl -sf "http://127.0.0.1:$MOCK_PORT/users/test_user/keys" >/dev/null 2>&1; then
        echo "✅ Mock server ready."
        break
    fi
    sleep 0.3
done
if ! kill -0 "$MOCK_PID" 2>/dev/null; then
    echo "❌ Mock server failed to start. Aborting."
    exit 1
fi

# ---------------------------------------------------------------------------
# CHECK 1: Valid signed commit → verify_pow.py must exit 0
# ---------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 1: Valid signed commit — verify must PASS"
echo "═══════════════════════════════════════════════════"

echo "hello" > valid.txt
git add valid.txt
git commit -m "feat: valid signed commit"
SIGNED_COMMIT=$(git rev-parse HEAD)
git push origin main --quiet

cat > "$TEST_DIR/push_event.json" <<EOF
{
  "ref": "refs/heads/main",
  "before": "$INITIAL_COMMIT",
  "after":  "$SIGNED_COMMIT",
  "repository": {"full_name": "owner/repo"},
  "pusher": {"name": "test_user"}
}
EOF

set +e
GITHUB_TOKEN=dummy_token \
GITHUB_REPOSITORY=owner/repo \
GITHUB_EVENT_NAME=push \
GITHUB_EVENT_PATH="$TEST_DIR/push_event.json" \
GITHUB_REF=refs/heads/main \
POW_ENFORCE=true \
POW_GITHUB_API_URL=http://127.0.0.1:$MOCK_PORT \
$PYTHON admin_templates/github/scripts/verify_pow.py
CHECK1_EXIT=$?
set -e

if [ "$CHECK1_EXIT" -eq 0 ]; then
    echo "✅ CHECK 1 PASSED: verify_pow.py accepted the valid signed commit."
else
    echo "❌ CHECK 1 FAILED: verify_pow.py rejected a valid signed commit (exit $CHECK1_EXIT)."
    exit 1
fi

# ---------------------------------------------------------------------------
# CHECK 2: Bypass commit → verify_pow.py must exit non-zero
# ---------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 2: Bypass commit (--no-verify) — verify must FAIL"
echo "═══════════════════════════════════════════════════"

echo "bypass" > bypass.txt
git add bypass.txt
git commit --no-verify -m "chore: bypass hooks"
BYPASS_COMMIT=$(git rev-parse HEAD)
git push origin main --quiet

cat > "$TEST_DIR/bypass_event.json" <<EOF
{
  "ref": "refs/heads/main",
  "before": "$SIGNED_COMMIT",
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
POW_ENFORCE=true \
POW_GITHUB_API_URL=http://127.0.0.1:$MOCK_PORT \
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
echo "🎉 All CI GitHub SSH checks passed!"
exit 0
