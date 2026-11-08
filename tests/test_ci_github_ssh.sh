#!/bin/bash
# ---------------------------------------------------------------------------
# CI E2E test: GitHub SSH key mode + challenge protocol — no act, no Docker.
# Calls verify_pow.py directly against the mock GitHub API server, which also
# plays the role of the attestation ledger (mints challenges solvable by
# tests/fake_scanner.py).  All configuration goes through the POW JSON.
#
# Requires: Python 3 with cryptography, ssh-keygen, curl
#
# Flow:
#   1. Generate a test Ed25519 SSH keypair
#   2. Set up a fresh repo with the v2 client configuration (.env POW='{...}')
#   3. Install hooks (POW_SSH_KEY_OVERRIDE pointing at the test key)
#   4. Start the mock GitHub API / ledger (test_mock_github_api.py)
#   5. Signed v2 commit, run verify_pow.py (v1 disallowed) → must PASS   (CHECK 1)
#   6. Bypass commit (--no-verify), run verify_pow.py → must FAIL          (CHECK 2)
#   7. Same valid commit, wrong hmac_key → INVALID                         (CHECK 3)
#   8. Mock API unreachable → INCONCLUSIVE, remote untouched               (CHECK 4)
# ---------------------------------------------------------------------------
set -euo pipefail

VENV_PYTHON="$HOME/.pow-hook/venv/bin/python"
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
HMAC_KEY="e2e-hmac-key"
API_URL="http://127.0.0.1:$MOCK_PORT"

cleanup() {
    set +euo pipefail
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
    cd "$SCRIPT_DIR" 2>/dev/null || true
    rm -rf "$TEST_DIR" 2>/dev/null || true
    echo "🧹 Cleaned up."
}
trap cleanup EXIT

echo "🔑 Generating test Ed25519 SSH keypair..."
KEY_PATH="$TEST_DIR/test_id_ed25519"
ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -q -C "e2e-ci"

echo "🌐 Starting mock GitHub API / ledger on port $MOCK_PORT..."
POW_HMAC_KEY="$HMAC_KEY" $PYTHON "$SCRIPT_DIR/test_mock_github_api.py" "$MOCK_PORT" "$KEY_PATH.pub" &
MOCK_PID=$!
for i in $(seq 1 20); do
    if curl -sf "$API_URL/users/test_user/keys" >/dev/null 2>&1; then
        echo "✅ Mock server ready."
        break
    fi
    sleep 0.3
done
kill -0 "$MOCK_PID" 2>/dev/null || { echo "❌ Mock server failed to start."; exit 1; }

echo "📦 Initialising test repository..."
cd "$TEST_DIR"
git init -q
git checkout -q -b main
git config user.name  "E2E Test"
git config user.email "e2e@example.com"

cp -r "$PRJ_ROOT"/hooks_templates .
cp -r "$PRJ_ROOT"/admin_templates .
cp "$PRJ_ROOT"/setup_hooks.py .
cp "$PRJ_ROOT"/.env.example .

# Client configuration: ONE variable, a JSON object (setup_hooks.py adds ssh_key to it).
PYTHON_ABS="$(command -v "$PYTHON" || echo "$PYTHON")"
cat > .env <<EOF
POW='{"github_pat_local":"e2e_pat","github_repo":"owner/repo","github_api_url":"$API_URL","corpus_cmd":"\"$PYTHON_ABS\" \"$SCRIPT_DIR/fake_scanner.py\" \"{corpus_dir}\"","challenge_timeout":30,"challenge_poll":1}'
EOF

git init -q --bare "$TEST_DIR/remote.git"
git remote add origin "$TEST_DIR/remote.git"

echo "🔧 Installing PoW hooks..."
export POW_SSH_KEY_OVERRIDE="$KEY_PATH"
export POW_HOOK_PYTHON="$PYTHON_ABS"
export PYTHONUTF8=1
$PYTHON setup_hooks.py
grep -q '"ssh_key"' .env || { echo "❌ setup_hooks.py did not write ssh_key into the POW JSON"; exit 1; }

echo "# e2e" > README.md
git add README.md
git commit -q --no-verify -m "chore: initial setup"
INITIAL_COMMIT=$(git rev-parse HEAD)
git push -q -u origin main

run_verify() {  # base head server-POW-json [extra env assignments...]
    local base="$1" head="$2" pow="$3"; shift 3
    cat > "$TEST_DIR/event.json" <<EOF
{"ref": "refs/heads/main", "before": "$base", "after": "$head", "repository": {"full_name": "owner/repo"}}
EOF
    env GITHUB_TOKEN=dummy_token GITHUB_REPOSITORY=owner/repo GITHUB_EVENT_NAME=push \
        GITHUB_EVENT_PATH="$TEST_DIR/event.json" GITHUB_REF=refs/heads/main \
        POW="$pow" "$@" $PYTHON admin_templates/github/scripts/verify_pow.py
}
SERVER_POW='{"enforce":"true","allow_v1":"false","github_api_url":"'"$API_URL"'","hmac_key":"'"$HMAC_KEY"'"}'

echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 1: Valid v2 commit — verify must PASS"
echo "═══════════════════════════════════════════════════"
echo "hello" > valid.txt
git add valid.txt
git commit -q -m "feat: valid signed commit"
SIGNED_COMMIT=$(git rev-parse HEAD)
git push -q origin main
TRAILER=$(git log -1 --format='%(trailers:key=PoW-Checks,valueonly)' | head -n1)
[ -n "$TRAILER" ] || { echo "❌ no trailer injected"; exit 1; }
VERSION=$($PYTHON -c "import base64,sys; print(base64.b64decode(sys.argv[1])[0])" "$TRAILER")
[ "$VERSION" = "2" ] || { echo "❌ expected a v2 trailer, got version $VERSION"; exit 1; }

set +e; run_verify "$INITIAL_COMMIT" "$SIGNED_COMMIT" "$SERVER_POW"; RC=$?; set -e
[ "$RC" -eq 0 ] && echo "✅ CHECK 1 PASSED" || { echo "❌ CHECK 1 FAILED (exit $RC)"; exit 1; }

echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 2: Bypass commit (--no-verify) — verify must FAIL"
echo "═══════════════════════════════════════════════════"
echo "bypass" > bypass.txt
git add bypass.txt
git commit -q --no-verify -m "chore: bypass hooks"
BYPASS_COMMIT=$(git rev-parse HEAD)
git push -q origin main
set +e; OUT=$(run_verify "$SIGNED_COMMIT" "$BYPASS_COMMIT" "$SERVER_POW" 2>&1); RC=$?; set -e
echo "$OUT" | tail -n 5
[ "$RC" -ne 0 ] && echo "$OUT" | grep -q "REJECTED" && echo "✅ CHECK 2 PASSED" || { echo "❌ CHECK 2 FAILED"; exit 1; }
[ "$(git --git-dir=remote.git rev-parse main)" = "$BYPASS_COMMIT" ] || { echo "❌ remote was rewritten on a policy failure"; exit 1; }

echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 3: Wrong hmac_key — receipt must be INVALID"
echo "═══════════════════════════════════════════════════"
WRONG_POW='{"enforce":"true","allow_v1":"false","github_api_url":"'"$API_URL"'","hmac_key":"wrong-key"}'
set +e; OUT=$(run_verify "$INITIAL_COMMIT" "$SIGNED_COMMIT" "$WRONG_POW" 2>&1); RC=$?; set -e
echo "$OUT" | tail -n 4
[ "$RC" -ne 0 ] && echo "$OUT" | grep -q "INVALID" && echo "✅ CHECK 3 PASSED" || { echo "❌ CHECK 3 FAILED"; exit 1; }

echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 4: Unreachable API — INCONCLUSIVE, no rewrite"
echo "═══════════════════════════════════════════════════"
DOWN_POW='{"enforce":"true","allow_v1":"false","github_api_url":"http://127.0.0.1:9","hmac_key":"'"$HMAC_KEY"'","auto_revert":"true"}'
set +e; OUT=$(run_verify "$INITIAL_COMMIT" "$SIGNED_COMMIT" "$DOWN_POW" 2>&1); RC=$?; set -e
echo "$OUT" | tail -n 4
[ "$RC" -ne 0 ] && echo "$OUT" | grep -q "INCONCLUSIVE" && echo "✅ CHECK 4 PASSED" || { echo "❌ CHECK 4 FAILED"; exit 1; }
[ "$(git --git-dir=remote.git rev-parse main)" = "$BYPASS_COMMIT" ] || { echo "❌ remote was rewritten on an inconclusive result"; exit 1; }

echo ""
echo "🎉 All CI GitHub SSH checks passed!"
exit 0
