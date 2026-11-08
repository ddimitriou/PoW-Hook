#!/bin/bash
# ---------------------------------------------------------------------------
# CI E2E test: real trufflehog (pinned) — local scan, challenge minting
# determinism, server-side bypass rejection and the nightly sweep.
# All configuration goes through the POW JSON.
#
# Requires: Python 3 with cryptography, Docker, ssh-keygen
#
# Flow:
#   1. Generate a test Ed25519 SSH keypair, set up a repo with checks_cmd = trufflehog
#   2. Stage a file containing a (random, high-entropy) fake GitHub PAT
#   3. Normal commit → trufflehog must BLOCK it                                   (CHECK 1)
#   4. Bypass with --no-verify, run verify_pow.py → must FAIL (missing trailer)   (CHECK 2)
#   5. Mint a real challenge with mint_challenge.py, scan the corpus the way the
#      client does, recompute the receipt → HMAC tag must match                   (CHECK 3)
#   6. trufflehog git scan of the repo + sweep_audit.py → bypass commit must be
#      classified LEAK_HONEST and the run must exit 1                             (CHECK 4)
# ---------------------------------------------------------------------------
set -euo pipefail

IMAGE="trufflesecurity/trufflehog:3.99.8"
# JSON-escaped checks_cmd (the \" become plain quotes once the POW JSON is parsed).
TRUFFLEHOG_CMD='docker run --rm -v \"$(git rev-parse --show-toplevel)\":/pwd '"$IMAGE"' filesystem /pwd --no-verification --fail'

VENV_PYTHON="$HOME/.pow-hook/venv/bin/python"
if [ -f "$VENV_PYTHON" ]; then
    PYTHON="$VENV_PYTHON"
else
    PYTHON="${PYTHON:-python3}"
fi

echo "🔍 Checking prerequisites..."
command -v ssh-keygen >/dev/null 2>&1 || { echo "❌ ssh-keygen not found."; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "❌ Docker not found."; exit 1; }
$PYTHON -c "import cryptography" 2>/dev/null || { echo "❌ cryptography not installed for $PYTHON"; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE" || { echo "❌ Could not pull $IMAGE"; exit 1; }

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

echo "🔑 Generating test Ed25519 SSH keypair..."
KEY_PATH="$TEST_DIR/test_id_ed25519"
ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -q -C "e2e-ci-trufflehog"

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
cat > .env <<EOF
POW='{"checks_cmd":"$TRUFFLEHOG_CMD"}'
EOF

git init -q --bare "$TEST_DIR/remote.git"
git remote add origin "$TEST_DIR/remote.git"

echo "🔧 Installing PoW hooks..."
export POW_SSH_KEY_OVERRIDE="$KEY_PATH"
export POW_HOOK_PYTHON="$(command -v "$PYTHON" || echo "$PYTHON")"
export PYTHONUTF8=1
$PYTHON setup_hooks.py

echo "# e2e" > README.md
git add README.md
git commit -q --no-verify -m "chore: initial setup"
INITIAL_COMMIT=$(git rev-parse HEAD)
git push -q -u origin main

# Random high-entropy token: trufflehog 3.99.x filters obviously sequential /
# low-entropy strings such as ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij.
FAKE_PAT="ghp_$($PYTHON -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(36)))")"

echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 1: Trufflehog blocks secret commit locally"
echo "═══════════════════════════════════════════════════"
echo "$FAKE_PAT" > malicious_secret.txt
git add malicious_secret.txt
set +e; git commit -q -m "feat: add credential"; COMMIT_CODE=$?; set -e
[ "$COMMIT_CODE" -ne 0 ] && echo "✅ CHECK 1 PASSED: Trufflehog blocked the secret commit." \
    || { echo "❌ CHECK 1 FAILED: Secret commit was not blocked by trufflehog."; exit 1; }

echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 2: Bypass commit (--no-verify) — verify must FAIL"
echo "═══════════════════════════════════════════════════"
git commit -q --no-verify -m "chore: bypass hooks and inject secret"
BYPASS_COMMIT=$(git rev-parse HEAD)
git push -q origin main
cat > "$TEST_DIR/bypass_event.json" <<EOF
{"ref": "refs/heads/main", "before": "$INITIAL_COMMIT", "after": "$BYPASS_COMMIT", "repository": {"full_name": "owner/repo"}}
EOF
set +e
GITHUB_TOKEN=dummy_token GITHUB_REPOSITORY=owner/repo GITHUB_EVENT_NAME=push \
GITHUB_EVENT_PATH="$TEST_DIR/bypass_event.json" GITHUB_REF=refs/heads/main \
POW='{"enforce":"true","checks_cmd":"'"$TRUFFLEHOG_CMD"'"}' \
$PYTHON admin_templates/github/scripts/verify_pow.py 2>&1 | tail -n 6
CHECK2_EXIT=${PIPESTATUS[0]}
set -e
[ "$CHECK2_EXIT" -ne 0 ] && echo "✅ CHECK 2 PASSED: verify_pow.py rejected the bypass commit." \
    || { echo "❌ CHECK 2 FAILED: verify_pow.py accepted a commit that bypassed the hooks."; exit 1; }

echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 3: Mint a real challenge — client receipt must match the tag"
echo "═══════════════════════════════════════════════════"
MINT_OUT="$TEST_DIR/challenge"
SESSION_ID=$($PYTHON -c "import uuid; print(uuid.uuid4())")
POW='{"hmac_key":"e2e-key","scanner_image":"'"$IMAGE"'"}' POW_SESSION_ID="$SESSION_ID" \
    $PYTHON admin_templates/github/scripts/mint_challenge.py --out "$MINT_OUT"
CLIENT_DIR="$TEST_DIR/client-corpus"
mkdir -p "$CLIENT_DIR"
tar -xf "$MINT_OUT/corpus.tar" -C "$CLIENT_DIR"
docker run --rm -v "$CLIENT_DIR":/pwd "$IMAGE" filesystem /pwd --no-verification --json 2>/dev/null > "$TEST_DIR/corpus_scan.jsonl" || true
$PYTHON - "$MINT_OUT/challenge.json" "$TEST_DIR/corpus_scan.jsonl" <<'PY'
import json, sys
sys.path.insert(0, "admin_templates/github/scripts")
from pow_trailer import receipt_from_jsonl, challenge_tag, tags_equal
cj = json.load(open(sys.argv[1]))
receipt = receipt_from_jsonl(open(sys.argv[2]).read(), cj["tool_version"])
ok = tags_equal(challenge_tag("e2e-key", cj["challenge_id"], cj["session_id"], receipt), cj["tag"])
print(f"tool={cj['tool_version']} receipt={receipt[:16]}… match={ok}")
sys.exit(0 if ok else 1)
PY
echo "✅ CHECK 3 PASSED: client-side receipt reproduces the minted HMAC tag."

echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 4: Nightly sweep classifies the bypass commit as LEAK_HONEST"
echo "═══════════════════════════════════════════════════"
docker run --rm -v "$TEST_DIR":/pwd "$IMAGE" git file:///pwd --no-verification --json 2>/dev/null > "$TEST_DIR/findings.jsonl" || true
echo "trufflehog git findings: $(wc -l < "$TEST_DIR/findings.jsonl")"
set +e
POW_FINDINGS_FILE="$TEST_DIR/findings.jsonl" POW_SWEEP_OUT_DIR="$TEST_DIR/sweep" \
POW='{"checks_cmd":"'"$TRUFFLEHOG_CMD"'","sweep_epoch":"'"$INITIAL_COMMIT"'"}' \
POW_SCANNER_VERSION="$(docker run --rm "$IMAGE" --version 2>&1 | head -n1)" \
$PYTHON admin_templates/github/scripts/sweep_audit.py
SWEEP_EXIT=$?
set -e
grep -q "\"classification\": \"LEAK_HONEST\"" "$TEST_DIR/sweep/report.json" || { echo "❌ CHECK 4 FAILED: no LEAK_HONEST in report"; exit 1; }
grep -q "$BYPASS_COMMIT" "$TEST_DIR/sweep/report.json" || { echo "❌ CHECK 4 FAILED: bypass commit not in report"; exit 1; }
grep -q "$FAKE_PAT" "$TEST_DIR/sweep/report.json" && { echo "❌ CHECK 4 FAILED: raw secret leaked into the report"; exit 1; }
[ "$SWEEP_EXIT" -eq 1 ] && echo "✅ CHECK 4 PASSED: sweep flagged the leak and exited 1." \
    || { echo "❌ CHECK 4 FAILED: sweep exit code $SWEEP_EXIT"; exit 1; }

echo ""
echo "🎉 All CI Trufflehog checks passed!"
exit 0
