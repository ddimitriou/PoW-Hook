#!/bin/bash
# ---------------------------------------------------------------------------
# E2E test: GitHub SSH key mode with act
#
# Requires: act (in PATH), Docker running, Python 3 with cryptography
#
# Flow:
#   1. Generate a test Ed25519 SSH keypair
#   2. Set up a fresh repo in github key_source mode
#   3. Install hooks (with POW_SSH_KEY_OVERRIDE pointing at the test key)
#   4. Start a mock GitHub API server accessible from within the act container
#   5. Make a validly-signed commit, then run act push → must PASS
#   6. Make a bypass commit (--no-verify), then run act push → must FAIL
#
# The mock server binds on all interfaces (0.0.0.0) so the Docker container
# can reach it via the host IP.  On Linux this is 172.17.0.1 (docker bridge);
# on Docker Desktop (Mac/Win) host.docker.internal resolves to the host.
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRJ_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="$(mktemp -d)"
MOCK_PORT=18080
MOCK_PID=""

kill_port() {
    local port="$1"
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        # Windows: kill ALL processes listening on the port
        for attempt in 1 2 3; do
            powershell -noprofile -command "
    \$conns = Get-NetTCPConnection -LocalPort ${port} -State Listen -ErrorAction SilentlyContinue
    \$pids  = \$conns | Select-Object -ExpandProperty OwningProcess | Sort-Object -Unique
    \$pids | ForEach-Object { Stop-Process -Id \$_ -Force -ErrorAction SilentlyContinue }
    " 2>/dev/null || true
            sleep 0.3
        done
    else
        # Unix-like: use lsof or fuser
        if command -v lsof >/dev/null; then
            lsof -ti :"$port" | xargs kill -9 2>/dev/null || true
        elif command -v fuser >/dev/null; then
            fuser -k "$port"/tcp 2>/dev/null || true
        fi
    fi
}

cleanup() {
    set +euo pipefail
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
    cd "$SCRIPT_DIR" 2>/dev/null || true
    rm -rf "$TEST_DIR" 2>/dev/null || true
    rm -f "$SCRIPT_DIR/.pow_e2e_pubkey.pub" 2>/dev/null || true
    echo "🧹 Cleaned up."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Generate test Ed25519 keypair (using ssh-keygen — avoids platform path issues)
# ---------------------------------------------------------------------------
echo "🔑 Generating test Ed25519 SSH keypair..."
KEY_PATH="$TEST_DIR/test_id_ed25519"
PUB_PATH="$TEST_DIR/test_id_ed25519.pub"

ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -q -C "e2e-test"
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

cat > .env <<'EOF'
# Empty env — no attestation dispatch in E2E test
EOF

# Scaffold .github/scripts from admin_templates
mkdir -p .github/scripts .github/workflows
cp admin_templates/github/scripts/verify_pow.py  .github/scripts/

# Write a debug helper script that runs inside the act container to diagnose
# signature verification issues (avoids YAML heredoc / << merge-key problems).
cat > .github/scripts/e2e_debug.py << 'PYEOF'
#!/usr/bin/env python3
"""Diagnostic: verify the signed commit from inside the act container."""
import subprocess, base64, urllib.request, json, os, sys
from cryptography.hazmat.primitives import serialization

def gitout(*args):
    return subprocess.check_output(["git"] + list(args), text=True).strip()

commit = gitout("log", "-1", "--format=%H")
tree   = gitout("log", "-1", "--format=%T", commit)
tok    = gitout("log", "-1", "--format=%(trailers:key=Validated-At-Local,valueonly)", commit)
sess   = gitout("log", "-1", "--format=%(trailers:key=PoW-Session,valueonly)", commit)
stat   = gitout("log", "-1", "--format=%(trailers:key=PoW-Status,valueonly)", commit)
payload = f"{tree}|{sess}|{stat}"
print(f"[e2e_debug] tree={tree}")
print(f"[e2e_debug] session={sess}")
print(f"[e2e_debug] status={stat}")
print(f"[e2e_debug] tok_len={len(tok)}")
print(f"[e2e_debug] payload={payload}")
api = os.environ.get("POW_GITHUB_API_URL", "")
req = urllib.request.Request(f"{api}/users/test_user/keys")
data = json.loads(urllib.request.urlopen(req).read())
pub_str = data[0]["key"]
print(f"[e2e_debug] mock_pub_prefix={pub_str[:40]}")
pub = serialization.load_ssh_public_key(pub_str.encode())
sig = base64.b64decode(tok)
try:
    pub.verify(sig, payload.encode())
    print("[e2e_debug] VERIFY: OK")
except Exception as e:
    print(f"[e2e_debug] VERIFY: FAIL {type(e).__name__}: {e}")
PYEOF

# Write a simplified workflow for E2E — avoids actions/setup-python which
# requires cloning from GitHub (fails with a dummy token).  The act-latest
# image already ships Python 3 + pip, so we just call pip directly.
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
          POW_GITHUB_API_URL: ${{ secrets.POW_GITHUB_API_URL }}
        run: |
          pip install cryptography -q --break-system-packages
          python3 .github/scripts/e2e_debug.py
          python3 .github/scripts/verify_pow.py
WORKFLOW

# ---------------------------------------------------------------------------
# 3. Install hooks
# ---------------------------------------------------------------------------
echo "🔧 Installing PoW hooks..."
# Convert key path to Windows-native format so Windows Python can find the file
# regardless of how environment variables are passed through the git hook chain.
# Convert key path to Windows-native format if on Windows
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    KEY_PATH_WIN=$(cygpath -w "$KEY_PATH" | tr '\\' '/')
else
    KEY_PATH_WIN="$KEY_PATH"
fi
export POW_SSH_KEY_OVERRIDE="$KEY_PATH_WIN"
export PYTHONUTF8=1       # prevent cp1252 encode errors on Windows
echo "   POW_SSH_KEY_OVERRIDE=$POW_SSH_KEY_OVERRIDE"
$PYTHON setup_hooks.py

# Commit the config so pre-receive can read it via git show
git add .pow-config.json
git commit --no-verify -m "chore: add pow config"
INITIAL_COMMIT=$(git rev-parse HEAD)

# ---------------------------------------------------------------------------
# 4. Start mock GitHub API server
# ---------------------------------------------------------------------------
echo "🌐 Starting mock GitHub API server on port $MOCK_PORT..."

# Determine host address reachable from inside Docker
if docker info 2>/dev/null | grep -qiE "docker desktop|context.*desktop"; then
    # Docker Desktop (Mac/Windows) — host is reachable via a special DNS name
    DOCKER_HOST_ADDR="host.docker.internal"
else
    # Linux native Docker — use bridge gateway
    DOCKER_HOST_ADDR=$(docker network inspect bridge \
        --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || echo "172.17.0.1")
fi
echo "   Docker → host via: $DOCKER_HOST_ADDR"

# Kill any stale mock server from a previous test run on this port.
echo "   Clearing port $MOCK_PORT of any stale processes..."
kill_port "$MOCK_PORT"
sleep 0.3

# Copy the public key to SCRIPT_DIR (a /c/... path that MSYS2 converts correctly
# to a Windows path for Windows Python, avoiding /tmp/... mapping ambiguity).
MOCK_PUB_KEY="$SCRIPT_DIR/.pow_e2e_pubkey.pub"
cp "$PUB_PATH" "$MOCK_PUB_KEY"
echo "   MOCK_PUB_KEY=$MOCK_PUB_KEY"
$PYTHON "$SCRIPT_DIR/test_mock_github_api.py" $MOCK_PORT "$MOCK_PUB_KEY" &
MOCK_PID=$!

# Give the server a moment to start (or crash if port is still in use)
sleep 0.5
if ! kill -0 "$MOCK_PID" 2>/dev/null; then
    echo "❌ Mock server crashed immediately (port $MOCK_PORT still in use?). Aborting."
    exit 1
fi

# Wait for server to be ready
for i in $(seq 1 20); do
    if curl -sf "http://127.0.0.1:$MOCK_PORT/users/test_user/keys" >/dev/null 2>&1; then
        echo "✅ Mock server ready."
        break
    fi
    sleep 0.5
done

# Verify mock server PID is the one WE started (sanity check)
if ! kill -0 "$MOCK_PID" 2>/dev/null; then
    echo "❌ Mock server died before we could use it. Aborting."
    exit 1
fi

# Sanity-check: confirm mock server is serving the test public key
echo "--- Mock key vs test key comparison ---"
MOCK_KEY_STR=$(curl -sf "http://127.0.0.1:$MOCK_PORT/users/test_user/keys" \
    | $PYTHON -c "import sys,json; d=json.load(sys.stdin); print(d[0]['key'])")
TEST_KEY_STR=$(cat "$PUB_PATH")
echo "Mock key : ${MOCK_KEY_STR:0:80}"
echo "Test key : ${TEST_KEY_STR:0:80}"
if [ "$MOCK_KEY_STR" = "$TEST_KEY_STR" ]; then
    echo "✅ Keys MATCH — mock server is serving the right public key."
else
    echo "❌ Keys DIFFER — mock server is serving the WRONG public key!"
fi
echo "---"

# ---------------------------------------------------------------------------
# 5. Signed commit → act push → must PASS
# ---------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 1: Valid signed commit — act push must PASS"
echo "═══════════════════════════════════════════════════"

echo "hello" > valid.txt
git add valid.txt
git commit -m "feat: valid signed commit"
SIGNED_COMMIT=$(git rev-parse HEAD)

# Debug: does the test key match the signature in the commit?
echo "--- DEBUG: key match check ---"
$PYTHON "$SCRIPT_DIR/test_e2e_key_debug.py"
echo "--- END DEBUG ---"

# Also verify directly using the PUBLIC key on the host
echo "--- DEBUG: host public-key verification ---"
$PYTHON "$SCRIPT_DIR/test_e2e_pubkey_verify.py"
echo "--- END DEBUG ---"

# Build secrets/env file for act
cat > .secrets <<EOF
GITHUB_TOKEN=dummy_token
POW_GITHUB_API_URL=http://${DOCKER_HOST_ADDR}:${MOCK_PORT}
EOF

# Build a push event payload for act
cat > /tmp/pow_push_event.json <<EOF
{
  "ref": "refs/heads/main",
  "before": "$INITIAL_COMMIT",
  "after":  "$SIGNED_COMMIT",
  "repository": {"full_name": "owner/repo"},
  "pusher": {"name": "test_user"}
}
EOF

set +e
"$ACT" push \
    --eventpath /tmp/pow_push_event.json \
    --secret-file .secrets \
    --network host \
    -P ubuntu-latest=ghcr.io/catthehacker/ubuntu:act-latest \
    2>&1
ACT_EXIT=$?
set -e

if [ "$ACT_EXIT" -eq 0 ]; then
    echo "✅ CHECK 1 PASSED: act accepted the valid signed commit."
else
    echo "❌ CHECK 1 FAILED: act rejected a valid signed commit (exit $ACT_EXIT)."
    exit 1
fi

# ---------------------------------------------------------------------------
# 6. Bypass commit → act push → must FAIL
# ---------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════"
echo " CHECK 2: Bypass commit (--no-verify) → must FAIL"
echo "═══════════════════════════════════════════════════"

echo "bypass" > bypass.txt
git add bypass.txt
git commit --no-verify -m "chore: bypass hooks"
BYPASS_COMMIT=$(git rev-parse HEAD)

cat > /tmp/pow_bypass_event.json <<EOF
{
  "ref": "refs/heads/main",
  "before": "$SIGNED_COMMIT",
  "after":  "$BYPASS_COMMIT",
  "repository": {"full_name": "owner/repo"},
  "pusher": {"name": "test_user"}
}
EOF

set +e
"$ACT" push \
    --eventpath /tmp/pow_bypass_event.json \
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
echo "🎉 All E2E checks passed!"
exit 0
