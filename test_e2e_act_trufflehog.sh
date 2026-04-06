#!/bin/bash
set -e

echo "🚀 Starting E2E Trufflehog + ACT Test..."

TEST_DIR="/tmp/pre-hooker-e2e"
rm -rf "$TEST_DIR"
cp -r "$(pwd)" "$TEST_DIR"
cd "$TEST_DIR"

if [ -d ".venv" ]; then
    rm -rf .venv
fi
if [ -d ".git" ]; then
    rm -rf .git
fi
if [ -d ".github" ]; then
    rm -rf .github
fi

echo "📦 Initializing clean local repository..."
git init
git config user.name "E2E Test"
git config user.email "e2e@example.com"
git add .
git commit -m "Initial baseline commit"

echo "🔧 Running Install payload..."
./install.sh

echo "🏗 Configuring GitHub Actions structure natively..."
# Mocking administrator input '1' for GitHub Actions deployment
echo "1" | python3 admin_install.py

echo "🛡 Injecting Trufflehog as the underlying local validator..."
# Trufflehog will scan the filesystem. We use --no-verification to catch everything, and fail securely.
cat << 'EOF' > .env
POW_CHECKS_CMD="docker run --rm -v $(pwd):/pwd trufflesecurity/trufflehog:latest filesystem /pwd --no-verification --fail"
EOF

# Prepare the secrets file for ACT to authenticate with
echo "🔐 Constructing Github Action secrets payload..."
python3 -c '
import json, sys, os
pub_path = os.path.expanduser("~/.pow/public_key.pem")
with open(pub_path, "r") as f:
    key = f.read()
secret_json = json.dumps({"test_user": key})
with open(".secrets", "w") as f:
    f.write(f"POW_PUBLIC_KEYS={secret_json}\n")
'

echo "🏴‍☠️ Injecting Malicious GitHub PAT into the codebase..."
# Trufflehog requires relatively exact entropy matching. 
echo "ghp_012345678901234567890123456789012345" > malicious_secret.txt
git add malicious_secret.txt

echo "🛑 Attempting isolated standard commit. Execution should FAIL instantly via Trufflehog!"
set +e
git commit -m "Leak a secret"
COMMIT_CODE=$?
set -e

if [ "$COMMIT_CODE" == "0" ]; then
    echo "❌ ERROR: Trufflehog failed to catch the secret and approved the commit!"
    exit 1
else
    echo "✅ Trufflehog successfully detected the secret and aborted the commit! (Passed Check 1)"
fi

echo "😈 Maliciously bypassing Trufflehog validation via --no-verify..."
git commit --no-verify -m "Malicious bypass commit"
echo "✅ Unverified payload injected into git index simulating insider-threat."

echo "☁️ Triggering server-side evaluation via Dockerized ACT natively analyzing the Push Event..."
set +e
# Run ACT in silence to avoid overflowing stdout, just capture exit code matching
act push --secret-file .secrets
ACT_EXIT=$?
set -e

if [ "$ACT_EXIT" != "0" ]; then
    echo "✅ Server gracefully blocked and struck down the unauthorized commit natively mapping RSA failures! (Passed Check 2)"
else
    echo "❌ ERROR: Server allowed the unauthorized commit!"
    exit 1
fi

echo "🎉 E2E Test Pipeline Complete! All military-grade defensive boundaries are holding solid natively against Trufflehog failures!"
