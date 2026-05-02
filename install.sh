#!/bin/bash
set -e

echo "🚀 Installing Proof-of-Work Git Hooks..."



SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_REPO="${1:-.}"

# Configure .env if it doesn't exist
if [ ! -f "$TARGET_REPO/.env" ]; then
    echo "📄 Creating .env from .env.example..."
    cp "$SCRIPT_DIR/.env.example" "$TARGET_REPO/.env"
fi

# Auto-derive POW_GITHUB_REPO from the target repo's git remote
REMOTE_URL=$(git -C "$TARGET_REPO" remote get-url origin 2>/dev/null || echo "")
if [[ -n "$REMOTE_URL" ]]; then
    DERIVED_REPO=$(python3 -c "
import re, sys
m = re.search(r'github\.com[:/]([^/]+/[^/.]+?)(\.git)?\$', sys.argv[1])
print(m.group(1) if m else '')
" "$REMOTE_URL" 2>/dev/null || echo "")
    if [[ -n "$DERIVED_REPO" ]]; then
        python3 -c "
import sys, re
env_file, repo = sys.argv[1], sys.argv[2]
with open(env_file) as f:
    content = f.read()
if not re.search(r'^POW_GITHUB_REPO=', content, re.MULTILINE):
    content = re.sub(r'^#.*POW_GITHUB_REPO=.*', 'POW_GITHUB_REPO=\"' + repo + '\"', content, flags=re.MULTILINE)
    if 'POW_GITHUB_REPO' not in content:
        content += '\nPOW_GITHUB_REPO=\"' + repo + '\"\n'
    with open(env_file, 'w') as f:
        f.write(content)
" "$TARGET_REPO/.env" "$DERIVED_REPO"
        echo "📦 Auto-detected POW_GITHUB_REPO=$DERIVED_REPO"
    fi
fi

# Use the central venv Python if it already exists (created by admin_install.py),
# otherwise fall back to system python3.  setup_hooks.py will create the central
# venv and install cryptography if it is not yet present.
CENTRAL_PYTHON="$HOME/.pow-hook/venv/bin/python3"
if [ -f "$CENTRAL_PYTHON" ]; then
    PYTHON="$CENTRAL_PYTHON"
else
    PYTHON="python3"
fi

"$PYTHON" "$SCRIPT_DIR/setup_hooks.py" "$TARGET_REPO"

echo ""
echo "--------------------------------------------------------"
echo "🎉 Installation complete."
echo "--------------------------------------------------------"
