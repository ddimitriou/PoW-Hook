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

# Use the central venv Python if it already exists (created by admin_install.py),
# otherwise fall back to system python3.  setup_hooks.py will create the central
# venv and install cryptography if it is not yet present.
CENTRAL_PYTHON="$HOME/.pow-hook/venv/bin/python3"
if [ -f "$CENTRAL_PYTHON" ]; then
    PYTHON="$CENTRAL_PYTHON"
else
    PYTHON="python3"
fi

# Auto-derive github_repo (inside the POW JSON) from the target repo's git remote
REMOTE_URL=$(git -C "$TARGET_REPO" remote get-url origin 2>/dev/null || echo "")
if [[ -n "$REMOTE_URL" ]]; then
    DERIVED_REPO=$("$PYTHON" -c "
import re, sys
m = re.search(r'github\.com[:/]([^/]+/[^/.]+?)(\.git)?\$', sys.argv[1])
print(m.group(1) if m else '')
" "$REMOTE_URL" 2>/dev/null || echo "")
    if [[ -n "$DERIVED_REPO" ]]; then
        "$PYTHON" -c "
import sys
sys.path.insert(0, sys.argv[1])
from setup_hooks import read_pow_env, update_pow_env
target, repo = sys.argv[2], sys.argv[3]
if not read_pow_env(target).get('github_repo'):
    update_pow_env(target, 'github_repo', repo)
    print('📦 Auto-detected github_repo=' + repo)
" "$SCRIPT_DIR" "$TARGET_REPO" "$DERIVED_REPO"
    fi
fi

"$PYTHON" "$SCRIPT_DIR/setup_hooks.py" "$TARGET_REPO"

echo ""
echo "--------------------------------------------------------"
echo "🎉 Installation complete."
echo "--------------------------------------------------------"
