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

"$PYTHON" "$SCRIPT_DIR/setup_hooks.py" "$TARGET_REPO"

echo ""
echo "--------------------------------------------------------"
echo "🎉 Installation complete."
echo "--------------------------------------------------------"
