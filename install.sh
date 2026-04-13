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

# Setup standard virtual environment
if [ ! -d ".venv" ]; then
    echo "🐍 Creating standard Python virtual environment in .venv..."
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install cryptography 2>/dev/null || true

# Run python install script
python3 "$SCRIPT_DIR/setup_hooks.py" "$TARGET_REPO"

echo ""
echo "--------------------------------------------------------"
echo "🎉 Installation complete."
echo "⚠️  IMPORTANT: Please share your Public Key with your repository admin to authorize your pushes!"
echo "--------------------------------------------------------"
