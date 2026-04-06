#!/bin/bash
set -e

echo "🚀 Installing Proof-of-Work Git Hooks..."



# Configure .env if it doesn't exist
if [ ! -f .env ]; then
    echo "📄 Creating .env from .env.example..."
    cp .env.example .env
fi

# Setup standard virtual environment
if [ ! -d ".venv" ]; then
    echo "🐍 Creating standard Python virtual environment in .venv..."
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install cryptography 2>/dev/null || true

# Run python install script
python3 setup_hooks.py

echo ""
echo "--------------------------------------------------------"
echo "🎉 Installation complete."
echo "⚠️  IMPORTANT: Please share your Public Key with your repository admin to authorize your pushes!"
echo "--------------------------------------------------------"
