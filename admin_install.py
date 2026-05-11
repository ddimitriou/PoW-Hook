#!/usr/bin/env python3
import os
import shutil
import json
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ADMIN_TEMPLATES = os.path.join(SCRIPT_DIR, "admin_templates")
sys.path.insert(0, SCRIPT_DIR)


def configure_github_actions(target_dir):
    print("\n☁️ Setting up GitHub Actions Configuration...")
    github_dir = os.path.join(target_dir, ".github")
    os.makedirs(github_dir, exist_ok=True)
    src = os.path.join(ADMIN_TEMPLATES, "github")
    if os.path.exists(src):
        shutil.copytree(src, github_dir, dirs_exist_ok=True)
        print("✅ Scaffolded .github/workflows and .github/scripts.")
    else:
        print(f"❌ Error: Missing {src} folder.")
    print("ℹ️  Commit .github/ directory to your repository.")
    print("ℹ️  Collaborators with write access will be auto-resolved via the GitHub API at verification time.")
    print("ℹ️  SSH keys are fetched from developer GitHub profiles — no manual key exchange needed.")


def configure_github_enterprise(target_dir):
    print("\n🏢 Setting up GitHub Enterprise Pre-Receive Hook...")
    hook_dir = os.path.join(target_dir, ".git", "hooks")
    os.makedirs(hook_dir, exist_ok=True)

    src = os.path.join(ADMIN_TEMPLATES, "pre-receive_hook", "pre-receive")
    dst = os.path.join(hook_dir, "pre-receive")

    if os.path.exists(src):
        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)
        print(f"✅ Pre-Receive hook successfully generated at {dst}.")
        print("ℹ️ Note: This must be physically uploaded to your Enterprise server storage natively to trigger on pushes!")
    else:
        print(f"❌ Error: Missing {src}.")

    print("ℹ️  Configure the POW environment variable on the server with your settings.")
    print("ℹ️  Collaborators with write access will be auto-resolved via the GitHub API at verification time.")
    print("⚠️  Ensure your Enterprise server has network access to the GitHub API.")
    print("ℹ️  Set github_api_url in the POW JSON if using a custom GitHub Enterprise Server API endpoint.")


def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."

    print("🐍 Setting up central Python environment...")
    from setup_hooks import ensure_central_venv
    if ensure_central_venv() is None:
        print("❌ Failed to create central venv. Aborting.")
        return

    print(f"Welcome to the PoW-Hook Administrator Setup! (Target: {target_dir})\n")
    print("1) GitHub Actions (Standard Cloud Deployment)")
    print("2) GitHub Enterprise Server (Self-Hosted 'pre-receive' Deployments)\n")

    choice = input("Select backend deployment structure [1/2]: ").strip()

    if choice not in ("1", "2"):
        print("❌ Invalid selection. Please re-run script.")
        return

    if choice == "1":
        configure_github_actions(target_dir)
    elif choice == "2":
        configure_github_enterprise(target_dir)


if __name__ == "__main__":
    main()
