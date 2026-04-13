#!/usr/bin/env python3
import os
import shutil
import json

POW_CONFIG_FILE = ".pow-config.json"


def write_pow_config(key_source):
    """Write .pow-config.json to the repository root."""
    config = {"key_source": key_source}
    with open(POW_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
    print(f"✅ Created {POW_CONFIG_FILE} (key_source: {key_source})")


def configure_github_actions(key_source):
    print("\n☁️ Setting up GitHub Actions Configuration...")
    os.makedirs(".github", exist_ok=True)
    if os.path.exists("admin_templates/github"):
        shutil.copytree("admin_templates/github", ".github", dirs_exist_ok=True)
        print("✅ Scaffolded .github/workflows and .github/scripts.")
    else:
        print("❌ Error: Missing admin_templates/github/ folder.")

    write_pow_config(key_source)

    print("ℹ️  Commit .pow-config.json to your repository.")
    print("ℹ️  Collaborators with write access will be auto-resolved via the GitHub API at verification time.")
    print("ℹ️  SSH keys are fetched from developer GitHub profiles — no manual key exchange needed.")


def configure_github_enterprise(key_source):
    print("\n🏢 Setting up GitHub Enterprise Pre-Receive Hook...")
    hook_dir = ".git/hooks"
    os.makedirs(hook_dir, exist_ok=True)

    src = "admin_templates/pre-receive_hook/pre-receive"
    dst = os.path.join(hook_dir, "pre-receive")

    if os.path.exists(src):
        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)
        print(f"✅ Pre-Receive hook successfully generated at {dst}.")
        print("ℹ️ Note: This must be physically uploaded to your Enterprise server storage natively to trigger on pushes!")
    else:
        print(f"❌ Error: Missing {src}.")

    write_pow_config(key_source)

    print("ℹ️  Commit .pow-config.json to your repository.")
    print("ℹ️  Collaborators with write access will be auto-resolved via the GitHub API at verification time.")
    print("⚠️  Ensure your Enterprise server has network access to the GitHub API.")
    print("ℹ️  Set POW_GITHUB_API_URL if using a custom GitHub Enterprise Server API endpoint.")


def main():
    print("Welcome to the PoW-Hook Administrator Setup!\n")
    print("1) GitHub Actions (Standard Cloud Deployment)")
    print("2) GitHub Enterprise Server (Self-Hosted 'pre-receive' Deployments)\n")

    choice = input("Select backend deployment structure [1/2]: ").strip()

    if choice not in ("1", "2"):
        print("❌ Invalid selection. Please re-run script.")
        return

    key_source = "github"

    if choice == "1":
        configure_github_actions(key_source)
    elif choice == "2":
        configure_github_enterprise(key_source)


if __name__ == "__main__":
    main()
