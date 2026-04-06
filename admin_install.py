#!/usr/bin/env python3
import os
import shutil

def configure_github_actions():
    print("\n☁️ Setting up GitHub Actions Configuration...")
    os.makedirs(".github", exist_ok=True)
    if os.path.exists("admin_templates/github"):
        shutil.copytree("admin_templates/github", ".github", dirs_exist_ok=True)
        print("✅ Scaffolded .github/workflows and .github/scripts.")
    else:
        print("❌ Error: Missing admin_templates/github/ folder.")
    print("⚠️ Don't forget to configure your 'POW_PUBLIC_KEYS' secret within your GitHub Repository settings!")

def configure_github_enterprise():
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

def main():
    print("Welcome to the PoW-Hook Administrator Setup!\n")
    print("1) GitHub Actions (Standard Cloud Deployment)")
    print("2) GitHub Enterprise Server (Self-Hosted 'pre-receive' Deployments)\n")
    
    choice = input("Select backend deployment structure [1/2]: ").strip()
    
    if choice == "1":
        configure_github_actions()
    elif choice == "2":
        configure_github_enterprise()
    else:
        print("❌ Invalid selection. Please re-run script.")

if __name__ == "__main__":
    main()
