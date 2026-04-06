import os
import stat
import shutil
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

HOOK_DIR = ".git/hooks"
TEMPLATE_DIR = "hooks_templates"
HOOKS_TO_INSTALL = ["pre-commit", "commit-msg", "pre-merge-commit"]

def generate_keys():
    key_dir = os.path.expanduser("~/.pow")
    priv_file = os.path.join(key_dir, "private_key.pem")
    pub_file = os.path.join(key_dir, "public_key.pem")

    os.makedirs(key_dir, exist_ok=True)

    if not os.path.exists(priv_file):
        print(f"🔑 Generating new RSA Keypair for signing in {key_dir}...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(priv_file, "wb") as f:
            f.write(priv_pem)
        with open(pub_file, "wb") as f:
            f.write(pub_pem)
        
        print("✅ Keypair generated.")
    else:
        print("✅ Existing RSA Keypair found.")
        with open(pub_file, "rb") as f:
            pub_pem = f.read()

    print("\n--- PUBLIC KEY FOR GITHUB SECRET: POW_PUBLIC_KEYS ---")
    print(pub_pem.decode().strip())
    print("-----------------------------------------------------\n")

def install():
    if not os.path.exists(HOOK_DIR):
        print(f"❌ Error: {HOOK_DIR} does not exist. Are you in the root of a Git repository?")
        return

    generate_keys()

    for hook_name in HOOKS_TO_INSTALL:
        src = os.path.join(TEMPLATE_DIR, hook_name)
        dst = os.path.join(HOOK_DIR, hook_name)
        
        if not os.path.exists(src):
            print(f"❌ Error: Hook template {src} not found.")
            continue
            
        with open(src, "r") as f:
            content = f.read()
            
        repo_root = os.path.abspath(os.getcwd())
        venv_python = os.path.join(repo_root, ".venv", "bin", "python")
        
        if content.startswith("#!/usr/bin/env python3"):
            content = content.replace("#!/usr/bin/env python3", f"#!{venv_python}", 1)
            
        with open(dst, "w") as f:
            f.write(content)
        
        # Make executable
        st = os.stat(dst)
        os.chmod(dst, st.st_mode | stat.S_IEXEC)
        
    print("✅ Hooks installed. Proof-of-Work protocol is now active.")

if __name__ == "__main__":
    install()
