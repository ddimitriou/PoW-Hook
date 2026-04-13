import os
import re
import stat
import shutil
import json
import subprocess
import sys

HOOK_DIR_TPL = ".git/hooks"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(SCRIPT_DIR, "hooks_templates")
HOOKS_TO_INSTALL = ["pre-commit", "commit-msg", "pre-merge-commit"]
POW_CONFIG_FILE_TPL = ".pow-config.json"


def read_pow_config(target_repo="."):
    config_file = os.path.join(target_repo, POW_CONFIG_FILE_TPL)
    if os.path.exists(config_file):
        with open(config_file) as f:
            return json.load(f)
    return {}


def find_ssh_key():
    """Return the SSH private key path used for github.com connections."""
    # Test/CI override — skips ssh -G detection entirely
    override = os.environ.get("POW_SSH_KEY_OVERRIDE")
    if override and os.path.exists(override):
        return override

    # Use ssh -G to resolve the effective identity file (respects ~/.ssh/config)
    try:
        out = subprocess.check_output(
            ["ssh", "-G", "github.com"], stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            if line.startswith("identityfile "):
                path = os.path.expanduser(line.split(None, 1)[1])
                if os.path.exists(path):
                    return path
    except Exception:
        pass

    # Fall back to default key locations
    for candidate in ["~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa"]:
        path = os.path.expanduser(candidate)
        if os.path.exists(path):
            return path

    return None


def validate_github_ssh_key(key_path):
    """
    Test that key_path authenticates to GitHub via ssh -T.
    Returns (success: bool, username: str | None).
    """
    try:
        result = subprocess.run(
            [
                "ssh", "-T",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                "-i", key_path,
                "git@github.com",
            ],
            capture_output=True,
            text=True,
        )
        combined = result.stdout + result.stderr
        if "successfully authenticated" in combined:
            m = re.search(r"Hi ([^!]+)!", combined)
            return True, (m.group(1) if m else None)
    except Exception:
        pass
    return False, None


def setup_github_ssh_mode():
    """
    Detect the developer's SSH key for GitHub SSH key mode.
    Returns the key path on success, None on failure.
    """
    print("\n🔍 Detecting SSH key for GitHub SSH key mode...")
    key_path = find_ssh_key()

    if key_path is None:
        print("❌ No SSH private key found in standard locations (~/.ssh/id_rsa, ~/.ssh/id_ed25519, etc.).")
        print("   Generate one: ssh-keygen -t ed25519 -C 'your@email.com'")
        print("   Then add it to your GitHub account: https://github.com/settings/ssh/new")
        return None

    print(f"   Found: {key_path}")
    print("   Validating against GitHub...")

    ok, username = validate_github_ssh_key(key_path)
    if ok:
        print(f"✅ Authenticated as GitHub user: {username}")
        print("ℹ️  This key will be used to sign your commits automatically.")
    else:
        print("   ⚠️  Could not validate key against GitHub (network/SSH may be unavailable).")
        print("      Ensure this key is added to your GitHub account before pushing.")

    return key_path


def install():
    target_repo = sys.argv[1] if len(sys.argv) > 1 else "."
    hook_dir = os.path.join(target_repo, HOOK_DIR_TPL)

    if not os.path.exists(hook_dir):
        print(f"❌ Error: {hook_dir} does not exist. Are you pointing to the root of a Git repository?")
        return

    ssh_key = setup_github_ssh_mode()
    if ssh_key is None:
        print("❌ Aborting: cannot install hooks without a valid SSH key.")
        return

    # Resolve the Python interpreter path.
    # On Windows (Git for Windows/MSYS2), we must use the Unix-style path
    # (/c/...) so the shell wrappers can execute it correctly.
    interp = sys.executable.replace("\\", "/")
    if os.name == "nt" and len(interp) >= 2 and interp[1] == ":":
        # C:/path -> /c/path
        interp = "/" + interp[0].lower() + interp[2:]

    on_windows = (os.name == "nt")

    for hook_name in HOOKS_TO_INSTALL:
        src = os.path.join(TEMPLATE_DIR, hook_name)
        dst = os.path.join(hook_dir, hook_name)

        if not os.path.exists(src):
            print(f"❌ Error: Hook template {src} not found.")
            continue

        with open(src, "r") as f:
            content = f.read()

        if on_windows:
            # Git for Windows runs hooks via its bundled sh.exe, which cannot
            # exec scripts whose shebang contains an MSYS2-style /c/... path.
            # Work-around: write a #!/bin/sh wrapper that exec's the Python
            # payload (saved alongside as <hook_name>.py).
            py_dst = dst + ".py"
            with open(py_dst, "w", newline="\n") as f:
                f.write(content)
            st = os.stat(py_dst)
            os.chmod(py_dst, st.st_mode | stat.S_IEXEC)

            wrapper = (
                "#!/bin/sh\n"
                f"exec '{interp}' \"$(dirname \"$0\")/{hook_name}.py\" \"$@\"\n"
            )
            with open(dst, "w", newline="\n") as f:
                f.write(wrapper)
        else:
            # On Unix, replace the env shebang with the exact interpreter so
            # the hook works inside virtualenvs without activation.
            if content.startswith("#!/usr/bin/env python3"):
                content = content.replace("#!/usr/bin/env python3", f"#!{interp}", 1)
            with open(dst, "w", newline="\n") as f:
                f.write(content)

        st = os.stat(dst)
        os.chmod(dst, st.st_mode | stat.S_IEXEC)

    print("✅ Hooks installed. Proof-of-Work protocol is now active.")


if __name__ == "__main__":
    install()
