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
CENTRAL_VENV_DIR = os.path.expanduser("~/.pow-hook/venv")


def read_pow_config(target_repo="."):
    config_file = os.path.join(target_repo, POW_CONFIG_FILE_TPL)
    if os.path.exists(config_file):
        with open(config_file) as f:
            return json.load(f)
    return {}


def find_ssh_key_candidates():
    """Return a list of potential SSH private key paths for github.com connections."""
    candidates = []

    # Test/CI override — skips detection entirely
    override = os.environ.get("POW_SSH_KEY_OVERRIDE")
    if override and os.path.exists(override):
        return [override]

    # Use ssh -G to resolve the effective identity files (respects ~/.ssh/config)
    try:
        out = subprocess.check_output(
            ["ssh", "-G", "github.com"], stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            if line.startswith("identityfile "):
                path = os.path.expanduser(line.split(None, 1)[1])
                if os.path.exists(path) and path not in candidates:
                    candidates.append(path)
    except Exception:
        pass

    # Fall back to default key locations
    for candidate in ["~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa"]:
        path = os.path.expanduser(candidate)
        if os.path.exists(path) and path not in candidates:
            candidates.append(path)

    return candidates


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


def update_env_file(target_repo, key, value):
    """Update or append a key=value pair in the .env file."""
    env_path = os.path.join(target_repo, ".env")
    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            lines = f.readlines()

    found = False
    new_line = f"{key}={value}\n"
    for i, line in enumerate(lines):
        if line.strip().startswith(f"{key}="):
            lines[i] = new_line
            found = True
            break

    if not found:
        # Ensure a newline if the file doesn't end with one
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(new_line)

    with open(env_path, "w") as f:
        f.writelines(lines)


def ensure_central_venv():
    """Ensure a central virtual environment exists with required dependencies."""
    if not os.path.exists(CENTRAL_VENV_DIR):
        print(f"📦 Creating centralized virtual environment at {CENTRAL_VENV_DIR}...")
        os.makedirs(os.path.dirname(CENTRAL_VENV_DIR), exist_ok=True)
        try:
            subprocess.run([sys.executable, "-m", "venv", CENTRAL_VENV_DIR], check=True)
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create virtual environment: {e}")
            return None

    # Determine pip and python paths within venv
    suffix = ".exe" if os.name == "nt" else ""
    venv_python = os.path.join(CENTRAL_VENV_DIR, "Scripts" if os.name == "nt" else "bin", f"python{suffix}")

    print(f"📥 Ensuring 'cryptography' is installed in central venv...")
    try:
        subprocess.run([venv_python, "-m", "pip", "install", "--upgrade", "pip"], capture_output=True, check=True)
        subprocess.run([venv_python, "-m", "pip", "install", "cryptography"], capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies in central venv: {e}")
        return None

    return venv_python


def resolve_best_python():
    """Return the best Python interpreter path (central venv preferred)."""
    # Prefer the central venv to ensure consistency across all hook installations
    central_python = ensure_central_venv()
    if central_python:
        return central_python

    # Fallback to current interpreter if for some reason central venv fails
    try:
        import cryptography
        return sys.executable
    except ImportError:
        pass

    return None


def setup_github_ssh_mode(target_repo="."):
    """
    Detect and validate the developer's SSH key for GitHub.
    Returns the first valid key path, or the first detected candidate if none validate.
    """
    print("\n🔍 Detecting SSH keys for GitHub SSH key mode...")
    candidates = find_ssh_key_candidates()

    if not candidates:
        print("❌ No SSH private keys found in standard locations (~/.ssh/id_rsa, ~/.ssh/id_ed25519, etc.).")
        print("   Generate one: ssh-keygen -t ed25519 -C 'your@email.com'")
        print("   Then add it to your GitHub account: https://github.com/settings/ssh/new")
        return None

    print(f"   Found {len(candidates)} candidate keys.")

    for key_path in candidates:
        print(f"   Validating: {key_path}...")
        ok, username = validate_github_ssh_key(key_path)
        if ok:
            print(f"✅ Authenticated as GitHub user: {username}")
            print(f"ℹ️  This key will be used to sign your commits automatically.")
            update_env_file(target_repo, "POW_SSH_KEY", key_path)
            return key_path

    # If none validated, fall back to the first one with a warning
    fallback = candidates[0]
    print(f"   ⚠️  None of the discovered keys could validate against GitHub.")
    print(f"      Falling back to: {fallback}")
    print("      Ensure this key is added to your GitHub account before pushing.")
    update_env_file(target_repo, "POW_SSH_KEY", fallback)
    return fallback


def install():
    target_repo = sys.argv[1] if len(sys.argv) > 1 else "."
    hook_dir = os.path.join(target_repo, HOOK_DIR_TPL)

    if not os.path.exists(hook_dir):
        print(f"❌ Error: {hook_dir} does not exist. Are you pointing to the root of a Git repository?")
        return

    ssh_key = setup_github_ssh_mode(target_repo)
    if ssh_key is None:
        print("❌ Aborting: cannot install hooks without a valid SSH key.")
        return

    interp = resolve_best_python()
    if interp is None:
        print("❌ Aborting: Could not find or create a Python environment with 'cryptography' installed.")
        return
    
    interp = interp.replace("\\", "/")
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
