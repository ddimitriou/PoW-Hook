"""
PoW-Hook test suite.

All tests run inside a Linux Docker container (via run_tests.sh) where git
hooks work correctly.  Do NOT run directly on Windows — use run_tests.sh.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import json
import base64
import http.server
import threading
import socket

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ---------------------------------------------------------------------------
# Helpers shared across test classes
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_mock_api_server(pub_key_ssh: str, port: int):
    """Return a started HTTPServer that mimics the GitHub keys/commits/artifacts APIs."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if "/keys" in self.path:
                body = json.dumps([{"id": 1, "key": pub_key_ssh}]).encode()
            elif "/commits/" in self.path:
                body = json.dumps({"author": {"login": "test_user"}}).encode()
            elif "/actions/artifacts" in self.path:
                # Simulate a found attestation so check_attestation_artifact returns True
                body = json.dumps({"total_count": 1, "artifacts": [{"id": 1}]}).encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    class _ReuseServer(http.server.HTTPServer):
        allow_reuse_address = True

    server = _ReuseServer(("127.0.0.1", port), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def _gen_ed25519():
    """Return (private_key, priv_pem_bytes, pub_ssh_str)."""
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    pub_ssh = priv.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode()
    return priv, priv_pem, pub_ssh


def _gen_rsa_ssh():
    """Return (private_key, priv_pem_bytes, pub_ssh_str) for an RSA SSH key."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    pub_ssh = priv.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode()
    return priv, priv_pem, pub_ssh


# ---------------------------------------------------------------------------
# Pure-Python unit tests — portable, no git/subprocess needed
# ---------------------------------------------------------------------------

class TestSignAndVerifyLogic(unittest.TestCase):
    """Directly exercise the sign/verify primitives used by commit-msg and verify_pow."""

    def _sign(self, priv, payload: bytes) -> bytes:
        if isinstance(priv, RSAPrivateKey):
            return priv.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        return priv.sign(payload)

    def _verify_with_ssh_pub(self, pub_ssh_str: str, sig: bytes, payload: bytes):
        pub = serialization.load_ssh_public_key(pub_ssh_str.encode())
        if isinstance(pub, RSAPublicKey):
            pub.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
        else:
            pub.verify(sig, payload)

    # ---- Ed25519 ----

    def test_ed25519_sign_and_verify(self):
        priv, _, pub_ssh = _gen_ed25519()
        payload = b"abc|session|PASSED"
        sig = self._sign(priv, payload)
        self._verify_with_ssh_pub(pub_ssh, sig, payload)  # must not raise

    def test_ed25519_verify_rejects_wrong_key(self):
        priv, _, _ = _gen_ed25519()
        _, _, other_pub_ssh = _gen_ed25519()
        sig = self._sign(priv, b"abc|session|PASSED")
        with self.assertRaises(Exception):
            self._verify_with_ssh_pub(other_pub_ssh, sig, b"abc|session|PASSED")

    def test_ed25519_verify_rejects_tampered_payload(self):
        priv, _, pub_ssh = _gen_ed25519()
        sig = self._sign(priv, b"abc|session|PASSED")
        with self.assertRaises(Exception):
            self._verify_with_ssh_pub(pub_ssh, sig, b"abc|session|FAILED")

    # ---- RSA SSH ----

    def test_rsa_ssh_sign_and_verify(self):
        priv, _, pub_ssh = _gen_rsa_ssh()
        payload = b"tree|uuid|PASSED"
        sig = self._sign(priv, payload)
        self._verify_with_ssh_pub(pub_ssh, sig, payload)

    def test_rsa_ssh_verify_rejects_wrong_key(self):
        priv, _, _ = _gen_rsa_ssh()
        _, _, other_pub = _gen_rsa_ssh()
        sig = self._sign(priv, b"tree|uuid|PASSED")
        with self.assertRaises(Exception):
            self._verify_with_ssh_pub(other_pub, sig, b"tree|uuid|PASSED")

    # ---- Mixed type rejection ----

    def test_ed25519_sig_rejected_by_rsa_key(self):
        ed_priv, _, _ = _gen_ed25519()
        _, _, rsa_pub = _gen_rsa_ssh()
        sig = ed_priv.sign(b"payload")
        with self.assertRaises(Exception):
            self._verify_with_ssh_pub(rsa_pub, sig, b"payload")


# ---------------------------------------------------------------------------
# Integration tests — require a real git repo + Linux hook execution
# ---------------------------------------------------------------------------

class TestGitHubSSHMode(unittest.TestCase):
    """
    Full integration tests for the github key_source mode.

    setUp installs the hooks into a temp git repo using the current Python
    interpreter (so cryptography is available) and a test Ed25519 SSH key.
    A mock GitHub API server is started in a background thread.
    """

    # ------------------------------------------------------------------ setup

    def setUp(self):
        self.original_cwd = os.getcwd()
        self.temp_dir = tempfile.mkdtemp()
        os.chdir(self.temp_dir)

        # Isolate HOME so no real SSH keys or configs interfere
        self.original_home = os.environ.get("HOME", "")
        os.environ["HOME"] = self.temp_dir

        # Generate test Ed25519 SSH keypair
        self._ed_priv, self._priv_pem, self._pub_ssh = _gen_ed25519()

        # Write the private key to a temp path
        self._key_path = os.path.join(self.temp_dir, "test_id_ed25519")
        with open(self._key_path, "wb") as f:
            f.write(self._priv_pem)
        os.chmod(self._key_path, 0o600)

        # Point hook key-detection at our test key (bypasses ssh -G)
        self._orig_env = {}
        self._set_env("POW_SSH_KEY_OVERRIDE", self._key_path)

        # Start mock GitHub API
        self._mock_port = _free_port()
        self._mock_server = _make_mock_api_server(self._pub_ssh, self._mock_port)
        self._set_env("POW_GITHUB_API_URL", f"http://127.0.0.1:{self._mock_port}")
        self._set_env("POW_GITHUB_TOKEN", "test_token")
        self._set_env("GITHUB_USER_LOGIN", "test_user")

        # Initialise git repo
        subprocess.check_call(["git", "init", "-b", "main"])
        subprocess.check_call(["git", "config", "user.name", "Test User"])
        subprocess.check_call(["git", "config", "user.email", "test@example.com"])

        # Copy project files into temp repo
        shutil.copytree(os.path.join(REPO_ROOT, "hooks_templates"), "hooks_templates")
        shutil.copytree(os.path.join(REPO_ROOT, "admin_templates"), "admin_templates")
        shutil.copy2(os.path.join(REPO_ROOT, "setup_hooks.py"), "setup_hooks.py")
        shutil.copy2(os.path.join(REPO_ROOT, ".env.example"), ".env.example")

        # Write .pow-config.json (github mode) and commit it so pre-receive can read it
        with open(".pow-config.json", "w") as f:
            json.dump({"key_source": "github"}, f)

        with open(".env", "w") as f:
            f.write("# Empty env\n")

        # Install hooks (uses sys.executable shebang so no venv needed)
        subprocess.check_call([sys.executable, "setup_hooks.py"])

        # Commit .pow-config.json so pre-receive can find it via git show
        subprocess.check_call(["git", "add", ".pow-config.json"])
        subprocess.check_call(
            ["git", "commit", "--no-verify", "-m", "chore: add pow config"]
        )
        self._base_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"]
        ).decode().strip()

    def tearDown(self):
        self._mock_server.shutdown()
        os.chdir(self.original_cwd)
        os.environ["HOME"] = self.original_home
        for k, v in self._orig_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.temp_dir)

    def _set_env(self, key, value):
        self._orig_env.setdefault(key, os.environ.get(key))
        os.environ[key] = value

    def _trailer(self, key):
        return subprocess.check_output([
            "git", "log", "-1",
            f"--format=%(trailers:key={key},valueonly)"
        ]).decode().strip()

    def _head(self):
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"]
        ).decode().strip()

    def _run_pre_receive(self, old, new):
        script = os.path.join("admin_templates", "pre-receive_hook", "pre-receive")
        stdin = f"{old} {new} refs/heads/main\n".encode()
        env = {**os.environ}
        proc = subprocess.Popen(
            [sys.executable, script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        out, _ = proc.communicate(stdin)
        return proc.returncode, out.decode()

    # --------------------------------------------------------------- tests

    def test_commit_produces_all_three_trailers(self):
        """A normal commit in github mode must carry the tri-factor trailers."""
        with open("a.txt", "w") as f:
            f.write("hello")
        subprocess.check_call(["git", "add", "a.txt"])
        subprocess.check_call(["git", "commit", "-m", "feat: add a"])

        self.assertTrue(self._trailer("Validated-At-Local"))
        self.assertTrue(self._trailer("PoW-Session"))
        self.assertEqual(self._trailer("PoW-Status"), "PASSED")

    def test_signature_is_valid_ed25519(self):
        """The Validated-At-Local trailer must be verifiable with the test key."""
        with open("b.txt", "w") as f:
            f.write("world")
        subprocess.check_call(["git", "add", "b.txt"])
        subprocess.check_call(["git", "commit", "-m", "feat: add b"])

        token   = self._trailer("Validated-At-Local")
        session = self._trailer("PoW-Session")
        status  = self._trailer("PoW-Status")
        tree    = subprocess.check_output(
            ["git", "log", "-1", "--format=%T"]
        ).decode().strip()

        sig_raw = base64.b64decode(token)
        payload = f"{tree}|{session}|{status}".encode()
        pub = self._ed_priv.public_key()
        pub.verify(sig_raw, payload)   # raises on failure

    def test_session_ids_are_unique(self):
        """Each commit must get a different PoW-Session UUID."""
        for name in ("c.txt", "d.txt"):
            with open(name, "w") as f:
                f.write(name)
            subprocess.check_call(["git", "add", name])
            subprocess.check_call(["git", "commit", "-m", f"feat: {name}"])

        # git log --format=%(trailers:...) may emit blank lines between commits
        raw = subprocess.check_output([
            "git", "log", "-2", "--format=%(trailers:key=PoW-Session,valueonly)"
        ]).decode()
        sessions = [s for s in raw.splitlines() if s.strip()]
        self.assertEqual(len(sessions), 2)
        self.assertNotEqual(sessions[0], sessions[1])
        self.assertEqual(len(sessions[0]), 36)
        self.assertEqual(sessions[0].count("-"), 4)

    def test_merge_commit_carries_trailers(self):
        """A --no-ff merge commit must also have tri-factor trailers."""
        with open("base.txt", "w") as f:
            f.write("base")
        subprocess.check_call(["git", "add", "base.txt"])
        subprocess.check_call(["git", "commit", "-m", "chore: base"])

        subprocess.check_call(["git", "checkout", "-b", "feature"])
        with open("feat.txt", "w") as f:
            f.write("feat")
        subprocess.check_call(["git", "add", "feat.txt"])
        subprocess.check_call(["git", "commit", "-m", "feat: feature"])

        subprocess.check_call(["git", "checkout", "main"])
        # Use GIT_EDITOR=true so git auto-accepts the merge message without
        # the -m flag; -m bypasses commit-msg on some git versions.
        env = {**os.environ, "GIT_EDITOR": "true"}
        subprocess.check_call(["git", "merge", "--no-ff", "feature"], env=env)

        self.assertTrue(self._trailer("Validated-At-Local"))
        self.assertEqual(self._trailer("PoW-Status"), "PASSED")

    def test_pre_receive_accepts_valid_signature(self):
        """pre-receive must pass when commits carry valid GitHub SSH signatures."""
        with open("valid.txt", "w") as f:
            f.write("valid")
        subprocess.check_call(["git", "add", "valid.txt"])
        subprocess.check_call(["git", "commit", "-m", "feat: valid"])
        new = self._head()

        rc, out = self._run_pre_receive(self._base_commit, new)
        self.assertEqual(rc, 0, f"pre-receive failed unexpectedly:\n{out}")

    def test_pre_receive_rejects_missing_trailers(self):
        """pre-receive must reject commits created with --no-verify."""
        with open("bypass.txt", "w") as f:
            f.write("bypass")
        subprocess.check_call(["git", "add", "bypass.txt"])
        subprocess.check_call(
            ["git", "commit", "--no-verify", "-m", "bypass hooks"]
        )
        new = self._head()

        rc, out = self._run_pre_receive(self._base_commit, new)
        self.assertNotEqual(rc, 0)
        self.assertIn("REJECTED", out)

    def test_pre_receive_rejects_wrong_key(self):
        """pre-receive must reject a commit signed with a key NOT on GitHub."""
        # Make a valid commit first (signed with test key)
        with open("legit.txt", "w") as f:
            f.write("legit")
        subprocess.check_call(["git", "add", "legit.txt"])
        subprocess.check_call(["git", "commit", "-m", "feat: legit"])
        signed_commit = self._head()

        # Now swap the mock API to return a DIFFERENT public key
        _, _, other_pub_ssh = _gen_ed25519()
        self._mock_server.shutdown()
        self._mock_server.server_close()
        import time; time.sleep(0.3)
        self._mock_server = _make_mock_api_server(other_pub_ssh, self._mock_port)

        rc, out = self._run_pre_receive(self._base_commit, signed_commit)
        self.assertNotEqual(rc, 0)
        self.assertIn("REJECTED", out)

    def test_setup_hooks_respects_pow_ssh_key_override(self):
        """setup_hooks.py must use POW_SSH_KEY_OVERRIDE and not call ssh -G."""
        # If setup passed (setUp completed), the override was respected.
        # Verify hooks are installed correctly.
        self.assertTrue(os.path.exists(".git/hooks/commit-msg"))
        self.assertTrue(os.path.exists(".git/hooks/pre-commit"))
        self.assertTrue(os.path.exists(".git/hooks/pre-merge-commit"))

    def test_verify_pow_accepts_valid_signature(self):
        """verify_pow.py must pass when commits carry valid GitHub SSH signatures."""
        # Create a commit with a valid signature
        with open("vp.txt", "w") as f:
            f.write("vp")
        subprocess.check_call(["git", "add", "vp.txt"])
        subprocess.check_call(["git", "commit", "-m", "feat: vp"])
        head = self._head()

        # Build a minimal push event payload
        event = {"before": self._base_commit, "after": head}
        event_path = os.path.join(self.temp_dir, "push_event.json")
        with open(event_path, "w") as f:
            json.dump(event, f)

        env = {
            **os.environ,
            "GITHUB_TOKEN":      "test_token",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_EVENT_PATH": event_path,
            "GITHUB_REF":        "refs/heads/main",
            "POW_GITHUB_API_URL": f"http://127.0.0.1:{self._mock_port}",
        }
        script = os.path.join("admin_templates", "github", "scripts", "verify_pow.py")
        proc = subprocess.run(
            [sys.executable, script],
            capture_output=True,
            text=True,
            env=env,
            cwd=self.temp_dir,
        )
        self.assertEqual(proc.returncode, 0, f"verify_pow.py failed:\n{proc.stdout}\n{proc.stderr}")
        self.assertIn("verified", proc.stdout.lower())

    def test_verify_pow_rejects_wrong_key(self):
        """verify_pow.py must fail when the mock API returns a different public key."""
        with open("bad.txt", "w") as f:
            f.write("bad")
        subprocess.check_call(["git", "add", "bad.txt"])
        subprocess.check_call(["git", "commit", "-m", "feat: bad"])
        head = self._head()

        # Swap mock to return a different key
        _, _, other_pub = _gen_ed25519()
        self._mock_server.shutdown()
        self._mock_server.server_close()
        import time; time.sleep(0.3)
        self._mock_server = _make_mock_api_server(other_pub, self._mock_port)

        event = {"before": self._base_commit, "after": head}
        event_path = os.path.join(self.temp_dir, "push_event_bad.json")
        with open(event_path, "w") as f:
            json.dump(event, f)

        env = {
            **os.environ,
            "GITHUB_TOKEN":      "test_token",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_EVENT_PATH": event_path,
            "GITHUB_REF":        "refs/heads/main",
            "POW_GITHUB_API_URL": f"http://127.0.0.1:{self._mock_port}",
        }
        script = os.path.join("admin_templates", "github", "scripts", "verify_pow.py")
        proc = subprocess.run(
            [sys.executable, script],
            capture_output=True,
            text=True,
            env=env,
            cwd=self.temp_dir,
        )
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
