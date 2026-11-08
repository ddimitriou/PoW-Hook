"""
PoW-Hook test suite.

Git hooks only execute reliably on Linux, so run this inside the CI container
or via tests/run_tests_windows.sh.  No Docker/trufflehog is needed: the
challenge protocol is exercised end-to-end against tests/fake_scanner.py and
the in-process mock GitHub API (tests/test_mock_github_api.py).

All configuration flows through the single POW JSON environment variable,
exactly as in production.
"""
import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import uuid as uuid_mod

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
SCRIPTS_DIR = os.path.join(REPO_ROOT, "admin_templates", "github", "scripts")
HOOKS_DIR = os.path.join(REPO_ROOT, "hooks_templates")
sys.path.insert(0, SCRIPTS_DIR)
sys.path.insert(0, TESTS_DIR)

from pow_trailer import (  # noqa: E402
    STATUS_PASSED, TRAILER_KEY, ZERO_SHA, build_sign_payload, canonical_corpus_path,
    challenge_tag, compute_receipt, decode_pow_trailer, encode_pow_trailer,
    finding_line, load_pow_config, parse_scanner_jsonl, receipt_from_jsonl, sha256_hex,
)
from test_mock_github_api import MockState, free_port, serve  # noqa: E402

FAKE_SCANNER = os.path.join(TESTS_DIR, "fake_scanner.py")
VERIFY_POW = os.path.join(SCRIPTS_DIR, "verify_pow.py")
SWEEP_AUDIT = os.path.join(SCRIPTS_DIR, "sweep_audit.py")
MINT_CHALLENGE = os.path.join(SCRIPTS_DIR, "mint_challenge.py")
PRE_RECEIVE = os.path.join(REPO_ROOT, "admin_templates", "pre-receive_hook", "pre-receive")
HMAC_KEY = "unit-test-hmac-key"
NONE_HASH = sha256_hex("none")
RUN = dict(capture_output=True, encoding="utf-8", errors="replace")


def pow_json(**cfg):
    return json.dumps(cfg, separators=(",", ":"))


def _gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                             serialization.NoEncryption())
    pub = priv.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                         serialization.PublicFormat.OpenSSH).decode()
    return priv, pem, pub


def _gen_rsa_ssh():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                             serialization.NoEncryption())
    pub = priv.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                         serialization.PublicFormat.OpenSSH).decode()
    return priv, pem, pub


# ---------------------------------------------------------------------------
# Pure-Python unit tests
# ---------------------------------------------------------------------------

class TestPowConfig(unittest.TestCase):
    def test_loads_json_object(self):
        self.assertEqual(load_pow_config({"POW": '{"checks_cmd":"x","enforce":"true"}'}),
                         {"checks_cmd": "x", "enforce": "true"})

    def test_invalid_or_missing_is_empty(self):
        self.assertEqual(load_pow_config({}), {})
        self.assertEqual(load_pow_config({"POW": ""}), {})
        self.assertEqual(load_pow_config({"POW": "not json"}), {})
        self.assertEqual(load_pow_config({"POW": "[1,2]"}), {})


class TestTrailerCodec(unittest.TestCase):
    def test_v1_roundtrip(self):
        sid = str(uuid_mod.uuid4())
        t = decode_pow_trailer(encode_pow_trailer(b"\x01" * 64, sid, "PASSED", "ab" * 32))
        self.assertEqual((t.version, t.session_id, t.status, t.checks_hash), (1, sid, "PASSED", "ab" * 32))
        self.assertIsNone(t.challenge_id)
        self.assertFalse(t.is_v2)
        self.assertFalse(t.legacy_json)

    def test_v2_roundtrip(self):
        sid, cid = str(uuid_mod.uuid4()), str(uuid_mod.uuid4())
        t = decode_pow_trailer(encode_pow_trailer(b"\x02" * 64, sid, "PASSED", "ab" * 32, cid, "cd" * 32, "ef" * 20))
        self.assertTrue(t.is_v2)
        self.assertEqual((t.challenge_id, t.receipt, t.anchor_sha), (cid, "cd" * 32, "ef" * 20))
        self.assertEqual(t.sign_payload("tree"), build_sign_payload("ab" * 32, "tree", sid, "PASSED", cid, "cd" * 32, "ef" * 20))

    def test_legacy_json_bundle_decodes_as_v1(self):
        """Trailers written by the pre-binary hooks (base64 JSON bundle) stay verifiable."""
        sid = str(uuid_mod.uuid4())
        bundle = json.dumps({"token": base64.b64encode(b"\x07" * 64).decode(), "session": sid,
                             "status": "PASSED", "checks_hash": "AB" * 32}, separators=(",", ":"))
        t = decode_pow_trailer(base64.b64encode(bundle.encode()).decode())
        self.assertEqual((t.version, t.session_id, t.status, t.checks_hash, t.sig), (1, sid, "PASSED", "ab" * 32, b"\x07" * 64))
        self.assertTrue(t.legacy_json)
        self.assertEqual(t.sign_payload("tree"), build_sign_payload("ab" * 32, "tree", sid, "PASSED"))
        for broken in ('{"token":"","session":"x"}', '{"session":"%s"}' % sid, "{not json"):
            with self.assertRaises(ValueError):
                decode_pow_trailer(base64.b64encode(broken.encode()).decode())

    def test_payload_layouts(self):
        self.assertEqual(build_sign_payload("h", "t", "s", "PASSED"), b"h|t|s|PASSED")
        self.assertEqual(build_sign_payload("h", "t", "s", "PASSED", "c", "r", "a"), b"h|t|s|PASSED|c|r|a")

    def test_rejects_malformed(self):
        sid, cid = str(uuid_mod.uuid4()), str(uuid_mod.uuid4())
        good = encode_pow_trailer(b"\x02" * 64, sid, "PASSED", "ab" * 32, cid, "cd" * 32, "ef" * 20)
        raw = base64.b64decode(good)
        for bad in (raw[:-5], raw + b"\x00", bytes([0x07]) + raw[1:], raw[:1 + 2 + 64 + 16] + b"\x05" + raw[1 + 2 + 64 + 17:]):
            with self.assertRaises(ValueError):
                decode_pow_trailer(base64.b64encode(bad).decode())
        with self.assertRaises(ValueError):
            decode_pow_trailer("not base64!!")

    def test_status_byte_values(self):
        sid = str(uuid_mod.uuid4())
        self.assertEqual(decode_pow_trailer(encode_pow_trailer(b"s", sid, "FAILED", "00" * 32)).status, "FAILED")
        with self.assertRaises(ValueError):
            encode_pow_trailer(b"s", sid, "MAYBE", "00" * 32)


class TestReceipt(unittest.TestCase):
    def test_canonical_path_is_mount_independent(self):
        self.assertEqual(canonical_corpus_path("/pwd/pow-corpus/src/a.py"), "src/a.py")
        self.assertEqual(canonical_corpus_path("C:\\Temp\\x\\pow-corpus\\b.env"), "b.env")
        self.assertEqual(canonical_corpus_path("/tmp/pow-corpus/pow-corpus-ish/c.txt"), "pow-corpus-ish/c.txt")

    def test_receipt_is_order_and_duplicate_independent(self):
        a = finding_line("Github", "/x/pow-corpus/a.py", 1, "secret-a")
        b = finding_line("Stripe", "/y/pow-corpus/b.env", 3, "secret-b")
        self.assertEqual(compute_receipt([a, b], "v1"), compute_receipt([b, a, a], "v1"))
        self.assertNotEqual(compute_receipt([a, b], "v1"), compute_receipt([a, b], "v2"))
        self.assertNotEqual(compute_receipt([a], "v1"), compute_receipt([a, b], "v1"))

    def test_parse_jsonl_skips_noise(self):
        text = "\n".join([
            '{"level":"info","msg":"running"}',
            '{"SourceMetadata":{"Data":{"Filesystem":{"file":"/pwd/pow-corpus/a.py","line":2}}},"DetectorName":"Github","Raw":"ghp_x"}',
            "not json",
            '{"SourceMetadata":{"Data":{"Git":{"commit":"abc","file":"a.txt","line":1}}},"DetectorName":"Stripe","Raw":"sk"}',
        ])
        parsed = parse_scanner_jsonl(text)
        self.assertEqual([(p["detector"], p["line"], p["commit"]) for p in parsed],
                         [("Github", 2, None), ("Stripe", 1, "abc")])
        self.assertEqual(receipt_from_jsonl(text, "t"),
                         compute_receipt([finding_line("Github", "/pwd/pow-corpus/a.py", 2, "ghp_x"),
                                          finding_line("Stripe", "a.txt", 1, "sk")], "t"))

    def test_tag_depends_on_every_input(self):
        base = challenge_tag("k", "c", "s", "r")
        self.assertNotEqual(base, challenge_tag("K", "c", "s", "r"))
        self.assertNotEqual(base, challenge_tag("k", "c", "s", "R"))
        self.assertEqual(len(base), 64)


class TestSignAndVerifyLogic(unittest.TestCase):
    def _sign(self, priv, payload):
        if isinstance(priv, RSAPrivateKey):
            return priv.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        return priv.sign(payload)

    def _verify(self, pub_ssh, sig, payload):
        pub = serialization.load_ssh_public_key(pub_ssh.encode())
        if isinstance(pub, RSAPublicKey):
            pub.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
        else:
            pub.verify(sig, payload)

    def test_ed25519_sign_and_verify(self):
        priv, _, pub = _gen_ed25519()
        self._verify(pub, self._sign(priv, b"abc|session|PASSED"), b"abc|session|PASSED")

    def test_ed25519_verify_rejects_wrong_key(self):
        priv, _, _ = _gen_ed25519()
        _, _, other = _gen_ed25519()
        with self.assertRaises(Exception):
            self._verify(other, self._sign(priv, b"p"), b"p")

    def test_ed25519_verify_rejects_tampered_payload(self):
        priv, _, pub = _gen_ed25519()
        with self.assertRaises(Exception):
            self._verify(pub, self._sign(priv, b"abc|session|PASSED"), b"abc|session|FAILED")

    def test_rsa_ssh_sign_and_verify(self):
        priv, _, pub = _gen_rsa_ssh()
        self._verify(pub, self._sign(priv, b"tree|uuid|PASSED"), b"tree|uuid|PASSED")

    def test_ed25519_sig_rejected_by_rsa_key(self):
        ed_priv, _, _ = _gen_ed25519()
        _, _, rsa_pub = _gen_rsa_ssh()
        with self.assertRaises(Exception):
            self._verify(rsa_pub, ed_priv.sign(b"payload"), b"payload")


class TestCorpusExtraction(unittest.TestCase):
    """pow_client must refuse hostile corpus tarballs."""

    def setUp(self):
        sys.path.insert(0, HOOKS_DIR)
        import pow_client  # noqa: F401
        self.pow_client = pow_client

    def _tar(self, entries):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for name, data in entries:
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def test_accepts_well_formed_corpus(self):
        dest = tempfile.mkdtemp()
        try:
            self.pow_client._safe_extract_tar(self._tar([("pow-corpus/src/a.py", b"x = 1\n")]), dest)
            self.assertTrue(os.path.exists(os.path.join(dest, "pow-corpus", "src", "a.py")))
        finally:
            shutil.rmtree(dest)

    def test_rejects_traversal_and_foreign_paths(self):
        dest = tempfile.mkdtemp()
        try:
            for name in ("pow-corpus/../evil", "/etc/passwd", "other/a.py"):
                with self.assertRaises(self.pow_client.ChallengeError):
                    self.pow_client._safe_extract_tar(self._tar([(name, b"x")]), dest)
            self.assertEqual(os.listdir(dest), [])
        finally:
            shutil.rmtree(dest)


class TestMintChallenge(unittest.TestCase):
    """mint_challenge.py end-to-end against the fake scanner (no Docker)."""

    def _env(self, pow_cfg=None, **extra):
        cfg = {"hmac_key": HMAC_KEY} if pow_cfg is None else pow_cfg
        env = {**os.environ, "POW": pow_json(**cfg), "POW_SESSION_ID": str(uuid_mod.uuid4()),
               "POW_SCANNER_VERSION": "fake-scanner 1.0",
               "POW_MINT_SCAN_CMD": f'"{sys.executable}" "{FAKE_SCANNER}" "{{corpus_dir}}"',
               "POW_MINT_PLANT_TYPES": "github_pat,stripe,huggingface"}
        env.update(extra)
        return env

    def test_mint_produces_verifiable_challenge(self):
        out = tempfile.mkdtemp()
        try:
            env = self._env()
            proc = subprocess.run([sys.executable, MINT_CHALLENGE, "--out", out], env=env, **RUN)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout.strip().splitlines()[-1])
            self.assertGreaterEqual(summary["plants"], 3)
            self.assertGreaterEqual(summary["decoys"], 5)
            self.assertGreaterEqual(summary["files"], 20)
            with open(os.path.join(out, "challenge.json")) as f:
                challenge = json.load(f)
            self.assertEqual(challenge["session_id"], env["POW_SESSION_ID"])
            self.assertNotIn("plants", challenge)

            # Client side: unpack, scan with the same scanner, recompute the receipt.
            work = tempfile.mkdtemp()
            try:
                with tarfile.open(os.path.join(out, "corpus.tar")) as tar:
                    tar.extractall(work)
                scan = subprocess.run([sys.executable, FAKE_SCANNER, work], check=True, **RUN)
                receipt = receipt_from_jsonl(scan.stdout, challenge["tool_version"])
                self.assertEqual(len(scan.stdout.strip().splitlines()), summary["plants"])
                self.assertEqual(challenge_tag(HMAC_KEY, challenge["challenge_id"], challenge["session_id"], receipt),
                                 challenge["tag"])
                # A lazy client that reports nothing cannot produce the tag.
                self.assertNotEqual(challenge_tag(HMAC_KEY, challenge["challenge_id"], challenge["session_id"],
                                                  compute_receipt([], challenge["tool_version"])), challenge["tag"])
            finally:
                shutil.rmtree(work)
        finally:
            shutil.rmtree(out)

    def test_mint_requires_key(self):
        out = tempfile.mkdtemp()
        try:
            proc = subprocess.run([sys.executable, MINT_CHALLENGE, "--out", out], env=self._env(pow_cfg={}), **RUN)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("hmac_key", proc.stderr)
        finally:
            shutil.rmtree(out)


# ---------------------------------------------------------------------------
# Integration tests — real git repo, hooks installed, mock GitHub API
# ---------------------------------------------------------------------------

class RepoTestCase(unittest.TestCase):
    V2 = False  # subclasses set True to enable the challenge protocol in the client POW config

    def setUp(self):
        self.original_cwd = os.getcwd()
        self.temp_dir = tempfile.mkdtemp()
        os.chdir(self.temp_dir)
        self._orig_env = {}
        self._set_env("HOME", self.temp_dir)
        self._set_env("POW_HOOK_PYTHON", sys.executable)

        self._ed_priv, self._priv_pem, self._pub_ssh = _gen_ed25519()
        self._key_path = os.path.join(self.temp_dir, "test_id_ed25519")
        with open(self._key_path, "wb") as f:
            f.write(self._priv_pem)
        os.chmod(self._key_path, 0o600)
        self._set_env("POW_SSH_KEY_OVERRIDE", self._key_path)  # for setup_hooks.py

        self.state = MockState([self._pub_ssh], hmac_key=HMAC_KEY)
        self.port = free_port()
        self.server = serve(self.state, self.port)
        self.api_url = f"http://127.0.0.1:{self.port}"

        # Client configuration for the hooks: the POW JSON in the environment
        # takes precedence over the POW line setup_hooks.py writes to .env.
        self._client_cfg = {"ssh_key_override": self._key_path, "github_api_url": self.api_url}
        if self.V2:
            self._client_cfg.update({
                "github_pat_local": "test_pat",
                "github_repo": "owner/repo",
                "corpus_cmd": f'"{sys.executable}" "{FAKE_SCANNER}" "{{corpus_dir}}"',
                "challenge_timeout": 20,
                "challenge_poll": 1,
            })
        self._set_pow()

        subprocess.check_call(["git", "init", "-q"])
        subprocess.check_call(["git", "checkout", "-q", "-b", "main"])
        subprocess.check_call(["git", "config", "user.name", "Test User"])
        subprocess.check_call(["git", "config", "user.email", "test@example.com"])

        shutil.copytree(HOOKS_DIR, "hooks_templates")
        shutil.copytree(os.path.join(REPO_ROOT, "admin_templates"), "admin_templates")
        shutil.copy2(os.path.join(REPO_ROOT, "setup_hooks.py"), "setup_hooks.py")
        shutil.copy2(os.path.join(REPO_ROOT, ".env.example"), ".env.example")
        with open(".env", "w") as f:
            f.write("# test repo\n")

        subprocess.check_call([sys.executable, "setup_hooks.py"], stdout=subprocess.DEVNULL)

        with open("README.md", "w") as f:
            f.write("# test repo\n")
        subprocess.check_call(["git", "add", "README.md"])
        subprocess.check_call(["git", "commit", "-q", "--no-verify", "-m", "chore: initial setup"])
        self.base = self._head()

        subprocess.check_call(["git", "init", "-q", "--bare", os.path.join(self.temp_dir, "remote.git")])
        subprocess.check_call(["git", "remote", "add", "origin", os.path.join(self.temp_dir, "remote.git")])
        subprocess.check_call(["git", "push", "-q", "-u", "origin", "main"])

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        os.chdir(self.original_cwd)
        for k, v in self._orig_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ---- helpers -----------------------------------------------------------

    def _set_env(self, key, value):
        self._orig_env.setdefault(key, os.environ.get(key))
        os.environ[key] = value

    def _set_pow(self, **overrides):
        """Set the client-side POW JSON seen by the hooks."""
        self._client_cfg.update(overrides)
        self._set_env("POW", pow_json(**self._client_cfg))

    def _head(self):
        return subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()

    def _remote_head(self):
        return subprocess.check_output(["git", "--git-dir", os.path.join(self.temp_dir, "remote.git"),
                                        "rev-parse", "main"]).decode().strip()

    def _push(self):
        subprocess.check_call(["git", "push", "-q", "origin", "main"])

    def _trailer(self, rev="HEAD"):
        raw = subprocess.check_output(["git", "log", "-1", f"--format=%(trailers:key={TRAILER_KEY},valueonly)", rev]).decode()
        return next((ln.strip() for ln in raw.splitlines() if ln.strip()), "")

    def _tree(self, rev="HEAD"):
        return subprocess.check_output(["git", "log", "-1", "--format=%T", rev]).decode().strip()

    def _commit(self, name, content=None, msg=None, no_verify=False, expect_ok=True):
        with open(name, "w") as f:
            f.write(content if content is not None else name)
        subprocess.check_call(["git", "add", name])
        cmd = ["git", "commit", "-q"] + (["--no-verify"] if no_verify else []) + ["-m", msg or f"feat: {name}"]
        proc = subprocess.run(cmd, **RUN)
        if expect_ok:
            self.assertEqual(proc.returncode, 0, f"commit failed:\n{proc.stdout}\n{proc.stderr}")
            return self._head()
        return proc

    def _crafted_commit(self, name, session_id, status="PASSED", v2=None, legacy_json=False):
        """Commit with a hand-signed trailer (bypasses hooks)."""
        with open(name, "w") as f:
            f.write(name)
        subprocess.check_call(["git", "add", name])
        tree = subprocess.check_output(["git", "write-tree"]).decode().strip()
        if v2:
            cid, receipt, anchor = v2
            payload = build_sign_payload(NONE_HASH, tree, session_id, status, cid, receipt, anchor)
            trailer = encode_pow_trailer(self._ed_priv.sign(payload), session_id, status, NONE_HASH, cid, receipt, anchor)
        else:
            payload = build_sign_payload(NONE_HASH, tree, session_id, status)
            sig = self._ed_priv.sign(payload)
            if legacy_json:
                bundle = json.dumps({"token": base64.b64encode(sig).decode(), "session": session_id,
                                     "status": status, "checks_hash": NONE_HASH}, separators=(",", ":"))
                trailer = base64.b64encode(bundle.encode()).decode()
            else:
                trailer = encode_pow_trailer(sig, session_id, status, NONE_HASH)
        subprocess.check_call(["git", "commit", "-q", "--allow-empty", "--no-verify",
                               "-m", f"crafted {name}\n\n{TRAILER_KEY}: {trailer}"])
        return self._head()

    def _server_cfg(self, **overrides):
        cfg = {"enforce": "true", "github_api_url": self.api_url, "allow_v1": "true", "hmac_key": HMAC_KEY}
        cfg.update(overrides)
        return cfg

    def _run_verify(self, base, head, event="push", ref="main", env_extra=None, **cfg_overrides):
        if event == "pull_request":
            payload = {"pull_request": {"base": {"sha": base}, "head": {"sha": head, "ref": ref}}}
        else:
            payload = {"before": base, "after": head}
        event_path = os.path.join(self.temp_dir, f"event-{uuid_mod.uuid4().hex}.json")
        with open(event_path, "w") as f:
            json.dump(payload, f)
        env = {
            **os.environ,
            "GITHUB_TOKEN": "test_token",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_EVENT_NAME": event,
            "GITHUB_EVENT_PATH": event_path,
            "GITHUB_REF": f"refs/heads/{ref}",
            "POW": pow_json(**self._server_cfg(**cfg_overrides)),
        }
        env.update(env_extra or {})
        proc = subprocess.run([sys.executable, VERIFY_POW], env=env, cwd=self.temp_dir, **RUN)
        return proc.returncode, proc.stdout + proc.stderr

    def _run_pre_receive(self, old, new, **cfg_overrides):
        cfg = {"github_token": "test_token", "github_api_url": self.api_url}
        cfg.update(cfg_overrides)
        env = {**os.environ, "POW": pow_json(**cfg), "GITHUB_USER_LOGIN": "test_user"}
        proc = subprocess.run([sys.executable, PRE_RECEIVE], input=f"{old} {new} refs/heads/main\n",
                              env=env, **RUN)
        return proc.returncode, proc.stdout


class TestV1Mode(RepoTestCase):
    """Hooks without ledger configuration produce v1 trailers."""

    def test_setup_installs_hooks_and_modules(self):
        for name in ("pre-commit", "commit-msg", "pre-merge-commit", "pow_client.py", "pow_trailer.py"):
            self.assertTrue(os.path.exists(os.path.join(".git", "hooks", name)), name)

    def test_setup_writes_ssh_key_into_pow_json(self):
        with open(".env") as f:
            pow_line = next(ln for ln in f if ln.startswith("POW="))
        cfg = json.loads(pow_line[4:].strip().strip("'\""))
        self.assertEqual(cfg["ssh_key"], self._key_path)

    def test_commit_produces_v1_trailer(self):
        self._commit("a.txt")
        t = decode_pow_trailer(self._trailer())
        self.assertEqual((t.version, t.status, t.checks_hash), (1, "PASSED", NONE_HASH))
        self.assertFalse(os.path.exists(os.path.join(".git", "POW_PASSED")))

    def test_signature_is_valid_over_v1_payload(self):
        self._commit("b.txt")
        t = decode_pow_trailer(self._trailer())
        self._ed_priv.public_key().verify(t.sig, t.sign_payload(self._tree()))

    def test_session_ids_are_unique(self):
        self._commit("c.txt")
        self._commit("d.txt")
        s1 = decode_pow_trailer(self._trailer("HEAD")).session_id
        s2 = decode_pow_trailer(self._trailer("HEAD~1")).session_id
        self.assertNotEqual(s1, s2)
        self.assertEqual(len(s1), 36)

    def test_merge_commit_carries_trailer(self):
        self._commit("base.txt")
        subprocess.check_call(["git", "checkout", "-q", "-b", "feature"])
        self._commit("feat.txt")
        subprocess.check_call(["git", "checkout", "-q", "main"])
        env = {**os.environ, "GIT_EDITOR": "true"}
        subprocess.check_call(["git", "merge", "-q", "--no-ff", "feature"], env=env)
        t = decode_pow_trailer(self._trailer())
        self.assertEqual(t.status, "PASSED")

    def test_checks_cmd_runs_and_blocks(self):
        self._set_pow(checks_cmd="exit 3")
        proc = self._commit("blocked.txt", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("exit code 3", proc.stdout + proc.stderr)
        self.assertEqual(self._head(), self.base)

    def test_pre_receive_accepts_valid_signature(self):
        new = self._commit("valid.txt")
        rc, out = self._run_pre_receive(self.base, new)
        self.assertEqual(rc, 0, out)

    def test_pre_receive_rejects_missing_trailer(self):
        new = self._commit("bypass.txt", no_verify=True)
        rc, out = self._run_pre_receive(self.base, new)
        self.assertNotEqual(rc, 0)
        self.assertIn("REJECTED", out)

    def test_pre_receive_rejects_wrong_key(self):
        new = self._commit("legit.txt")
        _, _, other = _gen_ed25519()
        self.state.pub_keys = [other]
        rc, out = self._run_pre_receive(self.base, new)
        self.assertNotEqual(rc, 0)
        self.assertIn("No matching", out)

    def test_pre_receive_rejects_v1_when_disallowed(self):
        new = self._commit("v1only.txt")
        rc, out = self._run_pre_receive(self.base, new, allow_v1="false")
        self.assertNotEqual(rc, 0)
        self.assertIn("v1 trailer", out)

    def test_verify_pow_accepts_v1_when_allowed(self):
        head = self._commit("vp.txt")
        rc, out = self._run_verify(self.base, head)
        self.assertEqual(rc, 0, out)
        self.assertIn("verified", out.lower())

    def test_verify_pow_disabled_without_enforce(self):
        head = self._commit("ne.txt", no_verify=True)
        rc, out = self._run_verify(self.base, head, enforce="false")
        self.assertEqual(rc, 0)
        self.assertIn("validation is disabled", out)

    def test_verify_pow_rejects_v1_when_disallowed(self):
        head = self._commit("vp2.txt")
        rc, out = self._run_verify(self.base, head, allow_v1="false")
        self.assertNotEqual(rc, 0)
        self.assertIn("REJECTED", out)
        self.assertIn("v1 trailer", out)

    def test_legacy_json_trailer_is_accepted_like_v1(self):
        head = self._crafted_commit("legacy.txt", str(uuid_mod.uuid4()), legacy_json=True)
        rc, out = self._run_verify(self.base, head)
        self.assertEqual(rc, 0, out)
        self.assertIn("legacy JSON", out)
        rc, out = self._run_verify(self.base, head, allow_v1="false")
        self.assertNotEqual(rc, 0)
        rc, out = self._run_pre_receive(self.base, head)
        self.assertEqual(rc, 0, out)

    def test_verify_pow_rejects_bypass_without_rewriting(self):
        head = self._commit("bypass.txt", no_verify=True)
        self._push()
        rc, out = self._run_verify(self.base, head, auto_revert="true")
        self.assertNotEqual(rc, 0)
        self.assertIn("REJECTED", out)
        self.assertEqual(self._remote_head(), head, "policy failures must never rewrite refs")

    def test_server_side_check_rejects_failing_tree(self):
        """Zero-trust fallback: the validator re-runs checks_cmd on the pushed tree."""
        cmd = 'test -z "$POW_TEST_FAIL_SERVER"'
        self._set_pow(checks_cmd=cmd)
        head = self._commit("srv.txt")
        rc, out = self._run_verify(self.base, head, checks_cmd=cmd)
        self.assertEqual(rc, 0, out)
        self.assertIn("Server-side check passed", out)
        rc, out = self._run_verify(self.base, head, checks_cmd=cmd, env_extra={"POW_TEST_FAIL_SERVER": "1"})
        self.assertNotEqual(rc, 0)
        self.assertIn("server-side re-run", out)
        self.assertIn("REJECTED", out)


class TestValidatorHardening(RepoTestCase):
    """SPEC.md section 0: status byte, no destructive false positives, no shell injection."""

    def test_signed_failed_attestation_is_rejected(self):
        head = self._crafted_commit("failed.txt", str(uuid_mod.uuid4()), status="FAILED")
        rc, out = self._run_verify(self.base, head)
        self.assertNotEqual(rc, 0)
        self.assertIn("status is FAILED", out)
        rc, out = self._run_pre_receive(self.base, head)
        self.assertNotEqual(rc, 0)
        self.assertIn("not PASSED", out)

    def test_wrong_key_is_invalid_but_not_reverted_by_default(self):
        head = self._commit("bad.txt")
        self._push()
        _, _, other = _gen_ed25519()
        self.state.pub_keys = [other]
        rc, out = self._run_verify(self.base, head)
        self.assertNotEqual(rc, 0)
        self.assertIn("INVALID", out)
        self.assertEqual(self._remote_head(), head)

    def test_wrong_key_with_auto_revert_resets_branch(self):
        head = self._commit("bad2.txt")
        self._push()
        self.state.pub_keys = [_gen_ed25519()[2]]
        self.state.open_prs = [{"number": 7}]
        rc, out = self._run_verify(self.base, head, auto_revert="true")
        self.assertNotEqual(rc, 0)
        self.assertIn("INVALID", out)
        self.assertEqual(self._remote_head(), self.base)
        self.assertEqual(self.state.closed_prs, [7])
        self.assertTrue(any("INVALID" in c["body"] for c in self.state.comments))

    def test_api_failure_is_inconclusive_and_never_reverts(self):
        head = self._commit("flaky.txt")
        self._push()
        self.state.fail_keys = True
        rc, out = self._run_verify(self.base, head, auto_revert="true")
        self.assertNotEqual(rc, 0)
        self.assertIn("INCONCLUSIVE", out)
        self.assertEqual(self._remote_head(), head)

    def test_unlinked_author_is_rejected_not_reverted(self):
        head = self._commit("unlinked.txt")
        self._push()
        self.state.author_login = None
        rc, out = self._run_verify(self.base, head, auto_revert="true")
        self.assertNotEqual(rc, 0)
        self.assertIn("REJECTED", out)
        self.assertIn("not linked", out)
        self.assertEqual(self._remote_head(), head)

    def test_hostile_ref_name_is_not_interpreted_by_a_shell(self):
        head = self._commit("evil.txt")
        self._push()
        self.state.pub_keys = [_gen_ed25519()[2]]
        marker = os.path.join(self.temp_dir, "pwned")
        ref = f"feat;touch {marker};echo"
        rc, out = self._run_verify(self.base, head, event="pull_request", ref=ref, auto_revert="true")
        self.assertNotEqual(rc, 0)
        self.assertFalse(os.path.exists(marker), "ref name reached a shell")
        self.assertIn("failed validation", out)
        self.assertEqual(self._remote_head(), head)


class TestV2Challenge(RepoTestCase):
    """SPEC.md section A: challenge corpus, v2 trailer, HMAC receipt verification."""
    V2 = True

    def test_commit_produces_v2_trailer_and_dispatches(self):
        self._commit("a.txt")
        t = decode_pow_trailer(self._trailer())
        self.assertTrue(t.is_v2)
        self.assertEqual(t.anchor_sha, ZERO_SHA)  # HEAD~1 of the root commit does not exist
        self.assertEqual(t.status, STATUS_PASSED)
        self._ed_priv.public_key().verify(t.sig, t.sign_payload(self._tree()))
        states = [d["state"] for d in self.state.dispatches]
        self.assertEqual(states, ["MINT_CHALLENGE", "PASSED"])
        ch = self.state.challenges[t.session_id]["challenge"]
        self.assertEqual(t.challenge_id, ch["challenge_id"])
        self.assertEqual(t.receipt, ch["_receipt"])
        self.assertEqual(self.state.dispatches[0]["ref"], "main")

    def test_verify_pow_accepts_v2_without_v1_allowance(self):
        head = self._commit("ok.txt")
        rc, out = self._run_verify(self.base, head, allow_v1="false")
        self.assertEqual(rc, 0, out)
        self.assertIn("Challenge receipt verified", out)

    def test_pre_receive_accepts_v2(self):
        head = self._commit("pr.txt")
        rc, out = self._run_pre_receive(self.base, head, allow_v1="false")
        self.assertEqual(rc, 0, out)
        self.assertIn("trailer v2", out)

    def test_second_commit_binds_parent_anchor(self):
        self._commit("one.txt")
        second = self._commit("two.txt")
        t = decode_pow_trailer(self._trailer())
        self.assertEqual(t.anchor_sha, self.base)  # HEAD~1 at hook time = parent of `one`
        rc, out = self._run_verify(self.base, second, allow_v1="false")
        self.assertEqual(rc, 0, out)

    def test_amend_still_verifies(self):
        self._commit("one.txt")
        self._commit("two.txt")
        proc = subprocess.run(["git", "commit", "-q", "--amend", "-m", "feat: two (amended)"], **RUN)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        rc, out = self._run_verify(self.base, self._head(), allow_v1="false")
        self.assertEqual(rc, 0, out)

    def test_wrong_hmac_key_is_invalid(self):
        head = self._commit("hm.txt")
        rc, out = self._run_verify(self.base, head, hmac_key="some-other-key")
        self.assertNotEqual(rc, 0)
        self.assertIn("INVALID", out)
        self.assertIn("minted tag", out)

    def test_missing_hmac_key_is_inconclusive(self):
        head = self._commit("nokey.txt")
        self._push()
        rc, out = self._run_verify(self.base, head, hmac_key="", auto_revert="true")
        self.assertNotEqual(rc, 0)
        self.assertIn("INCONCLUSIVE", out)
        self.assertEqual(self._remote_head(), head)

    def test_challenge_from_foreign_workflow_is_rejected(self):
        head = self._commit("foreign.txt")
        self.state.ledger_path = ".github/workflows/evil.yml"
        rc, out = self._run_verify(self.base, head)
        self.assertNotEqual(rc, 0)
        self.assertIn("REJECTED", out)
        self.assertIn("evil.yml", out)

    def test_challenge_minted_on_other_branch_is_rejected(self):
        head = self._commit("branch.txt")
        self.state.ledger_branch = "feature/tamper"
        rc, out = self._run_verify(self.base, head)
        self.assertNotEqual(rc, 0)
        self.assertIn("feature/tamper", out)

    def test_replayed_trailer_fails_anchor_check(self):
        first = self._commit("x.txt")
        trailer = self._trailer()
        # Same tree, different lineage: a child of `first` with an identical tree.
        subprocess.check_call(["git", "commit", "-q", "--allow-empty", "--no-verify",
                               "-m", f"replay\n\n{TRAILER_KEY}: {trailer}"])
        replay = self._head()
        self.assertEqual(self._tree(replay), self._tree(first))
        rc, out = self._run_verify(first, replay)
        self.assertNotEqual(rc, 0)
        self.assertIn("anchor", out)
        rc, out = self._run_pre_receive(first, replay)
        self.assertNotEqual(rc, 0)
        self.assertIn("anchor", out)

    def test_tampered_receipt_is_invalid(self):
        """A client that skips the corpus scan cannot produce an acceptable receipt."""
        empty_receipt = compute_receipt([], "fake-scanner 1.0")
        sid = str(uuid_mod.uuid4())
        # Mint a real challenge for this session via the mock ledger, then sign an empty receipt.
        import urllib.request
        req = urllib.request.Request(f"{self.api_url}/repos/owner/repo/actions/workflows/pow-ledger.yml/dispatches",
                                     data=json.dumps({"ref": "main", "inputs": {"session_id": sid, "state": "MINT_CHALLENGE",
                                                                                "tree_hash": "x", "pow_checks_hash": NONE_HASH}}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req)
        cid = self.state.challenges[sid]["challenge"]["challenge_id"]
        head = self._crafted_commit("lazy.txt", sid, v2=(cid, empty_receipt, ZERO_SHA))
        rc, out = self._run_verify(self.base, head)
        self.assertNotEqual(rc, 0)
        self.assertIn("INVALID", out)

    def test_challenge_timeout_aborts_commit(self):
        self.state.challenge_delay = 120
        self._set_pow(challenge_timeout=2)
        proc = self._commit("slow.txt", expect_ok=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Challenge failed", proc.stdout + proc.stderr)
        self.assertEqual(self._head(), self.base)

    def test_challenge_optional_falls_back_to_v1(self):
        self.state.challenge_delay = 120
        self._set_pow(challenge_timeout=2, challenge_optional="true")
        self._commit("fallback.txt")
        t = decode_pow_trailer(self._trailer())
        self.assertFalse(t.is_v2)
        self.assertEqual(t.status, STATUS_PASSED)


class TestSweep(RepoTestCase):
    """SPEC.md section B: nightly cross-reference of findings against trailers."""
    V2 = True

    def _finding(self, sha, path, raw, detector="Github", line=1):
        return json.dumps({"SourceMetadata": {"Data": {"Git": {"commit": sha, "file": path, "line": line,
                                                                "email": "Test User <test@example.com>"}}},
                           "DetectorName": detector, "Raw": raw, "Verified": False})

    def _run_sweep(self, findings, state_file=None, scanner_version="fake-scanner 1.0", **cfg_overrides):
        out_dir = os.path.join(self.temp_dir, f"sweep-{uuid_mod.uuid4().hex}")
        findings_path = os.path.join(self.temp_dir, f"findings-{uuid_mod.uuid4().hex}.jsonl")
        with open(findings_path, "w") as f:
            f.write("\n".join(findings) + "\n")
        cfg = {"github_api_url": self.api_url, "admin_handles": "@sec-team", "sweep_epoch": self.base}
        cfg.update(cfg_overrides)
        env = {**os.environ, "POW": pow_json(**cfg), "POW_FINDINGS_FILE": findings_path, "POW_SWEEP_OUT_DIR": out_dir,
               "GITHUB_TOKEN": "test_token", "GITHUB_REPOSITORY": "owner/repo", "POW_SCANNER_VERSION": scanner_version}
        if state_file:
            env["POW_SWEEP_STATE_FILE"] = state_file
        proc = subprocess.run([sys.executable, SWEEP_AUDIT], env=env, cwd=self.temp_dir, **RUN)
        with open(os.path.join(out_dir, "report.json")) as f:
            report = json.load(f)
        return proc, report, out_dir

    def _classes(self, report):
        return {(r["sha"], r["classification"]) for r in report["results"]}

    def test_classification_issue_webhook_and_watermark(self):
        honest = self._commit("clean.py", "x = 1\n")
        forged = self._commit("leak.py", 'TOKEN = "ghp_' + "A" * 36 + '"\n')          # hooks ran, but "scanner" missed it
        leak = self._commit("bypass.env", "TOKEN=ghp_" + "B" * 36 + "\n", no_verify=True)
        missing = self._commit("plain.txt", no_verify=True)
        shared = str(uuid_mod.uuid4())
        replay1 = self._crafted_commit("r1.txt", shared)
        replay2 = self._crafted_commit("r2.txt", shared)

        findings = [self._finding(forged, "leak.py", "ghp_" + "A" * 36),
                    self._finding(leak, "bypass.env", "ghp_" + "B" * 36)]
        proc, report, out_dir = self._run_sweep(findings, revoke_webhook=f"{self.api_url}/webhook",
                                                revoke_webhook_token="hook-token")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        classes = self._classes(report)
        self.assertIn((forged, "FORGERY"), classes)
        self.assertIn((leak, "LEAK_HONEST"), classes)
        self.assertIn((missing, "MISSING"), classes)
        self.assertIn((replay1, "REPLAY"), classes)
        self.assertIn((replay2, "REPLAY"), classes)
        self.assertNotIn(honest, {sha for sha, _ in classes})
        self.assertNotIn(self.base, {sha for sha, _ in classes})
        self.assertEqual(report["meta"]["violations"], 4)

        forgery = next(r for r in report["results"] if r["sha"] == forged)
        self.assertEqual(forgery["author_login"], "test_user")
        self.assertIn("fake-scanner 1.0", forgery["reason"])
        self.assertNotIn("ghp_" + "A" * 36, json.dumps(report), "raw secrets must never be written to the report")

        self.assertEqual(len(self.state.issues), 1)
        self.assertIn("4 violation", self.state.issues[0]["title"])
        self.assertIn("@sec-team", self.state.issues[0]["body"])
        self.assertEqual(len(self.state.webhooks), 4)
        self.assertEqual(self.state.webhooks[0]["auth"], "Bearer hook-token")
        self.assertTrue(all("ghp_" not in json.dumps(w["body"]) for w in self.state.webhooks))

        # Second run with the saved state: nothing new -> green, issue updated not duplicated.
        proc2, report2, _ = self._run_sweep(findings, state_file=os.path.join(out_dir, "state.json"))
        self.assertEqual(proc2.returncode, 0, proc2.stdout + proc2.stderr)
        self.assertEqual(report2["meta"]["new_violations"], 0)
        self.assertEqual(len(self.state.issues), 1)
        self.assertEqual(len(self.state.webhooks), 4)

        # sweep_fail_on=any keeps the run red while violations persist.
        proc3, _, _ = self._run_sweep(findings, state_file=os.path.join(out_dir, "state.json"), sweep_fail_on="any")
        self.assertEqual(proc3.returncode, 1)

    def test_version_drift_is_a_warning_not_a_forgery(self):
        forged = self._commit("leak.py", 'TOKEN = "ghp_' + "C" * 36 + '"\n')
        proc, report, _ = self._run_sweep([self._finding(forged, "leak.py", "ghp_" + "C" * 36)],
                                          scanner_version="fake-scanner 9.9")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn((forged, "VERSION_DRIFT"), self._classes(report))
        self.assertEqual(len(self.state.issues), 0)

    def test_baseline_suppresses_pre_epoch_findings(self):
        # A secret introduced before the epoch (the base commit) must not page anyone.
        findings = [self._finding(self.base, "README.md", "ghp_" + "D" * 36)]
        self._commit("clean.txt")
        proc, report, _ = self._run_sweep(findings)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(report["meta"]["findings_suppressed"], 1)
        self.assertEqual(report["results"], [])

    def test_inconclusive_when_api_fails(self):
        forged = self._commit("leak.py", 'TOKEN = "ghp_' + "E" * 36 + '"\n')
        self.state.fail_keys = True
        proc, report, _ = self._run_sweep([self._finding(forged, "leak.py", "ghp_" + "E" * 36)])
        self.assertEqual(proc.returncode, 0)
        self.assertIn((forged, "INCONCLUSIVE"), self._classes(report))


if __name__ == "__main__":
    unittest.main()
