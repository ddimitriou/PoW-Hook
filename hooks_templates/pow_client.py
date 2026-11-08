#!/usr/bin/env python3
"""
PoW-Hook client session logic shared by the pre-commit and pre-merge-commit hooks.

Flow (SPEC.md section A.2, client side):
  1. session_id = uuid4(), tree_hash = git write-tree
  2. dispatch MINT_CHALLENGE to pow-ledger.yml (or STARTED when challenges are off)
  3. run checks_cmd on the repository tree (the real scan)
  4. download the minted challenge corpus, run corpus_cmd on it, compute the receipt
  5. dispatch PASSED / FAILED
  6. write <git-dir>/POW_PASSED for commit-msg to sign

Configuration is the single POW environment variable (JSON), loaded from the
process environment or the repository's .env:
  checks_cmd, corpus_cmd, github_pat_local, github_repo, github_api_url,
  ledger_ref (default main), challenge_timeout (180), challenge_poll (5),
  challenge_optional ("true" to fall back to v1 when minting fails).

Challenges are active when github_pat_local, github_repo and corpus_cmd are
all set.  Without them the hooks fall back to v1 trailers (the server only
accepts those while allow_v1 is "true").
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

for _stream in (sys.stdout, sys.stderr):  # emoji-safe output on cp1252 consoles (Windows hooks)
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pow_trailer import (  # noqa: E402
    CORPUS_DIRNAME, STATUS_FAILED, STATUS_PASSED, cfg_int, cfg_truthy,
    challenge_artifact_name, load_pow_config, receipt_from_jsonl, sha256_hex,
)

MAX_CORPUS_MEMBER = 1 << 20  # 1 MiB per file
MAX_CORPUS_MEMBERS = 500


class ChallengeError(Exception):
    pass


# ---------------------------------------------------------------------------
# Environment / git helpers
# ---------------------------------------------------------------------------

def repo_root():
    return subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).decode().strip()


def git_dir():
    return os.path.abspath(subprocess.check_output(["git", "rev-parse", "--git-dir"]).decode().strip())


def load_env():
    """Load KEY=value lines from the repo's .env into the environment (existing vars win)."""
    try:
        env_path = os.path.join(repo_root(), ".env")
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    if "=" in line and not line.strip().startswith("#"):
                        key, val = line.strip().split("=", 1)
                        val = val.strip().strip("'\"")
                        if key not in os.environ:
                            os.environ[key] = val
    except Exception:
        pass


def api_base(cfg):
    return (cfg.get("github_api_url") or "https://api.github.com").rstrip("/")


def _headers(cfg, extra=None):
    h = {
        "Authorization": f"Bearer {cfg.get('github_pat_local', '')}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "pow-hook",
    }
    if extra:
        h.update(extra)
    return h


# ---------------------------------------------------------------------------
# Ledger dispatch
# ---------------------------------------------------------------------------

def dispatch_attestation(cfg, session_id, tree_hash, state, pow_checks_hash):
    """Fire a workflow_dispatch event to the PoW Attestation Ledger."""
    pat = cfg.get("github_pat_local", "")
    repo = cfg.get("github_repo", "")
    if not pat or not repo:
        print("⚠️  github_pat_local or github_repo not set in POW — skipping server-side attestation.")
        return False

    url = f"{api_base(cfg)}/repos/{repo}/actions/workflows/pow-ledger.yml/dispatches"
    payload = json.dumps({
        "ref": cfg.get("ledger_ref") or "main",
        "inputs": {
            "session_id": session_id,
            "tree_hash": tree_hash,
            "pow_checks_hash": pow_checks_hash,
            "state": state,
        },
    }).encode()
    req = urllib.request.Request(url, data=payload, headers=_headers(cfg, {"Content-Type": "application/json"}))
    try:
        urllib.request.urlopen(req, timeout=30)
        print(f"📡 Attestation dispatched: session={session_id[:8]}… state={state}")
        return True
    except urllib.error.HTTPError as e:
        print(f"⚠️  Attestation dispatch failed ({e.code}): {e.read().decode(errors='replace')[:200]}")
        return False
    except (urllib.error.URLError, OSError) as e:
        print(f"⚠️  Attestation dispatch failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def run_custom_checks(cfg):
    check_cmd = cfg.get("checks_cmd", "")
    if not check_cmd:
        print("✨ No custom checks defined (set checks_cmd in POW to run them).")
        return True
    print(f"✨ Running custom checks: {check_cmd}")
    try:
        subprocess.check_call(check_cmd, shell=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Custom checks failed with exit code {e.returncode}.")
        return False


# ---------------------------------------------------------------------------
# Challenge corpus
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _download_zip(cfg, archive_url):
    """Follow GitHub's 302 to the blob store manually, dropping the auth header."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(archive_url, headers=_headers(cfg))
    try:
        with opener.open(req, timeout=60) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            location = e.headers.get("Location")
            if not location:
                raise ChallengeError("artifact redirect without Location header")
            with urllib.request.urlopen(urllib.request.Request(location, headers={"User-Agent": "pow-hook"}), timeout=60) as resp:
                return resp.read()
        raise ChallengeError(f"artifact download failed (HTTP {e.code})")


def _find_artifact(cfg, name):
    repo = cfg.get("github_repo", "")
    url = f"{api_base(cfg)}/repos/{repo}/actions/artifacts?name={urllib.parse.quote(name)}&per_page=10"
    req = urllib.request.Request(url, headers=_headers(cfg))
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())
    for art in data.get("artifacts", []):
        if art.get("name") == name and not art.get("expired"):
            return art
    return None


def _safe_extract_tar(tar_bytes, dest):
    count = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tar:
        for member in tar:
            name = member.name.replace("\\", "/")
            if member.isdir():
                continue
            if not member.isfile():
                raise ChallengeError(f"corpus contains a non-regular member: {name}")
            if name.startswith("/") or ".." in name.split("/") or not name.startswith(CORPUS_DIRNAME + "/"):
                raise ChallengeError(f"corpus contains an unsafe path: {name}")
            if member.size > MAX_CORPUS_MEMBER:
                raise ChallengeError(f"corpus member too large: {name}")
            count += 1
            if count > MAX_CORPUS_MEMBERS:
                raise ChallengeError("corpus has too many members")
            target = os.path.join(dest, *name.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with tar.extractfile(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
    if count == 0:
        raise ChallengeError("corpus is empty")


def fetch_challenge(cfg, session_id, timeout, poll):
    """
    Poll the ledger for the minted challenge, download and unpack it.
    Returns (challenge_json, tmp_root) where tmp_root/<pow-corpus>/ holds the files.
    """
    name = challenge_artifact_name(session_id)
    deadline = time.monotonic() + timeout
    artifact = None
    last_err = None
    print(f"🧩 Waiting for challenge corpus {name} (timeout {timeout}s)…")
    while time.monotonic() < deadline:
        try:
            artifact = _find_artifact(cfg, name)
            last_err = None
        except (urllib.error.URLError, OSError, ValueError) as e:
            last_err = e
        if artifact:
            break
        time.sleep(poll)
    if not artifact:
        raise ChallengeError(f"challenge did not appear within {timeout}s" + (f" (last error: {last_err})" if last_err else ""))

    zip_bytes = _download_zip(cfg, artifact["archive_download_url"])
    challenge = tar_bytes = None
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for member in zf.namelist():
                if member.endswith("challenge.json"):
                    challenge = json.loads(zf.read(member).decode())
                elif member.endswith("corpus.tar"):
                    tar_bytes = zf.read(member)
    except (zipfile.BadZipFile, ValueError) as e:
        raise ChallengeError(f"challenge artifact is corrupt: {e}")
    if not challenge or tar_bytes is None:
        raise ChallengeError("challenge artifact is missing challenge.json or corpus.tar")
    if challenge.get("session_id") != session_id:
        raise ChallengeError("challenge artifact belongs to another session")

    tmp_root = tempfile.mkdtemp(prefix="pow-challenge-")
    try:
        _safe_extract_tar(tar_bytes, tmp_root)
    except Exception:
        shutil.rmtree(tmp_root, ignore_errors=True)
        raise
    return challenge, tmp_root


def run_corpus_scan(cfg, tmp_root):
    """Run corpus_cmd with {corpus_dir} substituted; return the scanner's stdout."""
    template = cfg.get("corpus_cmd", "")
    mount = tmp_root.replace("\\", "/")
    cmd = template.replace("{corpus_dir}", mount)
    print(f"🧩 Scanning challenge corpus: {cmd}")
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if proc.returncode not in (0, 183):
        raise ChallengeError(f"corpus scan exited {proc.returncode}: {proc.stderr[-400:]}")
    return proc.stdout


def solve_challenge(cfg, session_id):
    timeout = cfg_int(cfg.get("challenge_timeout"), 180)
    poll = cfg_int(cfg.get("challenge_poll"), 5)
    challenge, tmp_root = fetch_challenge(cfg, session_id, timeout, poll)
    try:
        output = run_corpus_scan(cfg, tmp_root)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
    receipt = receipt_from_jsonl(output, challenge.get("tool_version", ""))
    print(f"🧩 Challenge {challenge['challenge_id'][:8]}… solved (receipt {receipt[:12]}…, tool {challenge.get('tool_version')}).")
    return challenge["challenge_id"], receipt


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

def challenge_enabled(cfg):
    return bool(cfg.get("github_pat_local") and cfg.get("github_repo") and cfg.get("corpus_cmd"))


def run_session(kind="Commit"):
    load_env()
    cfg = load_pow_config()

    session_id = str(uuid.uuid4())
    tree_hash = subprocess.check_output(["git", "write-tree"]).decode().strip()
    check_cmd = (cfg.get("checks_cmd") or "").strip() or "none"
    pow_checks_hash = sha256_hex(check_cmd)
    optional = cfg_truthy(cfg.get("challenge_optional"))

    use_challenge = challenge_enabled(cfg)
    dispatched = dispatch_attestation(cfg, session_id, tree_hash,
                                      "MINT_CHALLENGE" if use_challenge else "STARTED", pow_checks_hash)
    if use_challenge and not dispatched:
        if optional:
            print("⚠️  Could not request a challenge; continuing with a v1 attestation (challenge_optional).")
            use_challenge = False
        else:
            print(f"❌ Could not request a challenge from the ledger. {kind} aborted.")
            print("   Set \"challenge_optional\": \"true\" in POW to fall back to v1 attestations.")
            return 1

    passed = run_custom_checks(cfg)

    challenge_id = receipt = None
    if passed and use_challenge:
        try:
            challenge_id, receipt = solve_challenge(cfg, session_id)
        except ChallengeError as e:
            if optional:
                print(f"⚠️  Challenge failed ({e}); continuing with a v1 attestation (challenge_optional).")
            else:
                print(f"❌ Challenge failed: {e}")
                print(f"   {kind} aborted. Set \"challenge_optional\": \"true\" in POW to fall back to v1 attestations.")
                return 1

    status = STATUS_PASSED if passed else STATUS_FAILED
    dispatch_attestation(cfg, session_id, tree_hash, status, pow_checks_hash)

    if not passed:
        print(f"❌ Quality checks failed. {kind} aborted.")
        return 1

    record = {
        "session_id": session_id,
        "status": status,
        "pow_checks_hash": pow_checks_hash,
        "tree_hash": tree_hash,
    }
    if challenge_id:
        record["challenge_id"] = challenge_id
        record["receipt"] = receipt
    with open(os.path.join(git_dir(), "POW_PASSED"), "w") as f:
        json.dump(record, f)
    return 0
