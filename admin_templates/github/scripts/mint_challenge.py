#!/usr/bin/env python3
"""
PoW-Hook challenge minter (runs inside pow-ledger.yml; SPEC.md section A).

Builds a small corpus of files containing K planted, detectable secrets and
M decoys (near-miss strings the pinned scanner provably ignores), scans it
once with the pinned scanner to self-check, and publishes

    challenge.json  {challenge_id, session_id, tool_version, scanner_image,
                     tag, created_at, format}
    corpus.tar      pow-corpus/<files>

where tag = HMAC-SHA256(POW_HMAC_KEY, challenge_id|session_id|R_expected) and
R_expected is the canonical receipt (pow_trailer.compute_receipt) over the
findings the scanner actually produced on this corpus.

Configuration (POW JSON env var)
--------------------------------
  hmac_key                required - never printed
  scanner_image           default trufflesecurity/trufflehog:3.99.8 (env POW_SCANNER_IMAGE also honoured)

Runner plumbing (plain env vars set by the workflow / tests)
-----------------------------------------------------------
  POW_SESSION_ID          required - UUID chosen by the client
  POW_SCANNER_VERSION     override the tool version string (skips docker --version)
  POW_MINT_SCAN_CMD       override the scan command; "{corpus_dir}" is replaced by the
                          directory that *contains* pow-corpus/ (testing / non-docker setups)
  POW_MINT_PLANT_TYPES    comma-separated subset of plant generators to use (testing)
  POW_MINT_ATTEMPTS       self-check retries, default 3

Usage: mint_challenge.py --out DIR
Planted values are never printed.
"""
import argparse
import json
import os
import random
import re
import secrets
import shutil
import string
import subprocess
import sys
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone

for _stream in (sys.stdout, sys.stderr):  # emoji-safe output on cp1252 consoles
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pow_trailer import (  # noqa: E402
    CORPUS_DIRNAME, canonical_corpus_path, challenge_tag, compute_receipt,
    finding_line, load_pow_config, parse_scanner_jsonl,
)

DEFAULT_IMAGE = "trufflesecurity/trufflehog:3.99.8"
B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
UPPER_DIGITS = string.ascii_uppercase + string.digits
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

_sysrand = random.SystemRandom()


def rnd(alphabet, n):
    return "".join(secrets.choice(alphabet) for _ in range(n))


# ---------------------------------------------------------------------------
# Plant / decoy generators
# Each returns (plant_pairs, decoy_pairs) where *pairs* is a list of
# (variable_name, value).  Decoys are the same shape made undetectable
# (too short / wrong prefix / missing companion).  Every generator below was
# validated against trufflehog 3.99.8 in all seven file formats (plant found,
# decoy ignored); the self-check at mint time re-validates every corpus.
# ---------------------------------------------------------------------------

def g_github_pat():
    return [("GITHUB_TOKEN", "ghp_" + rnd(B62, 36))], [("GITHUB_TOKEN", "ghp_" + rnd(B62, 35))]


def g_aws():
    secret = rnd(ALNUM + "+/", 40)
    plant = [("AWS_ACCESS_KEY_ID", "AKIA" + rnd(UPPER_DIGITS, 16)), ("AWS_SECRET_ACCESS_KEY", secret)]
    decoy = [("AWS_ACCESS_KEY_ID", "AKIA" + rnd(UPPER_DIGITS, 15)), ("AWS_SECRET_ACCESS_KEY", rnd(ALNUM + "+/", 40))]
    return plant, decoy


def g_stripe():
    return [("STRIPE_SECRET_KEY", "sk_live_" + rnd(ALNUM, 24))], [("STRIPE_SECRET_KEY", "sk_live_" + rnd(ALNUM, 19))]


def g_sendgrid():
    return ([("SENDGRID_API_KEY", f"SG.{rnd(ALNUM + '-_', 22)}.{rnd(ALNUM + '-_', 43)}")],
            [("SENDGRID_API_KEY", f"SG.{rnd(ALNUM + '-_', 22)}.{rnd(ALNUM + '-_', 30)}")])


def g_slack():
    return ([("SLACK_BOT_TOKEN", f"xoxb-{rnd(string.digits, 12)}-{rnd(string.digits, 12)}-{rnd(ALNUM, 24)}")],
            [("SLACK_BOT_TOKEN", f"xoxb-{rnd(string.digits, 8)}-{rnd(string.digits, 12)}-{rnd(ALNUM, 24)}")])


def g_huggingface():
    return [("HF_TOKEN", "hf_" + rnd(ALNUM, 34))], [("HF_TOKEN", "hf_" + rnd(ALNUM, 33))]


def g_npm():
    return [("NPM_TOKEN", "npm_" + rnd(ALNUM, 36))], [("NPM_TOKEN", "npm_" + rnd(ALNUM, 35))]


def g_digitalocean():
    return [("DIGITALOCEAN_TOKEN", "dop_v1_" + rnd(HEX, 64))], [("DIGITALOCEAN_TOKEN", "dop_v1_" + rnd(HEX, 63))]


def g_gitlab():
    return [("GITLAB_TOKEN", "glpat-" + rnd(ALNUM + "_-", 20))], [("GITLAB_TOKEN", "glpat-" + rnd(ALNUM + "_-", 19))]


def g_dockerhub():
    return [("DOCKERHUB_TOKEN", "dckr_pat_" + rnd(ALNUM + "_-", 27))], [("DOCKERHUB_TOKEN", "dckr_pat_" + rnd(ALNUM + "_-", 26))]


def g_telegram():
    return ([("TELEGRAM_BOT_TOKEN", f"{rnd(string.digits, 10)}:AA{rnd(ALNUM + '_-', 33)}")],
            [("TELEGRAM_BOT_TOKEN", f"{rnd(string.digits, 7)}:AA{rnd(ALNUM + '_-', 33)}")])


def g_mailchimp():
    return [("MAILCHIMP_API_KEY", f"{rnd(HEX, 32)}-us{_sysrand.randint(1, 20)}")], \
           [("MAILCHIMP_API_KEY", f"{rnd(HEX, 31)}-us{_sysrand.randint(1, 20)}")]


GENERATORS = {
    "github_pat": g_github_pat,
    "aws": g_aws,
    "stripe": g_stripe,
    "sendgrid": g_sendgrid,
    "slack": g_slack,
    "huggingface": g_huggingface,
    "npm": g_npm,
    "digitalocean": g_digitalocean,
    "gitlab": g_gitlab,
    "dockerhub": g_dockerhub,
    "telegram": g_telegram,
    "mailchimp": g_mailchimp,
}

# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

WORDS = ["alpha", "beta", "config", "deploy", "local", "prod", "staging", "service",
         "worker", "client", "legacy", "notes", "settings", "secrets", "runtime",
         "pipeline", "env", "backend", "gateway", "cache", "queue", "report", "ops"]
DIRS = ["", "src/", "config/", "docs/", "scripts/", "tests/", "deploy/"]
EXTS = [".py", ".env", ".json", ".md", ".yaml", ".txt", ".ini"]


def render(ext, pairs):
    if ext == ".py":
        return "import os\n\n" + "".join(f'{k} = os.environ.get("{k}", "{v}")\n' for k, v in pairs)
    if ext == ".json":
        return json.dumps({k.lower(): v for k, v in pairs}, indent=2) + "\n"
    if ext == ".yaml":
        return "".join(f"{k.lower()}: \"{v}\"\n" for k, v in pairs)
    if ext == ".md":
        return "# Deployment notes\n\n" + "".join(f"- {k}: `{v}`\n" for k, v in pairs)
    if ext == ".ini":
        return "[credentials]\n" + "".join(f"{k.lower()} = {v}\n" for k, v in pairs)
    # .env / .txt
    return "".join(f"{k}={v}\n" for k, v in pairs)


FILLERS = [
    (".py", "def healthcheck():\n    return {\"status\": \"ok\", \"version\": \"1.4.2\"}\n"),
    (".md", "# Runbook\n\nRestart the worker with `systemctl restart worker`.\n"),
    (".json", "{\n  \"name\": \"gateway\",\n  \"version\": \"2.0.1\",\n  \"private\": true\n}\n"),
    (".yaml", "server:\n  port: 8080\n  workers: 4\nlogging:\n  level: info\n"),
    (".env", "APP_ENV=production\nLOG_LEVEL=warn\nPORT=8080\n"),
    (".txt", "TODO: rotate certificates before the next release.\n"),
    (".ini", "[server]\nhost = 0.0.0.0\nport = 9000\n"),
]


def unique_path(used):
    while True:
        name = f"{_sysrand.choice(DIRS)}{_sysrand.choice(WORDS)}_{_sysrand.choice(WORDS)}{rnd(string.digits, 2)}"
        if name not in used:
            used.add(name)
            return name


def build_corpus(workdir, plant_types):
    """Write pow-corpus/ under workdir.  Returns (plant_paths, decoy_paths, total_files)."""
    corpus = os.path.join(workdir, CORPUS_DIRNAME)
    if os.path.exists(corpus):
        shutil.rmtree(corpus)
    os.makedirs(corpus)

    k = _sysrand.randint(3, min(8, len(plant_types)))
    m = _sysrand.randint(5, 15)
    chosen = _sysrand.sample(plant_types, k)
    used, plant_paths, decoy_paths = set(), [], []

    for label in chosen:
        plant, _ = GENERATORS[label]()
        ext = _sysrand.choice(EXTS)
        rel = unique_path(used) + ext
        plant_paths.append(rel)
        _write(corpus, rel, render(ext, plant))

    for _ in range(m):
        label = _sysrand.choice(plant_types)
        _, decoy = GENERATORS[label]()
        ext = _sysrand.choice(EXTS)
        rel = unique_path(used) + ext
        decoy_paths.append(rel)
        _write(corpus, rel, render(ext, decoy))

    total = _sysrand.randint(max(20, k + m + 2), 50)
    for _ in range(total - k - m):
        ext, body = _sysrand.choice(FILLERS)
        rel = unique_path(used) + ext
        _write(corpus, rel, body)

    return plant_paths, decoy_paths, total


def _write(corpus, rel, content):
    path = os.path.join(corpus, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="\n") as f:
        f.write(content)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def run_scanner(workdir, image):
    override = os.environ.get("POW_MINT_SCAN_CMD")
    mount = workdir.replace("\\", "/")
    if override:
        cmd = override.replace("{corpus_dir}", mount)
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    else:
        cmd = ["docker", "run", "--rm", "-v", f"{mount}:/pwd", image,
               "filesystem", "/pwd", "--no-verification", "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 183):  # 183 = trufflehog "findings present" with --fail
        raise RuntimeError(f"scanner exited {proc.returncode}: {proc.stderr[-400:]}")
    return proc.stdout


def scanner_version(image):
    override = os.environ.get("POW_SCANNER_VERSION")
    if override:
        return override.strip()
    proc = subprocess.run(["docker", "run", "--rm", image, "--version"], capture_output=True, text=True)
    text = (proc.stdout + "\n" + proc.stderr).strip()
    m = re.search(r"trufflehog\s+v?[\w.\-+]+", text)
    if not m:
        raise RuntimeError(f"could not determine scanner version from: {text[:200]!r}")
    return m.group(0)


def self_check(findings, plant_paths):
    """Every plant found, nothing else flagged.  Returns (ok, problems)."""
    found_paths = {canonical_corpus_path(f["file"]) for f in findings}
    plants = set(plant_paths)
    problems = []
    for missing in sorted(plants - found_paths):
        problems.append(f"plant not detected: {missing}")
    for extra in sorted(found_paths - plants):
        problems.append(f"unexpected finding in: {extra}")
    return not problems, problems


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="output directory for challenge.json and corpus.tar")
    args = ap.parse_args()

    cfg = load_pow_config()
    key = cfg.get("hmac_key") or ""
    session_id = os.environ.get("POW_SESSION_ID", "").strip().lower()
    image = cfg.get("scanner_image") or os.environ.get("POW_SCANNER_IMAGE") or DEFAULT_IMAGE
    attempts = int(os.environ.get("POW_MINT_ATTEMPTS", "3"))
    if not key:
        print("❌ hmac_key is not set in POW (add the POW_HMAC_KEY repository/environment secret).", file=sys.stderr)
        sys.exit(2)
    if not UUID_RE.match(session_id):
        print("❌ POW_SESSION_ID must be a lowercase UUID.", file=sys.stderr)
        sys.exit(2)

    plant_types = [t.strip() for t in os.environ.get("POW_MINT_PLANT_TYPES", "").split(",") if t.strip()]
    plant_types = plant_types or list(GENERATORS)
    unknown = [t for t in plant_types if t not in GENERATORS]
    if unknown:
        print(f"❌ unknown plant types: {unknown}", file=sys.stderr)
        sys.exit(2)
    if len(plant_types) < 3:
        print("❌ need at least 3 plant types.", file=sys.stderr)
        sys.exit(2)

    tool_version = scanner_version(image)
    os.makedirs(args.out, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix="pow-mint-")
    try:
        findings = None
        for attempt in range(1, attempts + 1):
            plant_paths, decoy_paths, total = build_corpus(workdir, plant_types)
            output = run_scanner(workdir, image)
            findings = parse_scanner_jsonl(output)
            ok, problems = self_check(findings, plant_paths)
            if ok:
                break
            print(f"⚠️  self-check attempt {attempt}/{attempts} failed:", file=sys.stderr)
            for p in problems:
                print(f"   - {p}", file=sys.stderr)
        else:
            print("❌ could not build a corpus the pinned scanner classifies as intended.", file=sys.stderr)
            sys.exit(1)

        lines = [finding_line(f["detector"], f["file"], f["line"], f["raw"]) for f in findings]
        receipt = compute_receipt(lines, tool_version)
        challenge_id = str(uuid.uuid4())
        tag = challenge_tag(key, challenge_id, session_id, receipt)

        tar_path = os.path.join(args.out, "corpus.tar")
        with tarfile.open(tar_path, "w") as tar:
            tar.add(os.path.join(workdir, CORPUS_DIRNAME), arcname=CORPUS_DIRNAME, filter=_tar_filter)

        challenge = {
            "format": 1,
            "challenge_id": challenge_id,
            "session_id": session_id,
            "tool_version": tool_version,
            "scanner_image": image,
            "tag": tag,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        with open(os.path.join(args.out, "challenge.json"), "w") as f:
            json.dump(challenge, f, indent=2)
            f.write("\n")

        print(json.dumps({
            "challenge_id": challenge_id,
            "session_id": session_id,
            "tool_version": tool_version,
            "plants": len(plant_paths),
            "decoys": len(decoy_paths),
            "files": total,
            "findings": len(lines),
            "attempt": attempt,
        }))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _tar_filter(info):
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    return info


if __name__ == "__main__":
    main()
