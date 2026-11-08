#!/usr/bin/env python3
"""
PoW-Hook nightly audit sweep (SPEC.md section B).

Cross-references a full-history trufflehog scan (JSON lines, git source)
against the PoW-Checks attestation trailers embedded in every commit.

Classification per post-epoch commit
------------------------------------
  FORGERY        trailer PASSED + valid signature + cmd hash matches
                 + attested tool version matches (or is unknown)
                 + the sweep found a secret introduced by this commit.
                 Cryptographic evidence: the author's own signature over a
                 false verdict.
  VERSION_DRIFT  as FORGERY but the attested scanner version differs from the
                 sweep's scanner version (warning, not a verdict).
  LEAK_HONEST    secret found, but the trailer is absent / FAILED / malformed
                 / unverifiable - the validator should have blocked this.
  REPLAY         the same session_id or challenge_id appears on more than one
                 commit with a verifying signature.
  MISSING        no / malformed trailer and no finding (report only).
  INCONCLUSIVE   API error while verifying a candidate (retried next night).

Violations (FORGERY, REPLAY, LEAK_HONEST) are written to the report, posted
to a single tracking issue, optionally POSTed to POW_REVOKE_WEBHOOK, and make
the run exit 1 (new violations by default; POW_SWEEP_FAIL_ON=any for every run).

Configuration (POW JSON env var)
--------------------------------
  checks_cmd               command whose hash honest trailers must carry
  github_api_url           GitHub Enterprise API base (optional)
  admin_handles            e.g. "@alice @security"
  revoke_webhook           optional URL; revoke_webhook_token optional bearer token
  sweep_epoch              enforcement epoch.  A commit SHA (that commit and its
                           ancestors are pre-epoch), an ISO-8601 date or epoch
                           seconds.  Default: the oldest commit carrying a trailer.
  sweep_fail_on            new | any   (default new)
  sweep_no_issue           "true" to skip issue management (testing)

Runner plumbing (plain env vars set by the workflow / tests)
-----------------------------------------------------------
  POW_FINDINGS_FILE        trufflehog JSONL (required)
  POW_SCANNER_VERSION      version string of the scanner used by this sweep
  POW_SWEEP_OUT_DIR        default ./pow-sweep-out
  POW_SWEEP_STATE_FILE     local state.json (else the newest pow-sweep-state artifact is used)
  GITHUB_TOKEN, GITHUB_REPOSITORY
"""
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

for _stream in (sys.stdout, sys.stderr):  # emoji-safe output on cp1252 consoles
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pow_trailer import (  # noqa: E402
    STATUS_PASSED, TRAILER_KEY, cfg_truthy, challenge_artifact_name, decode_pow_trailer,
    first_trailer_value, load_pow_config, parse_scanner_jsonl, sha256_hex,
)
from pow_github import (  # noqa: E402
    ApiError, api_base, api_call, api_json, download_artifact_zip, fetch_ssh_keys,
    find_artifact, read_challenge_json, read_zip_member, resolve_author_login,
    verify_signature,
)

FORGERY = "FORGERY"
VERSION_DRIFT = "VERSION_DRIFT"
LEAK_HONEST = "LEAK_HONEST"
REPLAY = "REPLAY"
MISSING = "MISSING"
INCONCLUSIVE = "INCONCLUSIVE"
VIOLATIONS = (FORGERY, REPLAY, LEAK_HONEST)

STATE_ARTIFACT = "pow-sweep-state"
ISSUE_TITLE_PREFIX = "🚨 PoW Sweep:"
ISSUE_LABEL = "pow-sweep"
BASELINE_FILE = ".pow-baseline.json"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class Commit:
    sha: str
    parents: List[str]
    tree: str
    ctime: int
    author_name: str
    author_email: str
    trailer_b64: str


@dataclass
class Result:
    sha: str
    classification: str
    reason: str
    author_login: Optional[str] = None
    author_email: str = ""
    findings: List[dict] = field(default_factory=list)
    trailer: Optional[dict] = None
    related: List[str] = field(default_factory=list)

    @property
    def violation_id(self):
        return f"{self.classification}:{self.sha}"


def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode(errors="replace").strip()


def fingerprint(f):
    return sha256_hex(f"{f['detector']}|{f['file']}|{sha256_hex(f['raw'])}")


def normalize_version(text):
    """Same normalisation mint_challenge.py applies: 'trufflehog 3.99.8' out of any banner."""
    text = (text or "").strip()
    m = re.search(r"trufflehog\s+v?[\w.\-+]+", text)
    return m.group(0) if m else text


def redact_finding(f):
    return {
        "detector": f["detector"],
        "file": f["file"],
        "line": f["line"],
        "secret_sha256": sha256_hex(f["raw"]),
        "fingerprint": fingerprint(f),
    }


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def load_findings(path) -> Dict[str, List[dict]]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        findings = parse_scanner_jsonl(fh.read())
    by_sha: Dict[str, List[dict]] = {}
    for f in findings:
        sha = (f.get("commit") or "").strip()
        if sha:
            by_sha.setdefault(sha, []).append(f)
    return by_sha


def enumerate_commits() -> List[Commit]:
    fmt = "%H%x1f%P%x1f%T%x1f%ct%x1f%an%x1f%ae%x1f%(trailers:key=" + TRAILER_KEY + ",valueonly)"
    out = subprocess.check_output(["git", "log", "--all", "--date-order", "-z", f"--format={fmt}"],
                                  stderr=subprocess.DEVNULL).decode(errors="replace")
    commits = []
    for rec in out.split("\0"):
        if not rec.strip():
            continue
        parts = rec.split("\x1f")
        if len(parts) < 7:
            continue
        sha, parents, tree, ctime, an, ae, trailer = parts[:7]
        trailer_b64 = first_trailer_value(trailer)
        commits.append(Commit(sha.strip(), parents.split(), tree.strip(), int(ctime), an, ae, trailer_b64))
    return commits


def decode(commit: Commit):
    if not commit.trailer_b64:
        return None, "no trailer"
    try:
        return decode_pow_trailer(commit.trailer_b64), ""
    except ValueError as e:
        return None, f"malformed trailer ({e})"


# ---------------------------------------------------------------------------
# Enforcement epoch
# ---------------------------------------------------------------------------

def resolve_epoch(commits: List[Commit], raw: str) -> Optional[dict]:
    """
    Returns {"kind": "sha", "value": <sha>} (that commit and its ancestors are
    pre-epoch), {"kind": "ts", "value": <epoch seconds>} or None when no commit
    carries a trailer yet (nothing to classify).
    """
    raw = (raw or "").strip()
    if raw:
        if SHA_RE.match(raw):
            if not any(c.sha == raw for c in commits):
                raise SystemExit(f"POW_SWEEP_EPOCH commit {raw} is not reachable")
            return {"kind": "sha", "value": raw}
        if raw.isdigit():
            return {"kind": "ts", "value": int(raw)}
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return {"kind": "ts", "value": int(dt.timestamp())}
    with_trailer = [c.ctime for c in commits if decode(c)[0] is not None]
    return {"kind": "ts", "value": min(with_trailer)} if with_trailer else None


def post_epoch_shas(commits: List[Commit], epoch: Optional[dict]) -> set:
    if epoch is None:
        return set()
    if epoch["kind"] == "sha":
        try:
            pre = set(git("rev-list", epoch["value"]).split())
        except subprocess.CalledProcessError:
            pre = set()
        return {c.sha for c in commits if c.sha not in pre}
    return {c.sha for c in commits if c.ctime >= epoch["value"]}


def describe_epoch(epoch):
    if epoch is None:
        return "not established (no attested commits yet)"
    if epoch["kind"] == "sha":
        return f"after commit {epoch['value']}"
    return datetime.fromtimestamp(epoch["value"], tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Classification (pure; verifier / version lookup are injected for testing)
# ---------------------------------------------------------------------------

def classify(commits, findings_by_sha, post_shas, baseline, expected_hash, sweep_tool_version,
             verifier, tool_version_lookup):
    """
    verifier(commit, trailer) -> (status, login, note) with status in VALID / INVALID / INCONCLUSIVE
    tool_version_lookup(trailer) -> version string or None
    """
    results: List[Result] = []
    post = [c for c in commits if c.sha in post_shas]
    verified_cache = {}

    def verify(commit, trailer):
        if commit.sha not in verified_cache:
            verified_cache[commit.sha] = verifier(commit, trailer)
        return verified_cache[commit.sha]

    for c in post:
        trailer, why = decode(c)
        live = [f for f in findings_by_sha.get(c.sha, []) if fingerprint(f) not in baseline]
        tdict = _trailer_dict(trailer)

        if live:
            redacted = [redact_finding(f) for f in live]
            if trailer is None:
                results.append(Result(c.sha, LEAK_HONEST, f"secret present; {why}", None, c.author_email, redacted, tdict))
                continue
            if trailer.status != STATUS_PASSED:
                results.append(Result(c.sha, LEAK_HONEST, "secret present; trailer honestly says FAILED", None, c.author_email, redacted, tdict))
                continue
            if trailer.checks_hash != expected_hash:
                results.append(Result(c.sha, LEAK_HONEST, "secret present; trailer carries an unexpected checks_cmd hash", None, c.author_email, redacted, tdict))
                continue
            status, login, note = verify(c, trailer)
            if status == "INCONCLUSIVE":
                results.append(Result(c.sha, INCONCLUSIVE, f"secret present; signature check failed: {note}", login, c.author_email, redacted, tdict))
                continue
            if status == "INVALID":
                results.append(Result(c.sha, LEAK_HONEST, f"secret present; PASSED trailer does not verify ({note})", login, c.author_email, redacted, tdict))
                continue
            attested_version = normalize_version(tool_version_lookup(trailer)) if trailer.is_v2 else None
            if attested_version and sweep_tool_version and attested_version != sweep_tool_version:
                results.append(Result(c.sha, VERSION_DRIFT,
                                      f"PASSED attestation by {login} with scanner {attested_version!r}; sweep uses {sweep_tool_version!r}",
                                      login, c.author_email, redacted, tdict))
                continue
            vers = attested_version or "unknown (v1 trailer or expired challenge artifact)"
            results.append(Result(c.sha, FORGERY,
                                  f"PASSED attestation signed by {login} over a tree containing a secret (attested scanner: {vers})",
                                  login, c.author_email, redacted, tdict))
        elif trailer is None:
            results.append(Result(c.sha, MISSING, why, None, c.author_email, [], None))

    # REPLAY: identical session / challenge ids across verifying commits
    groups: Dict[str, List[Commit]] = {}
    decoded: Dict[str, object] = {}
    for c in post:
        trailer, _ = decode(c)
        if trailer is None:
            continue
        decoded[c.sha] = trailer
        groups.setdefault(f"session:{trailer.session_id}", []).append(c)
        if trailer.challenge_id:
            groups.setdefault(f"challenge:{trailer.challenge_id}", []).append(c)
    flagged = set()
    for key, members in groups.items():
        if len(members) < 2:
            continue
        verifying = []
        for c in members:
            status, login, _ = verify(c, decoded[c.sha])
            if status == "VALID":
                verifying.append((c, login))
        if len(verifying) < 2:
            continue
        shas = [c.sha for c, _ in verifying]
        for c, login in verifying:
            if c.sha in flagged:
                continue
            flagged.add(c.sha)
            results.append(Result(c.sha, REPLAY, f"{key} reused on {len(shas)} commits", login, c.author_email, [],
                                  _trailer_dict(decoded[c.sha]), related=[s for s in shas if s != c.sha]))
    return results


def _trailer_dict(trailer):
    if trailer is None:
        return None
    return {
        "version": trailer.version,
        "session_id": trailer.session_id,
        "challenge_id": trailer.challenge_id,
        "status": trailer.status,
        "checks_hash": trailer.checks_hash,
        "receipt": trailer.receipt,
        "anchor_sha": trailer.anchor_sha,
        "signature_sha256": sha256_hex(trailer.sig),
    }


# ---------------------------------------------------------------------------
# API-backed verifier / lookups
# ---------------------------------------------------------------------------

def make_verifier(repo, token):
    def verifier(commit: Commit, trailer):
        if not repo or not token:
            return "INCONCLUSIVE", None, "GITHUB_TOKEN / GITHUB_REPOSITORY missing"
        try:
            login = resolve_author_login(repo, commit.sha, token)
            if not login:
                return "INVALID", None, "author e-mail not linked to a GitHub account"
            keys = fetch_ssh_keys(login, token)
        except ApiError as e:
            return "INCONCLUSIVE", None, str(e)
        if not keys:
            return "INVALID", login, "no registered SSH keys"
        ok = verify_signature(trailer.sig, trailer.sign_payload(commit.tree), keys)
        return ("VALID" if ok else "INVALID"), login, ("" if ok else "signature mismatch")
    return verifier


def make_tool_version_lookup(repo, token):
    cache = {}

    def lookup(trailer):
        if not repo or not token or not trailer.session_id:
            return None
        if trailer.session_id in cache:
            return cache[trailer.session_id]
        version = None
        try:
            art = find_artifact(repo, challenge_artifact_name(trailer.session_id), token)
            if art is not None:
                cj = read_challenge_json(download_artifact_zip(art["archive_download_url"], token))
                if cj.get("challenge_id") == trailer.challenge_id:
                    version = cj.get("tool_version")
        except (ApiError, ValueError, KeyError):
            version = None
        cache[trailer.session_id] = version
        return version
    return lookup


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def load_state(repo, token, local_path):
    if local_path and os.path.exists(local_path):
        with open(local_path) as f:
            return json.load(f)
    if repo and token:
        try:
            art = find_artifact(repo, STATE_ARTIFACT, token)
            if art is not None:
                raw = read_zip_member(download_artifact_zip(art["archive_download_url"], token), "state.json")
                return json.loads(raw.decode())
        except (ApiError, ValueError, KeyError) as e:
            print(f"⚠️  Could not load previous sweep state: {e}")
    return {}


def load_committed_baseline():
    if not os.path.exists(BASELINE_FILE):
        return set()
    try:
        with open(BASELINE_FILE) as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = data.get("fingerprints", [])
        return {str(x) for x in data}
    except (OSError, ValueError):
        return set()


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

def render_markdown(meta, results, new_ids):
    violations = [r for r in results if r.classification in VIOLATIONS]
    warnings = [r for r in results if r.classification in (VERSION_DRIFT, INCONCLUSIVE)]
    missing = [r for r in results if r.classification == MISSING]
    lines = [f"# PoW Sweep Report — {meta['generated_at']}", ""]
    lines += [f"- Repository: `{meta['repo']}`",
              f"- Sweep scanner: `{meta['sweep_tool_version'] or 'unknown'}`",
              f"- Enforcement epoch: {meta['epoch']}",
              f"- Commits examined (post-epoch): {meta['commits_post_epoch']} of {meta['commits_total']}",
              f"- Findings: {meta['findings_total']} total, {meta['findings_suppressed']} suppressed by baseline",
              f"- Violations: **{len(violations)}** ({len(new_ids)} new) · Warnings: {len(warnings)} · Missing attestations: {len(missing)}",
              ""]
    if violations:
        lines += ["## Violations", "", "| Commit | Author | Class | Reason | Evidence |", "|---|---|---|---|---|"]
        for r in violations:
            flag = "🆕 " if r.violation_id in new_ids else ""
            lines.append(f"| `{r.sha[:12]}` | {_author(r)} | {flag}**{r.classification}** | {r.reason} | {_evidence(r)} |")
        lines.append("")
    if warnings:
        lines += ["## Warnings", "", "| Commit | Author | Class | Reason |", "|---|---|---|---|"]
        for r in warnings:
            lines.append(f"| `{r.sha[:12]}` | {_author(r)} | {r.classification} | {r.reason} |")
        lines.append("")
    if missing:
        lines += ["<details><summary>Missing attestations (" + str(len(missing)) + ")</summary>", ""]
        for r in missing:
            lines.append(f"- `{r.sha[:12]}` {r.author_email} — {r.reason}")
        lines += ["", "</details>", ""]
    return "\n".join(lines)


def _author(r):
    return f"@{r.author_login}" if r.author_login else (r.author_email or "unknown")


def _evidence(r):
    bits = []
    for f in r.findings[:5]:
        bits.append(f"{f['detector']} @ `{f['file']}:{f['line']}` (sha256 `{f['secret_sha256'][:12]}…`)")
    if len(r.findings) > 5:
        bits.append(f"+{len(r.findings) - 5} more")
    if r.trailer:
        bits.append(f"session `{r.trailer['session_id'][:8]}…` sig `{r.trailer['signature_sha256'][:12]}…`")
    if r.related:
        bits.append("also on " + ", ".join(f"`{s[:12]}`" for s in r.related[:4]))
    return "<br>".join(bits) if bits else "—"


def upsert_issue(repo, token, title, body, new_results, admins):
    issues = api_json(f"{api_base()}/repos/{repo}/issues?state=open&per_page=100", token)
    existing = next((i for i in issues if isinstance(i, dict) and str(i.get("title", "")).startswith(ISSUE_TITLE_PREFIX)
                     and "pull_request" not in i), None)
    body = body[:60000]
    if existing is None:
        try:
            api_json(f"{api_base()}/repos/{repo}/labels", token, method="POST",
                     data={"name": ISSUE_LABEL, "color": "b60205", "description": "PoW sweep violations"})
        except ApiError:
            pass
        tag = f"{admins}\n\n" if admins else ""
        issue = api_json(f"{api_base()}/repos/{repo}/issues", token, method="POST",
                         data={"title": title, "body": tag + body, "labels": [ISSUE_LABEL]})
        print(f"📣 Opened issue #{issue.get('number')}: {title}")
        return issue
    number = existing["number"]
    api_json(f"{api_base()}/repos/{repo}/issues/{number}", token, method="PATCH", data={"title": title, "body": body})
    if new_results:
        tag = f"{admins} " if admins else ""
        comment = f"{tag}{len(new_results)} new violation(s) detected by the nightly sweep:\n\n" + "\n".join(
            f"- `{r.sha[:12]}` **{r.classification}** ({_author(r)}): {r.reason}" for r in new_results)
        api_json(f"{api_base()}/repos/{repo}/issues/{number}/comments", token, method="POST", data={"body": comment})
    print(f"📣 Updated issue #{number}: {title}")
    return existing


def post_webhook(url, token, repo, results):
    for r in results:
        for f in (r.findings or [{}]):
            payload = {
                "repository": repo,
                "commit": r.sha,
                "author_login": r.author_login,
                "author_email": r.author_email,
                "classification": r.classification,
                "reason": r.reason,
                "detector": f.get("detector"),
                "file": f.get("file"),
                "line": f.get("line"),
                "secret_sha256": f.get("secret_sha256"),
                "detected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            try:
                api_call(url, token, method="POST", data=payload)
            except ApiError as e:
                print(f"⚠️  Revocation webhook failed for {r.sha[:12]}: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    findings_file = os.environ.get("POW_FINDINGS_FILE")
    if not findings_file or not os.path.exists(findings_file):
        print("❌ POW_FINDINGS_FILE is missing.", file=sys.stderr)
        sys.exit(2)
    cfg = load_pow_config()
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    out_dir = os.environ.get("POW_SWEEP_OUT_DIR", "pow-sweep-out")
    checks_cmd = (cfg.get("checks_cmd") or "none").strip() or "none"
    expected_hash = hashlib.sha256(checks_cmd.encode()).hexdigest()
    sweep_tool_version = normalize_version(os.environ.get("POW_SCANNER_VERSION", ""))
    fail_on = str(cfg.get("sweep_fail_on") or "new").strip().lower()
    admins = str(cfg.get("admin_handles") or "").strip()
    epoch_override = str(cfg.get("sweep_epoch") or "").strip()
    os.makedirs(out_dir, exist_ok=True)

    findings_by_sha = load_findings(findings_file)
    findings_total = sum(len(v) for v in findings_by_sha.values())
    commits = enumerate_commits()
    state = load_state(repo, token, os.environ.get("POW_SWEEP_STATE_FILE"))

    epoch = state.get("epoch")
    if epoch_override or not epoch:
        epoch = resolve_epoch(commits, epoch_override)
    post_shas = post_epoch_shas(commits, epoch)

    baseline = set(state.get("baseline_fingerprints", [])) | load_committed_baseline()
    if "baseline_fingerprints" not in state and epoch is not None:
        for c in commits:
            if c.sha not in post_shas:
                baseline.update(fingerprint(f) for f in findings_by_sha.get(c.sha, []))
        print(f"📐 Baseline generated: {len(baseline)} pre-epoch finding fingerprint(s) suppressed.")

    results = classify(commits, findings_by_sha, post_shas, baseline, expected_hash, sweep_tool_version,
                       make_verifier(repo, token), make_tool_version_lookup(repo, token))

    violations = [r for r in results if r.classification in VIOLATIONS]
    reported = set(state.get("reported", []))
    new_results = [r for r in violations if r.violation_id not in reported]
    new_ids = {r.violation_id for r in new_results}
    suppressed = sum(1 for fs in findings_by_sha.values() for f in fs if fingerprint(f) in baseline)

    meta = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo": repo or "(local)",
        "sweep_tool_version": sweep_tool_version,
        "epoch": describe_epoch(epoch),
        "epoch_spec": epoch,
        "commits_total": len(commits),
        "commits_post_epoch": len(post_shas),
        "findings_total": findings_total,
        "findings_suppressed": suppressed,
        "violations": len(violations),
        "new_violations": len(new_results),
    }
    report = {"meta": meta, "results": [dict(asdict(r), violation_id=r.violation_id) for r in results]}
    with open(os.path.join(out_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
    markdown = render_markdown(meta, results, new_ids)
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as f:
        f.write(markdown)

    head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    new_state = {
        "version": 1,
        "updated_at": meta["generated_at"],
        "last_swept_head": head,
        "epoch": epoch,
        "baseline_fingerprints": sorted(baseline),
        "reported": sorted(reported | {r.violation_id for r in violations}),
    }
    with open(os.path.join(out_dir, "state.json"), "w") as f:
        json.dump(new_state, f, indent=2)

    print(markdown)

    if violations and repo and token and not cfg_truthy(cfg.get("sweep_no_issue")):
        title = f"{ISSUE_TITLE_PREFIX} {len(violations)} violation(s)"
        try:
            upsert_issue(repo, token, title, markdown, new_results, admins)
        except ApiError as e:
            print(f"⚠️  Could not open/update the tracking issue: {e}")

    webhook = str(cfg.get("revoke_webhook") or "").strip()
    if webhook and new_results:
        post_webhook(webhook, str(cfg.get("revoke_webhook_token") or ""), repo, new_results)

    if (fail_on == "any" and violations) or new_results:
        print(f"\n❌ {len(new_results)} new / {len(violations)} total violation(s).")
        sys.exit(1)
    print("\n✅ Sweep complete: no new violations.")
    sys.exit(0)


if __name__ == "__main__":
    main()
