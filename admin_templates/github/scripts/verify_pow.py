#!/usr/bin/env python3
"""
PoW-Hook Server-Side Verifier (GitHub Actions)

For every commit in a push / pull_request range:
  1. decode the PoW-Checks trailer (legacy JSON, v1 or v2),
  2. require status PASSED and the expected checks_cmd hash,
  3. verify the SSH signature against the author's GitHub-registered keys,
  4. (v2) verify the challenge receipt against the HMAC tag minted by
     pow-ledger.yml (SPEC.md section A.2 step 16),
  5. require the PASSED attestation artifact in the ledger,
and finally re-run checks_cmd on the checked-out tree (zero-trust fallback).

Configuration comes from the single POW environment variable (JSON):
  checks_cmd, enforce, admin_handles, github_api_url, hmac_key,
  allow_v1 (default "true"), auto_revert (default "false"),
  ledger_ref (default "main"), ledger_workflow_path, challenge_ttl_seconds,
  skip_ledger_check (testing).
GITHUB_TOKEN / GITHUB_REPOSITORY / GITHUB_EVENT_* are provided by Actions.

Per-commit outcomes
-------------------
  OK            everything verified
  REJECTED      policy failure (missing/malformed trailer, wrong cmd hash,
                status != PASSED, anchor mismatch, v1 not allowed, no ledger
                record, server-side check failed).  Check fails.  Refs are
                never rewritten.
  INVALID       cryptographically confirmed: the signature does not verify
                against any registered key of the author, or the signed
                receipt contradicts the minted tag.  Check fails.  The branch
                is force-reset to the last valid commit only when
                auto_revert is "true".
  INCONCLUSIVE  the verdict could not be reached (API error, missing
                configuration).  Check fails so branch protection blocks the
                merge, but nothing is rewritten.  Re-run the workflow.

All git invocations use argv lists; nothing from the event payload is ever
interpolated into a shell.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

for _stream in (sys.stdout, sys.stderr):  # emoji-safe output on cp1252 consoles
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pow_trailer import (  # noqa: E402
    STATUS_PASSED, TRAILER_KEY, ZERO_SHA,
    allowed_anchors, attestation_artifact_name, cfg_int, cfg_truthy,
    challenge_artifact_name, challenge_tag, decode_pow_trailer,
    first_trailer_value, load_pow_config, tags_equal,
)
from pow_github import (  # noqa: E402
    ApiError, close_pr, comment_on_issue, download_artifact_zip, fetch_run,
    fetch_ssh_keys, find_artifact, list_open_prs_for_branch, parse_github_time,
    read_challenge_json, resolve_author_login, verify_signature,
)

OK = "OK"
REJECTED = "REJECTED"
INVALID = "INVALID"
INCONCLUSIVE = "INCONCLUSIVE"

DEFAULT_LEDGER_PATH = ".github/workflows/pow-ledger.yml"
DEFAULT_LEDGER_REF = "main"
DEFAULT_CHALLENGE_TTL = 24 * 3600
COMMIT_CLOCK_SLACK = 600  # seconds a challenge may post-date the commit time

REF_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


class Outcome:
    def __init__(self, kind, reason=""):
        self.kind = kind
        self.reason = reason

    def __bool__(self):
        return self.kind == OK

    def __repr__(self):
        return f"{self.kind}: {self.reason}" if self.reason else self.kind


# ---------------------------------------------------------------------------
# git helpers (argv only)
# ---------------------------------------------------------------------------

def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode().strip()


def git_optional(*args):
    try:
        return git(*args)
    except subprocess.CalledProcessError:
        return None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Context:
    def __init__(self, cfg):
        self.cfg = cfg
        self.token = os.environ.get("GITHUB_TOKEN")
        self.repo = os.environ.get("GITHUB_REPOSITORY")
        self.checks_cmd = (cfg.get("checks_cmd") or "none").strip() or "none"
        self.expected_hash = hashlib.sha256(self.checks_cmd.encode()).hexdigest()
        self.allow_v1 = cfg_truthy(cfg.get("allow_v1"), default=True)
        self.auto_revert = cfg_truthy(cfg.get("auto_revert"))
        self.hmac_key = cfg.get("hmac_key") or ""
        self.ledger_path = cfg.get("ledger_workflow_path") or DEFAULT_LEDGER_PATH
        self.ledger_ref = cfg.get("ledger_ref", DEFAULT_LEDGER_REF)
        self.challenge_ttl = cfg_int(cfg.get("challenge_ttl_seconds"), DEFAULT_CHALLENGE_TTL)
        self.skip_ledger = cfg_truthy(cfg.get("skip_ledger_check"))
        self.admin_handles = cfg.get("admin_handles") or ""


# ---------------------------------------------------------------------------
# Verification steps
# ---------------------------------------------------------------------------

def verify_challenge(ctx, trailer, commit_time):
    """SPEC.md section A.2 steps 14-16."""
    if not ctx.hmac_key:
        return Outcome(INCONCLUSIVE, "hmac_key is not configured in POW; cannot verify the challenge receipt")
    if not ctx.token or not ctx.repo:
        return Outcome(INCONCLUSIVE, "GITHUB_TOKEN / GITHUB_REPOSITORY missing; cannot query the ledger")

    name = challenge_artifact_name(trailer.session_id)
    try:
        artifact = find_artifact(ctx.repo, name, ctx.token)
        if artifact is None:
            return Outcome(REJECTED, f"no challenge artifact {name} exists in the ledger")

        run_id = (artifact.get("workflow_run") or {}).get("id")
        if not run_id:
            return Outcome(REJECTED, "challenge artifact is not attached to a workflow run")
        run = fetch_run(ctx.repo, run_id, ctx.token)
        if run.get("path") != ctx.ledger_path:
            return Outcome(REJECTED, f"challenge was produced by {run.get('path')!r}, not {ctx.ledger_path!r}")
        if run.get("event") not in (None, "workflow_dispatch"):
            return Outcome(REJECTED, f"challenge run event is {run.get('event')!r}, expected workflow_dispatch")
        if ctx.ledger_ref and run.get("head_branch") not in (None, ctx.ledger_ref):
            return Outcome(REJECTED, f"challenge was minted on ref {run.get('head_branch')!r}, expected {ctx.ledger_ref!r}")

        created = parse_github_time(artifact.get("created_at"))
        if created > commit_time + COMMIT_CLOCK_SLACK:
            return Outcome(REJECTED, "challenge was minted after the commit was made")
        if commit_time - created > ctx.challenge_ttl:
            return Outcome(REJECTED, f"challenge is older than {ctx.challenge_ttl}s relative to the commit")

        zip_bytes = download_artifact_zip(artifact["archive_download_url"], ctx.token)
        challenge = read_challenge_json(zip_bytes)
    except ApiError as e:
        return Outcome(INCONCLUSIVE, f"ledger lookup failed: {e}")
    except (KeyError, ValueError) as e:
        return Outcome(INCONCLUSIVE, f"malformed challenge artifact: {e}")

    if challenge.get("session_id") != trailer.session_id:
        return Outcome(REJECTED, "challenge artifact belongs to a different session")
    if challenge.get("challenge_id") != trailer.challenge_id:
        return Outcome(REJECTED, "trailer challenge_id does not match the minted challenge")

    expected_tag = challenge_tag(ctx.hmac_key, trailer.challenge_id, trailer.session_id, trailer.receipt)
    if not tags_equal(expected_tag, challenge.get("tag", "")):
        return Outcome(INVALID, "signed challenge receipt does not match the minted tag "
                                "(scanner not run on the corpus, or a different scanner version)")
    print(f"   🧩 Challenge receipt verified (tool: {challenge.get('tool_version', '?')}).")
    return Outcome(OK)


def check_attestation_artifact(ctx, session_id, retries=3, delay=5):
    """Confirm the ledger recorded a PASSED attestation for this session."""
    if ctx.skip_ledger:
        return Outcome(OK)
    if not ctx.token or not ctx.repo:
        return Outcome(INCONCLUSIVE, "GITHUB_TOKEN / GITHUB_REPOSITORY missing; cannot query the ledger")
    name = attestation_artifact_name(session_id, ctx.expected_hash, STATUS_PASSED)
    last_error = None
    for attempt in range(retries):
        try:
            if find_artifact(ctx.repo, name, ctx.token) is not None:
                print(f"   📜 Attestation artifact found: {name}")
                return Outcome(OK)
            last_error = None
        except ApiError as e:
            last_error = e
        if attempt < retries - 1:
            print(f"   ⏳ Waiting {delay}s for attestation artifact (attempt {attempt + 2}/{retries})…")
            time.sleep(delay)
    if last_error is not None:
        return Outcome(INCONCLUSIVE, f"ledger lookup failed: {last_error}")
    return Outcome(REJECTED, f"no PASSED attestation artifact {name} in the ledger")


def verify_commit(ctx, commit):
    trailer_raw = git("log", "-1", f"--format=%(trailers:key={TRAILER_KEY},valueonly)", commit)
    trailer_b64 = first_trailer_value(trailer_raw)
    if not trailer_b64:
        return Outcome(REJECTED, f"missing required {TRAILER_KEY} trailer")

    try:
        trailer = decode_pow_trailer(trailer_b64)
    except ValueError as e:
        return Outcome(REJECTED, f"{TRAILER_KEY} trailer is malformed ({e})")

    if not trailer.is_v2 and not ctx.allow_v1:
        return Outcome(REJECTED, "v1 trailer not accepted (allow_v1 is not \"true\" in POW); upgrade the client hooks")
    if trailer.checks_hash != ctx.expected_hash:
        return Outcome(REJECTED, "commit used an unexpected checks_cmd (hash mismatch)")
    if trailer.status != STATUS_PASSED:
        return Outcome(REJECTED, f"attestation status is {trailer.status}, not {STATUS_PASSED}")

    tree_hash = git("log", "-1", "--format=%T", commit)
    parents = git("log", "-1", "--format=%P", commit).split()
    commit_time = int(git("log", "-1", "--format=%ct", commit))

    if trailer.is_v2:
        first_parent = parents[0] if parents else None
        grand_parent = None
        if first_parent:
            gp = git_optional("log", "-1", "--format=%P", first_parent)
            grand_parent = gp.split()[0] if gp else None
        if trailer.anchor_sha not in allowed_anchors(first_parent, grand_parent):
            return Outcome(REJECTED, "trailer anchor does not match this commit's lineage (trailer replayed onto another commit?)")

    payload = trailer.sign_payload(tree_hash)

    if not ctx.token or not ctx.repo:
        return Outcome(INCONCLUSIVE, "GITHUB_TOKEN / GITHUB_REPOSITORY missing; cannot resolve author keys")
    try:
        username = resolve_author_login(ctx.repo, commit, ctx.token)
    except ApiError as e:
        return Outcome(INCONCLUSIVE, f"could not resolve the commit author via the GitHub API: {e}")
    if not username:
        return Outcome(REJECTED, "commit author e-mail is not linked to a GitHub account")
    try:
        keys = fetch_ssh_keys(username, ctx.token)
    except ApiError as e:
        return Outcome(INCONCLUSIVE, f"could not fetch SSH keys for {username}: {e}")
    if not keys:
        return Outcome(REJECTED, f"GitHub user {username} has no registered SSH keys")

    if not verify_signature(trailer.sig, payload, keys):
        return Outcome(INVALID, f"signature does not verify against any SSH key registered for {username}")
    label = "legacy JSON" if trailer.legacy_json else f"v{trailer.version}"
    print(f"   ✅ Signature verified via GitHub SSH keys of {username} (trailer {label}).")

    if trailer.is_v2:
        outcome = verify_challenge(ctx, trailer, commit_time)
        if not outcome:
            return outcome

    return check_attestation_artifact(ctx, trailer.session_id)


def perform_server_side_check(checks_cmd):
    """
    Zero-trust fallback: run the very same checks_cmd on the checked-out tree.
    The checkout action stores the token as an http extraheader; hide it from
    the scanner while it runs so a secret scanner does not flag the runner's
    own credentials.
    """
    print(f"\n⚙️ Executing server-side check: {checks_cmd}")
    key = "http.https://github.com/.extraheader"
    extra_header = git_optional("config", "--local", "--get", key)
    if extra_header:
        subprocess.call(["git", "config", "--local", "--unset", key], stderr=subprocess.DEVNULL)
    try:
        subprocess.check_call(checks_cmd, shell=True)
        print("✅ Server-side check passed.")
        return Outcome(OK)
    except subprocess.CalledProcessError as e:
        return Outcome(REJECTED, f"server-side re-run of checks_cmd failed (exit {e.returncode}); "
                                 "the pushed tree does not pass the required checks")
    finally:
        if extra_header:
            subprocess.call(["git", "config", "--local", key, extra_header])


# ---------------------------------------------------------------------------
# Commit range resolution
# ---------------------------------------------------------------------------

def resolve_range():
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    event = {}
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and os.path.exists(event_path):
        try:
            with open(event_path) as f:
                event = json.load(f)
        except (OSError, ValueError):
            event = {}

    if event_name == "pull_request" and "pull_request" in event:
        pr = event["pull_request"]
        return pr["base"]["sha"], pr["head"]["sha"], pr["head"]["ref"], event

    base_sha = event.get("before")
    head_sha = event.get("after")
    ref_name = os.environ.get("GITHUB_REF", "").replace("refs/heads/", "")

    if not head_sha:
        head_sha = git_optional("rev-parse", "HEAD") or "HEAD"
    if not base_sha or base_sha == ZERO_SHA:
        base_sha = (git_optional("merge-base", "origin/main", head_sha)
                    or git_optional("rev-parse", f"{head_sha}~1")
                    or "HEAD~1")
    if not ref_name:
        ref_name = "main"
    return base_sha, head_sha, ref_name, event


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    cfg = load_pow_config()
    if not cfg_truthy(cfg.get("enforce")):
        print("⚠️  enforce is not \"true\" in POW — validation is disabled.")
        print("   Set \"enforce\": \"true\" in the POW JSON of .github/workflows/pow-validator.yml")
        print("   on your second commit (made with hooks installed and running).")
        sys.exit(0)

    ctx = Context(cfg)
    base_sha, head_sha, ref_name, event = resolve_range()
    ref_is_safe = bool(REF_NAME_RE.match(ref_name or "")) and ".." not in ref_name

    try:
        commits_str = git("log", f"{base_sha}..{head_sha}", "--format=%H")
    except subprocess.CalledProcessError:
        commits_str = ""
    if not commits_str:
        print("No new commits to verify.")
        sys.exit(0)

    commits = list(reversed(commits_str.splitlines()))
    last_valid = base_sha
    failure = None
    failed_commit = None

    for commit in commits:
        print(f"\n🔍 Verifying commit {commit}…")
        outcome = verify_commit(ctx, commit)
        if outcome:
            last_valid = commit
            continue
        failure, failed_commit = outcome, commit
        print(f"❌ {outcome.kind}: commit {commit}: {outcome.reason}")
        break

    if failure is None and ctx.checks_cmd != "none":
        outcome = perform_server_side_check(ctx.checks_cmd)
        if not outcome:
            failure, failed_commit, last_valid = outcome, head_sha, base_sha
            print(f"❌ {outcome.kind}: {outcome.reason}")

    if failure is None:
        print("\n🎉 All commits have valid Proof-of-Work tokens and server attestations!")
        sys.exit(0)

    print("\n-------------------------------------------------------")
    print(f"{failure.kind}: validation stopped at commit {failed_commit}.")
    print(f"Reason: {failure.reason}")
    if failure.kind == INCONCLUSIVE:
        print("No refs were rewritten. Re-run the workflow once the ledger / API is reachable.")
    elif failure.kind == INVALID and ctx.auto_revert:
        print(f"auto_revert is enabled: branch {ref_name} will be reset to {last_valid}.")
    else:
        print("No refs were rewritten (auto_revert is not enabled or the failure is not cryptographically confirmed).")
    print("-------------------------------------------------------")

    revert = failure.kind == INVALID and ctx.auto_revert
    if not ref_is_safe:
        print(f"⚠️  Ref name {ref_name!r} failed validation; skipping PR teardown and any ref update.")
        revert = False

    if ctx.token and ctx.repo and ref_is_safe:
        tag = f"{ctx.admin_handles} " if ctx.admin_handles else ""
        msg = (
            f"🚨 **Proof-of-Work validation failed** ({failure.kind})\n\n"
            f"{tag}Commit `{failed_commit}` on `{ref_name}`: {failure.reason}\n\n"
        )
        if revert:
            msg += (
                "_The PR has been closed and the branch reset to the last valid commit._\n\n"
                "**Manual action:** GitHub does not expose an API to hard-delete pull requests. "
                "To scrub the rejected commits from the repository index an administrator must "
                "[open a GitHub Support ticket](https://support.github.com/contact/general)."
            )
        elif failure.kind == INCONCLUSIVE:
            msg += "_The verdict is inconclusive (API/configuration problem). Nothing was rewritten; re-run the check._"
        else:
            msg += "_Branch protection blocks this merge until the commits are re-created with the PoW hooks running._"
        try:
            for pr in list_open_prs_for_branch(ctx.repo, ref_name, ctx.token):
                number = pr["number"]
                comment_on_issue(ctx.repo, number, msg, ctx.token)
                if revert:
                    close_pr(ctx.repo, number, ctx.token)
                    print(f"✅ Closed PR #{number} and notified admins.")
                else:
                    print(f"💬 Commented on PR #{number}.")
        except ApiError as e:
            print(f"⚠️  PR notification error: {e}")

    if revert:
        subprocess.check_call(["git", "config", "--global", "user.name", "github-actions[bot]"])
        subprocess.check_call(["git", "config", "--global", "user.email",
                               "github-actions[bot]@users.noreply.github.com"])
        subprocess.check_call(["git", "push", "--force", "origin", f"{last_valid}:refs/heads/{ref_name}"])

    sys.exit(1)


if __name__ == "__main__":
    main()
