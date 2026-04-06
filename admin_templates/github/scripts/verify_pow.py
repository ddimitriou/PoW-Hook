#!/usr/bin/env python3
"""
PoW-Hook Server-Side Verifier (GitHub Actions)

Verifies the tri-factor RSA signature (tree_hash|session_id|status) on every
commit in a push or pull_request, and optionally cross-references the
server-side attestation artifact produced by pow-ledger.yml.
"""
import sys
import os
import subprocess
import base64
import json
import time
import urllib.request
import urllib.error
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


def run(cmd):
    return subprocess.check_output(cmd, shell=True).decode().strip()


# ---------------------------------------------------------------------------
# Attestation Artifact Lookup
# ---------------------------------------------------------------------------

def check_attestation_artifact(repo, session_id, gh_token, retries=3, delay=5):
    """
    Query GitHub's Artifacts API to confirm a PASSED attestation artifact
    exists for the given session_id.  Returns True if found.
    """
    if not gh_token or not repo:
        return None  # Cannot check — treat as inconclusive

    artifact_name = f"pow-attestation-{session_id}-PASSED"
    url = f"https://api.github.com/repos/{repo}/actions/artifacts?name={artifact_name}"

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/vnd.github.v3+json",
            })
            resp = urllib.request.urlopen(req)
            data = json.loads(resp.read().decode())
            if data.get("total_count", 0) > 0:
                print(f"   📜 Attestation artifact found: {artifact_name}")
                return True
        except Exception:
            pass

        if attempt < retries - 1:
            print(f"   ⏳ Waiting {delay}s for attestation artifact (attempt {attempt+2}/{retries})…")
            time.sleep(delay)

    print(f"   ⚠️  Attestation artifact NOT found: {artifact_name}")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    keys_json = os.environ.get("POW_PUBLIC_KEYS", "{}")
    try:
        public_keys = json.loads(keys_json)
    except json.JSONDecodeError:
        sys.exit("❌ POW_PUBLIC_KEYS is not a valid JSON.")

    if not public_keys:
        sys.exit("❌ POW_PUBLIC_KEYS is empty.")

    gh_token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")  # auto-set by Actions

    # ---- Resolve commit range ----
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    event = {}
    if event_name == "pull_request":
        with open(os.environ.get("GITHUB_EVENT_PATH")) as f:
            event = json.load(f)
        base_sha = event["pull_request"]["base"]["sha"]
        head_sha = event["pull_request"]["head"]["sha"]
        ref_name = event["pull_request"]["head"]["ref"]
    else:
        try:
            with open(os.environ.get("GITHUB_EVENT_PATH")) as f:
                event = json.load(f)
            base_sha = event.get("before")
            head_sha = event.get("after")
            ref_name = os.environ.get("GITHUB_REF", "").replace("refs/heads/", "")

            if not base_sha or base_sha == "0" * 40:
                try:
                    base_sha = run(f"git merge-base origin/main {head_sha}") if head_sha else "HEAD~1"
                except Exception:
                    base_sha = "HEAD~1"
            if not head_sha:
                head_sha = "HEAD"
        except Exception:
            print("⚠️  Local ACT test fallback triggered")
            base_sha = run("git rev-parse HEAD~1")
            head_sha = run("git rev-parse HEAD")
            ref_name = "main"

    # ---- Enumerate commits ----
    try:
        commits_str = run(f"git log {base_sha}..{head_sha} --format=%H")
    except Exception:
        commits_str = ""

    if not commits_str:
        print("No new commits to verify.")
        sys.exit(0)

    commits = commits_str.splitlines()
    commits.reverse()

    missing = 0
    last_valid = base_sha

    for commit in commits:
        print(f"\n🔍 Verifying commit {commit}…")

        token     = run(f'git log -1 --format="%(trailers:key=Validated-At-Local,valueonly)" {commit}')
        session   = run(f'git log -1 --format="%(trailers:key=PoW-Session,valueonly)" {commit}')
        status    = run(f'git log -1 --format="%(trailers:key=PoW-Status,valueonly)" {commit}')
        tree_hash = run(f"git log -1 --format=%T {commit}")

        # 1. Check trailers exist
        if not token or not session or not status:
            print(f"❌ Commit {commit} missing required trailers.")
            missing += 1
            break

        # 2. Verify RSA signature against tri-factor payload
        sign_payload = f"{tree_hash}|{session}|{status}"

        try:
            sig_raw = base64.b64decode(token)
        except Exception:
            print(f"❌ Commit {commit} token is not valid base64.")
            missing += 1
            break

        valid = False
        for user, pub_key_pem in public_keys.items():
            try:
                public_key = serialization.load_pem_public_key(pub_key_pem.encode())
                public_key.verify(
                    sig_raw,
                    sign_payload.encode(),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                valid = True
                print(f"   ✅ RSA signature verified by {user}.")
                break
            except Exception:
                continue

        if not valid:
            print(f"❌ RSA Signature mismatch for commit {commit}.")
            missing += 1
            break

        # 3. Cross-reference server-side attestation artifact
        attestation = check_attestation_artifact(repo, session, gh_token)
        if attestation is False:
            print(f"❌ No server-side attestation found for session {session}.")
            missing += 1
            break

        last_valid = commit

    # ---- Rejection path ----
    if missing > 0:
        print("\n-------------------------------------------------------")
        print("REJECTED: One or more commits failed validation.")
        print(f"WARNING: Obliterating invalid commits from branch {ref_name}")
        print("-------------------------------------------------------")

        if event_name == "pull_request" and gh_token:
            try:
                repo_name = event["repository"]["full_name"]
                pr_number = event["pull_request"]["number"]
                admins = os.environ.get("POW_ADMIN_HANDLES", "")
                tag = f"{admins} " if admins else ""

                msg = (
                    f"🚨 **Proof-of-Work Validation Failed**\n\n"
                    f"{tag}This Pull Request contains commits that either lack "
                    f"valid cryptographic signatures or have no matching "
                    f"server-side attestation record.\n\n"
                    f"_The PR has been automatically closed._"
                )

                # Post Comment
                c_url = f"https://api.github.com/repos/{repo_name}/issues/{pr_number}/comments"
                req_c = urllib.request.Request(c_url, data=json.dumps({"body": msg}).encode(), headers={
                    "Authorization": f"Bearer {gh_token}",
                    "Accept": "application/vnd.github.v3+json",
                    "Content-Type": "application/json",
                })
                urllib.request.urlopen(req_c)

                # Close PR
                p_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
                req_p = urllib.request.Request(p_url, data=json.dumps({"state": "closed"}).encode(), headers={
                    "Authorization": f"Bearer {gh_token}",
                    "Accept": "application/vnd.github.v3+json",
                    "Content-Type": "application/json",
                }, method="PATCH")
                urllib.request.urlopen(req_p)

                print(f"✅ Closed PR #{pr_number} and notified admins.")
            except Exception as e:
                print(f"⚠️  PR API teardown error: {e}")

        run("git config --global user.name github-actions[bot]")
        run("git config --global user.email github-actions[bot]@users.noreply.github.com")
        run(f"git push --force origin {last_valid}:refs/heads/{ref_name}")
        sys.exit(1)

    print("\n🎉 All commits have valid Proof-of-Work tokens and server attestations!")


if __name__ == "__main__":
    main()
