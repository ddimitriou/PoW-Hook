#!/usr/bin/env python3
"""
PoW-Hook GitHub API helpers shared by verify_pow.py and sweep_audit.py.

Every function here raises ApiError on transport / non-2xx failures so that
callers can distinguish "the API said no" (a verdict) from "the API could not
be reached" (INCONCLUSIVE - never a verdict, never a reason to rewrite refs).
"""
import io
import json
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from pow_trailer import load_pow_config

USER_AGENT = "pow-hook"
DEFAULT_TIMEOUT = 30


class ApiError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def api_base():
    # "or" (not a default argument): an unset secret arrives as an empty string.
    return (load_pow_config().get("github_api_url") or "https://api.github.com").rstrip("/")


def _headers(token, extra=None):
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    if extra:
        h.update(extra)
    return h


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_call(url, token, method="GET", data=None, follow_redirects=True, timeout=DEFAULT_TIMEOUT):
    """Return (status, headers, body_bytes).  Raises ApiError on transport failure or non-2xx."""
    body = None
    extra = {}
    if data is not None:
        body = json.dumps(data).encode()
        extra["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=_headers(token, extra), method=method)
    opener = urllib.request.build_opener() if follow_redirects else urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        if not follow_redirects and e.code in (301, 302, 303, 307, 308):
            return e.code, dict(e.headers), b""
        detail = ""
        try:
            detail = e.read().decode(errors="replace")[:300]
        except Exception:
            pass
        raise ApiError(f"HTTP {e.code} for {method} {url}: {detail}", status=e.code)
    except urllib.error.URLError as e:
        raise ApiError(f"network error for {method} {url}: {e.reason}")
    except OSError as e:
        raise ApiError(f"I/O error for {method} {url}: {e}")


def api_json(url, token, method="GET", data=None):
    status, _, body = api_call(url, token, method=method, data=data)
    if not body:
        return {}
    try:
        return json.loads(body.decode())
    except ValueError as e:
        raise ApiError(f"non-JSON response from {url}: {e}", status=status)


def download_artifact_zip(archive_url, token):
    """
    GitHub answers the artifact download endpoint with a 302 to a short-lived
    signed blob URL.  The blob store rejects requests that still carry the
    GitHub Authorization header, so follow the redirect manually without it.
    """
    status, headers, body = api_call(archive_url, token, follow_redirects=False)
    if status in (301, 302, 303, 307, 308):
        location = headers.get("Location") or headers.get("location")
        if not location:
            raise ApiError("redirect without Location header while downloading artifact")
        _, _, body = api_call(location, None)
    if not body:
        raise ApiError("empty artifact download")
    return body


def read_zip_member(zip_bytes, suffix):
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if name.endswith(suffix):
                return zf.read(name)
    raise ApiError(f"artifact zip has no member ending in {suffix!r}")


def read_challenge_json(zip_bytes):
    return json.loads(read_zip_member(zip_bytes, "challenge.json").decode())


def parse_github_time(value):
    """'2024-01-10T17:39:03Z' -> epoch seconds."""
    if not value:
        raise ApiError("missing timestamp")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


# ---------------------------------------------------------------------------
# Repository-level lookups
# ---------------------------------------------------------------------------

def find_artifact(repo, name, token):
    """Newest non-expired artifact with exactly this name, or None."""
    url = f"{api_base()}/repos/{repo}/actions/artifacts?name={urllib.parse.quote(name)}&per_page=50"
    data = api_json(url, token)
    candidates = [a for a in data.get("artifacts", []) if a.get("name") == name and not a.get("expired")]
    if not candidates:
        return None
    candidates.sort(key=lambda a: a.get("created_at") or "", reverse=True)
    return candidates[0]


def fetch_run(repo, run_id, token):
    return api_json(f"{api_base()}/repos/{repo}/actions/runs/{run_id}", token)


def resolve_author_login(repo, commit_sha, token):
    """GitHub login of the commit author, or None when the e-mail is not linked to an account."""
    data = api_json(f"{api_base()}/repos/{repo}/commits/{commit_sha}", token)
    author = data.get("author") or {}
    return author.get("login") or None


def fetch_ssh_keys(login, token):
    data = api_json(f"{api_base()}/users/{urllib.parse.quote(login)}/keys", token)
    if not isinstance(data, list):
        raise ApiError("unexpected keys response")
    return [k["key"] for k in data if isinstance(k, dict) and k.get("key")]


def verify_signature(sig_raw, payload_bytes, ssh_keys):
    """True if sig_raw over payload_bytes verifies with any of the OpenSSH public keys."""
    for key_str in ssh_keys:
        try:
            pub_key = serialization.load_ssh_public_key(key_str.encode())
            if isinstance(pub_key, RSAPublicKey):
                pub_key.verify(sig_raw, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
            elif isinstance(pub_key, (Ed25519PublicKey, Ed448PublicKey)):
                pub_key.verify(sig_raw, payload_bytes)
            elif isinstance(pub_key, EllipticCurvePublicKey):
                pub_key.verify(sig_raw, payload_bytes, ECDSA(hashes.SHA256()))
            else:
                continue
            return True
        except Exception:
            continue
    return False


def list_open_prs_for_branch(repo, ref_name, token):
    owner = repo.split("/")[0]
    head = urllib.parse.quote(f"{owner}:{ref_name}")
    return api_json(f"{api_base()}/repos/{repo}/pulls?head={head}&state=open", token)


def comment_on_issue(repo, number, body, token):
    return api_json(f"{api_base()}/repos/{repo}/issues/{number}/comments", token, method="POST", data={"body": body})


def close_pr(repo, number, token):
    return api_json(f"{api_base()}/repos/{repo}/pulls/{number}", token, method="PATCH", data={"state": "closed"})
