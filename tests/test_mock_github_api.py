#!/usr/bin/env python3
"""
Mock GitHub API server for the PoW-Hook test-suite and the CI E2E scripts.

Importable (test_hooks.py):
    state  = MockState(pub_keys=[...], hmac_key="...")
    server = serve(state, port)           # threaded, call server.shutdown()

Standalone (shell E2E):
    python3 test_mock_github_api.py <port> <ssh-public-key-file>
    env POW_HMAC_KEY (default "test-hmac-key"), POW_MOCK_TOOL_VERSION (default "fake-scanner 1.0")
    prints READY once listening.

Endpoints
    GET  /repos/{o}/{r}/commits/{sha}                     -> author login
    GET  /users/{u}/keys                                   -> registered SSH keys (500 when state.fail_keys)
    POST /repos/{o}/{r}/actions/workflows/pow-ledger.yml/dispatches
                                                           -> records; MINT_CHALLENGE mints an in-memory
                                                              challenge solvable by tests/fake_scanner.py;
                                                              PASSED records the attestation artifact
    GET  /repos/{o}/{r}/actions/artifacts?name=...         -> pow-challenge-*, pow-attestation-*-PASSED, pow-sweep-state
    GET  /repos/{o}/{r}/actions/artifacts/{id}/zip         -> 302 to /blob/{id} (like GitHub)
    GET  /blob/{id}                                        -> zip bytes; 400 if an Authorization header is present
    GET  /repos/{o}/{r}/actions/runs/{id}                  -> {path, event, head_branch}
    GET  /repos/{o}/{r}/pulls?...                          -> state.open_prs
    PATCH/repos/{o}/{r}/pulls/{n}                          -> records closed PR
    GET  /repos/{o}/{r}/issues                             -> open issues
    POST /repos/{o}/{r}/issues, /issues/{n}/comments, /labels, PATCH /issues/{n}
    POST /webhook                                          -> records payload
"""
import http.server
import io
import json
import os
import re
import secrets
import signal
import socket
import string
import sys
import tarfile
import threading
import time
import urllib.parse
import uuid
import zipfile
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "admin_templates", "github", "scripts"))

from pow_trailer import CORPUS_DIRNAME, challenge_tag, compute_receipt, finding_line  # noqa: E402

ALNUM = string.ascii_letters + string.digits


def _rnd(n):
    return "".join(secrets.choice(ALNUM) for _ in range(n))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def mint_fake_challenge(session_id, hmac_key, tool_version, plants=3, decoys=5):
    """Return (challenge_dict, zip_bytes) solvable by tests/fake_scanner.py."""
    files, lines = {}, []
    for i in range(plants):
        tok = "ghp_" + _rnd(36)
        rel = f"src/plant{i}.py"
        files[rel] = f'TOKEN = "{tok}"\n'
        lines.append(finding_line("Github", f"{CORPUS_DIRNAME}/{rel}", 1, tok))
    for i in range(decoys):
        rel = f"config/decoy{i}.env"
        files[rel] = f"TOKEN={'ghp_' + _rnd(35) if i % 2 else 'sk_live_' + _rnd(19)}\n"
    files["README.md"] = "# nothing to see\n"

    receipt = compute_receipt(lines, tool_version)
    challenge_id = str(uuid.uuid4())
    challenge = {
        "format": 1,
        "challenge_id": challenge_id,
        "session_id": session_id,
        "tool_version": tool_version,
        "scanner_image": "fake",
        "tag": challenge_tag(hmac_key, challenge_id, session_id, receipt),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_receipt": receipt,  # test convenience; real mints never publish this
    }
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        for rel, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"{CORPUS_DIRNAME}/{rel}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("challenge.json", json.dumps({k: v for k, v in challenge.items() if not k.startswith("_")}))
        zf.writestr("corpus.tar", tar_buf.getvalue())
    return challenge, zip_buf.getvalue()


class MockState:
    def __init__(self, pub_keys, hmac_key="test-hmac-key", tool_version="fake-scanner 1.0"):
        self.pub_keys = list(pub_keys)
        self.hmac_key = hmac_key
        self.tool_version = tool_version
        self.author_login = "test_user"
        self.fail_keys = False
        self.ledger_path = ".github/workflows/pow-ledger.yml"
        self.ledger_branch = "main"
        self.strict_attestations = False
        self.challenge_delay = 0.0
        self.base_url = ""
        self.lock = threading.Lock()
        self.dispatches = []
        self.challenges = {}       # session_id -> dict(id, zip, created, run_id, challenge, visible_at)
        self.artifacts = {}        # artifact id -> zip bytes
        self.attestations = set()  # artifact names recorded via PASSED dispatch
        self.extra_artifacts = {}  # name -> zip bytes (e.g. pow-sweep-state)
        self.open_prs = []
        self.closed_prs = []
        self.issues = []
        self.comments = []
        self.labels = []
        self.webhooks = []
        self._next_id = 1000

    def next_id(self):
        self._next_id += 1
        return self._next_id

    def add_artifact(self, name, zip_bytes):
        self.extra_artifacts[name] = zip_bytes


def make_handler(state):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_):
            pass

        # ---- helpers -----------------------------------------------------
        def _send(self, code, body=None, headers=None):
            data = b"" if body is None else (json.dumps(body).encode() if not isinstance(body, bytes) else body)
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            if data and not (headers and "Content-Type" in headers):
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if data:
                self.wfile.write(data)

        def _read_json(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            try:
                return json.loads(raw.decode()) if raw else {}
            except ValueError:
                return {}

        def _base(self):
            return state.base_url or f"http://{self.headers.get('Host', '127.0.0.1')}"

        # ---- GET ---------------------------------------------------------
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)

            if re.match(r"^/repos/[^/]+/[^/]+/commits/[0-9a-fA-F]+$", path):
                author = {"login": state.author_login} if state.author_login else None
                return self._send(200, {"author": author})

            if re.match(r"^/users/[^/]+/keys$", path):
                if state.fail_keys:
                    return self._send(500, {"message": "boom"})
                return self._send(200, [{"id": i + 1, "key": k} for i, k in enumerate(state.pub_keys)])

            if re.match(r"^/repos/[^/]+/[^/]+/actions/artifacts$", path):
                return self._artifacts(path, qs.get("name", [""])[0])

            m = re.match(r"^/repos/[^/]+/[^/]+/actions/artifacts/(\d+)/zip$", path)
            if m:
                return self._send(302, b"", {"Location": f"{self._base()}/blob/{m.group(1)}"})

            m = re.match(r"^/blob/(\d+)$", path)
            if m:
                if self.headers.get("Authorization"):
                    return self._send(400, {"message": "AuthenticationFailed: unexpected Authorization header"})
                data = state.artifacts.get(int(m.group(1)))
                if data is None:
                    return self._send(404, {"message": "no such blob"})
                return self._send(200, data, {"Content-Type": "application/zip"})

            m = re.match(r"^/repos/[^/]+/[^/]+/actions/runs/(\d+)$", path)
            if m:
                return self._send(200, {"id": int(m.group(1)), "path": state.ledger_path,
                                        "event": "workflow_dispatch", "head_branch": state.ledger_branch})

            if re.match(r"^/repos/[^/]+/[^/]+/pulls$", path):
                return self._send(200, state.open_prs)

            if re.match(r"^/repos/[^/]+/[^/]+/issues$", path):
                return self._send(200, [i for i in state.issues if i.get("state") == "open"])

            return self._send(404, {"message": f"no route for GET {path}"})

        def _artifacts(self, path, name):
            repo_prefix = path[:-len("/actions/artifacts")]
            arts = []
            if name.startswith("pow-challenge-"):
                sid = name[len("pow-challenge-"):]
                with state.lock:
                    ch = state.challenges.get(sid)
                if ch and time.monotonic() >= ch["visible_at"]:
                    arts.append({
                        "id": ch["id"], "name": name, "expired": False, "created_at": ch["created"],
                        "archive_download_url": f"{self._base()}{repo_prefix}/actions/artifacts/{ch['id']}/zip",
                        "workflow_run": {"id": ch["run_id"]},
                    })
            elif name.startswith("pow-attestation-") and name.endswith("-PASSED"):
                if not state.strict_attestations or name in state.attestations:
                    arts.append({"id": 1, "name": name, "expired": False,
                                 "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
            elif name in state.extra_artifacts:
                aid = state.next_id()
                state.artifacts[aid] = state.extra_artifacts[name]
                arts.append({"id": aid, "name": name, "expired": False,
                             "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                             "archive_download_url": f"{self._base()}{repo_prefix}/actions/artifacts/{aid}/zip",
                             "workflow_run": {"id": 1}})
            return self._send(200, {"total_count": len(arts), "artifacts": arts})

        # ---- POST / PATCH ------------------------------------------------
        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path
            body = self._read_json()

            if re.match(r"^/repos/[^/]+/[^/]+/actions/workflows/pow-ledger\.yml/dispatches$", path):
                inputs = body.get("inputs", {})
                with state.lock:
                    state.dispatches.append({"ref": body.get("ref"), **inputs})
                    st = inputs.get("state")
                    sid = inputs.get("session_id", "")
                    if st == "MINT_CHALLENGE" and sid:
                        challenge, zip_bytes = mint_fake_challenge(sid, state.hmac_key, state.tool_version)
                        aid = state.next_id()
                        state.artifacts[aid] = zip_bytes
                        state.challenges[sid] = {
                            "id": aid, "run_id": state.next_id(), "challenge": challenge,
                            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "visible_at": time.monotonic() + state.challenge_delay,
                        }
                    if st == "PASSED" and sid:
                        state.attestations.add(f"pow-attestation-{sid}-{inputs.get('pow_checks_hash')}-PASSED")
                return self._send(204)

            m = re.match(r"^/repos/[^/]+/[^/]+/issues/(\d+)/comments$", path)
            if m:
                state.comments.append({"issue": int(m.group(1)), "body": body.get("body", "")})
                return self._send(201, {"id": len(state.comments)})

            if re.match(r"^/repos/[^/]+/[^/]+/issues$", path):
                issue = {"number": len(state.issues) + 1, "title": body.get("title", ""),
                         "body": body.get("body", ""), "labels": body.get("labels", []), "state": "open"}
                state.issues.append(issue)
                return self._send(201, issue)

            if re.match(r"^/repos/[^/]+/[^/]+/labels$", path):
                state.labels.append(body.get("name"))
                return self._send(201, body)

            if path == "/webhook":
                state.webhooks.append({"auth": self.headers.get("Authorization"), "body": body})
                return self._send(200, {"ok": True})

            return self._send(404, {"message": f"no route for POST {path}"})

        def do_PATCH(self):
            path = urllib.parse.urlparse(self.path).path
            body = self._read_json()
            m = re.match(r"^/repos/[^/]+/[^/]+/pulls/(\d+)$", path)
            if m:
                state.closed_prs.append(int(m.group(1)))
                return self._send(200, {"number": int(m.group(1)), "state": body.get("state")})
            m = re.match(r"^/repos/[^/]+/[^/]+/issues/(\d+)$", path)
            if m:
                for issue in state.issues:
                    if issue["number"] == int(m.group(1)):
                        issue.update({k: v for k, v in body.items() if k in ("title", "body", "state")})
                        return self._send(200, issue)
                return self._send(404, {"message": "no such issue"})
            return self._send(404, {"message": f"no route for PATCH {path}"})

    return Handler


class _Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(state, port, host="127.0.0.1"):
    server = _Server((host, port), make_handler(state))
    state.base_url = f"http://127.0.0.1:{port}"
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <port> <ssh-public-key-file>", file=sys.stderr)
        sys.exit(1)
    port = int(sys.argv[1])
    with open(sys.argv[2]) as f:
        pub_key = f.read().strip()
    state = MockState([pub_key], hmac_key=os.environ.get("POW_HMAC_KEY", "test-hmac-key"),
                      tool_version=os.environ.get("POW_MOCK_TOOL_VERSION", "fake-scanner 1.0"))
    server = _Server(("0.0.0.0", port), make_handler(state))
    state.base_url = f"http://127.0.0.1:{port}"

    def _shutdown(sig, frame):
        os._exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    print("READY", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
