#!/usr/bin/env python3
"""
Standalone mock GitHub API server for act E2E testing.

Usage:
    python3 test_mock_github_api.py <port> <ssh-public-key-file>

The server will listen on 127.0.0.1:<port> and respond to:
  GET /repos/*/commits/*   → {"author": {"login": "test_user"}}
  GET /users/*/keys        → [{"id": 1, "key": "<contents of ssh-public-key-file>"}]

It prints "READY" to stdout once listening (so callers can wait for it).
"""
import http.server
import json
import sys
import os
import signal


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <port> <ssh-public-key-file>", file=sys.stderr)
        sys.exit(1)

    port = int(sys.argv[1])
    with open(sys.argv[2]) as f:
        pub_key = f.read().strip()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if "/commits/" in self.path:
                body = json.dumps({"author": {"login": "test_user"}}).encode()
            elif "/keys" in self.path:
                body = json.dumps([{"id": 1, "key": pub_key}]).encode()
            elif "/actions/artifacts" in self.path:
                # Extract the artifact name from the query string (?name=...)
                # and return a "found" response for any PASSED attestation.
                import urllib.parse
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                name = qs.get("name", [""])[0]
                if "PASSED" in name:
                    body = json.dumps({"total_count": 1, "artifacts": [{"name": name}]}).encode()
                else:
                    body = json.dumps({"total_count": 0, "artifacts": []}).encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass  # silence request logs

    server = http.server.HTTPServer(("0.0.0.0", port), Handler)

    # Allow callers to kill us gracefully
    def _shutdown(sig, frame):
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    print("READY", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
