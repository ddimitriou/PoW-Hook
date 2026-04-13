#!/usr/bin/env python3
"""
E2E key debug: verify the signed commit token using the test key directly.
Parses trailers manually (avoids git 2.16 format-specifier limitation).
Run from the test repo root with POW_SSH_KEY_OVERRIDE set.
"""
import subprocess, base64, os, sys
from cryptography.hazmat.primitives import serialization

KEY_PATH = os.environ.get("POW_SSH_KEY_OVERRIDE", "")
if not KEY_PATH or not os.path.exists(KEY_PATH):
    print(f"ERROR: test key not found at {KEY_PATH!r}")
    sys.exit(1)

COMMIT = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
tree   = subprocess.check_output(["git", "log", "-1", "--format=%T", COMMIT], text=True).strip()
body   = subprocess.check_output(["git", "log", "-1", "--format=%B", COMMIT], text=True)

token = session = status = ""
for line in body.splitlines():
    if line.startswith("Validated-At-Local:"):
        token = line.split(":", 1)[1].strip()
    elif line.startswith("PoW-Session:"):
        session = line.split(":", 1)[1].strip()
    elif line.startswith("PoW-Status:"):
        status = line.split(":", 1)[1].strip()

payload = f"{tree}|{session}|{status}"
print(f"[key_debug] tree={tree}")
print(f"[key_debug] session={session}")
print(f"[key_debug] status={status}")
print(f"[key_debug] payload={payload}")
print(f"[key_debug] token_len={len(token)}")

with open(KEY_PATH, "rb") as f:
    key_data = f.read()
private_key = serialization.load_ssh_private_key(key_data, password=None)
sig = private_key.sign(payload.encode())
expected = base64.b64encode(sig).decode()

print(f"[key_debug] expected_token={expected}")
print(f"[key_debug] commit_token ={token}")
print(f"[key_debug] MATCH={'YES' if expected == token else 'NO'}")
