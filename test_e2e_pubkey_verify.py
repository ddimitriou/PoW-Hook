#!/usr/bin/env python3
"""
E2E host-side public-key verification.
Reads the committed token and verifies it using the PUBLIC key file
(not by re-signing — this is a genuine asymmetric verify).
Run from the test repo root with POW_SSH_KEY_OVERRIDE set (private key path).
"""
import subprocess, base64, os, sys
from cryptography.hazmat.primitives import serialization

PRIV_PATH = os.environ.get("POW_SSH_KEY_OVERRIDE", "")
if not PRIV_PATH:
    print("ERROR: POW_SSH_KEY_OVERRIDE not set")
    sys.exit(1)

PUB_PATH = PRIV_PATH + ".pub"
if not os.path.exists(PUB_PATH):
    print(f"ERROR: public key file not found at {PUB_PATH!r}")
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

with open(PUB_PATH) as f:
    pub_str = f.read().strip()

print(f"[pub_verify] pub_key_prefix={pub_str[:60]}")
print(f"[pub_verify] payload={payload}")
print(f"[pub_verify] token_len={len(token)}")

pub_key = serialization.load_ssh_public_key(pub_str.encode())
sig = base64.b64decode(token)
try:
    pub_key.verify(sig, payload.encode())
    print("[pub_verify] RESULT: OK — public key verifies the commit token")
except Exception as e:
    print(f"[pub_verify] RESULT: FAIL — {e!r}")
    print(f"[pub_verify] sig_len={len(sig)}")
    print(f"[pub_verify] sig_hex={sig.hex()[:40]}...")
