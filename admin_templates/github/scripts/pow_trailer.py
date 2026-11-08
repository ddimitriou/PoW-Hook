#!/usr/bin/env python3
"""
PoW-Hook shared protocol primitives (stdlib only).

Single source of truth for:
  * the POW JSON configuration loader (one env var for every setting)
  * PoW-Checks trailer encoding / decoding (v1 and v2, plus the legacy JSON bundle)
  * the signed payload layout
  * challenge receipt canonicalization (SPEC.md section A.4)
  * trufflehog JSON-lines parsing (filesystem and git sources)
  * the challenge HMAC tag (SPEC.md section A.2, steps 3 and 16)

Installed by the installers into:
  .github/scripts/pow_trailer.py   (validator, mint job, sweep)
  .git/hooks/pow_trailer.py        (client hooks)

Trailer layouts
---------------
legacy: base64(JSON {"token": base64(sig), "session", "status", "checks_hash"})
        - produced by pre-v1 hooks; decoded as version 1 (no challenge).
v1:     [0x01][2B BE sig_len][sig][16B session UUID][1B status][32B checks_hash]
v2:     [0x02][2B BE sig_len][sig][16B session UUID][1B status][32B checks_hash]
        [16B challenge UUID][32B receipt][20B anchor commit SHA-1]

Signed payloads (pipe-delimited ASCII)
--------------------------------------
v1: checks_hash|tree_hash|session_id|status
v2: checks_hash|tree_hash|session_id|status|challenge_id|receipt|anchor_sha

The *anchor* is the first parent of HEAD at commit-msg time (all-zero for the
first two commits of a repository).  A verifier accepts an anchor that is
either the commit's first parent or its first grandparent.  Binding the
grandparent instead of the parent is what makes "git commit --amend" work:
during an amend the hook still sees the *old* HEAD, whose first parent is
exactly the new commit's first parent.  Either way a trailer cannot be lifted
onto an unrelated commit with the same tree (SPEC.md sections 0.4 and A.5).
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import uuid as uuid_mod
from dataclasses import dataclass
from typing import Iterable, List, Optional

TRAILER_KEY = "PoW-Checks"
TRAILER_V1 = 0x01
TRAILER_V2 = 0x02
ZERO_SHA = "0" * 40
CORPUS_DIRNAME = "pow-corpus"
STATUS_PASSED = "PASSED"
STATUS_FAILED = "FAILED"
_STATUS_BYTES = {STATUS_FAILED: 0, STATUS_PASSED: 1}
_STATUS_NAMES = {v: k for k, v in _STATUS_BYTES.items()}


def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Configuration: everything lives in the single POW env var (a JSON object)
# ---------------------------------------------------------------------------

def load_pow_config(environ=None) -> dict:
    """Parse the POW environment variable.  Returns {} when absent or invalid."""
    raw = (environ if environ is not None else os.environ).get("POW", "") or "{}"
    try:
        cfg = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return cfg if isinstance(cfg, dict) else {}


def cfg_truthy(value, default=False) -> bool:
    """"true" / true -> True.  Missing (None) -> default."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def cfg_int(value, default) -> int:
    try:
        return int(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Trailer codec
# ---------------------------------------------------------------------------

@dataclass
class PowTrailer:
    version: int
    sig: bytes
    session_id: str
    status: str
    checks_hash: str
    challenge_id: Optional[str] = None
    receipt: Optional[str] = None
    anchor_sha: Optional[str] = None
    legacy_json: bool = False

    @property
    def is_v2(self) -> bool:
        return self.version == TRAILER_V2

    def sign_payload(self, tree_hash: str) -> bytes:
        return build_sign_payload(
            self.checks_hash, tree_hash, self.session_id, self.status,
            self.challenge_id, self.receipt, self.anchor_sha,
        )


def build_sign_payload(checks_hash, tree_hash, session_id, status,
                       challenge_id=None, receipt=None, anchor_sha=None) -> bytes:
    base = f"{checks_hash}|{tree_hash}|{session_id}|{status}"
    if challenge_id is None:
        return base.encode()
    if receipt is None or anchor_sha is None:
        raise ValueError("v2 payload requires challenge_id, receipt and anchor_sha")
    return f"{base}|{challenge_id}|{receipt}|{anchor_sha}".encode()


def encode_pow_trailer(sig: bytes, session_id: str, status: str, checks_hash: str,
                       challenge_id=None, receipt=None, anchor_sha=None) -> str:
    """Return the base64 trailer value.  v2 iff challenge_id is given."""
    if status not in _STATUS_BYTES:
        raise ValueError(f"unknown status {status!r}")
    if len(sig) > 0xFFFF:
        raise ValueError("signature too long")
    hash_bytes = bytes.fromhex(checks_hash)
    if len(hash_bytes) != 32:
        raise ValueError("checks_hash must be 32 bytes")
    version = TRAILER_V2 if challenge_id is not None else TRAILER_V1
    packed = (
        bytes([version])
        + struct.pack(">H", len(sig))
        + sig
        + uuid_mod.UUID(session_id).bytes
        + bytes([_STATUS_BYTES[status]])
        + hash_bytes
    )
    if version == TRAILER_V2:
        receipt_bytes = bytes.fromhex(receipt or "")
        anchor_bytes = bytes.fromhex(anchor_sha or "")
        if len(receipt_bytes) != 32:
            raise ValueError("receipt must be 32 bytes")
        if len(anchor_bytes) != 20:
            raise ValueError("anchor_sha must be 20 bytes")
        packed += uuid_mod.UUID(challenge_id).bytes + receipt_bytes + anchor_bytes
    return base64.b64encode(packed).decode()


def _decode_legacy_json(packed: bytes) -> PowTrailer:
    """Pre-v1 bundle: base64(JSON {token, session, status, checks_hash})."""
    try:
        bundle = json.loads(packed.decode())
        sig = base64.b64decode(bundle["token"], validate=True)
        session_id = str(uuid_mod.UUID(str(bundle["session"])))
        status = str(bundle["status"])
        checks_hash = str(bundle["checks_hash"]).lower()
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"legacy JSON trailer is malformed: {e}")
    if status not in _STATUS_BYTES:
        raise ValueError(f"legacy JSON trailer has unknown status {status!r}")
    if len(checks_hash) != 64 or any(c not in "0123456789abcdef" for c in checks_hash):
        raise ValueError("legacy JSON trailer has a malformed checks_hash")
    if not sig:
        raise ValueError("legacy JSON trailer has an empty signature")
    return PowTrailer(TRAILER_V1, sig, session_id, status, checks_hash, legacy_json=True)


def decode_pow_trailer(b64_value: str) -> PowTrailer:
    """Strictly decode a trailer value.  Raises ValueError on any malformation."""
    try:
        packed = base64.b64decode(b64_value, validate=True)
    except Exception as e:
        raise ValueError(f"trailer is not valid base64: {e}")
    if not packed:
        raise ValueError("empty trailer")
    if packed[:1] == b"{":
        return _decode_legacy_json(packed)
    version = packed[0]
    if version not in (TRAILER_V1, TRAILER_V2):
        raise ValueError(f"Unknown PoW trailer version: {version}")

    offset = 1

    def take(n, what):
        nonlocal offset
        chunk = packed[offset:offset + n]
        if len(chunk) != n:
            raise ValueError(f"trailer truncated while reading {what}")
        offset += n
        return chunk

    sig_len = struct.unpack(">H", take(2, "sig_len"))[0]
    sig = take(sig_len, "signature")
    if not sig:
        raise ValueError("empty signature")
    session_id = str(uuid_mod.UUID(bytes=take(16, "session_id")))
    status_byte = take(1, "status")[0]
    if status_byte not in _STATUS_NAMES:
        raise ValueError(f"unknown status byte {status_byte}")
    status = _STATUS_NAMES[status_byte]
    checks_hash = take(32, "checks_hash").hex()
    challenge_id = receipt = anchor_sha = None
    if version == TRAILER_V2:
        challenge_id = str(uuid_mod.UUID(bytes=take(16, "challenge_id")))
        receipt = take(32, "receipt").hex()
        anchor_sha = take(20, "anchor_sha").hex()
    if offset != len(packed):
        raise ValueError("trailing bytes after trailer")
    return PowTrailer(version, sig, session_id, status, checks_hash,
                      challenge_id, receipt, anchor_sha)


def first_trailer_value(raw: str) -> str:
    """
    First non-empty line of a `%(trailers:key=PoW-Checks,valueonly)` expansion.
    Git older than 2.22 does not understand the key= option and echoes the
    format string back; treat that as "no trailer" instead of "malformed".
    """
    for line in (raw or "").splitlines():
        line = line.strip()
        if line and not line.startswith("%("):
            return line
    return ""


def allowed_anchors(first_parent: Optional[str], grand_parent: Optional[str]) -> set:
    """Anchors a verifier accepts for a commit with the given lineage."""
    return {first_parent or ZERO_SHA, grand_parent or ZERO_SHA}


# ---------------------------------------------------------------------------
# Challenge receipt (SPEC.md section A.4)
# ---------------------------------------------------------------------------

def canonical_corpus_path(path: str) -> str:
    """'/pwd/pow-corpus/nested/a.py' -> 'nested/a.py' (mount-point independent)."""
    p = (path or "").replace("\\", "/")
    marker = CORPUS_DIRNAME + "/"
    idx = p.rfind(marker)
    if idx >= 0:
        return p[idx + len(marker):]
    return p.rsplit("/", 1)[-1]


def finding_line(detector: str, path: str, line, raw: str) -> str:
    return f"{detector}:{canonical_corpus_path(path)}:{int(line)}:{sha256_hex(raw or '')}"


def compute_receipt(lines: Iterable[str], tool_version: str) -> str:
    body = "\n".join(sorted(set(lines))) + "\n" + (tool_version or "")
    return sha256_hex(body)


def parse_scanner_jsonl(text: str) -> List[dict]:
    """
    Parse trufflehog --json output.  Returns dicts with keys
    detector, file, line, raw, redacted and (git source only) commit, email,
    timestamp.  Non-finding lines are skipped.
    """
    findings = []
    for raw_line in (text or "").splitlines():
        raw_line = raw_line.strip()
        if not raw_line.startswith("{"):
            continue
        try:
            d = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        detector = d.get("DetectorName")
        if not detector:
            continue
        data = (d.get("SourceMetadata") or {}).get("Data") or {}
        meta = {}
        for key in ("Filesystem", "Git", "Github"):
            if key in data and isinstance(data[key], dict):
                meta = data[key]
                break
        findings.append({
            "detector": detector,
            "file": meta.get("file", ""),
            "line": int(meta.get("line") or 0),
            "raw": d.get("Raw") or "",
            "redacted": d.get("Redacted") or "",
            "commit": meta.get("commit"),
            "email": meta.get("email"),
            "timestamp": meta.get("timestamp"),
        })
    return findings


def receipt_from_jsonl(text: str, tool_version: str) -> str:
    lines = [finding_line(f["detector"], f["file"], f["line"], f["raw"])
             for f in parse_scanner_jsonl(text)]
    return compute_receipt(lines, tool_version)


# ---------------------------------------------------------------------------
# Challenge tag + artifact naming
# ---------------------------------------------------------------------------

def challenge_tag(hmac_key: str, challenge_id: str, session_id: str, receipt: str) -> str:
    msg = f"{challenge_id}|{session_id}|{receipt}".encode()
    return hmac.new(hmac_key.encode(), msg, hashlib.sha256).hexdigest()


def tags_equal(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").encode(), (b or "").encode())


def challenge_artifact_name(session_id: str) -> str:
    return f"pow-challenge-{session_id}"


def attestation_artifact_name(session_id: str, checks_hash: str, state: str) -> str:
    return f"pow-attestation-{session_id}-{checks_hash}-{state}"
