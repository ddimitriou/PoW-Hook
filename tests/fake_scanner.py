#!/usr/bin/env python3
"""
Deterministic stand-in for trufflehog used by the test-suite (no Docker needed).

Usage:
    fake_scanner.py <directory>    trufflehog-style JSON lines on stdout
    fake_scanner.py --version      prints the tool version

Detects exactly:
    Github       ghp_ followed by exactly 36 [A-Za-z0-9]
    Stripe       sk_live_ followed by exactly 24 [A-Za-z0-9]
    HuggingFace  hf_ followed by exactly 34 [A-Za-z0-9]
so the one-character-short variants are reliable decoys (same shapes
mint_challenge.py uses for github_pat / stripe / huggingface).
"""
import json
import os
import re
import sys

VERSION = "fake-scanner 1.0"
PATTERNS = [
    ("Github", re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9])")),
    ("Stripe", re.compile(r"(?<![A-Za-z0-9])sk_live_[A-Za-z0-9]{24}(?![A-Za-z0-9])")),
    ("HuggingFace", re.compile(r"(?<![A-Za-z0-9])hf_[A-Za-z0-9]{34}(?![A-Za-z0-9])")),
]


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    if sys.argv[1] == "--version":
        print(VERSION)
        return
    root = sys.argv[1]
    for dirpath, _, files in sorted(os.walk(root)):
        for name in sorted(files):
            path = os.path.join(dirpath, name)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, 1):
                for detector, rx in PATTERNS:
                    for m in rx.finditer(line):
                        print(json.dumps({
                            "SourceMetadata": {"Data": {"Filesystem": {"file": path.replace("\\", "/"), "line": lineno}}},
                            "DetectorName": detector,
                            "Raw": m.group(0),
                            "Verified": False,
                        }))


if __name__ == "__main__":
    main()
