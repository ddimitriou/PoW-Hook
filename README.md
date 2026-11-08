# PoW-Hook: Proof-of-Work Github Repository Validator

[![CI](https://github.com/ddimitriou/PoW-Hook/actions/workflows/ci.yml/badge.svg)](https://github.com/ddimitriou/PoW-Hook/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**PoW-Hook** is an autonomous "Proof of Work" validation system for Github repositories. It cryptographically guarantees that no code enters your remote repository unless it has legitimately passed your local quality, linting, or security checks.

The idea for this project came from reviewing various solutions that allow the blocking of publishing secrets directly into github. The industry standard is to use the [Github Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security) product, which runs a pre-receive hook server side and block everything before it hits the git ledger. The intent was to develop an easy way to prevent at-scale developer from committing secrets and then accidentally push them into Github.

This reliably defeats developers bypassing rules with `git commit --no-verify`, deleting their `.git/hooks` folder, or skipping local tests — even malicious insiders.

It is a lower cost approach for smaller teams requiring more stringent controls without allocating a lot of budget, as the main resource for this kind of verification is only Github Action Runner (SaaS) minutes.

This project was created with [Google Antigravity](https://antigravity.google/) and [Claude Code](https://claude.com/product/claude-code).

---

## How It Works

PoW-Hook securely enforces that developers run required quality checks (linters, secret scanners, unit tests) locally before they are permitted to push to a central repository.

The system is constructed with an aggressive zero-trust architecture, treating the developer's client machine as untrusted until proven otherwise by cryptographic signatures and remote server-side validations. As a final zero-trust fallback, the server gatekeeper independently executes the exact same quality checks on the incoming commits to ensure no malicious bypass occurred.

[👉 **View the complete Sequence and Architecture Diagrams in `ARCHITECTURE.md`**](ARCHITECTURE.md)

You can also visit my blog where I have published a post about it at [here](https://must-feed.com/2026/04/18/pow-hook-zero-trust-security-for-your-git-hooks/)

---

## Supported Key Types

The signing and verification layer handles all SSH key types supported by GitHub:

| Key type          | Algorithm                      |
|-------------------|--------------------------------|
| Ed25519           | EdDSA (no hash — pure)         |
| Ed448             | EdDSA (no hash — pure)         |
| ECDSA (P-256/384/521) | ECDSA with SHA-256          |
| RSA               | PKCS#1 v1.5 with SHA-256       |

The correct algorithm is chosen automatically at runtime based on the key loaded — no configuration required.

---

## Prerequisites

Before installing or running PoW-Hook, ensure you have the following requirements met:

1. **Git version >= 2.15.0**: Required for `git interpret-trailers --in-place` support.
2. **GitHub Account Setup**:
   - An SSH key generated and added to your GitHub account (used for commit signing).
   - A Personal Access Token (PAT) with `actions` scope (required for server-side attestation dispatch).
3. **Repository Setup**:
   - A valid GitHub repository slug.

The `POW` environment variable must be properly configured in your local `.env` file (see the Developer Configuration section).

---

## Installation

### 1. Administrator Setup

Run once per repository to choose the enforcement backend. You can pass an optional target directory to install the configuration in a different project.

Add your desired `checks_cmd` to the `POW` JSON configuration (the default is `trufflehog`).

```bash
python3 admin_install.py [TARGET_DIR]
```

- **Option 1 — GitHub Actions**: Scaffolds `.github/workflows/` and `.github/scripts/` from `admin_templates/github/`.
- **Option 2 — GitHub Enterprise**: Deploys the `pre-receive` hook from `admin_templates/pre-receive_hook/`.

Both options scaffold the necessary files. Commit the `.github/` directory to the repository and push it to the remote.

### 2. Developer Onboarding

Copy `.env.example` to `.env` and configure the `POW` JSON variable with your desired `checks_cmd` (should match the value in the workflow YAML).


For each developer this should be installed locally in their repository. You can pass an optional target repository path. 

```bash
./install.sh [TARGET_REPO]
```

This will:
- Detect the SSH private key used for GitHub (`ssh -G github.com`) and store it as `ssh_key` in the `POW` JSON of `.env`.
- Create a central Python virtual environment (`~/.pow-hook/venv`).
- Install `pre-commit`, `commit-msg`, and `pre-merge-commit` hooks (plus the shared `pow_client.py` / `pow_trailer.py` modules) with the correct interpreter path.

For the full v2 protocol (challenge-corpus proof of execution) the `POW` JSON also needs `github_pat_local`, `github_repo` and `corpus_cmd` — see [section 6](#6-developer-env-configuration). Without them the hooks emit v1 trailers, which the server accepts only while `allow_v1` is `"true"`.

The key used for signing must be [registered on the developer's GitHub account](https://github.com/settings/keys). No manual public key exchange with the admin is needed — keys are fetched live from the GitHub API at verification time.

### 3. Bootstrap the Repository (two-commit setup)

The validator runs on every push to `main`. The very first push — which delivers the workflow file itself — has no PoW trailers yet, so it would fail its own check. PoW-Hook handles this with an `enforce` flag inside the `POW` JSON embedded directly in the workflow YAML (not a repository secret), making it tamper-evident: changing it back to `"false"` would itself require passing enforcement.

**Steps:**

1. Run `admin_install.py` — it scaffolds `.github/workflows/pow-validator.yml` with `"enforce": "false"` in the `POW` JSON.
2. Commit the `.github/` directory and push to `main` *(no hooks needed yet)*.
3. Confirm the `verify-pow` workflow run succeeds and prints `⚠️ enforce is not "true" in POW — validation is disabled`.
4. Run `./install.sh` to install local hooks on every developer machine.
5. Open `.github/workflows/pow-validator.yml`, change `"enforce": "false"` → `"enforce": "true"` in the `POW` JSON, and commit **with hooks running** (this commit gets a valid PoW signature).
6. Push — the validator now enforces signatures on every subsequent commit.

From step 5 onward, every commit must carry a valid PoW signature.

> [!NOTE]
> **Why this is self-reinforcing:** `enforce` lives in the `POW` JSON inside the workflow file, not in repository secrets. Reverting it to `"false"` is itself a commit that must pass PoW validation — so enforcement cannot be silently disabled by anyone without leaving a traceable, signed commit in the repository history.

### 4. GitHub Repository Secrets

| Secret               | Description                                                         |
|----------------------|---------------------------------------------------------------------|
| `GITHUB_TOKEN`       | Auto-provided by GitHub Actions — no manual setup required          |
| `POW_HMAC_KEY`       | **Required for v2.** Injected as `hmac_key`; shared by the ledger (mints challenge tags) and the validator (verifies receipts). `admin_install.py` prints a fresh value; or `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `POW_ADMIN_HANDLES`  | *(Optional)* Space-separated `@handles` to tag on PR violations and sweep issues (injected as `admin_handles`) |
| `POW_REVOKE_WEBHOOK` | *(Optional)* URL the nightly sweep POSTs new violations to (injected as `revoke_webhook`; `POW_REVOKE_WEBHOOK_TOKEN` as bearer token) |
| `POW_GITHUB_API_URL` | *(Optional)* Override GitHub API base URL for Enterprise Server (injected as `github_api_url`) |

No developer public keys need to be stored as secrets — they are resolved at runtime from each committer's GitHub profile.

> [!IMPORTANT]
> Anyone with write access can dispatch `pow-ledger.yml` on *their own branch* with a tampered copy of the workflow. The validator therefore only accepts challenges minted from `ledger_ref` (default `main`), and you should store `POW_HMAC_KEY` in a GitHub **environment** whose deployment-branch policy only allows `main` (then set `environment: pow-ledger` on the `mint-challenge` job). Repo admins can read secrets regardless; that is an explicit non-goal (see `SPEC.md`).

### 5. GitHub Workflow Setup (`POW` env var)

The server-side validator cryptographically strictly enforces that the developer ran the *exact* required checks.
In `.github/workflows/pow-validator.yml`, ensure the `POW` environment variable contains a JSON object with `checks_cmd` matching the client's command string literally:

```yaml
env:
  POW: >-
    {
      "checks_cmd": "docker run --rm -v \"$(git rev-parse --show-toplevel)\":/pwd trufflesecurity/trufflehog:3.99.8 filesystem /pwd --no-verification --fail",
      "enforce": "true",
      "allow_v1": "true",
      "auto_revert": "false",
      "ledger_ref": "main",
      "hmac_key": "${{ secrets.POW_HMAC_KEY }}"
    }
```

We're using [trufflehog](https://github.com/trufflesecurity/trufflehog) as the sample secret scanner. The image tag is **pinned** on purpose: the challenge receipt (see Deterrence Mechanisms below) and the nightly sweep only agree with the client when everyone runs the same scanner build. The same tag appears in `pow-ledger.yml` (`POW_SCANNER_IMAGE`), `pow-sweep.yml` and the developers' `corpus_cmd`; bump them together.

Server-side keys of the `POW` JSON:

| Key           | Default   | Meaning                                                                                   |
|---------------|-----------|-------------------------------------------------------------------------------------------|
| `enforce`     | `"false"` | Flip to `"true"` on the second commit (see bootstrap above)                               |
| `allow_v1`    | `"true"`  | Accept v1 / legacy trailers (no challenge receipt) during migration; set `"false"` once all clients run v2 |
| `auto_revert` | `"false"` | Force-reset the branch on *cryptographically confirmed* forgeries (needs `contents: write`) |
| `ledger_ref`  | `main`    | Only challenges minted by `pow-ledger.yml` on this ref are accepted                       |
| `hmac_key`    | —         | Secret shared with `pow-ledger.yml`                                                       |

After every commit verifies, the validator also **re-runs `checks_cmd` on the checked-out tree** as a zero-trust fallback.

### 6. Developer `.env` Configuration

All configuration is set via a single `POW` environment variable containing a JSON object:

```env
POW='{"checks_cmd":"docker run --rm -v \"$(git rev-parse --show-toplevel)\":/pwd trufflesecurity/trufflehog:3.99.8 filesystem /pwd --no-verification --fail","corpus_cmd":"docker run --rm -v \"{corpus_dir}\":/pwd trufflesecurity/trufflehog:3.99.8 filesystem /pwd --no-verification --json","github_pat_local":"ghp_...","github_repo":"owner/repo"}'
```

| Key | Description |
|-----|-------------|
| `checks_cmd` | Command to run before signing (e.g., linters, secret scanners); must equal the server's byte-for-byte |
| `corpus_cmd` | Challenge-corpus scan — same pinned scanner, JSON output; `{corpus_dir}` is substituted |
| `github_pat_local` | GitHub PAT used to dispatch the ledger and download challenge artifacts (classic: `repo` + `workflow`; fine-grained: Actions read/write) |
| `github_repo` | `owner/repo` slug for attestation dispatch (`install.sh` fills it from the origin remote) |
| `ssh_key` | Path to SSH private key (auto-detected by `setup_hooks.py`) |
| `ledger_ref` | Ref `pow-ledger.yml` is dispatched on (default `main`) |
| `challenge_timeout` / `challenge_poll` | Seconds to wait for the minted corpus (default 180) / poll interval (default 5) |
| `challenge_optional` | `"true"`: fall back to a v1 trailer when minting fails |
| `admin_handles` | Space-separated `@handles` for PR violation notifications (server) |
| `enforce` | Set to `"true"` to enable server-side enforcement (server) |
| `github_api_url` | Override GitHub API base URL (Enterprise Server) |
| `github_token` | GitHub token for pre-receive hook (Enterprise) |
| `allow_v1` | Pre-receive / validator: accept v1 and legacy trailers (default `"true"`) |
| `ssh_key_override` | Override SSH key path for testing/CI |

Each commit costs one ledger workflow spin-up (typically 15–60 s); the real tree scan runs while the challenge is being minted.

---

## Deterrence Mechanisms (v2)

PoW-Hook v1 proved *who* attested *what tree*. A malicious developer with admin rights on their own machine could still stub the scanner and sign a `PASSED` verdict. v2 adds two mechanisms (design in [`SPEC.md`](SPEC.md)) that make forgery **noisy, non-repudiable and no faster than compliance**:

### A. Challenge-Corpus Proof of Execution

1. `pre-commit` dispatches `MINT_CHALLENGE` to `pow-ledger.yml`.
2. The ledger generates a small corpus (20–50 files) with 3–8 **planted** secrets (random AWS / GitHub / Stripe / Slack / … shapes the pinned scanner detects) and 5–15 **decoys** (near-misses it provably ignores), self-checks it against the pinned scanner, and publishes `pow-challenge-<session>` with an HMAC tag over the expected findings. The expected receipt is never published.
3. The client downloads the corpus, runs `corpus_cmd`, canonicalises the findings into a receipt (`detector:path:line:sha256(secret)` lines, sorted, plus tool version) and signs it inside the **v2 trailer** together with the tree hash, session, challenge id and a lineage anchor.
4. The validator recomputes `HMAC(key, challenge_id|session_id|receipt)` and compares it with the minted tag. No server-side re-scan is needed. A receipt from a stubbed or wrong-version scanner is **INVALID**.

### B. Nightly Audit Sweep

`pow-sweep.yml` runs `trufflehog git` over the entire history every night and cross-references each finding with the attestation trailer of the commit that introduced it:

| Class            | Meaning                                                                                           |
|------------------|---------------------------------------------------------------------------------------------------|
| `FORGERY`        | `PASSED` trailer, valid signature, matching cmd hash, secret present — the forger's own signature over a false verdict |
| `VERSION_DRIFT`  | As above but the attested scanner version differs from the sweep's (warning)                      |
| `LEAK_HONEST`    | Secret present, trailer absent / FAILED / unverifiable — the validator should have blocked it      |
| `REPLAY`         | Same session or challenge id reused on several verifying commits                                  |
| `MISSING`        | No trailer after the enforcement epoch (report only)                                              |

Every run uploads a JSON + Markdown report (90-day retention). Violations open or update a single `🚨 PoW Sweep` issue tagging `admin_handles`, are optionally POSTed to `revoke_webhook`, and turn the run red. Findings before the enforcement epoch (`sweep_epoch`, default: the oldest attested commit) are baselined on the first run so historical noise never pages anyone.

---

## Automated Incident Response & Pull Requests

The validator reaches one of four outcomes per commit and stops at the first failure:

| Outcome        | Cause                                                                                             | Effect                                                                 |
|----------------|---------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `OK`           | Trailer, signature, challenge receipt, ledger record and the server-side re-run of `checks_cmd` all pass | Check passes                                                    |
| `REJECTED`     | Missing/malformed trailer, wrong cmd hash, status not `PASSED`, anchor mismatch, v1 not allowed, no ledger record, server-side check failed | Check fails; PR gets a comment tagging `admin_handles`; **refs are never rewritten** |
| `INVALID`      | Signature does not verify against the author's registered keys, or the signed receipt contradicts the minted tag | Check fails; with `"auto_revert": "true"` the branch is force-reset to the last valid commit and open PRs are closed |
| `INCONCLUSIVE` | GitHub API error or missing configuration (e.g. `hmac_key`)                                       | Check fails so branch protection blocks the merge; nothing is rewritten; re-run |

Protect `main` with a required `verify-pow` status check so that red results actually block merges. Automatic reverts are opt-in and limited to cryptographically confirmed forgeries, so an API outage can never wipe a branch.

> [!WARNING]
> **Manual Hard-Deletion Required**
> When a revert does happen, GitHub's API does not expose functionality to permanently hard-delete a Pull Request. To scrub the orphaned commits from the repository's background refs, an administrator is pointed (in the PR comment) to a GitHub Support ticket.

---

## Branch Protection

For zero-window protection on `main`:
1. Go to **Settings → Branches → Branch Protection Rules**.
2. Enable **Require status checks to pass before merging**.
3. Select `verify-pow` as a required check.
4. Enable **Require pull request reviews** and disable direct pushes.

This makes the force-revert a fallback — GitHub natively blocks unverified merges at the branch level.

---

## Running Tests

### Unit tests

```bash
# On Linux / macOS
pip install cryptography pytest
python3 -m pytest tests/test_hooks.py -v --tb=short

# On Windows (runs inside a Docker container — required for git hook execution)
bash tests/run_tests_windows.sh
```

### CI E2E tests (no act required)

These scripts run `verify_pow.py` directly against a lightweight mock GitHub API server that also acts as the ledger (it mints challenges solvable by `tests/fake_scanner.py`). They work on any Linux/macOS machine with Python 3 and `ssh-keygen`.

```bash
# v2 signing + verification, INVALID (wrong hmac_key) and INCONCLUSIVE (API down) paths
PYTHON=python3 bash tests/test_ci_github_ssh.sh

# Real pinned trufflehog: local block, bypass rejection, challenge mint determinism, nightly sweep (requires Docker)
PYTHON=python3 bash tests/test_ci_trufflehog.sh
```

The unit suite never needs Docker: the challenge protocol and the sweep are exercised with the fake scanner and the mock API. Set `POW_HOOK_PYTHON=/path/to/python` to make `setup_hooks.py` use a given interpreter instead of creating the central venv (the tests do this).

---

## Continuous Integration

Pushing to any branch or opening a pull request triggers the CI workflow at `.github/workflows/ci.yml`:

| Job | What it does |
|-----|--------------|
| `lint` | flake8 — fails on syntax errors / undefined names, warns on style |
| `unit-tests` | Runs `pytest test_hooks.py` directly on `ubuntu-latest` (codec, hooks, validator, challenge protocol, sweep) |
| `e2e-github-ssh` | Runs `test_ci_github_ssh.sh` — v2 signing, challenge receipt, INVALID / INCONCLUSIVE paths, no refs rewritten |
| `e2e-trufflehog` | Runs `test_ci_trufflehog.sh` — pinned trufflehog blocks a secret, bypass rejected, mint ↔ client receipt match, sweep flags the leak |

E2E jobs only start if unit tests pass.

---

## Project Structure

```
├── SPEC.md                     # v2 deterrence design (challenge corpus + nightly sweep)
│
├── tests/                      # Dedicated tests folder
│   ├── test_hooks.py               # Unit + integration suite (codec, hooks, validator, challenge, sweep)
│   ├── test_mock_github_api.py     # Mock GitHub API + ledger (mints fake challenges)
│   ├── fake_scanner.py             # Deterministic trufflehog stand-in (no Docker)
│   ├── test_ci_github_ssh.sh       # CI E2E: v2 signing, INVALID / INCONCLUSIVE paths
│   ├── test_ci_trufflehog.sh       # CI E2E: real trufflehog scan, mint determinism, sweep
│   ├── test_e2e_github_ssh.sh      # Local E2E: act simulation
│   ├── test_e2e_act_trufflehog.sh  # Local E2E: act trufflehog
│   ├── run_tests_windows.sh        # Dockerized test runner (Windows-only)
│   └── Dockerfile.test             # Container for unit tests
│
├── hooks_templates/
│   ├── pre-commit              # Thin wrapper → pow_client.run_session
│   ├── pre-merge-commit        # Same, for merge operations
│   ├── commit-msg              # Signs the v1/v2 payload with the SSH key, injects the trailer
│   └── pow_client.py           # Session flow: dispatch, checks, challenge download + receipt
│
├── admin_templates/
│   ├── github/
│   │   ├── workflows/
│   │   │   ├── pow-validator.yml   # Push/PR gatekeeper (GitHub Actions)
│   │   │   ├── pow-ledger.yml      # Attestation recorder + challenge minter (workflow_dispatch)
│   │   │   └── pow-sweep.yml       # Nightly full-history audit sweep
│   │   └── scripts/
│   │       ├── pow_trailer.py      # Shared protocol: POW config loader, trailer codec, receipt, HMAC tag
│   │       ├── pow_github.py       # GitHub API helpers (ApiError → INCONCLUSIVE)
│   │       ├── verify_pow.py       # Validator: signature, challenge receipt, ledger record, server re-run
│   │       ├── mint_challenge.py   # Corpus generator + self-check + tag
│   │       └── sweep_audit.py      # Cross-reference findings ↔ trailers, report, issue, webhook
│   └── pre-receive_hook/
│       └── pre-receive             # Standalone verifier for GitHub Enterprise (legacy, v1 and v2 trailers)
│
├── .github/
│   └── workflows/
│       └── ci.yml                  # CI: unit tests + E2E tests on every push / PR
│
├── admin_install.py            # Interactive admin setup (path-independent)
├── install.sh                  # Developer onboarding (path-independent)
├── setup_hooks.py              # Hook installer with cross-platform shebang handling
│
├── .env.example                # Environment variable template
├── .gitignore
└── README.md
```

---

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.
