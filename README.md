# PoW-Hook: Proof-of-Work Git Validator

[![CI](https://github.com/ddimitriou/PoW-Hook/actions/workflows/ci.yml/badge.svg)](https://github.com/ddimitriou/PoW-Hook/actions/workflows/ci.yml)
**PoW-Hook** is an autonomous "Proof of Work" validation system for Git repositories. It cryptographically guarantees that no code enters your remote repository unless it has legitimately passed your local quality, linting, or security checks.

This reliably defeats developers bypassing rules with `git commit --no-verify`, deleting their `.git/hooks` folder, or skipping local tests — even malicious insiders.

The idea for this project came from reviewing various solutions that allow the blocking of publishing secrets directly into github. The industry standard is to use the github advanced security product, which runs a pre-receive hook server side and block everything before it hits the git ledger.

This is a lower cost approach for smaller teams requiring more stringent controls without allocating a lot of budget, as the main resource for this kind of verification is only github action runner minutes.

This project was created with Google Antigravity and Claude Code.

---

## How It Works

The system operates in three layers:

### Layer 1 — The Laborer (`pre-commit` / `pre-merge-commit`)
When a developer runs `git commit` or `git merge`:
1. A unique **Session UUID** is generated locally.
2. The **Git Tree Hash** (`git write-tree`) is computed from the staged index.
3. A `STARTED` attestation is optionally dispatched to the remote GitHub Ledger workflow.
4. Your custom quality checks (`POW_CHECKS_CMD`) execute.
5. A `PASSED` or `FAILED` attestation is dispatched.
6. On success, session metadata is written to `.git/POW_PASSED`.

### Layer 2 — The Notary (`commit-msg`)
1. Consumes `.git/POW_PASSED` — aborts if it is absent (bypass detected).
2. Constructs a **tri-factor signing payload**: `tree_hash|session_id|status`.
3. Digitally signs the payload with the developer's **SSH private key** (RSA, Ed25519, Ed448, or ECDSA — auto-detected from `ssh -G github.com` or `POW_SSH_KEY_OVERRIDE`).
4. Bundles all attestation metadata and the signature into a Base64 encoded JSON string.
5. Injects a single Git trailer:
   - `PoW-Checks: <base64 JSON string>`

### Layer 3 — The Gatekeeper (GitHub Actions / `pre-receive`)
When code is pushed:
1. Extracts the `PoW-Checks` trailer from each new commit.
2. Reconstructs the tri-factor payload and verifies the signature against the committer's **SSH public keys registered on GitHub** (fetched live via the GitHub API).
3. Optionally cross-references the GitHub Artifacts API to confirm a `PASSED` attestation artifact exists for the session UUID.
4. Rejects and force-reverts any commits that fail either check.

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

## Installation

### 1. Administrator Setup

Run once per repository to choose the enforcement backend. You can pass an optional target directory to install the configuration in a different project.

```bash
python3 admin_install.py [TARGET_DIR]
```

- **Option 1 — GitHub Actions**: Scaffolds `.github/workflows/` and `.github/scripts/` from `admin_templates/github/`.
- **Option 2 — GitHub Enterprise**: Deploys the `pre-receive` hook from `admin_templates/pre-receive_hook/`.

Both options write a `.pow-config.json` file that the local hooks read to determine verification mode. Commit this file to the repository.

### 2. Developer Onboarding

Each developer installs the local hooks in their repository. You can pass an optional target repository path.

```bash
./install.sh [TARGET_REPO]
```

This will:
- Detect the SSH private key used for GitHub (`ssh -G github.com`) — no new key is generated.
- Create a Python virtual environment (`.venv/`).
- Install `pre-commit`, `commit-msg`, and `pre-merge-commit` hooks with the correct interpreter path.

The key used for signing must be [registered on the developer's GitHub account](https://github.com/settings/keys). No manual public key exchange with the admin is needed — keys are fetched live from the GitHub API at verification time.

### 3. GitHub Repository Secrets

| Secret               | Description                                                         |
|----------------------|---------------------------------------------------------------------|
| `GITHUB_TOKEN`       | Auto-provided by GitHub Actions — no manual setup required          |
| `POW_ADMIN_HANDLES`  | *(Optional)* Space-separated `@handles` to tag on PR violations     |
| `POW_GITHUB_API_URL` | *(Optional)* Override GitHub API base URL (GitHub Enterprise Server) |

No developer public keys need to be stored as secrets — they are resolved at runtime from each committer's GitHub profile.

### 4. GitHub Workflow Setup (`POW_CHECKS_CMD`)

The server-side validator cryptographically strictly enforces that the developer ran the *exact* required checks.
In `.github/workflows/pow-validator.yml` and `.github/workflows/pow-ledger.yml`, ensure the `POW_CHECKS_CMD` environment variable is defined and matches the client's command string literally:

```yaml
env:
  POW_CHECKS_CMD: 'docker run --rm -v "$(git rev-parse --show-toplevel)":/pwd trufflesecurity/trufflehog:latest filesystem /pwd --no-verification --fail'
```

### 5. Developer `.env` Configuration

```env
# Command to run before signing (e.g., linters, secret scanners)
POW_CHECKS_CMD="docker run --rm -v $(pwd):/pwd trufflesecurity/trufflehog:latest filesystem /pwd --no-verification --fail"

# Optional: GitHub PAT with 'actions' scope for server-side attestation dispatch
GITHUB_PAT_LOCAL="ghp_..."

# Optional: repository slug for attestation dispatch
POW_GITHUB_REPO="owner/repo"
```

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
python -m pytest tests/test_hooks.py -v --tb=short

# On Windows (runs inside a Docker container — required for git hook execution)
bash tests/run_tests_windows.sh
```

### CI E2E tests (no act required)

These scripts run `verify_pow.py` directly against a lightweight mock GitHub API server. They work on any machine with Python 3 and `ssh-keygen`.

```bash
# GitHub SSH signing + server-side verification
PYTHON=python3 bash tests/test_ci_github_ssh.sh

# Trufflehog local scan + server-side bypass rejection (requires Docker)
PYTHON=python3 bash tests/test_ci_trufflehog.sh
```

---

## Continuous Integration

Pushing to any branch or opening a pull request triggers the CI workflow at `.github/workflows/ci.yml`:

| Job | What it does |
|-----|--------------|
| `unit-tests` | Runs `pytest test_hooks.py` directly on `ubuntu-latest` |
| `e2e-github-ssh` | Runs `test_ci_github_ssh.sh` — verifies signing and rejection without act |
| `e2e-trufflehog` | Runs `test_ci_trufflehog.sh` — verifies trufflehog scan and bypass rejection |

E2E jobs only start if unit tests pass. The workflow has no dependency on `act` or large runner images.

---

## Project Structure

```
├── tests/                      # Dedicated tests folder
│   ├── test_hooks.py               # Unit test suite
│   ├── test_mock_github_api.py     # Mock GitHub API server
│   ├── test_ci_github_ssh.sh       # CI E2E: GitHub SSH signing
│   ├── test_ci_trufflehog.sh       # CI E2E: Trufflehog scan
│   ├── test_e2e_github_ssh.sh      # Local E2E: act simulation
│   ├── test_e2e_act_trufflehog.sh  # Local E2E: act trufflehog
│   ├── run_tests_windows.sh        # Dockerized test runner (Windows-only)
│   └── Dockerfile.test            # Container for unit tests
│
├── hooks_templates/
│   ├── pre-commit              # Runs checks, dispatches attestation, writes session
│   ├── pre-merge-commit        # Same as pre-commit, for merge operations
│   └── commit-msg              # Signs tri-factor payload with SSH key, injects trailers
│
├── admin_templates/
│   ├── github/
│   │   ├── workflows/
│   │   │   ├── pow-validator.yml   # Push/PR gatekeeper (GitHub Actions)
│   │   │   └── pow-ledger.yml      # Attestation recorder (workflow_dispatch)
│   │   └── scripts/
│   │       └── verify_pow.py       # Verifier: SSH key lookup + artifact cross-check
│   └── pre-receive_hook/
│       └── pre-receive             # Verifier for GitHub Enterprise (pre-receive hook)
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
