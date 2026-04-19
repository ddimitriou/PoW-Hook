# PoW-Hook: Proof-of-Work Git Validator

[![CI](https://github.com/ddimitriou/PoW-Hook/actions/workflows/ci.yml/badge.svg)](https://github.com/ddimitriou/PoW-Hook/actions/workflows/ci.yml)
**PoW-Hook** is an autonomous "Proof of Work" validation system for Github repositories. It cryptographically guarantees that no code enters your remote repository unless it has legitimately passed your local quality, linting, or security checks.

The idea for this project came from reviewing various solutions that allow the blocking of publishing secrets directly into github. The industry standard is to use the [Github Advanced Security] product, which runs a pre-receive hook server side and block everything before it hits the git ledger. The intent was to develop an easy way to prevent at-scale developer from committing secrets and then accidentally push them into Github.

This reliably defeats developers bypassing rules with `git commit --no-verify`, deleting their `.git/hooks` folder, or skipping local tests — even malicious insiders.

It is a lower cost approach for smaller teams requiring more stringent controls without allocating a lot of budget, as the main resource for this kind of verification is only Github Action Runner (SaaS) minutes.

This project was created with [Google Antigravity](https://antigravity.google/) and [Claude Code](https://claude.com/product/claude-code).

---

## How It Works

PoW-Hook securely enforces that developers run required quality checks (linters, secret scanners, unit tests) locally before they are permitted to push to a central repository.

The system is constructed with an aggressive zero-trust architecture, treating the developer's client machine as untrusted until proven otherwise by cryptographic signatures and remote server-side validations.

[👉 **View the complete Sequence and Architecture Diagrams in `ARCHITECTURE.md`**](ARCHITECTURE.md)

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

Add in your desired `POW_CHECKS_CMD` command that runs the checks you need to perform (the default is `trufflehog`).

```bash
python3 admin_install.py [TARGET_DIR]
```

- **Option 1 — GitHub Actions**: Scaffolds `.github/workflows/` and `.github/scripts/` from `admin_templates/github/`.
- **Option 2 — GitHub Enterprise**: Deploys the `pre-receive` hook from `admin_templates/pre-receive_hook/`.

Both options write a `.pow-config.json` file that the local hooks read to determine verification mode. Commit this file to the repository, and push it to the remote.

### 2. Developer Onboarding

Modify the `.env.sample` file and add in your desired `POW_CHECKS_CMD` command which should be the same as in the `Administration Setup` step.


For each developer this should be installed locally in their repository. You can pass an optional target repository path. 

```bash
./install.sh [TARGET_REPO]
```

This will:
- Detect the SSH private key used for GitHub (`ssh -G github.com`).
- Create a Python virtual environment (`.venv/`).
- Install `pre-commit`, `commit-msg`, and `pre-merge-commit` hooks with the correct interpreter path.

The key used for signing must be [registered on the developer's GitHub account](https://github.com/settings/keys). No manual public key exchange with the admin is needed — keys are fetched live from the GitHub API at verification time.

### 3. Bootstrap the Repository (two-commit setup)

The validator runs on every push to `main`. The very first push — which delivers the workflow file itself — has no PoW trailers yet, so it would fail its own check. PoW-Hook handles this with a `POW_ENFORCE` flag embedded directly in the workflow YAML (not a repository secret), making it tamper-evident: changing it back to `"false"` would itself require passing enforcement.

**Steps:**

1. Run `admin_install.py` — it scaffolds `.github/workflows/pow-validator.yml` with `POW_ENFORCE: "false"`.
2. Commit `.pow-config.json` and the `.github/` directory and push to `main` *(no hooks needed yet)*.
3. Confirm the `verify-pow` workflow run succeeds and prints `⚠️ POW_ENFORCE is not "true" — validation is disabled`.
4. Run `./install.sh` to install local hooks on every developer machine.
5. Open `.github/workflows/pow-validator.yml`, change `POW_ENFORCE: "false"` → `POW_ENFORCE: "true"`, and commit **with hooks running** (this commit gets a valid PoW signature).
6. Push — the validator now enforces signatures on every subsequent commit.

From step 5 onward, every commit must carry a valid PoW signature.

> [!NOTE]
> **Why this is self-reinforcing:** `POW_ENFORCE` lives in the workflow file, not in repository secrets. Reverting it to `"false"` is itself a commit that must pass PoW validation — so enforcement cannot be silently disabled by anyone without leaving a traceable, signed commit in the repository history.

### 4. GitHub Repository Secrets

| Secret               | Description                                                         |
|----------------------|---------------------------------------------------------------------|
| `GITHUB_TOKEN`       | Auto-provided by GitHub Actions — no manual setup required          |
| `POW_ADMIN_HANDLES`  | *(Optional)* Space-separated `@handles` to tag on PR violations     |
| `POW_GITHUB_API_URL` | *(Optional)* Override GitHub API base URL (GitHub Enterprise Server) |

No developer public keys need to be stored as secrets — they are resolved at runtime from each committer's GitHub profile.

### 5. GitHub Workflow Setup (`POW_CHECKS_CMD`)

The server-side validator cryptographically strictly enforces that the developer ran the *exact* required checks.
In `.github/workflows/pow-validator.yml` and `.github/workflows/pow-ledger.yml`, ensure the `POW_CHECKS_CMD` environment variable is defined and matches the client's command string literally:

```yaml
env:
  POW_CHECKS_CMD: 'docker run --rm -v "$(git rev-parse --show-toplevel)":/pwd trufflesecurity/trufflehog:latest filesystem /pwd --no-verification --fail'
```

We're using [trufflehog](https://github.com/trufflesecurity/trufflehog) as the sample secret key search mechanism.

### 6. Developer `.env` Configuration

```env
# Command to run before signing (e.g., linters, secret scanners)
POW_CHECKS_CMD="docker run --rm -v $(pwd):/pwd trufflesecurity/trufflehog:latest filesystem /pwd --no-verification --fail"

# Optional: GitHub PAT with 'actions' scope for server-side attestation dispatch
GITHUB_PAT_LOCAL="ghp_..."

# Optional: repository slug for attestation dispatch
POW_GITHUB_REPO="owner/repo"
```

---

## Automated Incident Response & Pull Requests

When the server-side validator detects an invalid, fraudulent, or missing PoW signature on a pushed branch:
1. It **obliterates** the unverified commits natively by force-pushing the branch back to the last known perfectly verified commit state.
2. If there are any open **Pull Requests** attached to the compromised branch, it automatically closes them.
3. It tags administrative handles (configured via `POW_ADMIN_HANDLES`) in the closed PR comments, notifying them of the breach.

> [!WARNING]
> **Manual Hard-Deletion Required**
> While PoW-Hook automatically blocks unverified commits and automatically closes compromised Pull Requests, GitHub's API does not expose functionality to completely, permanently hard-delete a Pull Request. To completely scrub the orphaned, unverified commit history completely outside of the repository's background cache refs, an administrator will be instructed to submit a ticket to GitHub Support with a direct link provided in the PR comment.

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
