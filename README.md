# PoW-Hook: Proof-of-Work Git Validator 🛡️

**PoW-Hook** is an autonomous "Proof of Work" validation system for Git repositories. It mathematically guarantees that no code enters your remote repository unless it has legitimately passed your local quality, linting, or security checks.

This reliably defeats developers unintentionally (or intentionally) bypassing rules using `git commit --no-verify`, deleting their `.git/hooks` folder, or skipping local tests.

## 🧠 How It Works

The system operates in three layers with **server-side attestation**:

### Layer 1 — The Laborer (`pre-commit` / `pre-merge-commit`)
When a developer runs `git commit` or `git merge`:
1. A unique **Session UUID** is generated locally.
2. The **Git Tree Hash** (`git write-tree`) is computed from the staged index.
3. A `STARTED` attestation is dispatched to the remote GitHub Ledger workflow.
4. Your custom quality checks (`POW_CHECKS_CMD`) execute.
5. A `PASSED` or `FAILED` attestation is dispatched to the remote Ledger.
6. On success, session metadata is written to `.git/POW_PASSED`.

### Layer 2 — The Notary (`commit-msg`)
1. Consumes `.git/POW_PASSED` (aborts if it doesn't exist — bypasses detected).
2. Constructs a **tri-factor signing payload**: `tree_hash|session_id|status`.
3. Digitally signs the payload with the developer's RSA private key.
4. Injects three Git trailers via `git interpret-trailers`:
   - `Validated-At-Local: <base64 RSA signature>`
   - `PoW-Session: <UUID>`
   - `PoW-Status: PASSED`

### Layer 3 — The Gatekeeper (GitHub Actions / `pre-receive`)
When code is pushed:
1. Extracts all three trailers from each commit.
2. Reconstructs the tri-factor payload and verifies the RSA signature against registered public keys.
3. **Cross-references** the GitHub Artifacts API to confirm a `PASSED` attestation artifact exists for the session UUID.
4. Rejects and **obliterates** (force-push revert) any commits that fail either check.

## 🚀 Installation

### 1. Administrator Setup
Administrators run `admin_install.py` once per repository to select the enforcement backend:

```bash
python3 admin_install.py
```

- **Option 1 — GitHub Actions**: Copies workflow and script files into `.github/`.
- **Option 2 — GitHub Enterprise**: Deploys the `pre-receive` hook for server-side enforcement.

### 2. Developer Onboarding
Each developer installs the local hooks:

```bash
chmod +x install.sh
./install.sh
```

This will:
- Generate an RSA keypair in `~/.pow/` (if not already present).
- Create a Python virtual environment (`.venv/`).
- Install Git hooks with absolute venv shebangs.
- Print the public key for submission to the admin.

### 3. GitHub Repository Secrets

| Secret               | Description                                                   |
|----------------------|---------------------------------------------------------------|
| `POW_PUBLIC_KEYS`    | JSON dict mapping developer names to PEM public keys          |
| `POW_ADMIN_HANDLES`  | *(Optional)* Space-separated `@handles` to tag on violations  |

Example `POW_PUBLIC_KEYS` value:
```json
{
  "alice": "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----",
  "bob":   "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----"
}
```

### 4. Developer `.env` Configuration

```env
# Command to run before signing (e.g., linters, secret scanners)
POW_CHECKS_CMD="docker run --rm -v $(pwd):/pwd trufflesecurity/trufflehog:latest filesystem /pwd --no-verification --fail"

# GitHub PAT with 'actions' scope — needed for server-side attestation
GITHUB_PAT_LOCAL="ghp_..."

# Repository slug for attestation dispatch
POW_GITHUB_REPO="owner/repo"
```

## 🛡 Branch Protection

For zero-window protection on `main`:
1. Go to **Settings → Branches → Branch Protection Rules**.
2. Enable **Require status checks to pass before merging**.
3. Select `verify-pow` as a required check.
4. Enable **Require pull request reviews** and disable direct pushes.

This makes the Obliterator a fallback — GitHub natively blocks unverified merges.

## 🧪 Running Tests

```bash
# Unit tests (tri-factor signing, pre-receive, merge flows)
python3 test_hooks.py -v

# End-to-end test (Trufflehog + ACT)
chmod +x test_e2e_act_trufflehog.sh
./test_e2e_act_trufflehog.sh
```

## 📂 Project Structure

```
├── hooks_templates/
│   ├── pre-commit          # Runs checks, dispatches attestation, writes session
│   ├── pre-merge-commit    # Same as pre-commit, for merge operations
│   └── commit-msg          # Signs tri-factor payload, injects trailers
├── admin_templates/
│   ├── github/
│   │   ├── workflows/
│   │   │   ├── pow-validator.yml   # Push/PR gatekeeper
│   │   │   └── pow-ledger.yml      # Attestation recorder (workflow_dispatch)
│   │   └── scripts/
│   │       └── verify_pow.py       # Tri-factor + Artifact API verifier
│   └── pre-receive_hook/
│       └── pre-receive             # Offline tri-factor verifier (Enterprise)
├── admin_install.py        # Interactive admin setup
├── install.sh              # Developer onboarding script
├── setup_hooks.py          # Hook installer with venv shebang patching
├── test_hooks.py           # Unit test suite
├── test_e2e_act_trufflehog.sh  # E2E test with Trufflehog + ACT
├── .env.example            # Environment variable template
└── README.md
```
