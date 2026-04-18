# PoW-Hook Architecture

PoW-Hook is a highly secure, cryptographic Proof-of-Work system for Git. It strictly enforces that developers run required quality checks (linters, secret scanners, unit tests) locally before they are permitted to push to a central repository.

The system is constructed with an aggressive trust-no-one zero-trust architecture, treating the developer's client machine as untrusted until proven otherwise by cryptographic signatures and remote server-side attestations.

## High-Level Component Overview

```mermaid
graph TD
    subgraph "1. Client (Developer Machine)"
        ENV[.env<br>POW_CHECKS_CMD]
        HOOK_PC[pre-commit hook]
        HOOK_CM[commit-msg hook]
        SSH_KEY[SSH Private Key]
        
        ENV --> HOOK_PC
        HOOK_PC -->|Runs Checks| STATE[.git/POW_PASSED]
        HOOK_PC -->|Dispatches async| LEDGER
        STATE --> HOOK_CM
        SSH_KEY -->|Signs Payload| HOOK_CM
        HOOK_CM -->|Injects JSON Trailer| LOCAL_COMMIT[(Signed Commit<br>with PoW-Checks trailer)]
    end

    subgraph "3. The Ledger (Async Attestation)"
        LEDGER[pow-ledger.yml<br>Workflow Action]
        ARTIF[(Attestation Artifacts)]
        LEDGER -->|Creates| ARTIF
    end

    subgraph "2. Server Gatekeeper (GitHub/Enterprise)"
        REMOTE_COMMIT[(Incoming Git Push)]
        VAL_YML[pow-validator.yml / Server]
        VERIFY[verify_pow.py / pre-receive]
        GH_API[GitHub API<br>Public Keys]
        
        LOCAL_COMMIT -->|Pushed| REMOTE_COMMIT
        REMOTE_COMMIT ..-> VAL_YML
        VAL_YML --> VERIFY
        VERIFY -->|1. Fetches PubKeys| GH_API
        VERIFY -->|2. Validates Trailer Sig| REMOTE_COMMIT
        VERIFY -->|3. Cross-references Attestation| ARTIF
    end
```

## How It Works (Sequence)

The system enforces compliance through a carefully choreographed 4-phase sequence.

```mermaid
sequenceDiagram
    actor Dev as Developer
    participant Git as Local Git hooks
    participant Ledger as GitHub Action<br/>(pow-ledger.yml)
    participant GH as GitHub API
    participant Validator as Gatekeeper<br/>(verify_pow.py)

    Note over Dev, Git: Phase 1: Local Pre-commit
    Dev->>Git: git commit
    Git->>Git: Execute `pre-commit` hook
    Git->>Git: Hash `POW_CHECKS_CMD` (SHA256)
    Git->>Git: Generate unique Session UUID
    Git->>Git: Run defined quality checks
    
    %% Attestation Dispatch
    Note over Git, Ledger: Phase 2: Remote Attestation
    Git->>Ledger: workflow_dispatch (Session ID, Status, Cmd Hash)
    Git->>Git: Write execution metadata to `.git/POW_PASSED`
    Ledger-->>GH: Upload Ledger Artifact<br/>`pow-attestation-{session}-{cmd_hash}-PASSED`
    
    Note over Dev, Git: Phase 3: Cryptographic Signing
    Git->>Git: Execute `commit-msg` hook
    Git->>Git: Retrieve Tree Hash natively
    Git->>Git: Read metadata from `.git/POW_PASSED`
    Git->>Git: Construct Payload `checks_hash|tree_hash|session_id|status`
    Git->>Git: Digitally Sign payload with Local SSH Private Key
    Git->>Git: Base64 Encode JSON bundle
    Git->>Git: Inject `PoW-Checks: <Base64>` metadata trailer
    Git-->>Dev: Commit finalized locally

    Note over Dev, Validator: Phase 4: Push Gatekeeper Zero-Trust Verification
    Dev->>GH: git push origin main
    GH->>Validator: Push Event triggers Validator
    
    Validator->>GH: Query developer's Public SSH Keys (`/users/user/keys`)
    GH-->>Validator: Return Public Keys
    
    Validator->>Validator: Extract Base64 `PoW-Checks` payload
    Validator->>Validator: Cryptographically verify SSH signature
    
    Validator->>Validator: Hash Server's strictly expected `POW_CHECKS_CMD`
    Validator->>Validator: Assert local hash securely matches server hash
    
    Validator->>GH: Query GitHub Actions API for Artifact matching Session ID & Hash
    GH-->>Validator: Return artifact match
    
    alt If Signature, Hash, and Artifacts all match
        Validator-->>GH: Accept Commit natively
    else Any deviation
        Validator-->>GH: Block Push / Revert Forcefully
    end
```

## Security Guarantees & Tamper Resistance

1. **Commit Tree integrity**: The commit signature encompasses `.git/tree_hash`. If a developer manipulates files post-validation, the tree hash mutates, violating and destroying the signature validity.
2. **Key Non-Repudiation**: Developers do not upload random public keys manually. The server inherently trusts the keys registered dynamically on `github.com/settings/ssh`, meaning only the legitimate user profile can forge their own signatures. 
3. **Execution Masking Hacks**: Command execution commands (`POW_CHECKS_CMD`) are cryptographically packaged and verified. A developer cannot run `docker run my-fake-tests` locally because the server gatekeeper will hash its own expected command string and detect the divergence.
4. **Air-Gap Prevention**: The async Ledger step guarantees that developers cannot "mock" a signature locally without checking in with the server. Even if a local signature evaluates flawlessly, if the GitHub Action Ledger never generated the secondary artifact, the push is aggressively rejected.
