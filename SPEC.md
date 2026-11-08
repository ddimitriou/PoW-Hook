# PoW-Hook v2 Deterrence Spec

Design for two new mechanisms plus prerequisite hardening, targeting a malicious
developer with **admin rights on their own machine** (but *not* repo-admin rights
on GitHub) pushing to **github.com cloud**, where pre-receive blocking is not
available to third parties.

Design goal (per threat-model discussion): forgery cannot be made impossible on
cloud; instead make it **noisy, non-repudiable, certain to be detected, and no
faster than compliance**.

| Mechanism | Threat it addresses | Guarantee |
|---|---|---|
| **B. Nightly Audit Sweep** | Forged `PASSED` attestation over a tree containing a secret | Certain, attributable detection within 24 h; cryptographic evidence (their signature over a false verdict) |
| **A. Challenge-Corpus Receipt** | Stubbed hook / scanner never executed ("lazy bypass at scale") | Producing a valid attestation requires actually running the scanner |
| **0. Hardening fixes** | Injection, destructive false-positives, unchecked verdict | Prerequisite correctness |

Explicit non-goals (documented residual risks):

- A determined insider who *runs* the scanner and filters real-tree findings out
  of their report defeats Mechanism A alone — Mechanism B catches this within a day.
- A **repo-admin** adversary can read Actions secrets (`POW_HMAC_KEY`) and mint
  fake challenges. Out of scope: repo admins can also delete the workflows.
- Secret *exposure* on cloud is not prevented (post-ingestion by design); the
  sweep's job is fast, attributable detection feeding rotation/revocation.

---

## 0. Prerequisite hardening (implement first, independent of A/B)

1. **Remove `shell=True` interpolation** in `admin_templates/github/scripts/verify_pow.py`
   (`run()` helper). `ref_name` on `pull_request` events is attacker-controlled
   (branch names allow `;|$&` etc.) and is interpolated into
   `git push --force origin {last_valid}:refs/heads/{ref_name}` → RCE with a
   `contents: write` token. Convert every `run(f"git …")` call to argv lists
   via `subprocess.check_output([...])`.
2. **Never force-push on inconclusive results.** `get_github_username_for_commit`
   and `get_github_ssh_keys` currently swallow all exceptions and return
   `None`/`[]`, which the main loop treats as "invalid" → branch obliteration on
   an API blip. Introduce a third outcome `INCONCLUSIVE`: fail the check run
   (red status blocks the merge via branch protection) but **do not** rewrite
   refs. Force-push only on cryptographically *confirmed* invalid signatures,
   and make even that opt-in (`POW_AUTO_REVERT: "true"`).
3. **Enforce the status byte.** `verify_pow.py` decodes `status` from the
   trailer but never asserts `status == "PASSED"`. A signed `FAILED` attestation
   currently passes. Add the assertion.
4. **Enforce trailer single-use.** Nothing prevents replaying one valid trailer
   onto a second commit with an identical tree. Covered structurally by the v2
   payload (binds parent SHA, §A.5) and retroactively by the sweep's duplicate-
   session detection (§B.3).

---

## A. Challenge-Corpus Proof-of-Execution

### A.1 Idea

The attestation ledger mints a small **challenge corpus** — a tarball of files
containing K randomly generated *detectable* planted secrets and M *decoys*
(near-miss strings the pinned scanner provably does **not** flag: invalid
checksums, sub-threshold entropy, wrong-length tokens). The client must run the
scanner over the corpus and submit a **receipt**: a digest over exactly the set
of findings. Distinguishing plants from decoys requires reproducing the
scanner's detector logic (checksum validation, entropy thresholds) — so the
cheapest way to produce a valid receipt **is to run the scanner**.

The server verifies the receipt **without re-running anything** via an HMAC tag
published at mint time (§A.4).

### A.2 Protocol

```
Client (pre-commit)                Ledger (pow-ledger.yml)           Validator (verify_pow.py)
-------------------                -----------------------           -------------------------
1. session_id = uuid4()
2. dispatch MINT_CHALLENGE  ─────► 3. generate corpus:
   {session_id, tree_hash}            - K plants, M decoys (runner CSPRNG)
                                      - challenge_id = uuid4()
                                      - R_expected = receipt(plants)
                                      - tag = HMAC(K_hmac,
                                          challenge_id ‖ session_id ‖ R_expected)
                                   4. upload artifact
                                      pow-challenge-{challenge_id}
                                      = {corpus.tar, challenge_id, tag,
                                         tool_version}
5. poll artifacts API, download
6. extract corpus to tmpdir
7. run POW_CHECKS_CMD on repo tree   (unchanged — the real scan)
8. run POW_CORPUS_CMD on tmpdir      (same scanner, --json output)
9. R_client = receipt(corpus findings)
10. write .git/POW_PASSED
    {session_id, status, checks_hash,
     challenge_id, receipt}
11. commit-msg signs v2 payload,
    injects v2 trailer
                                                                    12. decode v2 trailer
                                                                    13. verify SSH sig (existing)
                                                                    14. fetch pow-challenge-{challenge_id}
                                                                        artifact metadata + tag
                                                                    15. assert artifact was produced by
                                                                        pow-ledger.yml (workflow path on
                                                                        the run), created ≤ 24h before
                                                                        commit, matches session_id
                                                                    16. recompute
                                                                        HMAC(K_hmac, challenge_id ‖
                                                                        session_id ‖ R_client) == tag
```

Step 16 is the trick that keeps this cheap: the validator never learns or
recomputes the expected findings — it just checks that the client's receipt is
the one the mint committed to. `K_hmac` is a repo Actions secret
(`POW_HMAC_KEY`), readable by workflows but not by developers.

### A.3 Corpus format

- Tarball, 20–50 small files (mixed extensions: `.py`, `.env`, `.json`, `.md`).
- **K ∈ [3, 8] plants**: generated credentials in formats the pinned scanner
  detects offline (e.g., AWS `AKIA…` pairs, GitHub `ghp_…` with valid CRC32
  checksum, generic high-entropy tokens above threshold). Values from runner
  CSPRNG; never real credentials.
- **M ∈ [5, 15] decoys**: same shapes, made undetectable — corrupted checksum,
  entropy just below threshold, truncated length.
- Plant/decoy behavior MUST be validated empirically against the **pinned
  scanner version** (mint job runs the scanner once on its own corpus at mint
  time to self-check plants are found and decoys are not; this is the only
  server-side scan and costs seconds). Tool version ships in the challenge and
  is bound into the receipt.

### A.4 Receipt canonicalization

```
finding_line  = f"{detector_name}:{relative_path}:{line}:{sha256(raw_secret)}"
receipt       = sha256("\n".join(sorted(finding_lines)) + "\n" + tool_version).hexdigest()
```

Requires JSON output from the scanner for the corpus run only — new env var:

```env
POW_CORPUS_CMD="docker run --rm -v {corpus_dir}:/pwd trufflesecurity/trufflehog:latest filesystem /pwd --no-verification --json"
```

`POW_CHECKS_CMD` (the real tree scan) is unchanged.

### A.5 Trailer format v2

```
v1: [0x01][2B BE sig_len][sig][16B session UUID][1B status][32B checks_hash]
v2: [0x02][2B BE sig_len][sig][16B session UUID][1B status][32B checks_hash]
    [16B challenge UUID][32B receipt][20B parent commit SHA-1]
```

Signed payload v2 (pipe-delimited, extends v1):

```
checks_hash|tree_hash|session_id|status|challenge_id|receipt|parent_sha
```

Binding `parent_sha` kills trailer replay across commits (hardening item 4).
Validator accepts v1 only while `POW_ALLOW_V1: "true"` (migration window).

### A.6 Client changes

- `hooks_templates/pre-commit`: dispatch `MINT_CHALLENGE`, poll+download the
  challenge artifact (PAT needs `actions:read` in addition to current dispatch
  scope — update `.env.example`), run corpus scan, compute receipt, extend
  `.git/POW_PASSED`.
- `hooks_templates/commit-msg`: read new fields, build v2 payload/trailer.
- **Latency**: per-commit mint costs one workflow spin-up (~15–60 s).
  v1 accepts this; a **pre-minted challenge pool** (hourly batch mint, each
  challenge single-use with 24 h TTL, client claims the newest unclaimed one)
  is the designed optimization and requires no protocol change — only the
  binding `session_id` moves from mint-time into the client's signed payload,
  so the tag becomes `HMAC(K, challenge_id ‖ R_expected)` and single-use is
  enforced by the sweep (§B.3, duplicate `challenge_id`).

### A.7 What A does and does not prove

- ✅ The pinned scanner was executed against unpredictable input at attestation
  time (no stubbed hooks, no "docker not even installed").
- ✅ Combined with touch-required hardware keys: no unattended mass forgery.
- ❌ Does **not** prove the *repo tree's* findings were honestly reported.
  An attacker can scan corpus + tree and suppress tree findings. That's
  Mechanism B's job.

---

## B. Nightly Audit Sweep (implement before A — highest value, no client changes)

### B.1 Idea

`trufflehog git` scans the **entire repo history in one pass** (one scan cost,
not N). Nightly, sweep the full history, then cross-reference every finding
against the attestation trailers already embedded in commits. A commit whose
trailer says `PASSED` (valid signature, matching cmd hash) but which contains a
finding the same pinned scanner reports is **cryptographic evidence of a forged
attestation, signed by the forger's own GitHub-registered key**.

This converts the earlier "audit lottery" from probabilistic to
**certain-but-delayed**: every forgery is found within 24 h, attributed, with
non-repudiable evidence.

### B.2 Workflow: `admin_templates/github/workflows/pow-sweep.yml`

```yaml
on:
  schedule: [{cron: "17 2 * * *"}]
  workflow_dispatch:
permissions: {contents: read, issues: write, actions: read}
```

Steps:

1. `actions/checkout` with `fetch-depth: 0`.
2. Run the pinned scanner over full history:
   `docker run … trufflesecurity/trufflehog:<pinned> git file:///pwd --json --no-verification`
   → findings JSONL, each tagged with the commit SHA it appears in.
3. Run `sweep_audit.py` (new script, shares trailer decoding with
   `verify_pow.py` — extract `decode_pow_trailer` into a shared module).

### B.3 Cross-reference algorithm (`sweep_audit.py`)

```
findings_by_commit = parse(trufflehog JSONL)        # sha → [findings]
for commit in git log --format=%H%T%P (since enforcement epoch):
    trailer = decode_pow_trailer(commit)            # may be absent/invalid
    classify:
      FORGERY       trailer PASSED + valid sig + cmd hash matches
                    + tool version matches + findings_by_commit[sha] non-empty
      VERSION_DRIFT same, but attested tool version ≠ sweep tool version
                    (warning, not verdict — scanner behavior changed)
      MISSING       no/invalid trailer after enforcement epoch
      REPLAY        session_id or challenge_id seen on >1 commit
      LEAK_HONEST   findings present + trailer honestly says FAILED/absent
                    (validator should have blocked; investigate gap)
```

- **Baseline suppression**: findings in commits before the enforcement epoch go
  into `.pow-baseline.json` (finding fingerprints) generated on first run;
  suppressed thereafter so historical noise doesn't page anyone.
- **Watermark**: store last-swept HEAD in a repo Actions variable; trailer
  cross-ref is incremental, the trufflehog pass stays full-history (cheap, and
  catches history rewrites).

### B.4 Outputs

1. Report artifact (JSON + human-readable) every run, 90-day retention —
   this is the transparency record.
2. On any `FORGERY`/`REPLAY`/`LEAK_HONEST`: open (or update) a single issue
   `🚨 PoW Sweep: N violation(s)` tagging `POW_ADMIN_HANDLES`, listing commit,
   author (resolved via commits API), classification, and evidence
   (signature + finding), and exit 1 so the scheduled run shows red.
3. **Revocation hook (payoff-reduction dial)**: optional
   `POW_REVOKE_WEBHOOK` — POST the finding (detector type, sha256 of secret,
   commit, author) to an org-provided endpoint that rotates/revokes.
   v1 ships the webhook call only; provider-specific revocation is out of scope.

### B.5 Cost

One full-history trufflehog pass + one API-light Python script per night
≈ a few runner minutes/day. No client-side or protocol changes at all.

---

## Implementation plan

| Phase | Content | Touches | Effort |
|---|---|---|---|
| **1** | Hardening fixes 0.1–0.3 | `verify_pow.py`, `pre-receive` | Small (hours) |
| **2** | Nightly sweep (B) + shared trailer module + baseline | new `pow-sweep.yml`, `sweep_audit.py`, `admin_install.py` scaffolding, tests | ~1–2 days |
| **3** | Challenge corpus (A): mint job in `pow-ledger.yml`, trailer v2, client hooks, validator HMAC check, `POW_HMAC_KEY` setup in `admin_install.py` | client + server + installer | ~3–5 days |
| **4** | Challenge pool (latency), `ssh-keygen -Y` migration for FIDO2/touch keys, revocation integrations | — | later |

Phase 2 before Phase 3 deliberately: the sweep delivers the strongest deterrent
(certain detection) with zero protocol risk, and it is also the safety net that
Phase 3's known gap (§A.7) depends on.
