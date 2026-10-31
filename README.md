# 🛡️ DiffShield

[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-64%20passed%20in%202s-success.svg)]()

> **Deterministic AppSec GitHub App**  
> Inspects every pull request on installed repositories to detect and block malicious PRs, silent supply-chain tampering, and vulnerability reintroductions — featuring reverse-fix matching, disguise-proof AST comparison, multi-layer heuristics, transparent risk scoring, surgical patch synthesis, and a 12-hour quarantine hold.

---

## 📑 Table of Contents

- [Overview & The Threat Model](#-overview--the-threat-model)
- [The PR #482 Acceptance Scenario](#-the-pr-482-acceptance-scenario)
- [Architecture & Detection Design](#-architecture--detection-design)
  - [Layer 1 & 2: Reverse-Fix Matching (Block & Line Level)](#layer-1--2-reverse-fix-matching)
  - [Layer 3: Local Vector Embeddings & Camouflage Detection](#layer-3-local-vector-embeddings--camouflage-detection)
  - [Layer 4: Pattern Rules Engine](#layer-4-pattern-rules-engine)
  - [Risk Scoring, Hard-Block & Quarantine](#risk-scoring-hard-block--quarantine)
  - [Surgical Patch Synthesis](#surgical-patch-synthesis)
- [90-Second Local Demo (Zero Credentials)](#-90-second-local-demo)
- [GitHub App Registration in 6 Steps](#-github-app-registration-in-6-steps)
- [Per-Repository Policy Reference (`.diffshield.yml`)](#-per-repository-policy-reference-diffshieldyml)
- [Maintainer Command Channel](#-maintainer-command-channel)
- [Known Limitations](#-known-limitations)
- [Test Suite & Verification](#-test-suite--verification)

---

## 🎯 Overview & The Threat Model

Modern software supply-chain compromises often do not arrive as glaring malware payloads. Instead, attackers submit legitimate-looking, polite pull requests titled *"performance optimization"*, *"code clean-up"*, or *"refactor loops"*. Hidden within hundreds of innocuous edits is a single deleted line: the security check that originally fixed a critical CVE.

Traditional linters and SAST scanners fail here because they look for static vulnerable sinks in newly written code. They do not understand that the *absence* of a defensive check re-opens a known historical vulnerability.

**DiffShield blocks this threat model:**
1. **GitHub App, not an Action**: Server-side webhook driven. It posts rolling comments, sets commit statuses, creates check runs, and tags PRs with labels. It never executes untrusted code inside the repository.
2. **Zero LLM Anywhere**: 100% deterministic, reproducible byte-for-byte from the same input. No Claude, OpenAI, or external code-analysis APIs.
3. **Zero Code Exfiltration**: PR source code never leaves the host server. Outbound network traffic is strictly confined to `api.github.com`.
4. **Code Retention**: DiffShield blocks merges; it never `git revert`s the user's branch or destroys commit history.

---

## 🔍 The PR #482 Acceptance Scenario

The core acceptance test is modeled on the infamous prototype pollution regression:

```diff
 PR #482  Simplify merge for performance
   function merge(target, source) {
     for (const key in source) {
-      if (key === '__proto__') continue;
       target[key] = source[key];
     }
   }
 1 line removed: the check that fixed CVE-2019-10744 (prototype pollution)
```

### DiffShield's Automated Action
- **Verdict**: `QUARANTINE` (100/100, CRITICAL, Hard Block triggered).
- **Advisory Named**: `CVE-2019-10744` (Prototype Pollution in lodash.defaultsDeep and lodash.merge).
- **Check Run & Status**: `diffshield/security` marked failing.
- **Quarantine Hold**: 12-hour hold recorded in SQLite (`release_at = now + 12h`).
- **Remediation**:
  - `revert.patch`: unified diff undoing the PR.
  - `restore_guard.patch`: **surgical** patch re-inserting `if (key === '__proto__') continue;` directly into the post-PR code so maintainers can keep the performance improvements without re-opening the hole.

---

## 🏗️ Architecture & Detection Design

```
diffshield/
  engine/            # Pure, offline analysis. No HTTP, no GitHub, no I/O beyond rules/data.
    diffparse.py     # Unified diff parser, round-trip patching (forward_patch, apply_reverse_patch).
    astnorm.py       # Tree-sitter JS/TS parser; disguise-proof structural normalisation.
    fixdb.py         # Curated CVE fix index (>=15 entries), block-level & line-level matching.
    rules_engine.py  # YAML deterministic pattern rules (DS001 - DS012) with all_of & guard exclusion.
    similarity.py    # Local 512-dim signed hash embedder (blake2b) & camouflage detection.
    reverse.py       # Git-applicable revert.patch and surgical restore_guard.patch synthesis.
    risk.py          # Transparent additive scoring, bands, hard-block short-circuiting.
    analyse.py       # Pipeline orchestrator: PR diff -> canonical Report schema.
    render.py        # GitHub PR comment, check-run summary, annotations under 65k limit.
    cli.py           # Standalone CLI: scan | reverse | demo.
  rules/default.yml  # Deterministic pattern rules.
  data/fix_seed.json # Hand-curated historical CVE fix database (16 entries).
  app/
    config.py        # Settings from env; RepoPolicy parsed from base commit .diffshield.yml.
    github_client.py # App JWT (RS256) -> installation token -> REST; FakeGitHubClient for tests.
    pipeline.py      # Event dispatcher, hold scheduler, command processor, tick re-analysis.
    store.py         # SQLite ledger: holds, audits, reports.
    main.py          # FastAPI app: /webhook, /tasks/tick, /api/*, /healthz, HTML dashboard.
    manifest.json    # GitHub App manifest definition.
  scripts/
    demo_local.py    # Zero-credential interactive scenario browser at :8000.
    scenarios.py     # 6 canonical test/demo scenarios (4 attacks, 2 benign controls).
    ingest_osv.py    # Offline candidate harvester from OSV.dev (writes to candidates only).
  tests/             # Comprehensive 64-test suite (offline, fast).
```

### Layer 1 & 2: Reverse-Fix Matching
- **AST Block Extraction**: Cuts source code into semantic blocks (functions, methods, arrow functions, classes, statements) via `tree-sitter`.
- **Anti-Disguise Normalisation**: Standard identifiers are normalized to `ID`, declarations to `DECL`, and literals to `S`. **Security-sensitive identifiers and decoded strings are preserved verbatim** (`eval`, `child_process`, `__proto__`, `prototype`, `constructor`, `fetch`, `process.env`, etc.). Hex escapes (`\x5f\x5fproto__`), unicode escapes (`\u005f\u005fproto__`), quote styles (`'` vs `"`), and string concatenations (`"__" + "proto__"`) all evaluate to identical structural strings.
- **Precision Semantics Gating**: Every candidate match must mention advisory trigger strings or security identifiers. Unrelated loops are immediately discarded before similarity scoring.
- **Line-Level Detector**: Solves the *partial revert* problem (e.g., removing 1 of 2 guards). Scope is strictly scoped to the parent function — a guard surviving in an unrelated function does not protect the function that lost it.

### Layer 3: Local Vector Embeddings & Camouflage Detection
- **`HashedEmbedder`**: 512-dimensional signed hash of unigrams + token trigrams using Blake2b and L2 normalisation. Zero external model downloads.
- **Camouflage Detection**: Compares removed blocks with added blocks (similarity >= 0.82). If defenses are stripped (`guard_delta < 0`), risk points are emitted. **Pure parameter renames with intact guards produce exactly 0 points**.

### Layer 4: Pattern Rules Engine
Hot-reloadable YAML rules in `rules/default.yml`:
- `DS001`: Dynamic code execution sinks (`eval`, `Function`, `vm.runIn*`)
- `DS002`: Shell execution (`child_process`, `exec`, `spawn`)
- `DS003`: Credential exfiltration (`fetch`/`https` **AND** `process.env.TOKEN`, `all_of: true`)
- `DS004`: Obfuscated payloads (hex runs `\x..`, base64 buffers, `fromCharCode` runs)
- `DS005`: Minified bulk inserts (>800 character line additions)
- `DS006`: Defense removal (net guard count delta negative)
- `DS007`: Filesystem writes to sensitive paths (`.ssh`, `.aws`, `.env`, `/etc/passwd`)
- `DS008`: Suspicious install-lifecycle scripts in `package.json` (`postinstall` curl pipe)
- `DS009`: Untrusted dependency sources (tarballs, git URLs, `*` wildcards)
- `DS010`: CI/release tampering (`pull_request_target`, secrets exposure)
- `DS011`: Prototype pollution sinks (`all_of: true` + `exclude_if_guard: true` so valid guarded loops do not fire)
- `DS012`: Catastrophic regex / ReDoS nested quantifiers

### Risk Scoring, Hard-Block & Quarantine
- **Additive Scoring**:
  - Reintroduced CVE fix: `+40` pts
  - Critical pattern rule: `+34` pts
  - High pattern rule: `+22` pts
  - Medium pattern rule: `+12` pts
  - Camouflage with guard loss: `min(30, 10 + 6 * |guard_delta|)` pts
  - Churn nudges: >8 files (+8), >1500 lines (+6), deletion-only (+4)
  - Diminishing returns: 5th signal onwards gets half credit.
- **Hard Block Short-Circuit**: Any signal >= 34 points immediately triggers Quarantine.
- **Band Consistency**: Quarantined PRs are strictly high or critical (never labelled "low" or "info").

---

## ⚡ 90-Second Local Demo

DiffShield is built offline-first. You do not need GitHub credentials or an internet connection to run the full demonstration.

### 1. Terminal Demo (Scenario PR #482 Walkthrough)
```bash
python -m engine.cli demo
```
*Outputs the full detection breakdown, evidence table, and generated surgical restore patch in <0.2 seconds.*

### 2. Interactive Scenario Browser at `:8000`
```bash
python scripts/demo_local.py
```
Open **`http://localhost:8000`** in your browser:
- Test all 6 scenarios with 1-click execution.
- Review diff comparisons, real-time risk scores, evidence tables, and patches.

### 3. Standalone Diff Scanning CLI
```bash
python -m engine.cli scan \
  --patch-file pr.diff \
  --title "Add merge helper" \
  --out report.json \
  --markdown comment.md \
  --patches-dir patches/
```
*Exits with status code `1` on quarantine, making it pluggable into any CI pipeline.*

---

## 🚀 GitHub App Registration in 6 Steps

To deploy DiffShield to live GitHub repositories:

1. **Create the GitHub App**:
   - Go to **GitHub Settings ➔ Developer settings ➔ GitHub Apps ➔ New GitHub App**.
   - Fill in `App name` (e.g. `DiffShield-Guardian`).
   - Webhook URL: `https://<your-domain-or-tunnel>/webhook` (or smee.io URL for local dev).
   - Webhook secret: Set a strong secret (e.g. `openssl rand -hex 20`).

2. **Configure Permissions**:
   - **Repository permissions**:
     - `Checks`: Read & write
     - `Contents`: Read-only
     - `Issues`: Read & write
     - `Pull requests`: Read & write
     - `Commit statuses`: Read & write
     - `Metadata`: Read-only

3. **Subscribe to Events**:
   - `Pull request`
   - `Issue comment`
   - `Pull request review comment`
   - `Installation`
   - `Installation target`

4. **Generate Private Key & App ID**:
   - Save the generated `.pem` private key file to disk.
   - Note down the numerical `App ID`.

5. **Configure `.env`**:
   ```env
   GITHUB_APP_ID=123456
   GITHUB_PRIVATE_KEY_PATH=./diffshield.private-key.pem
   GITHUB_WEBHOOK_SECRET=your_webhook_secret_here
   DIFFSHIELD_DRY_RUN=0
   DIFFSHIELD_HOLD_HOURS=12
   ```

6. **Start the Webhook Server**:
   ```bash
   python run.py
   ```
   *(For local testing with live webhooks, run `make tunnel` or `smee --target http://localhost:8000/webhook`)*.

---

## 📜 Per-Repository Policy Reference (`.diffshield.yml`)

DiffShield repositories can customize behavior by placing `.diffshield.yml` in the root:

```yaml
# .diffshield.yml

# Enforcement mode:
# - hold: (default) failing check + comment + 12h quarantine timer
# - block: failing check + comment without auto-release timer
# - close: immediately close PR with explanation comment
# - comment: dry-run mode, posts findings without blocking merge
enforcement: hold

# Quarantine hold duration in hours (default: 12)
hold_hours: 12

# File glob ignore patterns
ignore_paths:
  - "dist/**"
  - "*/dist/**"
  - "*.min.js"
  - "*.min.css"
  - "node_modules/**"
  - "*/node_modules/**"
  - ".git/**"
```

> [!IMPORTANT]
> **Base-Branch Trust Boundary**: DiffShield **always** reads `.diffshield.yml` from the target **base** branch commit (`main` / `master`), never from the PR head. An attacker cannot submit a PR that alters its own security policy.

---

## 💬 Maintainer Command Channel

Maintainers (`OWNER`, `MEMBER`, `COLLABORATOR`) can manage holds directly from PR comments:

- `/diffshield release <reason>`: Ends the quarantine hold immediately and flips check runs to success.
- `/diffshield override <reason>`: Explicit maintainer risk acceptance. **A non-empty reason is strictly required** (override without reason is refused). Recorded in the permanent audit ledger.
- `/diffshield recheck`: Re-runs the full analysis on demand.

All commands from non-maintainers are automatically rejected and audited.

---

## ⚠️ Known Limitations

Honest threat modeling requires transparency about boundaries:

1. **JS/TS Scope in v1**: AST parsing and block comparison target JavaScript and TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`). Non-JS files (`package.json`, CI configs, scripts) are inspected via text and regex rules. Expanding AST grammars to Python and Go is additive.
2. **Curated Seed Database**: The initial seed contains 16 high-impact CVE entries across prototype pollution, ReDoS, SSRF, command injection, and traversal. It is curated for near-zero false positives, not exhaustive of all historical CVEs.
3. **Advanced Semantic Evasion**: An adversary who re-implements an entire vulnerable algorithm using completely novel control-flow patterns, indirect references, and dynamic string construction without standard identifiers may evade vector similarity. DiffShield focuses on catching real-world silent regressions and refactored guard removals.

---

## 🧪 Test Suite & Verification

The test suite runs 100% offline without network or GitHub credentials:

```bash
# Run complete test suite
pytest tests -v
```

**Results**:
- **64 tests passing** in ~2.0 seconds.
- 100% offline: relies on `FakeGitHubClient` and in-memory SQLite tables.
- Comprehensive coverage across AST normalization, diff parsing, round-trip patching, seed database matching, pattern rules, camouflage detection, risk scoring, SQLite concurrency, webhook HMAC verification, and maintainer command permissions.

