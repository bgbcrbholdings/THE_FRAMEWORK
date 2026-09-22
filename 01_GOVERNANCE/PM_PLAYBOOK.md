# PM PLAYBOOK — ONGOING OPERATIONS & PR GOVERNANCE

**Target Audience:** Non-Technical Project Manager (PM)  
**Execution Environment:** GitHub Web UI & Browser Chat Windows Only (Zero Terminal / Zero Local CLI)  
**Status:** CP-APPROVED (Master Operational Playbook)  
**Prerequisites:** `01_GOVERNANCE/CONSTITUTION.md` & `PHASE_0_RUNBOOK.md`  
**Core Rule:** The PM is the sole product and governance merge authority. The PM merges PRs via GitHub Web UI based strictly on mechanical CI badge verification and out-of-band review signals.

---

## 1. PULL REQUEST LABELS & CI ROUTING

Every Pull Request opened in the repository MUST be assigned exactly one PR label before CI execution completes:

| Label Name | PR Purpose | Expected CI Behavior | Merge Requirement |
|---|---|---|---|
| `type:contract` | Out-of-band canary test PRs (authored in Review Lane) | `contract_baseline` MUST exit 0 (GREEN). *(Proves the test FAILS against unbuilt baseline code)*. `check_allowlist` verifies ONLY `tests/` files are touched. | PM verifies `ci_result` GREEN $\to$ Click Squash & Merge |
| `type:build` | Builder implementation PRs (authored in Build Lane) | `contract_pass` MUST exit 0 (GREEN). `check_allowlist` verifies touched files match `ALLOWLIST.txt` and ZERO `tests/` files are touched. | PM verifies `ci_result` GREEN $\to$ Click Squash & Merge |
| `type:pathfinder` | Phase 2.5 E2E validation slice | `contract_pass` + `e2e_gate` GREEN. | PM verifies `ci_result` GREEN + Second Brain log $\to$ Click Squash & Merge |

**Rule:** If a PR has NO label or multiple labels, `validate_contract_type` fails (RED) and merging is mechanically blocked.

---

## 2. OUT-OF-BAND CONTRACT GENERATION PROTOCOL (OPTION C)

When establishing a new contract test for a micro-slice (e.g., Micro-Slice 1.1 `sequence_server.py`), the builder agent MUST NEVER author the contract test. The PM conducts out-of-band test authoring using fresh browser chat sessions:

### Step A: Draft Contract (Model A — Contract Author)
1. Open a fresh browser chat with **Model A** (e.g., Claude).
2. Paste prompt:
   > "You are Model A (Contract Author). Draft a failing contract test suite for module [MODULE_NAME]. Pure Python 3 standard library only. No mocks, no stubs, no swallowed exceptions. The test suite MUST exercise the real module and fail against unbuilt baseline code. Provide the complete file text for tests/test_[MODULE_NAME].py."
3. Copy Model A's output code.

### Step B: Adversarial Audit (Model B — Adversarial Auditor)
1. Open a fresh browser chat with **Model B** (e.g., Grok / DeepSeek).
2. Paste prompt:
   > "You are Model B (Adversarial Auditor). Audit this contract test suite for bypasses, tautologies, mocks, swallowed exceptions, or missing edge cases:
   > [PASTE MODEL A CODE HERE]
   > Output: APPROVE, AMEND (with specific fixes), or REJECT."
3. **If Model B requests amendments (AMEND / REJECT):**
   - Copy Model B's entire audit output.
   - Open a **NEW fresh browser chat** with Model A. Paste Model B's feedback and request corrected code.
   - Send Model A's corrected code to a **NEW fresh browser chat** with Model B.
   - **5-Cycle Tie-Breaker:** If Model A and B do not reach agreement after 5 passes, open a new chat with **Model C** (a third model family, e.g., Gemini). Model C's tie-breaking output is authoritative.

### Step C: PM Land Contract PR & Seal Manifest
1. In GitHub Web UI, open branch `contract/add-[MODULE_NAME]-test`.
2. Create `tests/test_[MODULE_NAME].py` and paste the approved test code.
3. Open PR to `main` $\rightarrow$ Add label `type:contract`.
4. Verify `contract_baseline` is GREEN.
5. **Verify Lock Manifest Auto-Update PR:**
   - CI will automatically open a second PR titled `MANIFEST UPDATE: add tests/test_[MODULE_NAME].py`.
   - Open the manifest PR $\rightarrow$ verify it modifies ONLY `.sequence/lock_manifest.json` $\rightarrow$ Click **Squash and Merge**.
6. Return to your `type:contract` PR $\rightarrow$ Click **Squash and Merge**.

---

## 3. DISPATCHING THE BUILDER AGENT (BUILD LANE)

Once the contract test is merged and sealed in `lock_manifest.json` on `main`:

1. Open a GitHub Issue describing the task (e.g. `Micro-Slice 1.1: sequence_server.py`).
2. Create `ALLOWLIST.txt` on a feature branch `build/[SLICE_NAME]` via Web UI:
   ```text
   # ALLOWLIST for Micro-Slice X (Implementation ONLY - NO tests)
   sequence_server.py
   ```
   *(CRITICAL: Never put tests/, .github/, or governance files in ALLOWLIST.txt)*.
3. Paste the **Straitjacket Builder Prompt** (see Appendix A) into the Issue / agent dispatch window.
4. The builder agent (`bgb-builder`) opens a PR to `main`.
5. PM verifies PR label is `type:build`.
6. Click **Files changed** tab: Verify modified files match `ALLOWLIST.txt` exactly. If ANY `tests/` or locked file was touched $\to$ **CLOSE PR IMMEDIATELY** (Allowlist Breach).
7. Check CI Status:
   - `check_allowlist` (GREEN) + `contract_pass` (GREEN) + `ci_result` (GREEN).
   - If GREEN $\to$ Click **Squash and Merge**.

---

## 4. CI FAILURE TRIAGE & GLASS JAW PROTOCOL

### CI Failure Triage (Zero-Code Debugging)
If a builder PR fails CI (status badge is **RED**), the PM does NOT read code or debug tracebacks:
1. In the GitHub PR, click **Details** next to the failed check $\rightarrow$ Copy the error log.
2. Open a fresh browser chat with **Model C (CI Translator)**.
3. Paste prompt:
   > "Translate this CI failure into a single, plain-English instruction for the builder agent. Do not write code. Just state what test failed and why:
   > [PASTE CI ERROR LOG HERE]"
4. Copy Model C's plain-English instruction and post it as a comment on the GitHub PR.
5. **3-Attempt Ladder:** The builder agent has 3 total attempts to push fixes. If CI is RED after Attempt 3, close the PR and escalate to human review.

### Glass Jaw Protocol (Violation Response)
Trust is promoted slowly (20 consecutive passes) but demoted instantly. Auto-merge remains dormant pre-Pathfinder.

| Violation Type | Trigger | PM UI Action |
|---|---|---|
| **Attempt Ceiling** | CI RED 3 times on same PR | Close PR. Add label `escalation:human-pm`. Re-assign issue. |
| **Allowlist Breach** | Builder modified file outside `ALLOWLIST.txt` | **CLOSE PR IMMEDIATELY.** Add label `violation:allowlist`. Unassign agent. Re-dispatch on new Issue. |
| **Lock Wall Breach** | Builder modified `tests/`, `.github/`, `01_GOVERNANCE/`, or `lock_manifest.json` | **CLOSE PR IMMEDIATELY.** Add label `violation:lock-wall`. Go to Settings $\rightarrow$ Collaborators $\rightarrow$ **REMOVE BUILDER AGENT ACCESS.** |

---

## 5. PM PR REVIEW CHECKLIST (LANE-SEPARATED)

Before clicking "Squash and merge" on ANY Pull Request, the PM verifies:

### Every PR
1. [ ] Is exactly ONE label assigned (`type:contract`, `type:build`, or `type:pathfinder`)?
2. [ ] Are ALL required CI status checks GREEN (`ci_result`, `check_allowlist`)?
3. [ ] Is merging blocked if any check is RED?

### `type:contract` PRs Only (Review Lane)
4. [ ] Was the contract test authored out-of-band via Model A/B (builder did NOT write it)?
5. [ ] Are changed files strictly inside `tests/`?
6. [ ] Did `contract_baseline` exit GREEN (verifying test failed on baseline)?
7. [ ] Was the auto-generated `lock_manifest.json` PR merged first?

### `type:build` PRs Only (Build Lane)
4. [ ] Are ALL changed files listed in `ALLOWLIST.txt`?
5. [ ] Are `tests/`, `.github/`, `.system/`, `01_GOVERNANCE/`, and `lock_manifest.json` UNTOUCHED? (If touched $\to$ Close PR immediately).
6. [ ] Did `contract_pass` exit GREEN?

---

## APPENDIX A: STRAITJACKET BUILDER PROMPT TEMPLATE

*Copy and paste this template into the Issue body when dispatching the builder agent:*

```text
---STRAITJACKET BUILDER PROMPT---

YOU ARE A BUILDER AGENT OPERATING UNDER STRICT CONSTRAINTS.

YOUR TASK: Repair the defect in [TARGET_MODULE] so that the locked contract test [TEST_FILE] passes cleanly in CI (exit 0).

ALLOWED FILES (YOU MAY ONLY TOUCH THESE):
- [FILE_1]
- [FILE_2]

FORBIDDEN ACTIONS:
- Do NOT modify any file in tests/, .github/, .system/, 01_GOVERNANCE/, or lock_manifest.json.
- Do NOT create any new files not listed in ALLOWED FILES above.
- Do NOT add external pip dependencies. Use Python 3 standard library only.
- Do NOT declare your own work "done" or "approved." Code only.

VERIFICATION:
Your PR will be mechanically verified by CI:
- check_allowlist: Every file you touch must be in ALLOWED FILES. Any extra file = REJECTED.
- contract_pass: The locked test must PASS (exit 0).
- ci_result: All checks must pass.

OUTPUT: Open a Pull Request from a feature branch to main with ONLY the allowed files changed.
---END STRAITJACKET PROMPT---
```

---

## APPENDIX B: QUICK REFERENCE CARD

| Badge | GREEN Means | RED Means |
|---|---|---|
| `contract_baseline` | Test FAILED against baseline (Correct — test is honest) | Test PASSED (Fake/tautological test) |
| `contract_pass` | Implementation PASSES the locked test | Implementation FAILS the test |
| `check_allowlist` | All modified files are in `ALLOWLIST.txt` | Un-allowlisted file detected |
| `validate_contract_type` | PR has exactly one valid label | Missing label or multiple labels |
| `ci_result` | ALL required checks passed | At least one check failed |
