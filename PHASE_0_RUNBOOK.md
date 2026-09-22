# PHASE 0 RUNBOOK — HUMAN PLATFORM LOCKDOWN

**Target Audience:** Non-Technical Project Manager (PM)  
**Execution Environment:** GitHub Web UI & Browser Chat Windows Only (Zero Terminal / Zero Local CLI)  
**Status:** CP-APPROVED (Master Execution Guide)  
**Prerequisites:** CP-Ratified `01_GOVERNANCE/CONSTITUTION.md`  
**Hard Rule:** No builder agent API token, repository access, or issue assignment may be issued until STEP 6 is complete and verified.

---

## STEP 0: Attach or Create Repository

- **Option A (Existing Repository):** If `THE_FRAMEWORK` already exists, DO NOT recreate it. Run the **Verification Checklist**: verify seed files exist, CI workflow is active, branch protection is enabled, and sabotage test is blocked. Proceed to fill any missing gaps.
- **Option B (New Repository):** Proceed to STEP 1.

---

## STEP 1: Repository Creation & Line-Ending Anchor

1. In GitHub Web UI, click **New repository**:
   - Repository Name: `THE_FRAMEWORK`
   - Visibility: **Private** (recommended during Bootstrap)
   - Add README: **Checked**
   - Default branch: `main`
2. Enable GitHub Actions:
   - Navigate to **Settings** $\rightarrow$ **Actions** $\rightarrow$ **General** $\rightarrow$ Select **Allow all actions and reusable workflows**.
3. Create `.gitattributes` via Web UI:
   - Click **Add file** $\rightarrow$ **Create new file**.
   - Path: `.gitattributes`
   - Content (exact):
     ```text
     * text=auto eol=lf
     ```
   - Commit **directly to main** *(Direct-to-main commits are permitted ONLY during pre-protection Phase 0 setup)*.
4. Create `.gitignore` via Web UI:
   - Path: `.gitignore`
   - Content (exact):
     ```text
     # Python
     __pycache__/
     *.py[cod]
     *.egg-info/
     .venv/
     venv/

     # OS
     .DS_Store
     Thumbs.db

     # IDE
     .vscode/
     .idea/

     # Framework runtime
     .sequence/state.db-journal
     .sequence/state.db-wal
     ```
   - Commit **directly to main**.

---

## STEP 2: Establish Governance Anchors & Seed Files

Create each of the following files individually via **Add file** $\rightarrow$ **Create new file**, committing each **directly to main**:

1. `.github/CODEOWNERS`
   - Content: `* @bgbcrbholdings` *(Replace with your exact PM GitHub username)*

2. `01_GOVERNANCE/BOOTSTRAP.md`
   - Content: Paste the ratified Autonomy Escalation Law text.

3. `01_GOVERNANCE/FORBIDDEN.yml`
   - Content: Paste the ratified Forbidden Builder Actions list.

4. `01_GOVERNANCE/CONSTITUTION.md`
   - Content: Paste the ratified 11-Invariant Constitution text.

5. `01_GOVERNANCE/PM_PLAYBOOK.md`
   - Content: Create file with initial text: `# PM PLAYBOOK\nStatus: SEEDED`.

6. `ALLOWLIST.txt`
   - Content (exact):
     ```text
     # Phase 0 Baseline Allowlist
     ALLOWLIST.txt
     .gitattributes
     .gitignore
     README.md
     ```

7. `.sequence/lock_manifest.json`
   - Content (exact):
     ```json
     {
       "version": "1.0",
       "generated_by": "Phase 0 Seed",
       "files": {}
     }
     ```
     *(Note: SHA-256 hashes will be updated mechanically by CI on subsequent PRs—zero terminal hashing required).*

8. `.system/CONSTITUTION.system.md`
   - Content: Copy the 4-paragraph Constitutional Charter preamble text.

---

## STEP 3: Out-of-Band Dual-AI CI Workflow Landing (Phase 0.5)

*Crucial Safeguard: The CI workflow MUST land before branch protection is locked and BEFORE builder agents exist.*

1. **Review Lane — Model A (Fresh Browser Chat):**
   - Paste the following prompt to Model A:
     > "Draft `.github/workflows/ci.yml` for GitHub Actions running on `pull_request` to `main`. Required jobs:
     > 1. `validate_contract_type`: Fails closed if PR label is not exactly one of: `type:contract` or `type:build`.
     > 2. `check_allowlist`: Reads `ALLOWLIST.txt` from base commit (`BASE_SHA`); fails (RED) if changed files are not in `ALLOWLIST.txt`.
     > 3. `contract_baseline`: Runs if label is `type:contract`; exits 0 (GREEN) IF AND ONLY IF test fails (exit non-zero) against baseline code.
     > 4. `contract_pass`: Runs if label is `type:build`; exits 0 (GREEN) IF AND ONLY IF all tests pass.
     > 5. `ci_result`: Aggregates job outcomes; exits 0 IF AND ONLY IF the required lane job + allowlist check succeeded. Never use `continue-on-error`."
2. **Review Lane — Model B (Fresh Browser Chat):**
   - Paste Model A's draft to Model B with prompt:
     > "Adversarially audit this GitHub Actions YAML for bypasses, `continue-on-error` loopholes, `pull_request_target` vulnerabilities, path filter omissions, or steps that allow unauthorized workflow edits. Emit a patched, secure YAML."
3. **PM Commit via Web UI:**
   - Copy Model B's approved YAML.
   - Click **Add file** $\rightarrow$ **Create new file** $\rightarrow$ Path: `.github/workflows/ci.yml`.
   - *CRITICAL:* Ensure 2-space YAML indentation is preserved (no tabs).
   - Commit **directly to main**.
4. **Verify Workflow Initialization:**
   - Click the **Actions** tab in GitHub Web UI.
   - Verify the initial workflow run appears and shows a green checkmark.

---

## STEP 4: Activate GitHub Branch Protection on `main`

1. In GitHub Web UI, navigate to **Settings** $\rightarrow$ **Branches** (or **Rulesets**).
2. Click **Add branch protection rule** (or **Create ruleset**):
   - Branch name pattern: `main`
3. Configure the following mandatory settings:
   - [x] **Require a pull request before merging**
     - **Require approvals: 0** *(CRITICAL for Solo PM: Protection is enforced mechanically by status checks and push restrictions. Setting to 1 will deadlock a solo PM as GitHub prevents self-approval).*
   - [x] **Require status checks to pass before merging**:
     - Check: **Require branches to be up to date before merging**
     - Add status check: `ci_result` *(CRITICAL: Consolidation job evaluating either contract_baseline or contract_pass)*
     - Add status check: `check_allowlist` *(Validates path allowlist bounds)*
     - *(DO NOT add contract_pass as a standalone required check—it will block contract PRs).*
   - [x] **Require linear history**
   - [x] **Include administrators** *(CRITICAL: Prevents PM/Admin bypass of CI checks)*
   - [x] **Restrict who can push to matching branches**:
     - Add user: `@bgbcrbholdings` *(PM username only. Builder agents cannot push to main).*
   - [x] **Do not allow bypassing the above settings**
   - [x] **Block force pushes & branch deletions**
4. Click **Save changes**.
5. *Sanity Check:* Verify that clicking "Add file" on `main` now forces creating a new branch and opening a Pull Request.

---

## STEP 5: Prove the Mechanical Cage (Sabotage Spot-Checks)

Execute these two browser-based spot-checks to verify the cage BEFORE creating agent tokens:

### TEST 5A — Sabotage PR (Must BLOCK Merging)
1. Click **Add file** on `main` $\rightarrow$ Edit `01_GOVERNANCE/CONSTITUTION.md` (add a single space).
2. Select **Create a new branch for this commit and start a pull request** $\rightarrow$ Branch name: `test/sabotage-check`.
3. Click **Propose changes** $\rightarrow$ Add label `type:build` $\rightarrow$ Click **Create pull request**.
4. Observe GitHub Actions execution:
   - `check_allowlist` and/or `ci_result` MUST fail (RED).
   - GitHub UI MUST display: **"Merging is blocked"**.
5. Click **Close pull request** $\rightarrow$ Delete branch `test/sabotage-check`.
6. *CRITICAL:* If Test 5A is mergeable, STOP IMMEDIATELY. Do not issue tokens. Fix branch protection settings and re-test.

### TEST 5B — Unlabeled PR (Must FAIL Closed)
1. Create a new PR modifying `README.md` without adding any label.
2. Verify `validate_contract_type` fails (RED) and merging is blocked.
3. Close PR and delete branch.

---

## STEP 6: Release Builder Agent Credentials (AUTONOMY GATE EXIT)

**Only after Steps 1–5 are 100% complete and verified:**

1. Navigate to GitHub **Settings** (top-right profile) $\rightarrow$ **Developer settings** $\rightarrow$ **Personal access tokens** $\rightarrow$ **Fine-grained tokens**.
2. Click **Generate new token**:
   - Token Name: `agent-bgb-builder-token`
   - Expiration: 30 days
   - Resource owner: Your account/organization
   - Repository access: **Only select repositories** $\rightarrow$ `THE_FRAMEWORK`
   - Permissions (Configure EXACTLY):
     - **Contents:** `Read and write` *(Allows branch creation & code commits)*
     - **Pull requests:** `Read and write` *(Allows opening PRs)*
     - **Issues:** `Read and write` *(Allows issue tracking)*
     - **Workflows:** `No access` *(CRITICAL SECURITY FIX: Prevents builder from editing CI workflows)*
     - *All other permissions:* `No access`
3. Click **Generate token** and copy the key to your password manager.
4. **PM Exit Verification Checklist:**
   - [x] Direct commits to `main` are blocked by GitHub UI
   - [x] Test 5A Sabotage PR was blocked (RED)
   - [x] Builder PAT has `Workflows: No access`
   - [x] Builder is NOT in CODEOWNERS and NOT in branch protection bypass lists
   - [x] Required check names match CI job names (`ci_result`, `check_allowlist`)
5. Stage 1 complete! Release token to developer agent `bgb-builder` to begin Stage 2 (Phase 1 TCB Micro-Slices).
