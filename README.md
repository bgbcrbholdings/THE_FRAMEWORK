# THE_FRAMEWORK

The Sequence Control Engine — Fail-Closed AI Coding & Governance Framework.

## Overview
THE_FRAMEWORK is an immutable, multi-model governed AI pair-programming and control-plane architecture designed by the 6-Model Cross-Panel (CP) Review Board (Claude, ChatGPT, DeepSeek, DeepSeek v4pro, Grok, Qwen).

It enforces zero agent discretion, strict air-gapped test canary locking, dual-PR allowlist authorization, and deterministic GitHub Actions CI gating.

---

## Current Status & Completed Phases

| Phase / Gate | Description | Status |
| :--- | :--- | :--- |
| **Phase 0** | Human Platform Lockdown & Branch Protection Setup | **COMPLETED & MERGED** |
| **Phase 2.5 (Slice 0)** | Pathfinder Gate (`tests/test_pathfinder.py` + `pathfinder_server.py`) | **COMPLETED & MERGED** |
| **Phase 3** | Lock Wall Infrastructure (`lock_wall.py`, `setup_hooks.py`, `scorecard.py`) | **COMPLETED & MERGED** |
| **Slice 006 / GAP-001** | PM Discovery Q&A Engine (`incubator_wizard.py`) | **NEXT UP** |

---

## Control Plane 20-Script Catalog

Every script in the control plane is authorized by `ALLOWLIST.txt` and protected by `lock_wall.py` SHA-256 integrity verification:

1. `verify.py` — Pre-flight allowlist & path checker
2. `sequence_server.py` — Sequence HTTP telemetry server
3. `schemas.py` — Strict Pydantic / JSON schema validator
4. `auditor_agent.py` — Autonomous review & audit agent
5. `build_packet.py` — Off-grid review packet bundler
6. `parse_reviews.py` — Off-grid review parser & resolution extractor
7. `agent_dispatcher.py` — Bounded agent execution dispatcher
8. `sequence_engine.py` — Master state machine & sequence runner
9. `watchdog.py` — Supply chain & file hygiene watchdog
10. `project_wizard.py` — Project scaffolding & genesis wizard
11. `lock_wall.py` — 1-way door architectural lock wall engine
12. `pathfinder_server.py` — Pathfinder Slice 0 health server
13. `setup_hooks.py` — Git pre-commit and pre-push hooks installer
14. `scorecard.py` — Defect scorecard & model accuracy tracker
15. `telemetry.py` — Real-time telemetry scanner & reporter
16. `backup_engine.py` — Automated backup & snapshot engine
17. `file_hygiene_engine.py` — Workspace hygiene & orphan cleaner
18. `packet_verify.py` — Review packet verifier
19. `regr_watchdog.py` — Regression watchdog scanner
20. `test_cp_review.py` — CP review test runner

---

## Governance Anchors (`01_GOVERNANCE/`)

* `01_GOVERNANCE/CONSTITUTION.md` — 11 Immutable Constitutional Invariants
* `01_GOVERNANCE/PM_PLAYBOOK.md` — Master Operational & PR Governance Playbook
* `PHASE_0_RUNBOOK.md` — Human Platform Lockdown & Setup Guide

---

## Verification & Local Tests

```bash
# Install local git hooks
python setup_hooks.py

# Verify lock wall integrity
python lock_wall.py

# Run full test suite
pytest -p no:superclaude
```