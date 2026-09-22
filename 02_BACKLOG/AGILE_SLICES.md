# Resequenced Agile Slices: Master Central Brain Project
**STATUS: LOCKED — MANDATORY REVELATION REVIEW SEQUENCE AUDIT PASSED for slice-006-genesis-test-harness**

The Master Control Engine is decomposed into 8 strictly resequenced feature slices, ordered so that the zero-LLM review parser and packet builder engine (`slice-001-off-grid-review-parser`) is locked FIRST to eliminate review sequence drift, followed by security, watchdog, and governance primitives before agent dispatch and UI dashboards.

Every slice uses the dual-naming convention: **Senior Lead Dev Level Title (`descriptive-slice-id`)**.

| Slice ID | Slice Title & Senior Dev Description | Risk Tier | Gating Status | Target ADR & Incubator Alignment | Review Directory Location | Allowed File Paths |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `slice-001-off-grid-review-parser` | **Slice 001: Off-Grid Courier & Mechanical Review Parser** | HIGH | [LOCKED & SEALED] | `ADR-001` (`adr_001_graph_and_swarm_engine`), `ADR-004` (`adr_004_zero_llm_review_parser`) | `04_REVIEWS/slice-001-off-grid-review-parser/` | `build_packet.py`, `parse_reviews.py`, `schemas.py`, `.sequence/review_resolutions.json`, `tests/**` |
| `slice-002-master-engine-core` | **Slice 002: Master Engine Core & Loopback Security** | HIGH | [LOCKED & SEALED] | `ADR-003` (`adr_003_harness_and_daemon_engine`) | `04_REVIEWS/slice-002-master-engine-core/` | `sequence_engine.py`, `sequence_server.py`, `sequence.bat`, `verify.py`, `schemas.py`, `.sequence/session.json`, `.sequence/lock_manifest.json`, `.sequence/boot_digest.txt`, `tests/**` |
| `slice-003-supply-chain-watchdog` | **Slice 003: Supply-Chain & Regression Watchdog** | HIGH | [LOCKED & SEALED] | `ADR-002` (`adr_002_autonomous_looping_engine`), `ADR-003` (`adr_003_harness_and_daemon_engine`) | `04_REVIEWS/slice-003-supply-chain-watchdog/` | `watchdog.py`, `regr_watchdog.py`, `file_hygiene_engine.py`, `schemas.py`, `tests/**` |
| `slice-004-sandboxed-sandwich` | **Slice 004: Bounded Agent Subprocess Dispatcher** | HIGH | [LOCKED & SEALED] | `ADR-001` (`adr_001_graph_and_swarm_engine`), `ADR-003` (`trust.tsv`, USD budget caps) | `04_REVIEWS/slice-004-sandboxed-sandwich/` | `agent_dispatcher.py`, `schemas.py`, `.sequence/trust.tsv`, `.sequence/cost_ledger.json`, `.sequence/agent_profile/**`, `.sequence/logs/agent_dispatch.log`, `tests/**` |
| `slice-005-second-brain-scorecard` | **Slice 005: Second Brain Memory Vault & Defect Scorecard** | LOW | [LOCKED & SEALED] | `ADR-002` (4-step memory lifecycle, self-writing vault `.sequence/wiki/`) | `04_REVIEWS/slice-005-second-brain-scorecard/` | `scorecard.py`, `backup_engine.py`, `dashboard/scorecard.html`, `tests/**` |
| `slice-006-genesis-test-harness` | **Slice 006: Project Genesis & 0-Pip Test Harness** | MEDIUM | [LOCKED & SEALED] | `ADR-003` (0-pip test harness stub generator) | `04_REVIEWS/slice-006-genesis-test-harness/` | `project_wizard.py`, `new_project.bat`, `tests/test_runner.py`, `schemas.py`, `tests/**` |
| `slice-007-grand-chess-board-ui` | **Slice 007: Grand Chess Board Command Center UI & Archify Renderer** | HIGH | [CP-Review Gated] | `ADR-001` (No-code fleet dashboard, GitHub Projects, `tt-a1i/archify` static SVG renderer) | `04_REVIEWS/slice-007-grand-chess-board-ui/` | `dashboard/**`, `telemetry.py`, `tests/**` |
| `slice-008-architectural-lock-wall` | **Slice 008: 1-Way Door Architectural Lock Wall, Graphify AST Parser & CodeGraph Symbol Mapper** | MEDIUM | [COMPLETED & MERGED ON MAIN] | `ADR-001` (Quorum consensus gating, header enforcer, JSON sanitizer, `Graphify-Labs/graphify` AST grapher, `colbymchenry/codegraph` symbol mapper) | `04_REVIEWS/slice-008-architectural-lock-wall/` | `lock_wall.py`, `file_hygiene_engine.py`, `parse_reviews.py`, `backup_engine.py`, `schemas.py`, `tests/**` |

---
*Enforced by Sequence Control Engine & Automated File Hygiene Watchdog*
