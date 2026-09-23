# Control-Plane Exit Code Registry

Central registry for non-zero process exit codes used by control-plane scripts in `00_DEV_TEAM_SEQUENCE`.

| Exit Code | Constant / Identifier | Tier | Target Script(s) | Description / Trigger Condition |
| :---: | :--- | :---: | :--- | :--- |
| **0** | `SUCCESS` | All | All | Operation completed with clean verification. |
| **1** | `GENERAL_FAILURE` / `GATE_DENIAL` | Tier 1/2 | `verify.py`, `slice_gate.py` | Generic gating violation or unauthorized slice action. |
| **7** | `FATAL_CHECKLIST_TRUNCATION` | Tier 1 | `build_packet.py` | Non-empty prior findings produce an empty checklist (truncation error). |
| **101** | `FATAL_CONTROL_PLANE_HASH_BREACH` | Tier 0 | `control_script_guard.py` | Control script SHA-256 hash mismatch against `CONTROL_PLANE_MANIFEST.json`. |

## Governance Invariants
1. Exit codes **7** and **101** are reserved for fatal control-plane security breaches and MUST terminate execution immediately.
2. Under no circumstances may an agent catch or swallow `sys.exit(7)` or `sys.exit(101)` during automated sequence evaluation.
