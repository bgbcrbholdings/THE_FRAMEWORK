#!/usr/bin/env python3
"""
Deterministic Worker: schema_gate_worker.py
Validates artifact JSON payloads against schemas.py contract validators.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import sys
import json
from pathlib import Path

# Add project root to sys.path to import schemas
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import schemas


VALIDATOR_MAP = {
    "dispatch_request": schemas.validate_dispatch_request,
    "dispatch_envelope": schemas.validate_dispatch_envelope,
    "trust_ledger_envelope": schemas.validate_trust_ledger_envelope,
    "cost_monitor_envelope": schemas.validate_cost_monitor_envelope
}


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("Usage: python schema_gate_worker.py <schema_name> <artifact_json_path>\n")
        sys.exit(1)

    schema_name = sys.argv[1]
    artifact_path = Path(sys.argv[2])

    if schema_name not in VALIDATOR_MAP:
        sys.stderr.write(f"Unknown schema name '{schema_name}'. Valid schemas: {list(VALIDATOR_MAP.keys())}\n")
        sys.exit(1)

    if not artifact_path.exists():
        sys.stderr.write(f"Artifact path '{artifact_path}' does not exist.\n")
        sys.exit(1)

    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    validator = VALIDATOR_MAP[schema_name]

    try:
        is_valid, err = validator(payload)
        res = {"is_valid": is_valid, "error": err}
        print(json.dumps(res, indent=2))
        if not is_valid:
            sys.exit(2)
    except Exception as e:
        sys.stderr.write(f"Schema validation exception: {e}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
