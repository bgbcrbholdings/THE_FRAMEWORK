#!/usr/bin/env python3
"""
Deterministic Worker: diff_validator.py
Validates candidate changed file paths against slice path allowlists.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import sys
import json
from pathlib import Path


def validate_diff_paths(changed_paths, allowlist_paths):
    """
    Validates that all paths in changed_paths match or are subpaths of entries in allowlist_paths.
    Returns dict with overall compliance boolean and unauthorized paths list.
    """
    allow_set = set(allowlist_paths)
    unauthorized = []

    for path in changed_paths:
        norm_path = Path(path).as_posix()
        # Direct match check or parent directory containment check
        authorized = False
        for allowed in allow_set:
            norm_allowed = Path(allowed).as_posix()
            if norm_path == norm_allowed or norm_path.startswith(norm_allowed.rstrip("/") + "/"):
                authorized = True
                break
        if not authorized:
            unauthorized.append(norm_path)

    return {
        "is_valid": len(unauthorized) == 0,
        "unauthorized_count": len(unauthorized),
        "unauthorized_paths": unauthorized
    }


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("Usage: python diff_validator.py <changed_paths_json> <allowlist_json>\n")
        sys.exit(1)

    changed_file = Path(sys.argv[1])
    allowlist_file = Path(sys.argv[2])

    if not changed_file.exists() or not allowlist_file.exists():
        sys.stderr.write("Input JSON files do not exist.\n")
        sys.exit(1)

    changed_paths = json.loads(changed_file.read_text(encoding="utf-8"))
    allowlist_paths = json.loads(allowlist_file.read_text(encoding="utf-8"))

    res = validate_diff_paths(changed_paths, allowlist_paths)
    print(json.dumps(res, indent=2))
    if not res["is_valid"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
