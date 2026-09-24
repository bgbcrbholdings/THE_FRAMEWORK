#!/usr/bin/env python3
"""
Deterministic Worker: ci_fetcher.py
Formats CI failures and status payloads into structured JSON artifacts.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import sys
import json
from pathlib import Path


def format_ci_summary(ci_log_text):
    """Parses raw CI output log text and produces a structured JSON summary."""
    lines = ci_log_text.splitlines()
    failures = [line for line in lines if "FAIL" in line or "ERROR" in line or "error" in line.lower()]
    return {
        "status": "FAILED" if failures else "PASSED",
        "failure_count": len(failures),
        "failure_lines": failures[:20],
        "total_log_lines": len(lines)
    }


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python ci_fetcher.py <input_log_or_json_path>\n")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        sys.stderr.write(f"Input path '{input_path}' does not exist.\n")
        sys.exit(1)

    log_text = input_path.read_text(encoding="utf-8")
    summary = format_ci_summary(log_text)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
