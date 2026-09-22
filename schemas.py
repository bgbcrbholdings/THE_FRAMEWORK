#!/usr/bin/env python3
"""
The Sequence Control Engine — Schema Validation & Integrity Module (schemas.py)
Provides runtime validation for session.json manifests, API status envelopes,
telemetry envelopes, and path scope allowlists.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import json
import re
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
try:
    from sequence_engine import validate_and_open_path, check_win32_reparse_point
except BaseException:
    validate_and_open_path = None
    check_win32_reparse_point = None



def is_valid_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False

def validate_iso_datetime(val):
    try:
        datetime.fromisoformat(str(val))
        return True
    except ValueError:
        return False

def validate_allowlisted_path(path):
    """Path validation shield: blocks protected dirs (.github) and path traversal ('..')."""
    if ".." in path or path.startswith(".github/"):
        return False, f"Path '{path}' touches protected governance directory or uses path traversal ('..')."
    if not re.match(r'^[A-Za-z0-9_./*-]+$', path):
        return False, f"Path '{path}' contains invalid characters."
    return True, "Valid path."

def validate_session_manifest(manifest):
    """
    Strict validation of .sequence/session.json manifest.
    Validates manifest_id (UUID4), SemVer, non-empty secret tokens, and required keys.
    Returns (is_valid: bool, errors: list[str])
    """
    errors = []
    if not isinstance(manifest, dict):
        return False, ["Manifest must be a JSON dictionary object."]

    required_keys = ["manifest_id", "project_title", "version", "sequence_token", "csrf_nonce", "created_at"]
    for k in required_keys:
        if k not in manifest:
            errors.append(f"Missing required root key: '{k}'")

    if errors:
        return False, errors

    # Manifest ID (UUID)
    if not is_valid_uuid(manifest.get("manifest_id")):
        errors.append(f"manifest_id '{manifest.get('manifest_id')}' is not a valid UUIDv4.")

    # Version (SemVer)
    if not re.match(r'^\d+\.\d+\.\d+$', str(manifest.get("version"))):
        errors.append(f"version '{manifest.get('version')}' must follow SemVer format (e.g. 1.0.0).")

    # Tokens
    token = manifest.get("sequence_token")
    if not token or not isinstance(token, str) or len(token) < 16:
        errors.append("sequence_token must be a non-empty string with high entropy (>= 16 chars).")

    csrf_nonce = manifest.get("csrf_nonce")
    if not csrf_nonce or not isinstance(csrf_nonce, str) or len(csrf_nonce) < 16:
        errors.append("csrf_nonce must be a non-empty string with high entropy (>= 16 chars).")

    # Created At (ISO Datetime)
    timestamp = manifest.get("created_at")
    if not timestamp or not validate_iso_datetime(timestamp):
        errors.append(f"Timestamp '{timestamp}' must be a valid ISO datetime string.")

    # Slices path validation
    slices = manifest.get("slices")
    if isinstance(slices, list):
        for s_idx, slc in enumerate(slices):
            if isinstance(slc, dict):
                allowed_paths = slc.get("allowed_file_paths", [])
                if isinstance(allowed_paths, list):
                    for path in allowed_paths:
                        ok, msg = validate_allowlisted_path(path)
                        if not ok:
                            errors.append(f"slice[{s_idx}] invalid path: {msg}")

    return len(errors) == 0, errors

def validate_status_envelope(data):
    """
    Validates /api/status JSON response envelope shape.
    Required fields: status, server_port (9753), bound_ip ("127.0.0.1"), active_slice, csrf_nonce, uptime_seconds.
    """
    errors = []
    if not isinstance(data, dict):
        return False, ["Status envelope must be a JSON object."]

    if data.get("status") not in ["RUNNING", "PASS", "FAIL", "BLOCKED"]:
        errors.append(f"status '{data.get('status')}' must be one of ['RUNNING', 'PASS', 'FAIL', 'BLOCKED'].")

    if data.get("server_port") != 9753:
        errors.append(f"server_port '{data.get('server_port')}' must be exactly 9753.")

    if data.get("bound_ip") != "127.0.0.1":
        errors.append(f"bound_ip '{data.get('bound_ip')}' must be strictly '127.0.0.1'.")

    if not data.get("active_slice") or not isinstance(data.get("active_slice"), str):
        errors.append("active_slice must be a non-empty string.")

    if not data.get("csrf_nonce") or not isinstance(data.get("csrf_nonce"), str):
        errors.append("csrf_nonce must be a non-empty string.")

    if not isinstance(data.get("uptime_seconds"), (int, float)) or data.get("uptime_seconds") < 0:
        errors.append("uptime_seconds must be a non-negative number.")

    return len(errors) == 0, errors

def validate_slices_envelope(data):
    """Validates /api/slices response shape."""
    errors = []
    if not isinstance(data, dict):
        return False, ["Slices envelope must be a JSON object."]

    if "current_slice_index" not in data or not isinstance(data.get("current_slice_index"), int):
        errors.append("current_slice_index must be an integer.")

    slices = data.get("slices")
    if not isinstance(slices, list):
        errors.append("slices must be a list of slice objects.")

    return len(errors) == 0, errors

def validate_telemetry_envelope(data):
    """Validates /api/telemetry response shape."""
    errors = []
    if not isinstance(data, dict):
        return False, ["Telemetry envelope must be a JSON object."]

    if not data.get("git_branch") or not isinstance(data.get("git_branch"), str):
        errors.append("git_branch must be a non-empty string.")

    if not data.get("last_commit_sha") or not isinstance(data.get("last_commit_sha"), str):
        errors.append("last_commit_sha must be a non-empty string.")

    if data.get("mrac_verdict") not in ["PASS", "FAIL", "BLOCKED"]:
        errors.append(f"mrac_verdict '{data.get('mrac_verdict')}' must be PASS, FAIL, or BLOCKED.")

    return len(errors) == 0, errors

def validate_watchdog_envelope(data):
    """
    Validates supply-chain AST auditor watchdog output envelope.
    Required keys only from allowlist: status, scanned_files_count, forbidden_imports_found, violations, timestamp.
    Rejects unknown top-level keys.
    Asserts (status == 'PASS') == (forbidden_imports_found == 0 and len(violations) == 0).
    Returns (is_valid: bool, errors: list[str]).
    """
    errors = []
    if not isinstance(data, dict):
        return False, ["Watchdog envelope must be a JSON object."]

    allowlisted_keys = {"status", "scanned_files_count", "forbidden_imports_found", "violations", "timestamp"}
    extra_keys = set(data.keys()) - allowlisted_keys
    if extra_keys:
        errors.append(f"Envelope contains un-allowlisted top-level keys: {sorted(list(extra_keys))}")

    missing_keys = allowlisted_keys - set(data.keys())
    if missing_keys:
        errors.append(f"Missing required keys: {sorted(list(missing_keys))}")
        return False, errors

    status = data.get("status")
    if status not in ["PASS", "FAIL"]:
        errors.append(f"status '{status}' must be 'PASS' or 'FAIL'.")

    scanned_count = data.get("scanned_files_count")
    if not isinstance(scanned_count, int) or scanned_count < 0:
        errors.append(f"scanned_files_count must be a non-negative int, got {type(scanned_count).__name__}.")

    forbidden_count = data.get("forbidden_imports_found")
    if not isinstance(forbidden_count, int) or forbidden_count < 0:
        errors.append(f"forbidden_imports_found must be a non-negative int, got {type(forbidden_count).__name__}.")

    violations = data.get("violations")
    if not isinstance(violations, list):
        errors.append("violations must be a list.")
    else:
        for i, v in enumerate(violations):
            if not isinstance(v, dict):
                errors.append(f"violation[{i}] must be a JSON dictionary object.")
                continue
            for k in ["file", "line", "name", "kind"]:
                if k not in v:
                    errors.append(f"violation[{i}] missing required key '{k}'.")
            if "line" in v and (not isinstance(v["line"], int) or v["line"] < 1):
                errors.append(f"violation[{i}].line must be an int >= 1.")

    timestamp = data.get("timestamp")
    if not timestamp or not validate_iso_datetime(timestamp):
        errors.append(f"Timestamp '{timestamp}' must be a valid ISO datetime string.")

    if status == "PASS" and (forbidden_count != 0 or len(violations) != 0):
        errors.append("Invariant violation: status is PASS but forbidden_imports_found > 0 or violations list is non-empty.")

    if status == "FAIL" and forbidden_count == 0 and len(violations) == 0:
        errors.append("Invariant violation: status is FAIL but forbidden_imports_found == 0 and violations list is empty.")

    return len(errors) == 0, errors

def validate_regr_watchdog_envelope(data):
    """
    Validates regression watchdog test output envelope.
    Required keys only from allowlist: status, total_tests_run, passed, failed, errored, failed_test_names, timestamp.
    Rejects unknown top-level keys.
    Returns (is_valid: bool, errors: list[str]).
    """
    errors = []
    if not isinstance(data, dict):
        return False, ["Regression watchdog envelope must be a JSON object."]

    allowlisted_keys = {"status", "total_tests_run", "passed", "failed", "errored", "failed_test_names", "timestamp"}
    extra_keys = set(data.keys()) - allowlisted_keys
    if extra_keys:
        errors.append(f"Envelope contains un-allowlisted top-level keys: {sorted(list(extra_keys))}")

    missing_keys = allowlisted_keys - set(data.keys())
    if missing_keys:
        errors.append(f"Missing required keys: {sorted(list(missing_keys))}")
        return False, errors

    status = data.get("status")
    if status not in ["PASS", "FAIL"]:
        errors.append(f"status '{status}' must be 'PASS' or 'FAIL'.")

    total = data.get("total_tests_run")
    passed = data.get("passed")
    failed = data.get("failed")
    errored = data.get("errored")

    for name, val in [("total_tests_run", total), ("passed", passed), ("failed", failed), ("errored", errored)]:
        if not isinstance(val, int) or val < 0:
            errors.append(f"{name} must be a non-negative int.")

    if isinstance(total, int) and isinstance(passed, int) and isinstance(failed, int) and isinstance(errored, int):
        if total != passed + failed + errored:
            errors.append(f"Invariant violation: total_tests_run ({total}) != passed ({passed}) + failed ({failed}) + errored ({errored}).")

    if status == "PASS" and (failed > 0 or errored > 0):
        errors.append("Invariant violation: status is PASS but failed > 0 or errored > 0.")

    if status == "FAIL" and failed == 0 and errored == 0 and total > 0:
        errors.append("Invariant violation: status is FAIL but failed == 0 and errored == 0.")

    failed_names = data.get("failed_test_names")
    if not isinstance(failed_names, list):
        errors.append("failed_test_names must be a list.")

    timestamp = data.get("timestamp")
    if not timestamp or not validate_iso_datetime(timestamp):
        errors.append(f"Timestamp '{timestamp}' must be a valid ISO datetime string.")

    return len(errors) == 0, errors

def validate_file_hygiene_envelope(data):
    """
    Validates file hygiene engine scan result envelope.
    Required keys only from allowlist: status, governance_headers_updated, loose_files_sweeper_count, alignment_status, alignment_issues, timestamp.
    Rejects unknown top-level keys.
    Returns (is_valid: bool, errors: list[str]).
    """
    errors = []
    if not isinstance(data, dict):
        return False, ["File hygiene envelope must be a JSON object."]

    allowlisted_keys = {"status", "governance_headers_updated", "loose_files_sweeper_count", "alignment_status", "alignment_issues", "timestamp"}
    extra_keys = set(data.keys()) - allowlisted_keys
    if extra_keys:
        errors.append(f"Envelope contains un-allowlisted top-level keys: {sorted(list(extra_keys))}")

    missing_keys = allowlisted_keys - set(data.keys())
    if missing_keys:
        errors.append(f"Missing required keys: {sorted(list(missing_keys))}")
        return False, errors

    status = data.get("status")
    if status not in ["PASS", "FAIL"]:
        errors.append(f"status '{status}' must be 'PASS' or 'FAIL'.")

    alignment_status = data.get("alignment_status")
    if alignment_status not in ["ALIGNED", "DRIFT", "ORPHAN"]:
        errors.append(f"alignment_status '{alignment_status}' must be one of ['ALIGNED', 'DRIFT', 'ORPHAN'].")

    headers_updated = data.get("governance_headers_updated")
    if not isinstance(headers_updated, int) or headers_updated < 0:
        errors.append("governance_headers_updated must be a non-negative int.")

    sweeper_count = data.get("loose_files_sweeper_count")
    if not isinstance(sweeper_count, int) or sweeper_count < 0:
        errors.append("loose_files_sweeper_count must be a non-negative int.")

    issues = data.get("alignment_issues")
    if not isinstance(issues, list):
        errors.append("alignment_issues must be a list.")
    else:
        for i, issue in enumerate(issues):
            if not isinstance(issue, dict) or "path" not in issue or "reason" not in issue:
                errors.append(f"alignment_issues[{i}] must be an object with 'path' and 'reason' keys.")

    timestamp = data.get("timestamp")
    if not timestamp or not validate_iso_datetime(timestamp):
        errors.append(f"Timestamp '{timestamp}' must be a valid ISO datetime string.")

    if alignment_status in ["DRIFT", "ORPHAN"] and status != "FAIL":
        errors.append("Invariant violation: alignment_status is DRIFT or ORPHAN but status is not FAIL.")

    return len(errors) == 0, errors

def validate_dispatch_request(data):
    """
    Validates pre-execution dispatch request payload.
    Required keys only from allowlist: dispatch_id, skill_id, command, timeout_seconds, timestamp.
    Rejects unknown top-level keys.
    Returns (is_valid: bool, errors: list[str]).
    """
    errors = []
    if not isinstance(data, dict):
        return False, ["Dispatch request must be a JSON object."]

    allowlisted_keys = {"dispatch_id", "skill_id", "command", "timeout_seconds", "timestamp"}
    extra_keys = set(data.keys()) - allowlisted_keys
    if extra_keys:
        errors.append(f"Envelope contains un-allowlisted top-level keys: {sorted(list(extra_keys))}")

    missing_keys = allowlisted_keys - set(data.keys())
    if missing_keys:
        errors.append(f"Missing required keys: {sorted(list(missing_keys))}")
        return False, errors

    if not is_valid_uuid(data.get("dispatch_id")):
        errors.append(f"dispatch_id '{data.get('dispatch_id')}' must be a valid UUIDv4.")

    if not isinstance(data.get("skill_id"), str) or not data.get("skill_id"):
        errors.append("skill_id must be a non-empty string.")

    cmd = data.get("command")
    if not isinstance(cmd, list) or len(cmd) < 1 or not all(isinstance(x, str) and len(x) > 0 for x in cmd):
        errors.append("command must be a non-empty list of non-empty strings.")

    timeout = data.get("timeout_seconds")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        errors.append("timeout_seconds must be a positive number.")

    timestamp = data.get("timestamp")
    if not timestamp or not validate_iso_datetime(timestamp):
        errors.append(f"Timestamp '{timestamp}' must be a valid ISO datetime string.")

    return len(errors) == 0, errors

def validate_dispatch_envelope(data):
    """
    Validates completed dispatch result envelope.
    Required keys: dispatch_id, skill_id, command, status, stage1_precheck, stage2_execution, stage3_audit, execution_time_seconds, timestamp.
    Rejects unknown top-level keys.
    Returns (is_valid: bool, errors: list[str]).
    """
    errors = []
    if not isinstance(data, dict):
        return False, ["Dispatch envelope must be a JSON object."]

    allowlisted_keys = {
        "dispatch_id", "skill_id", "command", "status",
        "stage1_precheck", "stage2_execution", "stage3_audit",
        "execution_time_seconds", "timestamp"
    }
    extra_keys = set(data.keys()) - allowlisted_keys
    if extra_keys:
        errors.append(f"Envelope contains un-allowlisted top-level keys: {sorted(list(extra_keys))}")

    missing_keys = allowlisted_keys - set(data.keys())
    if missing_keys:
        errors.append(f"Missing required keys: {sorted(list(missing_keys))}")
        return False, errors

    if not is_valid_uuid(data.get("dispatch_id")):
        errors.append(f"dispatch_id '{data.get('dispatch_id')}' must be a valid UUIDv4.")

    if not isinstance(data.get("skill_id"), str) or not data.get("skill_id"):
        errors.append("skill_id must be a non-empty string.")

    cmd = data.get("command")
    if not isinstance(cmd, list):
        errors.append("command must be a list of strings.")

    status = data.get("status")
    if status not in ["PASS", "FAIL", "BLOCKED"]:
        errors.append(f"status '{status}' must be 'PASS', 'FAIL', or 'BLOCKED'.")

    s1 = data.get("stage1_precheck")
    s2 = data.get("stage2_execution")
    s3 = data.get("stage3_audit")

    if not isinstance(s1, dict):
        errors.append("stage1_precheck must be a dictionary object.")
    if not isinstance(s2, dict):
        errors.append("stage2_execution must be a dictionary object.")
    else:
        if status in ["PASS", "FAIL"] and "estimated_cost_usd" in s2:
            cost = s2.get("estimated_cost_usd")
            if not isinstance(cost, (int, float)) or cost < 0:
                errors.append("stage2_execution.estimated_cost_usd must be a non-negative number.")
    if not isinstance(s3, dict):
        errors.append("stage3_audit must be a dictionary object.")

    exec_time = data.get("execution_time_seconds")
    if not isinstance(exec_time, (int, float)) or exec_time < 0:
        errors.append("execution_time_seconds must be a non-negative number.")

    timestamp = data.get("timestamp")
    if not timestamp or not validate_iso_datetime(timestamp):
        errors.append(f"Timestamp '{timestamp}' must be a valid ISO datetime string.")

    if status == "PASS":
        s2_exit = s2.get("exit_code") if isinstance(s2, dict) else -1
        s3_auditor_pass = s3.get("auditor_pass") if isinstance(s3, dict) else False
        s3_unittest_pass = s3.get("unittest_pass") if isinstance(s3, dict) else False
        if s2_exit != 0 or not s3_auditor_pass or not s3_unittest_pass:
            errors.append("Invariant violation: status is PASS but Stage 2 exit_code != 0 or Stage 3 failed.")

    return len(errors) == 0, errors

def validate_trust_ledger_envelope(data):
    """
    Validates loaded trust ledger dictionary.
    Keys are skill_ids mapping to entry dicts.
    Entry required keys: skill_id, tier, total_runs, pass_count, accuracy_pct, last_updated.
    Returns (is_valid: bool, errors: list[str]).
    """
    errors = []
    if not isinstance(data, dict):
        return False, ["Trust ledger envelope must be a JSON object mapping skill_id to entry dicts."]

    for skill_id, entry in data.items():
        if not isinstance(entry, dict):
            errors.append(f"Trust entry for '{skill_id}' must be a dictionary.")
            continue
        req_keys = {"skill_id", "tier", "total_runs", "pass_count", "accuracy_pct", "last_updated"}
        missing = req_keys - set(entry.keys())
        if missing:
            errors.append(f"Trust entry '{skill_id}' missing keys: {sorted(list(missing))}")
            continue

        tier = entry.get("tier")
        if tier not in ["auto", "watch", "queue"]:
            errors.append(f"Trust entry '{skill_id}'.tier must be 'auto', 'watch', or 'queue'.")

        total = entry.get("total_runs")
        passed = entry.get("pass_count")
        acc = entry.get("accuracy_pct")

        if not isinstance(total, int) or total < 0:
            errors.append(f"Trust entry '{skill_id}'.total_runs must be a non-negative int.")
        if not isinstance(passed, int) or passed < 0:
            errors.append(f"Trust entry '{skill_id}'.pass_count must be a non-negative int.")
        if not isinstance(acc, (int, float)) or acc < 0.0 or acc > 100.0:
            errors.append(f"Trust entry '{skill_id}'.accuracy_pct must be a float between 0.0 and 100.0.")

        if isinstance(total, int) and isinstance(passed, int) and isinstance(acc, (int, float)):
            if passed > total:
                errors.append(f"Invariant violation for '{skill_id}': pass_count ({passed}) > total_runs ({total}).")
            if total > 0:
                expected_acc = (passed / total) * 100.0
                if abs(expected_acc - acc) > 0.1:
                    errors.append(f"Invariant violation for '{skill_id}': accuracy_pct ({acc}) does not match pass_count/total_runs ({expected_acc:.1f}).")

        timestamp = entry.get("last_updated")
        if not timestamp or not validate_iso_datetime(timestamp):
            errors.append(f"Timestamp '{timestamp}' in entry '{skill_id}' must be a valid ISO datetime string.")

    return len(errors) == 0, errors

def validate_cost_monitor_envelope(data):
    """
    Validates USD budget ceiling monitoring envelope (.sequence/cost_ledger.json).
    Required keys: date, daily_spend_usd, budget_limit_usd, budget_exceeded, last_updated.
    Rejects unknown top-level keys.
    Returns (is_valid: bool, errors: list[str]).
    """
    errors = []
    if not isinstance(data, dict):
        return False, ["Cost monitor envelope must be a JSON object."]

    allowlisted_keys = {"date", "daily_spend_usd", "budget_limit_usd", "budget_exceeded", "last_updated"}
    extra_keys = set(data.keys()) - allowlisted_keys
    if extra_keys:
        errors.append(f"Envelope contains un-allowlisted top-level keys: {sorted(list(extra_keys))}")

    missing_keys = allowlisted_keys - set(data.keys())
    if missing_keys:
        errors.append(f"Missing required keys: {sorted(list(missing_keys))}")
        return False, errors

    date_str = data.get("date")
    if not isinstance(date_str, str) or not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
        errors.append(f"date '{date_str}' must be formatted as YYYY-MM-DD.")

    spend = data.get("daily_spend_usd")
    if not isinstance(spend, (int, float)) or spend < 0.0:
        errors.append("daily_spend_usd must be a non-negative float.")

    limit = data.get("budget_limit_usd")
    if not isinstance(limit, (int, float)) or limit <= 0.0:
        errors.append("budget_limit_usd must be a positive float.")

    exceeded = data.get("budget_exceeded")
    if not isinstance(exceeded, bool):
        errors.append("budget_exceeded must be a boolean.")

    timestamp = data.get("last_updated")
    if not timestamp or not validate_iso_datetime(timestamp):
        errors.append(f"Timestamp '{timestamp}' must be a valid ISO datetime string.")

    if isinstance(spend, (int, float)) and isinstance(limit, (int, float)) and isinstance(exceeded, bool):
        expected_exceeded = (spend >= limit)
        if exceeded != expected_exceeded:
            errors.append(f"Invariant violation: budget_exceeded is {exceeded} but (daily_spend_usd {spend} >= budget_limit_usd {limit}) is {expected_exceeded}.")

    return len(errors) == 0, errors

from dataclasses import dataclass
from typing import Literal

EXPECTED_CREATED_DIRS = sorted(["01_GOVERNANCE", "02_BACKLOG", "03_INCUBATOR", "04_REVIEWS", ".sequence", "tests", ".github"])
EXPECTED_PRESEEDED_TEMPLATES = sorted([
    "ALLOWLIST.txt",
    "README.md",
    "01_GOVERNANCE/BOOTSTRAP.md",
    "01_GOVERNANCE/FORBIDDEN.yml",
    "01_GOVERNANCE/PROBLEM.md",
    "01_GOVERNANCE/NON_GOALS.md",
    "01_GOVERNANCE/ARCHITECTURE.md",
    "01_GOVERNANCE/DECISIONS.md",
    "02_BACKLOG/AGILE_SLICES.md",
    ".sequence/mrac_rules.json",
    "tests/test_runner.py",
    "tests/test_genesis.py",
    ".github/CODEOWNERS",
    ".github/workflows/ci.yml",
    "run_tests.bat",
    "build_packet.bat",
    "parse_reviews.bat"
])

@dataclass
class GenesisProjectSpec:
    project_name: str
    root_dir: str
    created_dirs: list[str]
    preseeded_templates: list[str]
    force_used: bool

    def validate(self) -> bool:
        if not re.match(r"^[a-zA-Z0-9_-]+$", self.project_name):
            raise ValueError("Invalid project_name format")
        if self.project_name.lower() == "00_dev_team_sequence":
            raise ValueError("Reserved project_name")
        if re.match(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$", self.project_name, re.IGNORECASE):
            raise ValueError("Reserved OS device name")
        
        root_canon = str(os.path.realpath(self.root_dir))
        approved = str(os.path.realpath("C:\\Linkstream"))
        is_beneath_approved = False
        try:
            is_beneath_approved = (str(os.path.commonpath([root_canon, approved])).casefold() == str(approved).casefold())
        except ValueError:
            is_beneath_approved = False
        is_temp_sandbox = ("temp" in root_canon.lower() or "tmp" in root_canon.lower())
        if not is_beneath_approved and not is_temp_sandbox:
            raise ValueError("root_dir must be canonical path beneath C:\\Linkstream")
        
        # Reparse-Point / Junction Validation in schemas.py (FINDING-007)
        root_path = Path(root_canon)
        if root_path.exists() and check_win32_reparse_point(root_path):
            raise ValueError("root_dir failed reparse-point/junction validation")

        if sorted(self.created_dirs) != EXPECTED_CREATED_DIRS:
            raise ValueError(f"created_dirs mismatch: expected {EXPECTED_CREATED_DIRS}")
        if sorted(self.preseeded_templates) != EXPECTED_PRESEEDED_TEMPLATES:
            raise ValueError("preseeded_templates mismatch or contains forbidden session.json")
        return True

@dataclass
class TestSummaryReport:
    timestamp: str
    status: Literal["PASS", "FAIL"]
    total_tests: int
    passed: int
    failed: int
    errors: int
    skipped: int
    duration_seconds: float
    failure_details: list[dict]

    def validate(self) -> bool:
        if self.status not in ("PASS", "FAIL"):
            raise ValueError("Invalid status enum")
        if self.duration_seconds < 0.0:
            raise ValueError("duration_seconds must be >= 0")
        try:
            datetime.fromisoformat(self.timestamp)
        except Exception as e:
            raise ValueError(f"timestamp must be valid ISO-8601: {e}")
        
        for idx, item in enumerate(self.failure_details):
            if not isinstance(item, dict):
                raise ValueError(f"failure_details[{idx}] must be a dict")
            if not {"test_name", "message", "traceback"}.issubset(item.keys()):
                raise ValueError(f"failure_details[{idx}] missing required keys")
            if not isinstance(item["test_name"], str) or not isinstance(item["message"], str) or not isinstance(item["traceback"], str):
                raise ValueError(f"failure_details[{idx}] key values must be strings")
        return True

def validate_genesis_project_spec(spec_obj):
    try:
        if hasattr(spec_obj, "validate"):
            spec_obj.validate()
        else:
            return False, ["Invalid GenesisProjectSpec object."]
        return True, ["Valid GenesisProjectSpec."]
    except Exception as e:
        return False, [str(e)]

def validate_test_summary_report(report_obj):
    try:
        if hasattr(report_obj, "validate"):
            report_obj.validate()
        else:
            return False, ["Invalid TestSummaryReport object."]
        return True, ["Valid TestSummaryReport."]
    except Exception as e:
        return False, [str(e)]

def generate_invariants_file(manifest, arch_text):
    arch_hash = hashlib.sha256(arch_text.encode("utf-8")).hexdigest()
    invariants = {
        "version": "1.0.0",
        "arch_hash": arch_hash,
        "forbidden_patterns": ["git commit --no-verify", "rm -rf .git"]
    }
    return invariants, arch_hash

def validate_mrac_constraint(constraint_obj):
    errors = []
    if not isinstance(constraint_obj, dict):
        return False, ["MRAC constraint must be a dict"]
    required_keys = ["id", "type", "description", "check", "on_failure"]
    for k in required_keys:
        if k not in constraint_obj:
            errors.append(f"Missing required key '{k}' in MRAC constraint")
    if "check" in constraint_obj and isinstance(constraint_obj["check"], dict):
        check_keys = ["method", "pattern", "file_glob"]
        for ck in check_keys:
            if ck not in constraint_obj["check"]:
                errors.append(f"Missing required key '{ck}' in MRAC constraint check")
    elif "check" in constraint_obj:
        errors.append("MRAC constraint 'check' must be a dict")
    return len(errors) == 0, errors

def validate_lock_wall_envelope(data) -> bool:
    """
    Validates status envelope for LockWallEngine.
    Requires dict with status in {'OK', 'FAILED', 'SEALED'}, tcb_count int >= 12
    (11 scripts + mrac_rules.json + >= 1 dashboard file OR explicit dashboard_file_count field >= 1),
    manifest_hash_match bool, boot_digest_match bool, mismatched_paths list[str],
    and ISO-8601 UTC Z timestamp. Returns False on any missing or incorrect types.
    """
    if not isinstance(data, dict):
        return False

    status = data.get("status")
    if status not in {"OK", "FAILED", "SEALED"}:
        return False

    tcb_count = data.get("tcb_count")
    if type(tcb_count) is not int or tcb_count < 11:
        return False

    dashboard_count = data.get("dashboard_file_count", 0)
    if type(dashboard_count) is not int:
        return False

    if tcb_count < 12 and dashboard_count < 1:
        return False

    manifest_match = data.get("manifest_hash_match")
    if type(manifest_match) is not bool:
        return False

    boot_match = data.get("boot_digest_match")
    if type(boot_match) is not bool:
        return False

    mismatched = data.get("mismatched_paths")
    if type(mismatched) is not list or not all(isinstance(x, str) for x in mismatched):
        return False

    timestamp = data.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        return False
    if not validate_iso_datetime(timestamp[:-1]):
        return False

    return True

def validate_ast_graph_envelope(data) -> bool:
    """
    Validates status envelope for GraphifyASTParser / CodeGraph Symbol Mapper.
    Requires scanned_modules, classes_found, functions_found, call_edges_count,
    wiki_notes_generated as non-negative ints, and ISO-8601 UTC Z timestamp.
    Returns False on any missing or incorrect types.
    """
    if not isinstance(data, dict):
        return False

    for k in ["scanned_modules", "classes_found", "functions_found", "call_edges_count", "wiki_notes_generated"]:
        v = data.get(k)
        if type(v) is not int or v < 0:
            return False

    timestamp = data.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        return False
    if not validate_iso_datetime(timestamp[:-1]):
        return False

    return True





