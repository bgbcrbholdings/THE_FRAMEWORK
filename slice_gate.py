#!/usr/bin/env python3
"""
Project Zero: The Sequence Control Engine — Slice Lifecycle Circuit Breaker (slice_gate.py)
Action-aware circuit breaker enforcing slice lifecycle status and packet content hash binding.
Zero-pip Python standard library implementation.
"""

import sys
import json
import hashlib
import argparse
from pathlib import Path

READ_ONLY_ACTIONS = {"VIEW_STATUS"}
REMEDIATION_ACTIONS = {"REMEDIATE_PLAN", "BUILD_PACKET", "PARSE_REVIEWS"}
IMPLEMENTATION_ACTIONS = {"IMPLEMENT", "CONTRACT_TEST", "OPEN_PR", "RUN_WIZARD"}
LOCK_ACTIONS = {"LOCK"}

UNRESOLVED_STATUSES = {"OPEN", "REJECTED_NOT_IMPLEMENTED", "REJECTED_PARTIAL"}


class SliceGateDeniedError(Exception):
    """Raised when a slice action is denied by the lifecycle gate."""
    def __init__(self, message: str, code: str = "GATE_DENIED"):
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


def resolve_active_slice_id(project_root: Path) -> str:
    """
    Resolves active slice_id from .sequence/active_packet.json.
    Falls back to .sequence/review_resolutions.json top-level slice_id or latest slice.
    Raises SliceGateDeniedError if unresolved.
    """
    p_dir = Path(project_root)
    active_ptr = p_dir / ".sequence" / "active_packet.json"
    if active_ptr.exists():
        try:
            data = json.loads(active_ptr.read_text(encoding="utf-8"))
            if data.get("slice_id"):
                return data["slice_id"]
        except Exception:
            pass

    res_file = p_dir / ".sequence" / "review_resolutions.json"
    if res_file.exists():
        try:
            res_data = json.loads(res_file.read_text(encoding="utf-8"))
            if res_data.get("slice_id"):
                return res_data["slice_id"]
            slices = res_data.get("slices", {})
            if slices:
                return list(slices.keys())[-1]
        except Exception:
            pass

    raise SliceGateDeniedError("Unable to resolve active slice_id from .sequence pointer files", code="MISSING_ACTIVE_SLICE")


def compute_live_packet_hash(project_root: Path, slice_id: str) -> str:
    """
    Computes pure stdlib sha256 hex digest over line-numbered proposal + fixed governance anchors.
    Strict LF normalization (\r\n -> \n) applied across all inputs to guarantee cross-platform consistency.
    AGILE_SLICES.md is intentionally EXCLUDED from live packet hash anchors to eliminate self-lockout cascades.
    Exact proposal path required: 04_REVIEWS/<slice_id>/implementation_plan.md (no root fallback).
    """
    p_dir = Path(project_root)
    prob_file = p_dir / "01_GOVERNANCE" / "PROBLEM.md"
    nongoal_file = p_dir / "01_GOVERNANCE" / "NON_GOALS.md"
    arch_file = p_dir / "01_GOVERNANCE" / "ARCHITECTURE.md"

    prob_txt = prob_file.read_text(encoding="utf-8").replace("\r\n", "\n") if prob_file.exists() else ""
    nongoal_txt = nongoal_file.read_text(encoding="utf-8").replace("\r\n", "\n") if nongoal_file.exists() else ""
    arch_txt = arch_file.read_text(encoding="utf-8").replace("\r\n", "\n") if arch_file.exists() else ""

    plan_file = p_dir / "04_REVIEWS" / slice_id / "implementation_plan.md"
    if not plan_file.exists():
        raise SliceGateDeniedError(f"Plan file missing for '{slice_id}' at '{plan_file}'. DENIED.", code="MISSING_PLAN_FILE")
    
    plan_raw = plan_file.read_text(encoding="utf-8").replace("\r\n", "\n")

    lines = plan_raw.split("\n")
    plan_numbered = "\n".join([f"L{i+1:04d}: {line}" for i, line in enumerate(lines)])

    gov_anchors = f"=== LOCKED GOVERNANCE ANCHORS (PREFIX-PRESERVED FOR PROMPT CACHING) ===\n\n{prob_txt}\n\n---\n\n{nongoal_txt}\n\n---\n\n{arch_txt}"
    content_bundle = f"{gov_anchors}\n\n=== PROPOSED IMPLEMENTATION PLAN FOR SLICE: '{slice_id}' (LINE-NUMBERED ANCHORS) ===\n\n{plan_numbered}"
    
    return hashlib.sha256(content_bundle.encode("utf-8")).hexdigest()


def check_slice_action_allowed(slice_id: str, action: str, project_root: Path) -> None:
    """
    Pure Python check function. Raises SliceGateDeniedError on failure (never sys.exit).
    Used by safe_write and internal engine callers for catchable exception handling.
    """
    # 1. Immediate passthrough for READ_ONLY_ACTIONS
    if action in READ_ONLY_ACTIONS:
        return

    valid_actions = REMEDIATION_ACTIONS | IMPLEMENTATION_ACTIONS | LOCK_ACTIONS
    if action not in valid_actions:
        raise SliceGateDeniedError(f"Unknown action '{action}'. DENIED.", code="UNKNOWN_ACTION")

    res_path = Path(project_root) / ".sequence" / "review_resolutions.json"
    
    if not res_path.exists():
        if action in (IMPLEMENTATION_ACTIONS | LOCK_ACTIONS):
            raise SliceGateDeniedError(f"No review resolution file found for '{slice_id}'. Action '{action}' DENIED.", code="MISSING_RESOLUTIONS")
        return  # Remediation allowed for unreviewed slice (PENDING_REVIEW)

    try:
        data = json.loads(res_path.read_text(encoding="utf-8"))
    except Exception:
        raise SliceGateDeniedError(f"Corrupted review_resolutions.json. Action '{action}' DENIED.", code="CORRUPTED_RESOLUTIONS")

    slices_map = data.get("slices", {})
    slice_entry = slices_map.get(slice_id)
    
    # Legacy fallback guard: ONLY adopt top-level object IF data.get("slice_id") == slice_id
    if not slice_entry and data.get("slice_id") == slice_id:
        slice_entry = data

    if not slice_entry:
        if action in (IMPLEMENTATION_ACTIONS | LOCK_ACTIONS):
            raise SliceGateDeniedError(f"No review entry for slice '{slice_id}'. Action '{action}' DENIED.", code="SLICE_NOT_FOUND")
        return

    verdict = slice_entry.get("overall_verdict", "BLOCKED")
    gate_status = slice_entry.get("gate_status", "OK")

    # Strict Deny-by-Default for IMPLEMENTATION and LOCK actions
    if action in (IMPLEMENTATION_ACTIONS | LOCK_ACTIONS):
        if gate_status == "ALLOWLIST_PR_PENDING":
            raise SliceGateDeniedError(f"Slice '{slice_id}' has pending ALLOWLIST PR. Action '{action}' DENIED.", code="ALLOWLIST_PR_PENDING")

        if verdict != "APPROVED":
            raise SliceGateDeniedError(f"Slice '{slice_id}' status is '{verdict}' (not 'APPROVED'). Action '{action}' DENIED.", code="VERDICT_NOT_APPROVED")

        # Cryptographic Packet SHA256 Binding Check
        stored_hash = slice_entry.get("packet_sha256")
        current_hash = compute_live_packet_hash(project_root, slice_id)
        if not stored_hash or stored_hash != current_hash:
            raise SliceGateDeniedError(f"Packet hash mismatch for '{slice_id}'. Approved: {stored_hash}, Current: {current_hash}.", code="HASH_MISMATCH")

        # LOCK action additional prechecks: align unresolved finding status set
        if action in LOCK_ACTIONS:
            has_unresolved = any(
                f.get("severity") == "CRITICAL" and f.get("status", "OPEN") in UNRESOLVED_STATUSES
                for f in slice_entry.get("findings", [])
            )
            if has_unresolved:
                raise SliceGateDeniedError(f"Lock DENIED for '{slice_id}': unresolved CRITICAL findings exist.", code="OPEN_CRITICAL_FINDINGS")


def assert_slice_action_allowed(slice_id: str, action: str, project_root: Path) -> None:
    """
    CLI wrapper function. Calls check_slice_action_allowed and exits with status 1 on denial.
    """
    try:
        check_slice_action_allowed(slice_id, action, project_root)
    except SliceGateDeniedError as e:
        sys.stderr.write(f"\n[FATAL] GATING VIOLATION: {e.message}\n\n")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Slice Lifecycle Circuit Breaker CLI Gate")
    parser.add_argument("slice_id", help="Target slice ID or 'auto'")
    parser.add_argument("action", help="Lifecycle action to perform")
    parser.add_argument("--root", default=".", help="Project root directory path")
    args = parser.parse_args()

    root_path = Path(args.root).resolve()
    target_slice = resolve_active_slice_id(root_path) if args.slice_id == "auto" else args.slice_id
    assert_slice_action_allowed(target_slice, args.action, root_path)
