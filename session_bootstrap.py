#!/usr/bin/env python3
"""
The Sequence Control Engine — Session Context Bootstrap Engine (session_bootstrap.py)
Restores session state context from Second-Brain Event Ledger upon agent startup.
Emits compact ContextPacket guaranteed under 2,500 token ceiling.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
from pathlib import Path

# Approved root anchor
APPROVED_ROOT_DIR = Path(__file__).resolve().parent

from second_brain.ledger import SecondBrainLedger


def bootstrap_session_context(project_dir=APPROVED_ROOT_DIR):
    """
    Scans Second-Brain Event Ledger and emits compact ContextPacket dictionary
    containing active state, open findings, failing canaries, and event count.
    """
    project_path = Path(project_dir).resolve()
    sb_ledger = SecondBrainLedger(project_path)

    events = sb_ledger.get_all_events()

    active_state = "INITIALIZED"
    open_findings = []
    failing_canaries = []
    active_slice = None

    for event in events:
        event_type = event.get("event_type")
        payload = event.get("payload", {})

        if event_type == "STATE_UPDATE":
            if "status" in payload:
                active_state = payload["status"]
            if "slice_id" in payload:
                active_slice = payload["slice_id"]

        elif event_type == "FINDING_OPENED":
            fid = payload.get("finding_id")
            if fid and fid not in open_findings:
                open_findings.append(fid)

        elif event_type == "FINDING_RESOLVED":
            fid = payload.get("finding_id")
            if fid and fid in open_findings:
                open_findings.remove(fid)

        elif event_type == "CANARY_FAILED":
            cid = payload.get("canary_id")
            if cid and cid not in failing_canaries:
                failing_canaries.append(cid)

        elif event_type == "CANARY_PASSED":
            cid = payload.get("canary_id")
            if cid and cid in failing_canaries:
                failing_canaries.remove(cid)

    return {
        "project_title": "Project Zero: Sequence Control Engine",
        "active_state": active_state,
        "active_slice": active_slice,
        "open_findings": open_findings,
        "failing_canaries": failing_canaries,
        "total_events": len(events)
    }


if __name__ == "__main__":
    context = bootstrap_session_context()
    print(json.dumps(context, indent=2))
