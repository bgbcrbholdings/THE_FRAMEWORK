#!/usr/bin/env python3
"""
The Sequence Control Engine — Second-Brain Cryptographic Event Ledger (second_brain/ledger.py)
Implements append-only, SHA-256 hash-chained JSONL event ledger for session tracking.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
import uuid
import hashlib
from pathlib import Path
from datetime import datetime, timezone

from sequence_engine import validate_and_open_path


class SecondBrainLedger:
    """
    Append-only, SHA-256 hash-chained JSONL event ledger.
    Maintains immutable event log inside 03_STATE/second_brain/ledger.jsonl.
    """

    def __init__(self, project_dir):
        self.project_dir = Path(project_dir).resolve()
        self.state_dir = self.project_dir / "03_STATE" / "second_brain"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_path = self.state_dir / "ledger.jsonl"
        self._ensure_ledger_exists()

    def _ensure_ledger_exists(self):
        if not self.ledger_path.exists():
            with open(self.ledger_path, "w", encoding="utf-8") as f:
                f.write("")

    def _compute_event_hash(self, event_id, timestamp_utc, event_type, payload, prev_hash):
        """Computes deterministic SHA-256 hash over event fields."""
        payload_str = json.dumps(payload, sort_keys=True)
        raw = f"{event_id}|{timestamp_utc}|{event_type}|{payload_str}|{prev_hash}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get_last_event(self):
        """Reads and returns the last line of the ledger, or None if empty."""
        if not self.ledger_path.exists() or self.ledger_path.stat().st_size == 0:
            return None
        lines = self.ledger_path.read_text(encoding="utf-8").splitlines()
        valid_lines = [l for l in lines if l.strip()]
        if not valid_lines:
            return None
        return json.loads(valid_lines[-1])

    def append_event(self, event_type, payload):
        """
        Appends a new event to the ledger with SHA-256 hash chaining.
        """
        last_event = self.get_last_event()
        prev_hash = last_event["hash"] if last_event else "0" * 64

        event_id = str(uuid.uuid4())
        timestamp_utc = datetime.now(timezone.utc).isoformat()
        event_hash = self._compute_event_hash(event_id, timestamp_utc, event_type, payload, prev_hash)

        event_data = {
            "event_id": event_id,
            "timestamp_utc": timestamp_utc,
            "event_type": event_type,
            "payload": payload,
            "prev_hash": prev_hash,
            "hash": event_hash
        }

        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_data) + "\n")

        return event_data

    def get_all_events(self):
        """Reads all events from the ledger."""
        if not self.ledger_path.exists() or self.ledger_path.stat().st_size == 0:
            return []
        lines = self.ledger_path.read_text(encoding="utf-8").splitlines()
        events = []
        for line in lines:
            if line.strip():
                events.append(json.loads(line.strip()))
        return events

    def verify_ledger_chain(self):
        """
        Verifies SHA-256 hash chain integrity of all entries in the ledger.
        Returns tuple (is_valid: bool, detail: str).
        """
        events = self.get_all_events()
        if not events:
            return True, "Ledger is empty."

        expected_prev_hash = "0" * 64
        for idx, event in enumerate(events):
            event_id = event.get("event_id")
            timestamp_utc = event.get("timestamp_utc")
            event_type = event.get("event_type")
            payload = event.get("payload")
            prev_hash = event.get("prev_hash")
            stored_hash = event.get("hash")

            if prev_hash != expected_prev_hash:
                return False, f"TAMPERED_PREV_HASH: Entry index {idx} ({event_id}) prev_hash '{prev_hash}' != expected '{expected_prev_hash}'"

            computed_hash = self._compute_event_hash(event_id, timestamp_utc, event_type, payload, prev_hash)
            if computed_hash != stored_hash:
                return False, f"TAMPERED_HASH_MISMATCH: Entry index {idx} ({event_id}) stored '{stored_hash}' != computed '{computed_hash}'"

            expected_prev_hash = stored_hash

        return True, f"Ledger chain verified over {len(events)} events."


def verify_project_ledger(project_dir):
    """Utility wrapper for verify.py --verify-ledger CLI integration."""
    sb_ledger = SecondBrainLedger(project_dir)
    return sb_ledger.verify_ledger_chain()
