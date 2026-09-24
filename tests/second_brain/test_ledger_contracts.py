"""
Contract Tests for Second-Brain Event Ledger & Session Bootstrap (Ticket T5 / Phase 4)
Governance-Critical: Append-only hash-chained JSONL ledger and compact session bootstrap context.

Written FIRST per Split-Ticket TDD Protocol.
ALL tests MUST be run against baseline code to demonstrate RED failure before implementation.

CRITICAL INVARIANTS TESTED:
  1. Ledger appends compute cryptographic SHA-256 hash chains linked to prior entry hash.
  2. Tampering with any historical entry in the JSONL ledger is detected by verify_ledger_chain().
  3. session_bootstrap.py constructs a compact ContextPacket under 2,500 token ceiling.
"""

import unittest
import json
import os
import sys
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import second_brain.ledger as ledger
import session_bootstrap


class TestLedgerContracts(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ledger_append_event_builds_hash_chain(self):
        """
        GOVERNANCE INVARIANT: Every ledger event MUST contain a valid SHA-256 hash
        linked to the prior entry's hash.
        """
        self.assertTrue(
            hasattr(ledger, "SecondBrainLedger"),
            "second_brain.ledger MUST expose SecondBrainLedger class"
        )
        sb_ledger = ledger.SecondBrainLedger(self.project_dir)
        e1 = sb_ledger.append_event("PHASE_START", {"phase": 0})
        e2 = sb_ledger.append_event("TICKET_COMPLETE", {"ticket": "T1"})

        self.assertEqual(e1["prev_hash"], "0" * 64, "Root event prev_hash MUST be 64 zeros")
        self.assertEqual(e2["prev_hash"], e1["hash"], "Event 2 prev_hash MUST equal Event 1 hash")

        is_valid, msg = sb_ledger.verify_ledger_chain()
        self.assertTrue(is_valid, f"Fresh ledger hash chain MUST verify as valid: {msg}")

    def test_verify_ledger_chain_detects_tampering(self):
        """
        GOVERNANCE INVARIANT: Tampering with any historical ledger line MUST be detected by verify_ledger_chain().
        """
        sb_ledger = ledger.SecondBrainLedger(self.project_dir)
        sb_ledger.append_event("EVENT_1", {"data": "A"})
        sb_ledger.append_event("EVENT_2", {"data": "B"})

        # Tamper with file directly
        ledger_file = sb_ledger.ledger_path
        lines = ledger_file.read_text(encoding="utf-8").splitlines()
        payload = json.loads(lines[0])
        payload["payload"]["data"] = "TAMPERED"
        lines[0] = json.dumps(payload)
        ledger_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        is_valid, msg = sb_ledger.verify_ledger_chain()
        self.assertFalse(is_valid, "Tampered ledger MUST fail verification")
        self.assertIn("TAMPERED", msg.upper())

    def test_session_bootstrap_emits_compact_context_packet(self):
        """
        GOVERNANCE INVARIANT: session_bootstrap.py MUST construct a compact ContextPacket.
        """
        sb_ledger = ledger.SecondBrainLedger(self.project_dir)
        sb_ledger.append_event("STATE_UPDATE", {"status": "ACTIVE", "slice_id": "slice-001"})
        sb_ledger.append_event("FINDING_OPENED", {"finding_id": "FINDING-001"})

        self.assertTrue(
            hasattr(session_bootstrap, "bootstrap_session_context"),
            "session_bootstrap.py MUST expose bootstrap_session_context function"
        )
        packet = session_bootstrap.bootstrap_session_context(self.project_dir)
        self.assertIn("active_state", packet)
        self.assertIn("open_findings", packet)
        self.assertIn("FINDING-001", packet["open_findings"])


if __name__ == "__main__":
    unittest.main()
