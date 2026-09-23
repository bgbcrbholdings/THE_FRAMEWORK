"""
Contract Tests for build_packet.py (Ticket T1)
Governance-Critical: Fail-closed verification packet assembly contracts.

Written FIRST per Split-Ticket TDD Protocol.
ALL tests MUST be run against current HEAD to demonstrate RED failure before code fix.

CRITICAL INVARIANTS TESTED:
  1. v2 packets PRESERVE all prior findings
  2. Empty checklist from non-empty prior findings triggers FATAL exit 7
  3. Default verdict is BLOCKED (never default APPROVE)
"""

import unittest
import json
import sys
import os

import build_packet


class TestBuildPacketContracts(unittest.TestCase):

    def setUp(self):
        self.valid_prior_findings = [
            {
                "finding_id": "RT-001",
                "severity": "HIGH",
                "finding_type": "GOVERNANCE",
                "description": "Missing schema validation",
                "status": "OPEN"
            },
            {
                "finding_id": "RT-002",
                "severity": "CRITICAL",
                "finding_type": "SECURITY",
                "description": "Unchecked execution path",
                "status": "OPEN"
            }
        ]

    def test_v2_packet_preserves_all_prior_findings(self):
        """
        GOVERNANCE INVARIANT: Verification packets MUST contain ALL findings
        from prior review rounds.
        """
        packet = build_packet.assemble_v2_verification_packet(
            prior_findings=self.valid_prior_findings,
            builder_claims={"RT-001": "Fixed line 42"},
            spec_sha256="abc123hash",
            prior_packet_sha256="def456hash"
        )
        self.assertIn("findings", packet)
        self.assertEqual(len(packet["findings"]), 2, "v2 packet MUST preserve all 2 prior findings")

    def test_empty_checklist_triggers_fatal_exit_7(self):
        """
        GOVERNANCE INVARIANT: If non-empty prior findings produce an empty verification checklist,
        build_packet MUST terminate immediately with sys.exit(7).
        """
        with self.assertRaises(SystemExit) as cm:
            build_packet.assemble_v2_verification_packet(
                prior_findings=self.valid_prior_findings,
                builder_claims={},
                spec_sha256="abc123hash",
                prior_packet_sha256="def456hash",
                _force_empty_checklist=True
            )
        self.assertEqual(cm.exception.code, 7, "Checklist truncation MUST raise SystemExit with code 7")

    def test_default_verdict_is_blocked(self):
        """
        GOVERNANCE INVARIANT: Default reviewer verdict in assembled verification packet MUST be BLOCKED.
        """
        packet = build_packet.assemble_v2_verification_packet(
            prior_findings=[],
            builder_claims={},
            spec_sha256="abc123hash",
            prior_packet_sha256="def456hash"
        )
        self.assertEqual(packet.get("reviewer_verdict"), "BLOCKED", "Default verdict MUST be BLOCKED")


if __name__ == "__main__":
    unittest.main()
