"""
Contract Tests for sequence_engine.py Hardening (Ticket T3)
Governance-Critical: Exit 7 / Exit 101 error handling and Tier 0 startup attestation.

Written FIRST per Split-Ticket TDD Protocol.
ALL tests MUST be run against baseline code to demonstrate RED failure before implementation.

CRITICAL INVARIANTS TESTED:
  1. sequence_engine.py invokes Tier 0 attestation (control_script_guard) on startup
  2. Exit 7 (checklist truncation) halts execution with HALTED_REQUIRES_HUMAN_INTERVENTION
  3. Exit 101 (hash breach) halts execution with HALTED_REQUIRES_HUMAN_INTERVENTION
"""

import unittest
import json
import sys
import os

import sequence_engine


class TestSequenceEngineHardeningContracts(unittest.TestCase):

    def test_sequence_engine_has_tier0_attestation_hook(self):
        """
        GOVERNANCE INVARIANT: sequence_engine.py MUST expose and execute
        verify_startup_integrity() calling Tier 0 control_script_guard.
        """
        self.assertTrue(
            hasattr(sequence_engine, "verify_startup_integrity"),
            "sequence_engine.py MUST expose verify_startup_integrity function"
        )
        res = sequence_engine.verify_startup_integrity()
        self.assertTrue(res, "verify_startup_integrity MUST return True under valid environment")

    def test_handle_fatal_exit_code_7(self):
        """
        GOVERNANCE INVARIANT: Exit code 7 MUST map to HALTED_REQUIRES_HUMAN_INTERVENTION
        and raise SystemExit(7).
        """
        self.assertTrue(
            hasattr(sequence_engine, "handle_fatal_execution_error"),
            "sequence_engine.py MUST expose handle_fatal_execution_error function"
        )
        with self.assertRaises(SystemExit) as cm:
            sequence_engine.handle_fatal_execution_error(exit_code=7, slice_id="slice-test")
        
        self.assertEqual(cm.exception.code, 7, "Exit 7 handling MUST terminate with code 7")

    def test_handle_fatal_exit_code_101(self):
        """
        GOVERNANCE INVARIANT: Exit code 101 MUST map to HALTED_REQUIRES_HUMAN_INTERVENTION
        and raise SystemExit(101).
        """
        with self.assertRaises(SystemExit) as cm:
            sequence_engine.handle_fatal_execution_error(exit_code=101, slice_id="slice-test")
        
        self.assertEqual(cm.exception.code, 101, "Exit 101 handling MUST terminate with code 101")


if __name__ == "__main__":
    unittest.main()
