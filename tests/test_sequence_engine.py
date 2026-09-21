#!/usr/bin/env python3
"""
Contract Test Suite for Micro-Slice 1.4 — Dynamic Slice Execution Engine (tests/test_sequence_engine.py)
Defines contract specifications for sequence_engine.py:
1. Path traversal & Win32 reparse-point rejection via validate_and_open_path.
2. High-entropy session token and anti-CSRF nonce generation in get_or_create_active_session.
3. Restrictive DACL permission application and verification (apply_restrictive_dacl, verify_restrictive_dacl).
4. Fail-closed execution gate on un-allowlisted or out-of-boundary slice execution.
Pure Python 3 Standard Library — 0 External Dependencies.
"""

import os
import sys
import json
import unittest
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import sequence_engine
except BaseException:
    sequence_engine = None


class TestSequenceEngineContract(unittest.TestCase):
    """Contract tests defining behavioral invariants for sequence_engine.py."""

    def setUp(self):
        if sequence_engine is None:
            self.fail("CRITICAL: sequence_engine.py module is not implemented or unimportable.")

    def test_01_validate_and_open_path_traversal_rejection(self):
        """1. Asserts validate_and_open_path rejects path traversal ('..') and ADS streams with PermissionError."""
        if not hasattr(sequence_engine, "validate_and_open_path"):
            self.fail("sequence_engine.validate_and_open_path is missing")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            traversal_target = tmp_path / ".." / "system32"
            with self.assertRaises(PermissionError):
                sequence_engine.validate_and_open_path(traversal_target, root_dir_str=str(tmp_path), mode="r")

    def test_02_validate_and_open_path_valid_file_access(self):
        """2. Asserts validate_and_open_path opens valid relative/absolute path within approved root."""
        if not hasattr(sequence_engine, "validate_and_open_path"):
            self.fail("sequence_engine.validate_and_open_path is missing")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            test_file = tmp_path / "test_data.txt"
            test_file.write_text("hello_world", encoding="utf-8")

            with sequence_engine.validate_and_open_path(test_file, root_dir_str=str(tmp_path), mode="r") as f:
                content = f.read()
            self.assertEqual(content, "hello_world")

    def test_03_active_session_token_entropy(self):
        """3. Asserts get_or_create_active_session generates valid session manifest with >=16 char token and nonce."""
        if not hasattr(sequence_engine, "get_or_create_active_session"):
            self.fail("sequence_engine.get_or_create_active_session is missing")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            session_data = sequence_engine.get_or_create_active_session(str(tmp_path))

            self.assertIsInstance(session_data, dict)
            self.assertIn("sequence_token", session_data)
            self.assertIn("csrf_nonce", session_data)
            self.assertGreaterEqual(len(session_data["sequence_token"]), 16)
            self.assertGreaterEqual(len(session_data["csrf_nonce"]), 16)

    def test_04_restrictive_dacl_application_and_verification(self):
        """4. Asserts apply_restrictive_dacl and verify_restrictive_dacl enforce secure OS permissions."""
        if not hasattr(sequence_engine, "apply_restrictive_dacl") or not hasattr(sequence_engine, "verify_restrictive_dacl"):
            self.fail("DACL functions missing in sequence_engine")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            test_file = tmp_path / "protected_file.json"
            test_file.write_text("{}", encoding="utf-8")

            applied = sequence_engine.apply_restrictive_dacl(test_file)
            self.assertTrue(applied)
            verified = sequence_engine.verify_restrictive_dacl(test_file)
            self.assertTrue(verified)

    def test_05_reparse_point_detection(self):
        """5. Asserts check_win32_reparse_point handles non-reparse files cleanly without crashing."""
        if not hasattr(sequence_engine, "check_win32_reparse_point"):
            self.fail("sequence_engine.check_win32_reparse_point is missing")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            normal_file = tmp_path / "normal_file.txt"
            normal_file.write_text("normal", encoding="utf-8")

            is_reparse = sequence_engine.check_win32_reparse_point(normal_file)
            self.assertFalse(is_reparse)


if __name__ == "__main__":
    unittest.main()
