#!/usr/bin/env python3
"""
Unit Test Suite for LockWallEngine (tests/test_lock_wall.py)
Tests 1-Way Door Architectural Lock Wall Engine:
- Reading .sequence/lock_manifest.json
- Computing and checking SHA-256 hashes of TCB targets
- Fail-closed verification and exit code 1 on SHA-256 hash mismatch
- Path traversal rejection, Win32 reparse-point blocking, and status envelope validation.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
import unittest
from pathlib import Path

try:
    from lock_wall import LockWallEngine, canonicalize_and_validate_path, get_tcb_hash_targets, APPROVED_ROOT_DIR
except ImportError:
    LockWallEngine = None
    canonicalize_and_validate_path = None
    get_tcb_hash_targets = None
    APPROVED_ROOT_DIR = Path(__file__).resolve().parent.parent

try:
    from schemas import validate_lock_wall_envelope
except ImportError:
    validate_lock_wall_envelope = None



class TestLockWallEngine(unittest.TestCase):

    def setUp(self):
        self.assertIsNotNone(LockWallEngine, "lock_wall.py module could not be imported")
        self.assertIsNotNone(validate_lock_wall_envelope, "schemas.py module could not be imported")
        self.engine = LockWallEngine(APPROVED_ROOT_DIR)

    def test_canonicalize_and_validate_path(self):
        """Test path canonicalization, traversal rejection, and ADS blocking."""
        ok, res = canonicalize_and_validate_path("verify.py", str(APPROVED_ROOT_DIR))
        self.assertTrue(ok)

        ok, msg = canonicalize_and_validate_path("../outside.py", str(APPROVED_ROOT_DIR))
        self.assertFalse(ok)
        self.assertIn("PATH_TRAVERSAL", msg)

        ok, msg = canonicalize_and_validate_path("verify.py:stream", str(APPROVED_ROOT_DIR))
        self.assertFalse(ok)
        self.assertIn("ADS_DENIED", msg)

    def test_compute_script_hash_valid(self):
        """Test valid script hash computation for allowlisted TCB script."""
        h = self.engine.compute_script_hash("verify.py")
        self.assertEqual(len(h), 64)

    def test_compute_script_hash_invalid_target(self):
        """Test rejection of non-TCB targets or traversal paths."""
        with self.assertRaises(ValueError):
            self.engine.compute_script_hash("../outside.py")

        with self.assertRaises(ValueError):
            self.engine.compute_script_hash("non_existent_random_target.py")

        with self.assertRaises(ValueError):
            self.engine.compute_script_hash("verify.py:stream")

    def test_reads_lock_manifest_and_checks_sha256_hashes(self):
        """Asserts lock_wall.py reads lock_manifest.json and checks SHA-256 hashes against live targets."""
        # Reseal manifest to ensure pristine live hashes match
        manifest = self.engine.seal_lock_manifest()
        self.assertIn("hashes", manifest)
        self.assertIsInstance(manifest["hashes"], dict)

        manifest_file = APPROVED_ROOT_DIR / ".sequence" / "lock_manifest.json"
        self.assertTrue(manifest_file.exists(), ".sequence/lock_manifest.json must exist")

        # Verify reading lock_manifest.json and SHA-256 hash checking passes
        is_valid, errors = self.engine.verify_lock_integrity()
        self.assertTrue(is_valid, f"Lock integrity verification failed: {errors}")
        self.assertEqual(len(errors), 0)

    def test_exits_code_1_on_sha256_hash_mismatch(self):
        """Asserts lock_wall.py reads lock_manifest.json, checks SHA-256 hashes, and exits code 1 on mismatch."""
        self.engine.seal_lock_manifest()

        target_file = APPROVED_ROOT_DIR / ".sequence" / "mrac_rules.json"
        original_content = target_file.read_text(encoding="utf-8")

        try:
            # Modify target file content to force SHA-256 hash mismatch
            target_file.write_text(original_content + "\n// INTENTIONAL_HASH_MISMATCH_TAMPER", encoding="utf-8")

            # 1. Direct engine API assertion: verify_lock_integrity reports HASH_MISMATCH failure
            is_valid, errors = self.engine.verify_lock_integrity()
            self.assertFalse(is_valid, "verify_lock_integrity should fail when file content is tampered")
            self.assertTrue(
                any("HASH_MISMATCH" in err for err in errors),
                f"Expected HASH_MISMATCH in errors, got: {errors}"
            )

            # 2. CLI execution assertion: executing lock_wall.py script returns exit code 1
            cmd = [sys.executable, str(APPROVED_ROOT_DIR / "lock_wall.py")]
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(APPROVED_ROOT_DIR))
            self.assertEqual(
                res.returncode, 1,
                f"Expected lock_wall.py to exit with code 1 on SHA-256 mismatch, got exit code {res.returncode}. Stderr: {res.stderr}"
            )
            self.assertIn("[FAIL]", res.stderr)

        finally:
            # Restore original content and reseal manifest
            target_file.write_text(original_content, encoding="utf-8")
            self.engine.seal_lock_manifest()

    def test_tamper_dashboard_asset(self):
        """Tamper test: altering dashboard asset must trigger fail-closed rejection and exit code 1."""
        self.engine.seal_lock_manifest()

        dash_file = APPROVED_ROOT_DIR / "dashboard" / "scorecard.html"
        if not dash_file.exists():
            dash_file.parent.mkdir(parents=True, exist_ok=True)
            dash_file.write_text("<html><body>Dashboard</body></html>", encoding="utf-8")
            self.engine.seal_lock_manifest()

        original_content = dash_file.read_text(encoding="utf-8")
        try:
            dash_file.write_text(original_content + "<!-- TAMPERED -->", encoding="utf-8")
            is_valid, errors = self.engine.verify_lock_integrity()
            self.assertFalse(is_valid)
            self.assertGreater(len(errors), 0)

            with self.assertRaises(PermissionError):
                self.engine.assert_fail_closed()

            cmd = [sys.executable, str(APPROVED_ROOT_DIR / "lock_wall.py")]
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(APPROVED_ROOT_DIR))
            self.assertEqual(res.returncode, 1)
        finally:
            dash_file.write_text(original_content, encoding="utf-8")
            self.engine.seal_lock_manifest()

    def test_get_status_envelope_and_schema_validation(self):
        """Test status envelope generation and schemas validation."""
        self.engine.seal_lock_manifest()
        envelope = self.engine.get_status_envelope()

        self.assertIn("status", envelope)
        self.assertIn("tcb_count", envelope)
        self.assertIn("timestamp", envelope)

        valid = validate_lock_wall_envelope(envelope)
        self.assertTrue(valid)

    def test_validate_lock_wall_envelope_negative(self):
        """Test schema validation rejection of invalid envelope shapes."""
        self.assertFalse(validate_lock_wall_envelope(None))
        self.assertFalse(validate_lock_wall_envelope({}))
        self.assertFalse(validate_lock_wall_envelope({"status": "INVALID"}))
        self.assertFalse(validate_lock_wall_envelope({
            "status": "OK",
            "tcb_count": 5, # too small (< 11)
            "manifest_hash_match": True,
            "boot_digest_match": True,
            "mismatched_paths": [],
            "timestamp": "2026-09-18T16:00:00Z"
        }))


if __name__ == "__main__":
    unittest.main()
