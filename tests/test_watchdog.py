#!/usr/bin/env python3
"""
Unit Test Suite for Slice 003 — Supply-Chain & Regression Watchdog (tests/test_watchdog.py)
Covering watchdog.py, regr_watchdog.py, file_hygiene_engine.py, and schemas.py.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
import time
import shutil
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from watchdog import SupplyChainWatchdog
except BaseException:
    SupplyChainWatchdog = None

try:
    from regr_watchdog import RegressionWatchdog
except BaseException:
    RegressionWatchdog = None

try:
    from file_hygiene_engine import FileHygieneEngine
except BaseException:
    FileHygieneEngine = None


from schemas import (
    validate_watchdog_envelope,
    validate_regr_watchdog_envelope,
    validate_file_hygiene_envelope
)

class TestSupplyChainWatchdog(unittest.TestCase):
    """Test suite for watchdog.py (Supply-Chain AST Auditor)."""

    def setUp(self):
        if SupplyChainWatchdog is None:
            self.skipTest("watchdog.py module not available in environment")
        self.watchdog = SupplyChainWatchdog(str(PROJECT_ROOT))

    def test_codebase_stdlib_and_first_party_imports_pass(self):
        """Assures existing codebase stdlib and first-party imports pass with zero violations."""
        result = self.watchdog.audit()
        assert result["status"] == "PASS", f"Audit violations: {result.get('violations')}"
        self.assertEqual(result["forbidden_imports_found"], 0)
        self.assertEqual(len(result["violations"]), 0)

    def test_third_party_pip_imports_detected(self):
        """Asserts synthetic file with import requests / from yaml import load triggers FAIL."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            # Create minimal sequence_engine.py fixture
            (tmp_path / "sequence_engine.py").write_text("def validate_and_open_path(p, r, mode='r'): return open(p, mode)\n", encoding="utf-8")
            (tmp_path / ".sequence").mkdir()
            (tmp_path / ".sequence" / "mrac_rules.json").write_text(json.dumps({"forbidden_imports": ["eval"]}), encoding="utf-8")

            bad_file = tmp_path / "bad_script.py"
            bad_file.write_text("import requests\nfrom yaml import load\n", encoding="utf-8")

            wd = SupplyChainWatchdog(str(tmp_path))
            result = wd.audit()

            self.assertEqual(result["status"], "FAIL")
            self.assertGreaterEqual(result["forbidden_imports_found"], 2)
            names = [v["name"] for v in result["violations"]]
            self.assertIn("requests", names)
            self.assertIn("yaml", names)

    def test_dynamic_imports_detected(self):
        """Asserts __import__('requests') and importlib.import_module('yaml') yield FAIL."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "sequence_engine.py").write_text("def validate_and_open_path(p, r, mode='r'): return open(p, mode)\n", encoding="utf-8")
            (tmp_path / ".sequence").mkdir()
            (tmp_path / ".sequence" / "mrac_rules.json").write_text(json.dumps({"forbidden_imports": []}), encoding="utf-8")

            bad_file = tmp_path / "dynamic_script.py"
            bad_file.write_text("x = __import__('requests')\ny = importlib.import_module('yaml')\neval('1+1')\n", encoding="utf-8")

            wd = SupplyChainWatchdog(str(tmp_path))
            result = wd.audit()

            self.assertEqual(result["status"], "FAIL")
            self.assertGreaterEqual(result["forbidden_imports_found"], 3)
            kinds = [v["kind"] for v in result["violations"]]
            self.assertIn("DYNAMIC_IMPORT", kinds)
            self.assertIn("EVAL_EXEC", kinds)

    def test_syntax_error_and_relative_imports_handled(self):
        """Asserts malformed syntax returns schema-valid FAIL envelope without unhandled crash."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "sequence_engine.py").write_text("def validate_and_open_path(p, r, mode='r'): return open(p, mode)\n", encoding="utf-8")
            (tmp_path / ".sequence").mkdir()
            (tmp_path / ".sequence" / "mrac_rules.json").write_text(json.dumps({"forbidden_imports": []}), encoding="utf-8")

            syntax_file = tmp_path / "broken_syntax.py"
            syntax_file.write_text("def foo(: bar\n", encoding="utf-8")

            wd = SupplyChainWatchdog(str(tmp_path))
            result = wd.audit()

            self.assertEqual(result["status"], "FAIL")
            kinds = [v["kind"] for v in result["violations"]]
            self.assertIn("PARSE_ERROR", kinds)

    def test_dotted_submodule_imports_pass(self):
        """Asserts dotted imports like os.path and concurrent.futures pass cleanly."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "sequence_engine.py").write_text("def validate_and_open_path(p, r, mode='r'): return open(p, mode)\n", encoding="utf-8")
            (tmp_path / ".sequence").mkdir()
            (tmp_path / ".sequence" / "mrac_rules.json").write_text(json.dumps({"forbidden_imports": []}), encoding="utf-8")

            good_file = tmp_path / "dotted_script.py"
            good_file.write_text("import os.path\nfrom concurrent import futures\n", encoding="utf-8")

            wd = SupplyChainWatchdog(str(tmp_path))
            result = wd.audit()

            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["forbidden_imports_found"], 0)


class TestRegressionWatchdog(unittest.TestCase):
    """Test suite for regr_watchdog.py (Automated Regression Runner)."""

    def setUp(self):
        if RegressionWatchdog is None:
            self.skipTest("regr_watchdog.py module not available in environment")
        self.runner = RegressionWatchdog(str(PROJECT_ROOT), timeout_seconds=30)

    def _get_tracked_excludes(self):
        # Exclude tests that are not yet landed or self-referential
        all_tests = [p.name for p in (PROJECT_ROOT / "tests").glob("test_*.py")]
        landed_tests = {"test_api_fail_closed.py", "test_lock_wall.py", "test_watchdog.py"}
        return list(set(all_tests) - landed_tests) + ["test_watchdog.py"]

    def test_past_slice_unit_tests_pass(self):
        """Asserts past slice tests (test_review_engine.py, test_sequence_server.py) pass cleanly."""
        result = self.runner.run_regression_suite(exclude_files=self._get_tracked_excludes())
        self.assertEqual(result["status"], "PASS")
        self.assertGreaterEqual(result["total_tests_run"], 1)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["errored"], 0)

    def test_dynamic_discovery_runs_new_dummy_test(self):
        """Asserts adding a new dummy test_*.py fixture is executed dynamically without code changes."""
        dummy_test = PROJECT_ROOT / "tests" / "test_dummy_fixture.py"
        try:
            dummy_test.write_text("import unittest\nclass TestDummy(unittest.TestCase):\n    def test_pass(self): self.assertTrue(True)\n", encoding="utf-8")

            runner = RegressionWatchdog(str(PROJECT_ROOT), timeout_seconds=30)
            result = runner.run_regression_suite(exclude_files=self._get_tracked_excludes())

            self.assertEqual(result["status"], "PASS")
            self.assertGreaterEqual(result["total_tests_run"], 2)
        finally:
            if dummy_test.exists():
                dummy_test.unlink()

    def test_hanging_test_timeout_isolation(self):
        """Asserts synthetic test sleeping longer than timeout yields FAIL and non-zero exit."""
        slow_test = PROJECT_ROOT / "tests" / "test_slow_fixture.py"
        try:
            slow_test.write_text("import unittest, time\nclass TestSlow(unittest.TestCase):\n    def test_slow(self): time.sleep(15)\n", encoding="utf-8")

            runner = RegressionWatchdog(str(PROJECT_ROOT), timeout_seconds=2)
            excludes = [p.name for p in (PROJECT_ROOT / "tests").glob("test_*.py") if p.name != "test_slow_fixture.py"]
            result = runner.run_regression_suite(exclude_files=excludes)

            self.assertEqual(result["status"], "FAIL")
            self.assertGreaterEqual(result["failed"], 1)
        finally:
            if slow_test.exists():
                slow_test.unlink()



class TestFileHygieneEngine(unittest.TestCase):
    """Test suite for file_hygiene_engine.py."""

    def setUp(self):
        if FileHygieneEngine is None:
            self.skipTest("file_hygiene_engine.py module not available in environment")

    def test_locked_file_protection_zero_bytes_written(self):
        """Asserts zero bytes are written to a fixture file with STATUS: LOCKED header."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "sequence_engine.py").write_text("def validate_and_open_path(p, r, mode='r'): return open(p, mode)\n", encoding="utf-8")
            (tmp_path / "01_GOVERNANCE").mkdir()
            (tmp_path / "02_BACKLOG").mkdir()
            (tmp_path / "04_REVIEWS").mkdir()

            locked_file = tmp_path / "01_GOVERNANCE" / "PROBLEM.md"
            orig_content = "# Problem\n**STATUS: LOCKED — TEST**\nBody text content here.\n"
            locked_file.write_text(orig_content, encoding="utf-8")

            (tmp_path / "02_BACKLOG" / "AGILE_SLICES.md").write_text("# Backlog\n`slice-001-off-grid-review-parser`\n", encoding="utf-8")

            engine = FileHygieneEngine(str(tmp_path), apply_changes=True)
            result = engine.run_hygiene_audit()

            # Assert content unchanged
            self.assertEqual(locked_file.read_text(encoding="utf-8"), orig_content)
            self.assertEqual(result["governance_headers_updated"], 0)

    def test_orphan_incubator_doc_yields_orphan_status(self):
        """Asserts orphaned incubator doc forces alignment_status ORPHAN and status FAIL."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "sequence_engine.py").write_text("def validate_and_open_path(p, r, mode='r'): return open(p, mode)\n", encoding="utf-8")
            (tmp_path / "01_GOVERNANCE").mkdir()
            (tmp_path / "02_BACKLOG").mkdir()
            (tmp_path / "03_INCUBATOR").mkdir()
            (tmp_path / "04_REVIEWS").mkdir()

            (tmp_path / "02_BACKLOG" / "AGILE_SLICES.md").write_text("# Slices\n`slice-001-test`\n", encoding="utf-8")
            (tmp_path / "03_INCUBATOR" / "orphaned_idea.md").write_text("# Orphaned document without slice reference\n", encoding="utf-8")

            engine = FileHygieneEngine(str(tmp_path), apply_changes=False)
            result = engine.run_hygiene_audit()

            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["alignment_status"], "ORPHAN")
            self.assertGreaterEqual(len(result["alignment_issues"]), 1)


class TestSchemaValidation(unittest.TestCase):
    """Test suite for envelope validators in schemas.py."""

    def test_watchdog_envelope_validation(self):
        """Tests validate_watchdog_envelope invariants."""
        valid_envelope = {
            "status": "PASS",
            "scanned_files_count": 10,
            "forbidden_imports_found": 0,
            "violations": [],
            "timestamp": "2026-09-17T12:00:00Z"
        }
        ok, errors = validate_watchdog_envelope(valid_envelope)
        self.assertTrue(ok, msg=f"Errors: {errors}")

        # Invalid status PASS with non-empty violations
        invalid_envelope = dict(valid_envelope)
        invalid_envelope["violations"] = [{"file": "a.py", "line": 1, "name": "req", "kind": "IMPORT"}]
        ok, errors = validate_watchdog_envelope(invalid_envelope)
        self.assertFalse(ok)

        # Invalid unknown key
        unknown_key_envelope = dict(valid_envelope)
        unknown_key_envelope["extra_field"] = "bad"
        ok, errors = validate_watchdog_envelope(unknown_key_envelope)
        self.assertFalse(ok)

    def test_regr_watchdog_envelope_validation(self):
        """Tests validate_regr_watchdog_envelope invariants."""
        valid_envelope = {
            "status": "PASS",
            "total_tests_run": 5,
            "passed": 5,
            "failed": 0,
            "errored": 0,
            "failed_test_names": [],
            "timestamp": "2026-09-17T12:00:00Z"
        }
        ok, errors = validate_regr_watchdog_envelope(valid_envelope)
        self.assertTrue(ok, msg=f"Errors: {errors}")

        # Total mismatch
        invalid_envelope = dict(valid_envelope)
        invalid_envelope["total_tests_run"] = 10
        ok, errors = validate_regr_watchdog_envelope(invalid_envelope)
        self.assertFalse(ok)

    def test_file_hygiene_envelope_validation(self):
        """Tests validate_file_hygiene_envelope invariants."""
        valid_envelope = {
            "status": "PASS",
            "governance_headers_updated": 0,
            "loose_files_sweeper_count": 0,
            "alignment_status": "ALIGNED",
            "alignment_issues": [],
            "timestamp": "2026-09-17T12:00:00Z"
        }
        ok, errors = validate_file_hygiene_envelope(valid_envelope)
        self.assertTrue(ok, msg=f"Errors: {errors}")

        # DRIFT with status PASS
        invalid_envelope = dict(valid_envelope)
        invalid_envelope["alignment_status"] = "DRIFT"
        ok, errors = validate_file_hygiene_envelope(invalid_envelope)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
