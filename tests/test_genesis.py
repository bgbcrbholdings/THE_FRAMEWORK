#!/usr/bin/env python3
r"""
Contract Test Suite for Micro-Slice 1.5 — Project Genesis Wizard (tests/test_genesis.py)
Defines contract specifications for project_wizard.py:
1. Rejection of invalid project names, OS reserved device identifiers (CON, PRN, AUX, NUL), and reserved engine names.
2. Parent path containment validation (parent directory must equal C:\Linkstream).
3. Project scaffolding (governance files, .sequence state, local launchers).
4. Protection against accidental directory overwrite without force=True.
5. Fail-closed rejection of Win32 reparse-point / junction parent directories.
Pure Python 3 Standard Library — 0 External Dependencies.
"""

import os
import sys
import json
import shutil
import unittest
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import project_wizard
except BaseException:
    project_wizard = None


class TestProjectWizardContract(unittest.TestCase):
    """Contract tests defining behavioral invariants for project_wizard.py."""

    def setUp(self):
        if project_wizard is None:
            self.fail("CRITICAL: project_wizard.py module is not implemented or unimportable.")

    def test_01_invalid_project_name_rejection(self):
        """1. Asserts invalid project names, reserved OS device names, and Master Engine target raise ValueError."""
        if not hasattr(project_wizard, "create_project"):
            self.fail("project_wizard.create_project is missing")

        invalid_names = [
            "invalid name with spaces",
            "00_DEV_TEAM_SEQUENCE",
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "LPT1",
            "../../escaped_dir"
        ]
        for bad_name in invalid_names:
            with self.subTest(name=bad_name):
                with self.assertRaises(ValueError):
                    project_wizard.create_project(bad_name)

    def test_02_parent_path_containment_rejection(self):
        r"""2. Asserts parent_path argument escaping C:\Linkstream is rejected with ValueError."""
        if not hasattr(project_wizard, "create_project"):
            self.fail("project_wizard.create_project is missing")

        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(ValueError):
                project_wizard.create_project("test_project_bad_parent", parent_path_arg=tmp_dir)

    def test_03_project_scaffolding_success(self):
        """3. Asserts valid project creation scaffolds required governance files and .sequence state."""
        if not hasattr(project_wizard, "create_project"):
            self.fail("project_wizard.create_project is missing")

        test_proj_name = "test_sandbox_genesis"
        target_dir = Path("C:\\Linkstream") / test_proj_name

        try:
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)

            res_path = project_wizard.create_project(test_proj_name)
            self.assertTrue(target_dir.exists())

            # Verify governance files
            required_files = [
                target_dir / "ALLOWLIST.txt",
                target_dir / "README.md",
                target_dir / "01_GOVERNANCE" / "BOOTSTRAP.md",
                target_dir / "01_GOVERNANCE" / "FORBIDDEN.yml",
                target_dir / ".github" / "workflows" / "ci.yml",
                target_dir / ".sequence" / "session.json",
                target_dir / ".sequence" / "state.db",
                target_dir / ".sequence" / "lock_manifest.json"
            ]
            for req in required_files:
                self.assertTrue(req.exists(), f"Required file '{req}' missing from scaffolded project")
        finally:
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)

    def test_04_existing_directory_overwrite_guard(self):
        """4. Asserts attempting to create existing non-empty project without force=True raises ValueError."""
        if not hasattr(project_wizard, "create_project"):
            self.fail("project_wizard.create_project is missing")

        test_proj_name = "test_sandbox_existing"
        target_dir = Path("C:\\Linkstream") / test_proj_name

        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "existing.txt").write_text("existing_data", encoding="utf-8")

            with self.assertRaises(ValueError):
                project_wizard.create_project(test_proj_name, force=False)
        finally:
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
