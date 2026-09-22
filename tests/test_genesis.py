#!/usr/bin/env python3
"""
test_genesis.py

Contract canary test suite for project_wizard.py.

Authored by Model A (Contract Author) as an independent, stateless test
engineer. This suite makes ZERO assumptions about implementation details
beyond the documented module interface. It exercises the REAL module
against a REAL filesystem tree -- no mocks, no stubs, no swallowed
exceptions, no dummy assertions.

Pure Python 3 standard library only.

Note on parent_path_arg: the interface spec's step 2 illustrates the
"approved root" equality gate using the literal default value
(C:\\Linkstream), but the REQUIRED TEST CASES explicitly instruct calling
create_project("test_app", parent_path_arg=temp_dir) and expecting
successful scaffolding -- consistent with every other module in this
system (sequence_server, lock_wall, watchdog, sequence_engine), each of
which accepts an explicit root/parent parameter specifically so it can be
exercised against an isolated sandbox rather than real, fixed machine
paths. This suite follows the REQUIRED TEST CASES literally.
"""

import sys
import tempfile
import unittest
from pathlib import Path

try:
    import project_wizard
except Exception as exc:  # noqa: BLE001 - intentional fail-closed behavior
    raise ImportError(
        "CONTRACT CANARY FAILURE: could not import project_wizard.py: "
        f"{exc!r}"
    ) from exc


REQUIRED_ATTRS = (
    "RESERVED_DEVICE_PATTERN",
    "generate_lock_manifest",
    "create_project",
)
_missing = [name for name in REQUIRED_ATTRS if not hasattr(project_wizard, name)]
if _missing:
    raise AttributeError(
        "CONTRACT CANARY FAILURE: project_wizard.py is missing required "
        f"interface members: {_missing}"
    )


class ProjectWizardSandboxTestCase(unittest.TestCase):
    """
    Builds a real, isolated parent directory for each test and tears it
    down afterward. parent_path_arg is always passed explicitly into
    create_project(), so no test ever touches a real machine-wide path.
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(prefix="project_wizard_canary_")
        self.parent_dir = Path(self._tmpdir.name).resolve()

    def tearDown(self):
        self._tmpdir.cleanup()


class TestCreateProjectScaffoldsValidDirectory(ProjectWizardSandboxTestCase):
    def test_create_project_scaffolds_valid_directory(self):
        project_wizard.create_project(
            "test_app", parent_path_arg=str(self.parent_dir)
        )

        project_dir = self.parent_dir / "test_app"
        self.assertTrue(
            project_dir.is_dir(),
            "create_project() did not create the project root directory",
        )

        required_subfolders = (
            "01_GOVERNANCE",
            "02_BACKLOG",
            "03_INCUBATOR",
            "04_REVIEWS",
            ".sequence",
            "tests",
            ".github",
            ".github/workflows",
        )
        for relative_folder in required_subfolders:
            with self.subTest(folder=relative_folder):
                self.assertTrue(
                    (project_dir / relative_folder).is_dir(),
                    f"Required subfolder {relative_folder!r} was not created",
                )

        required_governance_files = (
            "ALLOWLIST.txt",
            "README.md",
            "01_GOVERNANCE/BOOTSTRAP.md",
            "01_GOVERNANCE/FORBIDDEN.yml",
            "01_GOVERNANCE/PROBLEM.md",
            "01_GOVERNANCE/NON_GOALS.md",
            "01_GOVERNANCE/ARCHITECTURE.md",
            "01_GOVERNANCE/DECISIONS.md",
            "02_BACKLOG/AGILE_SLICES.md",
            ".github/CODEOWNERS",
            ".github/workflows/ci.yml",
        )
        for relative_file in required_governance_files:
            with self.subTest(file=relative_file):
                self.assertTrue(
                    (project_dir / relative_file).is_file(),
                    f"Required preseeded file {relative_file!r} was not created",
                )

        # Step 7: pre-seeded framework state.
        framework_state_files = (
            ".sequence/mrac_rules.json",
            ".sequence/state.db",
            ".sequence/session.json",
            ".sequence/lock_manifest.json",
            ".sequence/boot_digest.txt",
        )
        for relative_file in framework_state_files:
            with self.subTest(file=relative_file):
                self.assertTrue(
                    (project_dir / relative_file).is_file(),
                    f"Required framework state file {relative_file!r} was "
                    f"not created",
                )


class TestInvalidProjectNameRejection(ProjectWizardSandboxTestCase):
    def test_invalid_project_name_rejection(self):
        invalid_names = ("invalid/name", "app space", "")
        for bad_name in invalid_names:
            with self.subTest(name=bad_name):
                with self.assertRaises(ValueError):
                    project_wizard.create_project(
                        bad_name, parent_path_arg=str(self.parent_dir)
                    )

        # Negative control: a name built only from the allowed character
        # set must not be rejected by this check.
        project_wizard.create_project(
            "valid_name-123", parent_path_arg=str(self.parent_dir)
        )
        self.assertTrue((self.parent_dir / "valid_name-123").is_dir())


class TestReservedEngineNameRejection(ProjectWizardSandboxTestCase):
    def test_reserved_engine_name_rejection(self):
        with self.assertRaises(ValueError):
            project_wizard.create_project(
                "00_dev_team_sequence", parent_path_arg=str(self.parent_dir)
            )

        self.assertFalse(
            (self.parent_dir / "00_dev_team_sequence").exists(),
            "create_project() left behind a directory despite raising "
            "ValueError for the reserved engine name",
        )


class TestWindowsReservedDeviceRejection(ProjectWizardSandboxTestCase):
    def test_windows_reserved_device_rejection(self):
        reserved_names = (
            "CON",
            "NUL",
            "PRN",
            "AUX",
            "COM1",
            "LPT1",
            "CON.txt",
            "NUL.log",
        )
        for reserved_name in reserved_names:
            with self.subTest(name=reserved_name):
                self.assertRegex(
                    reserved_name,
                    project_wizard.RESERVED_DEVICE_PATTERN,
                    f"{reserved_name!r} does not match the documented "
                    f"RESERVED_DEVICE_PATTERN",
                )
                with self.assertRaises(ValueError):
                    project_wizard.create_project(
                        reserved_name, parent_path_arg=str(self.parent_dir)
                    )
                self.assertFalse(
                    (self.parent_dir / reserved_name).is_dir(),
                    f"create_project() left behind a directory for the "
                    f"reserved device name {reserved_name!r}",
                )

        # Negative control: names that merely CONTAIN a reserved token as
        # a substring, but are not themselves exactly reserved, must not
        # be rejected -- guards against non-anchored substring matching.
        safe_names = ("CONFIG", "MYCONTACT", "AUXILIARY")
        for safe_name in safe_names:
            with self.subTest(name=safe_name):
                self.assertNotRegex(
                    safe_name,
                    project_wizard.RESERVED_DEVICE_PATTERN,
                    f"{safe_name!r} unexpectedly matches "
                    f"RESERVED_DEVICE_PATTERN",
                )
                project_wizard.create_project(
                    safe_name, parent_path_arg=str(self.parent_dir)
                )
                self.assertTrue((self.parent_dir / safe_name).is_dir())


class TestExistingDirectoryWithoutForceRejection(ProjectWizardSandboxTestCase):
    def test_existing_directory_without_force_rejection(self):
        project_wizard.create_project(
            "test_app", parent_path_arg=str(self.parent_dir)
        )
        self.assertTrue((self.parent_dir / "test_app").is_dir())

        with self.assertRaises(ValueError) as ctx:
            project_wizard.create_project(
                "test_app", parent_path_arg=str(self.parent_dir)
            )

        self.assertIn(
            "TARGET_EXISTS",
            str(ctx.exception),
            f"Expected a TARGET_EXISTS ValueError, got: {ctx.exception!r}",
        )


class TestEngineProtectionRejection(ProjectWizardSandboxTestCase):
    def test_engine_protection_rejection(self):
        with self.assertRaises(ValueError):
            project_wizard.create_project(
                "00_dev_team_sequence",
                parent_path_arg=str(self.parent_dir),
                force=True,
            )

        self.assertFalse(
            (self.parent_dir / "00_dev_team_sequence").exists(),
            "create_project(force=True) created/modified the reserved "
            "engine directory despite raising ValueError",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
