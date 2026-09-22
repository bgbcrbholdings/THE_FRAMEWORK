#!/usr/bin/env python3
"""
test_watchdog.py

Contract canary test suite for watchdog.py.

Authored by Model A (Contract Author) as an independent, stateless test
engineer. This suite makes ZERO assumptions about implementation details
beyond the documented module interface. It exercises the REAL module
against real temporary .py files and real AST parsing -- no mocks, no
stubs, no swallowed exceptions, no dummy assertions.

Pure Python 3 standard library only.

Note on fixtures: SupplyChainWatchdog.__init__ is documented to verify
sequence_engine.py's TCB integrity against .sequence/lock_manifest.json
-- the exact artifact produced by lock_wall.py's own already-specified,
already contract-tested public API (LockWallEngine.seal_lock_manifest()).
Rather than fabricate or assume watchdog.py's internal manifest format,
this suite uses lock_wall.py itself (a real, documented sibling TCB
module) purely as a fixture-sealing utility, so the watchdog's own
documented integrity check has real, valid state to verify against.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import watchdog
except Exception as exc:  # noqa: BLE001 - intentional fail-closed behavior
    raise ImportError(
        "CONTRACT CANARY FAILURE: could not import watchdog.py: "
        f"{exc!r}"
    ) from exc

try:
    import lock_wall
except Exception as exc:  # noqa: BLE001 - intentional fail-closed behavior
    raise ImportError(
        "CONTRACT CANARY FAILURE: could not import lock_wall.py, which "
        "this suite requires to seal a valid .sequence/lock_manifest.json "
        f"fixture for SupplyChainWatchdog's documented TCB check: {exc!r}"
    ) from exc


REQUIRED_ATTRS = (
    "STDLIB_FALLBACK",
    "KNOWN_TCB_MODULES",
    "SupplyChainWatchdog",
)
_missing = [name for name in REQUIRED_ATTRS if not hasattr(watchdog, name)]
if _missing:
    raise AttributeError(
        "CONTRACT CANARY FAILURE: watchdog.py is missing required "
        f"interface members: {_missing}"
    )

_REQUIRED_METHODS = (
    "load_mrac_rules",
    "is_first_party_module",
    "is_module_allowed",
    "scan_file",
    "scan_project",
)
_missing_methods = [
    name
    for name in _REQUIRED_METHODS
    if not hasattr(watchdog.SupplyChainWatchdog, name)
]
if _missing_methods:
    raise AttributeError(
        "CONTRACT CANARY FAILURE: SupplyChainWatchdog is missing "
        f"required methods: {_missing_methods}"
    )

_missing_lock_wall_attrs = [
    name
    for name in ("TCB_ENGINE_SCRIPTS", "LockWallEngine")
    if not hasattr(lock_wall, name)
]
if _missing_lock_wall_attrs:
    raise AttributeError(
        "CONTRACT CANARY FAILURE: lock_wall.py is missing members "
        f"required to seal test fixtures: {_missing_lock_wall_attrs}"
    )


class WatchdogSandboxTestCase(unittest.TestCase):
    """
    Builds a real, isolated TCB project tree -- all 11 TCB_ENGINE_SCRIPTS,
    .sequence/mrac_rules.json, and a real sealed .sequence/lock_manifest.json
    + boot_digest.txt -- then instantiates a real SupplyChainWatchdog bound
    to it via its documented project_dir_str constructor parameter.
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(prefix="watchdog_canary_")
        self.project_dir = Path(self._tmpdir.name).resolve()

        for script_name in lock_wall.TCB_ENGINE_SCRIPTS:
            script_path = self.project_dir / script_name
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text(
                f"# TCB script fixture: {script_name}\nVALUE = 1\n",
                encoding="utf-8",
            )

        # schemas.py must plausibly define GenesisProjectSpec, matching
        # the documented `from schemas import GenesisProjectSpec` case.
        (self.project_dir / "schemas.py").write_text(
            "class GenesisProjectSpec:\n    pass\n",
            encoding="utf-8",
        )

        sequence_dir = self.project_dir / ".sequence"
        sequence_dir.mkdir(parents=True, exist_ok=True)
        (sequence_dir / "mrac_rules.json").write_text(
            json.dumps({"forbidden_imports": []}), encoding="utf-8"
        )

        sealing_engine = lock_wall.LockWallEngine(project_dir=str(self.project_dir))
        sealing_engine.seal_lock_manifest()

        self.watchdog = watchdog.SupplyChainWatchdog(str(self.project_dir))

    def tearDown(self):
        self._tmpdir.cleanup()

    def _write_mrac_rules(self, forbidden_imports):
        mrac_path = self.project_dir / ".sequence" / "mrac_rules.json"
        mrac_path.write_text(
            json.dumps({"forbidden_imports": forbidden_imports}),
            encoding="utf-8",
        )

    def _write_scannable_file(self, relative_name, source_code):
        file_path = self.project_dir / relative_name
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(source_code, encoding="utf-8")
        return file_path


class TestStdlibImportAllowed(WatchdogSandboxTestCase):
    def test_stdlib_import_allowed(self):
        # "import os", "import sys", "from pathlib import Path"
        for module_name in ("os", "sys", "pathlib"):
            with self.subTest(module=module_name):
                self.assertIn(
                    module_name,
                    watchdog.STDLIB_FALLBACK,
                    f"{module_name!r} is missing from STDLIB_FALLBACK",
                )

                allowed, reason = self.watchdog.is_module_allowed(module_name, [])
                self.assertTrue(
                    allowed,
                    f"is_module_allowed({module_name!r}, []) returned "
                    f"(False, {reason!r}); expected a standard library "
                    f"module to be allowed",
                )


class TestFirstPartyImportAllowed(WatchdogSandboxTestCase):
    def test_first_party_import_allowed(self):
        # "import sequence_server", "from schemas import GenesisProjectSpec"
        for module_name in ("sequence_server", "schemas"):
            with self.subTest(module=module_name):
                self.assertTrue(
                    self.watchdog.is_first_party_module(module_name),
                    f"is_first_party_module({module_name!r}) returned "
                    f"False for a real .py file present in project_dir",
                )

                allowed, reason = self.watchdog.is_module_allowed(module_name, [])
                self.assertTrue(
                    allowed,
                    f"is_module_allowed({module_name!r}, []) returned "
                    f"(False, {reason!r}); expected a first-party TCB "
                    f"module to be allowed",
                )


class TestExternalPipPackageFlagged(WatchdogSandboxTestCase):
    def test_external_pip_package_flagged(self):
        # "import requests", "import pandas", "from bs4 import BeautifulSoup"
        for module_name in ("requests", "pandas", "bs4"):
            with self.subTest(module=module_name):
                allowed, reason = self.watchdog.is_module_allowed(module_name, [])
                self.assertFalse(
                    allowed,
                    f"is_module_allowed({module_name!r}, []) returned "
                    f"(True, ...); expected an unrecognized external pip "
                    f"package to be rejected",
                )
                self.assertIsInstance(reason, str)
                self.assertIn(
                    "External pip package",
                    reason,
                    f"Rejection reason for {module_name!r} did not read "
                    f"as an external-pip-package rejection: {reason!r}",
                )
                self.assertIn(module_name, reason)
                self.assertIn("not allowed", reason)


class TestStaticImportFlagged(WatchdogSandboxTestCase):
    def test_ast_import_of_external_package_is_flagged(self):
        forbidden_imports, load_errors = self.watchdog.load_mrac_rules()
        self.assertEqual(load_errors, [])
        forbidden_imports = forbidden_imports or []

        target_file = self._write_scannable_file(
            "static_external_import_sample.py",
            "import requests\n",
        )

        violations = self.watchdog.scan_file(target_file, forbidden_imports)

        self.assertIsInstance(violations, list)
        matching = [
            violation
            for violation in violations
            if "requests" in str(violation.get("name", ""))
        ]
        self.assertTrue(
            matching,
            "scan_file() did not flag the ast.Import node for "
            f"'import requests'; got: {violations!r}",
        )

        for violation in matching:
            self.assertIn("file", violation)
            self.assertIn("line", violation)
            self.assertIn("name", violation)
            self.assertIn("kind", violation)

        self.assertTrue(
            any(violation.get("line") == 1 for violation in matching),
            "No requests violation was attributed to the import on line 1: "
            f"{matching!r}",
        )

    def test_ast_importfrom_of_external_package_is_flagged(self):
        forbidden_imports, load_errors = self.watchdog.load_mrac_rules()
        self.assertEqual(load_errors, [])
        forbidden_imports = forbidden_imports or []

        target_file = self._write_scannable_file(
            "static_external_importfrom_sample.py",
            "from bs4 import BeautifulSoup\n",
        )

        violations = self.watchdog.scan_file(target_file, forbidden_imports)

        self.assertIsInstance(violations, list)
        matching = [
            violation
            for violation in violations
            if "bs4" in str(violation.get("name", ""))
        ]
        self.assertTrue(
            matching,
            "scan_file() did not flag the ast.ImportFrom node for "
            f"'from bs4 import BeautifulSoup'; got: {violations!r}",
        )

    def test_package_name_in_plain_string_is_not_an_import(self):
        forbidden_imports, load_errors = self.watchdog.load_mrac_rules()
        self.assertEqual(load_errors, [])
        forbidden_imports = forbidden_imports or []

        target_file = self._write_scannable_file(
            "external_package_string_sample.py",
            'package_name = "requests"\n',
        )

        violations = self.watchdog.scan_file(target_file, forbidden_imports)

        self.assertEqual(
            violations,
            [],
            "scan_file() treated an external-package name in a plain "
            f"string as an import: {violations!r}",
        )


class TestMracForbiddenImportFlagged(WatchdogSandboxTestCase):
    def test_mrac_forbidden_import_flagged(self):
        self._write_mrac_rules(["os.system"])

        forbidden_imports, load_errors = self.watchdog.load_mrac_rules()
        self.assertEqual(load_errors, [])
        self.assertIsNotNone(forbidden_imports)
        self.assertIn("os.system", forbidden_imports)

        target_file = self._write_scannable_file(
            "mrac_violation_sample.py",
            "import os\n\n\ndef run():\n    os.system(\"dir\")\n",
        )

        violations = self.watchdog.scan_file(target_file, forbidden_imports)

        self.assertIsInstance(violations, list)
        self.assertTrue(
            len(violations) > 0,
            "scan_file() reported no violations for an MRAC-forbidden "
            "os.system(...) call",
        )

        matching = [
            v for v in violations if "os.system" in str(v.get("name", ""))
        ]
        self.assertTrue(
            len(matching) > 0,
            f"No violation entry referenced the MRAC-forbidden name "
            f"'os.system'; got: {violations!r}",
        )

        violation = matching[0]
        self.assertIn("file", violation)
        self.assertIn("line", violation)
        self.assertIn("name", violation)
        self.assertIn("kind", violation)
        self.assertEqual(violation.get("kind"), "IMPORT")
        self.assertEqual(violation.get("line"), 5)


class TestTryGuardedImportIgnored(WatchdogSandboxTestCase):
    def test_try_guarded_import_ignored(self):
        forbidden_imports, load_errors = self.watchdog.load_mrac_rules()
        self.assertEqual(load_errors, [])
        forbidden_imports = forbidden_imports or []

        target_file = self._write_scannable_file(
            "try_guarded_sample.py",
            "try:\n"
            "    import optional_package\n"
            "except ImportError:\n"
            "    pass\n",
        )

        violations = self.watchdog.scan_file(target_file, forbidden_imports)

        self.assertEqual(
            violations,
            [],
            f"scan_file() flagged a try-guarded import as a violation: "
            f"{violations!r}",
        )


class TestDynamicImportFlagged(WatchdogSandboxTestCase):
    def test_dynamic_import_flagged(self):
        forbidden_imports, load_errors = self.watchdog.load_mrac_rules()
        self.assertEqual(load_errors, [])
        forbidden_imports = forbidden_imports or []

        dunder_import_file = self._write_scannable_file(
            "dynamic_dunder_import_sample.py",
            "mod = __import__(\"requests\")\n",
        )
        violations_a = self.watchdog.scan_file(dunder_import_file, forbidden_imports)
        self.assertTrue(
            len(violations_a) > 0,
            "scan_file() did not flag a __import__('requests') dynamic import",
        )
        matching_a = [
            v for v in violations_a if "requests" in str(v.get("name", ""))
        ]
        self.assertTrue(
            len(matching_a) > 0,
            f"No violation referenced 'requests' for the __import__(...) "
            f"call: {violations_a!r}",
        )

        importlib_file = self._write_scannable_file(
            "dynamic_importlib_sample.py",
            "import importlib\n\nmod = importlib.import_module(\"flask\")\n",
        )
        violations_b = self.watchdog.scan_file(importlib_file, forbidden_imports)
        matching_b = [
            v for v in violations_b if "flask" in str(v.get("name", ""))
        ]
        self.assertTrue(
            len(matching_b) > 0,
            f"No violation referenced 'flask' for the "
            f"importlib.import_module(...) call: {violations_b!r}",
        )

        for violation in matching_a + matching_b:
            self.assertIn("file", violation)
            self.assertIn("line", violation)
            self.assertIn("name", violation)
            self.assertIn("kind", violation)

    def test_external_name_in_ordinary_call_is_not_dynamic_import(self):
        forbidden_imports, load_errors = self.watchdog.load_mrac_rules()
        self.assertEqual(load_errors, [])
        forbidden_imports = forbidden_imports or []

        target_file = self._write_scannable_file(
            "ordinary_call_sample.py",
            "def lookup(name):\n"
            "    return name\n"
            "\n"
            'result = lookup("requests")\n',
        )

        violations = self.watchdog.scan_file(target_file, forbidden_imports)

        self.assertEqual(
            violations,
            [],
            "scan_file() treated an ordinary function call containing an "
            f"external-package name as a dynamic import: {violations!r}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
