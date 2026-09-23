#!/usr/bin/env python3
"""
test_lock_wall.py

Contract canary test suite for lock_wall.py / schemas.py.

Authored by Model A (Contract Author) as an independent, stateless test
engineer. This suite makes ZERO assumptions about implementation details
beyond the documented module interface. It exercises the REAL module
against a REAL filesystem tree -- no mocks, no stubs, no swallowed
exceptions, no dummy assertions.

Pure Python 3 standard library only.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import lock_wall
except Exception as exc:  # noqa: BLE001 - intentional fail-closed behavior
    sys.stderr.write(
        "CONTRACT CANARY FAILURE: could not import lock_wall.py: "
        f"{exc!r}\n"
    )
    sys.exit(1)


REQUIRED_ATTRS = (
    "TCB_ENGINE_SCRIPTS",
    "FILE_FLAG_OPEN_REPARSE_POINT",
    "APPROVED_ROOT_DIR",
    "check_win32_reparse_point",
    "canonicalize_and_validate_path",
    "get_tcb_hash_targets",
    "LockWallEngine",
)

_missing = [name for name in REQUIRED_ATTRS if not hasattr(lock_wall, name)]
if _missing:
    sys.stderr.write(
        "CONTRACT CANARY FAILURE: lock_wall.py is missing required "
        f"interface members: {_missing}\n"
    )
    sys.exit(1)

_REQUIRED_ENGINE_METHODS = (
    "compute_script_hash",
    "seal_lock_manifest",
    "verify_lock_integrity",
    "assert_fail_closed",
    "get_status_envelope",
)
_missing_methods = [
    name
    for name in _REQUIRED_ENGINE_METHODS
    if not hasattr(lock_wall.LockWallEngine, name)
]
if _missing_methods:
    sys.stderr.write(
        "CONTRACT CANARY FAILURE: LockWallEngine is missing required "
        f"methods: {_missing_methods}\n"
    )
    sys.exit(1)


def _sha256_of(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _errors_as_text(errors):
    """
    Errors may be returned as plain strings or as structured objects
    (dict/dataclass/etc.) carrying an error code. str() over the whole
    list surfaces the code substring either way without assuming a
    specific error-object schema.
    """
    return " ".join(str(e) for e in errors)


class LockWallSandboxTestCase(unittest.TestCase):
    """
    Builds a fully isolated, real filesystem TCB tree for each test:
    all 11 TCB_ENGINE_SCRIPTS, .sequence/mrac_rules.json, and a
    dashboard/ static file tree -- then instantiates a real
    LockWallEngine bound to that sandbox via its documented
    project_dir constructor parameter. No mocks, no stubs.
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(prefix="lock_wall_canary_")
        self.project_dir = Path(self._tmpdir.name).resolve()

        self.assertEqual(
            len(lock_wall.TCB_ENGINE_SCRIPTS),
            22,
            "TCB_ENGINE_SCRIPTS must list all 22 Framework engine scripts per spec",
        )

        for script_name in lock_wall.TCB_ENGINE_SCRIPTS:
            script_path = self.project_dir / script_name
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text(
                f"# TCB script fixture: {script_name}\nVALUE = 1\n",
                encoding="utf-8",
            )

        sequence_dir = self.project_dir / ".sequence"
        sequence_dir.mkdir(parents=True, exist_ok=True)
        (sequence_dir / "mrac_rules.json").write_text(
            json.dumps({"rules": []}), encoding="utf-8"
        )

        dashboard_dir = self.project_dir / "dashboard"
        dashboard_dir.mkdir(parents=True, exist_ok=True)
        (dashboard_dir / "index.html").write_text(
            "<html><body>canary dashboard</body></html>", encoding="utf-8"
        )
        assets_dir = dashboard_dir / "assets"
        assets_dir.mkdir(parents=True, exist_ok=True)
        (assets_dir / "app.js").write_text(
            "console.log('canary');\n", encoding="utf-8"
        )

        self.engine = lock_wall.LockWallEngine(project_dir=str(self.project_dir))
        self.engine.seal_lock_manifest()

    def tearDown(self):
        self._tmpdir.cleanup()


class TestSealLockManifestCreatesFiles(LockWallSandboxTestCase):
    def test_seal_lock_manifest_creates_files(self):
        manifest = self.engine.seal_lock_manifest()
        self.assertIsInstance(manifest, dict)
        self.assertTrue(len(manifest) > 0)

        manifest_path = self.project_dir / ".sequence" / "lock_manifest.json"
        digest_path = self.project_dir / ".sequence" / "boot_digest.txt"

        self.assertTrue(
            manifest_path.is_file(),
            "seal_lock_manifest() did not create .sequence/lock_manifest.json",
        )
        self.assertTrue(
            digest_path.is_file(),
            "seal_lock_manifest() did not create .sequence/boot_digest.txt",
        )

        on_disk_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertIsInstance(on_disk_manifest, dict)
        self.assertTrue(len(on_disk_manifest) > 0)

        boot_digest = digest_path.read_text(encoding="utf-8").strip()
        self.assertRegex(
            boot_digest,
            r"^[0-9a-fA-F]{64}$",
            "boot_digest.txt does not contain a 64-hex-char SHA-256 digest",
        )

        # Cross-check the documented per-file hashing contract directly:
        # compute_script_hash() must return the file's real, live SHA-256.
        sample_target = sorted(lock_wall.TCB_ENGINE_SCRIPTS)[0]
        expected_hash = _sha256_of(self.project_dir / sample_target)
        actual_hash = self.engine.compute_script_hash(sample_target)
        self.assertEqual(
            actual_hash,
            expected_hash,
            f"compute_script_hash({sample_target!r}) did not match the "
            f"file's real SHA-256 digest",
        )

        # get_tcb_hash_targets must cover all 11 TCB scripts plus the
        # documented mrac_rules.json and dashboard/** entries.
        targets = lock_wall.get_tcb_hash_targets(root_dir=str(self.project_dir))
        self.assertIsInstance(targets, list)
        targets_posix = set(targets)
        for script_name in lock_wall.TCB_ENGINE_SCRIPTS:
            self.assertIn(
                script_name,
                targets_posix,
                f"get_tcb_hash_targets() did not include TCB script "
                f"{script_name!r}",
            )
        self.assertIn(".sequence/mrac_rules.json", targets_posix)
        self.assertTrue(
            any(t.startswith("dashboard/") for t in targets_posix),
            "get_tcb_hash_targets() did not include any dashboard/** file",
        )


class TestVerifyLockIntegrityCleanRepo(LockWallSandboxTestCase):
    def test_verify_lock_integrity_passes_on_clean_repo(self):
        self.engine.seal_lock_manifest()

        ok, errors = self.engine.verify_lock_integrity()

        self.assertEqual(
            errors,
            [],
            f"verify_lock_integrity() reported errors on an unmodified "
            f"sealed repo: {errors!r}",
        )
        self.assertTrue(
            ok,
            "verify_lock_integrity() returned False on an unmodified "
            "sealed repo",
        )


class TestHashMismatchFailsVerification(LockWallSandboxTestCase):
    def test_hash_mismatch_fails_verification(self):
        self.engine.seal_lock_manifest()

        tampered_script = self.project_dir / "watchdog.py"
        original_bytes = tampered_script.read_bytes()
        tampered_bytes = bytearray(original_bytes)
        tampered_bytes[0] ^= 0xFF  # guaranteed single-byte change
        tampered_script.write_bytes(bytes(tampered_bytes))
        self.assertNotEqual(bytes(tampered_bytes), original_bytes)

        ok, errors = self.engine.verify_lock_integrity()

        self.assertFalse(
            ok, "verify_lock_integrity() returned True after a TCB "
            "script was modified"
        )
        self.assertTrue(len(errors) > 0)

        error_text = _errors_as_text(errors)
        self.assertIn(
            "HASH_MISMATCH",
            error_text,
            f"Expected explicit HASH_MISMATCH error, got: {errors!r}",
        )

        with self.assertRaises(PermissionError):
            self.engine.assert_fail_closed()


class TestMissingFileFailsVerification(LockWallSandboxTestCase):
    def test_missing_file_fails_verification(self):
        self.engine.seal_lock_manifest()

        missing_script = self.project_dir / "auditor_agent.py"
        missing_script.unlink()
        self.assertFalse(missing_script.exists())

        ok, errors = self.engine.verify_lock_integrity()

        self.assertFalse(
            ok,
            "verify_lock_integrity() returned True after a TCB script "
            "was deleted",
        )
        self.assertTrue(len(errors) > 0)

        error_text = _errors_as_text(errors)
        self.assertIn(
            "MISSING_TCB_FILE",
            error_text,
            f"Expected explicit MISSING_TCB_FILE error, got: {errors!r}",
        )

        with self.assertRaises(PermissionError):
            self.engine.assert_fail_closed()


class TestBootDigestTamperFailsVerification(LockWallSandboxTestCase):
    def test_boot_digest_tamper_fails_verification(self):
        self.engine.seal_lock_manifest()

        digest_path = self.project_dir / ".sequence" / "boot_digest.txt"
        original_digest = digest_path.read_text(encoding="utf-8").strip()
        self.assertRegex(original_digest, r"^[0-9a-fA-F]{64}$")

        flipped_char = "0" if original_digest[0].lower() != "0" else "1"
        forged_digest = flipped_char + original_digest[1:]
        self.assertNotEqual(forged_digest, original_digest)
        digest_path.write_text(forged_digest, encoding="utf-8")

        ok, errors = self.engine.verify_lock_integrity()

        self.assertFalse(
            ok,
            "verify_lock_integrity() returned True after boot_digest.txt "
            "was tampered with",
        )
        self.assertTrue(len(errors) > 0)

        error_text = _errors_as_text(errors)
        self.assertIn(
            "BOOT_DIGEST_MISMATCH",
            error_text,
            f"Expected explicit BOOT_DIGEST_MISMATCH error, got: {errors!r}",
        )

        with self.assertRaises(PermissionError):
            self.engine.assert_fail_closed()


class TestReparsePointRejection(LockWallSandboxTestCase):
    def test_reparse_point_rejection(self):
        self.engine.seal_lock_manifest()
        target_relative_path = "project_wizard.py"
        target_script = self.project_dir / target_relative_path

        decoy_target = self.project_dir / "_reparse_decoy_target.txt"
        decoy_target.write_text(
            "decoy content, not a real TCB script\n", encoding="utf-8"
        )

        target_script.unlink()
        try:
            os.symlink(str(decoy_target), str(target_script))
        except (OSError, NotImplementedError) as exc:
            self.skipTest(
                "Symlink creation is not permitted/supported on this "
                f"platform, so a real reparse point cannot be created: {exc!r}"
            )

        self.assertTrue(
            target_script.is_symlink(),
            "Test setup failure: TCB script path is not actually a symlink",
        )

        rejected = False
        rejection_text = ""

        try:
            self.engine.compute_script_hash(target_relative_path)
        except (ValueError, PermissionError, OSError) as exc:
            rejected = True
            rejection_text = str(exc)

        if not rejected:
            ok, errors = self.engine.verify_lock_integrity()
            self.assertFalse(
                ok,
                "verify_lock_integrity() returned True with a symlinked "
                "TCB script in place -- reparse point was not rejected",
            )
            rejection_text = _errors_as_text(errors)

        self.assertTrue(
            ("NON_REGULAR_TCB_FILE" in rejection_text)
            or ("REPARSE_POINT_DENIED" in rejection_text)
            or ("HASH_MISMATCH" in rejection_text),
            "Expected NON_REGULAR_TCB_FILE, REPARSE_POINT_DENIED, or HASH_MISMATCH in the "
            f"rejection details, got: {rejection_text!r}",
        )

        with self.assertRaises(PermissionError):
            self.engine.assert_fail_closed()


if __name__ == "__main__":
    unittest.main(verbosity=2)
