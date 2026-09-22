#!/usr/bin/env python3
"""
test_sequence_engine.py

Contract canary test suite for sequence_engine.py.

Authored by Model A (Contract Author) as an independent, stateless test
engineer. This suite makes ZERO assumptions about implementation details
beyond the documented module interface. It exercises the REAL module
against a REAL filesystem tree -- no mocks, no stubs, no swallowed
exceptions, no dummy assertions.

Pure Python 3 standard library only.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import sequence_engine
except Exception as exc:  # noqa: BLE001 - intentional fail-closed behavior
    raise ImportError(
        "CONTRACT CANARY FAILURE: could not import sequence_engine.py: "
        f"{exc!r}"
    ) from exc


REQUIRED_ATTRS = (
    "APPROVED_ROOT_DIR",
    "check_win32_reparse_point",
    "validate_and_open_path",
    "apply_restrictive_dacl",
    "verify_restrictive_dacl",
    "generate_and_save_session",
    "get_or_create_active_session",
)
_missing = [name for name in REQUIRED_ATTRS if not hasattr(sequence_engine, name)]
if _missing:
    raise AttributeError(
        "CONTRACT CANARY FAILURE: sequence_engine.py is missing required "
        f"interface members: {_missing}"
    )


class SequenceEngineSandboxTestCase(unittest.TestCase):
    """
    Builds a real, isolated root directory for each test and tears it
    down afterward. root_dir is passed explicitly into every documented
    function under test (validate_and_open_path's root_dir_str,
    generate_and_save_session's root_dir), so no test ever touches the
    real APPROVED_ROOT_DIR.
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(prefix="sequence_engine_canary_")
        self.root_dir = Path(self._tmpdir.name).resolve()

    def tearDown(self):
        self._tmpdir.cleanup()


class TestValidateAndOpenPathValidFile(SequenceEngineSandboxTestCase):
    def test_validate_and_open_path_opens_valid_file(self):
        target_file = self.root_dir / "hello.txt"
        expected_content = "canary payload 12345\n"
        target_file.write_text(expected_content, encoding="utf-8")

        handle = sequence_engine.validate_and_open_path(
            "hello.txt", root_dir_str=str(self.root_dir)
        )
        try:
            content = handle.read()
        finally:
            handle.close()

        self.assertEqual(
            content,
            expected_content,
            "validate_and_open_path() did not return the real content of "
            "a valid, contained file",
        )


class TestPathTraversalRejection(SequenceEngineSandboxTestCase):
    def test_path_traversal_rejection(self):
        traversal_inputs = (
            "../foo.py",
            "C:/Linkstream/00_dev_team_sequence/../secret.txt",
            "subdir/../../escape.txt",
        )
        for bad_path in traversal_inputs:
            with self.subTest(path=bad_path):
                with self.assertRaises(PermissionError):
                    sequence_engine.validate_and_open_path(
                        bad_path, root_dir_str=str(self.root_dir)
                    )

        # Negative control: a legitimate nested path with no ".."
        # component must NOT be rejected -- guards against an overly
        # broad implementation that blocks every path containing a
        # separator rather than specifically ".." traversal markers.
        nested_dir = self.root_dir / "subdir"
        nested_dir.mkdir(parents=True, exist_ok=True)
        nested_file = nested_dir / "legit.txt"
        nested_file.write_text("nested canary payload\n", encoding="utf-8")

        handle = sequence_engine.validate_and_open_path(
            "subdir/legit.txt", root_dir_str=str(self.root_dir)
        )
        try:
            self.assertEqual(handle.read(), "nested canary payload\n")
        finally:
            handle.close()


class TestAdsRejection(SequenceEngineSandboxTestCase):
    def test_ads_rejection(self):
        ads_inputs = ("file.txt:stream", "config.json:hidden_stream")
        for bad_path in ads_inputs:
            with self.subTest(path=bad_path):
                with self.assertRaises(PermissionError):
                    sequence_engine.validate_and_open_path(
                        bad_path, root_dir_str=str(self.root_dir)
                    )

        # Negative control: an ordinary filename with no colon must
        # still be openable -- guards against a check that rejects
        # every path rather than specifically ones containing ":".
        clean_file = self.root_dir / "clean_no_colon.txt"
        clean_file.write_text("no ads here\n", encoding="utf-8")
        handle = sequence_engine.validate_and_open_path(
            "clean_no_colon.txt", root_dir_str=str(self.root_dir)
        )
        try:
            self.assertEqual(handle.read(), "no ads here\n")
        finally:
            handle.close()


class TestReparsePointRejection(SequenceEngineSandboxTestCase):
    def test_reparse_point_rejection(self):
        # Deliberately placed INSIDE root_dir so containment (step 4)
        # still succeeds -- this isolates the rejection to the reparse
        # point check (step 5) specifically, rather than a coincidental
        # containment failure.
        decoy_target = self.root_dir / "_decoy_target.txt"
        decoy_target.write_text(
            "decoy content, not the intended target\n", encoding="utf-8"
        )

        symlinked_name = "linked.txt"
        symlink_path = self.root_dir / symlinked_name

        try:
            os.symlink(str(decoy_target), str(symlink_path))
        except (OSError, NotImplementedError) as exc:
            self.skipTest(
                "Symlink creation is not permitted/supported on this "
                f"platform: {exc!r}"
            )

        self.assertTrue(
            symlink_path.is_symlink(),
            "Test setup failure: target path is not actually a symlink",
        )

        with self.assertRaises(PermissionError):
            sequence_engine.validate_and_open_path(
                symlinked_name, root_dir_str=str(self.root_dir)
            )


class TestGenerateAndSaveSessionCreatesValidJson(SequenceEngineSandboxTestCase):
    def test_generate_and_save_session_creates_valid_json(self):
        result = sequence_engine.generate_and_save_session(root_dir=self.root_dir)

        self.assertIsInstance(result, dict)
        self.assertIn("sequence_token", result)
        self.assertIn("csrf_nonce", result)

        session_path = self.root_dir / ".sequence" / "session.json"
        tmp_path = self.root_dir / ".sequence" / "session.tmp"

        self.assertTrue(
            session_path.is_file(),
            "generate_and_save_session() did not create .sequence/session.json",
        )
        self.assertFalse(
            tmp_path.exists(),
            ".sequence/session.tmp was left behind; atomic rename to "
            "session.json did not complete",
        )

        on_disk = json.loads(session_path.read_text(encoding="utf-8"))
        self.assertIsInstance(on_disk, dict)
        self.assertIn("sequence_token", on_disk)
        self.assertIn("csrf_nonce", on_disk)

        sequence_token = on_disk["sequence_token"]
        csrf_nonce = on_disk["csrf_nonce"]

        # secrets.token_urlsafe(32) is deterministic in output length:
        # 32 random bytes base64url-encoded without padding is always
        # exactly 43 characters.
        self.assertIsInstance(sequence_token, str)
        self.assertEqual(
            len(sequence_token),
            43,
            "sequence_token length does not match secrets.token_urlsafe(32)'s "
            f"deterministic 43-character output; got: {sequence_token!r}",
        )

        # secrets.token_hex(16) is deterministic in output: exactly 32
        # lowercase hex characters (16 bytes).
        self.assertIsInstance(csrf_nonce, str)
        self.assertRegex(
            csrf_nonce,
            r"^[0-9a-f]{32}$",
            "csrf_nonce does not match secrets.token_hex(16)'s deterministic "
            f"32-lowercase-hex-character output; got: {csrf_nonce!r}",
        )

        self.assertEqual(result["sequence_token"], sequence_token)
        self.assertEqual(result["csrf_nonce"], csrf_nonce)

        # Entropy negative control: a second, independent session must
        # not reuse the same token/nonce -- guards against a dummy
        # implementation that returns static or non-random values.
        second_tmpdir = tempfile.TemporaryDirectory(
            prefix="sequence_engine_canary_second_"
        )
        try:
            second_root = Path(second_tmpdir.name).resolve()
            second_result = sequence_engine.generate_and_save_session(
                root_dir=second_root
            )
            self.assertNotEqual(
                result["sequence_token"],
                second_result["sequence_token"],
                "sequence_token was identical across two independent "
                "session generations -- token is not high-entropy/random",
            )
            self.assertNotEqual(
                result["csrf_nonce"],
                second_result["csrf_nonce"],
                "csrf_nonce was identical across two independent session "
                "generations -- nonce is not high-entropy/random",
            )
        finally:
            second_tmpdir.cleanup()


class TestDaclRestriction(SequenceEngineSandboxTestCase):
    def test_dacl_restriction(self):
        # Positive case: a real session.json produced via the documented
        # generate_and_save_session() -> apply_restrictive_dacl() path.
        sequence_engine.generate_and_save_session(root_dir=self.root_dir)
        session_path = self.root_dir / ".sequence" / "session.json"
        self.assertTrue(session_path.is_file())

        secure_mode = os.stat(str(session_path)).st_mode & 0o777
        if os.name != "nt":
            self.assertEqual(
                secure_mode & 0o077,
                0,
                "session.json permissions do not match chmod-600-equivalent "
                f"semantics after apply_restrictive_dacl(): {oct(secure_mode)}",
            )

        self.assertTrue(
            sequence_engine.verify_restrictive_dacl(session_path),
            "verify_restrictive_dacl() returned False for a session.json "
            "that had apply_restrictive_dacl() applied to it",
        )

        # Negative case: a plain file made permissive to everyone.
        insecure_file = self.root_dir / "insecure_world_readable.txt"
        insecure_file.write_text("not protected\n", encoding="utf-8")

        try:
            os.chmod(str(insecure_file), 0o666)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(
                "os.chmod with explicit permission bits is not supported "
                f"on this platform: {exc!r}"
            )

        actual_mode = os.stat(str(insecure_file)).st_mode & 0o777
        if actual_mode & 0o077 == 0:
            self.skipTest(
                "Platform did not honor world/group-permissive chmod bits "
                "-- no POSIX-style DACL semantics available to test against"
            )

        self.assertFalse(
            sequence_engine.verify_restrictive_dacl(insecure_file),
            "verify_restrictive_dacl() returned True for a file with "
            f"world-writable/readable permissions: {oct(actual_mode)}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
