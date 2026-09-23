"""
Contract Tests for control_script_guard.py (Ticket T2)
Governance-Critical: Tier 0 self-attestation and subprocess isolation contracts.

Written FIRST per Split-Ticket TDD Protocol.
ALL tests MUST be run against baseline code to demonstrate RED failure before implementation.

CRITICAL INVARIANTS TESTED:
  1. Hash breach in CONTROL_PLANE_MANIFEST.json triggers exit code 101
  2. Subprocess jail strips toxic env vars (tokens, proxies, pythonpath overrides)
  3. Valid sealed manifest passes self-attestation verification
"""

import unittest
import json
import sys
import os
import tempfile
import pathlib

import control_script_guard


class TestControlScriptGuardContracts(unittest.TestCase):

    def test_hash_breach_triggers_exit_101(self):
        """
        GOVERNANCE INVARIANT: Any hash drift between CONTROL_PLANE_MANIFEST.json
        and disk file MUST terminate process with exit code 101.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = pathlib.Path(tmpdir)
            script_file = tmppath / "fake_control_script.py"
            script_file.write_text("print('hello')", encoding="utf-8")

            manifest = {
                "manifest_name": "CONTROL_PLANE_MANIFEST",
                "version": "1.0.0",
                "scripts": {
                    "fake_control_script.py": {
                        "path": "fake_control_script.py",
                        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                        "tier": "Tier 0 (Constitutional Core)"
                    }
                }
            }
            manifest_file = tmppath / "CONTROL_PLANE_MANIFEST.json"
            manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            with self.assertRaises(SystemExit) as cm:
                control_script_guard.verify_control_plane_integrity(manifest_path=manifest_file, root_dir=tmppath)
            
            self.assertEqual(cm.exception.code, 101, "Hash breach MUST raise SystemExit with code 101")

    def test_subprocess_jail_sanitizes_environment(self):
        """
        GOVERNANCE INVARIANT: Subprocess jail MUST strip toxic environment variables
        (e.g., SECRET_TOKEN, HTTP_PROXY, PYTHONPATH) before launching worker scripts.
        """
        dirty_env = os.environ.copy()
        dirty_env["POISONED_TOKEN"] = "secret_bearer_123"
        dirty_env["HTTP_PROXY"] = "http://malicious-proxy:8080"
        dirty_env["PYTHONPATH"] = "/tmp/malicious_lib"

        clean_env = control_script_guard.build_jailed_environment(base_env=dirty_env)

        self.assertNotIn("POISONED_TOKEN", clean_env)
        self.assertNotIn("HTTP_PROXY", clean_env)
        self.assertNotIn("PYTHONPATH", clean_env)
        self.assertIn("PATH", clean_env, "Clean jail env MUST keep standard execution PATH")

    def test_valid_manifest_passes_integrity(self):
        """
        GOVERNANCE INVARIANT: Valid control scripts matching manifest hash MUST pass verification.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = pathlib.Path(tmpdir)
            script_file = tmppath / "test_script.py"
            content = "print('valid')"
            script_file.write_text(content, encoding="utf-8")
            
            import hashlib
            expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

            manifest = {
                "manifest_name": "CONTROL_PLANE_MANIFEST",
                "version": "1.0.0",
                "scripts": {
                    "test_script.py": {
                        "path": "test_script.py",
                        "sha256": expected_hash,
                        "tier": "Tier 0"
                    }
                }
            }
            manifest_file = tmppath / "CONTROL_PLANE_MANIFEST.json"
            manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            res = control_script_guard.verify_control_plane_integrity(manifest_path=manifest_file, root_dir=tmppath)
            self.assertTrue(res, "Valid manifest MUST return True")


if __name__ == "__main__":
    unittest.main()
