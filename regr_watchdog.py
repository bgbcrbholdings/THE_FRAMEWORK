#!/usr/bin/env python3
"""
The Sequence Control Engine — Automated Cross-Slice Regression Runner (regr_watchdog.py)
Executes unit test suites for past locked slices in isolated child Python processes.
Verifies test file integrity against .sequence/lock_manifest.json and enforces process timeouts.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
import ctypes
import hashlib
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime

def check_win32_reparse_point(path_obj):
    """Native Win32 atomic reparse-point check. Returns True if junction/symlink detected."""
    if os.name != 'nt':
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p
        ]

        handle = kernel32.CreateFileW(
            str(path_obj),
            0x80000000, # GENERIC_READ
            1 | 2 | 4,   # FILE_SHARE_READ | WRITE | DELETE
            None,
            3,          # OPEN_EXISTING
            0x00200000 | 0x02000000, # FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
            None
        )

        if not handle or handle == ctypes.c_void_p(-1).value or handle == 0xFFFFFFFF:
            return False

        class FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
            _fields_ = [("FileAttributes", ctypes.c_ulong), ("ReparseTag", ctypes.c_ulong)]

        info = FILE_ATTRIBUTE_TAG_INFO()
        kernel32.GetFileInformationByHandleEx.restype = ctypes.c_bool
        kernel32.GetFileInformationByHandleEx.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong
        ]

        res = kernel32.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info))
        kernel32.CloseHandle(handle)

        if res and (info.FileAttributes & 0x400):
            return True
        return False
    except Exception:
        return True # Fail-closed on error


class RegressionWatchdog:
    """Automated cross-slice regression runner executing unit tests in child process sandboxes."""

    def __init__(self, project_dir_str, timeout_seconds=30):
        self.raw_project_dir = project_dir_str
        self.project_dir = Path(project_dir_str).resolve()
        self.timeout_seconds = timeout_seconds

        # Verify sequence_engine integrity before importing
        self._verify_tcb_integrity()
        try:
            from sequence_engine import validate_and_open_path
            self.validate_and_open_path = validate_and_open_path
        except BaseException:
            def _default_open(p, r=None, mode='r'):
                return open(p, mode, encoding="utf-8" if "b" not in mode else None)
            self.validate_and_open_path = _default_open

        if check_win32_reparse_point(self.project_dir):
            raise PermissionError(f"REPARSE_POINT_DENIED: Root '{self.raw_project_dir}' is a junction point or symlink.")

    def _verify_tcb_integrity(self):
        """Verifies SHA-256 integrity of sequence_engine.py against .sequence/lock_manifest.json."""
        manifest_path = self.project_dir / ".sequence" / "lock_manifest.json"
        engine_path = self.project_dir / "sequence_engine.py"

        if not manifest_path.exists():
            if not engine_path.exists():
                raise FileNotFoundError("TCB script 'sequence_engine.py' is missing.")
            return

        try:
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected_hash = manifest_data.get("sequence_engine.py") or manifest_data.get("files", {}).get("sequence_engine.py")
            if expected_hash and engine_path.exists():
                live_hash = hashlib.sha256(engine_path.read_bytes()).hexdigest()
                if live_hash != expected_hash:
                    raise PermissionError(f"TCB_INTEGRITY_VIOLATION: sequence_engine.py hash '{live_hash}' != expected '{expected_hash}'")
        except Exception as e:
            if isinstance(e, PermissionError):
                raise
            raise PermissionError(f"TCB_INTEGRITY_CHECK_FAILED: {e}")

    def discover_test_files(self):
        """Dynamically discovers all unit test files in tests/ matching test_*.py."""
        tests_dir = self.project_dir / "tests"
        if not tests_dir.exists() or not tests_dir.is_dir():
            return []

        test_files = []
        for root, dirs, files in os.walk(tests_dir):
            root_path = Path(root)
            dirs[:] = [d for d in dirs if not d.startswith(".") and not check_win32_reparse_point(root_path / d)]
            for file_name in files:
                if file_name.startswith("test_") and file_name.endswith(".py"):
                    test_files.append(root_path / file_name)
        return sorted(test_files)

    def verify_test_file_manifest(self, test_file_path):
        """
        Verifies test file SHA-256 hash against .sequence/lock_manifest.json if locked.
        Returns (is_valid: bool, reason: str)
        """
        manifest_path = self.project_dir / ".sequence" / "lock_manifest.json"
        if not manifest_path.exists():
            return True, "No lock manifest present (pre-lock phase)."

        try:
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            rel_key = str(test_file_path.relative_to(self.project_dir)).replace("\\", "/")
            files_dict = manifest_data.get("files", {})

            expected_hash = files_dict.get(rel_key) or manifest_data.get(rel_key)
            if expected_hash:
                live_hash = hashlib.sha256(test_file_path.read_bytes()).hexdigest()
                if live_hash != expected_hash:
                    return False, f"MANIFEST_HASH_MISMATCH: '{rel_key}' hash '{live_hash}' != expected '{expected_hash}'"
                return True, "Hash verified against lock manifest."
            
            # If lock manifest is present but test file is for a new/unlocked slice, allow execution
            return True, "Test file present."
        except Exception as e:
            return False, f"MANIFEST_VERIFICATION_ERROR: {e}"

    def run_test_file_in_subprocess(self, test_file_path):
        """
        Executes a single test file in a separate child Python process with timeout isolation.
        Returns (passed: bool, error_msg: str)
        """
        original_cwd = os.getcwd()
        try:
            os.chdir(self.project_dir)
            rel_path = str(test_file_path.relative_to(self.project_dir)).replace("\\", "/")

            argv = [sys.executable, "-m", "unittest", rel_path]

            proc = subprocess.run(
                argv,
                shell=False,
                cwd=str(self.project_dir),
                timeout=self.timeout_seconds,
                capture_output=True,
                text=True
            )

            if proc.returncode == 0:
                return True, ""
            else:
                err_detail = proc.stderr.strip() or proc.stdout.strip()
                return False, f"FAIL ({rel_path}): exit code {proc.returncode}. Output: {err_detail[:300]}"

        except subprocess.TimeoutExpired:
            return False, f"TIMEOUT ({rel_path}): Test execution exceeded {self.timeout_seconds}s limit."
        except Exception as e:
            return False, f"EXECUTION_ERROR ({rel_path}): {e}"
        finally:
            os.chdir(original_cwd)

    def run_regression_suite(self, exclude_files=None):
        """Executes full regression suite across past locked slice test suites."""
        original_cwd = os.getcwd()
        original_sys_path = list(sys.path)
        exclude_files = exclude_files or []

        try:
            os.chdir(self.project_dir)
            test_files = self.discover_test_files()

            passed_count = 0
            failed_count = 0
            errored_count = 0
            failed_names = []

            for test_file in test_files:
                rel_name = str(test_file.relative_to(self.project_dir)).replace("\\", "/")

                # Exclude self-referential or explicitly excluded test files to prevent infinite recursion
                if rel_name in exclude_files or test_file.name in exclude_files:
                    continue

                # Integrity manifest check
                valid, msg = self.verify_test_file_manifest(test_file)
                if not valid:
                    errored_count += 1
                    failed_names.append(f"{rel_name} ({msg})")
                    continue

                # Run test in subprocess
                ok, err_msg = self.run_test_file_in_subprocess(test_file)
                if ok:
                    passed_count += 1
                else:
                    failed_count += 1
                    failed_names.append(rel_name)

            total_run = passed_count + failed_count + errored_count
            status = "PASS" if (failed_count == 0 and errored_count == 0 and total_run > 0) else ("PASS" if total_run == 0 else "FAIL")

            envelope = {
                "status": status,
                "total_tests_run": total_run,
                "passed": passed_count,
                "failed": failed_count,
                "errored": errored_count,
                "failed_test_names": failed_names,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }


            # Validate output envelope via schemas
            from schemas import validate_regr_watchdog_envelope
            valid, val_errors = validate_regr_watchdog_envelope(envelope)
            if not valid:
                raise ValueError(f"Envelope validation error: {val_errors}")

            return envelope
        finally:
            os.chdir(original_cwd)
            sys.path = original_sys_path


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else r"C:\Linkstream\00_DEV_TEAM_SEQUENCE"
    try:
        runner = RegressionWatchdog(target_dir)
        result = runner.run_regression_suite()
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["status"] == "PASS" else 1)
    except Exception as e:
        print(json.dumps({
            "status": "FAIL",
            "total_tests_run": 0,
            "passed": 0,
            "failed": 0,
            "errored": 1,
            "failed_test_names": [str(e)],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }, indent=2))
        sys.exit(1)
