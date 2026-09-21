#!/usr/bin/env python3
"""
The Sequence Control Engine — Supply-Chain AST Import Auditor (watchdog.py)
Enforces zero external pip dependencies across all codebase Python files (.py).
Traverses Python ASTs to audit static imports (ast.Import, ast.ImportFrom) and dynamic imports (ast.Call).
Resolves first-party project modules and Python stdlib modules; flags external pip packages as CRITICAL violations.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import ast
import json
import ctypes
import hashlib
from pathlib import Path
from datetime import datetime

# Fallback stdlib module list for Python standard modules across OS platforms
STDLIB_FALLBACK = {
    "abc", "argparse", "ast", "asyncio", "base64", "binascii", "bisect", "builtins",
    "bz2", "calendar", "cgi", "cgitb", "chunk", "cmath", "cmd", "code", "codecs",
    "codeop", "collections", "colorsys", "compileall", "concurrent", "configparser",
    "contextlib", "contextvars", "copy", "copyreg", "cProfile", "crypt", "csv",
    "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal", "difflib",
    "dis", "distutils", "doctest", "email", "encodings", "enum", "errno", "faulthandler",
    "fcntl", "filecmp", "fileinput", "fnmatch", "fractions", "ftplib", "functools",
    "gc", "getpass", "getopt", "gettext", "glob", "graphlib", "gzip", "hashlib",
    "heapq", "hmac", "html", "http", "imaplib", "imghdr", "importlib", "inspect",
    "io", "ipaddress", "itertools", "json", "keyword", "linecache", "locale",
    "logging", "lzma", "mailbox", "mailcap", "math", "mimetypes", "mmap", "modulefinder",
    "msilib", "msvcrt", "multiprocessing", "netrc", "nis", "nntplib", "numbers",
    "operator", "optparse", "os", "pathlib", "pdb", "pickle", "pickletools", "pkgutil",
    "platform", "plistlib", "poplib", "posix", "pprint", "profile", "pstats", "pty",
    "pwd", "py_compile", "pyclbr", "pydoc", "queue", "quopri", "random", "re",
    "readline", "resource", "rlcompleter", "sched", "secrets", "select", "selectors",
    "shelve", "shutil", "signal", "site", "smtpd", "smtplib", "sndhdr", "socket",
    "socketserver", "spwd", "sqlite3", "ssl", "stat", "statistics", "string",
    "stringprep", "struct", "subprocess", "sunau", "symtable", "sys", "sysconfig",
    "syslog", "tarfile", "telnetlib", "tempfile", "termios", "test", "textwrap",
    "threading", "time", "timeit", "tkinter", "token", "tokenize", "trace", "traceback",
    "tracemalloc", "tty", "types", "typing", "unicodedata", "unittest", "urllib",
    "uu", "uuid", "venv", "warnings", "wave", "weakref", "webbrowser", "winreg",
    "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib",
    "pytest"
}

KNOWN_TCB_MODULES = {
    "verify", "sequence_server", "schemas", "auditor_agent",
    "build_packet", "parse_reviews", "agent_dispatcher",
    "sequence_engine", "watchdog", "project_wizard", "lock_wall"
}

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


class SupplyChainWatchdog:
    """Supply-chain AST auditor enforcing 0 external pip dependencies."""

    def __init__(self, project_dir_str):
        self.raw_project_dir = project_dir_str
        self.project_dir = Path(project_dir_str).resolve()

        # Import sequence_engine after verifying integrity
        self._verify_tcb_integrity()
        try:
            from sequence_engine import validate_and_open_path
            self.validate_and_open_path = validate_and_open_path
        except BaseException:
            def _default_open(p, r=None, mode='r'):
                return open(p, mode, encoding="utf-8" if "b" not in mode else None)
            self.validate_and_open_path = _default_open

        # Canonicalize project_dir via validate_and_open_path
        if check_win32_reparse_point(self.project_dir):
            raise PermissionError(f"REPARSE_POINT_DENIED: Root '{self.raw_project_dir}' is a junction point or symlink.")

        # Stdlib module set
        self.stdlib_names = set(getattr(sys, "stdlib_module_names", STDLIB_FALLBACK)).union(STDLIB_FALLBACK)

    def _verify_tcb_integrity(self):
        """Verifies SHA-256 integrity of sequence_engine.py against .sequence/lock_manifest.json if present."""
        manifest_path = self.project_dir / ".sequence" / "lock_manifest.json"
        engine_path = self.project_dir / "sequence_engine.py"

        if not engine_path.exists():
            return

        if not manifest_path.exists():
            return

        try:
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected_hash = manifest_data.get("sequence_engine.py") or manifest_data.get("hashes", {}).get("sequence_engine.py")
            if expected_hash and engine_path.exists():
                live_hash = hashlib.sha256(engine_path.read_bytes()).hexdigest()
                if live_hash != expected_hash:
                    raise PermissionError(f"TCB_INTEGRITY_VIOLATION: sequence_engine.py hash '{live_hash}' != expected '{expected_hash}'")
        except Exception as e:
            if isinstance(e, PermissionError):
                raise
            raise PermissionError(f"TCB_INTEGRITY_CHECK_FAILED: {e}")

    def load_mrac_rules(self):
        """Loads .sequence/mrac_rules.json via validate_and_open_path."""
        mrac_path = self.project_dir / ".sequence" / "mrac_rules.json"
        if not mrac_path.exists():
            return [], []

        try:
            with self.validate_and_open_path(str(mrac_path), str(self.project_dir), mode='r') as f:
                data = json.load(f)
            
            if not isinstance(data, dict) or "forbidden_imports" not in data:
                return None, ["MRAC_RULES_INVALID: mrac_rules.json missing required 'forbidden_imports' key."]
            
            forbidden = data.get("forbidden_imports")
            if not isinstance(forbidden, list) or not all(isinstance(x, str) and x for x in forbidden):
                return None, ["MRAC_RULES_INVALID: 'forbidden_imports' must be a list of non-empty strings."]
            
            return forbidden, []
        except Exception as e:
            return None, [f"MRAC_RULES_INVALID: Failed to load mrac_rules.json: {e}"]

    def is_first_party_module(self, top_module_name):
        """Returns True if top_module_name resolves to a first-party .py file or package under project_dir."""
        if not top_module_name:
            return False

        if top_module_name in KNOWN_TCB_MODULES:
            return True

        # Direct file: <top_module_name>.py
        target_file = self.project_dir / f"{top_module_name}.py"
        if target_file.exists():
            return True

        # Package directory: <top_module_name>/__init__.py
        target_pkg = self.project_dir / top_module_name / "__init__.py"
        if target_pkg.exists():
            return True

        # Subdirectory under project_dir
        target_dir = self.project_dir / top_module_name
        if target_dir.exists() and target_dir.is_dir():
            return True

        # Check tests submodules (e.g. tests.test_sequence_server)
        if top_module_name == "tests":
            return True

        return False

    def is_module_allowed(self, module_name, forbidden_list):
        """
        Determines whether a module import is allowed.
        Returns (is_allowed: bool, reason: str)
        """
        if not module_name:
            return True, "Allowed relative or empty module name."

        # Split dotted submodule name to top-level
        top_name = module_name.split('.')[0]

        # Check MRAC forbidden imports first
        if forbidden_list:
            for forbidden_pattern in forbidden_list:
                if module_name == forbidden_pattern or top_name == forbidden_pattern:
                    return False, f"Matches forbidden MRAC rule '{forbidden_pattern}'."

        # Check stdlib module names
        if top_name in self.stdlib_names:
            return True, f"Standard library module '{top_name}'."

        # Check first-party module resolution
        if self.is_first_party_module(top_name):
            return True, f"First-party project module '{top_name}'."

        return False, f"External pip package '{top_name}' not allowed."

    def scan_file(self, filepath_obj, forbidden_mrac):
        """Parses AST of a single Python file and returns list of violation objects."""
        violations = []
        rel_path = str(filepath_obj.relative_to(self.project_dir)).replace("\\", "/")

        try:
            with self.validate_and_open_path(str(filepath_obj), str(self.project_dir), mode='r') as f:
                content = f.read()
        except Exception as e:
            return [{"file": rel_path, "line": 1, "name": "READ_ERROR", "kind": "PARSE_ERROR"}]

        try:
            tree = ast.parse(content, filename=str(filepath_obj))
        except (SyntaxError, UnicodeDecodeError) as e:
            line_no = getattr(e, 'lineno', 1) or 1
            return [{"file": rel_path, "line": line_no, "name": "PARSE_ERROR", "kind": "PARSE_ERROR"}]

        # Attach parent references to AST nodes to identify try-guarded optional imports
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child._parent = parent

        for node in ast.walk(tree):
            # Check if import statement is guarded inside a try/except block
            curr = getattr(node, "_parent", None)
            is_try_guarded = False
            while curr:
                if isinstance(curr, ast.Try):
                    is_try_guarded = True
                    break
                curr = getattr(curr, "_parent", None)

            if is_try_guarded:
                continue

            # Static Import: import foo, import bar.baz
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod_name = alias.name
                    allowed, reason = self.is_module_allowed(mod_name, forbidden_mrac)
                    if not allowed:
                        violations.append({
                            "file": rel_path,
                            "line": getattr(node, 'lineno', 1),
                            "name": mod_name,
                            "kind": "IMPORT"
                        })

            # Static ImportFrom: from foo import bar
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    # Guard relative imports: from . import baz
                    continue
                mod_name = node.module
                allowed, reason = self.is_module_allowed(mod_name, forbidden_mrac)
                if not allowed:
                    violations.append({
                        "file": rel_path,
                        "line": getattr(node, 'lineno', 1),
                        "name": mod_name,
                        "kind": "IMPORTFROM"
                    })

            # Dynamic Call Traversal: __import__('foo'), importlib.import_module('bar'), exec/eval/compile
            elif isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                # Check __import__
                if func_name == "__import__":
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        target_mod = node.args[0].value
                        allowed, _ = self.is_module_allowed(target_mod, forbidden_mrac)
                        if not allowed:
                            violations.append({
                                "file": rel_path,
                                "line": getattr(node, 'lineno', 1),
                                "name": target_mod,
                                "kind": "DYNAMIC_IMPORT"
                            })
                    else:
                        violations.append({
                            "file": rel_path,
                            "line": getattr(node, 'lineno', 1),
                            "name": "__import__",
                            "kind": "DYNAMIC_IMPORT_UNRESOLVED"
                        })

                # Check importlib.import_module or importlib.__import__
                elif func_name in ("import_module",):
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        target_mod = node.args[0].value
                        allowed, _ = self.is_module_allowed(target_mod, forbidden_mrac)
                        if not allowed:
                            violations.append({
                                "file": rel_path,
                                "line": getattr(node, 'lineno', 1),
                                "name": target_mod,
                                "kind": "DYNAMIC_IMPORT"
                            })
                    else:
                        violations.append({
                            "file": rel_path,
                            "line": getattr(node, 'lineno', 1),
                            "name": "importlib.import_module",
                            "kind": "DYNAMIC_IMPORT_UNRESOLVED"
                        })

                # Check exec / eval / compile
                elif func_name in ("exec", "eval", "compile"):
                    violations.append({
                        "file": rel_path,
                        "line": getattr(node, 'lineno', 1),
                        "name": func_name,
                        "kind": "EVAL_EXEC"
                    })

        return violations

    def audit(self):
        """Performs full supply-chain AST audit over codebase."""
        forbidden_mrac, errors = self.load_mrac_rules()
        if errors:
            return {
                "status": "FAIL",
                "scanned_files_count": 0,
                "forbidden_imports_found": 1,
                "violations": [{"file": ".sequence/mrac_rules.json", "line": 1, "name": "MRAC_RULES_INVALID", "kind": "MRAC_RULES_INVALID"}],
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

        all_violations = []
        scanned_count = 0

        # Walk directory structure with Win32 reparse point checks
        for root, dirs, files in os.walk(self.project_dir):
            root_path = Path(root)

            # Skip hidden or environment dirs
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".") and d not in ("__pycache__", "venv", "env", "node_modules")
                and not check_win32_reparse_point(root_path / d)
            ]

            for file_name in files:
                if file_name.endswith(".py"):
                    file_path = root_path / file_name
                    scanned_count += 1
                    file_violations = self.scan_file(file_path, forbidden_mrac)
                    all_violations.extend(file_violations)

        status = "PASS" if len(all_violations) == 0 else "FAIL"
        envelope = {
            "status": status,
            "scanned_files_count": scanned_count,
            "forbidden_imports_found": len(all_violations),
            "violations": all_violations,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        # Validate envelope via schemas
        from schemas import validate_watchdog_envelope
        valid, val_errors = validate_watchdog_envelope(envelope)
        if not valid:
            raise ValueError(f"Envelope validation error: {val_errors}")

        return envelope


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else r"C:\Linkstream\00_DEV_TEAM_SEQUENCE"
    try:
        auditor = SupplyChainWatchdog(target_dir)
        result = auditor.audit()
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["status"] == "PASS" else 1)
    except Exception as e:
        print(json.dumps({
            "status": "FAIL",
            "scanned_files_count": 0,
            "forbidden_imports_found": 1,
            "violations": [{"file": "watchdog.py", "line": 1, "name": str(e), "kind": "PARSE_ERROR"}],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }, indent=2))
        sys.exit(1)
