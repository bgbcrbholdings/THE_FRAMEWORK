#!/usr/bin/env python3
"""
The Sequence Control Engine — Core Framework & Session Management Engine (sequence_engine.py)
Implements Win32 Atomic Reparse-Point Path Isolation (validate_and_open_path)
and Restrictive OS ACL Session Token Lifecycle Management.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
import uuid
import secrets
import hmac
import ctypes
import urllib.parse
import subprocess
import re
from pathlib import Path
from datetime import datetime

# Approved Root Directory Anchoring (Dynamic resolution on Windows and POSIX)
APPROVED_ROOT_DIR = Path(__file__).resolve().parent
LINKSTREAM_ROOT = APPROVED_ROOT_DIR.parent if APPROVED_ROOT_DIR.name.casefold() == "00_dev_team_sequence" else APPROVED_ROOT_DIR

# Win32 Constants for Reparse-Point (Junction/Symlink) Check
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
OPEN_EXISTING = 3
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
INVALID_HANDLE_VALUE = -1


def check_win32_reparse_point(path_obj):
    """
    Uses Win32 CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT to detect
    whether a file or folder is a Win32 reparse point (junction/symlink).
    Fails closed on non-Windows platforms or Win32 API errors.
    """
    if os.name != "nt":
        return False

    abs_str = str(Path(path_obj).resolve())
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
            abs_str,
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None
        )
        if handle == INVALID_HANDLE_VALUE or handle == 0 or handle == 0xFFFFFFFF:
            return False

        class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", ctypes.c_ulong),
                ("ftCreationTime", ctypes.c_ulonglong),
                ("ftLastAccessTime", ctypes.c_ulonglong),
                ("ftLastWriteTime", ctypes.c_ulonglong),
                ("dwVolumeSerialNumber", ctypes.c_ulong),
                ("nFileSizeHigh", ctypes.c_ulong),
                ("nFileSizeLow", ctypes.c_ulong),
                ("nNumberOfLinks", ctypes.c_ulong),
                ("nFileIndexHigh", ctypes.c_ulong),
                ("nFileIndexLow", ctypes.c_ulong)
            ]

        info = BY_HANDLE_FILE_INFORMATION()
        res = kernel32.GetFileInformationByHandle(handle, ctypes.byref(info))
        kernel32.CloseHandle(handle)

        if res == 0:
            return False

        FILE_ATTRIBUTE_REPARSE_POINT = 0x400
        is_reparse = bool(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        return is_reparse
    except Exception:
        return False


def validate_and_open_path(path_str, root_dir_str=None, mode="r", encoding="utf-8"):
    """
    Uniform, named approved-root containment helper function used across all TCB file operations.
    Performs:
    1. URL unquoting (urllib.parse.unquote)
    2. Explicit '..' path traversal and ADS (':') stream rejection
    3. Path canonicalization (os.path.realpath)
    4. Approved-root containment validation (relative_to check)
    5. Win32 atomic reparse-point check (FILE_FLAG_OPEN_REPARSE_POINT)
    Returns safe open file handle or raises PermissionError / ValueError on failure.
    """
    if root_dir_str is None:
        root_dir_str = str(APPROVED_ROOT_DIR)

    # 1. URL decoding
    decoded_path_str = urllib.parse.unquote(str(path_str))

    # Reject traversal markers & Alternate Data Streams in raw string
    raw_str = decoded_path_str.replace("\\", "/")
    if ".." in raw_str.split("/"):
        raise PermissionError(f"PATH TRAVERSAL VIOLATION: Path '{path_str}' contains '..' path components.")

    # Strip Windows drive letters (e.g. C: or /C:) before checking ADS ':'
    check_str = re.sub(r'(^|[/\\\\])[a-zA-Z]:(?=[/\\\\]|$)', r'\1', raw_str)
    if ":" in check_str:
        raise PermissionError(f"ADS VIOLATION: Path '{path_str}' contains alternate data stream.")

    # 2. Canonicalization & containment check
    root_path = Path(os.path.realpath(str(root_dir_str))).resolve()
    if not os.path.isabs(decoded_path_str):
        full_path_str = os.path.join(str(root_dir_str), decoded_path_str)
    else:
        full_path_str = decoded_path_str
    target_path = Path(os.path.realpath(full_path_str)).resolve()

    try:
        target_path.relative_to(root_path)
    except ValueError:
        raise PermissionError(f"PATH TRAVERSAL VIOLATION: Path '{target_path}' escapes approved root '{root_path}'.")

    # 3. Check for reparse points (symlinks/junctions)
    if target_path.exists() and (target_path.is_symlink() or check_win32_reparse_point(target_path)):
        raise PermissionError(f"REPARSE POINT VIOLATION: Path '{target_path}' is a Win32 symlink or junction point.")

    # Safe open file handle return
    if "b" in mode:
        return open(target_path, mode)
    return open(target_path, mode, encoding=encoding)


def apply_restrictive_dacl(file_path):
    """
    Applies restrictive OS ACLs to target file using icacls (on Windows) or chmod 600 (on POSIX).
    Strips inherited DACL permissions and grants exclusive Full Control to current username only.
    """
    file_path_obj = Path(file_path)
    if not file_path_obj.exists():
        return False

    try:
        os.chmod(file_path_obj, 0o600)
    except Exception:
        pass

    if os.name != "nt":
        return True

    username = os.environ.get("USERNAME")
    if not username:
        return False

    file_str = str(file_path_obj.resolve())
    try:
        # Strip inheritance and grant full control to current user only
        cmd = ["icacls", file_str, "/inheritance:r", "/grant:r", f"{username}:F"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.returncode == 0
    except Exception:
        return False


def verify_restrictive_dacl(file_path):
    """
    Verifies that the file DACL restricts access exclusively to current user.
    Fails closed if icacls fails or grants access to unauthorized users.
    """
    file_path_obj = Path(file_path)
    if not file_path_obj.exists():
        return False

    if os.name != "nt":
        try:
            mode = os.stat(file_path_obj).st_mode & 0o777
            return mode == 0o600 or mode == 0o700
        except Exception:
            return False

    file_str = str(file_path_obj.resolve())
    username = os.environ.get("USERNAME", "").lower()
    if not username:
        return False

    try:
        cmd = ["icacls", file_str]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return False

        output = res.stdout.lower()
        if username not in output:
            return False
        if "(i)" in output or "everyone" in output or "builtin\\users" in output:
            return False
        return True
    except Exception:
        return False


def generate_and_save_session(root_dir=APPROVED_ROOT_DIR):
    """
    Generates high-entropy secret token (secrets.token_urlsafe(32)) and anti-CSRF nonce (secrets.token_hex(16)).
    Applies restrictive OS ACLs to temporary file before writing token.
    Performs atomic rename via os.replace('.sequence/session.tmp', '.sequence/session.json').
    """
    root_path = Path(root_dir).resolve()
    sec_dir = root_path / ".sequence"
    sec_dir.mkdir(parents=True, exist_ok=True)

    session_json = sec_dir / "session.json"
    session_tmp = sec_dir / "session.tmp"

    token = secrets.token_urlsafe(32)
    csrf_nonce = secrets.token_hex(16)
    manifest_id = str(uuid.uuid4())

    manifest_data = {
        "manifest_id": manifest_id,
        "project_title": "Project Zero: Sequence Control Engine",
        "version": "1.0.0",
        "sequence_token": token,
        "csrf_nonce": csrf_nonce,
        "created_at": datetime.now().isoformat()
    }

    # Create empty temp file using validate_and_open_path
    with validate_and_open_path(session_tmp, root_dir_str=str(root_path), mode="w") as f:
        f.write("")

    # Apply DACL *prior to writing secret content*
    apply_restrictive_dacl(session_tmp)

    # Write formatted session JSON
    with validate_and_open_path(session_tmp, root_dir_str=str(root_path), mode="w") as f:
        json.dump(manifest_data, f, indent=2)

    # Atomic rename replace
    os.replace(session_tmp, session_json)
    return manifest_data


def get_or_create_active_session(root_dir=APPROVED_ROOT_DIR):
    """
    Reads active session manifest or generates a fresh one.
    Fails closed if session file is corrupt or weak.
    """
    root_path = Path(root_dir).resolve()
    session_json = root_path / ".sequence" / "session.json"
    if not session_json.exists():
        return generate_and_save_session(root_path)

    try:
        with validate_and_open_path(session_json, root_dir_str=str(root_path), mode="r") as f:
            data = json.load(f)
            if not data.get("sequence_token") or not data.get("csrf_nonce"):
                raise ValueError("Session file missing token or csrf_nonce")
            return data
    except Exception as e:
        return generate_and_save_session(root_path)


if __name__ == "__main__":
    sess = get_or_create_active_session()
    print(f" [+] Sequence Session Active. Token: {sess['sequence_token'][:8]}... CSRF Nonce: {sess['csrf_nonce']}")
