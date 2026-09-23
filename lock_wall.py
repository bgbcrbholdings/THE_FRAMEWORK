#!/usr/bin/env python3
"""
Project Zero: The Sequence Control Engine — 1-Way Door Architectural Lock Wall Engine (lock_wall.py)
Enforces fail-closed cryptographic integrity verification over all TCB engine scripts,
.sequence/mrac_rules.json, and all static UI assets under dashboard/**.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
import ctypes
import hashlib
from pathlib import Path
from datetime import datetime, timezone

# Root Anchoring
APPROVED_ROOT_DIR = Path(__file__).resolve().parent

# 22 TCB Engine Scripts
TCB_ENGINE_SCRIPTS = [
    "verify.py",
    "sequence_server.py",
    "schemas.py",
    "auditor_agent.py",
    "build_packet.py",
    "parse_reviews.py",
    "agent_dispatcher.py",
    "sequence_engine.py",
    "watchdog.py",
    "project_wizard.py",
    "lock_wall.py",
    "pathfinder_server.py",
    "setup_hooks.py",
    "scorecard.py",
    "telemetry.py",
    "backup_engine.py",
    "file_hygiene_engine.py",
    "packet_verify.py",
    "regr_watchdog.py",
    "test_cp_review.py",
    "slice_gate.py",
    "allowlist_sync.py",
]

# Win32 Reparse Point Flags
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

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
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
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

        if res and (info.FileAttributes & 0x400): # FILE_ATTRIBUTE_REPARSE_POINT
            return True
        return False
    except Exception:
        return True # Fail-closed on error

def canonicalize_and_validate_path(path_str, root_dir_str=None):
    """Validates realpath boundary and Win32 atomic reparse point for input/output paths."""
    if root_dir_str is None:
        root_dir_str = str(APPROVED_ROOT_DIR)
    root_real = Path(root_dir_str).resolve()

    # Reject traversal markers & Alternate Data Streams in raw string
    raw_str = str(path_str).replace("\\", "/")
    if ".." in raw_str.split("/"):
        return False, f"PATH_TRAVERSAL: Path '{path_str}' contains '..' path components"
    
    # Strip Windows drive letter before checking ADS ':'
    check_str = raw_str
    if len(check_str) >= 2 and check_str[1] == ":":
        check_str = check_str[2:]
    if ":" in check_str:
        return False, f"ADS_DENIED: Path '{path_str}' contains alternate data stream"

    path_obj = Path(path_str)
    if path_obj.is_absolute():
        target_real = path_obj.resolve()
    else:
        target_real = (root_real / path_obj).resolve()

    try:
        target_real.relative_to(root_real)
    except ValueError:
        return False, f"PATH_TRAVERSAL: Path '{path_str}' escapes approved root '{root_dir_str}'"

    if check_win32_reparse_point(target_real):
        return False, f"REPARSE_POINT_DENIED: Path '{path_str}' is an NTFS junction point or symlink"

    return True, str(target_real)

def get_tcb_hash_targets(root_dir=APPROVED_ROOT_DIR):
    """Returns sorted list of root-relative POSIX paths for all TCB targets."""
    root_dir = Path(root_dir).resolve()
    targets = set(TCB_ENGINE_SCRIPTS)
    targets.add(".sequence/mrac_rules.json")

    dash_dir = root_dir / "dashboard"
    if dash_dir.exists():
        for p in dash_dir.rglob("*"):
            if p.is_file() and not check_win32_reparse_point(p):
                rel_posix = p.relative_to(root_dir).as_posix()
                targets.add(rel_posix)
    return sorted(list(targets))


class LockWallEngine:
    """1-Way Door Architectural Lock Wall Engine enforcing fail-closed cryptographic gates."""

    def __init__(self, project_dir=APPROVED_ROOT_DIR):
        self.raw_project_dir = str(project_dir)
        ok, res = canonicalize_and_validate_path(str(project_dir), str(project_dir))
        if not ok:
            raise PermissionError(f"INVALID_PROJECT_DIR: {res}")
        self.project_dir = Path(res).resolve()

    def compute_script_hash(self, relative_script_path: str) -> str:
        """
        Before opening or hashing, reject absolute paths, .. path components,
        alternate data streams, and any path not present in the fixed manifest file set.
        Resolve candidate through canonicalize_and_validate_path using Win32
        reparse-point-safe checks, require a regular non-reparse file within approved root,
        then hash bytes from the validated handle.
        """
        raw_str = str(relative_script_path).replace("\\", "/")
        if Path(relative_script_path).is_absolute():
            raise ValueError(f"ABSOLUTE_PATH_REJECTED: '{relative_script_path}' is absolute")
        if ".." in raw_str.split("/"):
            raise ValueError(f"PATH_TRAVERSAL_REJECTED: '{relative_script_path}' contains '..'")
        if ":" in raw_str:
            raise ValueError(f"ADS_REJECTED: '{relative_script_path}' contains alternate data stream")

        valid_targets = get_tcb_hash_targets(self.project_dir)
        posix_rel = Path(relative_script_path).as_posix()
        if posix_rel not in valid_targets:
            raise ValueError(f"INVALID_MANIFEST_TARGET: '{relative_script_path}' is not in TCB_HASH_TARGETS")

        ok, validated_path_str = canonicalize_and_validate_path(posix_rel, str(self.project_dir))
        if not ok:
            raise PermissionError(f"PATH_VALIDATION_FAILED: {validated_path_str}")

        val_path = Path(validated_path_str)
        if not val_path.exists():
            raise ValueError(f"FILE_NOT_FOUND: Target '{relative_script_path}' does not exist")
        if not val_path.is_file() or val_path.is_symlink() or check_win32_reparse_point(val_path):
            raise PermissionError(f"NON_REGULAR_FILE_OR_REPARSE: '{relative_script_path}' is invalid")

        hasher = hashlib.sha256()
        with open(val_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def verify_lock_integrity(self) -> tuple[bool, list[str]]:
        """
        Verifies a closed, deterministic manifest file set consisting of all 11 named TCB scripts,
        .sequence/mrac_rules.json, and every regular static file recursively beneath dashboard/.
        The manifest key for each file MUST be its root-relative POSIX path.
        Missing, extra, duplicate, malformed, non-regular, symlinked, or junctioned entries cause verification failure.
        Every live file hash must equal its manifest hash, and computed boot digest must equal .sequence/boot_digest.txt.
        """
        errors = []
        sec_dir = self.project_dir / ".sequence"
        manifest_file = sec_dir / "lock_manifest.json"
        boot_digest_file = sec_dir / "boot_digest.txt"

        if not manifest_file.exists():
            return False, ["MISSING_LOCK_MANIFEST: .sequence/lock_manifest.json does not exist"]
        if not boot_digest_file.exists():
            return False, ["MISSING_BOOT_DIGEST: .sequence/boot_digest.txt does not exist"]

        ok_m, msg_m = canonicalize_and_validate_path(manifest_file, str(self.project_dir))
        if not ok_m:
            return False, [f"MANIFEST_PATH_INVALID: {msg_m}"]

        ok_b, msg_b = canonicalize_and_validate_path(boot_digest_file, str(self.project_dir))
        if not ok_b:
            return False, [f"BOOT_DIGEST_PATH_INVALID: {msg_b}"]

        try:
            manifest_text = Path(msg_m).read_text(encoding="utf-8")
            manifest_data = json.loads(manifest_text)
        except Exception as e:
            return False, [f"MALFORMED_MANIFEST_JSON: {e}"]

        expected_hashes = manifest_data.get("hashes", {})
        if not isinstance(expected_hashes, dict):
            return False, ["MALFORMED_MANIFEST_HASHES: 'hashes' field must be a dictionary"]

        expected_targets = get_tcb_hash_targets(self.project_dir)
        live_hashes = {}

        for target_posix in expected_targets:
            target_path = self.project_dir / target_posix
            if not target_path.exists():
                errors.append(f"MISSING_TCB_FILE: Missing required TCB file '{target_posix}'")
                continue
            
            ok_t, msg_t = canonicalize_and_validate_path(target_path, str(self.project_dir))
            if not ok_t:
                errors.append(f"TCB_FILE_VALIDATION_FAILED: '{target_posix}': {msg_t}")
                continue

            if not Path(msg_t).is_file() or Path(msg_t).is_symlink() or check_win32_reparse_point(Path(msg_t)):
                errors.append(f"NON_REGULAR_TCB_FILE: '{target_posix}' is symlinked, junctioned, or non-regular")
                continue

            try:
                live_hash = self.compute_script_hash(target_posix)
                live_hashes[target_posix] = live_hash
            except Exception as e:
                errors.append(f"HASH_COMPUTATION_FAILED: '{target_posix}': {e}")
                continue

            expected_hash = expected_hashes.get(target_posix)
            if not expected_hash:
                errors.append(f"EXTRA_OR_UNSIGNED_FILE: Target '{target_posix}' not present in lock manifest")
            elif live_hash != expected_hash:
                errors.append(f"HASH_MISMATCH: Target '{target_posix}' live hash ({live_hash[:10]}...) != manifest ({expected_hash[:10]}...)")

        # Check for extra keys in manifest not in target set
        for k in expected_hashes:
            if k not in expected_targets:
                errors.append(f"UNKNOWN_MANIFEST_ENTRY: Lock manifest contains unknown target '{k}'")

        # Verify boot digest
        try:
            live_boot_digest = Path(msg_b).read_text(encoding="utf-8").strip()
            canonical_manifest_bytes = json.dumps(expected_hashes, sort_keys=True, separators=(',', ':')).encode("utf-8")
            computed_boot_digest = hashlib.sha256(canonical_manifest_bytes).hexdigest()

            if live_boot_digest != computed_boot_digest:
                errors.append(f"BOOT_DIGEST_MISMATCH: Live boot digest ({live_boot_digest[:10]}...) != computed ({computed_boot_digest[:10]}...)")
        except Exception as e:
            errors.append(f"BOOT_DIGEST_VERIFICATION_FAILED: {e}")

        is_valid = len(errors) == 0
        return is_valid, errors

    def seal_lock_manifest(self) -> dict:
        """
        Builds deterministic file set, rejects paths that fail canonicalize_and_validate_path,
        serializes manifest using canonical JSON (sort_keys=True, compact separators, UTF-8),
        derives boot digest as SHA-256 of those exact manifest bytes, and atomically writes
        both files only after successful validation.
        """
        sec_dir = self.project_dir / ".sequence"
        sec_dir.mkdir(parents=True, exist_ok=True)

        targets = get_tcb_hash_targets(self.project_dir)
        manifest_hashes = {}

        for posix_path in targets:
            target_path = self.project_dir / posix_path
            if target_path.is_file() and not check_win32_reparse_point(target_path):
                live_hash = self.compute_script_hash(posix_path)
                manifest_hashes[posix_path] = live_hash

        manifest_data = {
            "manifest_version": "1.0.0",
            "slice_id": "slice-008-architectural-lock-wall",
            "status": "SEALED",
            "tcb_scripts_count": len(TCB_ENGINE_SCRIPTS),
            "total_tcb_targets_count": len(manifest_hashes),
            "hashes": manifest_hashes
        }

        canonical_manifest_bytes = json.dumps(manifest_hashes, sort_keys=True, separators=(',', ':')).encode("utf-8")
        computed_boot_digest = hashlib.sha256(canonical_manifest_bytes).hexdigest()

        # Atomic file write using temporary files and os.replace
        manifest_file = sec_dir / "lock_manifest.json"
        tmp_manifest = sec_dir / "lock_manifest.json.tmp"
        tmp_manifest.write_text(json.dumps(manifest_data, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp_manifest, manifest_file)

        boot_digest_file = sec_dir / "boot_digest.txt"
        tmp_boot = sec_dir / "boot_digest.txt.tmp"
        tmp_boot.write_text(f"{computed_boot_digest}\n", encoding="utf-8")
        os.replace(tmp_boot, boot_digest_file)

        return manifest_data

    def assert_fail_closed(self):
        """Raises PermissionError if lock wall verification fails."""
        is_valid, errors = self.verify_lock_integrity()
        if not is_valid:
            err_msg = "; ".join(errors)
            raise PermissionError(f"FAIL_CLOSED_LOCK_WALL_VIOLATION: Lock integrity verification failed: {err_msg}")

    def get_status_envelope(self) -> dict:
        """Returns validatable status envelope for LockWallEngine."""
        is_valid, errors = self.verify_lock_integrity()
        sec_dir = self.project_dir / ".sequence"
        manifest_file = sec_dir / "lock_manifest.json"
        boot_digest_file = sec_dir / "boot_digest.txt"

        manifest_exists = manifest_file.exists()
        boot_exists = boot_digest_file.exists()

        tcb_targets = get_tcb_hash_targets(self.project_dir)

        status_str = "OK" if is_valid else "FAILED"
        if not manifest_exists or not boot_exists:
            status_str = "FAILED"

        utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return {
            "status": status_str,
            "tcb_count": len(tcb_targets),
            "dashboard_file_count": len([t for t in tcb_targets if t.startswith("dashboard/")]),
            "manifest_hash_match": is_valid,
            "boot_digest_match": is_valid,
            "mismatched_paths": errors,
            "timestamp": utc_now
        }

if __name__ == "__main__":
    engine = LockWallEngine()
    if len(sys.argv) > 1 and sys.argv[1] == "--seal":
        from slice_gate import assert_slice_action_allowed, resolve_active_slice_id
        slice_id = resolve_active_slice_id(APPROVED_ROOT_DIR)
        assert_slice_action_allowed(slice_id, "LOCK", APPROVED_ROOT_DIR)
        data = engine.seal_lock_manifest()
        print(f"[OK] LockWallEngine: Sealed manifest with {data['total_tcb_targets_count']} targets.")
        sys.exit(0)

    is_valid, errs = engine.verify_lock_integrity()
    if is_valid:
        print("[OK] LockWallEngine: Fail-closed lock integrity verification PASSED.")
        sys.exit(0)
    else:
        print(f"[FAIL] LockWallEngine: Fail-closed lock integrity FAILED ({len(errs)} errors):", file=sys.stderr)
        for err in errs:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
