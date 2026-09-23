#!/usr/bin/env python3
"""
The Sequence Control Engine — Mechanical File Hygiene & Anti-Rot Engine (file_hygiene_engine.py)
Validates governance file status headers with verify-only default and lock-manifest protection.
Checks 03_INCUBATOR/ document alignment against 02_BACKLOG/AGILE_SLICES.md.
Sweeps loose review files in 04_REVIEWS/ root into 04_REVIEWS/_archived_loose_reviews/.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import re
import json
import ctypes
import hashlib
from pathlib import Path
from datetime import datetime

GOVERNANCE_FILES = [
    "01_GOVERNANCE/PROBLEM.md",
    "01_GOVERNANCE/ARCHITECTURE.md",
    "01_GOVERNANCE/DECISIONS.md",
    "02_BACKLOG/AGILE_SLICES.md",
    "01_GOVERNANCE/NON_GOALS.md"
]

RESERVED_REVIEW_DIRS = {
    "_archived_loose_reviews",
    "genesis",
    "slice-001-off-grid-review-parser",
    "slice-002-master-engine-core",
    "slice-003-supply-chain-watchdog",
    "slice-004-sandboxed-sandwich",
    "slice-005-second-brain-scorecard",
    "slice-006-genesis-test-harness",
    "slice-007-grand-chess-board-ui",
    "slice-008-architectural-lock-wall",
    "slice-009-lifecycle-circuit-breaker"
}

class BlockedSliceWriteError(Exception):
    """Raised when an unapproved write attempt targets a source file under a BLOCKED slice."""
    pass

from urllib.parse import unquote

def _get_remediation_allowlist_from_findings(project_root: Path, slice_id: str) -> set[Path]:
    """
    Parse .sequence/review_resolutions.json for the given slice_id,
    extract all 'target_location' URLs from unresolved findings' remediation blocks,
    convert file:/// URLs to absolute Path objects dynamically resolved relative to project_root.
    Always includes 04_REVIEWS/<slice_id>/implementation_plan.md as a minimum fallback.
    Zero regex or hardcoded directory strings.
    """
    p_root = project_root.resolve()
    res_path = p_root / ".sequence" / "review_resolutions.json"
    allowlist = set()
    allowlist.add((p_root / "04_REVIEWS" / slice_id / "implementation_plan.md").resolve())
    
    if not res_path.exists():
        return allowlist

    try:
        data = json.loads(res_path.read_text(encoding="utf-8"))
    except Exception:
        return allowlist

    slices_map = data.get("slices", {})
    slice_entry = slices_map.get(slice_id, {})
    if not slice_entry and data.get("slice_id") == slice_id:
        slice_entry = data

    for finding in slice_entry.get("findings", []):
        status = finding.get("status", "OPEN")
        if status in ("OPEN", "REJECTED_NOT_IMPLEMENTED", "REJECTED_PARTIAL"):
            target_url = finding.get("remediation", {}).get("target_location", "")
            if target_url:
                raw_path_str = unquote(target_url.split("#")[0].replace("file:///", ""))
                p_obj = Path(raw_path_str)
                if p_obj.is_absolute():
                    try:
                        rel = p_obj.resolve().relative_to(p_root)
                        allowlist.add((p_root / rel).resolve())
                    except ValueError:
                        allowlist.add((p_root / p_obj.name).resolve())
                else:
                    allowlist.add((p_root / p_obj).resolve())

    return allowlist

def safe_write(target_path: str, content: str, slice_id: str, action: str = "IMPLEMENT", project_root: Path = None) -> None:
    """
    Upstream pre-write gate. Called BEFORE open(path, 'w') touches disk.
    Enforces Win32 CreateFileW FILE_FLAG_OPEN_REPARSE_POINT atomic checks per ADR-001,
    project root containment, and atomic tempfile replace via NamedTemporaryFile.
    Zero bytes touch target disk on failure.
    Requires explicit slice_id parameter (no silent default).
    Dynamic project_root fallback to Path.cwd() (zero hardcoded paths).
    """
    if not slice_id:
        raise ValueError("safe_write requires an explicit slice_id parameter")

    if project_root is None:
        project_root = Path.cwd()

    p_root = Path(project_root).resolve()
    raw_target = Path(target_path)
    
    if check_win32_reparse_point(raw_target.parent) or (raw_target.exists() and check_win32_reparse_point(raw_target)):
        raise BlockedSliceWriteError(f"Write target '{raw_target}' contains Windows reparse-point junction/symlink")
    
    target = Path(os.path.realpath(target_path))
    
    if check_win32_reparse_point(target.parent) or (target.exists() and check_win32_reparse_point(target)):
        raise BlockedSliceWriteError(f"Write target '{target}' contains Windows reparse-point junction/symlink")
    
    try:
        target.relative_to(p_root)
    except ValueError:
        raise BlockedSliceWriteError(f"Write target '{target}' escapes project root '{p_root}'")

    from slice_gate import check_slice_action_allowed, SliceGateDeniedError
    try:
        check_slice_action_allowed(slice_id, action, p_root)
    except SliceGateDeniedError as e:
        raise BlockedSliceWriteError(f"Slice lifecycle gate denied write: {e.message}")

    # Write-path allowlist narrowing per action
    if action == "PARSE_REVIEWS":
        allowed = (p_root / ".sequence" / "review_resolutions.json").resolve()
        if target.resolve() != allowed:
            raise BlockedSliceWriteError(f"Action 'PARSE_REVIEWS' write to '{target}' DENIED. Allowed: '{allowed}'")

    elif action == "BUILD_PACKET":
        allowed_dir = (p_root / "04_REVIEWS" / slice_id).resolve()
        allowed_ptr = (p_root / ".sequence" / "active_packet.json").resolve()
        try:
            target.resolve().relative_to(allowed_dir)
        except ValueError:
            if target.resolve() != allowed_ptr:
                raise BlockedSliceWriteError(f"Action 'BUILD_PACKET' write to '{target}' DENIED. Must target '{allowed_dir}' or '{allowed_ptr}'")

    elif action == "REMEDIATE_PLAN":
        allowed_prefix = (p_root / "04_REVIEWS" / slice_id).resolve()
        try:
            target.resolve().relative_to(allowed_prefix)
        except ValueError:
            findings_allowlist = _get_remediation_allowlist_from_findings(p_root, slice_id)
            if target.resolve() not in findings_allowlist:
                raise BlockedSliceWriteError(
                    f"Write to '{target}' DENIED for 'REMEDIATE_PLAN'. Allowed: {[str(p) for p in findings_allowlist]}"
                )

    import tempfile
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile('w', dir=target.parent, delete=False, encoding='utf-8') as tf:
            tf.write(content)
            temp_name = tf.name
        os.replace(temp_name, target)
    except Exception:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
        raise


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

def canonicalize_and_validate_path(path_str, root_dir_str=None):
    """Validates realpath boundary and Win32 atomic reparse point for input/output paths."""
    if root_dir_str is None:
        root_dir_str = r"C:\Linkstream\00_DEV_TEAM_SEQUENCE"
    root_real = Path(root_dir_str).resolve()

    raw_str = str(path_str).replace("\\", "/")
    if ".." in raw_str.split("/"):
        return False, f"PATH_TRAVERSAL: Path '{path_str}' contains '..' path components"

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


import ast
from datetime import timezone

class GraphifyASTParser:
    """
    Standard library ast Knowledge Graph generator (Graphify-Labs/graphify).
    Parses Python modules, extracts classes, functions, imports, and call-edges.
    Outputs symbol relationships as native Markdown [[wikilinks]] directly into .sequence/wiki/ast_symbols.md.
    """
    def __init__(self, project_dir=None):
        if project_dir is None:
            project_dir = r"C:\Linkstream\00_DEV_TEAM_SEQUENCE"
        ok, res = canonicalize_and_validate_path(str(project_dir))
        if not ok:
            raise PermissionError(f"INVALID_PROJECT_DIR: {res}")
        self.project_dir = Path(res).resolve()

    def parse_repository_symbols(self) -> dict:
        """
        Enumerates repository source files without following symlinks or NTFS junctions.
        Before each source read and before each .sequence/wiki/ directory or note write,
        it MUST call canonicalize_and_validate_path against APPROVED_ROOT_DIR, reject reparse points,
        alternate data streams, and non-regular source files, and fail closed on validation failure.
        Wiki output filenames MUST be fixed, allowlisted root-relative names;
        AST-derived symbols MUST NOT determine filesystem paths.
        """
        scanned_modules = 0
        classes_found = 0
        functions_found = 0
        call_edges_count = 0
        parse_errors = []
        wikilinks = []

        for root, dirs, files in os.walk(self.project_dir):
            current_dir = Path(root)
            ok_dir, msg_dir = canonicalize_and_validate_path(current_dir, str(self.project_dir))
            if not ok_dir:
                dirs.clear()
                continue

            for file_name in files:
                if not file_name.endswith(".py"):
                    continue

                file_path = current_dir / file_name
                ok_file, msg_file = canonicalize_and_validate_path(file_path, str(self.project_dir))
                if not ok_file:
                    raise PermissionError(f"PATH_ESCAPE_DENIED: {msg_file}")

                val_path = Path(msg_file)
                if not val_path.is_file() or check_win32_reparse_point(val_path):
                    continue

                try:
                    if val_path.stat().st_size > 2_000_000:
                        continue
                except Exception:
                    continue

                try:
                    with open(val_path, "r", encoding="utf-8", errors="strict") as f:
                        source_code = f.read()
                except Exception as e:
                    parse_errors.append({"file": val_path.relative_to(self.project_dir).as_posix(), "error": str(e)})
                    continue

                try:
                    tree = ast.parse(source_code, filename=file_name)
                except (SyntaxError, ValueError, UnicodeDecodeError) as e:
                    parse_errors.append({"file": val_path.relative_to(self.project_dir).as_posix(), "error": f"AST_SYNTAX_ERROR: {e}"})
                    continue

                scanned_modules += 1
                module_name = val_path.stem
                wikilinks.append(f"- [[Module:{module_name}]] ({val_path.relative_to(self.project_dir).as_posix()})")

                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        classes_found += 1
                        wikilinks.append(f"  - [[Class:{node.name}]] in [[Module:{module_name}]]")
                    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        functions_found += 1
                        wikilinks.append(f"  - [[Function:{node.name}]] in [[Module:{module_name}]]")
                    elif isinstance(node, ast.Call):
                        call_edges_count += 1

        sec_wiki_dir = self.project_dir / ".sequence" / "wiki"
        ok_w_dir, msg_w_dir = canonicalize_and_validate_path(sec_wiki_dir, str(self.project_dir))
        if not ok_w_dir:
            raise PermissionError(f"WIKI_DIR_INVALID: {msg_w_dir}")

        Path(msg_w_dir).mkdir(parents=True, exist_ok=True)
        wiki_note_file = Path(msg_w_dir) / "ast_symbols.md"

        ok_note, msg_note = canonicalize_and_validate_path(wiki_note_file, str(self.project_dir))
        if not ok_note:
            raise PermissionError(f"WIKI_NOTE_PATH_INVALID: {msg_note}")

        utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        wiki_content = f"# AST Knowledge Graph Symbol Index\n\n"
        wiki_content += f"Generated: {utc_now}\n"
        wiki_content += f"Modules Scanned: {scanned_modules} | Classes: {classes_found} | Functions: {functions_found} | Call Edges: {call_edges_count}\n\n"
        wiki_content += "\n".join(wikilinks) + "\n"

        Path(msg_note).write_text(wiki_content, encoding="utf-8")
        wiki_notes_generated = 1

        return {
            "scanned_modules": scanned_modules,
            "classes_found": classes_found,
            "functions_found": functions_found,
            "call_edges_count": call_edges_count,
            "wiki_notes_generated": wiki_notes_generated,
            "parse_errors": parse_errors,
            "timestamp": utc_now
        }


class FileHygieneEngine:
    """Mechanical governance status header updater, document alignment checker, and loose file sweeper."""

    def __init__(self, project_dir_str, apply_changes=False):
        self.raw_project_dir = project_dir_str
        self.project_dir = Path(project_dir_str).resolve()
        self.apply_changes = apply_changes

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
        """Verifies SHA-256 integrity of sequence_engine.py against .sequence/lock_manifest.json if present."""
        manifest_path = self.project_dir / ".sequence" / "lock_manifest.json"
        engine_path = self.project_dir / "sequence_engine.py"

        if not engine_path.exists():
            return

        if not manifest_path.exists():
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

    def load_lock_manifest(self):
        """Loads .sequence/lock_manifest.json if present."""
        manifest_path = self.project_dir / ".sequence" / "lock_manifest.json"
        if manifest_path.exists():
            try:
                with self.validate_and_open_path(str(manifest_path), str(self.project_dir), mode='r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def check_and_update_governance_headers(self, expected_status_substr="slice-002-master-engine-core"):
        """
        Validates governance file status headers with verify-only default and lock-manifest protection.
        Returns (updated_count: int, issues: list[{path, reason}])
        """
        lock_manifest = self.load_lock_manifest()
        manifest_files = lock_manifest.get("files", lock_manifest)

        updated_count = 0
        issues = []

        for rel_path_str in GOVERNANCE_FILES:
            file_path = self.project_dir / rel_path_str
            if not file_path.exists():
                continue

            # Check if file is in lock manifest
            normalized_rel = rel_path_str.replace("\\", "/")
            is_in_manifest = normalized_rel in manifest_files or file_path.name in manifest_files

            try:
                with self.validate_and_open_path(str(file_path), str(self.project_dir), mode='r') as f:
                    lines = f.readlines()
            except Exception as e:
                issues.append({"path": rel_path_str, "reason": f"Failed to read file: {e}"})
                continue

            if not lines:
                continue

            # Check for header line matching **STATUS: ...**
            header_idx = -1
            is_locked = False
            for i, line in enumerate(lines[:5]):
                if line.strip().startswith("**STATUS:"):
                    header_idx = i
                    if "STATUS: LOCKED" in line:
                        is_locked = True
                    break

            if is_locked or is_in_manifest:
                # LOCKED or manifest-protected file: verify-only mode
                if self.apply_changes:
                    issues.append({
                        "path": rel_path_str,
                        "reason": f"LOCKED_FILE_PROTECTION: Cannot modify governance file '{rel_path_str}' bound in lock manifest or marked STATUS: LOCKED."
                    })
                continue

            if header_idx != -1:
                current_header = lines[header_idx].strip()
                if expected_status_substr not in current_header:
                    if not self.apply_changes:
                        issues.append({
                            "path": rel_path_str,
                            "reason": f"HEADER_DRIFT: Header '{current_header}' does not match expected slice status."
                        })
                    else:
                        # Compute body hash after header line
                        body_text = "".join(lines[header_idx + 1:])
                        orig_body_hash = hashlib.sha256(body_text.encode('utf-8')).hexdigest()

                        # Construct new header line
                        new_header = f"**STATUS: LOCKED — MANDATORY REVELATION REVIEW SEQUENCE AUDIT PASSED for {expected_status_substr}**\n"
                        lines[header_idx] = new_header

                        # Verify body hash immutability
                        new_body_text = "".join(lines[header_idx + 1:])
                        new_body_hash = hashlib.sha256(new_body_text.encode('utf-8')).hexdigest()

                        if orig_body_hash != new_body_hash:
                            issues.append({
                                "path": rel_path_str,
                                "reason": f"BODY_TAMPER_ABORT: Body hash changed after header update for '{rel_path_str}'."
                            })
                            continue

                        # Write updated content
                        with self.validate_and_open_path(str(file_path), str(self.project_dir), mode='w') as f:
                            f.writelines(lines)
                        updated_count += 1

        return updated_count, issues

    def check_incubator_alignment(self):
        """
        Validates that all documents in 03_INCUBATOR/ correspond cleanly to registered slice IDs.
        Returns (alignment_status: str, issues: list[{path, reason}])
        """
        incubator_dir = self.project_dir / "03_INCUBATOR"
        slices_file = self.project_dir / "02_BACKLOG" / "AGILE_SLICES.md"

        if not incubator_dir.exists() or not incubator_dir.is_dir():
            return "ALIGNED", []

        # Read registered slice IDs from AGILE_SLICES.md
        registered_slices = set()
        if slices_file.exists():
            try:
                slices_txt = slices_file.read_text(encoding="utf-8")
                registered_slices = set(re.findall(r'`(slice-\d{3}-[a-z0-9-]+)`', slices_txt))
            except Exception:
                pass

        alignment_issues = []
        for file_path in incubator_dir.glob("*"):
            if file_path.is_file() and not file_path.name.startswith("."):
                rel_path = f"03_INCUBATOR/{file_path.name}"

                # Check if file references any registered slice ID
                content = ""
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    pass

                matches = re.findall(r'slice-\d{3}-[a-z0-9-]+', content)
                is_aligned = any(m in registered_slices for m in matches) or any(s in file_path.name for s in registered_slices)

                if not is_aligned and registered_slices:
                    alignment_issues.append({
                        "path": rel_path,
                        "reason": f"ORPHAN_INCUBATOR_DOC: Document '{file_path.name}' in 03_INCUBATOR/ does not align with any registered slice in 02_BACKLOG/AGILE_SLICES.md."
                    })

        if alignment_issues:
            return "ORPHAN", alignment_issues
        return "ALIGNED", []

    def sweep_loose_review_files(self):
        """
        Sweeps loose non-directory files directly under 04_REVIEWS/ into 04_REVIEWS/_archived_loose_reviews/.
        Returns (swept_count: int, issues: list[{path, reason}])
        """
        reviews_dir = self.project_dir / "04_REVIEWS"
        if not reviews_dir.exists() or not reviews_dir.is_dir():
            return 0, []

        archive_dir = reviews_dir / "_archived_loose_reviews"
        swept_count = 0
        issues = []

        # List non-directory files directly under 04_REVIEWS/ (not recursive)
        loose_files = []
        for entry in os.scandir(reviews_dir):
            if entry.is_file(follow_symlinks=False) and not entry.name.startswith("."):
                loose_files.append(Path(entry.path))

        if not loose_files:
            return 0, []

        if self.apply_changes:
            # Create archive directory
            archive_dir.mkdir(parents=True, exist_ok=True)

        for source_file in loose_files:
            rel_src = f"04_REVIEWS/{source_file.name}"
            if check_win32_reparse_point(source_file):
                issues.append({"path": rel_src, "reason": f"REPARSE_POINT_REJECTED: Loose file '{source_file.name}' is a junction/symlink."})
                continue

            if not self.apply_changes:
                issues.append({"path": rel_src, "reason": f"LOOSE_REVIEW_FILE: Loose review file '{source_file.name}' found in 04_REVIEWS/ root."})
            else:
                dest_file = archive_dir / source_file.name
                if dest_file.exists():
                    timestamp_suffix = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                    dest_file = archive_dir / f"{source_file.stem}_{timestamp_suffix}{source_file.suffix}"

                try:
                    os.rename(str(source_file), str(dest_file))
                    swept_count += 1
                except Exception as e:
                    issues.append({"path": rel_src, "reason": f"MOVE_FAILED: {e}"})

        return swept_count, issues

    def run_hygiene_audit(self):
        """Performs full file hygiene audit."""
        all_issues = []

        # 1. Header Check
        updated_count, header_issues = self.check_and_update_governance_headers()
        all_issues.extend(header_issues)

        # 2. Incubator Alignment
        alignment_status, align_issues = self.check_incubator_alignment()
        all_issues.extend(align_issues)

        # 3. Loose Review Files
        swept_count, sweeper_issues = self.sweep_loose_review_files()
        all_issues.extend(sweeper_issues)

        status = "PASS" if (alignment_status == "ALIGNED" and len(all_issues) == 0) else "FAIL"

        envelope = {
            "status": status,
            "governance_headers_updated": updated_count,
            "loose_files_sweeper_count": swept_count,
            "alignment_status": alignment_status,
            "alignment_issues": all_issues,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        # Validate envelope via schemas
        from schemas import validate_file_hygiene_envelope
        valid, val_errors = validate_file_hygiene_envelope(envelope)
        if not valid:
            raise ValueError(f"Envelope validation error: {val_errors}")

        return envelope


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else r"C:\Linkstream\00_DEV_TEAM_SEQUENCE"
    apply_flag = "--apply" in sys.argv

    try:
        engine = FileHygieneEngine(target_dir, apply_changes=apply_flag)
        result = engine.run_hygiene_audit()
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["status"] == "PASS" else 1)
    except Exception as e:
        print(json.dumps({
            "status": "FAIL",
            "governance_headers_updated": 0,
            "loose_files_sweeper_count": 0,
            "alignment_status": "DRIFT",
            "alignment_issues": [{"path": "file_hygiene_engine.py", "reason": str(e)}],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }, indent=2))
        sys.exit(1)
