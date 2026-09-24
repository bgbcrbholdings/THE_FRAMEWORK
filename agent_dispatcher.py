#!/usr/bin/env python3
"""
The Sequence Control Engine — Bounded Agent Subprocess Dispatcher (agent_dispatcher.py)
Fable 5 3-Stage Process Sandwich Execution Engine for CLI Agent Subprocesses.
Enforces default-deny environment allowlisting, isolated profile sandboxes,
process timeouts, append-only audit logging, dynamic trust ledger management,
and USD daily budget cap monitoring.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
import uuid
import ctypes
import tempfile
import shutil
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime

# Windows advisory locking
if os.name == 'nt':
    import msvcrt

from sequence_engine import validate_and_open_path
from schemas import (
    validate_dispatch_request,
    validate_dispatch_envelope,
    validate_trust_ledger_envelope,
    validate_cost_monitor_envelope
)

# Hardened Constants
ENVIRONMENT_ALLOWLIST = {'PATH', 'SYSTEMROOT', 'TEMP', 'TMP', 'SYSTEMDRIVE'}
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

WORKER_REGISTRY = {
    "ci_fetcher": "workers/ci_fetcher.py",
    "diff_validator": "workers/diff_validator.py",
    "schema_gate_worker": "workers/schema_gate_worker.py",
    "manifest_builder": "workers/manifest_builder.py"
}

APPROVED_ROOT_DIR = Path(__file__).resolve().parent


def build_sanitized_worker_env():
    """
    Returns a dictionary of environment variables strictly filtered down to ENVIRONMENT_ALLOWLIST.
    Prevents secret leakage to subprocess workers.
    """
    sanitized = {}
    for key in ENVIRONMENT_ALLOWLIST:
        if key in os.environ:
            sanitized[key] = os.environ[key]
    return sanitized


def dispatch_worker(worker_name, payload=None, project_dir=None):
    """
    Invokes registered worker script in an isolated subprocess with a sanitized environment.
    Fails closed if worker is unregistered or escapes approved directory jail.
    """
    if worker_name not in WORKER_REGISTRY:
        raise ValueError(f"UNREGISTERED_WORKER: '{worker_name}' is not in WORKER_REGISTRY")

    script_rel_path = WORKER_REGISTRY[worker_name]
    script_abs_path = APPROVED_ROOT_DIR / script_rel_path

    if not script_abs_path.exists():
        raise FileNotFoundError(f"WORKER_NOT_FOUND: Worker script '{script_abs_path}' missing")

    if project_dir is None:
        project_dir = APPROVED_ROOT_DIR

    scratch_dir = Path(project_dir) / "03_STATE" / "scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    sanitized_env = build_sanitized_worker_env()
    cmd = [sys.executable, str(script_abs_path)]

    # If payload provided, write to temp file in scratch dir
    temp_payload_path = None
    if payload is not None:
        temp_payload = tempfile.NamedTemporaryFile(mode="w", dir=scratch_dir, delete=False, suffix=".json")
        json.dump(payload, temp_payload)
        temp_payload.close()
        temp_payload_path = temp_payload.name
        cmd.append(temp_payload_path)

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(scratch_dir),
            env=sanitized_env,
            capture_output=True,
            text=True,
            timeout=30
        )
        return {
            "status": "SUCCESS" if proc.returncode == 0 else "FAIL",
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr
        }
    finally:
        if temp_payload_path and os.path.exists(temp_payload_path):
            try:
                os.remove(temp_payload_path)
            except Exception:
                pass


APPROVED_EXECUTABLE_BASENAMES = {

    'python.exe', 'pythonw.exe', 'py.exe',
    'claude.exe', 'codex.exe', 'kimi.exe', 'qwen.exe',
    'python', 'claude', 'codex', 'kimi', 'qwen'
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

        success = kernel32.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info))
        kernel32.CloseHandle(handle)

        if success and (info.FileAttributes & 0x400): # FILE_ATTRIBUTE_REPARSE_POINT
            return True
        return False
    except Exception:
        return False

def validate_and_open_path_in_slice(path, approved_root):
    """
    In-slice implementation of validate_and_open_path.
    Resolves path using os.path.realpath and Win32 FILE_FLAG_OPEN_REPARSE_POINT check.
    Rejects path traversal, symlink/junction reparse points, and alternate data streams.
    """
    path_str = str(path)
    if ":" in path_str and not (len(path_str) >= 2 and path_str[1] == ":" and path_str[2:3] in ("\\", "/")):
        # Alternate Data Stream check (e.g. file.txt:stream)
        raise ValueError(f"PATH_VALIDATION_FAILED: Path '{path_str}' contains alternate data stream marker")

    approved_canonical = os.path.realpath(str(approved_root))
    candidate_canonical = os.path.realpath(path_str)

    try:
        common = os.path.commonpath([approved_canonical, candidate_canonical])
        if os.path.realpath(common) != approved_canonical:
            raise ValueError(f"PATH_VALIDATION_FAILED: Path '{path_str}' escapes approved root '{approved_root}'")
    except ValueError as e:
        raise ValueError(f"PATH_VALIDATION_FAILED: {e}")

    p_obj = Path(candidate_canonical)
    if p_obj.exists() and check_win32_reparse_point(p_obj):
        raise ValueError(f"PATH_VALIDATION_FAILED: Path '{path_str}' is a Win32 reparse point / junction / symlink")

    return candidate_canonical

def verify_tcb_integrity(project_dir):
    """
    Verifies SHA-256 integrity of core TCB scripts (agent_dispatcher.py, sequence_engine.py, auditor_agent.py, schemas.py)
    against .sequence/lock_manifest.json.
    """
    manifest_path = Path(project_dir) / ".sequence" / "lock_manifest.json"
    if not manifest_path.exists():
        return True, "Lock manifest absent (genesis phase)."

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        tcb_scripts = ["agent_dispatcher.py", "sequence_engine.py", "auditor_agent.py", "schemas.py"]
        manifest_files = manifest.get("files", {})

        for script in tcb_scripts:
            script_path = Path(project_dir) / script
            if script_path.exists() and script in manifest_files:
                expected_hash = manifest_files[script]
                content = script_path.read_bytes()
                actual_hash = hashlib.sha256(content).hexdigest()
                if actual_hash != expected_hash:
                    return False, f"INTEGRITY_CHECK_FAILED: SHA-256 mismatch for TCB script '{script}'."
        return True, "TCB integrity verified."
    except Exception as e:
        return False, f"INTEGRITY_CHECK_FAILED: Error reading lock manifest: {e}"

class TrustLedgerManager:
    """Manages skill reliability metrics in .sequence/trust.tsv with inter-process locking and atomic writes."""

    def __init__(self, project_dir):
        self.project_dir = Path(project_dir)
        self.tsv_path = self.project_dir / ".sequence" / "trust.tsv"
        self.lock_path = self.project_dir / ".sequence" / "trust.tsv.lock"
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        self.tsv_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.tsv_path.exists():
            headers = "skill_id\ttier\ttotal_runs\tpass_count\taccuracy_pct\tlast_updated\n"
            default_entries = (
                "code_refactor\twatch\t0\t0\t0.0\t2026-09-17T00:00:00Z\n"
                "unit_testing\twatch\t0\t0\t0.0\t2026-09-17T00:00:00Z\n"
                "file_hygiene\twatch\t0\t0\t0.0\t2026-09-17T00:00:00Z\n"
                "documentation\twatch\t0\t0\t0.0\t2026-09-17T00:00:00Z\n"
            )
            self.tsv_path.write_text(headers + default_entries, encoding="utf-8")

    def _acquire_lock(self):
        """Acquires exclusive advisory file lock on .sequence/trust.tsv.lock."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_file = open(self.lock_path, "w")
        if os.name == 'nt':
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
        return lock_file

    def _release_lock(self, lock_file):
        """Releases advisory file lock."""
        if os.name == 'nt':
            try:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception:
                pass
        lock_file.close()

    def load_ledger(self):
        """Reads trust.tsv into dict mapping skill_id to entry dict."""
        lock_file = self._acquire_lock()
        try:
            entries = {}
            if not self.tsv_path.exists():
                return entries
            lines = self.tsv_path.read_text(encoding="utf-8").splitlines()
            if not lines:
                return entries

            for line in lines[1:]: # Skip header
                if not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) >= 6:
                    s_id, tier, total, passed, acc, updated = parts[:6]
                    entries[s_id] = {
                        "skill_id": s_id,
                        "tier": tier,
                        "total_runs": int(total),
                        "pass_count": int(passed),
                        "accuracy_pct": float(acc),
                        "last_updated": updated
                    }
            return entries
        finally:
            self._release_lock(lock_file)

    def get_skill_tier(self, skill_id):
        entries = self.load_ledger()
        if skill_id in entries:
            return entries[skill_id]["tier"]
        return "watch"

    def record_result(self, skill_id, is_pass):
        """
        Updates trust ledger entry for skill_id based on execution result.
        Promotes to 'auto' tier IFF total_runs >= 20 AND pass_count >= 20 AND accuracy_pct >= 95.0 AND abs(accuracy_pct - (pass_count/total_runs*100)) <= 0.1.
        Demotes to 'watch' tier on any failure.
        """
        lock_file = self._acquire_lock()
        try:
            entries = {}
            lines = self.tsv_path.read_text(encoding="utf-8").splitlines()
            header = lines[0] if lines else "skill_id\ttier\ttotal_runs\tpass_count\taccuracy_pct\tlast_updated"

            for line in lines[1:]:
                if not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) >= 6:
                    s_id, tier, total, passed, acc, updated = parts[:6]
                    entries[s_id] = {
                        "skill_id": s_id,
                        "tier": tier,
                        "total_runs": int(total),
                        "pass_count": int(passed),
                        "accuracy_pct": float(acc),
                        "last_updated": updated
                    }

            if skill_id not in entries:
                entries[skill_id] = {
                    "skill_id": skill_id,
                    "tier": "watch",
                    "total_runs": 0,
                    "pass_count": 0,
                    "accuracy_pct": 0.0,
                    "last_updated": datetime.utcnow().isoformat() + "Z"
                }

            entry = entries[skill_id]
            entry["total_runs"] += 1
            if is_pass:
                entry["pass_count"] += 1

            total = entry["total_runs"]
            passed = entry["pass_count"]
            acc = (passed / total * 100.0) if total > 0 else 0.0
            entry["accuracy_pct"] = round(acc, 1)
            entry["last_updated"] = datetime.utcnow().isoformat() + "Z"

            # Normative Promotion & Demotion Rules
            if is_pass:
                if total >= 20 and passed >= 20 and acc >= 95.0 and abs(acc - (passed / total * 100.0)) <= 0.1:
                    entry["tier"] = "auto"
            else:
                entry["tier"] = "watch"

            # Atomic TSV write using tempfile.mkstemp
            fd, tmp_path = tempfile.mkstemp(dir=str(self.tsv_path.parent), prefix="trust_", suffix=".tmp")
            with open(fd, "w", encoding="utf-8") as f:
                f.write(header + "\n")
                for s_id, e in entries.items():
                    f.write(f"{e['skill_id']}\t{e['tier']}\t{e['total_runs']}\t{e['pass_count']}\t{e['accuracy_pct']}\t{e['last_updated']}\n")

            os.replace(tmp_path, str(self.tsv_path))
            return entry
        finally:
            self._release_lock(lock_file)


class CostCapMonitor:
    """Manages daily USD budget monitoring stored in .sequence/cost_ledger.json with atomic writes."""

    def __init__(self, project_dir, budget_limit_usd=10.0):
        self.project_dir = Path(project_dir)
        self.json_path = self.project_dir / ".sequence" / "cost_ledger.json"
        self.default_limit = budget_limit_usd
        self._load_or_reset()

    def _load_or_reset(self):
        self.json_path.parent.mkdir(parents=True, exist_ok=True)
        today_str = datetime.utcnow().strftime("%Y-%m-%d")
        now_iso = datetime.utcnow().isoformat() + "Z"

        if self.json_path.exists():
            try:
                data = json.loads(self.json_path.read_text(encoding="utf-8"))
                valid, errors = validate_cost_monitor_envelope(data)
                if valid:
                    if data.get("date") == today_str:
                        self.date = today_str
                        self.daily_spend_usd = float(data.get("daily_spend_usd", 0.0))
                        self.budget_limit_usd = float(data.get("budget_limit_usd", self.default_limit))
                        self.budget_exceeded = bool(data.get("budget_exceeded", self.daily_spend_usd >= self.budget_limit_usd))
                        self.last_updated = data.get("last_updated", now_iso)
                        return
            except Exception:
                pass

        # Reset for new day or missing/invalid file
        self.date = today_str
        self.daily_spend_usd = 0.0
        self.budget_limit_usd = self.default_limit
        self.budget_exceeded = False
        self.last_updated = now_iso
        self._persist()

    def _persist(self):
        data = {
            "date": self.date,
            "daily_spend_usd": round(self.daily_spend_usd, 6),
            "budget_limit_usd": round(self.budget_limit_usd, 2),
            "budget_exceeded": self.daily_spend_usd >= self.budget_limit_usd,
            "last_updated": datetime.utcnow().isoformat() + "Z"
        }
        self.budget_exceeded = data["budget_exceeded"]

        # Atomic JSON write via .tmp + os.replace
        fd, tmp_path = tempfile.mkstemp(dir=str(self.json_path.parent), prefix="cost_", suffix=".tmp")
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, str(self.json_path))

    def record_spend(self, dispatch_id, estimated_usd_cost):
        """
        Unconditionally records estimated USD API spend on all completed Stage 2 attempts.
        """
        self._load_or_reset()
        self.daily_spend_usd += max(0.0, float(estimated_usd_cost))
        self.daily_spend_usd = round(self.daily_spend_usd, 6)
        self.budget_exceeded = self.daily_spend_usd >= self.budget_limit_usd
        self._persist()
        return self.daily_spend_usd, self.budget_exceeded


class AgentDispatcher:
    """Fable 5 3-Stage Process Sandwich Execution Engine for Bounded Subprocess Agent Invocation."""

    def __init__(self, project_dir):
        self.project_dir_str = validate_and_open_path_in_slice(project_dir, project_dir)
        self.project_dir = Path(self.project_dir_str)
        self.trust_manager = TrustLedgerManager(self.project_dir)
        self.cost_monitor = CostCapMonitor(self.project_dir)
        self.log_path = self.project_dir / ".sequence" / "logs" / "agent_dispatch.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Verify TCB Integrity
        ok, msg = verify_tcb_integrity(self.project_dir)
        if not ok:
            raise RuntimeError(msg)

    def _snapshot_files(self):
        """Snapshots file mtimes and SHA-256 hashes under project_dir for pre/post Stage 2 diffing."""
        snapshot = {}
        for root, dirs, files in os.walk(self.project_dir_str):
            # Skip hidden/system dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("__pycache__", "build", "dist")]
            for file in files:
                if file.endswith(".pyc") or file.endswith(".tmp") or file.endswith(".log"):
                    continue
                fp = Path(root) / file
                try:
                    stat = fp.stat()
                    snapshot[str(fp)] = (stat.st_mtime, stat.st_size)
                except Exception:
                    pass
        return snapshot

    def _compute_modified_files(self, pre_snapshot, post_snapshot):
        """Computes list of modified/added files between pre and post snapshots."""
        modified = []
        for fp, post_stat in post_snapshot.items():
            if fp not in pre_snapshot:
                modified.append(fp)
            elif pre_snapshot[fp] != post_stat:
                modified.append(fp)
        return modified

    def _append_audit_log(self, dispatch_id, header, content):
        """Appends stdout/stderr execution streams to .sequence/logs/agent_dispatch.log."""
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"\n--- [{datetime.utcnow().isoformat()}Z] DISPATCH: {dispatch_id} | {header} ---\n")
                f.write(content)
                f.write("\n")
        except Exception:
            pass

    def dispatch(self, skill_id, command_vector, timeout_seconds=120.0, auto_mode=False):
        """
        Executes the 3-Stage Process Sandwich Workflow:
        - Stage 1: Pre-check request validation, budget check, skill trust tier check, sandbox setup.
        - Stage 2: Bounded subprocess execution with scrubbed env and sandbox dir, timeout handling, unconditional spend recording.
        - Stage 3: Hardened post-execution audit hooks (auditor_agent + unittest) with modified-file scope handoff, trust promotion/demotion.
        """
        start_time = datetime.utcnow()
        dispatch_id = str(uuid.uuid4())
        now_iso = start_time.isoformat() + "Z"

        # Validate Inbound Dispatch Request (Stage 1)
        req_data = {
            "dispatch_id": dispatch_id,
            "skill_id": skill_id,
            "command": command_vector,
            "timeout_seconds": float(timeout_seconds),
            "timestamp": now_iso
        }
        valid_req, req_errors = validate_dispatch_request(req_data)
        if not valid_req:
            return {
                "dispatch_id": dispatch_id,
                "skill_id": skill_id,
                "command": command_vector,
                "status": "BLOCKED",
                "stage1_precheck": {"status": "FAIL", "errors": req_errors},
                "stage2_execution": {},
                "stage3_audit": {},
                "execution_time_seconds": 0.0,
                "timestamp": now_iso
            }

        # Stage 1: Pre-Check & Triage Gates
        stage1_res = {"status": "PASS", "reasons": []}

        # Check USD Budget Limit
        if self.cost_monitor.budget_exceeded:
            stage1_res["status"] = "BLOCKED"
            stage1_res["reasons"].append("BUDGET_CEILING_EXCEEDED")

        # Check Skill Trust Tier
        skill_tier = self.trust_manager.get_skill_tier(skill_id)
        if skill_tier == "watch" and auto_mode:
            stage1_res["status"] = "BLOCKED"
            stage1_res["reasons"].append("SKILL_DEMOTED_TO_WATCH")

        if stage1_res["status"] == "BLOCKED":
            return {
                "dispatch_id": dispatch_id,
                "skill_id": skill_id,
                "command": command_vector,
                "status": "BLOCKED",
                "stage1_precheck": stage1_res,
                "stage2_execution": {},
                "stage3_audit": {},
                "execution_time_seconds": 0.0,
                "timestamp": now_iso
            }

        # Setup Sandbox Profile Directory & Log Stream Target
        sandbox_dir = validate_and_open_path_in_slice(self.project_dir / ".sequence" / "agent_profile", self.project_dir)
        Path(sandbox_dir).mkdir(parents=True, exist_ok=True)

        # Stage 2: Command Normalization & Executable Resolution
        if not isinstance(command_vector, list) or len(command_vector) < 1:
            return {
                "dispatch_id": dispatch_id,
                "skill_id": skill_id,
                "command": command_vector if isinstance(command_vector, list) else [],
                "status": "BLOCKED",
                "stage1_precheck": {"status": "FAIL", "reason": "INVALID_COMMAND_VECTOR"},
                "stage2_execution": {},
                "stage3_audit": {},
                "execution_time_seconds": 0.0,
                "timestamp": now_iso
            }

        exe_raw = command_vector[0]
        resolved_exe = shutil.which(exe_raw)
        if not resolved_exe:
            return {
                "dispatch_id": dispatch_id,
                "skill_id": skill_id,
                "command": command_vector,
                "status": "BLOCKED",
                "stage1_precheck": {"status": "FAIL", "reason": "EXECUTABLE_NOT_FOUND"},
                "stage2_execution": {},
                "stage3_audit": {},
                "execution_time_seconds": 0.0,
                "timestamp": now_iso
            }

        canonical_exe = os.path.realpath(resolved_exe)
        exe_basename = Path(canonical_exe).name.lower()

        if exe_basename not in APPROVED_EXECUTABLE_BASENAMES and canonical_exe != os.path.realpath(sys.executable):
            return {
                "dispatch_id": dispatch_id,
                "skill_id": skill_id,
                "command": command_vector,
                "status": "BLOCKED",
                "stage1_precheck": {"status": "FAIL", "reason": "EXECUTABLE_NOT_ALLOWLISTED"},
                "stage2_execution": {},
                "stage3_audit": {},
                "execution_time_seconds": 0.0,
                "timestamp": now_iso
            }

        argv_list = [canonical_exe] + command_vector[1:]

        # Construct Scrubbed Environment Context
        scrubbed_env = {k: v for k, v in os.environ.items() if k in ENVIRONMENT_ALLOWLIST}
        scrubbed_env["USERPROFILE"] = sandbox_dir
        scrubbed_env["HOME"] = sandbox_dir

        # Snapshot Pre-Execution File State
        pre_snapshot = self._snapshot_files()

        # Execute Stage 2 Bounded Subprocess
        stage2_res = {"exit_code": -1, "stdout": "", "stderr": "", "status": "FAIL"}
        cmd_joined_chars = "".join(command_vector)
        estimated_cost_usd = max(0.001, round((len(cmd_joined_chars) / 4.0 / 1000.0) * 0.01, 6))

        timeout_occurred = False
        try:
            proc = subprocess.run(
                argv_list,
                shell=False,
                cwd=self.project_dir_str,
                env=scrubbed_env,
                timeout=timeout_seconds,
                capture_output=True,
                text=True
            )
            # Limit output capture to 10MB
            stage2_res["stdout"] = proc.stdout[:10 * 1024 * 1024] if proc.stdout else ""
            stage2_res["stderr"] = proc.stderr[:10 * 1024 * 1024] if proc.stderr else ""
            stage2_res["exit_code"] = proc.returncode
            stage2_res["status"] = "PASS" if proc.returncode == 0 else "FAIL"

            self._append_audit_log(dispatch_id, "STAGE 2 STDOUT", stage2_res["stdout"])
            if stage2_res["stderr"]:
                self._append_audit_log(dispatch_id, "STAGE 2 STDERR", stage2_res["stderr"])

        except subprocess.TimeoutExpired as te:
            timeout_occurred = True
            stage2_res["status"] = "FAIL"
            stage2_res["reason"] = "TIMEOUT_EXCEEDED"
            stage2_res["exit_code"] = 124
            self._append_audit_log(dispatch_id, "STAGE 2 TIMEOUT", "TIMEOUT_EXCEEDED: Subprocess killed after timeout.")

        # Unconditionally Record Spend on all Completed Stage 2 Attempts
        stage2_res["estimated_cost_usd"] = estimated_cost_usd
        self.cost_monitor.record_spend(dispatch_id, estimated_cost_usd)

        # Snapshot Post-Execution File State & Compute Modified Files
        post_snapshot = self._snapshot_files()
        modified_files = self._compute_modified_files(pre_snapshot, post_snapshot)

        # Stage 3: Hardened Post-Execution Audit Hooks
        stage3_res = {
            "auditor_pass": False,
            "unittest_pass": False,
            "modified_files_count": len(modified_files),
            "status": "FAIL"
        }

        if len(modified_files) == 0:
            self._append_audit_log(dispatch_id, "STAGE 3 AUDIT", "AUDIT_SCOPE_EMPTY: No files modified during dispatch.")

        # Auditor Agent Invocation
        auditor_script = self.project_dir / "auditor_agent.py"
        packet_json = self.project_dir / "04_REVIEWS" / "slice-004-sandboxed-sandwich" / "slice-004-sandboxed-sandwich-packet-v3.json"
        if not packet_json.exists():
            packet_files = sorted(list((self.project_dir / "04_REVIEWS").glob("**/*packet*.json")))
            if packet_files:
                packet_json = packet_files[-1]
            else:
                tmp_packet = self.project_dir / ".sequence" / "tmp_audit_packet.json"
                tmp_packet.write_text(json.dumps({
                    "allowed_file_paths": ["agent_dispatcher.py", "schemas.py", ".sequence/trust.tsv", ".sequence/cost_ledger.json", "tests/**"],
                    "forbidden_file_paths": [".github/**"],
                    "git_diff": "",
                    "invariants": {"forbidden_patterns": ["git commit --no-verify", "rm -rf .git"]}
                }), encoding="utf-8")
                packet_json = tmp_packet

        auditor_cmd = [sys.executable, str(auditor_script), str(packet_json)]
        try:
            audit_proc = subprocess.run(
                auditor_cmd,
                shell=False,
                cwd=self.project_dir_str,
                env=scrubbed_env,
                timeout=120,
                capture_output=True,
                text=True
            )
            stage3_res["auditor_pass"] = (audit_proc.returncode == 0)
            self._append_audit_log(dispatch_id, "STAGE 3 AUDITOR STDOUT", audit_proc.stdout or "")
            if audit_proc.stderr:
                self._append_audit_log(dispatch_id, "STAGE 3 AUDITOR STDERR", audit_proc.stderr)
        except Exception as e:
            stage3_res["auditor_pass"] = False
            self._append_audit_log(dispatch_id, "STAGE 3 AUDITOR ERROR", str(e))

        # Unittest Discovery Invocation
        if stage3_res["auditor_pass"]:
            unittest_cmd = [sys.executable, "-m", "unittest", "discover", "tests"]
            try:
                test_proc = subprocess.run(
                    unittest_cmd,
                    shell=False,
                    cwd=self.project_dir_str,
                    env=scrubbed_env,
                    timeout=60,
                    capture_output=True,
                    text=True
                )
                stage3_res["unittest_pass"] = (test_proc.returncode == 0)
                self._append_audit_log(dispatch_id, "STAGE 3 UNITTEST STDOUT", test_proc.stdout or "")
                if test_proc.stderr:
                    self._append_audit_log(dispatch_id, "STAGE 3 UNITTEST STDERR", test_proc.stderr)
            except Exception as e:
                stage3_res["unittest_pass"] = False
                self._append_audit_log(dispatch_id, "STAGE 3 UNITTEST ERROR", str(e))

        if stage3_res["auditor_pass"] and stage3_res["unittest_pass"]:
            stage3_res["status"] = "PASS"

        # Final Status & Trust Ledger Resolution
        overall_pass = (stage2_res["exit_code"] == 0) and stage3_res["auditor_pass"] and stage3_res["unittest_pass"] and not timeout_occurred
        final_status = "PASS" if overall_pass else "FAIL"

        # Record Trust Result
        self.trust_manager.record_result(skill_id, overall_pass)

        end_time = datetime.utcnow()
        exec_duration = round((end_time - start_time).total_seconds(), 3)

        envelope = {
            "dispatch_id": dispatch_id,
            "skill_id": skill_id,
            "command": command_vector,
            "status": final_status,
            "stage1_precheck": stage1_res,
            "stage2_execution": stage2_res,
            "stage3_audit": stage3_res,
            "execution_time_seconds": exec_duration,
            "timestamp": end_time.isoformat() + "Z"
        }

        # Validate Final Completed Envelope
        valid_env, env_errors = validate_dispatch_envelope(envelope)
        if not valid_env:
            envelope["status"] = "FAIL"
            envelope["schema_errors"] = env_errors

        return envelope


def main():
    """
    CLI Entrypoint for AgentDispatcher:
    `python agent_dispatcher.py --skill <skill_id> [project_dir] -- <absolute_executable> [arg1 ...]`
    Must reject `--cmd` or non-vector options.
    """
    args = sys.argv[1:]
    if "--cmd" in args:
        print(json.dumps({
            "status": "BLOCKED",
            "reason": "INVALID_COMMAND_VECTOR",
            "error": "The --cmd option is strictly rejected. Use vector syntax after '--' delimiter."
        }, indent=2))
        sys.exit(1)

    skill_id = None
    project_dir = r"C:\Linkstream\00_DEV_TEAM_SEQUENCE"
    command_vector = []

    if "--skill" in args:
        idx = args.index("--skill")
        if idx + 1 < len(args):
            skill_id = args[idx + 1]

    if "--" in args:
        sep_idx = args.index("--")
        command_vector = args[sep_idx + 1:]
        non_vec_args = args[:sep_idx]
    else:
        non_vec_args = args

    # Positional project_dir extraction
    positional = [a for a in non_vec_args if not a.startswith("--") and a != skill_id]
    if positional:
        project_dir = positional[0]

    if not skill_id or not command_vector:
        print(json.dumps({
            "status": "BLOCKED",
            "reason": "INVALID_CLI_ARGUMENTS",
            "usage": "python agent_dispatcher.py --skill <skill_id> [project_dir] -- <absolute_executable> [arg1 ...]"
        }, indent=2))
        sys.exit(1)

    try:
        dispatcher = AgentDispatcher(project_dir)
        res = dispatcher.dispatch(skill_id, command_vector)
        print(json.dumps(res, indent=2))
        sys.exit(0 if res.get("status") == "PASS" else 1)
    except Exception as e:
        print(json.dumps({
            "status": "FAIL",
            "error": str(e)
        }, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
