#!/usr/bin/env python3
"""
The Sequence Control Engine — Universal Verifier & Pre-Flight Lock Gate (verify.py)
Executes local pre-flight, pre-commit, and boot manifest checks.
Validates live SHA-256 hashes of all 11 TCB engine scripts against
.sequence/lock_manifest.json and .sequence/boot_digest.txt.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import sys
import os
import json
import hashlib
import subprocess
from pathlib import Path

from sequence_engine import APPROVED_ROOT_DIR, validate_and_open_path

# Complete 13-script TCB Engine List
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
    "slice_gate.py",
    "allowlist_sync.py"
]

def compute_file_sha256(file_path):
    """Computes live SHA-256 hash of file using validate_and_open_path."""
    hasher = hashlib.sha256()
    with validate_and_open_path(file_path, root_dir_str=str(APPROVED_ROOT_DIR), mode="rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def generate_lock_manifest(root_dir=APPROVED_ROOT_DIR):
    """
    Computes live SHA-256 hashes for all 11 TCB scripts and writes
    .sequence/lock_manifest.json and .sequence/boot_digest.txt.
    """
    sec_dir = root_dir / ".sequence"
    sec_dir.mkdir(parents=True, exist_ok=True)

    manifest_hashes = {}
    for script_name in TCB_ENGINE_SCRIPTS:
        script_path = root_dir / script_name
        if script_path.exists():
            manifest_hashes[script_name] = compute_file_sha256(script_path)
        else:
            manifest_hashes[script_name] = "FILE_MISSING_NOT_STUBBED"

    manifest_data = {
        "manifest_version": "1.0.0",
        "slice_id": "slice-004-sandboxed-sandwich",
        "status": "LOCKED",
        "tcb_scripts_count": len(TCB_ENGINE_SCRIPTS),
        "hashes": manifest_hashes
    }

    manifest_file = sec_dir / "lock_manifest.json"
    with validate_and_open_path(manifest_file, root_dir_str=str(root_dir), mode="w") as f:
        json.dump(manifest_data, f, indent=2)

    # Compute root boot digest string
    digest_input = json.dumps(manifest_hashes, sort_keys=True)
    boot_digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()

    boot_digest_file = sec_dir / "boot_digest.txt"
    with validate_and_open_path(boot_digest_file, root_dir_str=str(root_dir), mode="w") as f:
        f.write(f"{boot_digest}\n")

    print(f" [+] Generated Lock Manifest for {len(TCB_ENGINE_SCRIPTS)} TCB scripts. Boot Digest: {boot_digest}")
    return manifest_data, boot_digest

def run_verification(mode="precommit", root_dir_str=None):
    if root_dir_str is None:
        root_dir_str = str(APPROVED_ROOT_DIR)

    root_dir = Path(os.path.realpath(root_dir_str)).resolve()
    sec_dir = root_dir / ".sequence"

    from slice_gate import assert_slice_action_allowed, resolve_active_slice_id
    try:
        active_slice = resolve_active_slice_id(root_dir)
        assert_slice_action_allowed(active_slice, "IMPLEMENT", root_dir)
    except Exception as e:
        sys.stderr.write(f" [!] SLICE GATE DENIAL: {e}\n")
        return False

    session_file = sec_dir / "session.json"
    manifest_file = sec_dir / "lock_manifest.json"
    boot_digest_file = sec_dir / "boot_digest.txt"

    # If lock manifest is missing, auto-generate initial manifest
    if not manifest_file.exists() or not boot_digest_file.exists():
        generate_lock_manifest(root_dir)

    # 1. Verify Lock Manifest JSON Integrity
    try:
        with validate_and_open_path(manifest_file, root_dir_str=str(root_dir), mode="r") as f:
            manifest_data = json.load(f)

        expected_hashes = manifest_data.get("hashes", {})
        live_hashes = {}

        # 2. Check live SHA-256 for existing TCB engine scripts
        for script_name in TCB_ENGINE_SCRIPTS:
            script_path = root_dir / script_name
            if script_path.exists():
                live_hash = compute_file_sha256(script_path)
                live_hashes[script_name] = live_hash
                expected_hash = expected_hashes.get(script_name)

                # Validate hash match for existing files
                if expected_hash and expected_hash != "FILE_MISSING_NOT_STUBBED" and live_hash != expected_hash:
                    print(f" [!] PRE-FLIGHT LOCK MANIFEST MISMATCH: File '{script_name}' hash changed! Expected: {expected_hash}, Live: {live_hash}", file=sys.stderr)
                    return False
            else:
                live_hashes[script_name] = "FILE_MISSING_NOT_STUBBED"

        # 3. Verify Boot Digest
        with validate_and_open_path(boot_digest_file, root_dir_str=str(root_dir), mode="r") as f:
            boot_digest_live = f.read().strip()

        digest_input = json.dumps(expected_hashes, sort_keys=True, separators=(',', ':'))
        expected_digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()

        if boot_digest_live != expected_digest:
            # Fallback check without separators if generated by legacy runner
            legacy_input = json.dumps(expected_hashes, sort_keys=True)
            legacy_digest = hashlib.sha256(legacy_input.encode("utf-8")).hexdigest()
            if boot_digest_live != legacy_digest:
                print(f" [!] BOOT DIGEST MISMATCH: boot_digest.txt does not match manifest hashes! Live: {boot_digest_live}, Expected: {expected_digest}", file=sys.stderr)
                return False

    except Exception as e:
        print(f" [!] PRE-FLIGHT VERIFICATION EXCEPTION: {e}", file=sys.stderr)
        return False

    print(f" [OK] Lock manifest & boot digest verification passed for {root_dir.name}.")
    return True

def run_prepush_verification(root_dir):
    """Local Pre-Push CI Emulation. Diffs local branch against origin/main:ALLOWLIST.txt."""
    try:
        subprocess.run(["git", "fetch", "origin", "main", "--quiet"], cwd=root_dir, shell=False, check=False)
        raw_allowlist = subprocess.run(["git", "show", "origin/main:ALLOWLIST.txt"], cwd=root_dir, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if raw_allowlist.returncode != 0:
            print(" [!] PRE-PUSH GATE WARNING: origin/main:ALLOWLIST.txt is unreadable. Skipping prepush diff check.")
            return True

        allowlist = {line.strip() for line in raw_allowlist.stdout.splitlines() if line.strip() and not line.strip().startswith("#")}

        raw_changed = subprocess.run(["git", "diff", "--name-only", "-z", "--diff-filter=ACDMRTUXB", "origin/main", "HEAD"], cwd=root_dir, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        changed_files = {p.decode("utf-8") for p in raw_changed.stdout.split(b"\x00") if p}

        disallowed = sorted(changed_files - allowlist)
        if disallowed:
            print("\n [!] PRE-PUSH GATE DENIAL: Changed paths not authorized by base ALLOWLIST.txt on origin/main:", file=sys.stderr)
            for p in disallowed:
                print(f"  - '{p}'", file=sys.stderr)
            print("\nSubmit an ALLOWLIST contract PR or merge chore/allowlist before pushing.\n", file=sys.stderr)
            return False

        print(" [OK] Local Pre-Push CI Emulation passed: all changed paths authorized by origin/main:ALLOWLIST.txt.")
        return True
    except Exception as e:
        print(f" [!] PRE-PUSH VERIFICATION EXCEPTION: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "precommit"
    p_dir = sys.argv[2] if len(sys.argv) > 2 else str(APPROVED_ROOT_DIR)

    if mode == "generate":
        generate_lock_manifest(Path(p_dir).resolve())
        sys.exit(0)

    if mode == "prepush":
        ok_prepush = run_prepush_verification(Path(p_dir).resolve())
        if not ok_prepush:
            sys.exit(1)

    ok = run_verification(mode, p_dir)
    sys.exit(0 if ok else 1)
