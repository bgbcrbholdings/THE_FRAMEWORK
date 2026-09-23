#!/usr/bin/env python3
"""
The Sequence Control Engine — Tier 0 Control Script Guard (control_script_guard.py)
Provides execution-time self-attestation, control-plane manifest SHA-256 integrity verification,
and subprocess worker isolation (jail) to prevent packet poisoning, token leaks, and script mutation.

Exit Codes:
  Exit 101: Control script SHA-256 hash breach detected against CONTROL_PLANE_MANIFEST.json.
"""

import sys
import os
import json
import hashlib
import subprocess
from pathlib import Path

# TOXIC ENVIRONMENT VARIABLE DENYLIST (Case-Insensitive Match or Prefix Match)
TOXIC_ENV_DENYLIST = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "POISONED_TOKEN",
    "GEMINI_API_KEY",
    "GITHUB_PERSONAL_ACCESS_TOKEN",
    "TAVILY_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN"
}

TOXIC_PREFIXES = (
    "SECRET_",
    "TOKEN_",
    "KEY_",
    "AUTH_"
)


def compute_file_sha256(file_path: Path) -> str:
    """Computes live SHA-256 digest of a target file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_control_plane_integrity(manifest_path: Path = None, root_dir: Path = None) -> bool:
    """
    Verifies live SHA-256 hashes of all control scripts registered in CONTROL_PLANE_MANIFEST.json.
    Raises SystemExit(101) immediately on any hash mismatch, tampered script, or missing control script.
    """
    if root_dir is None:
        root_dir = Path(os.getcwd()).resolve()
    else:
        root_dir = Path(root_dir).resolve()

    if manifest_path is None:
        manifest_path = root_dir / "01_GOVERNANCE" / "CONTROL_PLANE_MANIFEST.json"
    else:
        manifest_path = Path(manifest_path).resolve()

    if not manifest_path.exists():
        sys.stderr.write(f"\n[FATAL HASH BREACH - EXIT 101] Control plane manifest missing at: {manifest_path}\n\n")
        sys.exit(101)

    try:
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        sys.stderr.write(f"\n[FATAL HASH BREACH - EXIT 101] Corrupted control plane manifest: {e}\n\n")
        sys.exit(101)

    scripts = manifest_data.get("scripts", {})
    breaches = []

    for script_name, spec in scripts.items():
        rel_path = spec.get("path", script_name)
        expected_hash = spec.get("sha256")
        target_path = root_dir / rel_path

        if not target_path.exists():
            breaches.append(f"MISSING: {script_name} (Expected: {expected_hash})")
            continue

        live_hash = compute_file_sha256(target_path)
        if live_hash != expected_hash:
            breaches.append(f"TAMPERED: {script_name} (Expected: {expected_hash}, Live: {live_hash})")

    if breaches:
        sys.stderr.write("\n=========================================================\n")
        sys.stderr.write("FATAL CONTROL PLANE INTEGRITY BREACH DETECTED (EXIT 101)\n")
        sys.stderr.write("=========================================================\n")
        for b in breaches:
            sys.stderr.write(f"  -> {b}\n")
        sys.stderr.write("\nRefusing to execute control plane operations under tampered environment.\n\n")
        sys.exit(101)

    return True


def build_jailed_environment(base_env: dict = None) -> dict:
    """
    Builds a sanitized environment dictionary for subprocess isolation.
    Strips proxy overrides, pythonpath injection vectors, and secret tokens.
    """
    if base_env is None:
        base_env = os.environ

    clean_env = {}
    for key, value in base_env.items():
        key_upper = key.upper()

        if key_upper in TOXIC_ENV_DENYLIST:
            continue

        if any(key_upper.startswith(prefix) for prefix in TOXIC_PREFIXES):
            continue

        clean_env[key] = value

    return clean_env


def run_jailed_worker(cmd_args: list, cwd: Path = None, base_env: dict = None, timeout: int = 300) -> subprocess.CompletedProcess:
    """
    Executes a worker command in a sanitized subprocess jail.
    """
    jailed_env = build_jailed_environment(base_env)
    return subprocess.run(
        cmd_args,
        cwd=cwd,
        env=jailed_env,
        capture_output=True,
        text=True,
        timeout=timeout
    )


if __name__ == "__main__":
    verify_control_plane_integrity()
    print("[OK] Tier 0 Control Script Guard self-attestation passed cleanly.")
