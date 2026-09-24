#!/usr/bin/env python3
"""
Deterministic Worker: manifest_builder.py
Generates SHA-256 Merkle manifests over directory paths and targets.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import sys
import json
import hashlib
from pathlib import Path


def generate_manifest(root_dir):
    """Recursively computes SHA-256 hashes over files in root_dir."""
    root_path = Path(root_dir).resolve()
    manifest_files = {}

    for file_path in sorted(root_path.rglob("*")):
        if file_path.is_file() and not file_path.name.endswith(".tmp") and ".git" not in file_path.parts:
            rel_path = file_path.relative_to(root_path).as_posix()
            content = file_path.read_bytes()
            sha256 = hashlib.sha256(content).hexdigest()
            manifest_files[rel_path] = {
                "sha256": sha256,
                "size_bytes": len(content)
            }

    return {
        "root_dir": str(root_path),
        "file_count": len(manifest_files),
        "files": manifest_files
    }


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python manifest_builder.py <target_directory_path>\n")
        sys.exit(1)

    target_dir = Path(sys.argv[1])
    if not target_dir.exists() or not target_dir.is_dir():
        sys.stderr.write(f"Target directory '{target_dir}' does not exist or is not a directory.\n")
        sys.exit(1)

    manifest = generate_manifest(target_dir)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
