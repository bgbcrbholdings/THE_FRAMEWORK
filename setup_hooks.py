#!/usr/bin/env python3
"""
The Sequence Control Engine — Git Hooks Installer
Installs pre-commit and pre-push hooks into the local repository's .git/hooks directory.
"""

import sys
from pathlib import Path

PRE_COMMIT_SCRIPT = """#!/bin/sh
echo "==> Running Sequence Pre-Commit Allowlist Check..."
python "C:\\Linkstream\\00_DEV_TEAM_SEQUENCE\\verify.py" precommit .
if [ $? -ne 0 ]; then
    echo "❌ Commit blocked by Sequence physical path allowlist filter."
    exit 1
fi
"""

PRE_PUSH_SCRIPT = """#!/bin/sh
echo "==> Running Sequence Pre-Push Verification..."
python "C:\\Linkstream\\00_DEV_TEAM_SEQUENCE\\verify.py" prepush .
if [ $? -ne 0 ]; then
    echo "❌ Push blocked by Sequence pre-push verification."
    exit 1
fi
"""

def install_hooks(project_dir_str="."):
    project_dir = Path(project_dir_str).resolve()
    git_hooks_dir = project_dir / ".git" / "hooks"

    if not git_hooks_dir.exists():
        print(f" [!] Error: .git/hooks directory not found at {git_hooks_dir}. Is this a git repository?")
        return False

    pre_commit_file = git_hooks_dir / "pre-commit"
    pre_push_file = git_hooks_dir / "pre-push"

    pre_commit_file.write_text(PRE_COMMIT_SCRIPT, encoding="utf-8")
    pre_push_file.write_text(PRE_PUSH_SCRIPT, encoding="utf-8")

    # Make executable on Unix/Git Bash
    try:
        pre_commit_file.chmod(0o755)
        pre_push_file.chmod(0o755)
    except Exception:
        pass

    print(f" [OK] Installed Sequence git hooks into {git_hooks_dir}")
    return True

if __name__ == "__main__":
    p_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    install_hooks(p_dir)
