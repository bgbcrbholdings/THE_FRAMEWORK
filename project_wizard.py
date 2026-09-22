#!/usr/bin/env python3
r"""
The Sequence Control Engine — Project Genesis Engine (project_wizard.py)
Initializes isolated project repositories beneath C:\Linkstream\<project_name>\ with 100% root isolation.
Two-phase Win32 atomic path validation, engine TCB lockout, OS reserved device shield,
governance template seeding, local .bat launchers, GitHub workflows (.github/workflows/ci.yml, CODEOWNERS),
and 0-pip test harness setup.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import sys
import os
import re
import json
import shutil
import argparse
from pathlib import Path

# Add engine directory to sys.path
ENGINE_ROOT = Path(__file__).resolve().parent
if str(ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENGINE_ROOT))

from sequence_engine import validate_and_open_path, check_win32_reparse_point
from schemas import GenesisProjectSpec

RESERVED_DEVICE_PATTERN = r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$"


def create_project(project_name, parent_path_arg="C:\\Linkstream", force=False):
    r"""
    Scaffolds a new project workspace under C:\Linkstream\<project_name>\.
    Strict two-phase path verification, engine lockout, and governance seeding.
    """
    # 1. Validate Project Name & Reserved Identifier Shields
    if not project_name or not re.match(r"^[a-zA-Z0-9_-]+$", project_name):
        raise ValueError(f"INVALID_NAME_FORMAT: Project name '{project_name}' must match regex ^[a-zA-Z0-9_-]+$")

    if project_name.lower() == "00_dev_team_sequence":
        raise ValueError("RESERVED_NAME_DENIED: Cannot target or overwrite Master Control Engine directory.")

    if re.match(RESERVED_DEVICE_PATTERN, project_name, re.IGNORECASE):
        raise ValueError(f"RESERVED_DEVICE_NAME_DENIED: '{project_name}' is a Windows OS reserved device name.")

    # 2. Phase 1: Parent Identity Equality Gate
    approved_root = os.path.realpath("C:\\Linkstream")
    parent_canonical = os.path.realpath(parent_path_arg)

    if parent_canonical.casefold() != approved_root.casefold():
        raise ValueError(f"PATH_TRAVERSAL_DENIED: Parent path '{parent_path_arg}' does not match approved root 'C:\\Linkstream'.")

    # Reparse-point validation on parent root
    parent_path = Path(parent_canonical)
    if parent_path.exists() and check_win32_reparse_point(parent_path):
        raise ValueError("PATH_TRAVERSAL_DENIED: Parent directory is a Win32 symlink or junction point.")

    # 3. Phase 2: Target Construction & Identity Assertions
    approved_path = Path(approved_root)
    target_dir = approved_path / project_name

    if str(target_dir.parent.resolve()).casefold() != str(approved_path.resolve()).casefold():
        raise ValueError("PATH_TRAVERSAL_DENIED: Target parent is not canonical approved root.")

    # Existing directory handling (--force)
    if target_dir.exists():
        if not force:
            raise ValueError(f"TARGET_EXISTS: Directory '{target_dir}' already exists. Use --force to re-initialize.")
        
        # Security check: never allow deleting engine directory or root
        if str(target_dir.resolve()).casefold() == str(approved_path.resolve()).casefold():
            raise ValueError("ENGINE_PROTECTION_DENIED: Cannot delete approved root directory.")
        if target_dir.name.lower() == "00_dev_team_sequence":
            raise ValueError("ENGINE_PROTECTION_DENIED: Cannot delete engine directory.")

        # Re-validate target path before force cleaning
        if check_win32_reparse_point(target_dir):
            raise ValueError("FORCE_CLEAN_DENIED: Cannot force clean path that is a symlink or junction.")

        shutil.rmtree(target_dir)

    # Create target directory
    target_dir.mkdir(parents=True, exist_ok=True)

    # Immediate post-creation reparse-point verification
    if check_win32_reparse_point(target_dir):
        shutil.rmtree(target_dir, ignore_errors=True)
        raise ValueError("TOCTOU_SECURITY_DENIED: Newly created directory failed reparse-point check.")

    # 4. Generate Standard Project Structure Including .github
    created_dirs = []
    for folder in ["01_GOVERNANCE", "02_BACKLOG", "03_INCUBATOR", "04_REVIEWS", ".sequence", "tests", ".github", ".github/workflows"]:
        d_path = target_dir / folder
        d_path.mkdir(parents=True, exist_ok=True)
        created_dirs.append(folder)

    # 5. Pre-seed Starter Governance Markdown Files
    preseeded_templates = []

    allowlist_txt = target_dir / "ALLOWLIST.txt"
    allowlist_txt.write_text("ALLOWLIST.txt\n01_GOVERNANCE/BOOTSTRAP.md\n", encoding="utf-8")
    preseeded_templates.append("ALLOWLIST.txt")

    readme_md = target_dir / "README.md"
    readme_md.write_text(f"# {project_name}\n\nProject initialized by Sequence Genesis Wizard.\n", encoding="utf-8")
    preseeded_templates.append("README.md")

    bootstrap_md = target_dir / "01_GOVERNANCE" / "BOOTSTRAP.md"
    bootstrap_md.write_text(f"# Governance Bootstrap: {project_name}\n\nInitial governance protocol specification for {project_name}.\n", encoding="utf-8")
    preseeded_templates.append("01_GOVERNANCE/BOOTSTRAP.md")

    forbidden_yml = target_dir / "01_GOVERNANCE" / "FORBIDDEN.yml"
    forbidden_yml.write_text(f"# Forbidden Patterns Policy: {project_name}\nforbidden_imports:\n  - os.system\n  - subprocess.Popen\n", encoding="utf-8")
    preseeded_templates.append("01_GOVERNANCE/FORBIDDEN.yml")
    
    problem_md = target_dir / "01_GOVERNANCE" / "PROBLEM.md"
    problem_md.write_text(
        f"# Project: {project_name}\n\n## 1. Problem Statement\nDefine target objectives and operational scope for {project_name}.\n",
        encoding="utf-8"
    )
    preseeded_templates.append("01_GOVERNANCE/PROBLEM.md")

    nongoals_md = target_dir / "01_GOVERNANCE" / "NON_GOALS.md"
    nongoals_md.write_text(
        f"# Non-Goals: {project_name}\n\nExplicitly out-of-scope items for {project_name}.\n",
        encoding="utf-8"
    )
    preseeded_templates.append("01_GOVERNANCE/NON_GOALS.md")

    arch_md = target_dir / "01_GOVERNANCE" / "ARCHITECTURE.md"
    arch_md.write_text(
        f"# Technical Architecture: {project_name}\n\nBaseline technical architecture and stack choices for {project_name}.\n",
        encoding="utf-8"
    )
    preseeded_templates.append("01_GOVERNANCE/ARCHITECTURE.md")

    decisions_md = target_dir / "01_GOVERNANCE" / "DECISIONS.md"
    decisions_md.write_text(
        f"# Architectural Decisions Log (ADR): {project_name}\n\nRecord of architectural decisions for {project_name}.\n",
        encoding="utf-8"
    )
    preseeded_templates.append("01_GOVERNANCE/DECISIONS.md")

    slices_md = target_dir / "02_BACKLOG" / "AGILE_SLICES.md"
    slices_md.write_text(
        f"# Resequenced Agile Slices: {project_name}\n\nFeature slice roadmap for {project_name}.\n",
        encoding="utf-8"
    )
    preseeded_templates.append("02_BACKLOG/AGILE_SLICES.md")

    # 6. Pre-seed GitHub Governance Files (.github/CODEOWNERS & .github/workflows/ci.yml)
    codeowners = target_dir / ".github" / "CODEOWNERS"
    codeowners.write_text(
        "# CODEOWNERS Governance Lock\n01_GOVERNANCE/** @project-owner\n.sequence/lock_manifest.json @project-owner\n",
        encoding="utf-8"
    )
    preseeded_templates.append(".github/CODEOWNERS")

    ci_yml = target_dir / ".github" / "workflows" / "ci.yml"
    ci_yml_content = f"""name: {project_name} CI & Lock Wall Verification
on: [push, pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Run 0-Pip Test Runner
        run: python tests/test_runner.py
"""
    ci_yml.write_text(ci_yml_content, encoding="utf-8")
    preseeded_templates.append(".github/workflows/ci.yml")

    # 7. Pre-seed Framework State (.sequence/mrac_rules.json, session.json, state.db, lock_manifest.json)
    mrac_json = target_dir / ".sequence" / "mrac_rules.json"
    mrac_payload = {
        "project_name": project_name,
        "allowed_write_paths": ["src/**", "tests/**", "01_GOVERNANCE/**", "02_BACKLOG/**"],
        "forbidden_imports": ["subprocess.Popen", "os.system", "shutil.rmtree"],
        "max_diff_lines": 500
    }
    mrac_json.write_text(json.dumps(mrac_payload, indent=2), encoding="utf-8")
    preseeded_templates.append(".sequence/mrac_rules.json")

    from sequence_engine import generate_and_save_session
    generate_and_save_session(target_dir)

    db_path = target_dir / ".sequence" / "state.db"
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS status (status TEXT, active_slice TEXT, uptime_seconds REAL)")
    conn.execute("INSERT INTO status VALUES ('RUNNING', 'Micro-Slice 1.0', 0.0)")
    conn.commit()
    conn.close()

    from verify import generate_lock_manifest
    generate_lock_manifest(target_dir)

    # 8. Copy 0-Pip Test Runner & Starter Unit Test into tests/
    runner_src = ENGINE_ROOT / "tests" / "test_runner.py"
    runner_dest = target_dir / "tests" / "test_runner.py"
    if runner_src.exists():
        shutil.copy2(runner_src, runner_dest)
    else:
        runner_dest.write_text("# 0-Pip Test Runner Stub\n", encoding="utf-8")
    preseeded_templates.append("tests/test_runner.py")

    test_gen = target_dir / "tests" / "test_genesis.py"
    test_gen_content = f'''import unittest
import os
from pathlib import Path

class TestGenesisScaffolding(unittest.TestCase):
    def test_project_structure(self):
        project_root = Path(__file__).resolve().parents[1]
        for folder in ["01_GOVERNANCE", "02_BACKLOG", "03_INCUBATOR", "04_REVIEWS", ".sequence", "tests", ".github"]:
            self.assertTrue((project_root / folder).exists(), f"Missing folder: {{folder}}")

if __name__ == "__main__":
    unittest.main()
'''
    test_gen.write_text(test_gen_content, encoding="utf-8")
    preseeded_templates.append("tests/test_genesis.py")

    # 9. Seed Project-Local Batch Launchers (.bat)
    run_tests_bat = target_dir / "run_tests.bat"
    run_tests_bat.write_text(
        "@echo off\ncd /d \"%~dp0\"\necho Running Unit Test Harness for " + project_name + "...\npython tests\\test_runner.py\npause\n",
        encoding="utf-8"
    )
    preseeded_templates.append("run_tests.bat")

    build_packet_bat = target_dir / "build_packet.bat"
    build_packet_bat.write_text(
        "@echo off\ncd /d \"%~dp0\"\necho Compiling Review Packet for " + project_name + "...\npython C:\\Linkstream\\00_DEV_TEAM_SEQUENCE\\build_packet.py " + project_name + " 04_REVIEWS 1\npause\n",
        encoding="utf-8"
    )
    preseeded_templates.append("build_packet.bat")

    parse_reviews_bat = target_dir / "parse_reviews.bat"
    parse_reviews_bat.write_text(
        "@echo off\ncd /d \"%~dp0\"\necho Adjudicating Off-Grid Reviews for " + project_name + "...\npython C:\\Linkstream\\00_DEV_TEAM_SEQUENCE\\parse_reviews.py 04_REVIEWS \"%~dp0\" %1\npause\n",
        encoding="utf-8"
    )
    preseeded_templates.append("parse_reviews.bat")

    # 10. Construct and Validate GenesisProjectSpec
    spec = GenesisProjectSpec(
        project_name=project_name,
        root_dir=str(target_dir),
        created_dirs=sorted([d.name for d in target_dir.iterdir() if d.is_dir()]),
        preseeded_templates=sorted(preseeded_templates),
        force_used=force
    )

    spec.validate()

    print(f"[+] Successfully initialized project '{project_name}' at {target_dir}")
    return spec


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Project Genesis Engine CLI")
    parser.add_argument("--name", required=True, help="New project repository name (^[a-zA-Z0-9_-]+$)")
    parser.add_argument("--path", default="C:\\Linkstream", help="Parent root directory (must equal C:\\Linkstream)")
    parser.add_argument("--force", action="store_true", help="Allow overwrite/re-init of pre-existing non-engine target directory")
    args = parser.parse_args()

    try:
        create_project(args.name, args.path, args.force)
        sys.exit(0)
    except Exception as e:
        print(f"[!] PROJECT GENESIS ERROR: {e}", file=sys.stderr)
        sys.exit(1)
