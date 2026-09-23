#!/usr/bin/env python3
"""
Project Zero: The Sequence Control Engine — Deterministic Packet Assembly Engine (build_packet.py)
Compiles reproducible review packets with strict 20,000 token / 80,000 char caps.
Enforces Prefix-Preserving Prompt Cache Layout, Line-Numbered Anchoring, and 4-Component Senior Personas.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
import re
import hashlib
import subprocess
from pathlib import Path

# Hardened Token & Character Limits (Pure Stdlib 4-char heuristic based)
MAX_TOTAL_CHARS = 80000      # 80,000 chars (~20,000 tokens)
MAX_TOTAL_TOKENS = 20000     # Hard total token cap
MAX_DIFF_TOKENS = 14000      # 70% Max allocation for Diff / Proposal
MIN_ANCHOR_TOKENS = 6000     # 30% Reserved Floor for Governance Anchors

COMPLEXITY_KEYWORDS = [
    "session", "queue", "webhook", "encrypt", "cron", "cache",
    "migrate", "atomic", "auth", "thread", "mutex", "lock",
    "retry", "except: pass"
]

CRITICAL_CHANGED_FILE_PATTERNS = [
    "package.json", "requirements.txt", "Pipfile", "pyproject.toml",
    "Dockerfile", ".github/workflows/", "migrations/"
]

def count_tokens(text):
    """
    Deterministic standard-library token estimator.
    Calculates tokens based on words and syntax structural symbols.
    """
    words = len(text.split())
    symbols = len(re.findall(r'[{}[\];:=+\-*\/\\<>&|^%#!~]', text))
    return int(words * 1.3 + symbols * 0.5)

def format_line_numbers(text):
    """
    Formats raw text with explicit line number anchors (L0001: <text>).
    Enables reviewer models to cite exact line anchors in remediation targets.
    """
    lines = text.splitlines()
    return "\n".join([f"L{i+1:04d}: {line}" for i, line in enumerate(lines)])

def assemble_slice_packet_text(project_dir, slice_id, proposal_file_path=None, version="v1"):
    """Compiles a deterministic Slice Review Packet with Prefix-Preserving Prompt Caching."""
    p_dir = Path(project_dir)
    prob_file = p_dir / "01_GOVERNANCE" / "PROBLEM.md"
    nongoal_file = p_dir / "01_GOVERNANCE" / "NON_GOALS.md"
    arch_file = p_dir / "01_GOVERNANCE" / "ARCHITECTURE.md"
    slices_file = p_dir / "02_BACKLOG" / "AGILE_SLICES.md"

    prob_txt = prob_file.read_text(encoding="utf-8") if prob_file.exists() else ""
    nongoal_txt = nongoal_file.read_text(encoding="utf-8") if nongoal_file.exists() else ""
    arch_txt = arch_file.read_text(encoding="utf-8") if arch_file.exists() else ""
    slices_txt = slices_file.read_text(encoding="utf-8") if slices_file.exists() else ""

    slice_proposal_raw = ""
    if proposal_file_path and Path(proposal_file_path).exists():
        slice_proposal_raw = Path(proposal_file_path).read_text(encoding="utf-8")
    else:
        slice_plan = p_dir / "04_REVIEWS" / slice_id / "implementation_plan.md"
        plan_file = p_dir / "implementation_plan.md"
        if slice_plan.exists():
            slice_proposal_raw = slice_plan.read_text(encoding="utf-8")
        elif plan_file.exists():
            slice_proposal_raw = plan_file.read_text(encoding="utf-8")

    # Format implementation proposal with explicit line anchors
    slice_proposal_txt = format_line_numbers(slice_proposal_raw)

    # Prefix-Preserving Prompt Cache Layout: Governance Anchors sit at absolute top
    gov_anchors = f"=== LOCKED GOVERNANCE ANCHORS (PREFIX-PRESERVED FOR PROMPT CACHING) ===\n\n{prob_txt}\n\n---\n\n{nongoal_txt}\n\n---\n\n{arch_txt}"
    content_bundle = f"{gov_anchors}\n\n=== PROPOSED IMPLEMENTATION PLAN FOR SLICE: '{slice_id}' (LINE-NUMBERED ANCHORS) ===\n\n{slice_proposal_txt}"
    from slice_gate import compute_live_packet_hash
    content_hash = compute_live_packet_hash(project_dir, slice_id)

    if version == "v1":
        header = f"""PROMPT FOR OFF-GRID REVIEWERS (CHATPLAYGROUND MULTI-MODEL AUDIT — SLICE: {slice_id} — VERSION: {version}):

=== 4-COMPONENT SENIOR PERSONA AUDITOR DIRECTIVES ===
You are acting as a Senior Principal Systems Architect, Chief Technology Officer (CTO), Senior Debugging Specialist, and Enterprise Security Auditor.
Your task is to conduct an INITIAL HOSTILE RED-TEAM AUDIT of the implementation proposal for Slice '{slice_id}' (SHA-256: {content_hash}).

=== UNIVERSAL AUDIT RULES & SCOPE BOUNDARIES (GOE APPROVED PROTOCOL) ===
1. THREAT MODEL BOUNDARY: Audit strictly within the defined tech stack (Python 3.11+ stdlib, Windows OS local process, zero pip packages). Do NOT raise out-of-scope findings demanding Docker containers, TPM keys, or cloud infrastructure.
2. STRICT SCOPE ISOLATION: Audit ONLY the implementation plan and file allowlist of the assigned slice ('{slice_id}'). Do NOT demand features, refactors, or changes assigned to future downstream slices.
3. NON-GOALS ENFORCEMENT: Any finding demanding an item explicitly listed in NON_GOALS.md (e.g., external pip packages, Flask/FastAPI, YAML parsers) is strictly INVALID.
4. MANDATORY REMEDIATION SCHEMA: You MUST provide an explicit, code/spec-level 'remediation' object for EVERY finding, citing exact line numbers from the proposal text (e.g. L0042). Vague prose complaints without an exact remediation object will be rejected.
5. ZERO NARRATIVE MANDATE: Output ONLY factual findings directly inside the mandatory terminal JSON block.
6. MANDATORY TERMINAL JSON VERDICT FORMAT: Your response MUST conclude with a valid JSON block matching this exact schema:

```json
{{
  "packet_sha256": "{content_hash}",
  "reviewer_model": "<MODEL_NAME>",
  "verdict": "APPROVED" or "BLOCKED",
  "findings": [
    {{
      "id": "FINDING-001",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "PATH_TRAVERSAL|AUTH_BYPASS|EXECUTION_SAFETY|SCHEMA_VIOLATION",
      "description": "<Detailed description of finding with exact line citation>",
      "remediation": {{
        "action_type": "INSERT|MODIFY|DELETE|GOVERNANCE_CITATION",
        "target_location": "file:///path/to/file#L0012-L0030",
        "exact_text": "<Verbatim specification or code requirement to be inserted>",
        "must_contain": "<String presence check>",
        "must_not_contain": "<String absence check>",
        "acceptance_test": "<Exact string check to verify resolution>"
      }}
    }}
  ],
  "blocking_reasons": []
}}
```

=== BEGIN SLICE REVIEW PACKET FOR '{slice_id}' (SHA-256: {content_hash}) ===

{content_bundle}

=== END SLICE REVIEW PACKET FOR '{slice_id}' ===
"""
    else:
        # Load Resolution Checklist for Verification Audit (v2+)
        resolutions_file = p_dir / ".sequence" / "review_resolutions.json"
        checklist_txt = ""
        open_ids_txt = ""
        if resolutions_file.exists():
            try:
                res_data = json.loads(resolutions_file.read_text(encoding="utf-8"))
                raw_open_items = [item for item in res_data.get("findings", []) if item.get("status") == "OPEN"]
                unique_dict = {}
                for item in raw_open_items:
                    fid = item.get("id")
                    if fid and fid not in unique_dict:
                        unique_dict[fid] = item
                checklist_items = list(unique_dict.values())
                checklist_txt = "\n".join([
                    f"- [{item.get('status', 'OPEN')}] {item.get('id')}: {item.get('remediation', {}).get('exact_text', item.get('description'))}" 
                    for item in checklist_items
                ])
                open_ids_txt = ", ".join([item.get('id') for item in checklist_items])
            except Exception:
                checklist_txt = "Checklist unavailable."

        header = f"""PROMPT FOR OFF-GRID REVIEWERS (TARGETED VERIFICATION AUDIT — SLICE: {slice_id} — VERSION: {version}):

=== 4-COMPONENT SENIOR PERSONA AUDITOR DIRECTIVES ===
You are acting as a Senior Principal Systems Architect, Chief Technology Officer (CTO), Senior Debugging Specialist, and Enterprise Security Auditor.
Your task is to conduct a TARGETED VERIFICATION AUDIT of the updated implementation proposal for Slice '{slice_id}' (SHA-256: {content_hash}).

=== NORMATIVE RULE 4 SCOPE LOCK (VERIFICATION MODE) ===
ROUND: {version}. ACTIVE OPEN FINDINGS FROM PRIOR ROUND: [{open_ids_txt}].
1. YOU MAY ONLY verify whether the remediation instructions for the ACTIVE FINDINGS listed below were executed word-for-word in the proposal text.
2. YOU ARE STRICTLY FORBIDDEN from raising new architectural, stylistic, or design complaints on any text that remained unchanged from prior rounds.
3. EXCEPTION 4A (SAFETY REGRESSION VALVE): You may file a NEW finding ONLY if newly introduced text directly contradicts a frozen contract or governance line in 01_GOVERNANCE/, quoting the exact line contradiction in description. All other new complaints on unchanged text WILL BE MECHANICALLY DISCARDED BY THE PARSER.

=== PRIOR RESOLUTION CHECKLIST ===
{checklist_txt}

=== MANDATORY TERMINAL JSON VERDICT FORMAT ===
```json
{{
  "packet_sha256": "{content_hash}",
  "reviewer_model": "<MODEL_NAME>",
  "verdict": "APPROVED" or "BLOCKED",
  "findings": [
    {{
      "id": "FINDING-001",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "PATH_TRAVERSAL|AUTH_BYPASS|EXECUTION_SAFETY|SCHEMA_VIOLATION",
      "description": "<Detailed description of unresolved finding or EXCEPTION 4A regression>",
      "remediation": {{
        "action_type": "INSERT|MODIFY|DELETE|GOVERNANCE_CITATION",
        "target_location": "file:///path/to/file#L0012-L0030",
        "exact_text": "<Verbatim specification or code requirement to be inserted>",
        "must_contain": "<String presence check>",
        "must_not_contain": "<String absence check>",
        "acceptance_test": "<Exact string check to verify resolution>"
      }}
    }}
  ],
  "blocking_reasons": []
}}
```

=== BEGIN VERIFICATION REVIEW PACKET FOR '{slice_id}' ({version}) (SHA-256: {content_hash}) ===

{content_bundle}

=== END VERIFICATION REVIEW PACKET FOR '{slice_id}' ===
"""
    return header, content_hash

def verify_remediations_applied(project_dir: Path, slice_id: str, proposal_raw: str) -> None:
    """
    Reads .sequence/review_resolutions.json for any OPEN findings belonging to slice_id.
    Mechanically verifies must_contain and must_not_contain strings against proposal_raw.
    Terminates process with exit status 1 immediately on any unsatisfied finding.
    """
    res_file = project_dir / ".sequence" / "review_resolutions.json"
    if not res_file.exists():
        return  # Initial packet build, no prior resolutions exist
    try:
        res_data = json.loads(res_file.read_text(encoding="utf-8"))
    except Exception as e:
        sys.stderr.write(f"\n[FATAL PRE-FLIGHT ERROR] Corrupted '.sequence/review_resolutions.json': {e}\n")
        sys.stderr.write("Refusing to compile packet while resolution state is corrupted.\n\n")
        sys.exit(1)

    # Check either per-slice map or top-level findings
    slices_map = res_data.get("slices", {})
    slice_entry = slices_map.get(slice_id, res_data)
    findings = slice_entry.get("findings", [])

    missing = []
    for f in findings:
        status = f.get("status", "OPEN")
        if status not in ("OPEN", "REJECTED_NOT_IMPLEMENTED", "REJECTED_PARTIAL"):
            continue
        rem = f.get("remediation", {})
        must_inc = rem.get("must_contain", "")
        must_exc = rem.get("must_not_contain", "")

        if must_inc and must_inc not in proposal_raw:
            missing.append(f"[FATAL PRE-FLIGHT] {f.get('id', 'FINDING')}: must_contain string missing from plan:\n  -> '{must_inc[:120]}...'")
        if must_exc and must_exc in proposal_raw:
            missing.append(f"[FATAL PRE-FLIGHT] {f.get('id', 'FINDING')}: must_not_contain string found in plan:\n  -> '{must_exc[:120]}...'")

    if missing:
        sys.stderr.write("\n=========================================================\n")
        sys.stderr.write("PRE-FLIGHT REMEDIATION VERIFICATION FAILED\n")
        sys.stderr.write("Refusing to compile packet until all prior remediation strings are present.\n")
        sys.stderr.write("=========================================================\n")
        for err in missing:
            sys.stderr.write(f"{err}\n")
        sys.stderr.write("\nUpdate implementation_plan.md to include all required strings before rebuilding.\n\n")
        sys.exit(1)

def build_packet(project_dir_str, slice_id="slice-001-off-grid-review-parser", proposal_file_path=None, version="v1"):
    project_dir = Path(project_dir_str)
    
    # 1. Read raw proposal for pre-flight check
    if proposal_file_path and Path(proposal_file_path).exists():
        proposal_raw = Path(proposal_file_path).read_text(encoding="utf-8")
    else:
        slice_plan = project_dir / "04_REVIEWS" / slice_id / "implementation_plan.md"
        plan_file = project_dir / "implementation_plan.md"
        if slice_plan.exists():
            proposal_raw = slice_plan.read_text(encoding="utf-8")
        elif plan_file.exists():
            proposal_raw = plan_file.read_text(encoding="utf-8")
        else:
            proposal_raw = ""

    # 2. Run Local Pre-Flight Remediation Verification Gate
    verify_remediations_applied(project_dir, slice_id, proposal_raw)

    packet_text, pkt_hash = assemble_slice_packet_text(project_dir, slice_id, proposal_file_path, version)
    slice_folder = project_dir / "04_REVIEWS" / slice_id
    out_filename = f"{slice_id}-packet-{version}.txt"

    total_tokens = count_tokens(packet_text)

    print(f" [+] Packet compiled for '{slice_id}' (Version {version}). Total Tokens: {total_tokens}, Chars: {len(packet_text)}.")

    if total_tokens > MAX_TOTAL_TOKENS or len(packet_text) > MAX_TOTAL_CHARS:
        print(f" [!] PACKET OVERFLOW ERROR: Total tokens ({total_tokens}) or Chars ({len(packet_text)}) exceed cap limit.")
        sys.exit(1)

    slice_folder.mkdir(parents=True, exist_ok=True)
    out_file = slice_folder / out_filename
    out_file.write_text(packet_text, encoding="utf-8")

    json_payload = {
        "packet_id": slice_id,
        "version": version,
        "allowed_file_paths": ["src/**", "tests/**", "build_packet.py", "parse_reviews.py", "auditor_agent.py", "schemas.py"],
        "forbidden_file_paths": [".github/**", ".sequence/**"],
        "git_diff": "",
        "invariants": {"forbidden_patterns": ["git commit --no-verify", "rm -rf .git"]},
        "adversarial_constraints": [],
        "content_sha256": pkt_hash
    }
    json_copy = dict(json_payload)
    json_payload["packet_hash"] = hashlib.sha256(json.dumps(json_copy, indent=2).encode('utf-8')).hexdigest()

    json_file = slice_folder / (out_file.stem + ".json")
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(json_payload, f, indent=2)

    # 3. Write .sequence/active_packet.json pointer file to eliminate CLI hash confusion
    active_ptr = project_dir / ".sequence" / "active_packet.json"
    active_ptr.parent.mkdir(parents=True, exist_ok=True)
    active_payload = {
        "slice_id": slice_id,
        "version": version,
        "content_sha256": pkt_hash,
        "review_dir": str(slice_folder.relative_to(project_dir))
    }
    active_ptr.write_text(json.dumps(active_payload, indent=2), encoding="utf-8")

    print(f" [OK] Packet text written to: {out_file.relative_to(project_dir)}")
    print(f" [OK] Packet JSON written to: {json_file.relative_to(project_dir)}")
    print(f" [OK] Active packet pointer updated: {active_ptr.relative_to(project_dir)}")
    print(f" [OK] SHA-256 Content Hash: {pkt_hash}\n")
    return pkt_hash, json_file

if __name__ == "__main__":
    p_dir = sys.argv[1] if len(sys.argv) > 1 else r"C:\Linkstream\00_DEV_TEAM_SEQUENCE"
    s_id = sys.argv[2] if len(sys.argv) > 2 else "slice-001-off-grid-review-parser"
    prop_path = sys.argv[3] if len(sys.argv) > 3 else None
    ver = sys.argv[4] if len(sys.argv) > 4 else "v1"
    if Path(p_dir).exists():
        build_packet(p_dir, s_id, prop_path, ver)
    else:
        print(f"Usage: python build_packet.py <project_directory> [<slice_id>] [<proposal_file_path>] [<version>]")
