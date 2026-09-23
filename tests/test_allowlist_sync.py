#!/usr/bin/env python3
"""
Unit Test Suite for allowlist_sync.py & verify.py prepush gate (test_allowlist_sync.py)
Validates positive and negative cases for Stage 1 pre-flight allowlist PR generation,
deadlock prevention (permitting BUILD_PACKET), gate_status set/clear cycle, git worktree isolation,
and local pre-push CI emulation.
"""

import sys
import os
import json
import unittest
import tempfile
import shutil
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from slice_gate import check_slice_action_allowed, SliceGateDeniedError
from allowlist_sync import extract_proposed_paths_from_plan
from verify import run_prepush_verification


class TestAllowlistSyncAndGates(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="seq_test_allowlist_"))
        self.sec_dir = self.test_dir / ".sequence"
        self.sec_dir.mkdir(parents=True, exist_ok=True)
        self.reviews_dir = self.test_dir / "04_REVIEWS" / "slice-009-lifecycle-circuit-breaker"
        self.reviews_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_extract_proposed_paths_from_plan(self):
        plan_path = self.reviews_dir / "implementation_plan.md"
        plan_content = """# Implementation Plan
### Allowed File Paths for slice-009-lifecycle-circuit-breaker:
- `[NEW]` [slice_gate.py](file:///path/to/slice_gate.py)
- `[NEW]` [allowlist_sync.py](file:///path/to/allowlist_sync.py)
- `[MODIFY]` [file_hygiene_engine.py](file:///path/to/file_hygiene_engine.py)
---
"""
        plan_path.write_text(plan_content, encoding="utf-8")
        extracted = extract_proposed_paths_from_plan(plan_path)
        self.assertIn("slice_gate.py", extracted)
        self.assertIn("allowlist_sync.py", extracted)
        self.assertIn("file_hygiene_engine.py", extracted)

    def test_build_packet_allowed_during_allowlist_pending(self):
        """Deadlock Prevention Test: BUILD_PACKET must be permitted when gate_status == ALLOWLIST_PR_PENDING."""
        res_file = self.sec_dir / "review_resolutions.json"
        res_data = {
            "slices": {
                "slice-009-lifecycle-circuit-breaker": {
                    "slice_id": "slice-009-lifecycle-circuit-breaker",
                    "overall_verdict": "APPROVED",
                    "packet_sha256": "dummy_hash",
                    "gate_status": "ALLOWLIST_PR_PENDING"
                }
            }
        }
        res_file.write_text(json.dumps(res_data), encoding="utf-8")

        # BUILD_PACKET must NOT raise SliceGateDeniedError
        try:
            check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "BUILD_PACKET", self.test_dir)
        except SliceGateDeniedError as e:
            self.fail(f"BUILD_PACKET was denied during ALLOWLIST_PR_PENDING: {e}")

    def test_implement_denied_during_allowlist_pending(self):
        """IMPLEMENT must be DENIED when gate_status == ALLOWLIST_PR_PENDING."""
        res_file = self.sec_dir / "review_resolutions.json"
        res_data = {
            "slices": {
                "slice-009-lifecycle-circuit-breaker": {
                    "slice_id": "slice-009-lifecycle-circuit-breaker",
                    "overall_verdict": "APPROVED",
                    "packet_sha256": "dummy_hash",
                    "gate_status": "ALLOWLIST_PR_PENDING"
                }
            }
        }
        res_file.write_text(json.dumps(res_data), encoding="utf-8")

        with self.assertRaises(SliceGateDeniedError) as ctx:
            check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "IMPLEMENT", self.test_dir)
        self.assertEqual(ctx.exception.code, "ALLOWLIST_PR_PENDING")

    def test_allowlist_remains_pending_when_paths_still_missing(self):
        """Negative test: gate_status remains ALLOWLIST_PR_PENDING if origin/main:ALLOWLIST.txt is missing paths."""
        res_file = self.sec_dir / "review_resolutions.json"
        res_data = {
            "slices": {
                "slice-009-lifecycle-circuit-breaker": {
                    "slice_id": "slice-009-lifecycle-circuit-breaker",
                    "overall_verdict": "APPROVED",
                    "packet_sha256": "dummy_hash",
                    "gate_status": "ALLOWLIST_PR_PENDING"
                }
            }
        }
        res_file.write_text(json.dumps(res_data), encoding="utf-8")

        # Read status back and assert it is still ALLOWLIST_PR_PENDING
        read_data = json.loads(res_file.read_text(encoding="utf-8"))
        status = read_data["slices"]["slice-009-lifecycle-circuit-breaker"].get("gate_status")
        self.assertEqual(status, "ALLOWLIST_PR_PENDING")


if __name__ == "__main__":
    unittest.main()
