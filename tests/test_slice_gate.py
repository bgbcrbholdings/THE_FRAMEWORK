#!/usr/bin/env python3
"""
Unit tests for slice_gate.py and safe_write pre-write gates.
16 Comprehensive Unit Test Cases using Python stdlib unittest.
Zero external pip dependencies.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from slice_gate import (
    check_slice_action_allowed,
    assert_slice_action_allowed,
    compute_live_packet_hash,
    resolve_active_slice_id,
    SliceGateDeniedError
)
from file_hygiene_engine import safe_write, BlockedSliceWriteError, _get_remediation_allowlist_from_findings
from build_packet import verify_remediations_applied


class TestSliceGate(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_read_only_action_always_allowed(self):
        # VIEW_STATUS should pass even if no resolution file exists
        check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "VIEW_STATUS", self.test_dir)

    def test_unknown_action_denies(self):
        with self.assertRaises(SliceGateDeniedError) as cm:
            check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "INVALID_ACTION", self.test_dir)
        self.assertEqual(cm.exception.code, "UNKNOWN_ACTION")

    def test_missing_resolution_file_denies_implement(self):
        with self.assertRaises(SliceGateDeniedError) as cm:
            check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "IMPLEMENT", self.test_dir)
        self.assertEqual(cm.exception.code, "MISSING_RESOLUTIONS")

    def test_missing_resolution_file_allows_remediation(self):
        # REMEDIATE_PLAN and BUILD_PACKET allowed for unreviewed slice
        check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "REMEDIATE_PLAN", self.test_dir)
        check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "BUILD_PACKET", self.test_dir)

    def test_corrupt_json_denies_all(self):
        seq_dir = self.test_dir / ".sequence"
        seq_dir.mkdir(parents=True)
        (seq_dir / "review_resolutions.json").write_text("{corrupt_json", encoding="utf-8")

        with self.assertRaises(SliceGateDeniedError) as cm:
            check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "IMPLEMENT", self.test_dir)
        self.assertEqual(cm.exception.code, "CORRUPTED_RESOLUTIONS")

    def test_slice_id_mismatch_denies_implement(self):
        seq_dir = self.test_dir / ".sequence"
        seq_dir.mkdir(parents=True)
        res_data = {
            "slices": {
                "slice-001-other": {
                    "slice_id": "slice-001-other",
                    "overall_verdict": "APPROVED",
                    "packet_sha256": "dummy_hash"
                }
            }
        }
        (seq_dir / "review_resolutions.json").write_text(json.dumps(res_data), encoding="utf-8")

        with self.assertRaises(SliceGateDeniedError) as cm:
            check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "IMPLEMENT", self.test_dir)
        self.assertEqual(cm.exception.code, "SLICE_NOT_FOUND")

    def test_verdict_blocked_denies_implement(self):
        seq_dir = self.test_dir / ".sequence"
        seq_dir.mkdir(parents=True)
        res_data = {
            "slices": {
                "slice-009-lifecycle-circuit-breaker": {
                    "slice_id": "slice-009-lifecycle-circuit-breaker",
                    "overall_verdict": "BLOCKED",
                    "packet_sha256": "dummy_hash"
                }
            }
        }
        (seq_dir / "review_resolutions.json").write_text(json.dumps(res_data), encoding="utf-8")

        with self.assertRaises(SliceGateDeniedError) as cm:
            check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "IMPLEMENT", self.test_dir)
        self.assertEqual(cm.exception.code, "VERDICT_NOT_APPROVED")

    def test_verdict_blocked_allows_build_packet(self):
        seq_dir = self.test_dir / ".sequence"
        seq_dir.mkdir(parents=True)
        res_data = {
            "slices": {
                "slice-009-lifecycle-circuit-breaker": {
                    "slice_id": "slice-009-lifecycle-circuit-breaker",
                    "overall_verdict": "BLOCKED",
                    "packet_sha256": "dummy_hash"
                }
            }
        }
        (seq_dir / "review_resolutions.json").write_text(json.dumps(res_data), encoding="utf-8")

        check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "BUILD_PACKET", self.test_dir)

    def test_verdict_typo_denies_implement(self):
        seq_dir = self.test_dir / ".sequence"
        seq_dir.mkdir(parents=True)
        res_data = {
            "slices": {
                "slice-009-lifecycle-circuit-breaker": {
                    "slice_id": "slice-009-lifecycle-circuit-breaker",
                    "overall_verdict": "APPROVED ",
                    "packet_sha256": "dummy_hash"
                }
            }
        }
        (seq_dir / "review_resolutions.json").write_text(json.dumps(res_data), encoding="utf-8")

        with self.assertRaises(SliceGateDeniedError) as cm:
            check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "IMPLEMENT", self.test_dir)
        self.assertEqual(cm.exception.code, "VERDICT_NOT_APPROVED")

    def test_stale_packet_hash_denies_implement(self):
        (self.test_dir / "01_GOVERNANCE").mkdir()
        (self.test_dir / "01_GOVERNANCE" / "PROBLEM.md").write_text("Prob", encoding="utf-8")
        (self.test_dir / "01_GOVERNANCE" / "NON_GOALS.md").write_text("NoGoal", encoding="utf-8")
        (self.test_dir / "01_GOVERNANCE" / "ARCHITECTURE.md").write_text("Arch", encoding="utf-8")

        rev_dir = self.test_dir / "04_REVIEWS" / "slice-009-lifecycle-circuit-breaker"
        rev_dir.mkdir(parents=True)
        (rev_dir / "implementation_plan.md").write_text("Plan Text", encoding="utf-8")

        seq_dir = self.test_dir / ".sequence"
        seq_dir.mkdir(parents=True)
        res_data = {
            "slices": {
                "slice-009-lifecycle-circuit-breaker": {
                    "slice_id": "slice-009-lifecycle-circuit-breaker",
                    "overall_verdict": "APPROVED",
                    "packet_sha256": "wrong_stale_hash"
                }
            }
        }
        (seq_dir / "review_resolutions.json").write_text(json.dumps(res_data), encoding="utf-8")

        with self.assertRaises(SliceGateDeniedError) as cm:
            check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "IMPLEMENT", self.test_dir)
        self.assertEqual(cm.exception.code, "HASH_MISMATCH")

    def test_approved_matching_hash_allows_implement(self):
        (self.test_dir / "01_GOVERNANCE").mkdir()
        (self.test_dir / "01_GOVERNANCE" / "PROBLEM.md").write_text("Prob", encoding="utf-8")
        (self.test_dir / "01_GOVERNANCE" / "NON_GOALS.md").write_text("NoGoal", encoding="utf-8")
        (self.test_dir / "01_GOVERNANCE" / "ARCHITECTURE.md").write_text("Arch", encoding="utf-8")

        rev_dir = self.test_dir / "04_REVIEWS" / "slice-009-lifecycle-circuit-breaker"
        rev_dir.mkdir(parents=True)
        (rev_dir / "implementation_plan.md").write_text("Plan Text", encoding="utf-8")

        valid_hash = compute_live_packet_hash(self.test_dir, "slice-009-lifecycle-circuit-breaker")

        seq_dir = self.test_dir / ".sequence"
        seq_dir.mkdir(parents=True)
        res_data = {
            "slices": {
                "slice-009-lifecycle-circuit-breaker": {
                    "slice_id": "slice-009-lifecycle-circuit-breaker",
                    "overall_verdict": "APPROVED",
                    "packet_sha256": valid_hash
                }
            }
        }
        (seq_dir / "review_resolutions.json").write_text(json.dumps(res_data), encoding="utf-8")

        check_slice_action_allowed("slice-009-lifecycle-circuit-breaker", "IMPLEMENT", self.test_dir)

    def test_local_pre_flight_failure(self):
        seq_dir = self.test_dir / ".sequence"
        seq_dir.mkdir(parents=True)
        res_data = {
            "slices": {
                "slice-009-lifecycle-circuit-breaker": {
                    "slice_id": "slice-009-lifecycle-circuit-breaker",
                    "overall_verdict": "BLOCKED",
                    "findings": [
                        {
                            "id": "FINDING-001",
                            "status": "OPEN",
                            "remediation": {"must_contain": "MANDATORY_STRING_XYZ"}
                        }
                    ]
                }
            }
        }
        (seq_dir / "review_resolutions.json").write_text(json.dumps(res_data), encoding="utf-8")

        with self.assertRaises(SystemExit) as cm:
            verify_remediations_applied(self.test_dir, "slice-009-lifecycle-circuit-breaker", "proposal without string")
        self.assertEqual(cm.exception.code, 1)

    def test_hash_cascade_exclusion(self):
        (self.test_dir / "01_GOVERNANCE").mkdir()
        (self.test_dir / "01_GOVERNANCE" / "PROBLEM.md").write_text("Prob", encoding="utf-8")
        (self.test_dir / "01_GOVERNANCE" / "NON_GOALS.md").write_text("NoGoal", encoding="utf-8")
        (self.test_dir / "01_GOVERNANCE" / "ARCHITECTURE.md").write_text("Arch", encoding="utf-8")

        (self.test_dir / "02_BACKLOG").mkdir()
        slices_file = self.test_dir / "02_BACKLOG" / "AGILE_SLICES.md"
        slices_file.write_text("Initial Backlog", encoding="utf-8")

        rev_dir = self.test_dir / "04_REVIEWS" / "slice-009-lifecycle-circuit-breaker"
        rev_dir.mkdir(parents=True)
        (rev_dir / "implementation_plan.md").write_text("Plan Text", encoding="utf-8")

        hash1 = compute_live_packet_hash(self.test_dir, "slice-009-lifecycle-circuit-breaker")

        # Modify AGILE_SLICES.md
        slices_file.write_text("Modified Backlog with Slice 010", encoding="utf-8")

        hash2 = compute_live_packet_hash(self.test_dir, "slice-009-lifecycle-circuit-breaker")

        self.assertEqual(hash1, hash2, "AGILE_SLICES.md modification must NOT change packet hash!")

    def test_missing_plan_file_denies(self):
        (self.test_dir / "01_GOVERNANCE").mkdir()
        (self.test_dir / "01_GOVERNANCE" / "PROBLEM.md").write_text("Prob", encoding="utf-8")
        (self.test_dir / "01_GOVERNANCE" / "NON_GOALS.md").write_text("NoGoal", encoding="utf-8")
        (self.test_dir / "01_GOVERNANCE" / "ARCHITECTURE.md").write_text("Arch", encoding="utf-8")

        with self.assertRaises(SliceGateDeniedError) as cm:
            compute_live_packet_hash(self.test_dir, "nonexistent-slice")
        self.assertEqual(cm.exception.code, "MISSING_PLAN_FILE")

    def test_safe_write_path_restrictions(self):
        # Unapproved slice denied for IMPLEMENT action
        with self.assertRaises(BlockedSliceWriteError):
            safe_write(str(self.test_dir / "some_file.py"), "content", "slice-009-lifecycle-circuit-breaker", action="IMPLEMENT", project_root=self.test_dir)

        # PARSE_REVIEWS denied if target is not .sequence/review_resolutions.json
        with self.assertRaises(BlockedSliceWriteError):
            safe_write(str(self.test_dir / "unauthorized.txt"), "content", "slice-009-lifecycle-circuit-breaker", action="PARSE_REVIEWS", project_root=self.test_dir)

    def test_safe_write_remediation_allowlist_unquote(self):
        seq_dir = self.test_dir / ".sequence"
        seq_dir.mkdir(parents=True)
        res_data = {
            "slices": {
                "slice-009-lifecycle-circuit-breaker": {
                    "slice_id": "slice-009-lifecycle-circuit-breaker",
                    "overall_verdict": "BLOCKED",
                    "findings": [
                        {
                            "id": "FINDING-001",
                            "status": "OPEN",
                            "remediation": {
                                "target_location": "file:///C:/Linkstream/00_DEV_TEAM_SEQUENCE/file_hygiene_engine.py#L0010"
                            }
                        }
                    ]
                }
            }
        }
        (seq_dir / "review_resolutions.json").write_text(json.dumps(res_data), encoding="utf-8")

        allowlist = _get_remediation_allowlist_from_findings(self.test_dir, "slice-009-lifecycle-circuit-breaker")
        expected = (self.test_dir / "file_hygiene_engine.py").resolve()
        self.assertIn(expected, allowlist)


if __name__ == "__main__":
    unittest.main()
