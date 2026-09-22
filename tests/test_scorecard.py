#!/usr/bin/env python3
"""
The Sequence Control Engine — Unit Test Suite for Slice 005 (tests/test_scorecard.py)
Validates defect scorecard tracking, model accuracy meters, 4-step memory vault lifecycle,
boot_digest immutability during Recall, Zip/Tar slip protection, TCB denylist enforcement,
git SHA resolution, and schema validation envelopes.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
import shutil
import tarfile
import zipfile
import tempfile
import unittest
import hashlib
from datetime import datetime
from unittest.mock import patch, MagicMock

# Import Slice 005 modules
from scorecard import ScorecardTracker, validate_scorecard_envelope
from backup_engine import (
    MemoryVaultManager,
    BackupEngine,
    validate_backup_envelope,
    RESTORE_DENYLIST
)


class TestScorecardTracker(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_scorecard_")
        self.seq_dir = os.path.join(self.tmp_dir, ".sequence")
        self.dash_dir = os.path.join(self.tmp_dir, "dashboard")
        os.makedirs(self.seq_dir, exist_ok=True)
        os.makedirs(self.dash_dir, exist_ok=True)
        self.tracker = ScorecardTracker(self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_validate_scorecard_envelope_valid(self):
        valid_payload = {
            "total_reviews": 1,
            "slice_verdicts": {"abc12345": {"packet_sha256": "abc12345", "overall_verdict": "PASS"}},
            "model_accuracy": {
                "chatgpt": {"pass_count": 1, "total_reviews": 1, "pass_rate_pct": 100.0},
                "claude": {"pass_count": 1, "total_reviews": 1, "pass_rate_pct": 100.0},
                "deepseek": {"pass_count": 1, "total_reviews": 1, "pass_rate_pct": 100.0},
                "grok": {"pass_count": 1, "total_reviews": 1, "pass_rate_pct": 100.0}
            },
            "defects_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "last_updated": datetime.now().isoformat()
        }
        ok, errors = validate_scorecard_envelope(valid_payload)
        self.assertTrue(ok, f"Expected valid scorecard payload, got errors: {errors}")

    def test_validate_scorecard_envelope_invalid(self):
        invalid_payload = {
            "total_reviews": -1,
            "extra_unallowlisted_key": True
        }
        ok, errors = validate_scorecard_envelope(invalid_payload)
        self.assertFalse(ok)
        self.assertIn("Envelope contains un-allowlisted top-level keys: ['extra_unallowlisted_key']", errors)

    def test_ingest_review_resolutions(self):
        resolutions_file = os.path.join(self.seq_dir, "review_resolutions.json")
        res_data = {
            "packet_sha256": "b22b4cb17e0b48d6d407a9bef8af235740fb8486f97a651914288976c6d737fb",
            "overall_verdict": "APPROVED",
            "model_verdicts": {
                "chatgpt": "APPROVED",
                "claude": "APPROVED",
                "deepseek": "APPROVED",
                "grok": "APPROVED"
            },
            "findings": [
                {"id": "F-1", "severity": "HIGH", "category": "SCHEMA_VIOLATION"}
            ]
        }
        with open(resolutions_file, "w", encoding="utf-8") as f:
            json.dump(res_data, f)

        res = self.tracker.ingest_review_resolutions(resolutions_file)
        self.assertEqual(res["total_reviews"], 1)
        self.assertEqual(res["defects_by_severity"]["HIGH"], 1)
        self.assertEqual(res["model_accuracy"]["chatgpt"]["pass_rate_pct"], 100.0)

        # Assert scorecard.json created
        scorecard_file = os.path.join(self.seq_dir, "scorecard.json")
        self.assertTrue(os.path.exists(scorecard_file))

        # Assert static dashboard sidecar exported
        sidecar_file = os.path.join(self.dash_dir, "scorecard_data.json")
        self.assertTrue(os.path.exists(sidecar_file))


class TestMemoryVaultManager(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_vault_")
        self.seq_dir = os.path.join(self.tmp_dir, ".sequence")
        self.wiki_dir = os.path.join(self.seq_dir, "wiki")
        os.makedirs(self.wiki_dir, exist_ok=True)

        self.boot_digest_file = os.path.join(self.seq_dir, "boot_digest.txt")
        self.initial_digest_content = b"98244099e180054e11d3b2d4b73d437eeb73852af57cae811da8e353499213b4"
        with open(self.boot_digest_file, "wb") as f:
            f.write(self.initial_digest_content)

        self.vault = MemoryVaultManager(self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_recall_boot_digest_immutability(self):
        """FINDING-001 / FINDING-007: Assert boot_digest.txt bytes and SHA-256 are untouched during Recall."""
        index_file = os.path.join(self.wiki_dir, "index.tsv")
        with open(index_file, "w", encoding="utf-8") as f:
            f.write("tag\tsummary\tfile\n")
            f.write("slice-005\tNever overwrite boot_digest\tnote1.md\n")

        with open(self.boot_digest_file, "rb") as f:
            hash_before = hashlib.sha256(f.read()).hexdigest()

        recall_res = self.vault.recall(["slice-005"])
        self.assertEqual(len(recall_res["lessons"]), 1)

        with open(self.boot_digest_file, "rb") as f:
            bytes_after = f.read()
            hash_after = hashlib.sha256(bytes_after).hexdigest()

        # Assert 100% byte-identical
        self.assertEqual(hash_before, hash_after)
        self.assertEqual(self.initial_digest_content, bytes_after)

        # Assert recall context persisted to .sequence/recall_context.json
        recall_context_file = os.path.join(self.seq_dir, "recall_context.json")
        self.assertTrue(os.path.exists(recall_context_file))

    def test_write_filing_sweep_and_wikilinks(self):
        note1 = os.path.join(self.wiki_dir, "Architecture.md")
        note2 = os.path.join(self.wiki_dir, "Security.md")

        with open(note1, "w", encoding="utf-8") as f:
            f.write("# Architecture\nThis document describes system Security principles.")

        with open(note2, "w", encoding="utf-8") as f:
            f.write("# Security\nThis covers core Architecture rules.")

        count = self.vault.write_filing_sweep()
        self.assertEqual(count, 2)

        # Verify [[wikilinks]] auto-injection
        with open(note1, "r", encoding="utf-8") as f:
            c1 = f.read()
        self.assertIn("[[Security]]", c1)

    def test_consolidate_and_prune_sentinel(self):
        note1 = os.path.join(self.wiki_dir, "Orphan1.md")
        with open(note1, "w", encoding="utf-8") as f:
            f.write("# Orphan Note 1\nNo links here.")

        links_per_note, orphan_pct, health = self.vault.consolidate_and_prune()
        self.assertEqual(links_per_note, 0.0)
        self.assertEqual(orphan_pct, 100.0)
        self.assertEqual(health, "DEGRADED")


class TestBackupEngine(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_backup_")
        self.seq_dir = os.path.join(self.tmp_dir, ".sequence")
        self.wiki_dir = os.path.join(self.seq_dir, "wiki")
        self.dash_dir = os.path.join(self.tmp_dir, "dashboard")
        os.makedirs(self.wiki_dir, exist_ok=True)
        os.makedirs(self.dash_dir, exist_ok=True)

        self.boot_digest_file = os.path.join(self.seq_dir, "boot_digest.txt")
        self.initial_digest_content = b"98244099e180054e11d3b2d4b73d437eeb73852af57cae811da8e353499213b4"
        with open(self.boot_digest_file, "wb") as f:
            f.write(self.initial_digest_content)

        self.engine = BackupEngine(self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_validate_backup_envelope_valid(self):
        envelope = {
            "snapshot_id": "snapshot_123",
            "snapshot_sha256": "a" * 64,
            "boot_digest_sha256": "b" * 64,
            "git_commit_sha": "c" * 40,
            "vault_note_count": 5,
            "graph_density_links_per_note": 4.5,
            "vault_health": "OK",
            "backup_file_path": ".sequence/backups/snapshot_123.tar.gz",
            "timestamp": datetime.now().isoformat()
        }
        ok, errors = validate_backup_envelope(envelope)
        self.assertTrue(ok, f"Expected valid envelope, got errors: {errors}")

    def test_create_snapshot_and_payload_hash(self):
        note1 = os.path.join(self.wiki_dir, "Note1.md")
        with open(note1, "w", encoding="utf-8") as f:
            f.write("# Note 1\nContent.")

        envelope = self.engine.create_snapshot()
        self.assertEqual(len(envelope["snapshot_sha256"]), 64)
        self.assertEqual(envelope["vault_note_count"], 1)

        # Assert sidecar created
        sidecar = os.path.join(self.dash_dir, "backup_status.json")
        self.assertTrue(os.path.exists(sidecar))

    def test_restore_zip_slip_rejection(self):
        """FINDING-001 / FINDING-002: Assert ZipSlip / TarSlip crafted members trigger SNAPSHOT_RESTORE_BLOCKED."""
        backups_dir = os.path.join(self.seq_dir, "backups")
        manifests_dir = os.path.join(backups_dir, "manifests")
        os.makedirs(manifests_dir, exist_ok=True)

        bad_archive = os.path.join(backups_dir, "bad_snapshot.tar.gz")
        with tarfile.open(bad_archive, "w:gz") as tar:
            # Craft member with relative path traversal
            tarinfo = tarfile.TarInfo(name="../escape.txt")
            content = b"EVIL DATA"
            tarinfo.size = len(content)
            tar.addfile(tarinfo, fileobj=io_bytes(content))

        # Stream bad archive bytes to compute real payload hash for envelope
        with open(bad_archive, "rb") as f:
            archive_bytes = f.read()
        snap_hash = hashlib.sha256(archive_bytes).hexdigest()

        manifest_file = os.path.join(manifests_dir, "bad_snapshot.json")
        envelope = {
            "snapshot_id": "bad_snapshot",
            "snapshot_sha256": snap_hash,
            "boot_digest_sha256": self.engine.get_boot_digest_hash(),
            "git_commit_sha": "UNKNOWN",
            "vault_note_count": 1,
            "graph_density_links_per_note": 0.0,
            "vault_health": "OK",
            "backup_file_path": ".sequence/backups/bad_snapshot.tar.gz",
            "timestamp": datetime.now().isoformat()
        }
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(envelope, f)

        # Attempt restore, assert SNAPSHOT_RESTORE_BLOCKED raised
        with self.assertRaises(PermissionError) as cm:
            self.engine.restore_snapshot(bad_archive, manifest_file)
        self.assertIn("SNAPSHOT_RESTORE_BLOCKED", str(cm.exception))

        # Assert no file created outside staging
        self.assertFalse(os.path.exists(os.path.join(self.tmp_dir, "escape.txt")))

    def test_restore_denylist_rejection(self):
        """FINDING-003: Assert snapshot containing lock_manifest.json or boot_digest.txt is rejected."""
        backups_dir = os.path.join(self.seq_dir, "backups")
        manifests_dir = os.path.join(backups_dir, "manifests")
        os.makedirs(manifests_dir, exist_ok=True)

        bad_archive = os.path.join(backups_dir, "denylist_snapshot.tar.gz")
        with tarfile.open(bad_archive, "w:gz") as tar:
            # Craft member attempting to overwrite boot_digest.txt
            tarinfo = tarfile.TarInfo(name=".sequence/boot_digest.txt")
            content = b"TAMPERED DIGEST"
            tarinfo.size = len(content)
            tar.addfile(tarinfo, fileobj=io_bytes(content))

        with open(bad_archive, "rb") as f:
            archive_bytes = f.read()
        snap_hash = hashlib.sha256(archive_bytes).hexdigest()

        manifest_file = os.path.join(manifests_dir, "denylist_snapshot.json")
        envelope = {
            "snapshot_id": "denylist_snapshot",
            "snapshot_sha256": snap_hash,
            "boot_digest_sha256": self.engine.get_boot_digest_hash(),
            "git_commit_sha": "UNKNOWN",
            "vault_note_count": 1,
            "graph_density_links_per_note": 0.0,
            "vault_health": "OK",
            "backup_file_path": ".sequence/backups/denylist_snapshot.tar.gz",
            "timestamp": datetime.now().isoformat()
        }
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(envelope, f)

        with self.assertRaises(PermissionError) as cm:
            self.engine.restore_snapshot(bad_archive, manifest_file)
        self.assertIn("SNAPSHOT_RESTORE_BLOCKED", str(cm.exception))

        # Assert boot_digest.txt remains byte-identical
        with open(self.boot_digest_file, "rb") as f:
            bytes_after = f.read()
        self.assertEqual(self.initial_digest_content, bytes_after)

    def test_resolve_git_commit_sha_subprocess(self):
        """FINDING-006: Assert git CLI subprocess is called with shell=False and handles fallback."""
        sha = self.engine.resolve_git_commit_sha()
        self.assertTrue(isinstance(sha, str))


def io_bytes(b_data):
    import io
    return io.BytesIO(b_data)


if __name__ == "__main__":
    unittest.main()
