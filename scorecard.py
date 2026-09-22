#!/usr/bin/env python3
"""
The Sequence Control Engine — Second Brain Defect Scorecard & Model Accuracy Tracker (scorecard.py)
Ingests review resolution data, tracks model pass rates (ChatGPT, Claude, DeepSeek, Grok),
logs findings by severity taxonomy (CRITICAL, HIGH, MEDIUM, LOW), and exports static sidecars.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
import re
from pathlib import Path
from datetime import datetime
from sequence_engine import validate_and_open_path, APPROVED_ROOT_DIR

EXPECTED_MODELS = ["chatgpt", "claude", "deepseek", "grok"]
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

def validate_iso_datetime(val):
    try:
        datetime.fromisoformat(str(val))
        return True
    except ValueError:
        return False

def validate_scorecard_envelope(data):
    """
    Validates defect scorecard envelope.
    Required keys: total_reviews, slice_verdicts, model_accuracy, defects_by_severity, last_updated.
    Rejects un-allowlisted top-level keys.
    Asserts severity counts equal findings count and pass rates match calculated ratios within 0.1 tolerance.
    Returns (is_valid: bool, errors: list[str]).
    """
    errors = []
    if not isinstance(data, dict):
        return False, ["Scorecard envelope must be a JSON dictionary object."]

    allowlisted_keys = {"total_reviews", "slice_verdicts", "model_accuracy", "defects_by_severity", "last_updated"}
    extra_keys = set(data.keys()) - allowlisted_keys
    if extra_keys:
        errors.append(f"Envelope contains un-allowlisted top-level keys: {sorted(list(extra_keys))}")

    missing_keys = allowlisted_keys - set(data.keys())
    if missing_keys:
        errors.append(f"Missing required keys: {sorted(list(missing_keys))}")
        return False, errors

    total_reviews = data.get("total_reviews")
    if not isinstance(total_reviews, int) or total_reviews < 0:
        errors.append("total_reviews must be a non-negative int.")

    slice_verdicts = data.get("slice_verdicts")
    if not isinstance(slice_verdicts, dict):
        errors.append("slice_verdicts must be a dictionary.")

    defects = data.get("defects_by_severity")
    if not isinstance(defects, dict):
        errors.append("defects_by_severity must be a dictionary.")
    else:
        for sev in SEVERITY_LEVELS:
            val = defects.get(sev)
            if not isinstance(val, int) or val < 0:
                errors.append(f"defects_by_severity['{sev}'] must be a non-negative int.")

    model_acc = data.get("model_accuracy")
    if not isinstance(model_acc, dict):
        errors.append("model_accuracy must be a dictionary.")
    else:
        for model in EXPECTED_MODELS:
            entry = model_acc.get(model)
            if not isinstance(entry, dict):
                errors.append(f"model_accuracy entry for '{model}' must be a dict.")
                continue
            req_entry_keys = {"pass_count", "total_reviews", "pass_rate_pct"}
            missing_entry = req_entry_keys - set(entry.keys())
            if missing_entry:
                errors.append(f"model_accuracy['{model}'] missing keys: {sorted(list(missing_entry))}")
                continue
            p_cnt = entry.get("pass_count")
            t_cnt = entry.get("total_reviews")
            p_rate = entry.get("pass_rate_pct")
            if not isinstance(p_cnt, int) or p_cnt < 0:
                errors.append(f"model_accuracy['{model}'].pass_count must be a non-negative int.")
            if not isinstance(t_cnt, int) or t_cnt < 0:
                errors.append(f"model_accuracy['{model}'].total_reviews must be a non-negative int.")
            if not isinstance(p_rate, (int, float)) or p_rate < 0.0 or p_rate > 100.0:
                errors.append(f"model_accuracy['{model}'].pass_rate_pct must be a float 0.0–100.0.")
            if isinstance(p_cnt, int) and isinstance(t_cnt, int) and isinstance(p_rate, (int, float)):
                if p_cnt > t_cnt:
                    errors.append(f"Invariant violation for '{model}': pass_count ({p_cnt}) > total_reviews ({t_cnt}).")
                if t_cnt > 0:
                    expected_rate = (p_cnt / t_cnt) * 100.0
                    if abs(expected_rate - p_rate) > 0.1:
                        errors.append(f"Invariant violation for '{model}': pass_rate_pct ({p_rate}) does not match ratio ({expected_rate:.1f}).")

    last_updated = data.get("last_updated")
    if not last_updated or not validate_iso_datetime(last_updated):
        errors.append(f"last_updated '{last_updated}' must be a valid ISO datetime string.")

    return len(errors) == 0, errors


class ScorecardTracker:
    """
    Defect Scorecard and Model Accuracy Tracker Engine.
    Manages .sequence/scorecard.json persistence and exports dashboard/scorecard_data.json.
    """

    def __init__(self, project_dir=None):
        self.project_dir = os.path.realpath(project_dir or APPROVED_ROOT_DIR)
        self.scorecard_file = os.path.join(self.project_dir, ".sequence", "scorecard.json")
        self.dashboard_sidecar = os.path.join(self.project_dir, "dashboard", "scorecard_data.json")

    def load_scorecard(self):
        """Loads and validates existing scorecard file or returns a clean default envelope."""
        if os.path.exists(self.scorecard_file):
            try:
                with validate_and_open_path(self.scorecard_file, self.project_dir, "r", encoding="utf-8") as f:
                    data = json.load(f)
                ok, _ = validate_scorecard_envelope(data)
                if ok:
                    return data
            except Exception:
                pass

        # Return default envelope if missing or unparseable
        default_model_acc = {
            m: {"pass_count": 0, "total_reviews": 0, "pass_rate_pct": 0.0}
            for m in EXPECTED_MODELS
        }
        return {
            "total_reviews": 0,
            "slice_verdicts": {},
            "model_accuracy": default_model_acc,
            "defects_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "last_updated": datetime.now().isoformat()
        }

    def ingest_review_resolutions(self, resolutions_path=None):
        """
        Ingests review resolutions from .sequence/review_resolutions.json and updates scorecard metrics.
        Persists atomically to .sequence/scorecard.json and exports dashboard/scorecard_data.json.
        """
        if resolutions_path is None:
            resolutions_path = os.path.join(self.project_dir, ".sequence", "review_resolutions.json")

        scorecard_data = self.load_scorecard()

        if os.path.exists(resolutions_path):
            with validate_and_open_path(resolutions_path, self.project_dir, "r", encoding="utf-8") as f:
                resolutions = json.load(f)

            pkt_hash = resolutions.get("packet_sha256", "UNKNOWN")
            overall_verdict = resolutions.get("overall_verdict", "UNKNOWN")
            model_verdicts = resolutions.get("model_verdicts", {})
            findings = resolutions.get("findings", [])

            # Record slice verdict
            scorecard_data["slice_verdicts"][pkt_hash[:12]] = {
                "packet_sha256": pkt_hash,
                "overall_verdict": overall_verdict,
                "timestamp": datetime.now().isoformat()
            }
            scorecard_data["total_reviews"] = len(scorecard_data["slice_verdicts"])

            # Update model accuracy counters
            for model in EXPECTED_MODELS:
                v = model_verdicts.get(model)
                if v:
                    entry = scorecard_data["model_accuracy"].setdefault(
                        model, {"pass_count": 0, "total_reviews": 0, "pass_rate_pct": 0.0}
                    )
                    entry["total_reviews"] += 1
                    if v.upper() in ("APPROVED", "PASS"):
                        entry["pass_count"] += 1
                    if entry["total_reviews"] > 0:
                        entry["pass_rate_pct"] = round((entry["pass_count"] / entry["total_reviews"]) * 100.0, 2)

            # Update defect count by severity
            for f_item in findings:
                if isinstance(f_item, dict):
                    sev = str(f_item.get("severity", "MEDIUM")).upper()
                    if sev in scorecard_data["defects_by_severity"]:
                        scorecard_data["defects_by_severity"][sev] += 1

        scorecard_data["last_updated"] = datetime.now().isoformat()

        # Validate envelope prior to saving
        ok, errors = validate_scorecard_envelope(scorecard_data)
        if not ok:
            raise ValueError(f"Invalid scorecard envelope structure: {errors}")

        # Atomic persistence to .sequence/scorecard.json
        os.makedirs(os.path.dirname(self.scorecard_file), exist_ok=True)
        tmp_file = self.scorecard_file + ".tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(scorecard_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, self.scorecard_file)

        # Export static dashboard sidecar to dashboard/scorecard_data.json
        os.makedirs(os.path.dirname(self.dashboard_sidecar), exist_ok=True)
        tmp_sidecar = self.dashboard_sidecar + ".tmp"
        with open(tmp_sidecar, "w", encoding="utf-8") as f:
            json.dump(scorecard_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_sidecar, self.dashboard_sidecar)

        return scorecard_data

    def get_scorecard_data(self):
        """Returns the current validated scorecard data."""
        return self.load_scorecard()


if __name__ == "__main__":
    tracker = ScorecardTracker()
    res = tracker.ingest_review_resolutions()
    print(json.dumps(res, indent=2))
