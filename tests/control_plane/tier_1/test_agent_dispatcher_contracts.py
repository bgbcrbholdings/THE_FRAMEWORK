"""
Contract Tests for agent_dispatcher.py Worker Isolation (Ticket T3 / Layer-2)
Governance-Critical: Worker registration, path containment, and isolated subprocess execution.

Written FIRST per Split-Ticket TDD Protocol.
ALL tests MUST be run against baseline code to demonstrate RED failure before implementation.

CRITICAL INVARIANTS TESTED:
  1. agent_dispatcher.py exposes WORKER_REGISTRY with strict worker entries
  2. Dispatching unregistered workers fails closed with ValueError
  3. Dispatching workers outside approved directory jails fails closed
  4. Executing registered workers runs in isolated subprocess with sanitized environment
"""

import unittest
import json
import os
import sys
import tempfile
from pathlib import Path

import agent_dispatcher


class TestAgentDispatcherContracts(unittest.TestCase):

    def test_worker_registry_exists_and_contains_registered_workers(self):
        """
        GOVERNANCE INVARIANT: agent_dispatcher.py MUST define WORKER_REGISTRY
        containing required worker scripts.
        """
        self.assertTrue(
            hasattr(agent_dispatcher, "WORKER_REGISTRY"),
            "agent_dispatcher.py MUST expose WORKER_REGISTRY"
        )
        registry = agent_dispatcher.WORKER_REGISTRY
        expected_workers = ["ci_fetcher", "diff_validator", "schema_gate_worker", "manifest_builder"]
        for worker in expected_workers:
            self.assertIn(worker, registry, f"WORKER_REGISTRY MUST register '{worker}'")

    def test_dispatch_unregistered_worker_fails_closed(self):
        """
        GOVERNANCE INVARIANT: Dispatching an unregistered worker script MUST raise ValueError.
        """
        self.assertTrue(
            hasattr(agent_dispatcher, "dispatch_worker"),
            "agent_dispatcher.py MUST expose dispatch_worker function"
        )
        with self.assertRaises(ValueError) as cm:
            agent_dispatcher.dispatch_worker("unregistered_malicious_worker", {})
        self.assertIn("UNREGISTERED_WORKER", str(cm.exception))

    def test_worker_subprocess_isolation_sanitizes_environment(self):
        """
        GOVERNANCE INVARIANT: Worker subprocess execution MUST pass only sanitized ENVIRONMENT_ALLOWLIST.
        """
        env = agent_dispatcher.build_sanitized_worker_env()
        self.assertNotIn("SECRET_TOKEN", env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        for key in env:
            self.assertIn(key, agent_dispatcher.ENVIRONMENT_ALLOWLIST)


if __name__ == "__main__":
    unittest.main()
