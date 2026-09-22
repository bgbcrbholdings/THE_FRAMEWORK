#!/usr/bin/env python3
"""
test_pathfinder.py

Failing contract canary for Pathfinder (Slice 0): a light HTTP handler in
pathfinder_server.py exposing GET /api/health.

Contract under test:
  - GET /api/health -> HTTP 200, JSON {"status": "ok"} (exact body,
    application/json content type) when a live, readable SQLite
    .sequence/state.db exists.
  - GET /api/health -> HTTP 503 (fail closed) when .sequence/state.db is
    missing, OR when it exists but is not a valid/readable SQLite
    database -- never 200, never mock/placeholder data.

Interface:
  - pathfinder_server.BOUND_IP: str, e.g. "127.0.0.1"
  - pathfinder_server.SERVER_PORT: int
  - pathfinder_server.PathfinderRequestHandler: a
    http.server.BaseHTTPRequestHandler subclass implementing GET
    /api/health, usable directly with stdlib http.server.HTTPServer.
"""

import http.client
import http.server
import json
import os
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

pathfinder_server = None
IMPORT_ERROR = None
REQUIRED_ATTRS = (
    "BOUND_IP",
    "SERVER_PORT",
    "PathfinderRequestHandler",
)

try:
    import pathfinder_server
    _missing = [name for name in REQUIRED_ATTRS if not hasattr(pathfinder_server, name)]
    if _missing:
        IMPORT_ERROR = f"pathfinder_server.py is missing required interface members: {_missing}"
        pathfinder_server = None
except Exception as exc:  # noqa: BLE001 - intentional fail-closed behavior
    IMPORT_ERROR = f"could not import pathfinder_server.py: {exc!r}"
    pathfinder_server = None


def _http_get(host, port, path, timeout=5):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, dict(resp.getheaders()), raw
    finally:
        conn.close()


def _parse_json(raw_bytes):
    try:
        return json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssertionError(
            f"Response body was not valid UTF-8 JSON: {raw_bytes!r}"
        ) from exc


def _check_port_bound(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(0.2)
        return sock.connect_ex((ip, port)) == 0
    finally:
        sock.close()


def _assert_json_content_type(test_case, headers):
    content_type = next(
        (
            value
            for name, value in headers.items()
            if name.lower() == "content-type"
        ),
        "",
    )
    media_type = content_type.split(";", 1)[0].strip().lower()
    test_case.assertEqual(
        media_type,
        "application/json",
        f"Expected Content-Type application/json; got {content_type!r}",
    )


class PathfinderHealthLiveServerTestCase(unittest.TestCase):
    """
    Boots a REAL http.server.HTTPServer using pathfinder_server's own
    documented handler class, in a real working directory this test
    controls, and issues REAL HTTP requests over a REAL socket. No mocks,
    no stubs.
    """

    @classmethod
    def setUpClass(cls):
        if IMPORT_ERROR or pathfinder_server is None:
            return

        cls._tmpdir = tempfile.TemporaryDirectory(prefix="pathfinder_canary_")
        cls.work_dir = cls._tmpdir.name

        cls._original_cwd = os.getcwd()
        os.chdir(cls.work_dir)

        cls.sequence_dir = os.path.join(cls.work_dir, ".sequence")
        cls.state_db_path = os.path.join(cls.sequence_dir, "state.db")

        if _check_port_bound(pathfinder_server.BOUND_IP, pathfinder_server.SERVER_PORT):
            os.chdir(cls._original_cwd)
            cls._tmpdir.cleanup()
            raise RuntimeError(
                f"CONTRACT CANARY SETUP ABORTED: port "
                f"{pathfinder_server.SERVER_PORT} on "
                f"{pathfinder_server.BOUND_IP} is already bound"
            )

        cls.httpd = http.server.HTTPServer(
            (pathfinder_server.BOUND_IP, pathfinder_server.SERVER_PORT),
            pathfinder_server.PathfinderRequestHandler,
        )
        cls.server_thread = threading.Thread(
            target=cls.httpd.serve_forever, name="pathfinder-canary-httpd", daemon=True
        )
        cls.server_thread.start()

        deadline = time.time() + 5
        listening = False
        while time.time() < deadline:
            if _check_port_bound(pathfinder_server.BOUND_IP, pathfinder_server.SERVER_PORT):
                listening = True
                break
            time.sleep(0.05)

        if not listening:
            cls.httpd.shutdown()
            cls.httpd.server_close()
            os.chdir(cls._original_cwd)
            cls._tmpdir.cleanup()
            raise RuntimeError(
                "CONTRACT CANARY SETUP ABORTED: live server did not start "
                "listening within the timeout window"
            )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "httpd"):
            cls.httpd.shutdown()
            cls.httpd.server_close()
            cls.server_thread.join(timeout=5)
            os.chdir(cls._original_cwd)
            cls._tmpdir.cleanup()

    def setUp(self):
        if IMPORT_ERROR or pathfinder_server is None:
            self.fail(f"CONTRACT CANARY FAILURE: {IMPORT_ERROR}")
        # Every test starts with a clean slate: no .sequence directory.
        if os.path.exists(self.state_db_path):
            os.remove(self.state_db_path)
        if os.path.isdir(self.sequence_dir) and not os.listdir(self.sequence_dir):
            os.rmdir(self.sequence_dir)

    def _create_live_state_db(self):
        os.makedirs(self.sequence_dir, exist_ok=True)
        conn = sqlite3.connect(self.state_db_path)
        try:
            conn.execute(
                "CREATE TABLE sequence_state (key TEXT PRIMARY KEY, value TEXT)"
            )
            conn.execute(
                "INSERT INTO sequence_state (key, value) VALUES (?, ?)",
                ("canary", "alive"),
            )
            conn.commit()
        finally:
            conn.close()
        self.assertTrue(os.path.isfile(self.state_db_path))


class TestHealthFailsClosedWhenStateDbMissing(PathfinderHealthLiveServerTestCase):
    def test_health_returns_503_when_state_db_missing(self):
        self.assertFalse(
            os.path.exists(self.state_db_path),
            "Test invariant violated: .sequence/state.db unexpectedly exists",
        )

        status, headers, raw = _http_get(
            pathfinder_server.BOUND_IP, pathfinder_server.SERVER_PORT, "/api/health"
        )

        self.assertNotEqual(
            status,
            200,
            "/api/health returned HTTP 200 with .sequence/state.db missing "
            "-- server did not fail closed",
        )
        self.assertEqual(
            status,
            503,
            f"/api/health returned {status} instead of 503 when "
            f".sequence/state.db is missing",
        )

        payload = _parse_json(raw)
        _assert_json_content_type(self, headers)
        self.assertIsInstance(payload, dict)
        self.assertNotEqual(
            payload.get("status"),
            "ok",
            "/api/health reported status 'ok' while .sequence/state.db is "
            "missing -- mock/placeholder data was served instead of "
            "failing closed",
        )


class TestHealthFailsClosedWhenStateDbInvalid(PathfinderHealthLiveServerTestCase):
    def test_health_returns_503_when_state_db_is_not_sqlite(self):
        os.makedirs(self.sequence_dir, exist_ok=True)
        with open(self.state_db_path, "wb") as state_file:
            state_file.write(b"this is not a SQLite database")

        self.assertTrue(os.path.isfile(self.state_db_path))

        status, headers, raw = _http_get(
            pathfinder_server.BOUND_IP,
            pathfinder_server.SERVER_PORT,
            "/api/health",
        )

        self.assertEqual(
            status,
            503,
            "The health endpoint did not fail closed when state.db "
            "existed but was not a valid SQLite database",
        )

        payload = _parse_json(raw)
        _assert_json_content_type(self, headers)
        self.assertIsInstance(payload, dict)
        self.assertNotEqual(
            payload.get("status"),
            "ok",
            "The health endpoint reported 'ok' for a corrupt state.db",
        )


class TestHealthOkWhenStateDbPresent(PathfinderHealthLiveServerTestCase):
    def test_health_returns_200_ok_when_state_db_present(self):
        self._create_live_state_db()

        status, headers, raw = _http_get(
            pathfinder_server.BOUND_IP, pathfinder_server.SERVER_PORT, "/api/health"
        )

        self.assertEqual(
            status,
            200,
            f"/api/health returned {status} instead of 200 with a live "
            f".sequence/state.db present",
        )

        payload = _parse_json(raw)
        _assert_json_content_type(self, headers)
        self.assertEqual(
            payload,
            {"status": "ok"},
            f"/api/health did not report exactly {{'status': 'ok'}}; got: "
            f"{payload!r}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
