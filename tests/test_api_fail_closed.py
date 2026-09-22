#!/usr/bin/env python3
"""
test_api_fail_closed.py

Contract canary test suite for sequence_server.py.

Authored by Model A (Contract Author) as an independent, stateless test
engineer. This suite makes ZERO assumptions about implementation details
beyond the documented module interface. It exercises the REAL module
against REAL sockets and a REAL handler instance -- no mocks, no stubs,
no swallowed exceptions, no dummy assertions.

Pure Python 3 standard library only.
"""

import http.client
import json
import os
import secrets
import shutil
import sys
import threading
import time
import unittest

try:
    import sequence_server as ss
except Exception as exc:  # noqa: BLE001 - intentional fail-closed behavior
    sys.stderr.write(
        "CONTRACT CANARY FAILURE: could not import sequence_server.py: "
        f"{exc!r}\n"
    )
    sys.exit(1)


REQUIRED_ATTRS = (
    "SERVER_PORT",
    "BOUND_IP",
    "check_state_db_exists",
    "query_state_db",
    "check_port_bound",
    "run_server",
    "SequenceHTTPServer",
    "SequenceRequestHandler",
    "APPROVED_ROOT_DIR",
)

_missing = [name for name in REQUIRED_ATTRS if not hasattr(ss, name)]
if _missing:
    sys.stderr.write(
        "CONTRACT CANARY FAILURE: sequence_server.py is missing required "
        f"interface members: {_missing}\n"
    )
    sys.exit(1)


REQUIRED_BOUND_IP = "127.0.0.1"
VALID_ORIGIN = "http://{}:{}".format(REQUIRED_BOUND_IP, ss.SERVER_PORT)


def _http_request(method, path, headers=None, body=None, timeout=5):
    """
    Issues a real HTTP request over a real socket to the live server.
    Returns (status_code, headers_dict, raw_body_bytes).
    """
    conn = http.client.HTTPConnection(ss.BOUND_IP, ss.SERVER_PORT, timeout=timeout)
    try:
        hdrs = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
            hdrs["Content-Length"] = str(len(data))
        conn.request(method, path, body=data, headers=hdrs)
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
            "Response body was not valid UTF-8 JSON: {!r}".format(raw_bytes)
        ) from exc


class TestServerBindingSecurity(unittest.TestCase):
    """
    Test case 1: SequenceHTTPServer must refuse to bind to anything other
    than 127.0.0.1. Pure constructor-level invariant; no live server needed.
    """

    def test_bound_ip_constant_is_required_loopback(self):
        self.assertEqual(
            ss.BOUND_IP,
            REQUIRED_BOUND_IP,
            "BOUND_IP must be exactly 127.0.0.1",
        )

    def test_server_binding_rejection(self):
        forbidden_addresses = (
            "0.0.0.0",
            "127.0.0.2",
            "192.0.2.1",
            "::",
            "::1",
            "localhost",
        )

        for address in forbidden_addresses:
            with self.subTest(address=address):
                rogue_server = None
                try:
                    with self.assertRaises(ValueError) as ctx:
                        rogue_server = ss.SequenceHTTPServer(
                            (address, ss.SERVER_PORT),
                            ss.SequenceRequestHandler,
                        )
                    self.assertIn("127.0.0.1", str(ctx.exception))
                finally:
                    if rogue_server is not None:
                        rogue_server.server_close()

    def test_required_loopback_binding_is_accepted(self):
        server = ss.SequenceHTTPServer(
            (REQUIRED_BOUND_IP, 0),
            ss.SequenceRequestHandler,
        )
        try:
            self.assertEqual(server.server_address[0], REQUIRED_BOUND_IP)
        finally:
            server.server_close()


class LiveServerTestCase(unittest.TestCase):
    """
    Shared fixture: boots a REAL SequenceHTTPServer/SequenceRequestHandler
    on a background thread, bound to 127.0.0.1:SERVER_PORT, with a valid
    active session in .sequence/session.json but WITHOUT .sequence/state.db
    -- exercising true fail-closed behavior for every test in this class.
    """

    @classmethod
    def setUpClass(cls):
        cls.root_dir = ss.APPROVED_ROOT_DIR
        cls.sequence_dir = os.path.join(cls.root_dir, ".sequence")

        cls._sequence_dir_preexisted = os.path.isdir(cls.sequence_dir)
        os.makedirs(cls.sequence_dir, exist_ok=True)

        cls.state_db_path = os.path.join(cls.sequence_dir, "state.db")
        if os.path.exists(cls.state_db_path):
            raise RuntimeError(
                "CONTRACT CANARY SETUP ABORTED: .sequence/state.db already "
                "exists in APPROVED_ROOT_DIR; refusing to run fail-closed "
                "canary against a non-clean environment."
            )

        cls.sequence_token = "canary-token-" + secrets.token_hex(16)
        cls.csrf_nonce = "canary-csrf-" + secrets.token_hex(16)

        cls.session_path = os.path.join(cls.sequence_dir, "session.json")
        cls._session_preexisted = os.path.exists(cls.session_path)
        cls._original_session_contents = None
        cls._original_session_mode = None

        if cls._session_preexisted:
            with open(cls.session_path, "rb") as fh:
                cls._original_session_contents = fh.read()
            cls._original_session_mode = os.stat(cls.session_path).st_mode

        now = time.time()
        session_payload = {
            "sequence_token": cls.sequence_token,
            "csrf_nonce": cls.csrf_nonce,
            "created_at": now,
            "expires_at": now + 3600,
            "active": True,
        }
        with open(cls.session_path, "w", encoding="utf-8") as fh:
            json.dump(session_payload, fh)

        cls.dashboard_dir = os.path.join(cls.root_dir, "dashboard")
        cls._dashboard_dir_preexisted = os.path.isdir(cls.dashboard_dir)
        os.makedirs(cls.dashboard_dir, exist_ok=True)
        cls._dashboard_index_preexisted = os.path.exists(
            os.path.join(cls.dashboard_dir, "index.html")
        )
        if not cls._dashboard_index_preexisted:
            with open(
                os.path.join(cls.dashboard_dir, "index.html"), "w", encoding="utf-8"
            ) as fh:
                fh.write("<html><body>canary</body></html>")

        if ss.check_port_bound(ss.BOUND_IP, ss.SERVER_PORT):
            raise RuntimeError(
                f"CONTRACT CANARY SETUP ABORTED: port {ss.SERVER_PORT} on "
                f"{ss.BOUND_IP} is already bound; cannot start live server "
                f"for canary tests."
            )

        cls.httpd = ss.SequenceHTTPServer(
            (ss.BOUND_IP, ss.SERVER_PORT), ss.SequenceRequestHandler
        )
        cls.server_thread = threading.Thread(
            target=cls.httpd.serve_forever, name="canary-httpd", daemon=True
        )
        cls.server_thread.start()

        deadline = time.time() + 5
        listening = False
        while time.time() < deadline:
            if ss.check_port_bound(ss.BOUND_IP, ss.SERVER_PORT):
                listening = True
                break
            time.sleep(0.05)

        if not listening:
            cls.httpd.shutdown()
            cls.httpd.server_close()
            raise RuntimeError(
                "CONTRACT CANARY SETUP ABORTED: live server did not start "
                "listening within the timeout window."
            )

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.server_thread.join(timeout=5)
        if cls.server_thread.is_alive():
            raise RuntimeError(
                "Live server thread did not terminate during teardown"
            )

        if not cls._dashboard_index_preexisted:
            index_path = os.path.join(cls.dashboard_dir, "index.html")
            if os.path.exists(index_path):
                os.remove(index_path)

        if not cls._dashboard_dir_preexisted and os.path.isdir(cls.dashboard_dir):
            shutil.rmtree(cls.dashboard_dir)

        if cls._session_preexisted:
            with open(cls.session_path, "wb") as fh:
                fh.write(cls._original_session_contents)
            os.chmod(cls.session_path, cls._original_session_mode)
        else:
            if os.path.exists(cls.session_path):
                os.remove(cls.session_path)

        if not cls._sequence_dir_preexisted and os.path.isdir(cls.sequence_dir):
            shutil.rmtree(cls.sequence_dir)

    def _valid_headers(self, include_csrf=False):
        headers = {
            "Origin": VALID_ORIGIN,
            "X-Sequence-Token": self.sequence_token,
        }
        if include_csrf:
            headers["X-CSRF-Token"] = self.csrf_nonce
        return headers

    def _assert_forbidden(self, status, raw):
        self.assertEqual(status, 403)
        payload = _parse_json(raw)
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload.get("code"), 403)
        self.assertIn("error", payload)
        self.assertNotEqual(str(payload.get("error", "")).strip(), "")


class TestSequenceRequestHandlerSecurity(LiveServerTestCase):
    """
    Test cases 2-6: exercised against a REAL running server instance over
    REAL socket connections.
    """

    def test_origin_header_enforcement(self):
        # Per spec: "Origin header validation: If present, must equal ...".
        # Origin is OPTIONAL -- its absence must not itself trigger a 403.
        # With a valid token and no Origin header, the request must still
        # fail closed on the missing state DB (503); it must never be
        # rejected with 403 for a header the contract never required.
        headers_no_origin = {
            "X-Sequence-Token": self.sequence_token,
        }
        status0, _, raw0 = _http_request(
            "GET", "/api/status", headers=headers_no_origin
        )
        self.assertNotEqual(
            status0,
            403,
            "Absent Origin header must not itself trigger 403 -- spec "
            "only requires validation 'if present'",
        )
        self.assertEqual(status0, 503)

        headers = self._valid_headers(include_csrf=False)
        headers["Origin"] = "http://evil.com"
        status, _, raw = _http_request("GET", "/api/status", headers=headers)
        self._assert_forbidden(status, raw)

        headers_alt = self._valid_headers(include_csrf=False)
        headers_alt["Origin"] = "http://127.0.0.1:9999"
        status2, _, raw2 = _http_request("GET", "/api/status", headers=headers_alt)
        self._assert_forbidden(status2, raw2)

    def test_missing_sequence_token_rejection(self):
        headers = {"Origin": VALID_ORIGIN}
        status, _, raw = _http_request("GET", "/api/status", headers=headers)
        self._assert_forbidden(status, raw)

        headers_bad = {
            "Origin": VALID_ORIGIN,
            "X-Sequence-Token": "not-the-real-token-" + secrets.token_hex(8),
        }
        status2, _, raw2 = _http_request("GET", "/api/status", headers=headers_bad)
        self._assert_forbidden(status2, raw2)

    def test_invalid_csrf_nonce_rejection(self):
        headers_no_csrf = self._valid_headers(include_csrf=False)
        status, _, raw = _http_request(
            "POST", "/api/action", headers=headers_no_csrf, body={"action": "noop"}
        )
        self._assert_forbidden(status, raw)

        headers_bad_csrf = self._valid_headers(include_csrf=True)
        headers_bad_csrf["X-CSRF-Token"] = "forged-nonce-" + secrets.token_hex(8)
        status2, _, raw2 = _http_request(
            "POST", "/api/action", headers=headers_bad_csrf, body={"action": "noop"}
        )
        self._assert_forbidden(status2, raw2)

        headers_bad_csrf_status = self._valid_headers(include_csrf=True)
        headers_bad_csrf_status["X-CSRF-Token"] = "forged-nonce-" + secrets.token_hex(8)
        status3, _, raw3 = _http_request(
            "POST",
            "/api/status",
            headers=headers_bad_csrf_status,
            body={"probe": True},
        )
        self._assert_forbidden(status3, raw3)

    def test_fail_closed_on_missing_state_db(self):
        self.assertFalse(
            os.path.exists(self.state_db_path),
            "Test invariant violated: .sequence/state.db unexpectedly exists",
        )

        headers = self._valid_headers(include_csrf=True)
        for path in ("/api/status", "/api/slices", "/api/telemetry"):
            with self.subTest(path=path):
                status, _, raw = _http_request("GET", path, headers=headers)
                self.assertNotEqual(
                    status,
                    200,
                    f"{path} returned HTTP 200 with .sequence/state.db missing "
                    f"-- server did NOT fail closed",
                )
                self.assertEqual(
                    status,
                    503,
                    f"{path} returned {status} instead of 503 when "
                    f".sequence/state.db is missing",
                )
                payload = _parse_json(raw)
                self.assertIsInstance(payload, dict)
                self.assertEqual(payload.get("code"), 503)
                self.assertIn("FAIL CLOSED", str(payload.get("error", "")))

    def test_dashboard_path_traversal_rejection(self):
        headers = self._valid_headers(include_csrf=False)

        status, _, raw = _http_request(
            "GET", "/dashboard/../sequence_server.py", headers=headers
        )
        self._assert_forbidden(status, raw)

        # Bonus, non-required variants: the spec only commits to the
        # literal ".." case above returning 403. These encoded/nested
        # variants are checked against the weaker, still-meaningful
        # invariant that the escaped file must never be served (200),
        # rather than assuming the handler performs percent-decoding
        # before path resolution.
        for suspicious_path in (
            "/dashboard/../../etc/passwd",
            "/dashboard/..%2Fsequence_server.py",
            "/dashboard/%2e%2e/sequence_server.py",
            "/dashboard/../.sequence/session.json",
        ):
            with self.subTest(path=suspicious_path):
                status_x, _, _ = _http_request(
                    "GET", suspicious_path, headers=headers
                )
                self.assertNotEqual(
                    status_x,
                    200,
                    f"{suspicious_path} was served with HTTP 200 -- "
                    f"path traversal was not blocked",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
