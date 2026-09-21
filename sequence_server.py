#!/usr/bin/env python3
"""
The Sequence Control Engine — Localhost HTTP Control Server (sequence_server.py)
Extends http.server.HTTPServer bound strictly to IPv4 loopback (127.0.0.1:9753).
Enforces Session Token Auth (X-Sequence-Token), Exact Origin Validation,
Anti-CSRF Nonce Lifecycle (X-CSRF-Token), Win32 Atomic Reparse-Point Path Isolation,
and Live State Database (.sequence/state.db) Fail-Closed Gating.
Pure Python 3 Standard Library — 0 External Pip Dependencies.
"""

import os
import sys
import json
import hmac
import socket
import sqlite3
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

from sequence_engine import (
    APPROVED_ROOT_DIR,
    validate_and_open_path,
    get_or_create_active_session,
    verify_restrictive_dacl
)

SERVER_PORT = 9753
BOUND_IP = "127.0.0.1"

def check_state_db_exists(root_dir=APPROVED_ROOT_DIR):
    """Verifies existence of live SQLite state database file (.sequence/state.db)."""
    db_path = Path(root_dir) / ".sequence" / "state.db"
    return db_path.exists() and db_path.is_file()

def query_state_db(query, params=(), root_dir=APPROVED_ROOT_DIR):
    """
    Safely queries live SQLite state database (.sequence/state.db) in read-only mode.
    Returns list of dict rows or None if database is missing or unreadable.
    """
    db_path = Path(root_dir) / ".sequence" / "state.db"
    if not db_path.exists() or not db_path.is_file():
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return None

class SequenceRequestHandler(BaseHTTPRequestHandler):
    """Hardened HTTP Request Handler enforcing Origin, Token, CSRF, Path Isolation, and State DB Fail-Closed Gating."""

    def log_message(self, format, *args):
        pass

    def send_error_response(self, code, message):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        body = json.dumps({"error": message, "code": code}).encode("utf-8")
        self.wfile.write(body)

    def validate_security_headers(self, is_state_changing=False):
        origin = self.headers.get("Origin")
        expected_origin = f"http://{BOUND_IP}:{SERVER_PORT}"
        if origin and origin != expected_origin:
            self.send_error_response(403, f"ORIGIN REJECTED: Origin '{origin}' does not match exact '{expected_origin}'.")
            return False

        active_session = get_or_create_active_session(APPROVED_ROOT_DIR)
        expected_token = active_session.get("sequence_token", "")
        provided_token = self.headers.get("X-Sequence-Token", "")

        if not provided_token or not hmac.compare_digest(provided_token, expected_token):
            self.send_error_response(403, "AUTHENTICATION FAILURE: Invalid or missing X-Sequence-Token header.")
            return False

        if is_state_changing:
            expected_nonce = active_session.get("csrf_nonce", "")
            provided_nonce = self.headers.get("X-CSRF-Token", "")
            if not provided_nonce or not hmac.compare_digest(provided_nonce, expected_nonce):
                self.send_error_response(403, "CSRF REJECTED: Invalid or missing X-CSRF-Token header on state-changing request.")
                return False

        return True

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/" or path == "/dashboard":
            path = "/dashboard/index.html"

        if path.startswith("/dashboard/"):
            self.serve_static_dashboard_file(path)
            return

        if not self.validate_security_headers(is_state_changing=False):
            return

        if path == "/api/status":
            self.handle_api_status()
            return
        elif path == "/api/slices":
            self.handle_api_slices()
            return
        elif path == "/api/telemetry":
            self.handle_api_telemetry()
            return

        self.send_error_response(404, f"Endpoint '{path}' not found.")

    def do_POST(self):
        if not self.validate_security_headers(is_state_changing=True):
            return

        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/status" or path == "/api/action":
            if not check_state_db_exists(APPROVED_ROOT_DIR):
                self.send_error_response(503, "FAIL CLOSED: .sequence/state.db missing.")
                return

            active_session = get_or_create_active_session(APPROVED_ROOT_DIR)
            response_data = {
                "status": "PASS",
                "message": "State-changing action accepted.",
                "csrf_nonce": active_session.get("csrf_nonce")
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode("utf-8"))
            return

        self.send_error_response(404, f"POST Endpoint '{path}' not found.")

    def handle_api_status(self):
        if not check_state_db_exists(APPROVED_ROOT_DIR):
            self.send_error_response(503, "FAIL CLOSED: .sequence/state.db missing.")
            return

        rows = query_state_db("SELECT * FROM status LIMIT 1")
        if rows is None:
            rows = query_state_db("SELECT * FROM state LIMIT 1")

        if rows is None or not rows:
            self.send_error_response(503, "FAIL CLOSED: Unable to read status from .sequence/state.db.")
            return

        status_data = dict(rows[0])
        for k, v in list(status_data.items()):
            if isinstance(v, str) and (v.startswith("{") or v.startswith("[")):
                try:
                    status_data[k] = json.loads(v)
                except Exception:
                    pass

        active_session = get_or_create_active_session(APPROVED_ROOT_DIR)
        status_data.setdefault("server_port", SERVER_PORT)
        status_data.setdefault("bound_ip", BOUND_IP)
        status_data.setdefault("csrf_nonce", active_session.get("csrf_nonce", ""))

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(status_data).encode("utf-8"))

    def handle_api_slices(self):
        if not check_state_db_exists(APPROVED_ROOT_DIR):
            self.send_error_response(503, "FAIL CLOSED: .sequence/state.db missing.")
            return

        rows = query_state_db("SELECT * FROM slices")
        if rows is None:
            self.send_error_response(503, "FAIL CLOSED: Unable to read slices from .sequence/state.db.")
            return

        if len(rows) == 1 and "slices" in rows[0]:
            slices_data = dict(rows[0])
            if isinstance(slices_data.get("slices"), str):
                try:
                    slices_data["slices"] = json.loads(slices_data["slices"])
                except Exception:
                    pass
        else:
            slices_data = {
                "current_slice_index": 1,
                "slices": rows
            }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(slices_data).encode("utf-8"))

    def handle_api_telemetry(self):
        if not check_state_db_exists(APPROVED_ROOT_DIR):
            self.send_error_response(503, "FAIL CLOSED: .sequence/state.db missing.")
            return

        rows = query_state_db("SELECT * FROM telemetry LIMIT 1")
        if rows is None or not rows:
            self.send_error_response(503, "FAIL CLOSED: Unable to read telemetry from .sequence/state.db.")
            return

        telemetry_data = dict(rows[0])
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(telemetry_data).encode("utf-8"))

    def serve_static_dashboard_file(self, rel_path_str):
        clean_rel = rel_path_str.lstrip("/")
        file_path = APPROVED_ROOT_DIR / clean_rel

        try:
            with validate_and_open_path(file_path, root_dir_str=str(APPROVED_ROOT_DIR), mode="rb") as f:
                content = f.read()

            content_type = "text/html"
            if clean_rel.endswith(".css"):
                content_type = "text/css"
            elif clean_rel.endswith(".js"):
                content_type = "application/javascript"
            elif clean_rel.endswith(".json"):
                content_type = "application/json"

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(content)
        except (PermissionError, ValueError, FileNotFoundError) as e:
            self.send_error_response(403, f"PATH ACCESS BLOCKED: {e}")

class SequenceHTTPServer(HTTPServer):
    """HTTPServer bound strictly to IPv4 loopback 127.0.0.1:9753."""

    def __init__(self, server_address, RequestHandlerClass):
        if server_address[0] != BOUND_IP:
            raise ValueError(f"SECURITY VIOLATION: Server must bind strictly to '{BOUND_IP}'. Attempted: '{server_address[0]}'")
        super().__init__(server_address, RequestHandlerClass)

def check_port_bound(ip, port):
    """Returns True if target port is already bound by another process."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        res = s.connect_ex((ip, port))
        return res == 0

def run_server(port=SERVER_PORT):
    if not check_state_db_exists(APPROVED_ROOT_DIR):
        print(" [!] CRITICAL SECURITY ABORT: .sequence/state.db is missing.", file=sys.stderr)
        sys.exit(1)

    if check_port_bound(BOUND_IP, port):
        print(f" [!] CRITICAL SECURITY ABORT: Port {port} is already bound by another process.", file=sys.stderr)
        sys.exit(1)

    active_session = get_or_create_active_session(APPROVED_ROOT_DIR)
    print(f" [+] Starting SequenceHTTPServer on http://{BOUND_IP}:{port}")
    print(f" [+] Active Session Token : {active_session['sequence_token'][:8]}...")
    print(f" [+] Anti-CSRF Nonce      : {active_session['csrf_nonce']}")

    server_address = (BOUND_IP, port)
    httpd = SequenceHTTPServer(server_address, SequenceRequestHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n [!] Stopping SequenceHTTPServer.")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
